package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// Long-lived credentials (CONTRACT §17.14).

const llPath = "/api/v1/me/long-lived"

func llInput() model.LongLivedRequestInput {
	return model.LongLivedRequestInput{CloudAccountID: demoAccountID, Resource: "ecs", Permission: "read",
		ResourceName: "i-2ze0demo001", Reason: "monitoring dashboard"}
}

// enableLongLived turns the feature on for the demo account and allows mei.
func (a *accessEnv) enableLongLived() {
	a.t.Helper()
	requireStatus(a.t, a.sup.do(http.MethodPut, supAccounts+"/"+a.providerID+"/user-admin", model.SetUserAdminKeyInput{}), http.StatusOK)
	yes := true
	requireStatus(a.t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{LongLived: &yes}), http.StatusOK)
}

// askLongLived asks as mei and returns the link key.
func (a *accessEnv) askLongLived(in model.LongLivedRequestInput) (model.LongLivedRequestResult, string) {
	a.t.Helper()
	rec := a.mei.do(http.MethodPost, llPath, in)
	requireStatus(a.t, rec, http.StatusCreated)
	out := decodeEnvelope[model.LongLivedRequestResult](a.t, rec)
	_, key, ok := strings.Cut(out.Link, longLivedLinkPrefix)
	if !ok || !longLivedKeyRE.MatchString(key) {
		a.t.Fatalf("link %q", out.Link)
	}
	return out, key
}

func (a *accessEnv) createLongLived(key string) model.LongLivedSecret {
	a.t.Helper()
	rec := a.mei.do(http.MethodPost, "/api/v1/me/long-lived-requests/"+key+"/create", nil)
	requireStatus(a.t, rec, http.StatusOK)
	return decodeEnvelope[model.LongLivedSecret](a.t, rec)
}

func (a *accessEnv) llStatus(id string) model.LongLivedStatus {
	a.t.Helper()
	row, err := a.srv.db.GetLongLived(context.Background(), id)
	if err != nil {
		a.t.Fatal(err)
	}
	return row.Status
}

func TestLongLivedFlow(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	// Not enabled, not allowed: refused.
	requireStatus(t, a.mei.do(http.MethodPost, llPath, llInput()), http.StatusForbidden)
	yes := true
	requireStatus(t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{LongLived: &yes}), http.StatusOK)
	requireStatus(t, a.mei.do(http.MethodPost, llPath, llInput()), http.StatusConflict) // account not enabled
	requireStatus(t, a.sup.do(http.MethodPut, supAccounts+"/"+a.providerID+"/user-admin", model.SetUserAdminKeyInput{}), http.StatusOK)
	// Above the role, or without a reason: refused.
	full := llInput()
	full.Permission = "full"
	requireStatus(t, a.mei.do(http.MethodPost, llPath, full), http.StatusForbidden)
	noReason := llInput()
	noReason.Reason = ""
	requireStatus(t, a.mei.do(http.MethodPost, llPath, noReason), http.StatusBadRequest)

	asked, key := a.askLongLived(llInput())
	if asked.Status != model.LongLivedPending || !asked.ExpiresAt.Equal(a.clock.Now().Add(time.Hour)) {
		t.Fatalf("asked %+v", asked)
	}
	// Only mei sees it; a command-line session cannot create it.
	jun := a.addPerson(a.sup, "jun", false)
	requireStatus(t, jun.do(http.MethodGet, "/api/v1/me/long-lived-requests/"+key, nil), http.StatusNotFound)
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/me/long-lived-requests/"+key+"/create", nil), http.StatusNotFound)
	cli := a.signInCLI(a.mei)
	requireStatus(t, cli.do(http.MethodPost, "/api/v1/me/long-lived-requests/"+key+"/create", nil), http.StatusForbidden)
	rec := a.mei.do(http.MethodGet, "/api/v1/me/long-lived-requests/"+key, nil)
	requireStatus(t, rec, http.StatusOK)
	if v := decodeEnvelope[model.LongLivedCredential](t, rec); v.Resource != "ecs" || v.Permission != "read" || v.ResourceName != "i-2ze0demo001" {
		t.Fatalf("view %+v", v)
	}

	secret := a.createLongLived(key)
	if secret.AccessKeyID == "" || secret.AccessKeySecret == "" || secret.Credential.Status != model.LongLivedActive ||
		secret.Credential.CloudUser == "" || len(secret.Env) != 2 || secret.Env[0].Name != "ALIBABA_CLOUD_ACCESS_KEY_ID" {
		t.Fatalf("secret answer %+v", secret.Credential)
	}
	// Once: the link is spent.
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/long-lived-requests/"+key+"/create", nil), http.StatusNotFound)

	// The key works in the mock cloud, within its policy only.
	h := a.srv.Handler()
	if c := rawRequest(t, h, http.MethodGet, "/mock-cloud/v1/ecs/instances/i-2ze0demo001", secret.AccessKeySecret, nil).Code; c != http.StatusOK {
		t.Fatalf("read with the long-lived key: %d", c)
	}
	if c := rawRequest(t, h, http.MethodPost, "/mock-cloud/v1/ecs/instances/i-2ze0demo001/restart", secret.AccessKeySecret, nil).Code; c != http.StatusForbidden {
		t.Fatalf("write with a read key: %d", c)
	}

	// The secret and the link key are nowhere but in that one answer.
	audit, _ := json.Marshal(a.listAudit(""))
	for _, leak := range []string{secret.AccessKeySecret, key} {
		if strings.Contains(string(audit), leak) || strings.Contains(a.logs.String(), leak) {
			t.Fatal("a secret reached the audit log or the server log")
		}
	}
	list := decodeEnvelope[listData[model.LongLivedCredential]](t, a.mei.do(http.MethodGet, llPath, nil))
	raw, _ := json.Marshal(list)
	if list.Total != 1 || strings.Contains(string(raw), secret.AccessKeySecret) {
		t.Fatalf("list %s", raw)
	}
	if ev := a.lastEvent("long_lived.created"); ev.Severity != "critical" {
		t.Fatalf("created event %+v", ev)
	}

	// Revoked by its owner: gone in the cloud.
	rec = a.mei.do(http.MethodPost, llPath+"/"+secret.Credential.ID+"/revoke", nil)
	requireStatus(t, rec, http.StatusOK)
	if a.llStatus(secret.Credential.ID) != model.LongLivedRevoked {
		t.Fatal("not revoked")
	}
	if c := rawRequest(t, h, http.MethodGet, "/mock-cloud/v1/ecs/instances/i-2ze0demo001", secret.AccessKeySecret, nil).Code; c != http.StatusUnauthorized {
		t.Fatalf("a revoked key: %d", c)
	}
	a.verifyAudit()
}

func TestLongLivedAgentRequestGivesOnlyALink(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	a.enableLongLived()
	rec := a.do(http.MethodPost, "/api/v1/agent/long-lived", a.token, llInput())
	requireStatus(t, rec, http.StatusCreated)
	body := rec.Body.String()
	out := decodeEnvelope[model.LongLivedRequestResult](t, rec)
	if out.Status != model.LongLivedPending || strings.Contains(body, "secret") || !strings.Contains(out.Link, longLivedLinkPrefix) {
		t.Fatalf("agent answer %s", body)
	}
	_, key, _ := strings.Cut(out.Link, longLivedLinkPrefix)
	secret := a.createLongLived(key) // the owner confirms
	if secret.Credential.AgentName != "mei-agent" {
		t.Fatalf("who asked: %+v", secret.Credential)
	}
	// An agent whose owner is not allowed is refused.
	jun := a.addPerson(a.sup, "jun", false)
	requireStatus(t, a.sup.do(http.MethodPut, supAccounts+"/"+a.providerID+"/people/"+jun.person.ID, model.PutBindingInput{Role: model.RoleMember}), http.StatusOK)
	_, junToken := a.signInAgent(jun, "jun-agent")
	requireStatus(t, a.do(http.MethodPost, "/api/v1/agent/long-lived", junToken, llInput()), http.StatusForbidden)
}

// Deleted at once when the owner may no longer hold it.
func TestLongLivedIsDeletedWhenTheOwnerLosesTheRight(t *testing.T) {
	no := false
	suspended, active := model.PersonSuspended, model.PersonActive
	disabled := model.ProviderDisabled
	for name, take := range map[string]func(a *accessEnv){
		"role removed": func(a *accessEnv) { a.unbind(a.mei) },
		"flag removed": func(a *accessEnv) {
			requireStatus(a.t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{LongLived: &no}), http.StatusOK)
		},
		"suspended": func(a *accessEnv) {
			requireStatus(a.t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
			requireStatus(a.t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{Status: &active}), http.StatusOK)
		},
		"reset": func(a *accessEnv) {
			requireStatus(a.t, a.sup.do(http.MethodPost, "/api/v1/supervisor/people/"+a.mei.person.ID+"/reset", nil), http.StatusOK)
		},
		"account disabled": func(a *accessEnv) {
			requireStatus(a.t, a.sup.do(http.MethodPatch, supAccounts+"/"+a.providerID, model.UpdateProviderInput{Status: &disabled}), http.StatusOK)
		},
	} {
		t.Run(name, func(t *testing.T) {
			a := newAccessEnv(t, model.RoleMember)
			a.enableLongLived()
			_, key := a.askLongLived(llInput())
			secret := a.createLongLived(key)
			take(a)
			if got := a.llStatus(secret.Credential.ID); got != model.LongLivedRevoked {
				t.Fatalf("status %s", got)
			}
			if ev := a.lastEvent("long_lived.revoked"); !strings.HasPrefix(ev.Metadata["reason"].(string), "automatic:") {
				t.Fatalf("event %+v", ev)
			}
		})
	}
	// A lower role that still permits the permission keeps it.
	a := newAccessEnv(t, model.RoleMember)
	a.enableLongLived()
	_, key := a.askLongLived(llInput())
	secret := a.createLongLived(key)
	a.bind(a.mei, model.RoleGuest)
	if got := a.llStatus(secret.Credential.ID); got != model.LongLivedActive {
		t.Fatalf("a read key under guest: %s", got)
	}
	// While it exists, the account's second key cannot be removed.
	requireStatus(t, a.sup.do(http.MethodDelete, supAccounts+"/"+a.providerID+"/user-admin", nil), http.StatusConflict)
}

// fakeUserAdmin records calls and can fail.
type fakeUserAdmin struct {
	mu                   sync.Mutex
	createErr, deleteErr error
	deleted              []string
}

func (f *fakeUserAdmin) CreateUser(_ context.Context, req provider.UserRequest) (provider.UserCreated, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return provider.UserCreated{}, f.createErr
	}
	name := provider.CloudUserName(req.CredentialID)
	return provider.UserCreated{UserName: name, PolicyName: name, AccessKeyID: "LTAIFAKELONG", AccessKeySecret: "fake-long-secret"}, nil
}

func (f *fakeUserAdmin) DeleteUser(_ context.Context, req provider.UserRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, req.UserName+"/"+req.PolicyName+"/"+req.AccessKeyID)
	return nil
}

func (f *fakeUserAdmin) Test(context.Context, provider.UserRequest) error { return nil }

func TestLongLivedCloudFailures(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	fake := &fakeUserAdmin{}
	a.srv.userAdminFactory = func(model.Provider) (provider.UserAdmin, error) { return fake, nil }
	a.enableLongLived()

	fake.createErr = errors.New("AccessDenied: not allowed to create users")
	_, key := a.askLongLived(llInput())
	rec := a.mei.do(http.MethodPost, "/api/v1/me/long-lived-requests/"+key+"/create", nil)
	requireStatus(t, rec, http.StatusBadGateway)
	rows, _ := a.srv.db.ListLongLived(context.Background(), store.LongLivedFilter{OwnerID: a.mei.person.ID})
	if len(rows) != 1 || rows[0].Status != model.LongLivedFailed || !strings.Contains(rows[0].FailureReason, "AccessDenied") {
		t.Fatalf("failed request %+v", rows)
	}

	fake.createErr = nil
	_, key = a.askLongLived(llInput())
	secret := a.createLongLived(key)
	// A deletion that fails is recorded, never shown as gone, and can be retried.
	fake.deleteErr = errors.New("Throttling: slow down")
	requireStatus(t, a.mei.do(http.MethodPost, llPath+"/"+secret.Credential.ID+"/revoke", nil), http.StatusOK)
	if a.llStatus(secret.Credential.ID) != model.LongLivedRevokeFailed {
		t.Fatal("a failed deletion shown as revoked")
	}
	if ev := a.lastEvent("long_lived.revoke_failed"); ev.Severity != "critical" || !strings.Contains(ev.Metadata["failure"].(string), "Throttling") {
		t.Fatalf("revoke failure audit %+v", ev)
	}
	fake.deleteErr = nil
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/supervisor/long-lived/"+secret.Credential.ID+"/revoke", nil), http.StatusOK)
	if a.llStatus(secret.Credential.ID) != model.LongLivedRevoked || len(fake.deleted) != 1 ||
		fake.deleted[0] != secret.Credential.CloudUser+"/"+secret.Credential.CloudUser+"/LTAIFAKELONG" {
		t.Fatalf("retry: %v", fake.deleted)
	}
	// Another person cannot revoke mei's.
	jun := a.addPerson(a.sup, "jun", false)
	requireStatus(t, jun.do(http.MethodPost, llPath+"/"+secret.Credential.ID+"/revoke", nil), http.StatusNotFound)
}

func TestLongLivedRequestExpiresAndCanBeDeclined(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	a.enableLongLived()
	asked, key := a.askLongLived(llInput())
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/long-lived-requests/"+key+"/deny", nil), http.StatusOK)
	if a.llStatus(asked.ID) != model.LongLivedDenied {
		t.Fatal("not denied")
	}
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/long-lived-requests/"+key+"/create", nil), http.StatusNotFound)
	asked, key = a.askLongLived(llInput())
	a.clock.Advance(20 * time.Minute)
	requireStatus(t, a.mei.do(http.MethodGet, "/api/v1/me/long-lived-requests/"+key, nil), http.StatusOK)
	a.clock.Advance(41 * time.Minute)
	a.srv.sweepOnce(context.Background())
	if a.llStatus(asked.ID) != model.LongLivedExpired {
		t.Fatalf("status %s", a.llStatus(asked.ID))
	}
	// The link key is masked in the access log path.
	if got := logPath("/api/v1/me/long-lived-requests/" + key + "/create"); got != "/api/v1/me/long-lived-requests/***/create" {
		t.Fatalf("log path %s", got)
	}
}

// Allowing a person is a raise: a command-line session needs a code.
func TestLongLivedFlagIsARaise(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	cli := a.signInCLI(a.sup)
	yes := true
	rec := cli.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{LongLived: &yes})
	requireErrorCode(t, rec, http.StatusForbidden, model.ErrCodeAuthenticatorCodeRequired)
	requireStatus(t, cli.do(http.MethodPut, supAccounts+"/"+a.providerID+"/user-admin", model.SetUserAdminKeyInput{}), http.StatusForbidden)
	if p, _ := a.srv.db.GetPerson(context.Background(), a.mei.person.ID); p.LongLived {
		t.Fatal("allowed without a code")
	}
}

// Creating checks everything again: a permission removed after asking stops it.
func TestLongLivedCreateRechecks(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	a.enableLongLived()
	asked, key := a.askLongLived(llInput())
	no := false
	requireStatus(t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{LongLived: &no}), http.StatusOK)
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/long-lived-requests/"+key+"/create", nil), http.StatusConflict)
	if a.llStatus(asked.ID) != model.LongLivedFailed {
		t.Fatalf("status %s", a.llStatus(asked.ID))
	}
}
