package server

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Behaviours of the request pipeline that do not depend on who approves:
// failures of the cloud, isolation between agents, listing, cloud account
// state and restarts.

// A cloud that refuses to issue a credential leaves a failed request, never
// a credential, whether the request was automatic or approved.
func TestMintFailure(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	a.minter.setFailure(errors.New("STS boom: AccessDenied"))

	rec := a.requestRaw(a.token, accessInput("ecs", "read"))
	requireStatus(t, rec, http.StatusCreated)
	failed := decodeEnvelope[model.AccessRequest](t, rec)
	if failed.Status != model.LeaseFailed || failed.CredentialAvailable {
		t.Fatalf("request = %q credential_available=%v, want failed without a credential", failed.Status, failed.CredentialAvailable)
	}
	if !strings.Contains(failed.FailureReason, "STS boom") {
		t.Fatalf("failure_reason = %q", failed.FailureReason)
	}
	requireErrorCode(t, a.credential(failed.ID), http.StatusConflict, model.ErrCodeLeaseNotActive)
	if !a.hasAction("lease.failed") {
		t.Fatal("missing lease.failed audit event")
	}

	// A failure at approval: 200 with a failed request and no credential.
	a.minter.setFailure(nil)
	pending := a.request(accessInput("ecs", "write"))
	a.minter.setFailure(errors.New("STS\ninjected\nnewline"))
	approved := a.approve(a.mei, pending.ID)
	requireStatus(t, approved, http.StatusOK)
	got := decodeEnvelope[model.AccessRequest](t, approved)
	if got.Status != model.LeaseFailed || got.CredentialAvailable {
		t.Fatalf("approved request = %q credential_available=%v, want failed", got.Status, got.CredentialAvailable)
	}
	if strings.ContainsAny(got.FailureReason, "\n\r") {
		t.Fatalf("failure_reason is not sanitized: %q", got.FailureReason)
	}
	requireErrorCode(t, a.credential(pending.ID), http.StatusConflict, model.ErrCodeLeaseNotActive)
	// A failed request cannot be approved again.
	a.minter.setFailure(nil)
	requireStatus(t, a.approve(a.mei, pending.ID), http.StatusConflict)
	a.verifyAudit()
}

// One agent never sees, fetches or revokes another agent's request, not even
// another agent of the same person.
func TestAgentIsolation(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	jun := a.addPerson(a.sup, "jun", false)
	a.bind(jun, model.RoleAdministrator)
	_, junToken := a.signInAgent(jun, "jun-agent")
	_, siblingToken := a.signInAgent(a.mei, "mei-second-agent")
	req := a.request(accessInput("ecs", "read"))

	for name, token := range map[string]string{"another person's agent": junToken, "the owner's other agent": siblingToken} {
		for _, call := range []struct{ method, path string }{
			{http.MethodGet, "/api/v1/agent/access-requests/" + req.ID},
			{http.MethodGet, "/api/v1/agent/leases/" + req.ID},
			{http.MethodPost, "/api/v1/agent/leases/" + req.ID + "/credential"},
			{http.MethodPost, "/api/v1/agent/leases/" + req.ID + "/revoke"},
		} {
			if rec := a.do(call.method, call.path, token, nil); rec.Code != http.StatusNotFound {
				t.Errorf("%s: %s %s = %d, want 404", name, call.method, call.path, rec.Code)
			}
		}
		rec := a.do(http.MethodGet, "/api/v1/agent/leases", token, nil)
		requireStatus(t, rec, http.StatusOK)
		if list := decodeEnvelope[listData[model.Lease]](t, rec); list.Total != 0 || len(list.Items) != 0 {
			t.Errorf("%s lists %d requests of another agent", name, list.Total)
		}
	}
	if a.status(req.ID) != model.LeaseActive {
		t.Fatal("another agent changed the request")
	}
	requireStatus(t, a.credential(req.ID), http.StatusOK)
}

func TestAgentLeaseListFilters(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	active := a.request(accessInput("ecs", "read"))
	pending := a.request(accessInput("ecs", "write"))
	denied := a.request(accessInput("ecs", "full"))
	if active.Status != model.LeaseActive || pending.Status != model.LeasePending || denied.Status != model.LeaseDenied {
		t.Fatalf("setup = %s/%s/%s", active.Status, pending.Status, denied.Status)
	}
	list := func(query string) listData[model.Lease] {
		rec := a.do(http.MethodGet, "/api/v1/agent/leases"+query, a.token, nil)
		requireStatus(t, rec, http.StatusOK)
		return decodeEnvelope[listData[model.Lease]](t, rec)
	}
	if all := list(""); all.Total != 3 || len(all.Items) != 3 {
		t.Fatalf("all = %d", all.Total)
	}
	for status, want := range map[string]string{"active": active.ID, "pending": pending.ID, "denied": denied.ID} {
		got := list("?status=" + status)
		if got.Total != 1 || got.Items[0].ID != want {
			t.Fatalf("status=%s lists %+v", status, got)
		}
	}
	if got := list("?status=revoked"); got.Total != 0 {
		t.Fatalf("status=revoked lists %d", got.Total)
	}
	if page := list("?limit=2&offset=2"); page.Total != 3 || len(page.Items) != 1 {
		t.Fatalf("paging = total %d, %d items", page.Total, len(page.Items))
	}
	requireStatus(t, a.do(http.MethodGet, "/api/v1/agent/leases?status=nonsense", a.token, nil), http.StatusBadRequest)
}

// Disabling a cloud account stops what it issued and issues nothing new;
// enabling it again does not bring anything back.
func TestDisabledAccountStopsEverything(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	active := a.request(accessInput("ecs", "read"))
	pending := a.request(accessInput("ecs", "write"))
	account := "/api/v1/supervisor/accounts/" + a.providerID

	requireStatus(t, a.sup.do(http.MethodPatch, account, map[string]any{"status": "disabled"}), http.StatusOK)
	for _, id := range []string{active.ID, pending.ID} {
		if got := a.status(id); got != model.LeaseRevoked {
			t.Fatalf("request %s after disabling the account = %s", id, got)
		}
	}
	if rec := a.credential(active.ID); rec.Code == http.StatusOK {
		t.Fatal("a disabled account handed out a credential")
	}
	requireStatus(t, a.approve(a.mei, pending.ID), http.StatusConflict)
	before := a.leaseCount()
	requireErrorCode(t, a.requestRaw(a.token, accessInput("ecs", "read")), http.StatusConflict, model.ErrCodeConflict)
	if a.leaseCount() != before || a.minter.requestCount() != 1 {
		t.Fatal("a disabled account accepted a request")
	}
	rec := a.do(http.MethodGet, "/api/v1/agent/accounts", a.token, nil)
	if decodeEnvelope[listData[model.AgentAccount]](t, rec).Total != 0 {
		t.Fatal("a disabled account is offered to the agent")
	}

	requireStatus(t, a.sup.do(http.MethodPatch, account, map[string]any{"status": "active"}), http.StatusOK)
	if a.status(active.ID) != model.LeaseRevoked || a.status(pending.ID) != model.LeaseRevoked {
		t.Fatal("enabling the account brought a revoked request back")
	}
	if again := a.request(accessInput("ecs", "read")); again.Status != model.LeaseActive {
		t.Fatalf("request after enabling = %s", again.Status)
	}
}

// Rotating the account's own AccessKey does not touch credentials already
// issued, and later requests use the new key.
func TestRotationKeepsIssuedCredentials(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	before := a.request(accessInput("ecs", "read"))
	first, rec := a.fetchCredential(a.token, before.ID)
	requireStatus(t, rec, http.StatusOK)

	rotate := model.RotateProviderCredentialInput{AccessKeyID: "LTAI5tRotatedKeyId77", AccessKeySecret: "rotated-secret-value-for-test"}
	rec = a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts/"+a.providerID+"/rotate", rotate)
	requireStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), rotate.AccessKeySecret) || strings.Contains(rec.Body.String(), rotate.AccessKeyID) {
		t.Fatal("rotate response carries the new key")
	}

	if a.status(before.ID) != model.LeaseActive {
		t.Fatalf("issued credential after rotation = %s", a.status(before.ID))
	}
	again, rec := a.fetchCredential(a.token, before.ID)
	requireStatus(t, rec, http.StatusOK)
	if again.Credential.AccessKeyID != first.Credential.AccessKeyID || again.Credential.AccessKeySecret != first.Credential.AccessKeySecret {
		t.Fatal("rotation changed a credential that was already issued")
	}
	a.minter.mu.Lock()
	a.minter.requests = nil
	a.minter.mu.Unlock()
	after := a.request(accessInput("oss", "read"))
	if after.Status != model.LeaseActive {
		t.Fatalf("request after rotation = %s", after.Status)
	}
	if got := a.minter.lastRequest(t).BrokerAccessKeyID; got != rotate.AccessKeyID {
		t.Fatalf("credential minted with key %q, want the rotated one", got)
	}
	if ev := a.lastEvent("provider.credential_rotated"); ev.ActorID != a.sup.person.ID {
		t.Fatalf("rotation attributed to %s", ev.ActorID)
	}
}

func TestAccountValidation(t *testing.T) {
	a := newAccessEnv(t, "")
	base := func() map[string]any {
		return map[string]any{"name": "x", "type": "aliyun", "mode": "sts", "region": "cn-hangzhou",
			"role_arn": "acs:ram::6543210987654321:role/csg", "access_key_id": "LTAI5tValidationKey1", "access_key_secret": "placeholder-secret-value"}
	}
	for name, change := range map[string]func(map[string]any){
		"unknown type":         func(m map[string]any) { m["type"] = "aws" },
		"unknown mode":         func(m map[string]any) { m["mode"] = "static" },
		"no region":            func(m map[string]any) { m["region"] = " " },
		"sts without key id":   func(m map[string]any) { m["access_key_id"] = "" },
		"sts without secret":   func(m map[string]any) { m["access_key_secret"] = "" },
		"sts without role":     func(m map[string]any) { m["role_arn"] = "" },
		"mock without a role":  func(m map[string]any) { m["mode"], m["role_arn"] = "mock", "" },
		"role of another kind": func(m map[string]any) { m["role_arn"] = "acs:ram::6543210987654321:user/csg" },
	} {
		body := base()
		change(body)
		if rec := a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d (%.200s)", name, rec.Code, rec.Body.String())
		}
	}
	rec := a.sup.do(http.MethodGet, "/api/v1/supervisor/accounts", nil)
	if decodeEnvelope[listData[model.Provider]](t, rec).Total != 1 {
		t.Fatal("a refused account was stored")
	}
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts", base()), http.StatusCreated)
}

// The audit chain and everything issued survive a restart.
func TestAuditAndRequestsSurviveRestart(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	active := a.request(accessInput("ecs", "read"))
	pending := a.request(accessInput("ecs", "write"))
	before := a.verifyAudit()
	if before.Events == 0 {
		t.Fatal("no audit events before the restart")
	}

	a.restart()
	after := a.verifyAudit()
	if after.Events != before.Events {
		t.Fatalf("audit chain changed across a restart: %+v -> %+v", before, after)
	}
	if a.status(active.ID) != model.LeaseActive || a.status(pending.ID) != model.LeasePending {
		t.Fatalf("requests after restart = %s/%s", a.status(active.ID), a.status(pending.ID))
	}
	requireStatus(t, a.credential(active.ID), http.StatusOK)
	// The deadline still holds after the restart.
	a.clock.Advance(11 * time.Minute)
	a.srv.sweepOnce(t.Context())
	if got := a.status(active.ID); got != model.LeaseExpired {
		t.Fatalf("credential past its deadline after a restart = %s", got)
	}
	if rec := a.credential(active.ID); rec.Code == http.StatusOK {
		t.Fatal("an expired credential was handed out")
	}
	a.verifyAudit()
}
