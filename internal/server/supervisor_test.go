package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Supervisors run cloud accounts, settings, audit and the emergency stop
// from their console session (CONTRACT §17.8).

const supAccounts = "/api/v1/supervisor/accounts"

func newMockAccount(name, accountID string) model.CreateProviderInput {
	return model.CreateProviderInput{Name: name, Type: model.ProviderAliyun, Mode: model.ModeMock, Region: "cn-hangzhou",
		RoleARN: "acs:ram::" + accountID + ":role/csg", AccessKeyID: "LTAI5tSupervisorTest", AccessKeySecret: "placeholder-secret-value"}
}

// lastEvent returns the newest audit event of an action.
func (a *accessEnv) lastEvent(action string) model.AuditEvent {
	a.t.Helper()
	events := a.listAudit(action)
	if len(events) == 0 {
		a.t.Fatalf("no %s event", action)
	}
	return events[0]
}

func (a *accessEnv) requireActor(ev model.AuditEvent, p *personClient) {
	a.t.Helper()
	if ev.ActorType != "person" || ev.ActorID != p.person.ID || ev.ActorName != p.person.Username {
		a.t.Fatalf("%s attributed to %s %s (%s), want person %s", ev.Action, ev.ActorType, ev.ActorID, ev.ActorName, p.person.Username)
	}
}

func TestOnlySupervisorsReachTheSupervisorRoutes(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	pending := a.request(accessInput("ecs", "write"))
	routes := []struct{ method, path string }{
		{http.MethodGet, supAccounts}, {http.MethodPost, supAccounts},
		{http.MethodGet, supAccounts + "/" + a.providerID}, {http.MethodPatch, supAccounts + "/" + a.providerID},
		{http.MethodPost, supAccounts + "/" + a.providerID + "/rotate"}, {http.MethodPost, supAccounts + "/" + a.providerID + "/test"},
		{http.MethodGet, "/api/v1/supervisor/settings"}, {http.MethodPut, "/api/v1/supervisor/settings"},
		{http.MethodGet, "/api/v1/supervisor/audit"}, {http.MethodGet, "/api/v1/supervisor/audit/verify"},
		{http.MethodGet, "/api/v1/supervisor/leases"}, {http.MethodGet, "/api/v1/supervisor/leases/" + pending.ID},
		{http.MethodPost, "/api/v1/supervisor/leases/" + pending.ID + "/deny"},
		{http.MethodPost, "/api/v1/supervisor/leases/" + pending.ID + "/revoke"},
	}
	for _, r := range routes {
		if code := a.mei.do(r.method, r.path, map[string]string{"reason": "x"}).Code; code != http.StatusForbidden {
			t.Errorf("person %s %s = %d, want 403", r.method, r.path, code)
		}
		if code := a.do(r.method, r.path, a.token, nil).Code; code != http.StatusUnauthorized {
			t.Errorf("agent token %s %s = %d, want 401", r.method, r.path, code)
		}
		if code := a.do(r.method, r.path, a.adminToken, nil).Code; code != http.StatusUnauthorized {
			t.Errorf("operator token %s %s = %d, want 401", r.method, r.path, code)
		}
	}
	if a.status(pending.ID) != model.LeasePending {
		t.Fatal("a refused call changed the request")
	}
	// Writes need the CSRF token.
	rec := a.testEnv.request(http.MethodPost, supAccounts, a.sup.cookie, nil, newMockAccount("x", "6543210987654321"))
	requireStatus(t, rec, http.StatusForbidden)
}

func TestSupervisorManagesCloudAccounts(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	read := a.request(accessInput("ecs", "read"))

	rec := a.sup.do(http.MethodGet, supAccounts, nil)
	requireStatus(t, rec, http.StatusOK)
	list := decodeEnvelope[listData[model.Provider]](t, rec)
	if list.Total != 1 || list.Items[0].CloudAccountID != demoAccountID || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("account list = %s", rec.Body.String())
	}

	rec = a.sup.do(http.MethodPost, supAccounts, newMockAccount("staging", "6543210987654321"))
	requireStatus(t, rec, http.StatusCreated)
	created := decodeEnvelope[model.Provider](t, rec)
	if created.CloudAccountID != "6543210987654321" || created.MaxAutoLevel != model.ModeRead || strings.Contains(rec.Body.String(), "placeholder-secret-value") {
		t.Fatalf("created = %s", rec.Body.String())
	}
	a.requireActor(a.lastEvent("provider.created"), a.sup)
	// Creating an account gives nobody a role on it, not even its creator.
	if b, _ := a.srv.db.ListBindings(context.Background(), "", created.ID); len(b) != 0 {
		t.Fatalf("bindings on a new account: %+v", b)
	}
	requireStatus(t, a.sup.do(http.MethodPost, supAccounts, newMockAccount("dup", "6543210987654321")), http.StatusConflict)

	requireStatus(t, a.sup.do(http.MethodPost, supAccounts+"/"+created.ID+"/test", nil), http.StatusOK)
	requireStatus(t, a.sup.do(http.MethodPost, supAccounts+"/"+created.ID+"/rotate",
		model.RotateProviderCredentialInput{AccessKeyID: "LTAI5tRotatedKeyId1", AccessKeySecret: "another-placeholder"}), http.StatusOK)
	a.requireActor(a.lastEvent("provider.credential_rotated"), a.sup)

	// Disabling the account stops the credentials issued on it, and the
	// revocation names the supervisor.
	disabled := model.ProviderDisabled
	requireStatus(t, a.sup.do(http.MethodPatch, supAccounts+"/"+a.providerID, model.UpdateProviderInput{Status: &disabled}), http.StatusOK)
	if a.status(read.ID) != model.LeaseRevoked {
		t.Fatalf("credential after disabling its account = %s", a.status(read.ID))
	}
	ev := a.lastEvent("lease.revoked")
	a.requireActor(ev, a.sup)
	if ev.TargetID != read.ID {
		t.Fatalf("revocation event for %s", ev.TargetID)
	}
	a.requireActor(a.lastEvent("provider.updated"), a.sup)
	a.verifyAudit()
}

// Supervisors can stop any request or credential, never grant one.
func TestSupervisorEmergencyStop(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	active := a.request(accessInput("ecs", "read"))
	pending := a.request(accessInput("dns", "write"))

	rec := a.sup.do(http.MethodGet, "/api/v1/supervisor/leases", nil)
	requireStatus(t, rec, http.StatusOK)
	if list := decodeEnvelope[listData[model.Lease]](t, rec); list.Total != 2 {
		t.Fatalf("lease list total = %d", list.Total)
	}

	// There is no approve route for supervisors.
	for _, path := range []string{"/api/v1/supervisor/leases/" + pending.ID + "/approve", "/api/v1/supervisor/requests/" + pending.ID + "/approve"} {
		if code := a.sup.do(http.MethodPost, path, nil).Code; code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d", path, code)
		}
	}
	if a.status(pending.ID) != model.LeasePending || a.minter.requestCount() != 1 {
		t.Fatal("a supervisor approved a request")
	}

	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/supervisor/leases/"+pending.ID+"/deny", model.DenyLeaseInput{Reason: "incident"}), http.StatusOK)
	if a.status(pending.ID) != model.LeaseDenied {
		t.Fatalf("pending after deny = %s", a.status(pending.ID))
	}
	a.requireActor(a.lastEvent("lease.denied"), a.sup)

	rec = a.sup.do(http.MethodPost, "/api/v1/supervisor/leases/"+active.ID+"/revoke", nil)
	requireStatus(t, rec, http.StatusOK)
	if got := decodeEnvelope[model.Lease](t, rec); got.Status != model.LeaseRevoked || got.RevokeReason != "revoked by supervisor admin" {
		t.Fatalf("revoked = %s %q", got.Status, got.RevokeReason)
	}
	if rec := a.credential(active.ID); rec.Code == http.StatusOK {
		t.Fatal("credential handed out after a supervisor revoked it")
	}
	ev := a.lastEvent("lease.revoked")
	a.requireActor(ev, a.sup)
	if ev.Metadata["actor"] != "person:"+a.sup.person.ID {
		t.Fatalf("revoke actor = %v", ev.Metadata["actor"])
	}
	// The owner cannot bring a denied request back.
	requireStatus(t, a.approve(a.mei, pending.ID), http.StatusConflict)
}

func TestSupervisorSettingsAndAudit(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	rec := a.sup.do(http.MethodGet, "/api/v1/supervisor/settings", nil)
	requireStatus(t, rec, http.StatusOK)
	settings := decodeEnvelope[model.PolicySettings](t, rec)

	bad := settings
	bad.LeasesPerMinutePerAgent = 0
	requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/settings", bad), http.StatusBadRequest)
	settings.LeasesPerMinutePerAgent = 20
	requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/settings", settings), http.StatusOK)
	if got, _ := a.srv.db.GetPolicySettings(context.Background()); got.LeasesPerMinutePerAgent != 20 {
		t.Fatalf("settings not stored: %+v", got)
	}
	a.requireActor(a.lastEvent("policy.updated"), a.sup)

	rec = a.sup.do(http.MethodGet, "/api/v1/supervisor/audit?action=policy.updated", nil)
	requireStatus(t, rec, http.StatusOK)
	if list := decodeEnvelope[listData[model.AuditEvent]](t, rec); list.Total != 1 || list.Items[0].ActorID != a.sup.person.ID {
		t.Fatalf("audit list = %+v", list)
	}
	rec = a.sup.do(http.MethodGet, "/api/v1/supervisor/audit/verify", nil)
	requireStatus(t, rec, http.StatusOK)
	if v := decodeEnvelope[model.AuditVerifyResult](t, rec); !v.OK {
		t.Fatalf("audit verify = %+v", v)
	}
}

// The operator token keeps working, recorded as the operator, until it is
// removed.
func TestOperatorTokenIsStillRecordedAsOperator(t *testing.T) {
	a := newAccessEnv(t, "")
	requireStatus(t, a.admin(http.MethodPost, "/api/v1/admin/providers", newMockAccount("ops", "6543210987654321")), http.StatusCreated)
	if ev := a.lastEvent("provider.created"); ev.ActorType != "admin" || ev.ActorName != "operator" {
		t.Fatalf("operator action attributed to %s %s", ev.ActorType, ev.ActorName)
	}
}

// Each person sees only their own accounts, with what their agents get there.
func TestMyAccounts(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	requireStatus(t, a.sup.do(http.MethodPost, supAccounts, newMockAccount("staging", "6543210987654321")), http.StatusCreated)

	rec := a.mei.do(http.MethodGet, "/api/v1/me/accounts", nil)
	requireStatus(t, rec, http.StatusOK)
	list := decodeEnvelope[listData[model.PersonAccount]](t, rec)
	if list.Total != 1 {
		t.Fatalf("mei sees %d accounts", list.Total)
	}
	acct := list.Items[0]
	if acct.CloudAccountID != demoAccountID || acct.Role != model.RoleMember || acct.HighestPermission != "write" ||
		acct.MaxAutoLevel != model.ModeRead || acct.AutomaticUpTo != "read" || acct.ProviderID != a.providerID {
		t.Fatalf("account = %+v", acct)
	}

	// Mode and level raise what is automatic, up to the role.
	requireCode(t, a.setLevel(model.ModeFull), http.StatusOK)
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	rec = a.mei.do(http.MethodGet, "/api/v1/me/accounts", nil)
	if acct := decodeEnvelope[listData[model.PersonAccount]](t, rec).Items[0]; acct.AutomaticUpTo != "write" || acct.MaxAutoLevel != model.ModeFull {
		t.Fatalf("after raising = %+v", acct)
	}

	// A supervisor without a role sees no accounts here.
	rec = a.sup.do(http.MethodGet, "/api/v1/me/accounts", nil)
	if n := decodeEnvelope[listData[model.PersonAccount]](t, rec).Total; n != 0 {
		t.Fatalf("supervisor without a role sees %d accounts", n)
	}
	requireStatus(t, a.do(http.MethodGet, "/api/v1/me/accounts", a.token, nil), http.StatusUnauthorized)
}

// ---- regression tests for the independent review of commit 7d486a5 ----

// A browser that goes away right after an authority change is written must
// not stop the sweep and the audit record that follow it.
func TestAbortedRequestStillSweepsAndAudits(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	read := a.request(accessInput("ecs", "read"))

	ctx, cancel := context.WithCancel(context.Background())
	a.srv.hookAfterAuthorityWrite = func(kind string) {
		if kind == "provider" {
			cancel() // the client disconnects right after the write
		}
	}
	disabled := model.ProviderDisabled
	body, _ := json.Marshal(model.UpdateProviderInput{Status: &disabled})
	req := httptest.NewRequest(http.MethodPatch, supAccounts+"/"+a.providerID, bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeader, a.sup.csrf)
	req.AddCookie(a.sup.cookie)
	a.srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	a.srv.hookAfterAuthorityWrite = nil

	if ctx.Err() == nil {
		t.Fatal("the hook did not run; the test did not abort the request")
	}
	if a.status(read.ID) != model.LeaseRevoked {
		t.Fatalf("credential after an aborted disable = %s", a.status(read.ID))
	}
	a.requireActor(a.lastEvent("provider.updated"), a.sup)
	a.requireActor(a.lastEvent("lease.revoked"), a.sup)
}

// The same for a settings change, cancelled before the handler starts.
func TestCancelledSettingsChangeIsStillAudited(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	settings, _ := a.srv.db.GetPolicySettings(context.Background())
	settings.LeasesPerMinutePerAgent = 21
	body, _ := json.Marshal(settings)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/supervisor/settings", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(csrfHeader, a.sup.csrf)
	req.AddCookie(a.sup.cookie)
	a.srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
	if got, _ := a.srv.db.GetPolicySettings(context.Background()); got.LeasesPerMinutePerAgent != 21 {
		t.Fatalf("settings = %d", got.LeasesPerMinutePerAgent)
	}
	a.requireActor(a.lastEvent("policy.updated"), a.sup)
}

// Deny and revoke events name the agent and its owner; settings-induced
// revocations name the supervisor.
func TestStopEventsNameAgentOwnerAndSupervisor(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	pending := a.request(accessInput("ecs", "write"))
	active := a.request(accessInput("dns", "read"))
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/supervisor/leases/"+pending.ID+"/deny", model.DenyLeaseInput{Reason: "no"}), http.StatusOK)
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/supervisor/leases/"+active.ID+"/revoke", nil), http.StatusOK)
	for _, action := range []string{"lease.denied", "lease.revoked"} {
		m := a.lastEvent(action).Metadata
		if m["agent_id"] != a.agent.ID || m["agent_name"] != a.agent.Name || m["owner_id"] != a.mei.person.ID {
			t.Errorf("%s metadata = %+v", action, m)
		}
	}

	// Lowering the validity ceiling below an active credential revokes it,
	// in the supervisor's name.
	again := a.request(accessInput("oss", "read"))
	settings, _ := a.srv.db.GetPolicySettings(context.Background())
	settings.AutoApproveMaxTTLSeconds = 300
	settings.MaxLeaseTTLSeconds = 300
	requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/settings", settings), http.StatusOK)
	if a.status(again.ID) != model.LeaseRevoked {
		t.Fatalf("credential above the new ceiling = %s", a.status(again.ID))
	}
	ev := a.lastEvent("lease.revoked")
	a.requireActor(ev, a.sup)
	if ev.TargetID != again.ID || ev.Metadata["agent_id"] != a.agent.ID {
		t.Fatalf("settings revocation = %+v", ev)
	}
}

// Account edits record what changed, and a role or status change is a warning.
func TestAccountEditsRecordOldAndNewValues(t *testing.T) {
	a := newAccessEnv(t, "")
	arn := "acs:ram::" + demoAccountID + ":role/another"
	requireStatus(t, a.sup.do(http.MethodPatch, supAccounts+"/"+a.providerID, model.UpdateProviderInput{RoleARN: &arn}), http.StatusOK)
	ev := a.lastEvent("provider.updated")
	changes, _ := ev.Metadata["changes"].(map[string]any)
	roleARN, _ := changes["role_arn"].(map[string]any)
	if ev.Severity != "warning" || roleARN["to"] != arn || roleARN["from"] == "" {
		t.Fatalf("role ARN change audit = %+v", ev)
	}
	region := "cn-shanghai"
	requireStatus(t, a.sup.do(http.MethodPatch, supAccounts+"/"+a.providerID, model.UpdateProviderInput{Region: &region}), http.StatusOK)
	if ev := a.lastEvent("provider.updated"); ev.Severity != "info" {
		t.Fatalf("region change severity = %s", ev.Severity)
	}
}

// A disabled account issues nothing, so it shows no automatic level.
func TestMyAccountsOnADisabledAccount(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	disabled := model.ProviderDisabled
	requireStatus(t, a.sup.do(http.MethodPatch, supAccounts+"/"+a.providerID, model.UpdateProviderInput{Status: &disabled}), http.StatusOK)
	rec := a.mei.do(http.MethodGet, "/api/v1/me/accounts", nil)
	acct := decodeEnvelope[listData[model.PersonAccount]](t, rec).Items[0]
	if acct.Status != model.ProviderDisabled || acct.AutomaticUpTo != "" {
		t.Fatalf("disabled account = %+v", acct)
	}
	if _, err := a.srv.db.SQL().Exec(`UPDATE role_bindings SET role = 'owner' WHERE person_id = ?`, a.mei.person.ID); err != nil {
		t.Fatal(err)
	}
	rec = a.mei.do(http.MethodGet, "/api/v1/me/accounts", nil)
	if acct := decodeEnvelope[listData[model.PersonAccount]](t, rec).Items[0]; acct.HighestPermission != "" || acct.AutomaticUpTo != "" {
		t.Fatalf("unknown role = %+v", acct)
	}
}

// No secret appears in any supervisor or account response.
func TestSupervisorResponsesCarryNoSecrets(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	const canaryID, canarySecret = "LTAI5tCanaryKeyIdXyz", "canary-broker-secret-value"
	in := newMockAccount("canary", "6543210987654321")
	in.AccessKeyID, in.AccessKeySecret = canaryID, canarySecret
	rec := a.sup.do(http.MethodPost, supAccounts, in)
	requireStatus(t, rec, http.StatusCreated)
	created := decodeEnvelope[model.Provider](t, rec)
	read := a.request(accessInput("ecs", "read"))
	requireStatus(t, a.credential(read.ID), http.StatusOK)
	cred, _ := a.srv.db.GetLeaseCredential(context.Background(), read.ID)

	bodies := map[string]string{"create": rec.Body.String()}
	for _, path := range []string{supAccounts, supAccounts + "/" + created.ID, "/api/v1/supervisor/audit?limit=200",
		"/api/v1/supervisor/leases", "/api/v1/supervisor/leases/" + read.ID, "/api/v1/supervisor/settings", "/api/v1/me/accounts"} {
		r := a.sup.do(http.MethodGet, path, nil)
		requireStatus(t, r, http.StatusOK)
		bodies[path] = r.Body.String()
	}
	for _, path := range []string{supAccounts + "/" + created.ID + "/test", supAccounts + "/" + created.ID + "/rotate"} {
		r := a.sup.do(http.MethodPost, path, model.RotateProviderCredentialInput{AccessKeyID: "LTAI5tRotatedCanary1", AccessKeySecret: "rotated-canary-secret"})
		bodies[path] = r.Body.String()
	}
	for where, body := range bodies {
		for _, secret := range []string{canaryID, canarySecret, "rotated-canary-secret", cred, a.token, a.sup.csrf} {
			if secret != "" && strings.Contains(body, secret) {
				t.Errorf("%s contains a secret", where)
			}
		}
	}
	// A supervisor session cannot fetch a credential.
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/agent/leases/"+read.ID+"/credential", nil), http.StatusUnauthorized)
}

// Every new write refuses a request without the CSRF token or from another
// origin.
func TestEverySupervisorWriteNeedsCSRF(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	pending := a.request(accessInput("ecs", "write"))
	writes := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, supAccounts, newMockAccount("x", "6543210987654321")},
		{http.MethodPatch, supAccounts + "/" + a.providerID, map[string]string{"status": "disabled"}},
		{http.MethodPost, supAccounts + "/" + a.providerID + "/rotate", model.RotateProviderCredentialInput{AccessKeyID: "LTAI5tRotatedKeyId2", AccessKeySecret: "x"}},
		{http.MethodPost, supAccounts + "/" + a.providerID + "/test", nil},
		{http.MethodPut, "/api/v1/supervisor/settings", model.DefaultPolicySettings()},
		{http.MethodPost, "/api/v1/supervisor/leases/" + pending.ID + "/deny", model.DenyLeaseInput{Reason: "x"}},
		{http.MethodPost, "/api/v1/supervisor/leases/" + pending.ID + "/revoke", nil},
	}
	for _, w := range writes {
		for name, headers := range map[string]map[string]string{
			"no token":     nil,
			"cross origin": {csrfHeader: a.sup.csrf, "Origin": "https://evil.example"},
		} {
			if code := a.testEnv.request(w.method, w.path, a.sup.cookie, headers, w.body).Code; code != http.StatusForbidden {
				t.Errorf("%s %s (%s) = %d", w.method, w.path, name, code)
			}
		}
	}
	prov, _ := a.srv.db.GetProvider(context.Background(), a.providerID)
	if prov.Status != model.ProviderActive || a.status(pending.ID) != model.LeasePending {
		t.Fatal("a refused write changed something")
	}
}

// Whoever holds a setup code can complete the setup, so every setup records
// who issued the code; the person and other supervisors can see it, and the
// setup-completed event names the issuer (owner's decision: accept and trace).
func TestSetupCodeIssuerIsTraced(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	issued := func(p model.Person) model.SetupIssue {
		t.Helper()
		if p.SetupIssued == nil {
			t.Fatalf("%s has no setup issuer", p.Username)
		}
		return *p.SetupIssued
	}

	// The bootstrap supervisor came from csg init.
	if got := issued(a.sup.person); got.ByID != "system" || got.Kind != model.SetupBootstrap {
		t.Fatalf("bootstrap issuer = %+v", got)
	}

	// A created person: issued by the supervisor, shown to the person.
	rec := a.sup.do(http.MethodPost, "/api/v1/supervisor/people", model.CreatePersonInput{Username: "jun"})
	requireStatus(t, rec, http.StatusCreated)
	created := decodeEnvelope[model.PersonWithSetupCode](t, rec)
	if got := issued(created.Person); got.ByID != a.sup.person.ID || got.ByName != a.sup.person.Username || got.Kind != model.SetupCreated {
		t.Fatalf("created issuer = %+v", got)
	}
	jun := a.completeSetup(created.SetupCode)
	rec = jun.do(http.MethodGet, "/api/v1/auth/me", nil)
	if got := issued(decodeEnvelope[model.SessionInfo](t, rec).Person); got.ByID != a.sup.person.ID || got.Kind != model.SetupCreated {
		t.Fatalf("/auth/me issuer = %+v", got)
	}

	// A reset used by the supervisor themselves: the account now acts as mei,
	// but the setup-completed event and mei's record name the supervisor.
	rec = a.sup.do(http.MethodPost, "/api/v1/supervisor/people/"+a.mei.person.ID+"/reset", nil)
	requireStatus(t, rec, http.StatusOK)
	reset := decodeEnvelope[model.PersonWithSetupCode](t, rec)
	a.completeSetup(reset.SetupCode)
	ev := a.lastEvent("person.setup_completed")
	if ev.ActorID != a.mei.person.ID || ev.Metadata["setup_issued_by"] != a.sup.person.ID ||
		ev.Metadata["setup_issued_by_name"] != a.sup.person.Username || ev.Metadata["setup_issued_kind"] != model.SetupReset {
		t.Fatalf("setup completed event = %+v", ev)
	}
	rec = a.sup.do(http.MethodGet, "/api/v1/supervisor/people", nil)
	for _, p := range decodeEnvelope[listData[model.Person]](t, rec).Items {
		if p.ID == a.mei.person.ID {
			if got := issued(p); got.ByID != a.sup.person.ID || got.Kind != model.SetupReset {
				t.Fatalf("people list issuer = %+v", got)
			}
		}
	}

	// Local recovery is issued by the system.
	if _, err := RecoverSupervisor(context.Background(), RecoverOptions{DataDir: a.dir, Username: a.sup.person.Username}); err != nil {
		t.Fatal(err)
	}
	p, _ := a.srv.db.GetPerson(context.Background(), a.sup.person.ID)
	if got := issued(p); got.ByID != "system" || got.Kind != model.SetupRecovered {
		t.Fatalf("recovery issuer = %+v", got)
	}
}
