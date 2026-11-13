package server

import (
	"context"
	"net/http"
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
