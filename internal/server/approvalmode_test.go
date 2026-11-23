package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Approval modes per cloud account (CONTRACT §17.11): a person's mode on an
// account, capped by their role there, decides what is issued without asking.

func modePath(providerID string) string { return "/api/v1/me/accounts/" + providerID + "/mode" }

func (a *accessEnv) setMode(p *personClient, mode model.ApprovalMode, expiresIn int) int {
	a.t.Helper()
	return p.do(http.MethodPut, modePath(a.providerID), model.SetApprovalModeInput{Mode: mode, ExpiresInSeconds: expiresIn}).Code
}

// storedMode is the person's mode on the demo account as it applies now.
func (a *accessEnv) storedMode(p *personClient) model.ApprovalMode {
	a.t.Helper()
	m, err := a.srv.db.GetAccountMode(context.Background(), p.person.ID, a.providerID)
	if err != nil {
		a.t.Fatal(err)
	}
	return m.Effective(a.clock.Now())
}

// myAccount is the demo account as GET /me/accounts shows it to p.
func (a *accessEnv) myAccount(p *personClient) model.PersonAccount {
	a.t.Helper()
	rec := p.do(http.MethodGet, "/api/v1/me/accounts", nil)
	requireStatus(a.t, rec, http.StatusOK)
	for _, acct := range decodeEnvelope[listData[model.PersonAccount]](a.t, rec).Items {
		if acct.ProviderID == a.providerID {
			return acct
		}
	}
	a.t.Fatal("demo account not listed")
	return model.PersonAccount{}
}

// addAccount creates a second mock cloud account and binds p to it.
func (a *accessEnv) addAccount(p *personClient, role model.Role) (providerID, cloudAccountID string) {
	a.t.Helper()
	rec := a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts", map[string]any{
		"name": "second", "type": "aliyun", "mode": "mock", "region": "cn-hangzhou",
		"role_arn": "acs:ram::6543210987654321:role/csg", "access_key_id": "LTAI5tNewAccount1",
		"access_key_secret": "placeholder-secret-value"})
	requireStatus(a.t, rec, http.StatusCreated)
	prov := decodeEnvelope[model.Provider](a.t, rec)
	requireStatus(a.t, a.sup.do(http.MethodPut, "/api/v1/supervisor/accounts/"+prov.ID+"/people/"+p.person.ID,
		model.PutBindingInput{Role: role}), http.StatusOK)
	return prov.ID, prov.CloudAccountID
}

// The whole table: for every mode and every permission, automatic or waiting.
func TestApprovalModeTable(t *testing.T) {
	automatic := map[model.ApprovalMode]map[string]bool{
		model.ModeRead:  {"read": true, "write": false, "full": false},
		model.ModeWrite: {"read": true, "write": true, "full": false},
		model.ModeFull:  {"read": true, "write": true, "full": true},
	}
	for mode, row := range automatic {
		for permission, auto := range row {
			t.Run(string(mode)+" mode, "+permission, func(t *testing.T) {
				a := newAccessEnv(t, model.RoleAdministrator)
				if mode != model.ModeRead {
					requireCode(t, a.setMode(a.mei, mode, 0), http.StatusOK)
				}
				req := a.request(accessInput("ecs", permission))
				want := model.LeasePending
				if auto {
					want = model.LeaseActive
				}
				if req.Status != want {
					t.Fatalf("status = %s, want %s (%+v)", req.Status, want, req.Decision.Reasons)
				}
				if auto != (a.minter.requestCount() == 1) {
					t.Fatalf("mints = %d", a.minter.requestCount())
				}
			})
		}
	}
}

// The default is read on every account.
func TestDefaultsAreTheSafest(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	if acct := a.myAccount(a.mei); acct.ApprovalMode != model.ModeRead || acct.ApprovalModeExpiresAt != nil || acct.AutomaticUpTo != "read" {
		t.Fatalf("default = %+v", acct)
	}
	if req := a.request(accessInput("ecs", "read")); req.Status != model.LeaseActive {
		t.Fatalf("read = %s", req.Status)
	}
	if req := a.request(accessInput("ecs", "write")); req.Status != model.LeasePending {
		t.Fatalf("write = %s", req.Status)
	}
}

// A mode applies to one cloud account only.
func TestModesArePerAccount(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	second, secondAccount := a.addAccount(a.mei, model.RoleAdministrator)
	requireCode(t, a.mei.do(http.MethodPut, modePath(second), model.SetApprovalModeInput{Mode: model.ModeFull}).Code, http.StatusOK)

	if req := a.request(accessInput("ecs", "write")); req.Status != model.LeasePending {
		t.Fatalf("write on the read account = %s", req.Status)
	}
	in := accessInput("dns", "write")
	in.CloudAccountID = secondAccount
	if req := a.request(in); req.Status != model.LeaseActive {
		t.Fatalf("write on the full account = %s", req.Status)
	}
	rec := a.do(http.MethodGet, "/api/v1/agent/accounts", a.token, nil)
	for _, acct := range decodeEnvelope[listData[model.AgentAccount]](t, rec).Items {
		want := "read"
		if acct.CloudAccountID == secondAccount {
			want = "full"
		}
		if acct.AutomaticUpTo != want {
			t.Fatalf("%s: automatic %s, want %s", acct.CloudAccountID, acct.AutomaticUpTo, want)
		}
	}
}

// A mode never gives more than the role.
func TestModeNeverExceedsTheRole(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	if req := a.request(accessInput("ecs", "full")); req.Status != model.LeaseDenied {
		t.Fatalf("full for a member in full mode = %s", req.Status)
	}
	if a.minter.requestCount() != 0 {
		t.Fatal("minted above the role")
	}
	if req := a.request(accessInput("ecs", "write")); req.Status != model.LeaseActive {
		t.Fatalf("write for a member in full mode = %s", req.Status)
	}
	rec := a.do(http.MethodGet, "/api/v1/agent/accounts", a.token, nil)
	acct := decodeEnvelope[listData[model.AgentAccount]](t, rec).Items[0]
	if acct.HighestPermission != "write" || acct.AutomaticUpTo != "write" {
		t.Fatalf("account view = %+v", acct)
	}
	if mine := a.myAccount(a.mei); mine.ApprovalMode != model.ModeFull || mine.AutomaticUpTo != "write" {
		t.Fatalf("person's view = %+v", mine)
	}
}

// Who may set what.
func TestOnlyThePersonSetsTheirMode(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	path := modePath(a.providerID)
	body := model.SetApprovalModeInput{Mode: model.ModeFull}

	// Not an agent token, not without a session, not without the CSRF token.
	requireStatus(t, a.do(http.MethodPut, path, a.token, body), http.StatusUnauthorized)
	requireStatus(t, a.do(http.MethodPut, path, "", body), http.StatusUnauthorized)
	requireStatus(t, a.testEnv.request(http.MethodPut, path, a.mei.cookie, nil, body), http.StatusForbidden)
	// Not on an account without a role there, nor on an unknown one.
	jun := a.addPerson(a.sup, "jun", false)
	requireStatus(t, jun.do(http.MethodPut, path, body), http.StatusNotFound)
	requireStatus(t, a.mei.do(http.MethodPut, modePath("prv_missing"), body), http.StatusNotFound)
	// A supervisor sets only their own mode: there is no route for another
	// person's mode.
	requireCode(t, a.setMode(a.sup, model.ModeFull, 0), http.StatusOK)
	if got := a.storedMode(a.mei); got != model.ModeRead {
		t.Fatalf("someone else changed mei's mode: %s", got)
	}
	for _, bad := range []model.SetApprovalModeInput{{Mode: "admin"}, {Mode: ""}, {Mode: model.ModeWrite, ExpiresInSeconds: -1},
		{Mode: model.ModeWrite, ExpiresInSeconds: 31 * 24 * 3600}} {
		requireStatus(t, a.mei.do(http.MethodPut, path, bad), http.StatusBadRequest)
	}
	// The removed routes are gone.
	for _, gone := range []string{"/api/v1/me/approval-mode", "/api/v1/supervisor/accounts/" + a.providerID + "/auto-level"} {
		if rec := a.sup.do(http.MethodPut, gone, body); rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s answers %d", gone, rec.Code)
		}
	}

	// Changes are audited, a raise as a warning, naming the account.
	requireCode(t, a.setMode(a.mei, model.ModeWrite, 0), http.StatusOK)
	requireCode(t, a.setMode(a.mei, model.ModeRead, 0), http.StatusOK)
	events := a.listAudit("person.approval_mode_changed")
	var mei []model.AuditEvent
	for _, ev := range events {
		if ev.ActorID == a.mei.person.ID {
			mei = append(mei, ev)
		}
	}
	if len(mei) != 2 || mei[1].Severity != "warning" || mei[1].Metadata["mode"] != "write" || mei[1].Metadata["previous_mode"] != "read" ||
		mei[1].Metadata["cloud_account_id"] != demoAccountID || mei[0].Severity != "info" || mei[0].Metadata["mode"] != "read" {
		t.Fatalf("mode audit = %+v", mei)
	}
	a.verifyAudit()
}

// A temporary mode falls back to read at its deadline, and is shown so.
func TestTemporaryModeExpires(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	// 20 minutes: shorter than the console session's idle limit.
	requireCode(t, a.setMode(a.mei, model.ModeWrite, 1200), http.StatusOK)
	if acct := a.myAccount(a.mei); acct.ApprovalMode != model.ModeWrite || acct.ApprovalModeExpiresAt == nil {
		t.Fatalf("during the mode: %+v", acct)
	}
	if req := a.request(accessInput("ecs", "write")); req.Status != model.LeaseActive {
		t.Fatalf("write during the mode = %s", req.Status)
	}
	a.clock.Advance(20 * time.Minute)
	if req := a.request(accessInput("dns", "write")); req.Status != model.LeasePending {
		t.Fatalf("write after the mode expired = %s", req.Status)
	}
	rec := a.do(http.MethodGet, "/api/v1/agent/accounts", a.token, nil)
	if acct := decodeEnvelope[listData[model.AgentAccount]](t, rec).Items[0]; acct.AutomaticUpTo != "read" {
		t.Fatalf("automatic after expiry = %s", acct.AutomaticUpTo)
	}
	if acct := a.myAccount(a.mei); acct.ApprovalMode != model.ModeRead || acct.ApprovalModeExpiresAt != nil {
		t.Fatalf("shown after expiry: %+v", acct)
	}
}

// Changing a mode later does not touch what already exists; a reset, or
// losing the role, brings the mode back to read.
func TestModeChangesAreNotRetroactive(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	waiting := a.request(accessInput("ecs", "write"))
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	if a.status(waiting.ID) != model.LeasePending {
		t.Fatal("raising the mode approved a waiting request")
	}
	issued := a.request(accessInput("dns", "write"))
	requireCode(t, a.setMode(a.mei, model.ModeRead, 0), http.StatusOK)
	if a.status(issued.ID) != model.LeaseActive {
		t.Fatal("lowering the mode revoked an issued credential")
	}

	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	a.unbind(a.mei)
	a.bind(a.mei, model.RoleAdministrator)
	if got := a.storedMode(a.mei); got != model.ModeRead {
		t.Fatalf("mode survived losing the role: %s", got)
	}
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/supervisor/people/"+a.mei.person.ID+"/reset", nil), http.StatusOK)
	if got := a.storedMode(a.mei); got != model.ModeRead {
		t.Fatalf("mode after a reset = %s", got)
	}
}

// The request's record and audit event say which mode decided it.
func TestAutomaticIssueRecordsWhy(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	req := a.request(accessInput("ecs", "write"))
	found := false
	for _, r := range req.Decision.Reasons {
		if r.Rule == ruleAutomatic {
			found = true
		}
	}
	if !found {
		t.Fatalf("decision reasons = %+v", req.Decision.Reasons)
	}
	for _, ev := range a.listAudit("lease.requested") {
		if ev.TargetID == req.ID {
			if ev.Metadata["approval_mode"] != "full" {
				t.Fatalf("audit metadata = %+v", ev.Metadata)
			}
			return
		}
	}
	t.Fatal("no lease.requested event")
}

func TestEffectiveAccountMode(t *testing.T) {
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	later, earlier := now.Add(time.Minute), now.Add(-time.Minute)
	for name, tc := range map[string]struct {
		m    model.AccountMode
		want model.ApprovalMode
	}{
		"write":             {model.AccountMode{Mode: model.ModeWrite}, model.ModeWrite},
		"full until later":  {model.AccountMode{Mode: model.ModeFull, ExpiresAt: &later}, model.ModeFull},
		"full, expired":     {model.AccountMode{Mode: model.ModeFull, ExpiresAt: &earlier}, model.ModeRead},
		"expires right now": {model.AccountMode{Mode: model.ModeFull, ExpiresAt: &now}, model.ModeRead},
		"unknown value":     {model.AccountMode{Mode: "admin"}, model.ModeRead},
		"empty":             {model.AccountMode{}, model.ModeRead},
	} {
		if got := tc.m.Effective(now); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
}

func requireCode(t *testing.T, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

// A damaged or unknown stored mode counts as read, never as more.
func TestUnknownStoredModeCountsAsRead(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	if _, err := a.srv.db.SQL().Exec(`UPDATE account_modes SET mode = 'everything'`); err != nil {
		t.Fatal(err)
	}
	if req := a.request(accessInput("ecs", "write")); req.Status != model.LeasePending {
		t.Fatalf("write under an unknown mode = %s", req.Status)
	}
}

// The agent learns how far it is issued automatically, never the owner's
// mode itself.
func TestAgentNeverSeesTheMode(t *testing.T) {
	a := newAccessEnv(t, model.RoleGuest)
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	rec := a.requestRaw(a.token, accessInput("ecs", "read"))
	requireStatus(t, rec, http.StatusCreated)
	id := decodeEnvelope[model.AccessRequest](t, rec).ID
	bodies := map[string]string{"create": rec.Body.String()}
	for _, path := range []string{"/api/v1/agent/access-requests/" + id, "/api/v1/agent/leases/" + id, "/api/v1/agent/leases", "/api/v1/agent/accounts"} {
		r := a.do(http.MethodGet, path, a.token, nil)
		requireStatus(t, r, http.StatusOK)
		bodies[path] = r.Body.String()
	}
	for where, body := range bodies {
		for _, leak := range []string{"owner's mode", "approval_mode", `"full"`} {
			if strings.Contains(body, leak) {
				t.Errorf("%s shows %s to the agent", where, leak)
			}
		}
	}
	for _, ev := range a.listAudit("lease.requested") {
		if ev.TargetID == id && ev.Metadata["approval_mode"] != "full" {
			t.Fatalf("audit lost the mode: %+v", ev.Metadata)
		}
	}
}

// The route refuses requests without the CSRF token or from another origin.
func TestModeRouteNeedsCSRFAndSameOrigin(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	path, body := modePath(a.providerID), model.SetApprovalModeInput{Mode: model.ModeFull}
	requireStatus(t, a.testEnv.request(http.MethodPut, path, a.mei.cookie, nil, body), http.StatusForbidden)
	requireStatus(t, a.testEnv.request(http.MethodPut, path, a.mei.cookie,
		map[string]string{csrfHeader: a.mei.csrf, "Origin": "https://evil.example"}, body), http.StatusForbidden)
	if got := a.storedMode(a.mei); got != model.ModeRead {
		t.Fatalf("a refused request changed the mode: %s", got)
	}
}

// Resetting a person or recovering a supervisor puts every mode back to read,
// and the audit event says from what.
func TestResetAndRecoveryRecordTheModesTheyClear(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/supervisor/people/"+a.mei.person.ID+"/reset", nil), http.StatusOK)
	ev := a.listAudit("person.setup_reset")
	if len(ev) != 1 || ev[0].Metadata["mode"] != "read" {
		t.Fatalf("reset audit = %+v", ev)
	}
	if prev, _ := ev[0].Metadata["previous_modes"].(map[string]any); prev[demoAccountID] != "full" {
		t.Fatalf("reset audit previous modes = %+v", ev[0].Metadata)
	}

	requireCode(t, a.setMode(a.sup, model.ModeWrite, 0), http.StatusOK)
	if _, err := RecoverSupervisor(context.Background(), RecoverOptions{DataDir: a.dir, Username: a.sup.person.Username}); err != nil {
		t.Fatal(err)
	}
	ev = a.listAudit("person.supervisor_recovered")
	if len(ev) != 1 || ev[0].Metadata["mode"] != "read" {
		t.Fatalf("recovery audit = %+v", ev)
	}
	if prev, _ := ev[0].Metadata["previous_modes"].(map[string]any); prev[demoAccountID] != "write" {
		t.Fatalf("recovery audit previous modes = %+v", ev[0].Metadata)
	}
	if got := a.storedMode(a.sup); got != model.ModeRead {
		t.Fatalf("mode after recovery = %s", got)
	}
}

// A suspension puts every mode back to read; removed modes are audited.
func TestSuspensionAndRoleRemovalClearModesAndSaySo(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	suspended, active := model.PersonSuspended, model.PersonActive
	requireStatus(t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
	requireStatus(t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{Status: &active}), http.StatusOK)
	if got := a.storedMode(a.mei); got != model.ModeRead {
		t.Fatalf("mode after suspension and reactivation = %s", got)
	}
	ev := a.listAudit("person.status_changed")
	var found bool
	for _, e := range ev {
		if removed, _ := e.Metadata["removed_modes"].(map[string]any); removed[demoAccountID] == "full" {
			found = true
		}
	}
	if !found {
		t.Fatalf("suspension audit does not list the removed mode: %+v", ev)
	}

	mei := a.loginAgain(a.mei)
	requireCode(t, a.setMode(mei, model.ModeWrite, 0), http.StatusOK)
	a.unbind(mei)
	removed := a.listAudit("binding.removed")
	if len(removed) == 0 {
		t.Fatal("no binding.removed event")
	}
	if m, _ := removed[0].Metadata["removed_modes"].(map[string]any); m[demoAccountID] != "write" {
		t.Fatalf("binding.removed audit = %+v", removed[0].Metadata)
	}
}

// loginAgain signs p in again (a suspension ended their session).
func (a *accessEnv) loginAgain(p *personClient) *personClient {
	a.t.Helper()
	a.nextStep()
	rec := a.login(p.person.Username, testPassword, a.totp(p.secret, 0))
	requireStatus(a.t, rec, http.StatusOK)
	info := decodeEnvelope[model.SessionInfo](a.t, rec)
	return &personClient{env: a.testEnv, cookie: sessionCookie(rec), csrf: info.CSRFToken, secret: p.secret, person: p.person}
}
