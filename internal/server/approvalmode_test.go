package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Approval modes (CONTRACT §17.5): a person's mode and the cloud account's
// highest automatic level decide what is issued without asking.

func (a *accessEnv) setMode(p *personClient, mode model.ApprovalMode, expiresIn int) int {
	a.t.Helper()
	return p.do(http.MethodPut, "/api/v1/me/approval-mode", model.SetApprovalModeInput{Mode: mode, ExpiresInSeconds: expiresIn}).Code
}

func (a *accessEnv) setLevel(level model.ApprovalMode) int {
	a.t.Helper()
	return a.sup.do(http.MethodPut, "/api/v1/supervisor/accounts/"+a.providerID+"/auto-level", model.SetAutoLevelInput{MaxAutoLevel: level}).Code
}

// The whole table: for every mode and every permission, automatic or waiting,
// on an account whose level allows everything.
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
				requireCode(t, a.setLevel(model.ModeFull), http.StatusOK)
				if mode != model.ModeRead {
					if code := a.setMode(a.mei, mode, 0); code != http.StatusOK {
						t.Fatalf("set mode: %d", code)
					}
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

// The default is read mode on a read-level account: what was built before.
func TestDefaultsAreTheSafest(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	rec := a.mei.do(http.MethodGet, "/api/v1/auth/me", nil)
	if p := decodeEnvelope[model.SessionInfo](t, rec).Person; p.ApprovalMode != model.ModeRead || p.ApprovalModeExpiresAt != nil {
		t.Fatalf("default mode = %+v", p)
	}
	prov, err := a.srv.db.GetProvider(context.Background(), a.providerID)
	if err != nil || prov.MaxAutoLevel != model.ModeRead {
		t.Fatalf("default level = %q, %v", prov.MaxAutoLevel, err)
	}
	if req := a.request(accessInput("ecs", "read")); req.Status != model.LeaseActive {
		t.Fatalf("read = %s", req.Status)
	}
	if req := a.request(accessInput("ecs", "write")); req.Status != model.LeasePending {
		t.Fatalf("write = %s", req.Status)
	}
	// A new cloud account starts at read too, whatever the request says.
	rec = a.admin(http.MethodPost, "/api/v1/admin/providers", map[string]any{
		"name": "new", "type": "aliyun", "mode": "mock", "region": "cn-hangzhou",
		"role_arn": "acs:ram::6543210987654321:role/csg", "access_key_id": "LTAI5tNewAccount1",
		"access_key_secret": "placeholder-secret-value", "max_auto_level": "full"})
	requireStatus(t, rec, http.StatusCreated)
	if created := decodeEnvelope[model.Provider](t, rec); created.MaxAutoLevel != model.ModeRead {
		t.Fatalf("new account level = %q", created.MaxAutoLevel)
	}
}

// The account's level caps the person's mode, in both directions.
func TestAccountLevelCapsTheMode(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)

	// Each check ends its request, so the agent's limit on open requests
	// never decides an outcome here.
	check := func(resource, permission string, want model.LeaseStatus, what string) {
		t.Helper()
		req := a.request(accessInput(resource, permission))
		if req.Status != want {
			t.Fatalf("%s = %s (%+v)", what, req.Status, req.Decision.Reasons)
		}
		requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/requests/"+req.ID+"/revoke", nil), http.StatusOK)
	}
	// Level read (the default): full mode still asks for write.
	check("ecs", "write", model.LeasePending, "write under a read-level account")
	requireCode(t, a.setLevel(model.ModeWrite), http.StatusOK)
	check("dns", "write", model.LeaseActive, "write under a write-level account")
	check("oss", "full", model.LeasePending, "full under a write-level account")
	// A low mode is not raised by a high level.
	requireCode(t, a.setLevel(model.ModeFull), http.StatusOK)
	requireCode(t, a.setMode(a.mei, model.ModeRead, 0), http.StatusOK)
	check("ecs", "write", model.LeasePending, "write in read mode on a full-level account")
}

// A mode never gives more than the role.
func TestModeNeverExceedsTheRole(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	requireCode(t, a.setLevel(model.ModeFull), http.StatusOK)
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
	// The agent sees what it may get and what is automatic.
	rec := a.do(http.MethodGet, "/api/v1/agent/accounts", a.token, nil)
	acct := decodeEnvelope[listData[model.AgentAccount]](t, rec).Items[0]
	if acct.HighestPermission != "write" || acct.AutomaticUpTo != "write" {
		t.Fatalf("account view = %+v", acct)
	}
}

// Who may set what.
func TestOnlyTheRightPeopleSetModesAndLevels(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	path := "/api/v1/me/approval-mode"
	body := model.SetApprovalModeInput{Mode: model.ModeFull}

	// Not an agent token, not the operator, not without the CSRF token.
	requireStatus(t, a.do(http.MethodPut, path, a.token, body), http.StatusUnauthorized)
	requireStatus(t, a.admin(http.MethodPut, path, body), http.StatusUnauthorized)
	requireStatus(t, a.testEnv.request(http.MethodPut, path, a.mei.cookie, nil, body), http.StatusForbidden)
	// A supervisor sets only their own mode: there is no route for another
	// person's mode.
	requireCode(t, a.setMode(a.sup, model.ModeFull, 0), http.StatusOK)
	stored, _ := a.srv.db.GetPerson(context.Background(), a.mei.person.ID)
	if stored.ApprovalMode != model.ModeRead {
		t.Fatalf("someone else changed mei's mode: %s", stored.ApprovalMode)
	}
	for _, bad := range []model.SetApprovalModeInput{{Mode: "admin"}, {Mode: ""}, {Mode: model.ModeWrite, ExpiresInSeconds: -1},
		{Mode: model.ModeWrite, ExpiresInSeconds: 31 * 24 * 3600}} {
		requireStatus(t, a.mei.do(http.MethodPut, path, bad), http.StatusBadRequest)
	}

	// The account level: supervisors only.
	level := "/api/v1/supervisor/accounts/" + a.providerID + "/auto-level"
	requireStatus(t, a.mei.do(http.MethodPut, level, model.SetAutoLevelInput{MaxAutoLevel: model.ModeFull}), http.StatusForbidden)
	requireStatus(t, a.do(http.MethodPut, level, a.token, model.SetAutoLevelInput{MaxAutoLevel: model.ModeFull}), http.StatusUnauthorized)
	requireStatus(t, a.sup.do(http.MethodPut, level, model.SetAutoLevelInput{MaxAutoLevel: "admin"}), http.StatusBadRequest)
	requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/accounts/prv_missing/auto-level", model.SetAutoLevelInput{MaxAutoLevel: model.ModeRead}), http.StatusNotFound)
	if prov, _ := a.srv.db.GetProvider(context.Background(), a.providerID); prov.MaxAutoLevel != model.ModeRead {
		t.Fatalf("level changed by someone other than a supervisor: %s", prov.MaxAutoLevel)
	}

	// Both changes are audited, a raise as a warning.
	requireCode(t, a.setMode(a.mei, model.ModeWrite, 0), http.StatusOK)
	requireCode(t, a.setLevel(model.ModeWrite), http.StatusOK)
	modeEvents := a.listAudit("person.approval_mode_changed")
	levelEvents := a.listAudit("provider.auto_level_changed")
	if len(modeEvents) != 2 || modeEvents[0].ActorID != a.mei.person.ID || modeEvents[0].Severity != "warning" ||
		modeEvents[0].Metadata["mode"] != "write" || modeEvents[0].Metadata["previous_mode"] != "read" {
		t.Fatalf("mode audit = %+v", modeEvents)
	}
	if len(levelEvents) != 1 || levelEvents[0].ActorID != a.sup.person.ID || levelEvents[0].Severity != "warning" {
		t.Fatalf("level audit = %+v", levelEvents)
	}
	a.verifyAudit()
}

// A temporary mode falls back to read at its deadline.
func TestTemporaryModeExpires(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	requireCode(t, a.setLevel(model.ModeFull), http.StatusOK)
	requireCode(t, a.setMode(a.mei, model.ModeWrite, 3600), http.StatusOK)
	in := accessInput("ecs", "write")
	if req := a.request(in); req.Status != model.LeaseActive {
		t.Fatalf("write during the mode = %s", req.Status)
	}
	a.clock.Advance(time.Hour)
	if req := a.request(accessInput("dns", "write")); req.Status != model.LeasePending {
		t.Fatalf("write after the mode expired = %s", req.Status)
	}
	rec := a.do(http.MethodGet, "/api/v1/agent/accounts", a.token, nil)
	if acct := decodeEnvelope[listData[model.AgentAccount]](t, rec).Items[0]; acct.AutomaticUpTo != "read" {
		t.Fatalf("automatic after expiry = %s", acct.AutomaticUpTo)
	}
}

// Changing a mode or a level later does not touch what already exists, and
// a reset brings the mode back to read.
func TestModeChangesAreNotRetroactive(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	requireCode(t, a.setLevel(model.ModeFull), http.StatusOK)
	waiting := a.request(accessInput("ecs", "write"))
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	if a.status(waiting.ID) != model.LeasePending {
		t.Fatal("raising the mode approved a waiting request")
	}
	issued := a.request(accessInput("dns", "write"))
	requireCode(t, a.setMode(a.mei, model.ModeRead, 0), http.StatusOK)
	requireCode(t, a.setLevel(model.ModeRead), http.StatusOK)
	if a.status(issued.ID) != model.LeaseActive {
		t.Fatal("lowering the mode or level revoked an issued credential")
	}

	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/supervisor/people/"+a.mei.person.ID+"/reset", nil), http.StatusOK)
	if p, _ := a.srv.db.GetPerson(context.Background(), a.mei.person.ID); p.ApprovalMode != model.ModeRead {
		t.Fatalf("mode after a reset = %s", p.ApprovalMode)
	}
}

// The request's record and audit event say which mode and level decided it.
func TestAutomaticIssueRecordsWhy(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	requireCode(t, a.setLevel(model.ModeWrite), http.StatusOK)
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
			if ev.Metadata["approval_mode"] != "full" || ev.Metadata["max_auto_level"] != "write" {
				t.Fatalf("audit metadata = %+v", ev.Metadata)
			}
			return
		}
	}
	t.Fatal("no lease.requested event")
}

func TestEffectiveApprovalMode(t *testing.T) {
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	later, earlier := now.Add(time.Minute), now.Add(-time.Minute)
	for name, tc := range map[string]struct {
		p    model.Person
		want model.ApprovalMode
	}{
		"write":             {model.Person{ApprovalMode: model.ModeWrite}, model.ModeWrite},
		"full until later":  {model.Person{ApprovalMode: model.ModeFull, ApprovalModeExpiresAt: &later}, model.ModeFull},
		"full, expired":     {model.Person{ApprovalMode: model.ModeFull, ApprovalModeExpiresAt: &earlier}, model.ModeRead},
		"expires right now": {model.Person{ApprovalMode: model.ModeFull, ApprovalModeExpiresAt: &now}, model.ModeRead},
		"unknown value":     {model.Person{ApprovalMode: "admin"}, model.ModeRead},
		"empty":             {model.Person{}, model.ModeRead},
	} {
		if got := tc.p.EffectiveApprovalMode(now); got != tc.want {
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

// A damaged or unknown stored level counts as read, never as more.
func TestUnknownStoredLevelCountsAsRead(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	if _, err := a.srv.db.SQL().Exec(`UPDATE providers SET max_auto_level = 'everything' WHERE id = ?`, a.providerID); err != nil {
		t.Fatal(err)
	}
	if req := a.request(accessInput("ecs", "write")); req.Status != model.LeasePending {
		t.Fatalf("write under an unknown level = %s", req.Status)
	}
}
