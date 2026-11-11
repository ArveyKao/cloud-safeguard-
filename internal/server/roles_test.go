package server

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/capcatalog"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// builtinAccess is the frozen access level of each builtin (CONTRACT §16.2).
var builtinAccess = map[string]model.AccessLevel{
	capcatalog.IDCloudRead:    model.AccessRead,
	capcatalog.IDDNSManage:    model.AccessWrite,
	capcatalog.IDCertDNS01:    model.AccessWrite,
	capcatalog.IDECSOps:       model.AccessWrite,
	capcatalog.IDAccountAdmin: model.AccessAdmin,
}

// builtinParams are valid params for each builtin, so a lease request never
// fails validation before reaching the policy engine.
var builtinParams = map[string]map[string]string{
	capcatalog.IDCloudRead:    nil,
	capcatalog.IDDNSManage:    {"domain": "arveykao.com"},
	capcatalog.IDCertDNS01:    {"domain": "arveykao.com"},
	capcatalog.IDECSOps:       {"instance_id": "i-2ze0demo001"},
	capcatalog.IDAccountAdmin: nil,
}

// builtinCapabilityIDs returns the five builtin IDs.
func builtinCapabilityIDs() []string {
	ids := make([]string, 0, 5)
	for _, c := range capcatalog.Builtin() {
		ids = append(ids, c.ID)
	}
	return ids
}

// sortedCopy returns ids sorted, so grant sets can be compared as sets: the
// contract fixes which capabilities a role is granted, not their order.
func sortedCopy(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.Strings(out)
	return out
}

// createAgent creates an agent through the admin API and registers its token so
// env.agent(name, ...) can be used afterwards.
func (e *testEnv) createAgent(name string, role model.AgentRole, grants []string) model.Agent {
	e.t.Helper()
	rec := e.admin(http.MethodPost, "/api/v1/admin/agents", model.CreateAgentInput{
		Name:   name,
		Role:   role,
		Grants: grants,
	})
	requireStatus(e.t, rec, http.StatusCreated)
	created := decodeEnvelope[model.AgentWithToken](e.t, rec)
	e.agentTokens[name] = created.Token
	e.agentIDs[name] = created.Agent.ID
	return created.Agent
}

// patchAgent PATCHes an agent and requires success.
func (e *testEnv) patchAgent(name string, in model.UpdateAgentInput) model.Agent {
	e.t.Helper()
	rec := e.admin(http.MethodPatch, "/api/v1/admin/agents/"+e.agentIDs[name], in)
	requireStatus(e.t, rec, http.StatusOK)
	return decodeEnvelope[model.Agent](e.t, rec)
}

// TestRoleAccessMatrixOverHTTP walks all three roles against all five builtin
// capabilities through the agent API (CONTRACT §16.8). role_permits is a pure
// function of (role, capability.access): it must deny exactly the cells the
// role does not cover, and nothing may be minted for those.
func TestRoleAccessMatrixOverHTTP(t *testing.T) {
	env := newTestEnv(t, true)
	capabilityIDs := builtinCapabilityIDs()

	agents := map[model.AgentRole]string{
		model.RoleGuest:         "matrix-guest",
		model.RoleMember:        "matrix-member",
		model.RoleAdministrator: "matrix-administrator",
	}
	for role, name := range agents {
		// Omitted grants mean "every enabled capability the role permits", which
		// is exactly the in-role half of this row.
		env.createAgent(name, role, nil)
	}

	for _, role := range model.AgentRoles() {
		name := agents[role]
		for _, capabilityID := range capabilityIDs {
			access := builtinAccess[capabilityID]
			permitted := role.Permits(access)
			t.Run(string(role)+"/"+capabilityID, func(t *testing.T) {
				mintsBefore := env.minter.requestCount()
				lease, rec := env.createLease(name, model.CreateLeaseInput{
					CapabilityID: capabilityID,
					Params:       builtinParams[capabilityID],
					Reason:       "role matrix: " + string(role) + " wants " + capabilityID,
				})
				requireStatus(t, rec, http.StatusCreated)

				if permitted {
					requireRuleOutcome(t, lease.Decision, "role_permits", "allow")
					if strings.Contains(lease.DeniedReason, "role_permits") {
						t.Fatalf("%s/%s denied by role_permits even though the role permits %s: %q",
							role, capabilityID, access, lease.DeniedReason)
					}
					return
				}

				requireRuleOutcome(t, lease.Decision, "role_permits", "deny")
				if lease.Status != model.LeaseDenied {
					t.Fatalf("%s/%s status = %q, want denied", role, capabilityID, lease.Status)
				}
				if !strings.Contains(lease.DeniedReason, "role_permits") {
					t.Fatalf("%s/%s denied_reason = %q, want it to name role_permits",
						role, capabilityID, lease.DeniedReason)
				}
				if got := env.minter.requestCount(); got != mintsBefore {
					t.Fatalf("%s/%s minted a credential (%d -> %d)", role, capabilityID, mintsBefore, got)
				}
				if lease.CredentialAvailable {
					t.Fatalf("%s/%s reports a credential", role, capabilityID)
				}
			})
		}
	}

	// The in-role cells are exactly the capabilities each agent was granted and
	// can see.
	wantVisible := map[model.AgentRole]int{
		model.RoleGuest:         1, // read
		model.RoleMember:        4, // read + three write
		model.RoleAdministrator: 5, // everything
	}
	for role, name := range agents {
		rec := env.agent(name, http.MethodGet, "/api/v1/agent/capabilities", nil)
		requireStatus(t, rec, http.StatusOK)
		visible := decodeEnvelope[agentCapabilitiesResponse](t, rec)
		if visible.Total != wantVisible[role] {
			t.Fatalf("%s sees %d capabilities, want %d", role, visible.Total, wantVisible[role])
		}
		if visible.Role != role {
			t.Fatalf("%s capabilities response role = %q", role, visible.Role)
		}
		for _, c := range visible.Items {
			if !role.Permits(c.Access) {
				t.Fatalf("%s can see %s, which needs %s access", role, c.ID, c.Access)
			}
		}
	}
	env.verifyAudit()
}

// TestAgentCreateAndPatchRoles covers CONTRACT §16.5: default grants per role,
// rejection of out-of-role grants, and the grant reset on a role change.
func TestAgentCreateAndPatchRoles(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, true)
	all := sortedCopy(builtinCapabilityIDs())
	readOnly := []string{capcatalog.IDCloudRead}
	readWrite := make([]string, 0, 4)
	for _, id := range all {
		if builtinAccess[id] != model.AccessAdmin {
			readWrite = append(readWrite, id)
		}
	}

	// ---- default grants ----
	for _, tc := range []struct {
		role       model.AgentRole
		wantGrants []string
	}{
		{model.RoleGuest, readOnly},
		{model.RoleMember, readWrite},
		{model.RoleAdministrator, all},
	} {
		ag := env.createAgent("defaults-"+string(tc.role), tc.role, nil)
		if ag.Role != tc.role {
			t.Fatalf("created role = %q, want %q", ag.Role, tc.role)
		}
		if got := sortedCopy(ag.Grants); strings.Join(got, ",") != strings.Join(tc.wantGrants, ",") {
			t.Fatalf("%s default grants = %v, want %v", tc.role, got, tc.wantGrants)
		}
	}

	// An omitted role defaults to guest, and so do its default grants.
	rec := env.admin(http.MethodPost, "/api/v1/admin/agents", map[string]any{"name": "no-role-given"})
	requireStatus(t, rec, http.StatusCreated)
	defaulted := decodeEnvelope[model.AgentWithToken](t, rec).Agent
	if defaulted.Role != model.RoleGuest {
		t.Fatalf("agent created without a role = %q, want guest", defaulted.Role)
	}
	if got := sortedCopy(defaulted.Grants); strings.Join(got, ",") != strings.Join(readOnly, ",") {
		t.Fatalf("default grants for an implicit guest = %v, want %v", got, readOnly)
	}

	// An explicit empty grant list means the same thing as an omitted one.
	explicitEmpty := env.createAgent("explicit-empty-grants", model.RoleMember, []string{})
	if got := sortedCopy(explicitEmpty.Grants); strings.Join(got, ",") != strings.Join(readWrite, ",") {
		t.Fatalf("explicit empty grants = %v, want the member default %v", got, readWrite)
	}

	// ---- out-of-role grants are rejected ----
	for _, tc := range []struct {
		name  string
		role  model.AgentRole
		grant string
	}{
		{"guest cannot hold write", model.RoleGuest, capcatalog.IDDNSManage},
		{"guest cannot hold admin", model.RoleGuest, capcatalog.IDAccountAdmin},
		{"member cannot hold admin", model.RoleMember, capcatalog.IDAccountAdmin},
	} {
		t.Run("create/"+tc.name, func(t *testing.T) {
			rec := env.admin(http.MethodPost, "/api/v1/admin/agents", model.CreateAgentInput{
				Name:   "rejected-" + tc.name,
				Role:   tc.role,
				Grants: []string{capcatalog.IDCloudRead, tc.grant},
			})
			requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
			if msg := decodeError(t, rec).Error.Message; !strings.Contains(msg, tc.grant) {
				t.Fatalf("error message = %q, want it to name %s", msg, tc.grant)
			}
		})
	}

	// An unknown role is a 400 on both create and patch.
	rec = env.admin(http.MethodPost, "/api/v1/admin/agents", map[string]any{"name": "bad-role", "role": "superuser"})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	target := env.createAgent("patch-target", model.RoleMember, nil)
	rec = env.admin(http.MethodPatch, "/api/v1/admin/agents/"+target.ID, map[string]any{"role": "superuser"})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// PATCHing an out-of-role grant is a 400, and the stored grants are intact.
	outOfRole := []string{capcatalog.IDAccountAdmin}
	rec = env.admin(http.MethodPatch, "/api/v1/admin/agents/"+target.ID, model.UpdateAgentInput{Grants: &outOfRole})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	stored, err := env.srv.db.GetAgent(ctx, target.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got := sortedCopy(stored.Grants); strings.Join(got, ",") != strings.Join(readWrite, ",") {
		t.Fatalf("refused PATCH changed grants to %v", got)
	}

	// Grants and role may be raised together in one request; the supplied order
	// is preserved verbatim.
	admin := model.RoleAdministrator
	withAdmin := append(append([]string(nil), readWrite...), capcatalog.IDAccountAdmin)
	promoted := env.patchAgent("patch-target", model.UpdateAgentInput{Role: &admin, Grants: &withAdmin})
	if promoted.Role != model.RoleAdministrator ||
		strings.Join(promoted.Grants, ",") != strings.Join(withAdmin, ",") {
		t.Fatalf("promoted agent = %+v", promoted)
	}

	// ---- a role change without grants resets them to the role default ----
	guest := model.RoleGuest
	reset := env.patchAgent("patch-target", model.UpdateAgentInput{Role: &guest})
	if reset.Role != model.RoleGuest {
		t.Fatalf("reset role = %q, want guest", reset.Role)
	}
	if got := sortedCopy(reset.Grants); strings.Join(got, ",") != strings.Join(readOnly, ",") {
		t.Fatalf("grants after the role reset = %v, want the guest default %v", got, readOnly)
	}
	// A patch that keeps the role does not touch grants.
	same := model.RoleGuest
	unchanged := env.patchAgent("patch-target", model.UpdateAgentInput{Role: &same})
	if strings.Join(unchanged.Grants, ",") != strings.Join(reset.Grants, ",") {
		t.Fatalf("a no-op role patch changed grants: %v -> %v", reset.Grants, unchanged.Grants)
	}

	// ---- later capabilities are not granted retroactively ----
	createRec := env.admin(http.MethodPost, "/api/v1/admin/capabilities", model.Capability{
		Name:              "Later bucket read",
		ProviderType:      model.ProviderAliyun,
		Risk:              model.RiskLow,
		Access:            model.AccessRead,
		PolicyTemplate:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:List*"],"Resource":["*"]}]}`,
		DefaultTTLSeconds: 300,
		MaxTTLSeconds:     600,
	})
	requireStatus(t, createRec, http.StatusCreated)
	later := decodeEnvelope[model.Capability](t, createRec)
	refetched := env.admin(http.MethodGet, "/api/v1/admin/agents/"+defaulted.ID, nil)
	requireStatus(t, refetched, http.StatusOK)
	if got := sortedCopy(decodeEnvelope[model.Agent](t, refetched).Grants); strings.Join(got, ",") != strings.Join(readOnly, ",") {
		t.Fatalf("existing agent grants changed when %s was added: %v", later.ID, got)
	}
	// A guest created now does pick it up, and a role reset re-reads the catalog.
	fresh := env.createAgent("guest-after-new-capability", model.RoleGuest, nil)
	wantFresh := sortedCopy(append(append([]string(nil), readOnly...), later.ID))
	if got := sortedCopy(fresh.Grants); strings.Join(got, ",") != strings.Join(wantFresh, ",") {
		t.Fatalf("guest created after %s has grants %v, want %v", later.ID, got, wantFresh)
	}
	member := model.RoleMember
	rePromoted := env.patchAgent("patch-target", model.UpdateAgentInput{Role: &member})
	wantMember := sortedCopy(append(append([]string(nil), readWrite...), later.ID))
	if got := sortedCopy(rePromoted.Grants); strings.Join(got, ",") != strings.Join(wantMember, ",") {
		t.Fatalf("grants after the role reset = %v, want %v", got, wantMember)
	}
	env.verifyAudit()
}

// TestDemotionRevokesExactlyOutOfRoleLeases covers CONTRACT §16.5: a demotion
// revokes every pending or active lease the new role no longer permits, in the
// same request, and leaves the in-role ones alone.
func TestDemotionRevokesExactlyOutOfRoleLeases(t *testing.T) {
	env := newTestEnv(t, true)
	env.createAgent("demote-me", model.RoleAdministrator, nil)

	// One active read lease (survives) and three out-of-role ones (revoked).
	readLease, _ := env.createLease("demote-me", model.CreateLeaseInput{
		CapabilityID: capcatalog.IDCloudRead,
		Reason:       "inventory before the demotion",
	})
	if readLease.Status != model.LeaseActive {
		t.Fatalf("read lease status = %q, want active", readLease.Status)
	}
	dnsLease, _ := env.createLease("demote-me", model.CreateLeaseInput{
		CapabilityID: capcatalog.IDDNSManage,
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "dns change before the demotion",
	})
	ecsLease, _ := env.createLease("demote-me", model.CreateLeaseInput{
		CapabilityID: capcatalog.IDECSOps,
		Params:       map[string]string{"instance_id": "i-2ze0demo001"},
		Reason:       "instance restart before the demotion",
	})
	adminLease, _ := env.createLease("demote-me", model.CreateLeaseInput{
		CapabilityID: capcatalog.IDAccountAdmin,
		Reason:       "emergency before the demotion",
		BreakGlass:   true,
	})
	for _, lease := range []model.Lease{dnsLease, ecsLease, adminLease} {
		if lease.Status != model.LeasePending {
			t.Fatalf("lease %s on %s status = %q, want pending", lease.ID, lease.CapabilityID, lease.Status)
		}
	}
	// A terminal lease must not be touched by the sweep.
	denied, _ := env.createLease("demote-me", model.CreateLeaseInput{
		CapabilityID: capcatalog.IDAccountAdmin,
		Reason:       "no break-glass flag, so denied up front",
	})
	if denied.Status != model.LeaseDenied {
		t.Fatalf("control lease status = %q, want denied", denied.Status)
	}

	guest := model.RoleGuest
	demoted := env.patchAgent("demote-me", model.UpdateAgentInput{Role: &guest})
	if demoted.Role != model.RoleGuest {
		t.Fatalf("role after demotion = %q", demoted.Role)
	}

	wantRevoked := []string{dnsLease.ID, ecsLease.ID, adminLease.ID}
	sort.Strings(wantRevoked)
	gotRevoked := make([]string, 0, 3)
	for _, lease := range []model.Lease{dnsLease, ecsLease, adminLease} {
		got := env.getLease(lease.ID)
		if got.Status != model.LeaseRevoked {
			t.Fatalf("lease %s on %s status = %q, want revoked", got.ID, got.CapabilityID, got.Status)
		}
		if got.RevokeReason != "role changed to guest" {
			t.Fatalf("lease %s revoke reason = %q, want %q", got.ID, got.RevokeReason, "role changed to guest")
		}
		if got.CredentialAvailable {
			t.Fatalf("revoked lease %s still reports a credential", got.ID)
		}
		gotRevoked = append(gotRevoked, got.ID)
	}
	sort.Strings(gotRevoked)
	if strings.Join(gotRevoked, ",") != strings.Join(wantRevoked, ",") {
		t.Fatalf("revoked = %v, want %v", gotRevoked, wantRevoked)
	}

	// The in-role lease is untouched and its credential still works.
	survivor := env.getLease(readLease.ID)
	if survivor.Status != model.LeaseActive {
		t.Fatalf("in-role lease status after demotion = %q, want active", survivor.Status)
	}
	if _, rec := env.fetchCredential("demote-me", readLease.ID); rec.Code != http.StatusOK {
		t.Fatalf("in-role credential fetch after demotion status = %d, want 200", rec.Code)
	}
	// The denied control lease stayed denied.
	if got := env.getLease(denied.ID); got.Status != model.LeaseDenied {
		t.Fatalf("terminal lease status = %q, want denied", got.Status)
	}

	// Audit: agent.role_changed at warning severity, naming from/to and the
	// revoked lease IDs.
	events := env.listAudit("agent.role_changed")
	if len(events) != 1 {
		t.Fatalf("agent.role_changed events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Severity != "warning" {
		t.Fatalf("agent.role_changed severity = %q, want warning", ev.Severity)
	}
	if ev.TargetID != env.agentIDs["demote-me"] {
		t.Fatalf("agent.role_changed target = %q", ev.TargetID)
	}
	if ev.Metadata["from"] != string(model.RoleAdministrator) || ev.Metadata["to"] != string(model.RoleGuest) {
		t.Fatalf("agent.role_changed metadata = %+v", ev.Metadata)
	}
	rawIDs, ok := ev.Metadata["revoked_lease_ids"].([]any)
	if !ok {
		t.Fatalf("revoked_lease_ids metadata = %#v", ev.Metadata["revoked_lease_ids"])
	}
	auditedIDs := make([]string, 0, len(rawIDs))
	for _, raw := range rawIDs {
		auditedIDs = append(auditedIDs, raw.(string))
	}
	sort.Strings(auditedIDs)
	if strings.Join(auditedIDs, ",") != strings.Join(wantRevoked, ",") {
		t.Fatalf("audited revoked lease IDs = %v, want %v", auditedIDs, wantRevoked)
	}

	// Promotion back up does not resurrect anything.
	admin := model.RoleAdministrator
	env.patchAgent("demote-me", model.UpdateAgentInput{Role: &admin})
	for _, lease := range []model.Lease{dnsLease, ecsLease, adminLease} {
		if got := env.getLease(lease.ID); got.Status != model.LeaseRevoked {
			t.Fatalf("lease %s status after re-promotion = %q, want revoked", lease.ID, got.Status)
		}
	}
	env.verifyAudit()
}

// TestApprovalRechecksAuthorization covers CONTRACT §16.5 (delivery finding
// F3): an approval that arrives after a suspension, a grant removal, a
// demotion or a capability edit returns 409 and mints nothing.
//
// Demotion and capability edits are applied straight to the store, because the
// admin API already prevents those states (demotion revokes, and a prohibited
// template is a 400). The recheck exists for exactly that race.
func TestApprovalRechecksAuthorization(t *testing.T) {
	ctx := context.Background()

	// pendingLease spins up a fresh environment with one pending write lease.
	pendingLease := func(t *testing.T) (*testEnv, model.Lease) {
		t.Helper()
		env := newTestEnv(t, true)
		env.createAgent("recheck", model.RoleMember, nil)
		lease, rec := env.createLease("recheck", model.CreateLeaseInput{
			CapabilityID: capcatalog.IDDNSManage,
			Params:       map[string]string{"domain": "arveykao.com"},
			Reason:       "pending until the operator decides",
		})
		requireStatus(t, rec, http.StatusCreated)
		if lease.Status != model.LeasePending {
			t.Fatalf("lease status = %q, want pending", lease.Status)
		}
		if env.minter.requestCount() != 0 {
			t.Fatal("minter was called for a pending lease")
		}
		return env, lease
	}

	tests := []struct {
		name          string
		breakIt       func(t *testing.T, env *testEnv, lease model.Lease)
		wantInMessage string
		// wantStatus is where the lease ends up. Changes made through the
		// admin API revoke the affected pending lease at once (CONTRACT §16.5),
		// so approval finds it revoked; changes written straight to the store
		// leave it pending and are caught by the recheck itself.
		wantStatus model.LeaseStatus
	}{
		{
			name: "agent suspended",
			breakIt: func(t *testing.T, env *testEnv, _ model.Lease) {
				rec := env.admin(http.MethodPost, "/api/v1/admin/agents/"+env.agentIDs["recheck"]+"/suspend", nil)
				requireStatus(t, rec, http.StatusOK)
			},
			wantInMessage: "revoked",
			wantStatus:    model.LeaseRevoked,
		},
		{
			name: "grant removed",
			breakIt: func(t *testing.T, env *testEnv, _ model.Lease) {
				grants := []string{capcatalog.IDCloudRead}
				env.patchAgent("recheck", model.UpdateAgentInput{Grants: &grants})
			},
			wantInMessage: "revoked",
			wantStatus:    model.LeaseRevoked,
		},
		{
			name: "role demoted underneath the lease",
			breakIt: func(t *testing.T, env *testEnv, _ model.Lease) {
				ag, err := env.srv.db.GetAgent(ctx, env.agentIDs["recheck"])
				if err != nil {
					t.Fatalf("GetAgent: %v", err)
				}
				ag.Role = model.RoleGuest
				if err := env.srv.db.UpdateAgent(ctx, ag); err != nil {
					t.Fatalf("UpdateAgent: %v", err)
				}
			},
			wantInMessage: "does not permit write access",
			wantStatus:    model.LeasePending,
		},
		{
			name: "capability template became prohibited",
			breakIt: func(t *testing.T, env *testEnv, lease model.Lease) {
				c, err := env.srv.db.GetCapability(ctx, lease.CapabilityID)
				if err != nil {
					t.Fatalf("GetCapability: %v", err)
				}
				c.PolicyTemplate = `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ram:ListUsers"],"Resource":["*"]}]}`
				c.Params = nil
				if err := env.srv.db.UpdateCapability(ctx, c); err != nil {
					t.Fatalf("UpdateCapability: %v", err)
				}
			},
			wantInMessage: "prohibited policy",
			wantStatus:    model.LeasePending,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, lease := pendingLease(t)
			tt.breakIt(t, env, lease)

			rec := env.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", model.ApproveLeaseInput{
				Note: "approved before the recheck landed",
			})
			requireErrorCode(t, rec, http.StatusConflict, model.ErrCodeConflict)
			if msg := decodeError(t, rec).Error.Message; !strings.Contains(msg, tt.wantInMessage) {
				t.Fatalf("conflict message = %q, want substring %q", msg, tt.wantInMessage)
			}

			// Nothing was minted and the lease never became active.
			if env.minter.requestCount() != 0 {
				t.Fatalf("approval minted a credential after %s", tt.name)
			}
			after := env.getLease(lease.ID)
			if after.Status != tt.wantStatus {
				t.Fatalf("lease status after the refused approval = %q, want %q", after.Status, tt.wantStatus)
			}
			if after.CredentialAvailable || after.ApprovedBy != "" {
				t.Fatalf("refused approval left approval state on the lease: %+v", after)
			}
			if _, err := env.srv.db.GetLeaseCredential(ctx, lease.ID); err == nil {
				t.Fatal("refused approval stored a credential blob")
			}
			env.verifyAudit()
		})
	}
}

// TestRetiredCapabilityLeasesAreRevokedOnStartup covers CONTRACT §16.6: a lease
// that still points at aliyun.iam.break_glass can never become active again.
func TestRetiredCapabilityLeasesAreRevokedOnStartup(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, true)

	// Re-create the retired capability row and a lease on it, exactly as an
	// upgraded v1 install would carry them.
	now := env.clock.Now()
	retired := model.Capability{
		ID:                capcatalog.IDBreakGlass,
		Name:              "Emergency account-wide access (break-glass)",
		ProviderType:      model.ProviderAliyun,
		Risk:              model.RiskCritical,
		Access:            model.AccessAdmin,
		PolicyTemplate:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		DefaultTTLSeconds: 900,
		MaxTTLSeconds:     1800,
		Enabled:           false,
		Builtin:           true,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := env.srv.db.CreateCapability(ctx, retired); err != nil {
		t.Fatalf("CreateCapability: %v", err)
	}
	expires := now.Add(900 * time.Second)
	for _, status := range []model.LeaseStatus{model.LeasePending, model.LeaseActive, model.LeaseExpired} {
		lease := model.Lease{
			ID:                  "lea_retired_" + string(status),
			AgentID:             env.agentIDs["claude-code"],
			AgentName:           "claude-code",
			CapabilityID:        capcatalog.IDBreakGlass,
			CapabilityName:      retired.Name,
			ProviderID:          env.providerID,
			ProviderMode:        model.ModeMock,
			Risk:                model.RiskCritical,
			Status:              status,
			BreakGlass:          true,
			EffectiveTTLSeconds: 900,
			CreatedAt:           now,
		}
		if status == model.LeaseActive {
			lease.IssuedAt = &now
			lease.ExpiresAt = &expires
		}
		if err := env.srv.db.CreateLease(ctx, lease); err != nil {
			t.Fatalf("CreateLease(%s): %v", lease.ID, err)
		}
	}

	// Restart the control plane on the same data directory.
	if err := env.srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	restarted, err := New(Config{DataDir: env.dir, Now: env.clock.Now})
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	defer restarted.Close()

	for _, status := range []model.LeaseStatus{model.LeasePending, model.LeaseActive} {
		got, err := restarted.db.GetLease(ctx, "lea_retired_"+string(status))
		if err != nil {
			t.Fatalf("GetLease: %v", err)
		}
		if got.Status != model.LeaseRevoked {
			t.Fatalf("%s lease on the retired capability = %q, want revoked", status, got.Status)
		}
		if got.RevokeReason != "capability retired" {
			t.Fatalf("revoke reason = %q, want %q", got.RevokeReason, "capability retired")
		}
	}
	// Terminal leases are left as history.
	expired, err := restarted.db.GetLease(ctx, "lea_retired_expired")
	if err != nil {
		t.Fatalf("GetLease(expired): %v", err)
	}
	if expired.Status != model.LeaseExpired {
		t.Fatalf("expired lease status = %q, want expired", expired.Status)
	}
	// The capability row itself is kept so the history stays readable.
	if _, err := restarted.db.GetCapability(ctx, capcatalog.IDBreakGlass); err != nil {
		t.Fatalf("retired capability row was removed: %v", err)
	}

	// The revocations are audited as system actions and the chain still verifies.
	events, _, err := restarted.db.ListAudit(ctx, store.AuditFilter{Action: "lease.revoked", Limit: 100})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	retiredEvents := 0
	for _, ev := range events {
		if ev.Metadata["reason"] == "capability retired" {
			retiredEvents++
			if ev.ActorType != "system" {
				t.Fatalf("startup revocation actor type = %q, want system", ev.ActorType)
			}
			if ev.Severity != "critical" {
				t.Fatalf("break-glass revocation severity = %q, want critical", ev.Severity)
			}
		}
	}
	if retiredEvents != 2 {
		t.Fatalf("startup revocation events = %d, want 2", retiredEvents)
	}
	result, err := restarted.db.VerifyAudit(ctx)
	if err != nil || !result.OK {
		t.Fatalf("audit verify after startup revocations = %+v, %v", result, err)
	}
}

// A lease whose capability now renders a policy that violates the IAM
// prohibition (for example a v1 custom capability that allowed RAM, disabled by
// the schema-2 migration) is revoked on startup, while a lease on a compliant
// capability is left alone.
func TestProhibitedPolicyLeasesAreRevokedOnStartup(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, true)
	now := env.clock.Now()
	expires := now.Add(900 * time.Second)

	ramCap := model.Capability{
		ID: "cap_v1_ram", Name: "v1 RAM helper", ProviderType: model.ProviderAliyun,
		Risk: model.RiskHigh, Access: model.AccessAdmin,
		PolicyTemplate:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ram:*"],"Resource":"*"}]}`,
		DefaultTTLSeconds: 900, MaxTTLSeconds: 1800, Enabled: false,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := env.srv.db.CreateCapability(ctx, ramCap); err != nil {
		t.Fatalf("CreateCapability: %v", err)
	}
	mk := func(id, capID string) {
		lease := model.Lease{
			ID: id, AgentID: env.agentIDs["claude-code"], AgentName: "claude-code",
			CapabilityID: capID, ProviderID: env.providerID, ProviderMode: model.ModeMock,
			Risk: model.RiskHigh, Status: model.LeaseActive, EffectiveTTLSeconds: 900,
			CreatedAt: now, IssuedAt: &now, ExpiresAt: &expires,
		}
		if err := env.srv.db.CreateLease(ctx, lease); err != nil {
			t.Fatalf("CreateLease(%s): %v", id, err)
		}
	}
	mk("lea_v1_ram", ramCap.ID)
	mk("lea_v1_read", capcatalog.IDCloudRead)

	if err := env.srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	restarted, err := New(Config{DataDir: env.dir, Now: env.clock.Now})
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	defer restarted.Close()

	got, _ := restarted.db.GetLease(ctx, "lea_v1_ram")
	if got.Status != model.LeaseRevoked || got.RevokeReason != "policy violates the IAM prohibition" {
		t.Fatalf("RAM lease after restart = %q (%q), want revoked for the IAM prohibition", got.Status, got.RevokeReason)
	}
	kept, _ := restarted.db.GetLease(ctx, "lea_v1_read")
	if kept.Status != model.LeaseActive {
		t.Fatalf("compliant lease after restart = %q, want active", kept.Status)
	}
	if res, err := restarted.db.VerifyAudit(ctx); err != nil || !res.OK {
		t.Fatalf("audit verify after startup revocation = %+v, %v", res, err)
	}
}
