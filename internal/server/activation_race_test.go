package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/capcatalog"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// These tests reproduce the window between "authorization checked" and "lease
// written as active". The fake minter's hook changes state at exactly that
// point. Before the compare-and-set activation, the final write overwrote the
// revoked status and resurrected the lease with a live credential.

// requireNoLiveCredential asserts a lease is not active, has no stored
// credential and cannot be fetched by its agent.
func requireNoLiveCredential(t *testing.T, env *testEnv, agentName string, leaseID string, wantStatus model.LeaseStatus) {
	t.Helper()
	got := env.getLease(leaseID)
	if got.Status != wantStatus {
		t.Fatalf("lease status = %q, want %q", got.Status, wantStatus)
	}
	if got.CredentialAvailable {
		t.Fatal("lease still reports credential_available=true")
	}
	if _, err := env.srv.db.GetLeaseCredential(context.Background(), leaseID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stored credential after lost activation: err = %v, want ErrNotFound", err)
	}
	if _, rec := env.fetchCredential(agentName, leaseID); rec.Code == http.StatusOK {
		t.Fatal("agent fetched a credential for a lease that lost its activation")
	}
	if !env.hasAction("lease.activation_aborted") {
		t.Fatal("missing lease.activation_aborted audit event")
	}
	if res := env.verifyAudit(); !res.OK {
		t.Fatalf("audit chain invalid after lost activation: %+v", res)
	}
}

func TestApprovalLosesRaceWithConcurrentRevoke(t *testing.T) {
	env := newTestEnv(t, true)
	env.createAgent("racer", model.RoleMember, nil)
	lease, rec := env.createLease("racer", model.CreateLeaseInput{
		CapabilityID: capcatalog.IDDNSManage,
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "approval race test",
	})
	requireStatus(t, rec, http.StatusCreated)
	if lease.Status != model.LeasePending {
		t.Fatalf("lease status = %q, want pending", lease.Status)
	}

	env.minter.onMint = func(req provider.MintRequest) {
		r := env.admin(http.MethodPost, "/api/v1/admin/leases/"+req.LeaseID+"/revoke",
			model.RevokeLeaseInput{Reason: "revoked while approval was minting"})
		requireStatus(t, r, http.StatusOK)
	}
	approve := env.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", model.ApproveLeaseInput{Note: "race"})
	requireErrorCode(t, approve, http.StatusConflict, model.ErrCodeConflict)
	requireNoLiveCredential(t, env, "racer", lease.ID, model.LeaseRevoked)
	if env.hasAction("lease.approved") {
		t.Fatal("lease.approved was audited for an approval that lost the race")
	}
}

func TestApprovalLosesRaceWithConcurrentDemotion(t *testing.T) {
	env := newTestEnv(t, true)
	env.createAgent("racer", model.RoleMember, nil)
	lease, rec := env.createLease("racer", model.CreateLeaseInput{
		CapabilityID: capcatalog.IDECSOps,
		Params:       map[string]string{"instance_id": "i-2ze0demo001"},
		Reason:       "demotion race test",
	})
	requireStatus(t, rec, http.StatusCreated)
	if lease.Status != model.LeasePending {
		t.Fatalf("lease status = %q, want pending", lease.Status)
	}

	env.minter.onMint = func(provider.MintRequest) {
		guest := model.RoleGuest
		env.patchAgent("racer", model.UpdateAgentInput{Role: &guest})
	}
	approve := env.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", model.ApproveLeaseInput{Note: "race"})
	requireErrorCode(t, approve, http.StatusConflict, model.ErrCodeConflict)
	requireNoLiveCredential(t, env, "racer", lease.ID, model.LeaseRevoked)
}

func TestAutoApprovalLosesRaceWithConcurrentRevoke(t *testing.T) {
	env := newTestEnv(t, true)
	env.createAgent("racer", model.RoleGuest, nil)

	env.minter.onMint = func(req provider.MintRequest) {
		r := env.admin(http.MethodPost, "/api/v1/admin/leases/"+req.LeaseID+"/revoke",
			model.RevokeLeaseInput{Reason: "revoked while auto-approval was minting"})
		requireStatus(t, r, http.StatusOK)
	}
	_, rec := env.createLease("racer", model.CreateLeaseInput{
		CapabilityID: capcatalog.IDCloudRead,
		Reason:       "auto-approval race test",
	})
	requireErrorCode(t, rec, http.StatusConflict, model.ErrCodeConflict)

	leaseID := env.minter.lastRequest(t).LeaseID
	requireNoLiveCredential(t, env, "racer", leaseID, model.LeaseRevoked)
}

// Authority changes that do not touch the lease's status (written straight to
// the store, so no sweep runs) must still stop activation: the post-mint
// recheck in activateLease re-reads the agent and capability.
func TestActivationRechecksAuthorityChangedDuringMint(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		auto    bool
		breakIt func(t *testing.T, env *testEnv)
	}{
		{"approval: grant removed during mint", false, func(t *testing.T, env *testEnv) {
			ag, _ := env.srv.db.GetAgent(ctx, env.agentIDs["racer"])
			ag.Grants = []string{capcatalog.IDCloudRead}
			if err := env.srv.db.UpdateAgent(ctx, ag); err != nil {
				t.Fatalf("UpdateAgent: %v", err)
			}
		}},
		{"approval: agent suspended during mint", false, func(t *testing.T, env *testEnv) {
			ag, _ := env.srv.db.GetAgent(ctx, env.agentIDs["racer"])
			ag.Status = model.AgentSuspended
			if err := env.srv.db.UpdateAgent(ctx, ag); err != nil {
				t.Fatalf("UpdateAgent: %v", err)
			}
		}},
		{"approval: capability disabled during mint", false, func(t *testing.T, env *testEnv) {
			c, _ := env.srv.db.GetCapability(ctx, capcatalog.IDDNSManage)
			c.Enabled = false
			if err := env.srv.db.UpdateCapability(ctx, c); err != nil {
				t.Fatalf("UpdateCapability: %v", err)
			}
		}},
		{"auto-approval: grant removed during mint", true, func(t *testing.T, env *testEnv) {
			ag, _ := env.srv.db.GetAgent(ctx, env.agentIDs["racer"])
			ag.Grants = []string{capcatalog.IDDNSManage}
			if err := env.srv.db.UpdateAgent(ctx, ag); err != nil {
				t.Fatalf("UpdateAgent: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, true)
			env.createAgent("racer", model.RoleMember, nil)
			var leaseID string
			var rec = (*httptest.ResponseRecorder)(nil)
			if tc.auto {
				env.minter.onMint = func(provider.MintRequest) { tc.breakIt(t, env) }
				_, rec = env.createLease("racer", model.CreateLeaseInput{CapabilityID: capcatalog.IDCloudRead, Reason: "auto race"})
				leaseID = env.minter.lastRequest(t).LeaseID
			} else {
				lease, r := env.createLease("racer", model.CreateLeaseInput{
					CapabilityID: capcatalog.IDDNSManage,
					Params:       map[string]string{"domain": "arveykao.com"},
					Reason:       "approval race",
				})
				requireStatus(t, r, http.StatusCreated)
				leaseID = lease.ID
				env.minter.onMint = func(provider.MintRequest) { tc.breakIt(t, env) }
				rec = env.admin(http.MethodPost, "/api/v1/admin/leases/"+leaseID+"/approve", model.ApproveLeaseInput{Note: "race"})
			}
			requireErrorCode(t, rec, http.StatusConflict, model.ErrCodeConflict)
			requireNoLiveCredential(t, env, "racer", leaseID, model.LeaseRevoked)
		})
	}
}

// Authority changes made through the admin API revoke affected leases in the
// same request (CONTRACT §16.5), so an approval racing them loses its
// compare-and-set even when the change lands after the post-mint recheck.
func TestAuthorityChangesRevokeAffectedLeases(t *testing.T) {
	t.Run("suspension revokes pending and active leases", func(t *testing.T) {
		env := newTestEnv(t, true)
		env.createAgent("sus", model.RoleMember, nil)
		active, _ := env.createLease("sus", model.CreateLeaseInput{CapabilityID: capcatalog.IDCloudRead, Reason: "read"})
		pending, _ := env.createLease("sus", model.CreateLeaseInput{
			CapabilityID: capcatalog.IDDNSManage, Params: map[string]string{"domain": "arveykao.com"}, Reason: "write",
		})
		if active.Status != model.LeaseActive || pending.Status != model.LeasePending {
			t.Fatalf("setup statuses = %q/%q, want active/pending", active.Status, pending.Status)
		}
		requireStatus(t, env.admin(http.MethodPost, "/api/v1/admin/agents/"+env.agentIDs["sus"]+"/suspend", nil), http.StatusOK)
		for _, id := range []string{active.ID, pending.ID} {
			if got := env.getLease(id); got.Status != model.LeaseRevoked {
				t.Fatalf("lease %s status after suspension = %q, want revoked", id, got.Status)
			}
		}
	})

	t.Run("grant removal revokes leases on the removed capability only", func(t *testing.T) {
		env := newTestEnv(t, true)
		env.createAgent("grt", model.RoleMember, nil)
		keep, _ := env.createLease("grt", model.CreateLeaseInput{CapabilityID: capcatalog.IDCloudRead, Reason: "read"})
		drop, _ := env.createLease("grt", model.CreateLeaseInput{
			CapabilityID: capcatalog.IDDNSManage, Params: map[string]string{"domain": "arveykao.com"}, Reason: "write",
		})
		grants := []string{capcatalog.IDCloudRead}
		env.patchAgent("grt", model.UpdateAgentInput{Grants: &grants})
		if got := env.getLease(keep.ID); got.Status != model.LeaseActive {
			t.Fatalf("still-granted lease status = %q, want active", got.Status)
		}
		if got := env.getLease(drop.ID); got.Status != model.LeaseRevoked {
			t.Fatalf("removed-grant lease status = %q, want revoked", got.Status)
		}
	})

	t.Run("disabling a capability revokes its pending leases", func(t *testing.T) {
		env := newTestEnv(t, true)
		env.createAgent("cap", model.RoleMember, nil)
		pending, _ := env.createLease("cap", model.CreateLeaseInput{
			CapabilityID: capcatalog.IDDNSManage, Params: map[string]string{"domain": "arveykao.com"}, Reason: "write",
		})
		requireStatus(t, env.admin(http.MethodPatch, "/api/v1/admin/capabilities/"+capcatalog.IDDNSManage, map[string]any{"enabled": false}), http.StatusOK)
		if got := env.getLease(pending.ID); got.Status != model.LeaseRevoked {
			t.Fatalf("pending lease after disable = %q, want revoked", got.Status)
		}
	})

	t.Run("an agent update re-runs the sweep, so a retry finishes it", func(t *testing.T) {
		ctx := context.Background()
		env := newTestEnv(t, true)
		env.createAgent("retry", model.RoleMember, nil)
		drop, _ := env.createLease("retry", model.CreateLeaseInput{
			CapabilityID: capcatalog.IDDNSManage, Params: map[string]string{"domain": "arveykao.com"}, Reason: "write",
		})
		// Simulate a demotion whose sweep failed half-way: the agent row changed
		// but the lease was left behind.
		ag, _ := env.srv.db.GetAgent(ctx, env.agentIDs["retry"])
		ag.Role = model.RoleGuest
		ag.Grants = []string{capcatalog.IDCloudRead}
		if err := env.srv.db.UpdateAgent(ctx, ag); err != nil {
			t.Fatalf("UpdateAgent: %v", err)
		}
		// Retrying the same change through the API (a no-op for the row) must
		// still revoke the stranded lease.
		guest := model.RoleGuest
		env.patchAgent("retry", model.UpdateAgentInput{Role: &guest})
		if got := env.getLease(drop.ID); got.Status != model.LeaseRevoked {
			t.Fatalf("stranded lease after retry = %q, want revoked", got.Status)
		}
	})
}

// The retired aliyun.iam.break_glass row is kept for history and can never be
// re-enabled, granted or leased (CONTRACT §16.6).
func TestRetiredCapabilityCannotBeRevived(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, true)
	retired := model.Capability{
		ID: capcatalog.IDBreakGlass, Name: "Retired break-glass", ProviderType: model.ProviderAliyun,
		Risk: model.RiskCritical, Access: model.AccessAdmin,
		PolicyTemplate:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		DefaultTTLSeconds: 900, MaxTTLSeconds: 1800, Enabled: false, Builtin: true,
		CreatedAt: fixedTestTime, UpdatedAt: fixedTestTime,
	}
	if err := env.srv.db.CreateCapability(ctx, retired); err != nil {
		t.Fatalf("CreateCapability: %v", err)
	}

	rec := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/"+capcatalog.IDBreakGlass, map[string]any{"enabled": true})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	grants := []string{capcatalog.IDBreakGlass}
	rec = env.admin(http.MethodPatch, "/api/v1/admin/agents/"+env.agentIDs["claude-code"], model.UpdateAgentInput{Grants: &grants})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// Even if the row were enabled and granted behind the API's back, a lease
	// on it is denied by policy.
	retired.Enabled = true
	if err := env.srv.db.UpdateCapability(ctx, retired); err != nil {
		t.Fatalf("UpdateCapability: %v", err)
	}
	ag, _ := env.srv.db.GetAgent(ctx, env.agentIDs["claude-code"])
	ag.Grants = append(ag.Grants, capcatalog.IDBreakGlass)
	if err := env.srv.db.UpdateAgent(ctx, ag); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	lease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: capcatalog.IDBreakGlass, Reason: "revive attempt", BreakGlass: true,
	})
	if lease.Status != model.LeaseDenied {
		t.Fatalf("lease on retired capability status = %q, want denied", lease.Status)
	}

	// New administrators never get it by default.
	admin := env.createAgent("fresh-admin", model.RoleAdministrator, nil)
	for _, g := range admin.Grants {
		if g == capcatalog.IDBreakGlass {
			t.Fatal("retired capability was granted by default to a new administrator")
		}
	}
}

// Two approvals of one pending lease at the same moment (double click, client
// retry) must mint once and leave the winner's credential usable.
func TestConcurrentApprovalsMintOnceAndKeepWinnerCredential(t *testing.T) {
	for round := 0; round < 5; round++ {
		env := newTestEnv(t, true)
		env.createAgent("dbl", model.RoleMember, nil)
		lease, rec := env.createLease("dbl", model.CreateLeaseInput{
			CapabilityID: capcatalog.IDDNSManage, Params: map[string]string{"domain": "arveykao.com"}, Reason: "double approve",
		})
		requireStatus(t, rec, http.StatusCreated)

		codes := make(chan int, 2)
		start := make(chan struct{})
		for i := 0; i < 2; i++ {
			go func() {
				<-start
				r := env.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", model.ApproveLeaseInput{Note: "dbl"})
				codes <- r.Code
			}()
		}
		close(start)
		a, b := <-codes, <-codes
		if !((a == http.StatusOK && b == http.StatusConflict) || (a == http.StatusConflict && b == http.StatusOK)) {
			t.Fatalf("round %d: approval codes = %d, %d; want one 200 and one 409", round, a, b)
		}
		if n := env.minter.requestCount(); n != 1 {
			t.Fatalf("round %d: minter called %d times, want 1", round, n)
		}
		got := env.getLease(lease.ID)
		if got.Status != model.LeaseActive || !got.CredentialAvailable {
			t.Fatalf("round %d: lease = %q credential_available=%v, want active with credential", round, got.Status, got.CredentialAvailable)
		}
		if _, r := env.fetchCredential("dbl", lease.ID); r.Code != http.StatusOK {
			t.Fatalf("round %d: winner's credential fetch = %d, want 200", round, r.Code)
		}
	}
}

// The post-mint recheck also covers TTL ceilings and the provider.
func TestActivationRechecksTTLAndProvider(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name    string
		breakIt func(t *testing.T, env *testEnv)
	}{
		{"agent max TTL lowered during mint", func(t *testing.T, env *testEnv) {
			ag, _ := env.srv.db.GetAgent(ctx, env.agentIDs["ttl"])
			ag.MaxTTLSeconds = 600
			if err := env.srv.db.UpdateAgent(ctx, ag); err != nil {
				t.Fatalf("UpdateAgent: %v", err)
			}
		}},
		{"capability max TTL lowered during mint", func(t *testing.T, env *testEnv) {
			c, _ := env.srv.db.GetCapability(ctx, capcatalog.IDDNSManage)
			c.DefaultTTLSeconds, c.MaxTTLSeconds = 300, 600
			if err := env.srv.db.UpdateCapability(ctx, c); err != nil {
				t.Fatalf("UpdateCapability: %v", err)
			}
		}},
		{"provider disabled during mint", func(t *testing.T, env *testEnv) {
			p, _ := env.srv.db.GetProvider(ctx, env.providerID)
			p.Status = model.ProviderDisabled
			if err := env.srv.db.UpdateProvider(ctx, p); err != nil {
				t.Fatalf("UpdateProvider: %v", err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, true)
			env.createAgent("ttl", model.RoleMember, nil)
			lease, rec := env.createLease("ttl", model.CreateLeaseInput{
				CapabilityID: capcatalog.IDDNSManage, Params: map[string]string{"domain": "arveykao.com"},
				TTLSeconds: 1800, Reason: "long lease",
			})
			requireStatus(t, rec, http.StatusCreated)
			env.minter.onMint = func(provider.MintRequest) { tc.breakIt(t, env) }
			approve := env.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", model.ApproveLeaseInput{Note: "race"})
			requireErrorCode(t, approve, http.StatusConflict, model.ErrCodeConflict)
			requireNoLiveCredential(t, env, "ttl", lease.ID, model.LeaseRevoked)
		})
	}
}

// F2: an operator approves an auto-approvable lease after its pending row is
// written but before auto-approval takes the lease lock. Auto-approval must not
// mint a second credential over the approved one.
func TestAutoApprovalSkipsLeaseApprovedBeforeItsLock(t *testing.T) {
	env := newTestEnv(t, true)
	env.createAgent("f2", model.RoleGuest, nil)
	env.srv.hookBeforeAutoLock = func(leaseID string) {
		r := env.admin(http.MethodPost, "/api/v1/admin/leases/"+leaseID+"/approve", model.ApproveLeaseInput{TTLSeconds: 60, Note: "first"})
		requireStatus(t, r, http.StatusOK)
	}
	_, rec := env.createLease("f2", model.CreateLeaseInput{CapabilityID: capcatalog.IDCloudRead, Reason: "auto vs approve"})
	requireErrorCode(t, rec, http.StatusConflict, model.ErrCodeConflict)

	if n := env.minter.requestCount(); n != 1 {
		t.Fatalf("minter called %d times, want 1 (approval only)", n)
	}
	leaseID := env.minter.lastRequest(t).LeaseID
	got := env.getLease(leaseID)
	if got.Status != model.LeaseActive || got.EffectiveTTLSeconds != 60 {
		t.Fatalf("lease = %q ttl=%d, want active with the approved 60s", got.Status, got.EffectiveTTLSeconds)
	}
	cred, r := env.fetchCredential("f2", leaseID)
	requireStatus(t, r, http.StatusOK)
	if want := env.minter.lastRequest(t).DurationSeconds; want != 60 {
		t.Fatalf("minted duration = %d, want 60", want)
	}
	if cred.Credential.AccessKeyID == "" {
		t.Fatal("approved credential missing")
	}
}

// F3: the exact interleaving the review found, for edits that do not take the
// capability lock (agent and provider). The approval passes its post-mint
// recheck; the edit commits; the activation write lands; only then does the
// edit's re-check sweep run. The sweep must see the active lease and revoke it.
func TestChangeBetweenRecheckAndActivationIsEnforced(t *testing.T) {
	cases := []struct {
		name   string
		kind   string
		change func(env *testEnv) *httptest.ResponseRecorder
	}{
		{"agent max TTL lowered", "agent", func(env *testEnv) *httptest.ResponseRecorder {
			ttl := 600
			return env.admin(http.MethodPatch, "/api/v1/admin/agents/"+env.agentIDs["f3"], model.UpdateAgentInput{MaxTTLSeconds: &ttl})
		}},
		{"provider disabled", "provider", func(env *testEnv) *httptest.ResponseRecorder {
			return env.admin(http.MethodPatch, "/api/v1/admin/providers/"+env.providerID, map[string]any{"status": "disabled"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, true)
			env.createAgent("f3", model.RoleMember, nil)
			lease, rec := env.createLease("f3", model.CreateLeaseInput{
				CapabilityID: capcatalog.IDDNSManage, Params: map[string]string{"domain": "arveykao.com"},
				TTLSeconds: 1800, Reason: "window",
			})
			requireStatus(t, rec, http.StatusCreated)

			rechecked, goActivate := make(chan struct{}), make(chan struct{})
			committed, goSweep := make(chan struct{}), make(chan struct{})
			env.srv.hookAfterLeaseRecheck = func(string) { close(rechecked); <-goActivate }
			env.srv.hookAfterAuthorityWrite = func(kind string) {
				if kind == tc.kind {
					close(committed)
					<-goSweep
				}
			}
			approveDone := make(chan int, 1)
			go func() {
				approveDone <- env.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", model.ApproveLeaseInput{Note: "window"}).Code
			}()
			<-rechecked
			changeDone := make(chan int, 1)
			go func() { changeDone <- tc.change(env).Code }()
			<-committed
			close(goActivate)
			if code := <-approveDone; code != http.StatusOK {
				t.Fatalf("approval = %d; the interleaving did not happen as intended", code)
			}
			if got := env.getLease(lease.ID); got.Status != model.LeaseActive {
				t.Fatalf("lease before the sweep = %q, want active", got.Status)
			}
			close(goSweep)
			if code := <-changeDone; code != http.StatusOK {
				t.Fatalf("edit = %d, want 200", code)
			}
			if got := env.getLease(lease.ID); got.Status != model.LeaseRevoked {
				t.Fatalf("lease after %s = %q, want revoked by the edit's sweep", tc.name, got.Status)
			}
		})
	}
}

// Capability edits take the capability's write lock, so they cannot commit
// while an approval of one of its leases is between reading the capability and
// activating. The edit waits, then its sweep applies to the now-active lease.
// For a narrowed policy this is what keeps a lease from being "pending when the
// edit committed, then activated with the old policy" (review 4, finding 1).
func TestCapabilityEditWaitsForInFlightActivation(t *testing.T) {
	cases := []struct {
		name        string
		body        map[string]any
		wantRevoked bool
	}{
		{"disabled", map[string]any{"enabled": false}, true},
		{"max TTL lowered", map[string]any{"default_ttl_seconds": 300, "max_ttl_seconds": 600}, true},
		// The approval finished before the narrowing committed, so its lease
		// was legitimately approved under the old definition and stays.
		{"policy narrowed", map[string]any{"policy_template": `{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:ListBuckets"],"Resource":["*"]}]}`, "params": []any{}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, true)
			env.createAgent("cw", model.RoleAdministrator, nil)
			custom := env.admin(http.MethodPost, "/api/v1/admin/capabilities", map[string]any{
				"name": "custom write", "risk": "medium", "access": "write",
				"policy_template":     `{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:PutObject","oss:ListBuckets"],"Resource":["*"]}]}`,
				"default_ttl_seconds": 900, "max_ttl_seconds": 1800,
			})
			requireStatus(t, custom, http.StatusCreated)
			capID := decodeEnvelope[model.Capability](t, custom).ID
			ag, _ := env.srv.db.GetAgent(context.Background(), env.agentIDs["cw"])
			grants := append(ag.Grants, capID)
			env.patchAgent("cw", model.UpdateAgentInput{Grants: &grants})
			lease, rec := env.createLease("cw", model.CreateLeaseInput{CapabilityID: capID, TTLSeconds: 1800, Reason: "edit wait"})
			requireStatus(t, rec, http.StatusCreated)
			if lease.Status != model.LeasePending {
				t.Fatalf("lease = %q, want pending", lease.Status)
			}

			rechecked, goActivate := make(chan struct{}), make(chan struct{})
			committed := make(chan struct{}, 1)
			env.srv.hookAfterLeaseRecheck = func(string) { close(rechecked); <-goActivate }
			env.srv.hookAfterAuthorityWrite = func(kind string) {
				if kind == "capability" {
					committed <- struct{}{}
				}
			}
			approveDone := make(chan int, 1)
			go func() {
				approveDone <- env.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", model.ApproveLeaseInput{Note: "edit wait"}).Code
			}()
			<-rechecked
			editDone := make(chan int, 1)
			go func() { editDone <- env.admin(http.MethodPatch, "/api/v1/admin/capabilities/"+capID, tc.body).Code }()
			select {
			case <-committed:
				t.Fatal("capability edit committed while an activation of its lease was in flight")
			case <-time.After(150 * time.Millisecond):
			}
			close(goActivate)
			if code := <-approveDone; code != http.StatusOK {
				t.Fatalf("approval = %d, want 200", code)
			}
			if code := <-editDone; code != http.StatusOK {
				t.Fatalf("edit = %d, want 200", code)
			}
			got := env.getLease(lease.ID)
			if tc.wantRevoked && got.Status != model.LeaseRevoked {
				t.Fatalf("lease after %s = %q, want revoked", tc.name, got.Status)
			}
			if !tc.wantRevoked && got.Status != model.LeaseActive {
				t.Fatalf("lease after %s = %q, want active (approved before the edit)", tc.name, got.Status)
			}
		})
	}
}

// Auto-approval decided against an earlier read of the capability; if the
// capability changed before it takes the capability lock, it must not mint.
func TestAutoApprovalAbortsWhenCapabilityChangedBeforeMint(t *testing.T) {
	env := newTestEnv(t, true)
	env.createAgent("ac", model.RoleGuest, nil)
	env.srv.hookBeforeAutoLock = func(string) {
		r := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/"+capcatalog.IDCloudRead, map[string]any{"description": "unchanged grant"})
		requireStatus(t, r, http.StatusOK)
		// A real narrowing of a builtin is not possible through the API, so
		// change what it grants directly in the store.
		c, _ := env.srv.db.GetCapability(context.Background(), capcatalog.IDCloudRead)
		c.MaxTTLSeconds = 1200
		if err := env.srv.db.UpdateCapability(context.Background(), c); err != nil {
			t.Fatalf("UpdateCapability: %v", err)
		}
	}
	_, rec := env.createLease("ac", model.CreateLeaseInput{CapabilityID: capcatalog.IDCloudRead, Reason: "auto vs edit"})
	requireErrorCode(t, rec, http.StatusConflict, model.ErrCodeConflict)
	if n := env.minter.requestCount(); n != 0 {
		t.Fatalf("minter called %d times after the capability changed, want 0", n)
	}
}

// Review 5, F5-1: an authority sweep must see every affected lease even while
// other leases leave the pending/active set during the sweep. With LIMIT/OFFSET
// paging, rows shifted between pages were skipped.
func TestSuspensionSweepSeesEveryLeaseDuringConcurrentExpiry(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, true)
	env.createAgent("many", model.RoleMember, nil)
	agentID := env.agentIDs["many"]
	now := env.clock.Now()
	expires := now.Add(15 * time.Minute)
	const total = 2500
	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		id := fmt.Sprintf("lea_many_%05d", i)
		created := now.Add(time.Duration(i) * time.Millisecond)
		if err := env.srv.db.CreateLease(ctx, model.Lease{
			ID: id, AgentID: agentID, AgentName: "many", CapabilityID: capcatalog.IDDNSManage,
			ProviderID: env.providerID, ProviderMode: model.ModeMock, Risk: model.RiskMedium,
			Status: model.LeaseActive, EffectiveTTLSeconds: 900, CreatedAt: created, IssuedAt: &created, ExpiresAt: &expires,
		}); err != nil {
			t.Fatalf("CreateLease: %v", err)
		}
		ids = append(ids, id)
	}
	// Concurrently move the 200 newest leases to expired while the sweep runs.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := total - 1; i >= total-200; i-- {
			l, err := env.srv.db.GetLease(ctx, ids[i])
			if err != nil {
				continue
			}
			l.Status = model.LeaseExpired
			_ = env.srv.db.UpdateLeaseIfStatus(ctx, l, model.LeaseActive)
		}
	}()
	requireStatus(t, env.admin(http.MethodPost, "/api/v1/admin/agents/"+agentID+"/suspend", nil), http.StatusOK)
	<-done

	left, err := env.srv.db.ListAllLeases(ctx, store.LeaseFilter{
		AgentID: agentID, Statuses: []model.LeaseStatus{model.LeasePending, model.LeaseActive},
	})
	if err != nil {
		t.Fatalf("ListAllLeases: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("%d leases of the suspended agent are still pending/active (e.g. %s)", len(left), left[0].ID)
	}
}
