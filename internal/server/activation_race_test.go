package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// These tests reproduce the window between "authorization checked" and
// "request written as active". The fake minter's hook changes state at
// exactly that point. Without the compare-and-set activation, the final write
// would overwrite the revoked status and bring the request back with a live
// credential.

// requireNoLiveCredential asserts a request is not active, has no stored
// credential and cannot be fetched by its agent.
func requireNoLiveCredential(t *testing.T, a *accessEnv, leaseID string, wantStatus model.LeaseStatus) {
	t.Helper()
	got := a.getLease(leaseID)
	if got.Status != wantStatus {
		t.Fatalf("status = %q, want %q", got.Status, wantStatus)
	}
	if got.CredentialAvailable {
		t.Fatal("request still reports credential_available=true")
	}
	if _, err := a.srv.db.GetLeaseCredential(context.Background(), leaseID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stored credential after a lost activation: err = %v, want ErrNotFound", err)
	}
	if rec := a.credential(leaseID); rec.Code == http.StatusOK {
		t.Fatal("the agent fetched a credential for a request that lost its activation")
	}
	if !a.hasAction("lease.activation_aborted") {
		t.Fatal("missing lease.activation_aborted audit event")
	}
	a.verifyAudit()
}

// supervisorRevoke is the emergency stop, as a supervisor.
func (a *accessEnv) supervisorRevoke(leaseID, reason string) *httptest.ResponseRecorder {
	return a.sup.do(http.MethodPost, "/api/v1/supervisor/leases/"+leaseID+"/revoke", model.RevokeLeaseInput{Reason: reason})
}

// onlyLeaseID returns the ID of the single lease the agent has.
func (a *accessEnv) onlyLeaseID() string {
	a.t.Helper()
	leases, err := a.srv.db.ListAllLeases(context.Background(), store.LeaseFilter{AgentID: a.agent.ID})
	if err != nil || len(leases) != 1 {
		a.t.Fatalf("leases of the agent: %d, %v", len(leases), err)
	}
	return leases[0].ID
}

func TestApprovalLosesRaceWithConcurrentRevoke(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	req := a.request(accessInput("ecs", "write"))
	if req.Status != model.LeasePending {
		t.Fatalf("status = %q, want pending", req.Status)
	}
	a.minter.onMint = func(m provider.MintRequest) {
		requireStatus(t, a.supervisorRevoke(m.LeaseID, "revoked while the approval was minting"), http.StatusOK)
	}
	requireErrorCode(t, a.approve(a.mei, req.ID), http.StatusConflict, model.ErrCodeConflict)
	requireNoLiveCredential(t, a, req.ID, model.LeaseRevoked)
	if a.hasAction("lease.approved") {
		t.Fatal("lease.approved was recorded for an approval that lost the race")
	}
}

func TestApprovalLosesRaceWithConcurrentRoleChange(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	req := a.request(accessInput("ecs", "write"))
	a.minter.onMint = func(provider.MintRequest) { a.bind(a.mei, model.RoleGuest) }
	requireErrorCode(t, a.approve(a.mei, req.ID), http.StatusConflict, model.ErrCodeConflict)
	requireNoLiveCredential(t, a, req.ID, model.LeaseRevoked)
}

func TestAutomaticIssueLosesRaceWithConcurrentRevoke(t *testing.T) {
	a := newAccessEnv(t, model.RoleGuest)
	a.minter.onMint = func(m provider.MintRequest) {
		requireStatus(t, a.supervisorRevoke(m.LeaseID, "revoked while the request was minting"), http.StatusOK)
	}
	requireErrorCode(t, a.requestRaw(a.token, accessInput("ecs", "read")), http.StatusConflict, model.ErrCodeConflict)
	requireNoLiveCredential(t, a, a.minter.lastRequest(t).LeaseID, model.LeaseRevoked)
}

// Authority changes that do not touch the request's status (written straight
// to the store, so no sweep runs) must still stop activation: the check after
// minting reads the agent, its owner, the role and the cloud account again.
func TestActivationRechecksAuthorityChangedDuringMint(t *testing.T) {
	ctx := context.Background()
	exec := func(t *testing.T, a *accessEnv, query string, args ...any) {
		t.Helper()
		if _, err := a.srv.db.SQL().Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name    string
		breakIt func(t *testing.T, a *accessEnv)
	}{
		{"role removed", func(t *testing.T, a *accessEnv) {
			if err := a.srv.db.DeleteBinding(ctx, a.mei.person.ID, a.providerID); err != nil {
				t.Fatal(err)
			}
		}},
		{"agent suspended", func(t *testing.T, a *accessEnv) {
			exec(t, a, `UPDATE agents SET status = 'suspended' WHERE id = ?`, a.agent.ID)
		}},
		{"agent revoked", func(t *testing.T, a *accessEnv) {
			exec(t, a, `UPDATE agents SET status = 'revoked' WHERE id = ?`, a.agent.ID)
		}},
		{"owner suspended", func(t *testing.T, a *accessEnv) {
			exec(t, a, `UPDATE persons SET status = 'suspended' WHERE id = ?`, a.mei.person.ID)
		}},
		{"cloud account disabled", func(t *testing.T, a *accessEnv) {
			p, err := a.srv.db.GetProvider(ctx, a.providerID)
			if err != nil {
				t.Fatal(err)
			}
			p.Status = model.ProviderDisabled
			if err := a.srv.db.UpdateProvider(ctx, p); err != nil {
				t.Fatal(err)
			}
		}},
		{"longest validity lowered", func(t *testing.T, a *accessEnv) {
			settings := model.DefaultPolicySettings()
			settings.MaxLeaseTTLSeconds = 300
			if err := a.srv.db.SetPolicySettings(ctx, settings); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		for _, automatic := range []bool{false, true} {
			name := tc.name + " during an approval"
			if automatic {
				name = tc.name + " during an automatic issue"
			}
			t.Run(name, func(t *testing.T) {
				a := newAccessEnv(t, model.RoleMember)
				var leaseID string
				var rec *httptest.ResponseRecorder
				if automatic {
					a.minter.onMint = func(provider.MintRequest) { tc.breakIt(t, a) }
					rec = a.requestRaw(a.token, accessInput("ecs", "read"))
					leaseID = a.minter.lastRequest(t).LeaseID
				} else {
					leaseID = a.request(accessInput("ecs", "write")).ID
					a.minter.onMint = func(provider.MintRequest) { tc.breakIt(t, a) }
					rec = a.approve(a.mei, leaseID)
				}
				requireErrorCode(t, rec, http.StatusConflict, model.ErrCodeConflict)
				got := a.getLease(leaseID)
				if got.Status != model.LeaseRevoked || got.CredentialAvailable {
					t.Fatalf("request = %q credential_available=%v, want revoked without a credential", got.Status, got.CredentialAvailable)
				}
				if _, err := a.srv.db.GetLeaseCredential(ctx, leaseID); !errors.Is(err, store.ErrNotFound) {
					t.Fatalf("stored credential: err = %v, want ErrNotFound", err)
				}
				if !a.hasAction("lease.activation_aborted") {
					t.Fatal("missing lease.activation_aborted audit event")
				}
				a.verifyAudit()
			})
		}
	}
}

// Two approvals of one waiting request at the same moment (double click,
// client retry) must mint once and leave the winner's credential usable.
func TestConcurrentApprovalsMintOnceAndKeepWinnerCredential(t *testing.T) {
	for round := 0; round < 5; round++ {
		a := newAccessEnv(t, model.RoleMember)
		req := a.request(accessInput("ecs", "write"))

		codes := make(chan int, 2)
		start := make(chan struct{})
		for i := 0; i < 2; i++ {
			go func() {
				<-start
				codes <- a.approve(a.mei, req.ID).Code
			}()
		}
		close(start)
		first, second := <-codes, <-codes
		if !((first == http.StatusOK && second == http.StatusConflict) || (first == http.StatusConflict && second == http.StatusOK)) {
			t.Fatalf("round %d: approval codes = %d, %d; want one 200 and one 409", round, first, second)
		}
		if n := a.minter.requestCount(); n != 1 {
			t.Fatalf("round %d: minted %d times, want 1", round, n)
		}
		got := a.getLease(req.ID)
		if got.Status != model.LeaseActive || !got.CredentialAvailable {
			t.Fatalf("round %d: request = %q credential_available=%v, want active with a credential", round, got.Status, got.CredentialAvailable)
		}
		if rec := a.credential(req.ID); rec.Code != http.StatusOK {
			t.Fatalf("round %d: the winner's credential fetch = %d, want 200", round, rec.Code)
		}
	}
}

// A request that would be issued automatically, and someone acting on it
// after its pending row is written but before the automatic issue takes the
// lease's lock.
//   - The owner's approval is kept out by the agent's lock: it waits, then
//     finds the request already issued (the first subtest).
//   - A supervisor's deny does not wait: the automatic issue must see that
//     the request is no longer pending and not mint over the decision (the
//     second subtest; it fails without the status check under the lock).
func TestAutomaticIssueAndADecisionBeforeItsLock(t *testing.T) {
	// The owner cannot get in between: an approval waits for the agent's
	// request in flight, then finds the request already issued.
	t.Run("the owner's approval waits for the agent's lock", func(t *testing.T) {
		a := newAccessEnv(t, model.RoleGuest)
		approval := make(chan int, 1)
		a.srv.hookBeforeAutoLock = func(leaseID string) {
			started := make(chan struct{})
			go func() {
				close(started)
				approval <- a.approve(a.mei, leaseID).Code
			}()
			<-started
			time.Sleep(50 * time.Millisecond) // let it reach the agent's lock
		}
		rec := a.requestRaw(a.token, accessInput("ecs", "read"))
		requireStatus(t, rec, http.StatusCreated)
		if got := decodeEnvelope[model.AccessRequest](t, rec); got.Status != model.LeaseActive {
			t.Fatalf("automatic request = %s", got.Status)
		}
		if code := <-approval; code != http.StatusConflict {
			t.Fatalf("approval of a request already issued = %d, want 409", code)
		}
		if n := a.minter.requestCount(); n != 1 {
			t.Fatalf("minted %d times, want 1", n)
		}
		leaseID := a.onlyLeaseID()
		if got := a.getLease(leaseID); got.Status != model.LeaseActive || got.ApprovedBy != "auto" {
			t.Fatalf("request = %q approved by %q, want active by auto", got.Status, got.ApprovedBy)
		}
		requireStatus(t, a.credential(leaseID), http.StatusOK)
	})
	t.Run("a supervisor's deny is not minted over", func(t *testing.T) {
		a := newAccessEnv(t, model.RoleGuest)
		a.srv.hookBeforeAutoLock = func(leaseID string) {
			rec := a.sup.do(http.MethodPost, "/api/v1/supervisor/leases/"+leaseID+"/deny", model.DenyLeaseInput{Reason: "stop"})
			requireStatus(t, rec, http.StatusOK)
		}
		requireErrorCode(t, a.requestRaw(a.token, accessInput("ecs", "read")), http.StatusConflict, model.ErrCodeConflict)
		if n := a.minter.requestCount(); n != 0 {
			t.Fatalf("minted %d times for a denied request", n)
		}
		leaseID := a.onlyLeaseID()
		if got := a.getLease(leaseID); got.Status != model.LeaseDenied {
			t.Fatalf("request = %q, want denied", got.Status)
		}
		if rec := a.credential(leaseID); rec.Code == http.StatusOK {
			t.Fatal("a denied request handed out a credential")
		}
	})
}

// The exact interleaving an earlier review found. The approval passes its
// check after minting; an authority change commits; the activation write
// lands; only then does the change's sweep run. The sweep must see the active
// request and revoke it.
func TestChangeBetweenRecheckAndActivationIsEnforced(t *testing.T) {
	cases := []struct {
		name   string
		kind   string
		change func(a *accessEnv) *httptest.ResponseRecorder
	}{
		{"role lowered", "binding", func(a *accessEnv) *httptest.ResponseRecorder {
			return a.sup.do(http.MethodPut, "/api/v1/supervisor/accounts/"+a.providerID+"/people/"+a.mei.person.ID,
				model.PutBindingInput{Role: model.RoleGuest})
		}},
		{"role removed", "binding", func(a *accessEnv) *httptest.ResponseRecorder {
			return a.sup.do(http.MethodDelete, "/api/v1/supervisor/accounts/"+a.providerID+"/people/"+a.mei.person.ID, nil)
		}},
		{"owner suspended", "person", func(a *accessEnv) *httptest.ResponseRecorder {
			suspended := model.PersonSuspended
			return a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{Status: &suspended})
		}},
		{"cloud account disabled", "provider", func(a *accessEnv) *httptest.ResponseRecorder {
			return a.sup.do(http.MethodPatch, "/api/v1/supervisor/accounts/"+a.providerID, map[string]any{"status": "disabled"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAccessEnv(t, model.RoleMember)
			req := a.request(accessInput("ecs", "write"))

			rechecked, goActivate := make(chan struct{}), make(chan struct{})
			committed, goSweep := make(chan struct{}), make(chan struct{})
			a.srv.hookAfterLeaseRecheck = func(string) { close(rechecked); <-goActivate }
			a.srv.hookAfterAuthorityWrite = func(kind string) {
				if kind == tc.kind {
					close(committed)
					<-goSweep
				}
			}
			approveDone := make(chan int, 1)
			go func() { approveDone <- a.approve(a.mei, req.ID).Code }()
			<-rechecked
			changeDone := make(chan int, 1)
			go func() { changeDone <- tc.change(a).Code }()
			<-committed
			close(goActivate)
			if code := <-approveDone; code != http.StatusOK {
				t.Fatalf("approval = %d; the interleaving did not happen as intended", code)
			}
			if got := a.getLease(req.ID); got.Status != model.LeaseActive {
				t.Fatalf("request before the sweep = %q, want active", got.Status)
			}
			close(goSweep)
			if code := <-changeDone; code != http.StatusOK {
				t.Fatalf("change = %d, want 200", code)
			}
			if got := a.getLease(req.ID); got.Status != model.LeaseRevoked {
				t.Fatalf("request after %s = %q, want revoked by the change's sweep", tc.name, got.Status)
			}
			if rec := a.credential(req.ID); rec.Code == http.StatusOK {
				t.Fatalf("credential handed out after %s", tc.name)
			}
		})
	}
}

// An authority sweep must see every affected request even while other
// requests leave the pending/active set during the sweep. With LIMIT/OFFSET
// paging, rows shifted between pages were skipped.
func TestSuspensionSweepSeesEveryLeaseDuringConcurrentExpiry(t *testing.T) {
	ctx := context.Background()
	a := newAccessEnv(t, model.RoleMember)
	template := a.getLease(a.request(accessInput("ecs", "read")).ID)
	now := a.clock.Now()
	expires := now.Add(15 * time.Minute)
	const total = 2500
	ids := make([]string, 0, total)
	for i := 0; i < total; i++ {
		lease := template
		lease.ID = fmt.Sprintf("lea_many_%05d", i)
		created := now.Add(time.Duration(i) * time.Millisecond)
		lease.CreatedAt, lease.IssuedAt, lease.ExpiresAt = created, &created, &expires
		if err := a.srv.db.CreateLease(ctx, lease); err != nil {
			t.Fatalf("CreateLease: %v", err)
		}
		ids = append(ids, lease.ID)
	}
	// Concurrently move the 200 newest to expired while the sweep runs.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := total - 1; i >= total-200; i-- {
			l, err := a.srv.db.GetLease(ctx, ids[i])
			if err != nil {
				continue
			}
			l.Status = model.LeaseExpired
			_ = a.srv.db.UpdateLeaseIfStatus(ctx, l, model.LeaseActive)
		}
	}()
	suspended := model.PersonSuspended
	requireStatus(t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID,
		model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
	<-done

	left, err := a.srv.db.ListAllLeases(ctx, store.LeaseFilter{
		AgentID: a.agent.ID, Statuses: []model.LeaseStatus{model.LeasePending, model.LeaseActive},
	})
	if err != nil {
		t.Fatalf("ListAllLeases: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("%d requests of the suspended owner's agent are still pending or active (e.g. %s)", len(left), left[0].ID)
	}
}
