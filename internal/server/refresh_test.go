package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
)

// Refresh (CONTRACT §17.12): a new key under the same request, within the
// request's refresh window.

func (a *accessEnv) refresh(token, id string) *httptest.ResponseRecorder {
	a.t.Helper()
	return a.do(http.MethodPost, "/api/v1/agent/access-requests/"+id+"/refresh", token, nil)
}

func TestRefreshWindowIsSetAtIssue(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	issued := a.clock.Now()
	req := a.request(accessInput("ecs", "read"))
	if req.MaxLifetimeSeconds != model.DefaultRefreshLifetimeSeconds || req.RefreshUntil == nil ||
		!req.RefreshUntil.Equal(issued.Add(8*time.Hour)) || req.RefreshCount != 0 {
		t.Fatalf("default window: %+v", req)
	}
	in := accessInput("dns", "read")
	in.MaxLifetimeSeconds = 3600
	if req := a.request(in); req.MaxLifetimeSeconds != 3600 || !req.RefreshUntil.Equal(issued.Add(time.Hour)) {
		t.Fatalf("declared window: %+v", req)
	}
	// Above the supervisor's limit, or shorter than one key: refused.
	for _, lifetime := range []int{24*3600 + 1, 599, -1} {
		in := accessInput("oss", "read")
		in.MaxLifetimeSeconds = lifetime
		requireStatus(t, a.requestRaw(a.token, in), http.StatusBadRequest)
	}
	// A request that waits gets its window when it is approved.
	waiting := a.request(accessInput("oss", "write"))
	if waiting.RefreshUntil != nil {
		t.Fatalf("a waiting request has a window: %+v", waiting)
	}
	a.clock.Advance(time.Minute)
	requireStatus(t, a.approve(a.mei, waiting.ID), http.StatusOK)
	rec := a.do(http.MethodGet, "/api/v1/agent/access-requests/"+waiting.ID, a.token, nil)
	if got := decodeEnvelope[model.AccessRequest](t, rec); got.RefreshUntil == nil || !got.RefreshUntil.Equal(a.clock.Now().Add(8*time.Hour)) {
		t.Fatalf("window after approval: %+v", got)
	}
}

func TestRefreshIssuesANewKey(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	req := a.request(accessInput("ecs", "read"))
	firstKey := decodeEnvelope[model.CredentialEnvelope](t, a.credential(req.ID)).Credential.AccessKeyID

	a.clock.Advance(5 * time.Minute)
	rec := a.refresh(a.token, req.ID)
	requireStatus(t, rec, http.StatusOK)
	got := decodeEnvelope[model.AccessRequest](t, rec)
	if got.Status != model.LeaseActive || got.RefreshCount != 1 || !got.ExpiresAt.Equal(a.clock.Now().Add(600*time.Second)) {
		t.Fatalf("after refresh: %+v", got)
	}
	if mint := a.minter.lastRequest(t); a.minter.requestCount() != 2 || mint.DurationSeconds != 600 || mint.LeaseID != req.ID {
		t.Fatalf("refresh minted %d times, last %+v", a.minter.requestCount(), mint)
	}
	if key := decodeEnvelope[model.CredentialEnvelope](t, a.credential(req.ID)).Credential.AccessKeyID; key == firstKey {
		t.Fatal("the stored key was not replaced")
	}
	// The same policy as the first key.
	if a.minter.requests[0].SessionName != a.minter.requests[1].SessionName ||
		string(a.minter.requests[0].PolicyJSON) != string(a.minter.requests[1].PolicyJSON) {
		t.Fatal("the refresh changed the policy")
	}
	// Once a minute at most.
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusTooManyRequests)
	a.clock.Advance(61 * time.Second)
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusOK)

	ev := a.listAudit("lease.refreshed")
	if len(ev) != 2 || ev[0].TargetID != req.ID || ev[0].Metadata["fingerprint"] == "" || ev[0].Metadata["owner_id"] != a.mei.person.ID {
		t.Fatalf("refresh audit = %+v", ev)
	}
	a.verifyAudit()
}

// The last key is shortened to the end of the window; after that, refused.
func TestRefreshStopsAtTheWindow(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	in := accessInput("ecs", "read")
	in.MaxLifetimeSeconds = 900
	req := a.request(in)
	a.clock.Advance(500 * time.Second)
	rec := a.refresh(a.token, req.ID)
	requireStatus(t, rec, http.StatusOK)
	if got := decodeEnvelope[model.AccessRequest](t, rec); !got.ExpiresAt.Equal(*req.RefreshUntil) {
		t.Fatalf("last key ends at %v, window at %v", got.ExpiresAt, req.RefreshUntil)
	}
	a.clock.Advance(397 * time.Second) // 3 s left, below the provider minimum
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusConflict)
	a.clock.Advance(10 * time.Second)
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusConflict)
}

func TestRefreshRefusals(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	req := a.request(accessInput("ecs", "read"))

	// Another agent, an unknown id, no token.
	jun := a.addPerson(a.sup, "jun", false)
	_, other := a.signInAgent(jun, "jun-agent")
	requireStatus(t, a.refresh(other, req.ID), http.StatusNotFound)
	requireStatus(t, a.refresh(a.token, "lea_00000000000000000000000000000000"), http.StatusNotFound)
	requireStatus(t, a.refresh(a.token, "lea_NOT-AN-ID"), http.StatusNotFound)
	requireStatus(t, a.refresh("", req.ID), http.StatusUnauthorized)

	// Not while waiting, nor after expiry or revocation.
	waiting := a.request(accessInput("dns", "write"))
	requireStatus(t, a.refresh(a.token, waiting.ID), http.StatusConflict)
	a.clock.Advance(601 * time.Second)
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusConflict)
	fresh := a.request(accessInput("oss", "read"))
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/requests/"+fresh.ID+"/revoke", nil), http.StatusOK)
	requireStatus(t, a.refresh(a.token, fresh.ID), http.StatusConflict)
	if n := len(a.listAudit("lease.refreshed")); n != 0 {
		t.Fatalf("%d refreshes recorded", n)
	}
}

// A refresh repeats the checks of a release: a lowered role stops it.
func TestRefreshRechecksTheRole(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	req := a.request(accessInput("ecs", "write"))
	mints := a.minter.requestCount()
	// Lowering the role revokes the write credential; reading it back as
	// active directly makes sure the refresh itself checks.
	a.bind(a.mei, model.RoleGuest)
	if _, err := a.srv.db.SQL().Exec(`UPDATE leases SET status = 'active' WHERE id = ?`, req.ID); err != nil {
		t.Fatal(err)
	}
	a.clock.Advance(2 * time.Minute)
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusConflict)
	if a.minter.requestCount() != mints {
		t.Fatal("minted for a role that no longer permits it")
	}
}

// A request approved above the mode is refreshed without a new approval.
func TestApprovedRequestRefreshesWithoutApproval(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	req := a.request(accessInput("ecs", "write"))
	requireStatus(t, a.approve(a.mei, req.ID), http.StatusOK)
	a.clock.Advance(2 * time.Minute)
	rec := a.refresh(a.token, req.ID)
	requireStatus(t, rec, http.StatusOK)
	if got := decodeEnvelope[model.AccessRequest](t, rec); got.Status != model.LeaseActive || got.RefreshCount != 1 {
		t.Fatalf("after refresh: %+v", got)
	}
}

// A revoke that lands while the new key is minted wins: nothing is stored
// and the request stays revoked.
func TestRefreshLosesToAConcurrentRevoke(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	req := a.request(accessInput("ecs", "read"))
	a.clock.Advance(2 * time.Minute)
	a.minter.onMint = func(provider.MintRequest) {
		a.minter.onMint = nil
		lease, err := a.srv.db.GetLease(context.Background(), req.ID)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := a.srv.revokeLeaseAsSystem(context.Background(), lease, "test"); err != nil {
			t.Error(err)
		}
	}
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusConflict)
	if a.status(req.ID) != model.LeaseRevoked {
		t.Fatal("the refresh undid the revoke")
	}
	if _, err := a.srv.db.GetLeaseCredential(context.Background(), req.ID); err == nil {
		t.Fatal("a credential was stored on a revoked request")
	}
}

// The supervisor's limit: kept by clients that do not send it, raising it
// is a raise.
func TestRefreshLimitSetting(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	rec := a.sup.do(http.MethodGet, "/api/v1/supervisor/settings", nil)
	settings := decodeEnvelope[model.PolicySettings](t, rec)
	if settings.MaxRefreshLifetimeSeconds != 24*3600 {
		t.Fatalf("default limit = %d", settings.MaxRefreshLifetimeSeconds)
	}
	old := map[string]int{"max_lease_ttl_seconds": settings.MaxLeaseTTLSeconds, "pending_timeout_seconds": settings.PendingTimeoutSeconds,
		"max_concurrent_leases_per_agent": settings.MaxConcurrentLeasesPerAgent, "leases_per_minute_per_agent": settings.LeasesPerMinutePerAgent}
	requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/settings", old), http.StatusOK)
	if got, _ := a.srv.db.GetPolicySettings(context.Background()); got.MaxRefreshLifetimeSeconds != 24*3600 {
		t.Fatalf("limit after an old client's write = %d", got.MaxRefreshLifetimeSeconds)
	}
	for _, bad := range []int{settings.MaxLeaseTTLSeconds - 1, model.MaxRefreshLifetimeLimit + 1} {
		s := settings
		s.MaxRefreshLifetimeSeconds = bad
		requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/settings", s), http.StatusBadRequest)
	}
	s := settings
	s.MaxRefreshLifetimeSeconds = 7 * 24 * 3600
	requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/settings", s), http.StatusOK)
	in := accessInput("ecs", "read")
	in.MaxLifetimeSeconds = 3 * 24 * 3600
	if req := a.request(in); req.MaxLifetimeSeconds != 3*24*3600 {
		t.Fatalf("declared window under a raised limit: %+v", req)
	}
	// Settings stored before the limit existed read as the default.
	if _, err := a.srv.db.SQL().Exec(`UPDATE meta SET value = json_remove(value, '$.max_refresh_lifetime_seconds') WHERE key = ?`,
		"policy_settings"); err != nil {
		t.Fatal(err)
	}
	if got, err := a.srv.db.GetPolicySettings(context.Background()); err != nil || got.MaxRefreshLifetimeSeconds != 24*3600 {
		t.Fatalf("old stored settings = %+v, %v", got, err)
	}
}

// ---- regression tests for the independent review of commit 762017d ----

// A sweep that listed the lease before a refresh does not expire it.
func TestStaleSweepDoesNotExpireARefreshedLease(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	req := a.request(accessInput("ecs", "read"))
	a.clock.Advance(590 * time.Second)
	stale, err := a.srv.db.GetLease(context.Background(), req.ID)
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusOK)
	a.clock.Advance(20 * time.Second) // past the old deadline, before the new one
	a.srv.expireLease(context.Background(), stale, "deadline reached")
	if a.status(req.ID) != model.LeaseActive {
		t.Fatal("a stale sweep expired a refreshed lease")
	}
	requireStatus(t, a.credential(req.ID), http.StatusOK)
	a.clock.Advance(600 * time.Second)
	a.srv.sweepOnce(context.Background())
	if a.status(req.ID) != model.LeaseExpired {
		t.Fatal("the refreshed lease did not expire at its own deadline")
	}
}

// Failed attempts count towards the once-a-minute limit.
func TestFailedRefreshAttemptsAreLimited(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	req := a.request(accessInput("ecs", "read"))
	a.minter.setFailure(errors.New("Throttling: try later"))
	mints := a.minter.requestCount()
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusBadGateway)
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusTooManyRequests)
	if a.minter.requestCount() != mints+1 {
		t.Fatalf("the cloud was asked %d times", a.minter.requestCount()-mints)
	}
	a.minter.setFailure(nil)
	a.clock.Advance(61 * time.Second)
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusOK)
}

// Two refreshes at once: exactly one wins.
func TestConcurrentRefreshesHaveOneWinner(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	req := a.request(accessInput("ecs", "read"))
	a.clock.Advance(2 * time.Minute)
	var wg sync.WaitGroup
	codes := make([]int, 4)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = a.refresh(a.token, req.ID).Code
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, c := range codes {
		if c == http.StatusOK {
			ok++
		}
	}
	lease, _ := a.srv.db.GetLease(context.Background(), req.ID)
	if ok != 1 || lease.RefreshCount != 1 {
		t.Fatalf("codes %v, refresh count %d", codes, lease.RefreshCount)
	}
}

// A lowered limit applies to waiting requests and to issued windows.
func TestLoweredRefreshLimitApplies(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	long := accessInput("ecs", "read")
	long.TTLSeconds = 3600
	issued := a.request(long) // one-hour key, 8 hour window
	in := accessInput("dns", "write")
	in.MaxLifetimeSeconds = 24 * 3600
	waiting := a.request(in)

	rec := a.sup.do(http.MethodGet, "/api/v1/supervisor/settings", nil)
	settings := decodeEnvelope[model.PolicySettings](t, rec)
	settings.MaxRefreshLifetimeSeconds = 3600
	requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/settings", settings), http.StatusOK)

	requireStatus(t, a.approve(a.mei, waiting.ID), http.StatusOK)
	got := decodeEnvelope[model.AccessRequest](t, a.do(http.MethodGet, "/api/v1/agent/access-requests/"+waiting.ID, a.token, nil))
	if got.MaxLifetimeSeconds != 3600 || !got.RefreshUntil.Equal(a.clock.Now().Add(time.Hour)) {
		t.Fatalf("approved under a lowered limit: %+v", got)
	}
	// The issued request's 8 hour window is cut to issue + 1 hour.
	a.clock.Advance(50 * time.Minute)
	rec = a.refresh(a.token, issued.ID)
	requireStatus(t, rec, http.StatusOK)
	if r := decodeEnvelope[model.AccessRequest](t, rec); !r.ExpiresAt.Equal(issued.IssuedAt.Add(time.Hour)) {
		t.Fatalf("refresh past the lowered limit: expires %v", r.ExpiresAt)
	}
	a.clock.Advance(10*time.Minute + time.Second)
	requireStatus(t, a.refresh(a.token, issued.ID), http.StatusConflict)
}

// Stored settings from before the limit never exceed 30 days.
func TestOldSettingsStayWithinThirtyDays(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	if _, err := a.srv.db.SQL().Exec(`UPDATE meta SET value = json_remove(json_set(value, '$.max_lease_ttl_seconds', ?), '$.max_refresh_lifetime_seconds') WHERE key = 'policy_settings'`,
		40*24*3600); err != nil {
		t.Fatal(err)
	}
	got, err := a.srv.db.GetPolicySettings(context.Background())
	if err != nil || got.MaxRefreshLifetimeSeconds != model.MaxRefreshLifetimeLimit {
		t.Fatalf("limit = %d, %v", got.MaxRefreshLifetimeSeconds, err)
	}
	in := accessInput("ecs", "read")
	in.MaxLifetimeSeconds = 35 * 24 * 3600
	requireStatus(t, a.requestRaw(a.token, in), http.StatusBadRequest)
}

// A lease from before refresh existed has no window and is not refreshed.
func TestLeaseWithoutWindowIsNotRefreshed(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	req := a.request(accessInput("ecs", "read"))
	if _, err := a.srv.db.SQL().Exec(`UPDATE leases SET refresh_until = NULL, max_lifetime_seconds = 0 WHERE id = ?`, req.ID); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, a.refresh(a.token, req.ID), http.StatusConflict)
}
