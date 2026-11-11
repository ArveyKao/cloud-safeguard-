package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

func (e *testEnv) startSignIn(name string) model.AgentSignInStart {
	e.t.Helper()
	rec := e.request(http.MethodPost, "/api/v1/agent-signin/start", nil, nil, model.AgentSignInStartInput{AgentName: name})
	requireStatus(e.t, rec, http.StatusCreated)
	return decodeEnvelope[model.AgentSignInStart](e.t, rec)
}

func (e *testEnv) pollSignIn(deviceCode string) model.AgentSignInResult {
	e.t.Helper()
	rec := e.request(http.MethodPost, "/api/v1/agent-signin/token", nil, nil, model.AgentSignInTokenInput{DeviceCode: deviceCode})
	requireStatus(e.t, rec, http.StatusOK)
	return decodeEnvelope[model.AgentSignInResult](e.t, rec)
}

// signInAgent runs the whole flow and returns the agent with its token.
func (e *testEnv) signInAgent(owner *personClient, name string) (model.Agent, string) {
	e.t.Helper()
	start := e.startSignIn(name)
	requireStatus(e.t, owner.do(http.MethodPost, "/api/v1/me/signins/"+start.UserCode+"/approve", nil), http.StatusOK)
	res := e.pollSignIn(start.DeviceCode)
	if res.Status != model.SignInApproved || res.Agent == nil || res.Token == "" {
		e.t.Fatalf("sign-in not completed: %+v", res)
	}
	return *res.Agent, res.Token
}

func TestAgentSignInFlow(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)

	start := env.startSignIn("cursor-ci")
	if len(start.UserCode) != userCodeLength+1 || start.DeviceCode == "" || start.IntervalSeconds <= 0 ||
		!strings.Contains(start.VerificationURL, start.UserCode) || !start.ExpiresAt.Equal(env.clock.Now().Add(signInTTL)) {
		t.Fatalf("unexpected start: %+v", start)
	}
	if got := env.pollSignIn(start.DeviceCode); got.Status != model.SignInPending || got.Token != "" {
		t.Fatalf("poll before approval: %+v", got)
	}

	// The person's side needs a session, and the CSRF token to decide.
	path := "/api/v1/me/signins/" + start.UserCode
	requireStatus(t, env.request(http.MethodGet, path, nil, nil, nil), http.StatusUnauthorized)
	requireStatus(t, env.request(http.MethodPost, path+"/approve", mei.cookie, nil, nil), http.StatusForbidden)
	// The code is accepted as typed: lower case, no dash.
	typed := strings.ToLower(strings.ReplaceAll(start.UserCode, "-", ""))
	rec := mei.do(http.MethodGet, "/api/v1/me/signins/"+typed, nil)
	requireStatus(t, rec, http.StatusOK)
	view := decodeEnvelope[model.AgentSignIn](t, rec)
	if view.AgentName != "cursor-ci" || view.Status != model.SignInPending || view.RemoteAddr == "" {
		t.Fatalf("unexpected view: %+v", view)
	}
	if strings.Contains(rec.Body.String(), start.DeviceCode) {
		t.Fatal("the person's view exposes the device code")
	}
	requireStatus(t, mei.do(http.MethodGet, "/api/v1/me/signins/ZZZ-ZZZZ", nil), http.StatusNotFound)

	requireStatus(t, mei.do(http.MethodPost, path+"/approve", nil), http.StatusOK)
	// A decision is final.
	requireStatus(t, mei.do(http.MethodPost, path+"/deny", nil), http.StatusNotFound)
	requireStatus(t, sup.do(http.MethodPost, path+"/approve", nil), http.StatusNotFound)

	res := env.pollSignIn(start.DeviceCode)
	if res.Status != model.SignInApproved || res.Agent == nil || res.Token == "" {
		t.Fatalf("poll after approval: %+v", res)
	}
	ag := *res.Agent
	if ag.OwnerID != mei.person.ID || ag.Name != "cursor-ci" || ag.Role != model.RoleGuest || len(ag.Grants) != 0 {
		t.Fatalf("unexpected agent: %+v", ag)
	}
	// The token is handed out exactly once.
	if again := env.pollSignIn(start.DeviceCode); again.Status != model.SignInExpired || again.Token != "" || again.Agent != nil {
		t.Fatalf("second poll: %+v", again)
	}

	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", res.Token, nil), http.StatusOK)
	// An owned agent has no grants: the §16 request path gives it nothing.
	recLease := env.do(http.MethodPost, "/api/v1/agent/leases", res.Token, model.CreateLeaseInput{CapabilityID: "aliyun.cloud.read", Reason: "look"})
	if lease := decodeEnvelope[model.Lease](t, recLease); lease.Status != model.LeaseDenied {
		t.Fatalf("owned agent got a lease through the old path: %+v", lease)
	}

	// Neither secret reached the audit log or the server log.
	events, _, err := env.srv.db.ListAudit(context.Background(), auditAll())
	if err != nil {
		t.Fatal(err)
	}
	dump, _ := json.Marshal(events)
	for _, secret := range []string{start.DeviceCode, res.Token} {
		if strings.Contains(string(dump), secret) || strings.Contains(env.logs.String(), secret) {
			t.Fatal("a secret leaked into the audit log or server log")
		}
	}
	if len(env.listAudit("agent_signin.approved")) != 1 || len(env.listAudit("agent_signin.completed")) != 1 {
		t.Fatal("sign-in not audited")
	}
	env.verifyAudit()
}

func TestAgentSignInDenyExpiryAndValidation(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()

	denied := env.startSignIn("worker-1")
	requireStatus(t, sup.do(http.MethodPost, "/api/v1/me/signins/"+denied.UserCode+"/deny", nil), http.StatusOK)
	if got := env.pollSignIn(denied.DeviceCode); got.Status != model.SignInDenied || got.Token != "" {
		t.Fatalf("poll after denial: %+v", got)
	}
	requireStatus(t, sup.do(http.MethodPost, "/api/v1/me/signins/"+denied.UserCode+"/approve", nil), http.StatusNotFound)

	// An unapproved sign-in expires; it can no longer be approved.
	stale := env.startSignIn("worker-2")
	// An approved sign-in also expires if the agent never collects.
	uncollected := env.startSignIn("worker-3")
	requireStatus(t, sup.do(http.MethodPost, "/api/v1/me/signins/"+uncollected.UserCode+"/approve", nil), http.StatusOK)
	env.clock.Advance(signInTTL)
	requireStatus(t, sup.do(http.MethodPost, "/api/v1/me/signins/"+stale.UserCode+"/approve", nil), http.StatusNotFound)
	for _, s := range []model.AgentSignInStart{stale, uncollected} {
		if got := env.pollSignIn(s.DeviceCode); got.Status != model.SignInExpired || got.Token != "" {
			t.Fatalf("poll after expiry: %+v", got)
		}
	}

	for _, name := range []string{"", "x", "-leading", "has space", "semi;colon", strings.Repeat("a", 65)} {
		rec := env.request(http.MethodPost, "/api/v1/agent-signin/start", nil, nil, model.AgentSignInStartInput{AgentName: name})
		requireStatus(t, rec, http.StatusBadRequest)
	}
	rec := env.request(http.MethodPost, "/api/v1/agent-signin/token", nil, nil, model.AgentSignInTokenInput{DeviceCode: "not-a-real-code"})
	requireStatus(t, rec, http.StatusNotFound)
}

// Parallel polls of one approved sign-in hand out exactly one token.
func TestAgentSignInTokenIssuedOnce(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	start := env.startSignIn("racer")
	requireStatus(t, sup.do(http.MethodPost, "/api/v1/me/signins/"+start.UserCode+"/approve", nil), http.StatusOK)

	const n = 8
	var wg sync.WaitGroup
	results := make([]model.AgentSignInResult, n)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = env.pollSignIn(start.DeviceCode)
		}()
	}
	wg.Wait()
	tokens := 0
	for _, r := range results {
		if r.Token != "" {
			tokens++
		}
	}
	agents, err := env.srv.db.ListAgentsByOwner(context.Background(), sup.person.ID)
	if err != nil {
		t.Fatal(err)
	}
	if tokens != 1 || len(agents) != 1 {
		t.Fatalf("%d tokens and %d agents from one sign-in, want 1 and 1", tokens, len(agents))
	}
}

func TestAgentSignInLimits(t *testing.T) {
	env := newTestEnv(t, false)
	for i := 0; i < maxOpenSignInsPerAddr; i++ {
		env.startSignIn("flood")
	}
	rec := env.request(http.MethodPost, "/api/v1/agent-signin/start", nil, nil, model.AgentSignInStartInput{AgentName: "flood"})
	requireErrorCode(t, rec, http.StatusTooManyRequests, model.ErrCodeRateLimited)
	// Another address is not affected, and the limit frees up with time.
	other := httptest.NewRequest(http.MethodPost, "/api/v1/agent-signin/start", strings.NewReader(`{"agent_name":"elsewhere"}`))
	other.Header.Set("Content-Type", "application/json")
	other.RemoteAddr = "198.51.100.7:4000"
	recOther := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(recOther, other)
	requireStatus(t, recOther, http.StatusCreated)
	env.clock.Advance(signInTTL)
	env.startSignIn("flood")
}

func TestAgentActsOnlyWhileOwnerIsActive(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	ag, tok := env.signInAgent(mei, "mei-agent")
	personPath := "/api/v1/supervisor/people/" + mei.person.ID
	suspended, active := model.PersonSuspended, model.PersonActive

	// Give the agent a lease through the legacy admin path, so there is
	// something to revoke.
	role := model.RoleGuest
	grants := []string{"aliyun.cloud.read"}
	requireStatus(t, env.admin(http.MethodPatch, "/api/v1/admin/agents/"+ag.ID, model.UpdateAgentInput{Role: &role, Grants: &grants}), http.StatusOK)
	rec := env.do(http.MethodPost, "/api/v1/agent/leases", tok, model.CreateLeaseInput{CapabilityID: "aliyun.cloud.read", Reason: "look"})
	lease := decodeEnvelope[model.Lease](t, rec)
	if lease.Status != model.LeaseActive {
		t.Fatalf("setup lease not active: %+v", lease)
	}

	requireStatus(t, sup.do(http.MethodPatch, personPath, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
	requireErrorCode(t, env.do(http.MethodGet, "/api/v1/agent/me", tok, nil), http.StatusForbidden, model.ErrCodeForbidden)
	requireStatus(t, env.do(http.MethodPost, "/api/v1/agent/leases/"+lease.ID+"/credential", tok, nil), http.StatusForbidden)
	if got := env.getLease(lease.ID); got.Status != model.LeaseRevoked || got.CredentialAvailable {
		t.Fatalf("lease after the owner was suspended: %+v", got)
	}

	// A suspended person cannot approve a sign-in, and one they approved
	// earlier yields no token.
	requireStatus(t, sup.do(http.MethodPatch, personPath, model.UpdatePersonInput{Status: &active}), http.StatusOK)
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", tok, nil), http.StatusOK)
	env.nextStep()
	relogin := env.login("mei", testPassword, env.totp(mei.secret, 0))
	requireStatus(t, relogin, http.StatusOK)
	mei.cookie, mei.csrf = sessionCookie(relogin), decodeEnvelope[model.SessionInfo](t, relogin).CSRFToken
	pendingPickup := env.startSignIn("late-agent")
	requireStatus(t, mei.do(http.MethodPost, "/api/v1/me/signins/"+pendingPickup.UserCode+"/approve", nil), http.StatusOK)
	requireStatus(t, sup.do(http.MethodPatch, personPath, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
	if got := env.pollSignIn(pendingPickup.DeviceCode); got.Token != "" || got.Agent != nil {
		t.Fatalf("token issued for a suspended owner: %+v", got.Status)
	}

	// A pending lease of an owned agent cannot be approved while the owner
	// is suspended.
	requireStatus(t, sup.do(http.MethodPatch, personPath, model.UpdatePersonInput{Status: &active}), http.StatusOK)
	member := model.RoleMember
	writeGrants := []string{"aliyun.dns.manage"}
	requireStatus(t, env.admin(http.MethodPatch, "/api/v1/admin/agents/"+ag.ID, model.UpdateAgentInput{Role: &member, Grants: &writeGrants}), http.StatusOK)
	rec = env.do(http.MethodPost, "/api/v1/agent/leases", tok, model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage", Params: map[string]string{"domain": "arveykao.com"}, Reason: "dns change"})
	pending := decodeEnvelope[model.Lease](t, rec)
	if pending.Status != model.LeasePending {
		t.Fatalf("write lease not pending: %+v", pending)
	}
	if _, err := env.srv.db.SQL().Exec(`UPDATE persons SET status = 'suspended' WHERE id = ?`, mei.person.ID); err != nil {
		t.Fatal(err) // bypass the sweep to test the approval-time check alone
	}
	requireErrorCode(t, env.admin(http.MethodPost, "/api/v1/admin/leases/"+pending.ID+"/approve", model.ApproveLeaseInput{}),
		http.StatusConflict, model.ErrCodeConflict)
	if env.minter.requestCount() != 1 {
		t.Fatalf("minted %d times, want 1 (the first read lease only)", env.minter.requestCount())
	}
}

func TestOwnerManagesOnlyOwnAgents(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	jun := env.addPerson(sup, "jun", false)
	meiAgent, meiToken := env.signInAgent(mei, "shared-name")
	junAgent, junToken := env.signInAgent(jun, "shared-name")

	list := func(c *personClient) []model.Agent {
		rec := c.do(http.MethodGet, "/api/v1/me/agents", nil)
		requireStatus(t, rec, http.StatusOK)
		return decodeEnvelope[listData[model.Agent]](t, rec).Items
	}
	if got := list(mei); len(got) != 1 || got[0].ID != meiAgent.ID {
		t.Fatalf("mei's agents: %+v", got)
	}
	if got := list(sup); len(got) != 0 {
		t.Fatalf("a supervisor sees other people's agents: %+v", got)
	}
	// Someone else's agent, a legacy agent and a missing one all look alike.
	for _, id := range []string{junAgent.ID, env.agentIDs[demoAgentClaudeCode], "agt_missing"} {
		requireStatus(t, mei.do(http.MethodPost, "/api/v1/me/agents/"+id+"/revoke", nil), http.StatusNotFound)
	}
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", junToken, nil), http.StatusOK)

	requireStatus(t, mei.do(http.MethodPost, "/api/v1/me/agents/"+meiAgent.ID+"/revoke", nil), http.StatusOK)
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", meiToken, nil), http.StatusForbidden)
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", junToken, nil), http.StatusOK)
}

// Signing in again under the same name replaces the owner's earlier agent:
// the old token dies and its leases are revoked. Other owners are untouched.
func TestSignInAgainReplacesTheAgent(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	old, oldToken := env.signInAgent(mei, "laptop")
	other, otherToken := env.signInAgent(sup, "laptop")

	role := model.RoleGuest
	grants := []string{"aliyun.cloud.read"}
	requireStatus(t, env.admin(http.MethodPatch, "/api/v1/admin/agents/"+old.ID, model.UpdateAgentInput{Role: &role, Grants: &grants}), http.StatusOK)
	lease := decodeEnvelope[model.Lease](t, env.do(http.MethodPost, "/api/v1/agent/leases", oldToken,
		model.CreateLeaseInput{CapabilityID: "aliyun.cloud.read", Reason: "look"}))
	if lease.Status != model.LeaseActive {
		t.Fatalf("setup lease: %+v", lease)
	}

	env.clock.Advance(time.Second)
	fresh, freshToken := env.signInAgent(mei, "laptop")
	if fresh.ID == old.ID || fresh.OwnerID != mei.person.ID || len(fresh.Grants) != 0 {
		t.Fatalf("replacement agent: %+v", fresh)
	}
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", oldToken, nil), http.StatusForbidden)
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", freshToken, nil), http.StatusOK)
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", otherToken, nil), http.StatusOK)
	if got := env.getLease(lease.ID); got.Status != model.LeaseRevoked {
		t.Fatalf("old agent's lease: %+v", got.Status)
	}
	if stored, err := env.srv.db.GetAgent(context.Background(), other.ID); err != nil || stored.Status != model.AgentActive {
		t.Fatalf("another owner's agent was touched: %+v, %v", stored, err)
	}
}
