package server

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
)

// Regression tests for the independent review of agent ownership and sign-in.

// bindDirect gives a person a role on the demo cloud account, writing the
// binding straight to the store.
func (e *testEnv) bindDirect(personID string, role model.Role) {
	e.t.Helper()
	now := e.clock.Now()
	err := e.srv.db.PutBinding(context.Background(), model.RoleBinding{
		PersonID: personID, ProviderID: e.providerID, Role: role, CreatedAt: now, UpdatedAt: now})
	if err != nil {
		e.t.Fatal(err)
	}
}

// accessLease posts an access request for the agent and returns the stored
// lease behind it.
func (e *testEnv) accessLease(tok, resource, permission string) model.Lease {
	e.t.Helper()
	in := model.AccessRequestInput{CloudAccountID: "1234567890123456", Resource: resource, Permission: permission, TTLSeconds: 600}
	if permission != "read" {
		in.Reason = "change for a test"
	}
	rec := e.do(http.MethodPost, "/api/v1/agent/access-requests", tok, in)
	requireStatus(e.t, rec, http.StatusCreated)
	lease, err := e.srv.db.GetLease(context.Background(), decodeEnvelope[model.AccessRequest](e.t, rec).ID)
	if err != nil {
		e.t.Fatal(err)
	}
	return lease
}

// ownedAgentWithLease signs an agent in for owner, makes the owner a member
// of the demo cloud account and gives the agent an active read credential.
func (e *testEnv) ownedAgentWithLease(owner *personClient, name string) (model.Agent, string, model.Lease) {
	e.t.Helper()
	ag, tok := e.signInAgent(owner, name)
	e.bindDirect(owner.person.ID, model.RoleMember)
	lease := e.accessLease(tok, "ecs", "read")
	if lease.Status != model.LeaseActive {
		e.t.Fatalf("setup lease not active: %+v", lease)
	}
	return ag, tok, lease
}

// restart closes the server and starts a new one on the same data directory.
func (e *testEnv) restart() {
	e.t.Helper()
	if err := e.srv.Close(); err != nil {
		e.t.Fatal(err)
	}
	srv, err := New(Config{
		Addr: "127.0.0.1:0", DataDir: e.dir, Now: e.clock.Now,
		PasswordParams: &authn.Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32},
		MinterFactory:  func(model.Provider) (provider.Minter, error) { return e.minter, nil },
	})
	if err != nil {
		e.t.Fatalf("restart: %v", err)
	}
	srv.logWriter = log.New(e.logs, "", 0)
	e.t.Cleanup(func() { _ = srv.Close() })
	e.srv = srv
}

// Local recovery resets the owner; their agents' leases must not survive it,
// even after the owner sets up again and the agent's token works again.
func TestRecoveryRevokesOwnedAgentLeases(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	_, tok, lease := env.ownedAgentWithLease(mei, "mei-agent")

	out, err := RecoverSupervisor(context.Background(), RecoverOptions{DataDir: env.dir, Username: "mei"})
	if err != nil {
		t.Fatal(err)
	}
	if got := env.getLease(lease.ID); got.Status != model.LeaseRevoked || got.CredentialAvailable {
		t.Fatalf("lease after recovery: %+v", got)
	}
	if _, err := env.srv.db.GetLeaseCredential(context.Background(), lease.ID); err == nil {
		t.Fatal("stored credential survived recovery")
	}
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", tok, nil), http.StatusForbidden)

	env.completeSetup(out.SetupCode)
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", tok, nil), http.StatusOK)
	requireStatus(t, env.do(http.MethodPost, "/api/v1/agent/leases/"+lease.ID+"/credential", tok, nil), http.StatusConflict)
	events := env.listAudit("person.supervisor_recovered")
	if ids, _ := events[0].Metadata["revoked_lease_ids"].([]any); len(ids) != 1 || ids[0] != lease.ID {
		t.Fatalf("recovery audit does not list the revoked lease: %+v", events[0].Metadata)
	}
}

// Authority that changed while the server was not looking (a crash between a
// status change and its sweep, a database edit) is enforced at startup.
func TestStartupRevokesLeasesThatAreNoLongerAuthorized(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	_, _, owned := env.ownedAgentWithLease(mei, "mei-agent")
	legacy, rec := env.createLease(demoAgentClaudeCode, model.CreateLeaseInput{CapabilityID: "aliyun.cloud.read", Reason: "look"})
	requireStatus(t, rec, http.StatusCreated)

	if _, err := env.srv.db.SQL().Exec(`UPDATE persons SET status = 'suspended' WHERE id = ?`, mei.person.ID); err != nil {
		t.Fatal(err)
	}
	if got := env.getLease(owned.ID); got.Status != model.LeaseActive {
		t.Fatalf("precondition: lease is %s", got.Status)
	}
	env.restart()
	if got := env.getLease(owned.ID); got.Status != model.LeaseRevoked {
		t.Fatalf("lease of a suspended owner's agent after restart: %s", got.Status)
	}
	if got := env.getLease(legacy.ID); got.Status != model.LeaseActive {
		t.Fatalf("an authorized lease was revoked at startup: %s", got.Status)
	}
	ev := env.listAudit("lease.revoked")[0]
	if ev.ActorType != "system" || ev.Metadata["caused_by"] != "startup check" {
		t.Fatalf("startup revocation not attributed: %+v", ev)
	}
}

// Suspending the owner revokes active and pending leases at once, and the
// audit log says who caused it and whose agent it was.
func TestOwnerSuspensionRevokesAndIsAttributed(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	ag, tok, active := env.ownedAgentWithLease(mei, "mei-agent")
	pending := env.accessLease(tok, "dns", "write")
	if pending.Status != model.LeasePending {
		t.Fatalf("write lease not pending: %+v", pending)
	}
	suspended := model.PersonSuspended
	requireStatus(t, sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+mei.person.ID, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
	for _, id := range []string{active.ID, pending.ID} {
		if got := env.getLease(id); got.Status != model.LeaseRevoked {
			t.Fatalf("lease %s after suspension: %s", id, got.Status)
		}
	}
	events := env.listAudit("lease.revoked")
	if len(events) != 2 {
		t.Fatalf("%d lease.revoked events, want 2", len(events))
	}
	for _, ev := range events {
		m := ev.Metadata
		if ev.ActorType != "system" || m["caused_by"] != "person:"+sup.person.ID || m["caused_by_username"] != "admin" ||
			m["owner_id"] != mei.person.ID || m["agent_id"] != ag.ID || m["agent_name"] != "mei-agent" {
			t.Fatalf("revocation not attributed to the supervisor and the agent: %+v %+v", ev, m)
		}
	}
	// An owner revoking their own agent is attributed to the owner.
	requireStatus(t, sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+mei.person.ID,
		model.UpdatePersonInput{Status: func() *model.PersonStatus { s := model.PersonActive; return &s }()}), http.StatusOK)
	_, _, lease := env.ownedAgentWithLease(sup, "sup-agent")
	agents := decodeEnvelope[listData[model.Agent]](t, sup.do(http.MethodGet, "/api/v1/me/agents", nil)).Items
	requireStatus(t, sup.do(http.MethodPost, "/api/v1/me/agents/"+agents[0].ID+"/revoke", nil), http.StatusOK)
	ev := env.listAudit("lease.revoked")[0]
	if ev.TargetID != lease.ID || ev.Metadata["caused_by"] != "person:"+sup.person.ID {
		t.Fatalf("owner revocation not attributed: %+v", ev)
	}
}

// The owner is suspended while an approval is in flight: before the mint the
// approval fails; after the last check the suspension's sweep revokes the
// lease. Either way no lease stays active for a suspended owner.
func TestOwnerSuspendedDuringActivation(t *testing.T) {
	suspend := func(env *testEnv, sup *personClient, id string) int {
		s := model.PersonSuspended
		return sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+id, model.UpdatePersonInput{Status: &s}).Code
	}
	setup := func(t *testing.T) (*testEnv, *personClient, *personClient, model.Lease) {
		env := newTestEnv(t, true)
		sup := env.supervisorClient()
		mei := env.addPerson(sup, "mei", false)
		_, tok, _ := env.ownedAgentWithLease(mei, "mei-agent")
		pending := env.accessLease(tok, "dns", "write")
		if pending.Status != model.LeasePending {
			t.Fatalf("write request not pending: %+v", pending)
		}
		return env, sup, mei, pending
	}

	t.Run("during the mint", func(t *testing.T) {
		env, sup, mei, pending := setup(t)
		env.minter.mu.Lock()
		env.minter.onMint = func(provider.MintRequest) {
			if code := suspend(env, sup, mei.person.ID); code != http.StatusOK {
				t.Errorf("suspend = %d", code)
			}
		}
		env.minter.mu.Unlock()
		rec := mei.do(http.MethodPost, "/api/v1/me/requests/"+pending.ID+"/approve", nil)
		requireStatus(t, rec, http.StatusConflict)
		if got := env.getLease(pending.ID); got.Status == model.LeaseActive || got.CredentialAvailable {
			t.Fatalf("lease activated for a suspended owner: %+v", got)
		}
		if _, err := env.srv.db.GetLeaseCredential(context.Background(), pending.ID); err == nil {
			t.Fatal("a credential was stored for a suspended owner's agent")
		}
	})

	t.Run("after the last check", func(t *testing.T) {
		env, sup, mei, pending := setup(t)
		rechecked, goActivate := make(chan struct{}), make(chan struct{})
		committed, goSweep := make(chan struct{}), make(chan struct{})
		env.srv.hookAfterLeaseRecheck = func(string) { close(rechecked); <-goActivate }
		env.srv.hookAfterAuthorityWrite = func(kind string) {
			if kind == "person" {
				close(committed)
				<-goSweep
			}
		}
		approveDone := make(chan int, 1)
		go func() {
			approveDone <- mei.do(http.MethodPost, "/api/v1/me/requests/"+pending.ID+"/approve", nil).Code
		}()
		<-rechecked
		suspendDone := make(chan int, 1)
		go func() { suspendDone <- suspend(env, sup, mei.person.ID) }()
		<-committed
		close(goActivate)
		if code := <-approveDone; code != http.StatusOK {
			t.Fatalf("approval = %d; the interleaving did not happen as intended", code)
		}
		close(goSweep)
		if code := <-suspendDone; code != http.StatusOK {
			t.Fatalf("suspend = %d", code)
		}
		if got := env.getLease(pending.ID); got.Status != model.LeaseRevoked {
			t.Fatalf("lease after the suspension's sweep = %s, want revoked", got.Status)
		}
	})
}

// A credential is not handed out once the lease, the agent or the owner has
// changed, even if the request passed authentication just before.
func TestCredentialReleaseIsRechecked(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	ag, _, lease := env.ownedAgentWithLease(mei, "mei-agent")
	ctx := context.Background()
	problem := func() string {
		p, err := env.srv.credentialReleaseProblem(ctx, ag.ID, lease.ID)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := env.srv.db.SQL().Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	if p := problem(); p != "" {
		t.Fatalf("healthy lease refused: %s", p)
	}
	exec(`UPDATE persons SET status = 'suspended' WHERE id = ?`, mei.person.ID)
	if p := problem(); !strings.Contains(p, "owner is suspended") {
		t.Fatalf("suspended owner: %q", p)
	}
	exec(`UPDATE persons SET status = 'active' WHERE id = ?`, mei.person.ID)
	exec(`UPDATE agents SET status = 'revoked' WHERE id = ?`, ag.ID)
	if p := problem(); !strings.Contains(p, "agent is revoked") {
		t.Fatalf("revoked agent: %q", p)
	}
	exec(`UPDATE agents SET status = 'active' WHERE id = ?`, ag.ID)
	exec(`UPDATE leases SET status = 'revoked' WHERE id = ?`, lease.ID)
	if p := problem(); !strings.Contains(p, "lease is revoked") {
		t.Fatalf("revoked lease: %q", p)
	}
	exec(`UPDATE leases SET status = 'active' WHERE id = ?`, lease.ID)
	env.clock.Advance(lease.ExpiresAt.Sub(env.clock.Now()))
	if p := problem(); !strings.Contains(p, "expired") {
		t.Fatalf("expired lease: %q", p)
	}
}

func TestOwnerSurvivesAdminEditsAndLegacyAgentsAreUntouched(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	// Same name as the legacy demo agent, which has no owner.
	ag, tok := env.signInAgent(mei, demoAgentClaudeCode)

	rec := env.admin(http.MethodPost, "/api/v1/admin/agents/"+ag.ID+"/token/rotate", nil)
	requireStatus(t, rec, http.StatusOK)
	rotated := decodeEnvelope[model.AgentWithToken](t, rec)
	name := "renamed"
	requireStatus(t, env.admin(http.MethodPatch, "/api/v1/admin/agents/"+ag.ID, model.UpdateAgentInput{Name: &name}), http.StatusOK)
	stored, err := env.srv.db.GetAgent(context.Background(), ag.ID)
	if err != nil || stored.OwnerID != mei.person.ID {
		t.Fatalf("owner after admin edits: %+v, %v", stored, err)
	}
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", tok, nil), http.StatusUnauthorized)
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", rotated.Token, nil), http.StatusOK)

	// Re-sign-in replaces only the owner's own agent of that name.
	second, _ := env.signInAgent(mei, demoAgentClaudeCode)
	third, _ := env.signInAgent(mei, demoAgentClaudeCode)
	if got, _ := env.srv.db.GetAgent(context.Background(), second.ID); got.Status != model.AgentRevoked {
		t.Fatalf("replaced agent is %s", got.Status)
	}
	if got, _ := env.srv.db.GetAgent(context.Background(), third.ID); got.Status != model.AgentActive {
		t.Fatalf("new agent is %s", got.Status)
	}
	legacy, err := env.srv.db.GetAgent(context.Background(), env.agentIDs[demoAgentClaudeCode])
	if err != nil || legacy.Status != model.AgentActive || legacy.OwnerID != "" {
		t.Fatalf("legacy agent with the same name was touched: %+v, %v", legacy, err)
	}
	requireStatus(t, env.agent(demoAgentClaudeCode, http.MethodGet, "/api/v1/agent/me", nil), http.StatusOK)
}

func TestAgentSignInRefusesCrossSiteRequests(t *testing.T) {
	env := newTestEnv(t, false)
	post := func(path, body string, headers map[string]string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		env.srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	json := map[string]string{"Content-Type": "application/json"}
	for _, path := range []string{"/api/v1/agent-signin/start", "/api/v1/agent-signin/token"} {
		body := `{"agent_name":"phish","device_code":"x"}`
		if code := post(path, body, map[string]string{"Content-Type": "text/plain"}); code != http.StatusUnsupportedMediaType {
			t.Errorf("%s text/plain = %d", path, code)
		}
		if code := post(path, body, map[string]string{"Content-Type": "application/json", "Origin": "https://evil.example"}); code != http.StatusForbidden {
			t.Errorf("%s foreign origin = %d", path, code)
		}
		if code := post(path, body, map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"}); code != http.StatusForbidden {
			t.Errorf("%s cross-site = %d", path, code)
		}
	}
	if code := post("/api/v1/agent-signin/start", `{"agent_name":"real-agent"}`, json); code != http.StatusCreated {
		t.Errorf("plain agent request = %d", code)
	}
	if n := len(env.listAudit("agent_signin.started")); n != 1 {
		t.Fatalf("%d sign-ins started, want 1", n)
	}
}

func TestClientAddrBehindTrustedProxy(t *testing.T) {
	env := newTestEnv(t, false)
	addr := func(peer string, xff ...string) string {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = peer
		for _, v := range xff {
			req.Header.Add("X-Forwarded-For", v)
		}
		return env.srv.clientAddr(req)
	}
	// Without trusted proxies the header is ignored: it cannot be spoofed.
	if got := addr("203.0.113.9:5000", "198.51.100.1"); got != "203.0.113.9" {
		t.Fatalf("untrusted peer, no proxies: %s", got)
	}
	var err error
	if env.srv.trustedProxies, err = parseTrustedProxies([]string{"127.0.0.1", " 10.0.0.0/8 ", ""}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, peer string
		xff        []string
		want       string
	}{
		{"direct client, spoofed header", "203.0.113.9:5000", []string{"198.51.100.1"}, "203.0.113.9"},
		{"through the proxy", "127.0.0.1:4000", []string{"198.51.100.1"}, "198.51.100.1"},
		{"client-supplied entry is ignored", "127.0.0.1:4000", []string{"6.6.6.6, 198.51.100.1"}, "198.51.100.1"},
		{"two proxies", "127.0.0.1:4000", []string{"198.51.100.1, 10.1.2.3"}, "198.51.100.1"},
		{"split headers", "127.0.0.1:4000", []string{"6.6.6.6", "198.51.100.1"}, "198.51.100.1"},
		{"no header", "127.0.0.1:4000", nil, "127.0.0.1"},
		{"malformed header", "127.0.0.1:4000", []string{"not-an-ip"}, "127.0.0.1"},
		{"only proxies", "127.0.0.1:4000", []string{"10.0.0.2"}, "127.0.0.1"},
		{"ipv6 client", "127.0.0.1:4000", []string{"2001:db8::1"}, "2001:db8::1"},
	} {
		if got := addr(c.peer, c.xff...); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	if _, err := parseTrustedProxies([]string{"proxy.example"}); err == nil {
		t.Error("a hostname was accepted as a trusted proxy")
	}
	if p, _ := parseTrustedProxies([]string{"::ffff:10.0.0.1"}); len(p) != 1 || p[0] != netip.MustParsePrefix("10.0.0.1/32") {
		t.Errorf("mapped address not normalized: %v", p)
	}

	// Behind the proxy the per-address limit applies per real client.
	start := func(client string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-signin/start", strings.NewReader(`{"agent_name":"bot"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", client)
		req.RemoteAddr = "127.0.0.1:4000"
		rec := httptest.NewRecorder()
		env.srv.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < maxOpenSignInsPerAddr; i++ {
		if code := start("198.51.100.1"); code != http.StatusCreated {
			t.Fatalf("start %d = %d", i, code)
		}
	}
	if code := start("198.51.100.1"); code != http.StatusTooManyRequests {
		t.Fatalf("one client over its limit = %d", code)
	}
	if code := start("198.51.100.2"); code != http.StatusCreated {
		t.Fatalf("another client behind the same proxy = %d", code)
	}
}

func TestAPIHardening(t *testing.T) {
	env := newTestEnv(t, false)
	for _, rec := range []*httptest.ResponseRecorder{
		env.request(http.MethodGet, "/api/v1/auth/me", nil, nil, nil),                                                       // error
		env.request(http.MethodPost, "/api/v1/agent-signin/start", nil, nil, model.AgentSignInStartInput{AgentName: "bot"}), // data
	} {
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("status %d: Cache-Control = %q", rec.Code, got)
		}
	}
	for in, want := range map[string]string{
		"/api/v1/me/signins/K7Q-4XPM":         "/api/v1/me/signins/***",
		"/api/v1/me/signins/K7Q-4XPM/approve": "/api/v1/me/signins/***/approve",
		"/api/v1/me/signins/":                 "/api/v1/me/signins/",
		"/api/v1/me/agents":                   "/api/v1/me/agents",
	} {
		if got := logPath(in); got != want {
			t.Errorf("logPath(%q) = %q, want %q", in, got, want)
		}
	}
	// The user code never reaches the access log.
	sup := env.supervisorClient()
	start := env.startSignIn("bot")
	requireStatus(t, sup.do(http.MethodPost, "/api/v1/me/signins/"+start.UserCode+"/approve", nil), http.StatusOK)
	if strings.Contains(env.logs.String(), start.UserCode) {
		t.Fatal("the user code was written to the access log")
	}
	for i := 0; i < 200; i++ {
		code, err := newUserCode()
		if err != nil || len(code) != userCodeLength {
			t.Fatalf("newUserCode: %q, %v", code, err)
		}
		if _, ok := normalizeUserCode(formatUserCode(code)); !ok {
			t.Fatalf("generated code %q does not normalize", code)
		}
	}
}
