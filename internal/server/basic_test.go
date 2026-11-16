package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/token"
)

func TestHealthEndpoint(t *testing.T) {
	env := newTestEnv(t, true)
	rec := env.do(http.MethodGet, "/healthz", "", nil)
	requireStatus(t, rec, http.StatusOK)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	// /healthz returns the object directly (no {"data":...} envelope).
	var health model.Health
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health.Status != "ok" || health.Version != model.Version || health.Name != model.ProductName {
		t.Fatalf("health = %+v", health)
	}
	if !health.Time.Equal(fixedTestTime) {
		t.Fatalf("health.Time = %v, want fixed clock %v", health.Time, fixedTestTime)
	}
}

func TestStaticSPAServing(t *testing.T) {
	env := newTestEnv(t, true)

	// Root serves the dashboard shell.
	root := env.do(http.MethodGet, "/", "", nil)
	requireStatus(t, root, http.StatusOK)
	if ct := root.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET / Content-Type = %q, want text/html", ct)
	}
	if !strings.Contains(strings.ToLower(root.Body.String()), "<html") {
		t.Fatalf("GET / body does not look like HTML: %.200s", root.Body.String())
	}

	// Unknown client-side routes fall back to the same shell.
	spa := env.do(http.MethodGet, "/leases/lea_nonexistent", "", nil)
	requireStatus(t, spa, http.StatusOK)
	if ct := spa.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("SPA fallback Content-Type = %q, want text/html", ct)
	}
	if spa.Body.String() != root.Body.String() {
		t.Fatal("SPA fallback body differs from the index shell")
	}

	// API paths never fall back to the SPA shell.
	api := env.do(http.MethodGet, "/api/v1/does-not-exist", "", nil)
	requireErrorCode(t, api, http.StatusNotFound, model.ErrCodeNotFound)

	// Write methods on non-API paths are rejected.
	post := env.do(http.MethodPost, "/", "", nil)
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST / status = %d, want 405", post.Code)
	}
}

func TestUnknownAPIEndpointsReturnJSON404(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	// Unprefixed API paths are unknown regardless of auth.
	for _, rec := range []*httptest.ResponseRecorder{
		a.do(http.MethodGet, "/api/v1/nope", "", nil),
		a.do(http.MethodGet, "/api/v1/nope", a.token, nil),
		a.sup.do(http.MethodGet, "/api/v1/nope", nil),
		// Authenticated requests to unknown sub-paths get JSON 404s.
		a.do(http.MethodGet, "/api/v1/agent/nope", a.token, nil),
		a.mei.do(http.MethodGet, "/api/v1/me/nope", nil),
		a.sup.do(http.MethodGet, "/api/v1/supervisor/nope", nil),
	} {
		requireErrorCode(t, rec, http.StatusNotFound, model.ErrCodeNotFound)
	}
}

func TestMockCloudMountOnlyWithMockProvider(t *testing.T) {
	// A non-demo install has no provider: the mock cloud must not be mounted.
	env := newTestEnv(t, false)
	rec := env.do(http.MethodGet, "/mock-cloud/v1/ecs/instances", "", nil)
	requireErrorCode(t, rec, http.StatusNotFound, model.ErrCodeNotFound)

	// A demo install has a mock provider: the path is routed (the mock cloud
	// package owns the exact response; here we only prove the mount).
	demo := newTestEnv(t, true)
	routed := demo.do(http.MethodGet, "/mock-cloud/v1/ecs/instances", "", nil)
	if routed.Code == http.StatusNotFound {
		t.Fatalf("mock cloud path is 404 even though a mock provider exists: %.300s", routed.Body.String())
	}
}

func TestAuthBoundaries(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	env := a.testEnv

	// No token.
	rec := env.do(http.MethodGet, "/api/v1/agent/me", "", nil)
	requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)

	// Malformed / non-bearer credentials, and the prefix of the removed
	// admin token.
	for _, bogus := range []string{"not-a-token", "Bearer", "csg_adm_" + strings.Repeat("B", 43)} {
		for _, path := range []string{"/api/v1/agent/me", "/api/v1/agent/accounts", "/api/v1/agent/leases"} {
			rec := env.do(http.MethodGet, path, bogus, nil)
			requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)
		}
	}

	// An agent token is not a console session.
	for _, path := range []string{"/api/v1/me/requests", "/api/v1/supervisor/accounts", "/api/v1/supervisor/audit/verify", "/api/v1/auth/me"} {
		rec = env.do(http.MethodGet, path, a.token, nil)
		requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)
	}
	// A console session is not an agent token, and a person who is not a
	// supervisor does not reach the supervisor routes.
	requireErrorCode(t, a.mei.do(http.MethodGet, "/api/v1/agent/me", nil), http.StatusUnauthorized, model.ErrCodeUnauthorized)
	requireErrorCode(t, a.mei.do(http.MethodGet, "/api/v1/supervisor/accounts", nil), http.StatusForbidden, model.ErrCodeForbidden)

	// Unknown / forged agent token.
	forged := token.AgentPrefix + strings.Repeat("A", 43)
	rec = env.do(http.MethodGet, "/api/v1/agent/me", forged, nil)
	requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)
	if !env.hasAction("auth.agent_auth_failed") {
		t.Fatal("forged agent token did not record auth.agent_auth_failed audit event")
	}

	// Valid credentials reach their routes.
	requireStatus(t, env.do(http.MethodGet, "/api/v1/agent/me", a.token, nil), http.StatusOK)
	requireStatus(t, a.mei.do(http.MethodGet, "/api/v1/me/requests", nil), http.StatusOK)
	requireStatus(t, a.sup.do(http.MethodGet, "/api/v1/supervisor/accounts", nil), http.StatusOK)

	// Audit chain is still intact after all auth failures.
	env.verifyAudit()
}

// An agent that is suspended or revoked is refused on every agent endpoint.
func TestInactiveAgentIsForbidden(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	paths := []string{"/api/v1/agent/me", "/api/v1/agent/accounts", "/api/v1/agent/leases"}
	if _, err := a.srv.db.SQL().Exec(`UPDATE agents SET status = 'suspended' WHERE id = ?`, a.agent.ID); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		requireErrorCode(t, a.do(http.MethodGet, path, a.token, nil), http.StatusForbidden, model.ErrCodeForbidden)
	}
	requireStatus(t, a.requestRaw(a.token, accessInput("ecs", "read")), http.StatusForbidden)
	if _, err := a.srv.db.SQL().Exec(`UPDATE agents SET status = 'active' WHERE id = ?`, a.agent.ID); err != nil {
		t.Fatal(err)
	}
	requireStatus(t, a.do(http.MethodGet, "/api/v1/agent/me", a.token, nil), http.StatusOK)

	// The owner revokes the agent in the console: it is refused for good.
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/agents/"+a.agent.ID+"/revoke", nil), http.StatusOK)
	for _, path := range paths {
		requireErrorCode(t, a.do(http.MethodGet, path, a.token, nil), http.StatusForbidden, model.ErrCodeForbidden)
	}
	requireStatus(t, a.requestRaw(a.token, accessInput("ecs", "read")), http.StatusForbidden)
	if a.leaseCount() != 0 {
		t.Fatal("an inactive agent created a request")
	}
}

func TestAgentMeAndHeartbeat(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	active := a.request(accessInput("ecs", "read"))

	rec := a.do(http.MethodGet, "/api/v1/agent/me", a.token, nil)
	requireStatus(t, rec, http.StatusOK)
	me := decodeEnvelope[struct {
		Agent        model.Agent `json:"agent"`
		ActiveLeases int         `json:"active_leases"`
		ServerTime   time.Time   `json:"server_time"`
	}](t, rec)
	if me.Agent.ID != a.agent.ID || me.Agent.Name != "mei-agent" || me.Agent.Status != model.AgentActive || me.Agent.OwnerID != a.mei.person.ID {
		t.Fatalf("agent = %+v", me.Agent)
	}
	if me.ActiveLeases != 1 || active.Status != model.LeaseActive {
		t.Fatalf("active_leases = %d, want 1", me.ActiveLeases)
	}
	if !me.ServerTime.Equal(a.clock.Now()) {
		t.Fatalf("server_time = %v, want %v", me.ServerTime, a.clock.Now())
	}
	// An agent has no role or grants of its own: it inherits its owner's role.
	if len(me.Agent.Grants) != 0 {
		t.Fatalf("agent has grants of its own: %v", me.Agent.Grants)
	}
	if strings.Contains(rec.Body.String(), a.token) {
		t.Fatal("agent/me returned the token")
	}

	rec = a.do(http.MethodPost, "/api/v1/agent/heartbeat", a.token, nil)
	requireStatus(t, rec, http.StatusOK)
	if heartbeat := decodeEnvelope[map[string]any](t, rec); heartbeat["ok"] != true {
		t.Fatalf("heartbeat = %+v", heartbeat)
	}
}

func TestUninitializedServerFailsWithInitHint(t *testing.T) {
	// Missing data dir entirely.
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := New(Config{DataDir: missing}); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("New(missing dir) error = %v, want ErrNotInitialized", err)
	} else if !strings.Contains(err.Error(), "csg init") {
		t.Fatalf("New(missing dir) error %q does not mention `csg init`", err)
	}

	// Directory exists but is empty.
	empty := t.TempDir()
	if _, err := New(Config{DataDir: empty}); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("New(empty dir) error = %v, want ErrNotInitialized", err)
	}

	// A master key without a database is still uninitialized.
	partial := t.TempDir()
	if err := os.WriteFile(filepath.Join(partial, "master.key"), make([]byte, 32), 0o600); err != nil {
		t.Fatalf("write partial key: %v", err)
	}
	if _, err := New(Config{DataDir: partial}); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("New(partial dir) error = %v, want ErrNotInitialized", err)
	}

	// A database that was created but never bootstrapped (no supervisor, no
	// settings) is uninitialized too, even though its schema is current.
	bare := t.TempDir()
	if err := os.WriteFile(filepath.Join(bare, "master.key"), make([]byte, 32), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	db, err := store.Open(context.Background(), bare)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	db.Close()
	if _, err := New(Config{DataDir: bare}); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("New(bare database) error = %v, want ErrNotInitialized", err)
	}
}

func TestInitBootstrapArtifacts(t *testing.T) {
	dir := t.TempDir()
	result, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: true})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if result.Supervisor == nil || result.Supervisor.SetupCode == "" || !result.Supervisor.Person.Supervisor {
		t.Fatalf("Init did not issue the first supervisor's setup code: %+v", result.Supervisor)
	}
	if len(result.ProviderIDs) != 1 {
		t.Fatalf("demo Init created %d cloud accounts, want 1", len(result.ProviderIDs))
	}
	// Init hands out no token of any kind: the setup code is the only secret.
	raw, _ := json.Marshal(result)
	for _, prefix := range []string{"csg_adm_", token.AgentPrefix} {
		if strings.Contains(string(raw), prefix) {
			t.Fatalf("InitResult carries a %s token: %s", prefix, raw)
		}
	}

	// File permissions and layout.
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat data dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("data dir mode = %o, want 0700", perm)
	}
	keyInfo, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("stat master.key: %v", err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("master.key mode = %o, want 0600", perm)
	}
	dbInfo, err := os.Stat(filepath.Join(dir, "csg.db"))
	if err != nil {
		t.Fatalf("stat csg.db: %v", err)
	}
	if perm := dbInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("csg.db mode = %o, want 0600", perm)
	}

	// Open the database directly to inspect the bootstrap meta + seed rows.
	db, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if id, err := db.GetMeta(ctx, store.MetaInstanceID); err != nil || !strings.HasPrefix(id, "csg_") {
		t.Errorf("instance id = %q, %v", id, err)
	}
	if _, err := db.GetMeta(ctx, store.MetaBootstrapTime); err != nil {
		t.Errorf("bootstrap time: %v", err)
	}
	for _, key := range []string{"admin_token_hash", "admin_token_prefix"} {
		if _, err := db.GetMeta(ctx, key); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("meta %s exists (err %v); no admin token may be created", key, err)
		}
	}
	if mode, _ := db.GetMeta(ctx, store.MetaDemoMode); mode != "true" {
		t.Errorf("demo_mode = %q, want true", mode)
	}
	wantSchema := strconv.Itoa(store.CurrentSchemaVersion)
	if version, _ := db.GetMeta(ctx, store.MetaSchemaVersion); version != wantSchema {
		t.Errorf("schema_version = %q, want %s", version, wantSchema)
	}
	// No stored capabilities and no agents: access templates live in code,
	// and agents exist only after a person approves their sign-in.
	if caps, err := db.ListCapabilities(ctx); err != nil || len(caps) != 0 {
		t.Fatalf("seeded capabilities = %d, %v; want none", len(caps), err)
	}
	if agents, err := db.ListAgents(ctx); err != nil || len(agents) != 0 {
		t.Fatalf("seeded agents = %d, %v; want none", len(agents), err)
	}
	providers, err := db.ListProviders(ctx)
	if err != nil || len(providers) != 1 {
		t.Fatalf("seeded providers = %d, %v", len(providers), err)
	}
	if providers[0].Name != "demo-aliyun" || providers[0].Mode != model.ModeMock || providers[0].Status != model.ProviderActive ||
		providers[0].CloudAccountID != demoAccountID || providers[0].MaxAutoLevel != model.ModeRead {
		t.Fatalf("demo provider = %+v", providers[0])
	}
	people, err := db.ListPersons(ctx)
	if err != nil || len(people) != 1 || !people[0].Supervisor || people[0].Status != model.PersonPending {
		t.Fatalf("bootstrap people = %+v, %v", people, err)
	}

	// Init never touches an initialized dir, and there is no way to force it.
	if _, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: true}); err == nil {
		t.Fatal("Init on an initialized dir succeeded, want refusal")
	} else if !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("re-init error = %v, want 'already initialized'", err)
	}

	// A Server can start on the initialized dir.
	srv, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New after Init: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestAgentLastSeenThrottled(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	env := a.testEnv
	ctx := context.Background()
	start := env.clock.Now()
	if _, err := env.srv.db.SQL().Exec(`UPDATE agents SET last_seen_at = NULL WHERE id = ?`, a.agent.ID); err != nil {
		t.Fatal(err)
	}

	// First agent request refreshes last_seen_at.
	rec := env.do(http.MethodGet, "/api/v1/agent/me", a.token, nil)
	requireStatus(t, rec, http.StatusOK)
	first := decodeEnvelope[struct {
		Agent model.Agent `json:"agent"`
	}](t, rec).Agent.LastSeenAt
	if first == nil || !first.Equal(start) {
		t.Fatalf("last_seen_at after first request = %v, want %v", first, start)
	}

	// Requests within 60 s do not refresh it.
	env.clock.Advance(30 * time.Second)
	rec = env.do(http.MethodGet, "/api/v1/agent/me", a.token, nil)
	requireStatus(t, rec, http.StatusOK)
	stillFirst := decodeEnvelope[struct {
		Agent model.Agent `json:"agent"`
	}](t, rec).Agent.LastSeenAt
	if stillFirst == nil || !stillFirst.Equal(*first) {
		t.Fatalf("last_seen_at advanced within 60 s: %v", stillFirst)
	}

	// After 60 s it refreshes again.
	env.clock.Advance(31 * time.Second)
	rec = env.do(http.MethodGet, "/api/v1/agent/me", a.token, nil)
	requireStatus(t, rec, http.StatusOK)
	refreshed := decodeEnvelope[struct {
		Agent model.Agent `json:"agent"`
	}](t, rec).Agent.LastSeenAt
	want := start.Add(61 * time.Second)
	if refreshed == nil || !refreshed.Equal(want) {
		t.Fatalf("last_seen_at = %v, want %v", refreshed, want)
	}

	// Heartbeat touches last_seen explicitly and immediately.
	env.clock.Advance(5 * time.Second)
	rec = env.do(http.MethodPost, "/api/v1/agent/heartbeat", a.token, nil)
	requireStatus(t, rec, http.StatusOK)
	agent, err := env.srv.db.GetAgent(ctx, a.agent.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	heartbeatWant := start.Add(66 * time.Second)
	if agent.LastSeenAt == nil || !agent.LastSeenAt.Equal(heartbeatWant) {
		t.Fatalf("last_seen_at after heartbeat = %v, want %v", agent.LastSeenAt, heartbeatWant)
	}
}
