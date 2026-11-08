package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
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
	env := newTestEnv(t, true)
	// Unprefixed API paths are unknown regardless of auth.
	rec := env.admin(http.MethodGet, "/api/v1/nope", nil)
	requireErrorCode(t, rec, http.StatusNotFound, model.ErrCodeNotFound)

	// Authenticated requests to unknown sub-paths get JSON 404s.
	rec = env.agent("claude-code", http.MethodGet, "/api/v1/agent/nope", nil)
	requireErrorCode(t, rec, http.StatusNotFound, model.ErrCodeNotFound)
	rec = env.admin(http.MethodGet, "/api/v1/admin/nope", nil)
	requireErrorCode(t, rec, http.StatusNotFound, model.ErrCodeNotFound)
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
	env := newTestEnv(t, true)

	// No token.
	rec := env.do(http.MethodGet, "/api/v1/agent/me", "", nil)
	requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)

	// Malformed / non-bearer credentials.
	for _, bogus := range []string{"not-a-token", "Bearer", ""} {
		rec := env.do(http.MethodGet, "/api/v1/agent/me", bogus, nil)
		requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)
	}

	// Admin token on agent routes.
	rec = env.do(http.MethodGet, "/api/v1/agent/me", env.adminToken, nil)
	requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)
	rec = env.do(http.MethodPost, "/api/v1/agent/leases", env.adminToken, model.CreateLeaseInput{CapabilityID: "aliyun.cloud.read"})
	requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)

	// Agent token on admin routes.
	agentToken := env.agentTokens["claude-code"]
	rec = env.do(http.MethodGet, "/api/v1/admin/overview", agentToken, nil)
	requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)
	rec = env.do(http.MethodGet, "/api/v1/admin/audit/verify", agentToken, nil)
	requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)

	// Unknown / forged agent token.
	forged := token.AgentPrefix + strings.Repeat("A", 43)
	rec = env.do(http.MethodGet, "/api/v1/agent/me", forged, nil)
	requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)
	if !env.hasAction("auth.agent_auth_failed") {
		t.Fatal("forged agent token did not record auth.agent_auth_failed audit event")
	}

	// Invalid admin token.
	rec = env.do(http.MethodPost, "/api/v1/admin/login", token.AdminPrefix+strings.Repeat("B", 43), nil)
	requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)
	if !env.hasAction("auth.admin_auth_failed") {
		t.Fatal("invalid admin token did not record auth.admin_auth_failed audit event")
	}

	// Valid tokens reach their routes.
	rec = env.agent("claude-code", http.MethodGet, "/api/v1/agent/me", nil)
	requireStatus(t, rec, http.StatusOK)
	rec = env.admin(http.MethodGet, "/api/v1/admin/overview", nil)
	requireStatus(t, rec, http.StatusOK)

	// Audit chain is still intact after all auth failures.
	env.verifyAudit()
}

func TestSuspendedAgentIsForbidden(t *testing.T) {
	env := newTestEnv(t, true)
	agentID := env.agentIDs["claude-code"]
	rec := env.admin(http.MethodPost, "/api/v1/admin/agents/"+agentID+"/suspend", nil)
	requireStatus(t, rec, http.StatusOK)
	suspended := decodeEnvelope[model.Agent](t, rec)
	if suspended.Status != model.AgentSuspended {
		t.Fatalf("agent status = %q, want suspended", suspended.Status)
	}

	// Every agent endpoint must reject the suspended agent with 403.
	for _, path := range []string{"/api/v1/agent/me", "/api/v1/agent/capabilities", "/api/v1/agent/leases"} {
		rec = env.agent("claude-code", http.MethodGet, path, nil)
		requireErrorCode(t, rec, http.StatusForbidden, model.ErrCodeForbidden)
	}
	if !env.hasAction("agent.suspended") {
		t.Fatal("agent.suspended audit event missing")
	}

	// Re-activating restores access.
	rec = env.admin(http.MethodPost, "/api/v1/admin/agents/"+agentID+"/activate", nil)
	requireStatus(t, rec, http.StatusOK)
	rec = env.agent("claude-code", http.MethodGet, "/api/v1/agent/me", nil)
	requireStatus(t, rec, http.StatusOK)
}

func TestAgentMeAndCapabilities(t *testing.T) {
	env := newTestEnv(t, true)

	rec := env.agent("claude-code", http.MethodGet, "/api/v1/agent/me", nil)
	requireStatus(t, rec, http.StatusOK)
	me := decodeEnvelope[struct {
		Agent        model.Agent `json:"agent"`
		ActiveLeases int         `json:"active_leases"`
		ServerTime   time.Time   `json:"server_time"`
	}](t, rec)
	if me.Agent.Name != "claude-code" || me.Agent.Status != model.AgentActive {
		t.Fatalf("agent = %+v", me.Agent)
	}
	if me.ActiveLeases != 0 {
		t.Fatalf("active_leases = %d, want 0", me.ActiveLeases)
	}
	if !me.ServerTime.Equal(fixedTestTime) {
		t.Fatalf("server_time = %v, want %v", me.ServerTime, fixedTestTime)
	}
	if len(me.Agent.Grants) != 5 {
		t.Fatalf("claude-code grants = %v, want all 5 builtins", me.Agent.Grants)
	}

	// Claude-code sees exactly its granted + enabled capabilities.
	rec = env.agent("claude-code", http.MethodGet, "/api/v1/agent/capabilities", nil)
	requireStatus(t, rec, http.StatusOK)
	claudeCaps := decodeEnvelope[model.ListResponse[model.Capability]](t, rec)
	if claudeCaps.Total != 5 || len(claudeCaps.Items) != 5 {
		t.Fatalf("claude-code capabilities total=%d len=%d, want 5/5", claudeCaps.Total, len(claudeCaps.Items))
	}

	// Hermes only sees its one granted capability.
	rec = env.agent("hermes-researcher", http.MethodGet, "/api/v1/agent/capabilities", nil)
	requireStatus(t, rec, http.StatusOK)
	hermesCaps := decodeEnvelope[model.ListResponse[model.Capability]](t, rec)
	if hermesCaps.Total != 1 || len(hermesCaps.Items) != 1 || hermesCaps.Items[0].ID != "aliyun.cloud.read" {
		t.Fatalf("hermes capabilities = %+v, want only aliyun.cloud.read", hermesCaps)
	}

	// Heartbeat works.
	rec = env.agent("claude-code", http.MethodPost, "/api/v1/agent/heartbeat", nil)
	requireStatus(t, rec, http.StatusOK)
	heartbeat := decodeEnvelope[map[string]any](t, rec)
	if heartbeat["ok"] != true {
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
}

func TestInitBootstrapArtifacts(t *testing.T) {
	dir := t.TempDir()
	result, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: true})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !strings.HasPrefix(result.AdminToken, token.AdminPrefix) {
		t.Fatalf("admin token %q has wrong prefix", result.AdminToken)
	}
	if result.AdminTokenPrefix != token.DisplayPrefix(result.AdminToken) {
		t.Fatalf("admin token prefix = %q", result.AdminTokenPrefix)
	}
	if len(result.Agents) != 2 {
		t.Fatalf("demo Init created %d agents, want 2", len(result.Agents))
	}
	for _, agent := range result.Agents {
		if !strings.HasPrefix(agent.Token, token.AgentPrefix) {
			t.Fatalf("agent %s token %q has wrong prefix", agent.Name, agent.Token)
		}
	}
	if len(result.ProviderIDs) != 1 {
		t.Fatalf("demo Init created %d providers, want 1", len(result.ProviderIDs))
	}
	if len(result.CapabilityIDs) != 5 {
		t.Fatalf("demo Init seeded %d capabilities, want 5", len(result.CapabilityIDs))
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
	for metaKey, wantPrefix := range map[string]string{
		store.MetaInstanceID:     "csg_",
		store.MetaAdminTokenHash: "",
	} {
		value, err := db.GetMeta(ctx, metaKey)
		if err != nil {
			t.Fatalf("meta %s: %v", metaKey, err)
		}
		if wantPrefix != "" && !strings.HasPrefix(value, wantPrefix) {
			t.Errorf("meta %s = %q, want prefix %q", metaKey, value, wantPrefix)
		}
	}
	if hash, _ := db.GetMeta(ctx, store.MetaAdminTokenHash); hash != token.Hash(result.AdminToken) {
		t.Error("stored admin token hash does not match the returned admin token")
	}
	if mode, _ := db.GetMeta(ctx, store.MetaDemoMode); mode != "true" {
		t.Errorf("demo_mode = %q, want true", mode)
	}
	if version, _ := db.GetMeta(ctx, store.MetaSchemaVersion); version != "1" {
		t.Errorf("schema_version = %q, want 1", version)
	}
	caps, err := db.ListCapabilities(ctx)
	if err != nil || len(caps) != 5 {
		t.Fatalf("seeded capabilities = %d, %v", len(caps), err)
	}
	for _, c := range caps {
		if !c.Builtin || !c.Enabled {
			t.Errorf("capability %s builtin=%v enabled=%v, want true/true", c.ID, c.Builtin, c.Enabled)
		}
	}
	providers, err := db.ListProviders(ctx)
	if err != nil || len(providers) != 1 {
		t.Fatalf("seeded providers = %d, %v", len(providers), err)
	}
	if providers[0].Name != "demo-aliyun" || providers[0].Mode != model.ModeMock || providers[0].Status != model.ProviderActive {
		t.Fatalf("demo provider = %+v", providers[0])
	}
	agents, err := db.ListAgents(ctx)
	if err != nil || len(agents) != 2 {
		t.Fatalf("seeded agents = %d, %v", len(agents), err)
	}
	// Agent token hashes resolve; raw tokens are not stored.
	for _, agent := range result.Agents {
		if _, err := db.GetAgentByTokenHash(ctx, token.Hash(agent.Token)); err != nil {
			t.Errorf("agent token for %s does not resolve: %v", agent.Name, err)
		}
	}

	// Init is refused on an initialized dir.
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
	env := newTestEnv(t, true)
	ctx := context.Background()

	// First agent request refreshes last_seen_at.
	rec := env.agent("claude-code", http.MethodGet, "/api/v1/agent/me", nil)
	requireStatus(t, rec, http.StatusOK)
	first := decodeEnvelope[struct {
		Agent model.Agent `json:"agent"`
	}](t, rec).Agent.LastSeenAt
	if first == nil || !first.Equal(fixedTestTime) {
		t.Fatalf("last_seen_at after first request = %v, want %v", first, fixedTestTime)
	}

	// Requests within 60 s do not refresh it.
	env.clock.Advance(30 * time.Second)
	rec = env.agent("claude-code", http.MethodGet, "/api/v1/agent/me", nil)
	requireStatus(t, rec, http.StatusOK)
	stillFirst := decodeEnvelope[struct {
		Agent model.Agent `json:"agent"`
	}](t, rec).Agent.LastSeenAt
	if stillFirst == nil || !stillFirst.Equal(*first) {
		t.Fatalf("last_seen_at advanced within 60 s: %v", stillFirst)
	}

	// After 60 s it refreshes again.
	env.clock.Advance(31 * time.Second)
	rec = env.agent("claude-code", http.MethodGet, "/api/v1/agent/me", nil)
	requireStatus(t, rec, http.StatusOK)
	refreshed := decodeEnvelope[struct {
		Agent model.Agent `json:"agent"`
	}](t, rec).Agent.LastSeenAt
	want := fixedTestTime.Add(61 * time.Second)
	if refreshed == nil || !refreshed.Equal(want) {
		t.Fatalf("last_seen_at = %v, want %v", refreshed, want)
	}

	// Heartbeat touches last_seen explicitly and immediately.
	env.clock.Advance(5 * time.Second)
	rec = env.agent("claude-code", http.MethodPost, "/api/v1/agent/heartbeat", nil)
	requireStatus(t, rec, http.StatusOK)
	agent, err := env.srv.db.GetAgent(ctx, env.agentIDs["claude-code"])
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	heartbeatWant := fixedTestTime.Add(66 * time.Second)
	if agent.LastSeenAt == nil || !agent.LastSeenAt.Equal(heartbeatWant) {
		t.Fatalf("last_seen_at after heartbeat = %v, want %v", agent.LastSeenAt, heartbeatWant)
	}
}

func TestDisabledCapabilityHiddenFromAgentList(t *testing.T) {
	env := newTestEnv(t, true)
	// Disable a builtin capability.
	rec := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/aliyun.cloud.read", map[string]any{"enabled": false})
	requireStatus(t, rec, http.StatusOK)

	rec = env.agent("claude-code", http.MethodGet, "/api/v1/agent/capabilities", nil)
	requireStatus(t, rec, http.StatusOK)
	caps := decodeEnvelope[model.ListResponse[model.Capability]](t, rec)
	if caps.Total != 4 {
		t.Fatalf("agent capabilities total = %d, want 4 after disabling one", caps.Total)
	}
	for _, c := range caps.Items {
		if c.ID == "aliyun.cloud.read" {
			t.Fatal("disabled capability is still listed to the agent")
		}
	}
}
