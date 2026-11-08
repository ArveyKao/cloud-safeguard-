package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

const (
	adminTokenA = "csg_adm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	adminTokenB = "csg_adm_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	agentTokenA = "csg_agt_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

// capsServer returns a fake admin API whose capability list contains one ID.
func capsServer(t *testing.T, capabilityID, wantToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/capabilities" {
			t.Errorf("unexpected path %s", r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected path")
			return
		}
		requireAuth(t, r, wantToken)
		writeEnvelope(w, http.StatusOK, model.ListResponse[model.Capability]{
			Items: []model.Capability{{ID: capabilityID, Name: capabilityID, Risk: model.RiskLow, Enabled: true}},
			Total: 1,
		})
	}))
}

func TestConfigPrecedence(t *testing.T) {
	serverA := capsServer(t, "cap_from_file", adminTokenA)
	defer serverA.Close()
	serverB := capsServer(t, "cap_from_env", adminTokenB)
	defer serverB.Close()

	ta := newTestApp(t)
	path, err := ta.app.saveFileConfig(fileConfig{Server: serverA.URL, Token: adminTokenA, Kind: "admin"})
	if err != nil {
		t.Fatalf("saveFileConfig: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config file mode = %04o, want 0600", perm)
	}

	// 1. Config file only.
	if code := ta.run("caps", "list"); code != ExitOK {
		t.Fatalf("file config: exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "cap_from_file") {
		t.Fatalf("file config output = %q", ta.out())
	}

	// 2. Environment beats the file.
	ta = newTestApp(t)
	if _, err := ta.app.saveFileConfig(fileConfig{Server: serverA.URL, Token: adminTokenA, Kind: "admin"}); err != nil {
		t.Fatalf("saveFileConfig: %v", err)
	}
	ta.env["CSG_SERVER"] = serverB.URL
	ta.env["CSG_TOKEN"] = adminTokenB
	if code := ta.run("caps", "list"); code != ExitOK {
		t.Fatalf("env config: exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "cap_from_env") {
		t.Fatalf("env config output = %q", ta.out())
	}

	// 3. Flags beat the environment.
	if code := ta.run("caps", "list", "--server", serverA.URL, "--token", adminTokenA); code != ExitOK {
		t.Fatalf("flag config: exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "cap_from_file") {
		t.Fatalf("flag config output = %q", ta.out())
	}
}

func TestLoginAdminThenWhoami(t *testing.T) {
	var loginCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/admin/login":
			loginCalls++
			requireAuth(t, r, adminTokenA)
			writeEnvelope(w, http.StatusOK, model.LoginResult{OK: true, Role: "admin", Version: model.Version})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected path")
		}
	}))
	defer srv.Close()

	ta := newTestApp(t)
	if code := ta.run("login", "--server", srv.URL, "--token", adminTokenA); code != ExitOK {
		t.Fatalf("login exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "logged in as admin") {
		t.Fatalf("login output = %q", ta.out())
	}
	if !strings.Contains(ta.out(), "config saved to") {
		t.Fatalf("login output missing config path: %q", ta.out())
	}

	path := filepath.Join(ta.home, ".config", "cloud-safeguard", "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	var cfg fileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("decode saved config: %v", err)
	}
	if cfg.Server != srv.URL || cfg.Token != adminTokenA || cfg.Kind != "admin" {
		t.Fatalf("saved config = %+v", cfg)
	}

	// whoami uses the saved config (no env/flags).
	ta.stdout.Reset()
	ta.stderr.Reset()
	if code := ta.run("whoami"); code != ExitOK {
		t.Fatalf("whoami exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "role:      admin") {
		t.Fatalf("whoami output = %q", ta.out())
	}
	if loginCalls != 2 {
		t.Fatalf("login endpoint calls = %d, want 2 (login + whoami)", loginCalls)
	}
}

func TestLoginAgentThenWhoamiJSON(t *testing.T) {
	agent := model.Agent{ID: "agt_demo1", Name: "claude-code", Status: model.AgentActive, Grants: []string{"aliyun.cloud.read"}, MaxTTLSeconds: 3600, MaxConcurrentLeases: 3}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/me" {
			t.Errorf("unexpected path %s", r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected path")
			return
		}
		requireAuth(t, r, agentTokenA)
		writeEnvelope(w, http.StatusOK, agentMe{Agent: agent, ActiveLeases: 2})
	}))
	defer srv.Close()

	ta := newTestApp(t)
	if code := ta.run("login", "--server", srv.URL, "--token", agentTokenA); code != ExitOK {
		t.Fatalf("login exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "agent claude-code") {
		t.Fatalf("login output = %q", ta.out())
	}

	ta.stdout.Reset()
	ta.stderr.Reset()
	if code := ta.run("whoami", "--json"); code != ExitOK {
		t.Fatalf("whoami --json exit = %d, stderr = %s", code, ta.errOut())
	}
	var payload agentMe
	if err := json.Unmarshal(ta.stdout.Bytes(), &payload); err != nil {
		t.Fatalf("whoami --json output = %q: %v", ta.out(), err)
	}
	if payload.Agent.Name != "claude-code" || payload.ActiveLeases != 2 {
		t.Fatalf("whoami payload = %+v", payload)
	}
}

func TestLoginValidation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "invalid token")
	}))
	defer srv.Close()

	ta := newTestApp(t)
	if code := ta.run("login", "--token", adminTokenA); code != ExitUsage {
		t.Fatalf("login without server exit = %d, want %d", code, ExitUsage)
	}
	if code := ta.run("login", "--server", srv.URL); code != ExitUsage {
		t.Fatalf("login without token exit = %d, want %d", code, ExitUsage)
	}
	if code := ta.run("login", "--server", srv.URL, "--token", "not-a-csg-token"); code != ExitUsage {
		t.Fatalf("login with unknown prefix exit = %d, want %d", code, ExitUsage)
	}
	if code := ta.run("login", "--server", "not-a-url", "--token", adminTokenA); code != ExitUsage {
		t.Fatalf("login with bad url exit = %d, want %d", code, ExitUsage)
	}

	// A server 401 surfaces as an auth exit code.
	if code := ta.run("login", "--server", srv.URL, "--token", adminTokenA); code != ExitAuth {
		t.Fatalf("login with rejected token exit = %d, want %d; stderr = %q", code, ExitAuth, ta.errOut())
	}
}

func TestMissingConfigurationExitCodes(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.run("caps", "list"); code != ExitUsage {
		t.Fatalf("no server exit = %d, want %d; stderr = %q", code, ExitUsage, ta.errOut())
	}

	ta = newTestApp(t)
	ta.env["CSG_SERVER"] = "http://127.0.0.1:8787"
	if code := ta.run("caps", "list"); code != ExitAuth {
		t.Fatalf("no token exit = %d, want %d; stderr = %q", code, ExitAuth, ta.errOut())
	}

	ta = newTestApp(t)
	ta.env["CSG_SERVER"] = "http://127.0.0.1:8787"
	ta.env["CSG_TOKEN"] = "opaque-token"
	if code := ta.run("whoami"); code != ExitAuth {
		t.Fatalf("opaque token whoami exit = %d, want %d; stderr = %q", code, ExitAuth, ta.errOut())
	}
}

func TestWrongTokenKindIsAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server must not be called for a token-kind mismatch (path %s)", r.URL.Path)
		writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "should not happen")
	}))
	defer server.Close()

	ta := newTestApp(t)
	ta.useServer(server.URL, adminTokenA)
	if code := ta.run("leases", "mine"); code != ExitAuth {
		t.Fatalf("admin token for agent command exit = %d, want %d; stderr = %q", code, ExitAuth, ta.errOut())
	}
	if !strings.Contains(ta.errOut(), "agent token required") {
		t.Fatalf("stderr = %q", ta.errOut())
	}

	ta = newTestApp(t)
	ta.useServer(server.URL, agentTokenA)
	if code := ta.run("caps", "list"); code != ExitAuth {
		t.Fatalf("agent token for admin command exit = %d, want %d", code, ExitAuth)
	}
	if !strings.Contains(ta.errOut(), "admin token required") {
		t.Fatalf("stderr = %q", ta.errOut())
	}
}

func TestServer401MapsToAuthExit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "invalid admin token")
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, adminTokenA)
	code := ta.run("caps", "list")
	if code != ExitAuth {
		t.Fatalf("exit = %d, want %d; stderr = %q", code, ExitAuth, ta.errOut())
	}
	if !strings.Contains(ta.errOut(), "invalid admin token") {
		t.Fatalf("stderr = %q", ta.errOut())
	}
}

func TestServer403MapsToOperationExit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErrorEnvelope(w, http.StatusForbidden, "forbidden", "token suspended")
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, adminTokenA)
	if code := ta.run("caps", "list"); code != ExitOperationErr {
		t.Fatalf("exit = %d, want %d; stderr = %q", code, ExitOperationErr, ta.errOut())
	}
}
