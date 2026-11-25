package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

const (
	agentTokenA = "csg_agt_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
	agentTokenB = "csg_agt_DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
	// oldAdminToken has the prefix of the removed admin token.
	oldAdminToken = "csg_adm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// accountsServer returns a fake agent API whose account list has one name.
func accountsServer(t *testing.T, accountName, wantToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agent/accounts" {
			t.Errorf("unexpected path %s", r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected path")
			return
		}
		requireAuth(t, r, wantToken)
		writeEnvelope(w, http.StatusOK, model.ListResponse[model.AgentAccount]{
			Items: []model.AgentAccount{{CloudAccountID: "1234567890123456", Name: accountName, Role: model.RoleGuest, HighestPermission: "read"}},
			Total: 1,
		})
	}))
}

func TestConfigPrecedence(t *testing.T) {
	serverA := accountsServer(t, "account_from_file", agentTokenA)
	defer serverA.Close()
	serverB := accountsServer(t, "account_from_env", agentTokenB)
	defer serverB.Close()

	ta := newTestApp(t)
	path, err := ta.app.saveFileConfig(fileConfig{Server: serverA.URL, Token: agentTokenA, Kind: "agent"})
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
	if code := ta.run("accounts"); code != ExitOK {
		t.Fatalf("file config: exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "account_from_file") {
		t.Fatalf("file config output = %q", ta.out())
	}

	// 2. Environment beats the file.
	ta = newTestApp(t)
	if _, err := ta.app.saveFileConfig(fileConfig{Server: serverA.URL, Token: agentTokenA, Kind: "agent"}); err != nil {
		t.Fatalf("saveFileConfig: %v", err)
	}
	ta.env["CSG_SERVER"] = serverB.URL
	ta.env["CSG_TOKEN"] = agentTokenB
	if code := ta.run("accounts"); code != ExitOK {
		t.Fatalf("env config: exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "account_from_env") {
		t.Fatalf("env config output = %q", ta.out())
	}

	// 3. Flags beat the environment.
	if code := ta.run("accounts", "--server", serverA.URL, "--token", agentTokenA); code != ExitOK {
		t.Fatalf("flag config: exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "account_from_file") {
		t.Fatalf("flag config output = %q", ta.out())
	}
}

func TestWhoami(t *testing.T) {
	agent := model.Agent{ID: "agt_demo1", Name: "claude-code", Status: model.AgentActive, OwnerID: "per_mei"}
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
	ta.useServer(srv.URL, agentTokenA)
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

	ta.stdout.Reset()
	if code := ta.run("whoami"); code != ExitOK {
		t.Fatalf("whoami exit = %d, stderr = %s", code, ta.errOut())
	}
	for _, want := range []string{"claude-code (agt_demo1)", "active requests: 2", srv.URL} {
		if !strings.Contains(ta.out(), want) {
			t.Fatalf("whoami output %q has no %q", ta.out(), want)
		}
	}
}

func TestLoginValidation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "invalid token")
	}))
	defer srv.Close()

	ta := newTestApp(t)
	if code := ta.run("login"); code != ExitUsage {
		t.Fatalf("login without server exit = %d, want %d", code, ExitUsage)
	}
	// login starts an agent sign-in; this fake server refuses everything, so
	// the sign-in fails as an auth error.
	if code := ta.run("login", "--server", srv.URL); code != ExitAuth {
		t.Fatalf("refused sign-in exit = %d, want %d", code, ExitAuth)
	}
	if code := ta.run("login", "--server", "not-a-url"); code != ExitUsage {
		t.Fatalf("login with bad url exit = %d, want %d", code, ExitUsage)
	}
	// A token cannot be pasted in any more: agents sign in.
	if code := ta.run("login", "--server", srv.URL, "--token", agentTokenA); code != ExitUsage {
		t.Fatalf("login --token exit = %d, want %d", code, ExitUsage)
	}
}

func TestMissingConfigurationExitCodes(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.run("accounts"); code != ExitUsage {
		t.Fatalf("no server exit = %d, want %d; stderr = %q", code, ExitUsage, ta.errOut())
	}

	ta = newTestApp(t)
	ta.env["CSG_SERVER"] = "http://127.0.0.1:8787"
	if code := ta.run("accounts"); code != ExitAuth {
		t.Fatalf("no token exit = %d, want %d; stderr = %q", code, ExitAuth, ta.errOut())
	}

	ta = newTestApp(t)
	ta.env["CSG_SERVER"] = "http://127.0.0.1:8787"
	ta.env["CSG_TOKEN"] = "opaque-token"
	if code := ta.run("whoami"); code != ExitAuth {
		t.Fatalf("opaque token whoami exit = %d, want %d; stderr = %q", code, ExitAuth, ta.errOut())
	}
}

// A token that is not an agent token (the removed admin token, for one) is
// refused before anything is sent to the server.
func TestWrongTokenKindIsAuthError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server must not be called for a token-kind mismatch (path %s)", r.URL.Path)
		writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "should not happen")
	}))
	defer server.Close()

	for _, command := range [][]string{{"leases", "mine"}, {"accounts"}, {"whoami"}} {
		ta := newTestApp(t)
		ta.useServer(server.URL, oldAdminToken)
		if code := ta.run(command...); code != ExitAuth {
			t.Fatalf("%v with an admin token exit = %d, want %d; stderr = %q", command, code, ExitAuth, ta.errOut())
		}
		if !strings.Contains(ta.errOut(), "agent token required") {
			t.Fatalf("%v stderr = %q", command, ta.errOut())
		}
	}
}

func TestServer401MapsToAuthExit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErrorEnvelope(w, http.StatusUnauthorized, "unauthorized", "invalid agent token")
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)
	code := ta.run("accounts")
	if code != ExitAuth {
		t.Fatalf("exit = %d, want %d; stderr = %q", code, ExitAuth, ta.errOut())
	}
	if !strings.Contains(ta.errOut(), "invalid agent token") {
		t.Fatalf("stderr = %q", ta.errOut())
	}
}

func TestServer403MapsToOperationExit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErrorEnvelope(w, http.StatusForbidden, "forbidden", "token suspended")
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)
	if code := ta.run("accounts"); code != ExitOperationErr {
		t.Fatalf("exit = %d, want %d; stderr = %q", code, ExitOperationErr, ta.errOut())
	}
}
