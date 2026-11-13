package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/server"
)

// End to end against a real control plane: the agent signs in, asks for
// access, runs a command and talks MCP; a person approves in between.

const e2eAccount = "1234567890123456"

type e2e struct {
	t        *testing.T
	url      string
	provider string
	person   *http.Client
	csrf     string
	personID string
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	dir := t.TempDir()
	res, err := server.Init(context.Background(), server.InitOptions{DataDir: dir, Demo: true})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{DataDir: dir, PasswordParams: &authn.Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { hs.Close(); srv.Close() })
	jar, _ := cookiejar.New(nil)
	e := &e2e{t: t, url: hs.URL, provider: res.ProviderIDs[0], person: &http.Client{Jar: jar}}

	// The bootstrap supervisor sets up, then takes a member role on the demo
	// account, so their agents can ask for read and write.
	var begin model.SetupBeginResult
	e.call(http.MethodPost, "/api/v1/auth/setup/begin", model.SetupBeginInput{SetupCode: res.Supervisor.SetupCode, Password: "an e2e test passphrase"}, &begin, http.StatusOK)
	code, _ := authn.TOTPCode(begin.TOTPSecret, authn.TOTPStep(time.Now()))
	var info model.SessionInfo
	e.call(http.MethodPost, "/api/v1/auth/setup/finish", model.SetupFinishInput{SetupCode: res.Supervisor.SetupCode, TOTPCode: code}, &info, http.StatusOK)
	e.csrf, e.personID = info.CSRFToken, info.Person.ID
	e.call(http.MethodPut, "/api/v1/supervisor/accounts/"+e.provider+"/people/"+e.personID, model.PutBindingInput{Role: model.RoleMember}, nil, http.StatusOK)
	return e
}

// call is a request in the person's console session.
func (e *e2e) call(method, path string, body, out any, want int) {
	e.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, e.url+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if e.csrf != "" {
		req.Header.Set(csrfHeaderName, e.csrf)
	}
	resp, err := e.person.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&env)
	if resp.StatusCode != want {
		e.t.Fatalf("%s %s = %d, want %d (%s)", method, path, resp.StatusCode, want, env.Data)
	}
	if out != nil {
		if err := json.Unmarshal(env.Data, out); err != nil {
			e.t.Fatal(err)
		}
	}
}

const csrfHeaderName = "X-CSRF-Token"

// agentApp is a CLI signed in as an agent owned by the e2e person.
func (e *e2e) agentApp() *testApp {
	e.t.Helper()
	ta := newTestApp(e.t)
	var deviceCode string
	ta.app.afterSignInStart = func(start model.AgentSignInStart) {
		deviceCode = start.DeviceCode
		e.call(http.MethodPost, "/api/v1/me/signins/"+start.UserCode+"/approve", nil, nil, http.StatusOK)
	}
	if code := ta.run("login", "--server", e.url, "--name", "e2e-agent"); code != ExitOK {
		e.t.Fatalf("login exit %d: %s", code, ta.errOut())
	}
	printed := ta.errOut() + ta.out()
	if strings.Contains(printed, "csg_agt_") || deviceCode == "" || strings.Contains(printed, deviceCode) {
		e.t.Fatal("login printed the agent token or the device code")
	}
	ta.stdout.Reset()
	ta.stderr.Reset()
	return ta
}

func TestE2EAgentSignInAccessAndExec(t *testing.T) {
	old := pollSleep
	pollSleep = func(time.Duration) {}
	t.Cleanup(func() { pollSleep = old })
	e := newE2E(t)
	ta := e.agentApp()

	// The token went to the config file, readable only by the user.
	path, _ := ta.app.configPath()
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config file: %v %v", st, err)
	}

	if code := ta.run("accounts", "--json"); code != ExitOK {
		t.Fatalf("accounts exit %d: %s", code, ta.errOut())
	}
	var accounts []model.AgentAccount
	_ = json.Unmarshal(ta.stdout.Bytes(), &accounts)
	if len(accounts) != 1 || accounts[0].CloudAccountID != e2eAccount || accounts[0].Role != model.RoleMember {
		t.Fatalf("accounts = %s", ta.out())
	}

	request := func(args ...string) (model.AccessRequest, int) {
		t.Helper()
		ta.stdout.Reset()
		ta.stderr.Reset()
		code := ta.run(append([]string{"access", "request", "--account", e2eAccount, "--resource", "ecs", "--ttl", "60s", "--json"}, args...)...)
		var req model.AccessRequest
		_ = json.Unmarshal(ta.stdout.Bytes(), &req)
		return req, code
	}

	// read: issued at once.
	read, code := request("--permission", "read")
	if code != ExitOK || read.Status != model.LeaseActive {
		t.Fatalf("read = %+v exit %d: %s", read, code, ta.errOut())
	}
	ta.stdout.Reset()
	if code := ta.run("credential", "--lease", read.ID, "--export"); code != ExitOK || !strings.Contains(ta.out(), "export ALIBABA_CLOUD_ACCESS_KEY_ID=") {
		t.Fatalf("credential exit %d: %s", code, ta.out())
	}
	ta.run("revoke", "--lease", read.ID)

	// write: waits for the owner, who approves in the console.
	write, code := request("--permission", "write", "--reason", "restart after a config change")
	if code != ExitOK || write.Status != model.LeasePending {
		t.Fatalf("write = %+v exit %d", write, code)
	}
	e.call(http.MethodPost, "/api/v1/me/requests/"+write.ID+"/approve", nil, nil, http.StatusOK)
	ta.stdout.Reset()
	if code := ta.run("access", "status", write.ID, "--json"); code != ExitOK || !strings.Contains(ta.out(), `"status": "active"`) {
		t.Fatalf("status after approval exit %d: %s", code, ta.out())
	}
	ta.run("revoke", "--lease", write.ID)

	// full: above the member role, denied at once, exit 1.
	full, code := request("--permission", "full", "--reason", "x")
	if code != ExitOperationErr || full.Status != model.LeaseDenied {
		t.Fatalf("full = %+v exit %d", full, code)
	}

	// Missing fields are a usage error.
	if code := ta.run("access", "request", "--account", e2eAccount, "--resource", "ecs", "--permission", "read"); code != ExitUsage {
		t.Fatalf("missing --ttl exit %d", code)
	}

	// exec: the command gets the credential environment, then it is revoked.
	ta.stdout.Reset()
	ta.stderr.Reset()
	code = ta.run("exec", "--account", e2eAccount, "--resource", "ecs", "--permission", "read", "--ttl", "60s", "--", "/usr/bin/env")
	if code != ExitOK || !strings.Contains(ta.out(), "ALIBABA_CLOUD_ACCESS_KEY_ID=") || !strings.Contains(ta.out(), "CSG_LEASE_ID=lea_") {
		t.Fatalf("exec exit %d: %s %s", code, ta.out(), ta.errOut())
	}
	if !strings.Contains(ta.errOut(), "(revoked)") {
		t.Fatalf("exec did not revoke: %s", ta.errOut())
	}
}

func TestE2EMCPServer(t *testing.T) {
	e := newE2E(t)
	ta := e.agentApp()

	lines := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","method":"ping"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_accounts","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"request_access","arguments":{"cloud_account_id":"` + e2eAccount + `","resource":"ecs","permission":"read","ttl_seconds":60}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"request_access","arguments":{"cloud_account_id":"` + e2eAccount + `","resource":"ecs","permission":"full","ttl_seconds":60,"reason":"x"}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"check_status","arguments":{"request_id":"../../etc/passwd"}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"no/such/method"}`,
		`not json`,
	}
	ta.app.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	if code := ta.run("mcp"); code != ExitOK {
		t.Fatalf("mcp exit %d: %s", code, ta.errOut())
	}
	responses := map[string]map[string]any{}
	var parseErr map[string]any
	nullIDs := 0
	sc := bufio.NewScanner(bytes.NewReader(ta.stdout.Bytes()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("non-JSON output line %q", sc.Text())
		}
		id, _ := json.Marshal(m["id"])
		if string(id) == "null" {
			parseErr = m
			nullIDs++
			continue
		}
		responses[string(id)] = m
	}
	// Exactly one reply has no id: the parse error. The notification gets none.
	if len(responses) != 7 || parseErr == nil || nullIDs != 1 {
		t.Fatalf("got %d responses (notifications must get none): %v", len(responses), responses)
	}
	result := func(id string) map[string]any {
		r, _ := responses[id]["result"].(map[string]any)
		return r
	}
	text := func(id string) (string, bool) {
		r := result(id)
		content, _ := r["content"].([]any)
		first, _ := content[0].(map[string]any)
		s, _ := first["text"].(string)
		isErr, _ := r["isError"].(bool)
		return s, isErr
	}
	if v := result("1")["protocolVersion"]; v != "2025-06-18" {
		t.Fatalf("protocol version = %v", v)
	}
	if tools, _ := result("2")["tools"].([]any); len(tools) != 5 {
		t.Fatalf("tools = %v", result("2"))
	}
	if s, isErr := text("3"); isErr || !strings.Contains(s, e2eAccount) {
		t.Fatalf("list_accounts = %s", s)
	}
	readText, isErr := text("4")
	var read map[string]any
	_ = json.Unmarshal([]byte(readText), &read)
	if isErr || read["status"] != "active" {
		t.Fatalf("request_access read = %s", readText)
	}
	if s, _ := text("5"); !strings.Contains(s, `"denied"`) {
		t.Fatalf("request_access full = %s", s)
	}
	if s, isErr := text("6"); !isErr || !strings.Contains(s, "request_id") {
		t.Fatalf("path-like request id = %s", s)
	}
	if e := responses["7"]["error"]; e == nil {
		t.Fatal("unknown method got no error")
	}

	// get_credential writes a private file and never returns the secret.
	id := read["id"].(string)
	ta.stdout.Reset()
	ta.app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"get_credential","arguments":{"request_id":"` + id + `"}}}` + "\n")
	ta.run("mcp")
	out := ta.out()
	credPath, _ := ta.app.credentialPath(id)
	st, err := os.Stat(credPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("credential file: %v %v", st, err)
	}
	if dir, _ := os.Stat(strings.TrimSuffix(credPath, "/"+id+".env")); dir.Mode().Perm() != 0o700 {
		t.Fatalf("credentials directory mode %v", dir.Mode().Perm())
	}
	content, _ := os.ReadFile(credPath)
	var secret string
	for _, line := range strings.Split(string(content), "\n") {
		if v, ok := strings.CutPrefix(line, "export ALIBABA_CLOUD_ACCESS_KEY_SECRET="); ok {
			secret = strings.Trim(v, "'")
		}
	}
	if secret == "" || strings.Contains(out, secret) || !strings.Contains(out, credPath) {
		t.Fatalf("get_credential output exposes the secret or lacks the path: %s", out)
	}

	// revoke ends it and deletes the file.
	ta.stdout.Reset()
	ta.app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"revoke","arguments":{"request_id":"` + id + `"}}}` + "\n")
	ta.run("mcp")
	if !strings.Contains(ta.out(), `\"status\": \"revoked\"`) {
		t.Fatalf("revoke = %s", ta.out())
	}
	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatal("credential file still exists after revoke")
	}
}
