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

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/server"
)

// QA lifecycle / MCP coverage for QA_BRIEF A (second half). Already covered
// elsewhere (reference only — do not duplicate):
//
//	CLI refresh rate limit: TestE2EAgentSignInAccessAndExec
//	Remote MCP adversarial + refresh: mcpremote_test.go / TestRemoteMCPFlow
//	Long-lived / fetch-after-terminal: server longlived_test.go, access_test.go

// TestQAMCPToolsIncludeRefreshAndSecretFree asserts tools/list includes the
// access lifecycle tools and that get_credential / refresh_credential never
// print the secret from the .env file. Refresh must rotate the secret and
// bump refresh_count. request_long_lived_credential is called: refused when
// not enabled, and returns only a console link when a supervisor enabled it.
func TestQAMCPToolsIncludeRefreshAndSecretFree(t *testing.T) {
	e := newE2E(t)
	ta := e.agentApp()

	lines := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"qa","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"request_access","arguments":{"cloud_account_id":"` + e2eAccount + `","resource":"ecs","permission":"read","ttl_seconds":60}}}`,
	}
	ta.app.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	if code := ta.run("mcp"); code != ExitOK {
		t.Fatalf("mcp exit %d", code)
	}

	responses := map[string]map[string]any{}
	sc := bufio.NewScanner(bytes.NewReader(ta.stdout.Bytes()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("non-JSON output line")
		}
		id, _ := json.Marshal(m["id"])
		if string(id) == "null" {
			continue
		}
		responses[string(id)] = m
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

	tools, _ := result("2")["tools"].([]any)
	names := map[string]bool{}
	for _, raw := range tools {
		tool, _ := raw.(map[string]any)
		if n, _ := tool["name"].(string); n != "" {
			names[n] = true
		}
	}
	for _, want := range []string{
		"list_accounts", "request_access", "check_status",
		"get_credential", "refresh_credential", "revoke",
		"request_long_lived_credential",
	} {
		if !names[want] {
			t.Fatalf("tools/list missing %q", want)
		}
	}

	readText, isErr := text("3")
	var read map[string]any
	_ = json.Unmarshal([]byte(readText), &read)
	if isErr || read["status"] != "active" {
		t.Fatalf("request_access read status=%v isError=%v", read["status"], isErr)
	}
	id, _ := read["id"].(string)
	if id == "" {
		t.Fatal("no request id from request_access")
	}

	secretFromFile := func(path string) string {
		t.Helper()
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read credential file: %v", err)
		}
		for _, line := range strings.Split(string(content), "\n") {
			if v, ok := strings.CutPrefix(line, "export ALIBABA_CLOUD_ACCESS_KEY_SECRET="); ok {
				return strings.Trim(v, "'")
			}
		}
		t.Fatal("no ALIBABA_CLOUD_ACCESS_KEY_SECRET in credential file")
		return ""
	}

	// get_credential: writes a private file; never prints the secret.
	ta.stdout.Reset()
	ta.app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_credential","arguments":{"request_id":"` + id + `"}}}` + "\n")
	if code := ta.run("mcp"); code != ExitOK {
		t.Fatalf("get_credential mcp exit %d", code)
	}
	out := ta.out()
	credPath, _ := ta.app.credentialPath(id)
	st, err := os.Stat(credPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("credential file: mode err=%v", err)
	}
	secret := secretFromFile(credPath)
	if secret == "" || strings.Contains(out, secret) || !strings.Contains(out, credPath) {
		t.Fatal("get_credential output exposes the secret or lacks the path")
	}

	// refresh_credential: rotates the secret, bumps refresh_count, never prints it.
	ta.stdout.Reset()
	ta.app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"refresh_credential","arguments":{"request_id":"` + id + `"}}}` + "\n")
	if code := ta.run("mcp"); code != ExitOK {
		t.Fatalf("refresh_credential mcp exit %d", code)
	}
	refreshOut := ta.out()
	var refreshResp map[string]any
	_ = json.Unmarshal([]byte(strings.TrimSpace(refreshOut)), &refreshResp)
	refreshResult, _ := refreshResp["result"].(map[string]any)
	if isErr, _ := refreshResult["isError"].(bool); isErr {
		t.Fatal("first refresh_credential errored")
	}
	newSecret := secretFromFile(credPath)
	if newSecret == "" || newSecret == secret {
		t.Fatal("refresh did not rotate the secret")
	}
	if strings.Contains(refreshOut, newSecret) || strings.Contains(refreshOut, secret) {
		t.Fatal("refresh_credential output exposes a secret")
	}
	if !strings.Contains(refreshOut, credPath) {
		t.Fatal("refresh_credential output lacks the path")
	}

	ta.stdout.Reset()
	ta.app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"check_status","arguments":{"request_id":"` + id + `"}}}` + "\n")
	if code := ta.run("mcp"); code != ExitOK {
		t.Fatalf("check_status mcp exit %d", code)
	}
	statusOut := ta.out()
	var statusResp map[string]any
	_ = json.Unmarshal([]byte(strings.TrimSpace(statusOut)), &statusResp)
	statusResult, _ := statusResp["result"].(map[string]any)
	statusContent, _ := statusResult["content"].([]any)
	statusFirst, _ := statusContent[0].(map[string]any)
	statusText, _ := statusFirst["text"].(string)
	var statusBody map[string]any
	_ = json.Unmarshal([]byte(statusText), &statusBody)
	if statusBody["refresh_count"] != float64(1) {
		t.Fatalf("refresh_count = %v, want 1", statusBody["refresh_count"])
	}

	// Second refresh within a minute errors.
	ta.stdout.Reset()
	ta.app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"refresh_credential","arguments":{"request_id":"` + id + `"}}}` + "\n")
	ta.run("mcp")
	secondOut := ta.out()
	var secondResp map[string]any
	_ = json.Unmarshal([]byte(strings.TrimSpace(secondOut)), &secondResp)
	secondResult, _ := secondResp["result"].(map[string]any)
	if isErr, _ := secondResult["isError"].(bool); !isErr {
		t.Fatal("second refresh within a minute succeeded")
	}

	// revoke ends the request.
	ta.stdout.Reset()
	ta.app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"revoke","arguments":{"request_id":"` + id + `"}}}` + "\n")
	ta.run("mcp")
	revokeOut := ta.out()
	if !strings.Contains(revokeOut, "revoked") {
		t.Fatal("revoke did not report revoked")
	}
	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatal("credential file still exists after revoke")
	}

	// request_long_lived_credential: not enabled → clear refusal (no secret).
	ta.stdout.Reset()
	ta.app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"request_long_lived_credential","arguments":{"cloud_account_id":"` + e2eAccount + `","resource":"ecs","permission":"read","reason":"qa refuse"}}}` + "\n")
	ta.run("mcp")
	refuseOut := ta.out()
	var refuseResp map[string]any
	_ = json.Unmarshal([]byte(strings.TrimSpace(refuseOut)), &refuseResp)
	refuseResult, _ := refuseResp["result"].(map[string]any)
	if isErr, _ := refuseResult["isError"].(bool); !isErr {
		t.Fatal("request_long_lived_credential succeeded without long-lived enabled")
	}
	refuseContent, _ := refuseResult["content"].([]any)
	refuseFirst, _ := refuseContent[0].(map[string]any)
	refuseText, _ := refuseFirst["text"].(string)
	if refuseText == "" || strings.Contains(strings.ToLower(refuseText), "secret") ||
		strings.Contains(refuseText, "AccessKey") {
		t.Fatal("long-lived refusal missing a clear error or leaked a secret field")
	}
	if !strings.Contains(strings.ToLower(refuseText), "long-lived") &&
		!strings.Contains(strings.ToLower(refuseText), "supervisor") &&
		!strings.Contains(strings.ToLower(refuseText), "allowed") {
		t.Fatal("long-lived refusal is not a clear enablement/permission error")
	}
}

// TestQAMCPLongLivedEnabled returns a console link and never a secret once a
// supervisor has enabled long-lived keys on the account and allowed the person.
func TestQAMCPLongLivedEnabled(t *testing.T) {
	e := newE2EWithLongLived(t)
	ta := e.agentApp()

	lines := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"qa","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"request_long_lived_credential","arguments":{"cloud_account_id":"` + e2eAccount + `","resource":"ecs","permission":"read","reason":"cdn origin","resource_name":"i-2ze0demo001"}}}`,
	}
	ta.app.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	if code := ta.run("mcp"); code != ExitOK {
		t.Fatalf("mcp exit %d", code)
	}
	out := ta.out()
	var resp map[string]any
	sc := bufio.NewScanner(bytes.NewReader(ta.stdout.Bytes()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			continue
		}
		id, _ := json.Marshal(m["id"])
		if string(id) == "2" {
			resp = m
		}
	}
	result, _ := resp["result"].(map[string]any)
	if isErr, _ := result["isError"].(bool); isErr {
		t.Fatal("request_long_lived_credential errored after enablement")
	}
	content, _ := result["content"].([]any)
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	var body map[string]any
	if err := json.Unmarshal([]byte(text), &body); err != nil {
		t.Fatal("long-lived response is not JSON")
	}
	link, _ := body["link"].(string)
	if link == "" || !strings.Contains(link, "long-lived=") {
		t.Fatal("long-lived response missing console link")
	}
	if body["status"] != "pending" {
		t.Fatalf("long-lived status = %v, want pending", body["status"])
	}
	lower := strings.ToLower(out)
	for _, leak := range []string{"access_key_secret", "accesskeysecret", "secret_access_key"} {
		if strings.Contains(lower, leak) {
			t.Fatalf("long-lived response mentions secret field %q", leak)
		}
	}
	if _, hasSecret := body["access_key_secret"]; hasSecret {
		t.Fatal("long-lived response included access_key_secret")
	}
	if _, hasSecret := body["secret"]; hasSecret {
		t.Fatal("long-lived response included secret")
	}
}

// newE2EWithLongLived is newE2E plus supervisor enablement of long-lived keys
// on the demo account and allow-list for mei (see server enableLongLived).
func newE2EWithLongLived(t *testing.T) *e2e {
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

	e.setup(res.Supervisor.SetupCode)
	var mei model.PersonWithSetupCode
	e.call(http.MethodPost, "/api/v1/supervisor/people", model.CreatePersonInput{Username: "mei"}, &mei, http.StatusCreated)
	e.call(http.MethodPut, "/api/v1/supervisor/accounts/"+e.provider+"/people/"+mei.Person.ID, model.PutBindingInput{Role: model.RoleMember}, nil, http.StatusOK)
	e.call(http.MethodPut, "/api/v1/supervisor/accounts/"+e.provider+"/user-admin", model.SetUserAdminKeyInput{}, nil, http.StatusOK)
	yes := true
	e.call(http.MethodPatch, "/api/v1/supervisor/people/"+mei.Person.ID, model.UpdatePersonInput{LongLived: &yes}, nil, http.StatusOK)

	jar, _ = cookiejar.New(nil)
	e.person, e.csrf = &http.Client{Jar: jar}, ""
	e.setup(mei.SetupCode)
	return e
}
