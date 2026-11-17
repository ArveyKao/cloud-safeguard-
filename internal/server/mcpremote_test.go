package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/mcp"
	"github.com/arveykao/cloud-safeguard/internal/model"
)

const testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// raw sends a request with exactly the given headers and body.
func (e *testEnv) raw(method, target string, headers map[string]string, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func (e *testEnv) registerClient(name string, redirects ...string) string {
	e.t.Helper()
	body, _ := json.Marshal(map[string]any{"client_name": name, "redirect_uris": redirects})
	rec := e.raw(http.MethodPost, "/oauth/register", map[string]string{"Content-Type": "application/json"}, string(body))
	requireStatus(e.t, rec, http.StatusCreated)
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.ClientID == "" {
		e.t.Fatalf("register: %v %s", err, rec.Body)
	}
	return out.ClientID
}

// authorize starts an authorization and returns the connection id.
func (e *testEnv) authorize(clientID, redirect, state string) string {
	e.t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect}, "state": {state},
		"code_challenge": {pkceS256(testVerifier)}, "code_challenge_method": {"S256"},
		"resource": {"http://example.com/mcp"},
	}
	rec := e.raw(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, "")
	requireStatus(e.t, rec, http.StatusFound)
	id, ok := strings.CutPrefix(rec.Header().Get("Location"), "/?mcp-connect=")
	if !ok || !connectKeyRE.MatchString(id) {
		e.t.Fatalf("unexpected redirect %q", rec.Header().Get("Location"))
	}
	return id
}

func (e *testEnv) exchange(form url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.raw(http.MethodPost, "/oauth/token", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, form.Encode())
}

// approveConnection approves and returns the code from the redirect.
func approveConnection(t *testing.T, p *personClient, id, agentName, wantState string) string {
	t.Helper()
	rec := p.do(http.MethodPost, "/api/v1/me/mcp-connections/"+id+"/approve", map[string]string{"agent_name": agentName})
	requireStatus(t, rec, http.StatusOK)
	out := decodeEnvelope[map[string]string](t, rec)
	u, err := url.Parse(out["redirect_url"])
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("state") != wantState || u.Query().Get("iss") != "http://example.com" || u.Query().Get("code") == "" {
		t.Fatalf("unexpected redirect %q", out["redirect_url"])
	}
	return u.Query().Get("code")
}

func (e *testEnv) mcpCall(tok string, msg string) *httptest.ResponseRecorder {
	e.t.Helper()
	h := map[string]string{"Content-Type": "application/json", "MCP-Protocol-Version": "2025-06-18"}
	if tok != "" {
		h["Authorization"] = "Bearer " + tok
	}
	return e.raw(http.MethodPost, "/mcp", h, msg)
}

func toolText(t *testing.T, rec *httptest.ResponseRecorder) (string, bool) {
	t.Helper()
	requireStatus(t, rec, http.StatusOK)
	var resp struct {
		Result mcp.ToolResult `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || len(resp.Result.Content) != 1 {
		t.Fatalf("unexpected tool response: %s", rec.Body)
	}
	return resp.Result.Content[0].Text, resp.Result.IsError
}

func callTool(name string, args map[string]any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	return string(b)
}

func TestRemoteMCPFlow(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	env.bindDirect(mei.person.ID, model.RoleMember)

	// Discovery: /mcp without a token points at the metadata.
	rec := env.mcpCall("", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	requireStatus(t, rec, http.StatusUnauthorized)
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer resource_metadata="http://example.com/.well-known/oauth-protected-resource"` {
		t.Fatalf("challenge %q", got)
	}
	rec = env.raw(http.MethodGet, "/.well-known/oauth-protected-resource", nil, "")
	requireStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"resource":"http://example.com/mcp"`) {
		t.Fatalf("resource metadata %s", rec.Body)
	}
	rec = env.raw(http.MethodGet, "/.well-known/oauth-authorization-server", nil, "")
	requireStatus(t, rec, http.StatusOK)
	for _, want := range []string{`"issuer":"http://example.com"`, `"code_challenge_methods_supported":["S256"]`, `/oauth/register`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("server metadata lacks %s: %s", want, rec.Body)
		}
	}

	redirect := "http://127.0.0.1:33418/callback"
	clientID := env.registerClient("Claude Code", redirect)
	id := env.authorize(clientID, "http://127.0.0.1:40000/callback", "st-1") // loopback port may differ

	// The console shows where the sign-in goes.
	path := "/api/v1/me/mcp-connections/" + id
	requireStatus(t, env.request(http.MethodGet, path, nil, nil, nil), http.StatusUnauthorized)
	rec = mei.do(http.MethodGet, path, nil)
	requireStatus(t, rec, http.StatusOK)
	view := decodeEnvelope[mcpConnection](t, rec)
	if view.ClientName != "Claude Code" || view.RedirectHost != "127.0.0.1:40000" || !view.Local || view.AgentName != "claude-code" {
		t.Fatalf("view %+v", view)
	}
	requireStatus(t, mei.do(http.MethodPost, path+"/approve", map[string]string{"agent_name": "x"}), http.StatusBadRequest)
	code := approveConnection(t, mei, id, "laptop-claude", "st-1")
	requireStatus(t, mei.do(http.MethodGet, path, nil), http.StatusNotFound) // decided

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {"http://127.0.0.1:40000/callback"}, "code_verifier": {testVerifier}}
	rec = env.exchange(form)
	requireStatus(t, rec, http.StatusOK)
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &tok); err != nil || tok.TokenType != "Bearer" || tok.AccessToken == "" {
		t.Fatalf("token %s", rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("token response may be cached")
	}
	// The code works once.
	requireStatus(t, env.exchange(form), http.StatusBadRequest)

	// The agent belongs to mei.
	agents := decodeEnvelope[listData[model.Agent]](t, mei.do(http.MethodGet, "/api/v1/me/agents", nil)).Items
	if len(agents) != 1 || agents[0].Name != "laptop-claude" || agents[0].OwnerID != mei.person.ID || agents[0].Description != "MCP: Claude Code" {
		t.Fatalf("agents %+v", agents)
	}

	// MCP over HTTP.
	rec = env.mcpCall(tok.AccessToken, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	requireStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), `"protocolVersion":"2025-06-18"`) {
		t.Fatalf("initialize %s", rec.Body)
	}
	rec = env.mcpCall(tok.AccessToken, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	requireStatus(t, rec, http.StatusAccepted)
	if rec.Body.Len() != 0 {
		t.Fatal("a notification got a body")
	}
	rec = env.mcpCall(tok.AccessToken, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	requireStatus(t, rec, http.StatusOK)
	if !strings.Contains(rec.Body.String(), "one-time link") {
		t.Fatalf("tools/list %s", rec.Body)
	}
	text, isErr := toolText(t, env.mcpCall(tok.AccessToken, callTool("list_accounts", nil)))
	if isErr || !strings.Contains(text, "1234567890123456") {
		t.Fatalf("list_accounts %s", text)
	}
	text, isErr = toolText(t, env.mcpCall(tok.AccessToken, callTool("request_access", map[string]any{
		"cloud_account_id": "1234567890123456", "resource": "ecs", "permission": "read", "ttl_seconds": 600})))
	if isErr {
		t.Fatalf("request_access %s", text)
	}
	var req struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(text), &req); err != nil || req.Status != "active" {
		t.Fatalf("request_access %s", text)
	}

	text, isErr = toolText(t, env.mcpCall(tok.AccessToken, callTool("get_credential", map[string]any{"request_id": req.ID})))
	if isErr || strings.Contains(text, "FAKE") || strings.Contains(text, "secret") && strings.Contains(text, "SECRET=") {
		t.Fatalf("get_credential %s", text)
	}
	var cred struct {
		Run string `json:"run"`
	}
	_ = json.Unmarshal([]byte(text), &cred)
	start := strings.Index(cred.Run, "http://example.com/api/v1/credential-links/")
	if start < 0 || !strings.HasPrefix(cred.Run, `eval "$(curl -fsS -X POST '`) {
		t.Fatalf("run %q", cred.Run)
	}
	link := strings.TrimSuffix(strings.TrimPrefix(cred.Run[start:], "http://example.com"), `')"`)

	// The link releases the credential once, as shell exports.
	rec = env.raw(http.MethodGet, link, nil, "")
	if rec.Code == http.StatusOK {
		t.Fatal("GET released the credential")
	}
	rec = env.raw(http.MethodPost, link, nil, "")
	requireStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	for _, want := range []string{"export ALIBABA_CLOUD_ACCESS_KEY_ID='", "export ALIBABA_CLOUD_ACCESS_KEY_SECRET='", "export CSG_LEASE_ID='" + req.ID + "'"} {
		if !strings.Contains(body, want) {
			t.Fatalf("link body lacks %s:\n%s", want, body)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("credential may be cached")
	}
	rec = env.raw(http.MethodPost, link, nil, "")
	requireStatus(t, rec, http.StatusNotFound)
	if strings.Contains(rec.Body.String(), "export") {
		t.Fatal("a used link released again")
	}
	if !env.hasAction("lease.credential_fetched") || !env.hasAction("lease.credential_link_created") || !env.hasAction("mcp_signin.completed") {
		t.Fatal("missing audit events")
	}
	if strings.Contains(env.logs.String(), strings.TrimPrefix(link, credentialLinkPrefix)) || strings.Contains(env.logs.String(), id) {
		t.Fatal("a link token or connection key reached the log")
	}
	audit, _ := json.Marshal(env.listAudit(""))
	if strings.Contains(string(audit), id) || strings.Contains(string(audit), code) || strings.Contains(string(audit), tok.AccessToken) {
		t.Fatal("a connection key, code or token reached the audit log")
	}

	// A link expires after 60 seconds.
	text, _ = toolText(t, env.mcpCall(tok.AccessToken, callTool("get_credential", map[string]any{"request_id": req.ID})))
	_ = json.Unmarshal([]byte(text), &cred)
	link = cred.Run[strings.Index(cred.Run, credentialLinkPrefix):]
	link = strings.TrimSuffix(link, `')"`)
	env.clock.Advance(61 * time.Second)
	requireStatus(t, env.raw(http.MethodPost, link, nil, ""), http.StatusNotFound)

	// A link dies with the request: revoke, then fetch.
	text, _ = toolText(t, env.mcpCall(tok.AccessToken, callTool("get_credential", map[string]any{"request_id": req.ID})))
	_ = json.Unmarshal([]byte(text), &cred)
	link = strings.TrimSuffix(cred.Run[strings.Index(cred.Run, credentialLinkPrefix):], `')"`)
	text, isErr = toolText(t, env.mcpCall(tok.AccessToken, callTool("revoke", map[string]any{"request_id": req.ID})))
	if isErr || !strings.Contains(text, `"revoked"`) {
		t.Fatalf("revoke %s", text)
	}
	rec = env.raw(http.MethodPost, link, nil, "")
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "export") {
		t.Fatalf("a revoked request's link released: %d %s", rec.Code, rec.Body)
	}

	// Revoking the agent ends MCP access, and its open links.
	text, _ = toolText(t, env.mcpCall(tok.AccessToken, callTool("request_access", map[string]any{
		"cloud_account_id": "1234567890123456", "resource": "ecs", "permission": "read", "ttl_seconds": 600})))
	_ = json.Unmarshal([]byte(text), &req)
	text, _ = toolText(t, env.mcpCall(tok.AccessToken, callTool("get_credential", map[string]any{"request_id": req.ID})))
	_ = json.Unmarshal([]byte(text), &cred)
	link = strings.TrimSuffix(cred.Run[strings.Index(cred.Run, credentialLinkPrefix):], `')"`)
	requireStatus(t, mei.do(http.MethodPost, "/api/v1/me/agents/"+agents[0].ID+"/revoke", nil), http.StatusOK)
	rec = env.raw(http.MethodPost, link, nil, "")
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "export") {
		t.Fatalf("a revoked agent's link answered %d %s", rec.Code, rec.Body)
	}
	requireStatus(t, env.mcpCall(tok.AccessToken, `{"jsonrpc":"2.0","id":1,"method":"ping"}`), http.StatusForbidden)
}

func TestRemoteMCPTokenChecks(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	redirect := "https://client.example.net/cb"
	clientID := env.registerClient("Tool", redirect)
	other := env.registerClient("Other", redirect)

	base := func(code string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
			"redirect_uri": {redirect}, "code_verifier": {testVerifier}}
	}
	for name, mutate := range map[string]func(url.Values){
		"wrong verifier": func(f url.Values) { f.Set("code_verifier", strings.Repeat("a", 43)) },
		"other client":   func(f url.Values) { f.Set("client_id", other) },
		"other redirect": func(f url.Values) { f.Set("redirect_uri", "https://client.example.net/other") },
		"other resource": func(f url.Values) { f.Set("resource", "https://evil.example/mcp") },
		"expired":        nil,
	} {
		t.Run(name, func(t *testing.T) {
			id := env.authorize(clientID, redirect, "s")
			code := approveConnection(t, mei, id, "tool", "s")
			form := base(code)
			switch name {
			case "expired":
				env.clock.Advance(oauthCodeTTL + time.Second)
			default:
				mutate(form)
				rec := env.exchange(form)
				requireStatus(t, rec, http.StatusBadRequest)
				if !strings.Contains(rec.Body.String(), `"invalid_grant"`) {
					t.Fatalf("error %s", rec.Body)
				}
				form = base(code) // the right values no longer help: the code is burned
			}
			rec := env.exchange(form)
			requireStatus(t, rec, http.StatusBadRequest)
		})
	}

	// Wrong grant type and content type.
	rec := env.exchange(url.Values{"grant_type": {"refresh_token"}})
	if !strings.Contains(rec.Body.String(), "unsupported_grant_type") {
		t.Fatalf("grant type %s", rec.Body)
	}
	requireStatus(t, env.raw(http.MethodPost, "/oauth/token", map[string]string{"Content-Type": "application/json"}, `{}`), http.StatusBadRequest)
}

func TestRemoteMCPResetEndsApprovals(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	redirect := "https://client.example.net/cb"
	clientID := env.registerClient("Tool", redirect)
	id := env.authorize(clientID, redirect, "s")
	code := approveConnection(t, mei, id, "tool", "s")
	requireStatus(t, sup.do(http.MethodPost, "/api/v1/supervisor/people/"+mei.person.ID+"/reset", nil), http.StatusOK)
	rec := env.exchange(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {clientID},
		"redirect_uri": {redirect}, "code_verifier": {testVerifier}})
	requireStatus(t, rec, http.StatusBadRequest)
}

func TestRemoteMCPRegistrationAndAuthorizeChecks(t *testing.T) {
	env := newTestEnv(t, true)
	reg := func(body string) *httptest.ResponseRecorder {
		return env.raw(http.MethodPost, "/oauth/register", map[string]string{"Content-Type": "application/json"}, body)
	}
	for _, bad := range []string{
		`{"client_name":"x","redirect_uris":["http://evil.example/cb"]}`,
		`{"client_name":"x","redirect_uris":["javascript:alert(1)"]}`,
		`{"client_name":"x","redirect_uris":["https://a.example/cb#frag"]}`,
		`{"client_name":"x","redirect_uris":[]}`,
		`{"client_name":"x","redirect_uris":["https://a.example/cb"],"grant_types":["client_credentials"]}`,
		`not json`,
	} {
		requireStatus(t, reg(bad), http.StatusBadRequest)
	}
	if redirectURIMatches("http://127.0.0.1:1/cb", "http://localhost:2/cb") || redirectURIMatches("http://127.0.0.1:1/cb", "http://127.0.0.1:2/other") ||
		redirectURIMatches("https://a.example/cb", "https://a.example:444/cb") || !redirectURIMatches("http://localhost:1/cb", "http://localhost:9/cb") {
		t.Fatal("redirect URI matching is wrong")
	}
	for _, good := range []string{"cursor://anysphere.cursor-mcp/oauth/callback", "http://localhost:6274/oauth/callback", "https://claude.ai/api/mcp/auth_callback"} {
		requireStatus(t, reg(`{"client_name":"x","redirect_uris":["`+good+`"]}`), http.StatusCreated)
	}

	clientID := env.registerClient("Tool", "https://client.example.net/cb")
	authz := func(q url.Values) *httptest.ResponseRecorder {
		return env.raw(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, "")
	}
	good := func() url.Values {
		return url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://client.example.net/cb"},
			"code_challenge": {pkceS256(testVerifier)}, "code_challenge_method": {"S256"}, "state": {"s"}}
	}
	// Untrusted client or redirect: no redirect at all.
	q := good()
	q.Set("redirect_uri", "https://evil.example/cb")
	requireStatus(t, authz(q), http.StatusBadRequest)
	q = good()
	q.Set("client_id", "mcc_00000000000000000000000000000000")
	requireStatus(t, authz(q), http.StatusBadRequest)
	// Bad requests from a known client go back to it with an error.
	for key, value := range map[string]string{"code_challenge_method": "plain", "response_type": "token", "resource": "https://other.example/mcp"} {
		q = good()
		q.Set(key, value)
		rec := authz(q)
		requireStatus(t, rec, http.StatusFound)
		loc, _ := url.Parse(rec.Header().Get("Location"))
		if loc.Host != "client.example.net" || loc.Query().Get("error") == "" || loc.Query().Get("state") != "s" {
			t.Fatalf("%s: redirect %s", key, rec.Header().Get("Location"))
		}
	}
	// Deny sends access_denied back.
	sup := env.supervisorClient()
	id := env.authorize(clientID, "https://client.example.net/cb", "s")
	rec := sup.do(http.MethodPost, "/api/v1/me/mcp-connections/"+id+"/deny", nil)
	requireStatus(t, rec, http.StatusOK)
	if !strings.Contains(decodeEnvelope[map[string]string](t, rec)["redirect_url"], "error=access_denied") {
		t.Fatalf("deny %s", rec.Body)
	}
}

func TestRemoteMCPEndpointGuards(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	_, tok := env.signInAgent(sup, "bot")
	h := map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + tok}
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	requireStatus(t, env.raw(http.MethodPost, "/mcp", h, ping), http.StatusOK)

	h["Origin"] = "https://evil.example"
	requireStatus(t, env.raw(http.MethodPost, "/mcp", h, ping), http.StatusForbidden)
	h["Origin"] = "http://example.com"
	requireStatus(t, env.raw(http.MethodPost, "/mcp", h, ping), http.StatusOK)
	delete(h, "Origin")
	requireStatus(t, env.raw(http.MethodGet, "/mcp", h, ""), http.StatusMethodNotAllowed)
	requireStatus(t, env.raw(http.MethodDelete, "/mcp", h, ""), http.StatusMethodNotAllowed)
	h["MCP-Protocol-Version"] = "1999-01-01"
	requireStatus(t, env.raw(http.MethodPost, "/mcp", h, ping), http.StatusBadRequest)
	delete(h, "MCP-Protocol-Version")
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", mcp.MaxMessage) + `"}}`
	requireStatus(t, env.raw(http.MethodPost, "/mcp", h, big), http.StatusRequestEntityTooLarge)
	rec := env.raw(http.MethodPost, "/mcp", h, `[`+ping+`,{"jsonrpc":"2.0","method":"notifications/x"}]`)
	requireStatus(t, rec, http.StatusOK)
	var batch []json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &batch); err != nil || len(batch) != 1 {
		t.Fatalf("batch %s", rec.Body)
	}
	// A notification does nothing, even a tools/call.
	rec = env.raw(http.MethodPost, "/mcp", h, `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_accounts"}}`)
	requireStatus(t, rec, http.StatusAccepted)

	// A CLI session cannot approve an MCP connection.
	cli := env.signInCLI(sup)
	clientID := env.registerClient("Tool", "https://client.example.net/cb")
	id := env.authorize(clientID, "https://client.example.net/cb", "s")
	requireStatus(t, cli.do(http.MethodPost, "/api/v1/me/mcp-connections/"+id+"/approve", map[string]string{"agent_name": "tool"}), http.StatusForbidden)
	_ = bytes.MinRead
}
