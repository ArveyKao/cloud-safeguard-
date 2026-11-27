package server

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// TestQAEveryStateChangingRouteNeedsCSRFOrSameOrigin proves QA_BRIEF B /
// CONTRACT §17.3 for every person-facing state-changing route registered in
// api.go: cookie-session writes need X-CSRF-Token and same Origin; unauthenticated
// setup/login/sign-in starts need same Origin. Agent bearer, OAuth and MCP
// routes are not console sessions (CONTRACT §17.3 / §17.9) and are out of this
// CSRF table.
func TestQAEveryStateChangingRouteNeedsCSRFOrSameOrigin(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	sup := a.sup
	mei := a.mei
	pid, mid := a.providerID, mei.person.ID
	pending := a.request(accessInput("ecs", "write"))

	type route struct {
		who          *personClient // nil = unauthenticated (Origin only)
		method, path string
		body         any
	}
	// Placeholder path segments are fine: requireSession / requireSameOrigin
	// reject before the handler runs.
	sessionWrites := []route{
		{sup, http.MethodPost, "/api/v1/auth/logout", nil},
		{mei, http.MethodPost, "/api/v1/me/signins/CODE123/approve", nil},
		{mei, http.MethodPost, "/api/v1/me/signins/CODE123/deny", nil},
		{mei, http.MethodPost, "/api/v1/me/agents/agt_x/revoke", nil},
		{mei, http.MethodPut, "/api/v1/me/accounts/" + pid + "/mode", model.SetApprovalModeInput{Mode: model.ModeRead}},
		{mei, http.MethodPost, "/api/v1/me/cli-signins/CODE123/approve", nil},
		{mei, http.MethodPost, "/api/v1/me/cli-signins/CODE123/deny", nil},
		{mei, http.MethodPost, "/api/v1/me/cli-signins/CODE123/cancel", nil},
		{mei, http.MethodPost, "/api/v1/me/long-lived", model.LongLivedRequestInput{
			CloudAccountID: demoAccountID, Resource: "ecs", Permission: "read", Reason: "qa",
		}},
		{mei, http.MethodPost, "/api/v1/me/long-lived/ll_x/revoke", nil},
		{mei, http.MethodPost, "/api/v1/me/long-lived-requests/key_x/create", nil},
		{mei, http.MethodPost, "/api/v1/me/long-lived-requests/key_x/deny", nil},
		{mei, http.MethodPost, "/api/v1/me/mcp-connections/key_x/approve", map[string]string{"agent_name": "qa"}},
		{mei, http.MethodPost, "/api/v1/me/mcp-connections/key_x/deny", nil},
		{mei, http.MethodPost, "/api/v1/me/cli-sessions/ses_x/revoke", nil},
		{mei, http.MethodPost, "/api/v1/me/requests/" + pending.ID + "/approve", nil},
		{mei, http.MethodPost, "/api/v1/me/requests/" + pending.ID + "/deny", nil},
		{mei, http.MethodPost, "/api/v1/me/requests/" + pending.ID + "/revoke", nil},
		{sup, http.MethodPost, "/api/v1/supervisor/people", model.CreatePersonInput{Username: "qa-csrf"}},
		{sup, http.MethodPatch, "/api/v1/supervisor/people/" + mid, model.UpdatePersonInput{}},
		{sup, http.MethodPost, "/api/v1/supervisor/people/" + mid + "/reset", nil},
		{sup, http.MethodPut, "/api/v1/supervisor/accounts/" + pid + "/people/" + mid, model.PutBindingInput{Role: model.RoleGuest}},
		{sup, http.MethodDelete, "/api/v1/supervisor/accounts/" + pid + "/people/" + mid, nil},
		{sup, http.MethodPost, "/api/v1/supervisor/accounts", newMockAccount("qa-csrf", "6543210987654321")},
		{sup, http.MethodPatch, "/api/v1/supervisor/accounts/" + pid, map[string]string{"status": "disabled"}},
		{sup, http.MethodPost, "/api/v1/supervisor/accounts/" + pid + "/rotate", model.RotateProviderCredentialInput{AccessKeyID: "LTAIqa", AccessKeySecret: "x"}},
		{sup, http.MethodPost, "/api/v1/supervisor/accounts/" + pid + "/test", nil},
		{sup, http.MethodPut, "/api/v1/supervisor/settings", model.DefaultPolicySettings()},
		{sup, http.MethodPost, "/api/v1/supervisor/long-lived/ll_x/revoke", nil},
		{sup, http.MethodPut, "/api/v1/supervisor/accounts/" + pid + "/user-admin", model.SetUserAdminKeyInput{}},
		{sup, http.MethodDelete, "/api/v1/supervisor/accounts/" + pid + "/user-admin", nil},
		{sup, http.MethodPost, "/api/v1/supervisor/leases/" + pending.ID + "/deny", model.DenyLeaseInput{Reason: "qa"}},
		{sup, http.MethodPost, "/api/v1/supervisor/leases/" + pending.ID + "/revoke", nil},
	}
	originOnly := []route{
		{nil, http.MethodPost, "/api/v1/auth/setup/begin", model.SetupBeginInput{SetupCode: "x", Password: testPassword}},
		{nil, http.MethodPost, "/api/v1/auth/setup/finish", model.SetupFinishInput{SetupCode: "x", TOTPCode: "000000"}},
		{nil, http.MethodPost, "/api/v1/auth/login", model.PersonLoginInput{Username: "admin", Password: testPassword, TOTPCode: "000000"}},
		{nil, http.MethodPost, "/api/v1/agent-signin/start", model.AgentSignInStartInput{AgentName: "qa"}},
		{nil, http.MethodPost, "/api/v1/agent-signin/token", model.AgentSignInTokenInput{DeviceCode: "x"}},
		{nil, http.MethodPost, "/api/v1/person-signin/start", model.PersonSignInStartInput{ClientName: "qa"}},
		{nil, http.MethodPost, "/api/v1/person-signin/token", model.AgentSignInTokenInput{DeviceCode: "x"}},
	}

	for _, w := range sessionWrites {
		for name, headers := range map[string]map[string]string{
			"no token":     nil,
			"cross origin": {csrfHeader: w.who.csrf, "Origin": "https://evil.example"},
		} {
			rec := a.testEnv.request(w.method, w.path, w.who.cookie, headers, w.body)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s (%s) = %d, want 403", w.method, w.path, name, rec.Code)
			}
		}
	}
	for _, w := range originOnly {
		rec := a.testEnv.request(w.method, w.path, nil, map[string]string{"Origin": "https://evil.example"}, w.body)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s %s (cross origin) = %d, want 403", w.method, w.path, rec.Code)
		}
	}

	// Guard: every route registration in this package is classified, so a
	// route added later cannot skip this check. A state-changing route under
	// a session or sign-in prefix must be in one of the tables above; any
	// other state-changing route must belong to a group that is not a browser
	// session; a registration without a method, or whose path is not one
	// string literal, must be listed below with the reason.
	sessionPrefix := regexp.MustCompile(`^/api/v1/(me|supervisor|auth|agent-signin|person-signin)/`)
	nonSession := []string{
		"/api/v1/agent/", // agent bearer token, never a cookie
		"/oauth/",        // OAuth for remote MCP clients: PKCE and client checks (§17.10)
	}
	methodless := map[string]string{
		"/":                      "the console's static files and the unknown-route answer of each group",
		"/api/v1/auth/":          "mounts authMux; its routes are scanned one by one",
		"/api/v1/agent-signin/":  "mounts signInMux; its routes are scanned one by one",
		"/api/v1/person-signin/": "mounts personSignInMux; its routes are scanned one by one",
		"/api/v1/me/":            "mounts meMux behind requireSession",
		"/api/v1/supervisor/":    "mounts supervisorMux behind requireSession",
		"/api/v1/agent/":         "mounts agentMux behind requireAgent (bearer token)",
		"/mcp":                   "remote MCP: bearer token and an Origin check of its own (TestRemoteMCPEndpointGuards)",
		"/mock-cloud/":           "the mock cloud: its own signed tokens, never a session",
	}
	nonLiteral := map[string]string{
		`"POST "+credentialLinkPrefix+"{token}"`: "one-time credential link: the link's token is the authorization, no session",
	}
	call := regexp.MustCompile(`\.(?:HandleFunc|Handle)\(([^,]+),`)
	literal := regexp.MustCompile(`^"(?:(GET|HEAD|POST|PUT|PATCH|DELETE) )?(/[^"]*)"$`)
	placeholder := regexp.MustCompile(`\{[^}]+\}`)
	tables := append(append([]route{}, sessionWrites...), originOnly...)
	files, _ := filepath.Glob("*.go")
	seen, writes := 0, 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range call.FindAllStringSubmatch(string(src), -1) {
			arg := strings.TrimSpace(c[1])
			seen++
			m := literal.FindStringSubmatch(arg)
			if m == nil {
				if _, ok := nonLiteral[arg]; !ok {
					t.Errorf("%s: route %s is not one string literal; classify it in this test", f, arg)
				}
				continue
			}
			method, path := m[1], m[2]
			switch {
			case method == "":
				if _, ok := methodless[path]; !ok {
					t.Errorf("%s: %s is registered for every method; classify it in this test", f, path)
				}
			case method == "GET" || method == "HEAD":
			case sessionPrefix.MatchString(path):
				writes++
				pattern := regexp.MustCompile("^" + strings.ReplaceAll(regexp.QuoteMeta(placeholder.ReplaceAllString(path, "PLACEHOLDER")), "PLACEHOLDER", "[^/]+") + "$")
				covered := false
				for _, r := range tables {
					if r.method == method && pattern.MatchString(r.path) {
						covered = true
						break
					}
				}
				if !covered {
					t.Errorf("%s %s (in %s) is not in the CSRF/Origin table of this test", method, path, f)
				}
			default:
				ok := false
				for _, prefix := range nonSession {
					ok = ok || strings.HasPrefix(path, prefix)
				}
				if !ok {
					t.Errorf("%s %s (in %s) changes state outside every known group; classify it in this test", method, path, f)
				}
			}
		}
	}
	if seen < 60 || writes < 30 {
		t.Fatalf("found only %d registrations and %d session writes; the route scan is broken", seen, writes)
	}

	// Refused writes must not have applied side effects on live fixtures.
	if a.status(pending.ID) != model.LeasePending {
		t.Fatalf("CSRF-refused write changed lease status to %s", a.status(pending.ID))
	}
	prov, err := a.srv.db.GetProvider(context.Background(), a.providerID)
	if err != nil || prov.Status != model.ProviderActive {
		t.Fatalf("CSRF-refused write changed provider: %v %+v", err, prov)
	}
}
