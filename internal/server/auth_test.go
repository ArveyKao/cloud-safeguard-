package server

import (
	"bytes"
	"context"
	cryptotls "crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

func auditAll() store.AuditFilter { return store.AuditFilter{Limit: 200} }

const testPassword = "a long test passphrase"

// personClient is a browser-like client: it keeps the session cookie and
// CSRF token of one signed-in person.
type personClient struct {
	env    *testEnv
	cookie *http.Cookie
	csrf   string
	secret string // TOTP secret
	person model.Person
}

// request sends a request with optional cookie, CSRF token and headers.
func (e *testEnv) request(method, path string, cookie *http.Cookie, headers map[string]string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			e.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func (c *personClient) do(method, path string, body any) *httptest.ResponseRecorder {
	c.env.t.Helper()
	return c.env.request(method, path, c.cookie, map[string]string{csrfHeader: c.csrf}, body)
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	return nil
}

func (e *testEnv) totp(secret string, offsetSteps int64) string {
	e.t.Helper()
	code, err := authn.TOTPCode(secret, authn.TOTPStep(e.clock.Now())+offsetSteps)
	if err != nil {
		e.t.Fatal(err)
	}
	return code
}

// completeSetup runs setup begin+finish for a setup code and returns a
// signed-in client.
func (e *testEnv) completeSetup(setupCode string) *personClient {
	e.t.Helper()
	rec := e.request(http.MethodPost, "/api/v1/auth/setup/begin", nil, nil,
		model.SetupBeginInput{SetupCode: setupCode, Password: testPassword})
	requireStatus(e.t, rec, http.StatusOK)
	begin := decodeEnvelope[model.SetupBeginResult](e.t, rec)
	rec = e.request(http.MethodPost, "/api/v1/auth/setup/finish", nil, nil,
		model.SetupFinishInput{SetupCode: setupCode, TOTPCode: e.totp(begin.TOTPSecret, 0)})
	requireStatus(e.t, rec, http.StatusOK)
	info := decodeEnvelope[model.SessionInfo](e.t, rec)
	return &personClient{env: e, cookie: sessionCookie(rec), csrf: info.CSRFToken, secret: begin.TOTPSecret, person: info.Person}
}

// supervisorClient sets up the bootstrap supervisor.
func (e *testEnv) supervisorClient() *personClient {
	e.t.Helper()
	if e.supervisor == nil {
		e.t.Fatal("Init returned no supervisor")
	}
	return e.completeSetup(e.supervisor.SetupCode)
}

// addPerson has a supervisor create a person and completes their setup.
func (e *testEnv) addPerson(sup *personClient, username string, supervisor bool) *personClient {
	e.t.Helper()
	rec := sup.do(http.MethodPost, "/api/v1/supervisor/people", model.CreatePersonInput{Username: username, Supervisor: supervisor})
	requireStatus(e.t, rec, http.StatusCreated)
	created := decodeEnvelope[model.PersonWithSetupCode](e.t, rec)
	return e.completeSetup(created.SetupCode)
}

func (e *testEnv) login(username, password, code string) *httptest.ResponseRecorder {
	e.t.Helper()
	return e.request(http.MethodPost, "/api/v1/auth/login", nil, nil,
		model.PersonLoginInput{Username: username, Password: password, TOTPCode: code})
}

// nextStep moves the clock one TOTP period forward so a fresh code exists.
func (e *testEnv) nextStep() { e.clock.Advance(authn.TOTPPeriod) }

func TestSupervisorSetupAndSession(t *testing.T) {
	env := newTestEnv(t, true)
	code := env.supervisor.SetupCode
	if env.supervisor.Person.Username != DefaultSupervisorUsername || !env.supervisor.Person.Supervisor ||
		env.supervisor.Person.Status != model.PersonPending {
		t.Fatalf("unexpected bootstrap supervisor: %+v", env.supervisor.Person)
	}

	// A pending person cannot log in, and weak passwords are refused.
	requireStatus(t, env.login("admin", testPassword, "000000"), http.StatusUnauthorized)
	rec := env.request(http.MethodPost, "/api/v1/auth/setup/begin", nil, nil,
		model.SetupBeginInput{SetupCode: code, Password: "short"})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	// Finishing before choosing a password is refused.
	rec = env.request(http.MethodPost, "/api/v1/auth/setup/finish", nil, nil,
		model.SetupFinishInput{SetupCode: code, TOTPCode: "123456"})
	requireStatus(t, rec, http.StatusBadRequest)

	rec = env.request(http.MethodPost, "/api/v1/auth/setup/begin", nil, nil,
		model.SetupBeginInput{SetupCode: code, Password: testPassword})
	requireStatus(t, rec, http.StatusOK)
	begin := decodeEnvelope[model.SetupBeginResult](t, rec)
	if !strings.HasPrefix(begin.OTPAuthURL, "otpauth://totp/") || begin.TOTPSecret == "" {
		t.Fatalf("bad setup result: %+v", begin)
	}
	// A wrong code does not activate.
	wrong := "000000"
	if wrong == env.totp(begin.TOTPSecret, 0) {
		wrong = "111111"
	}
	rec = env.request(http.MethodPost, "/api/v1/auth/setup/finish", nil, nil,
		model.SetupFinishInput{SetupCode: code, TOTPCode: wrong})
	requireStatus(t, rec, http.StatusBadRequest)

	rec = env.request(http.MethodPost, "/api/v1/auth/setup/finish", nil, nil,
		model.SetupFinishInput{SetupCode: code, TOTPCode: env.totp(begin.TOTPSecret, 0)})
	requireStatus(t, rec, http.StatusOK)
	cookie := sessionCookie(rec)
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("session cookie flags wrong: %+v", cookie)
	}
	info := decodeEnvelope[model.SessionInfo](t, rec)
	if info.Person.Status != model.PersonActive || info.CSRFToken == "" {
		t.Fatalf("bad session info: %+v", info)
	}

	// The setup code is single-use.
	for _, path := range []string{"/api/v1/auth/setup/begin", "/api/v1/auth/setup/finish"} {
		rec = env.request(http.MethodPost, path, nil, nil,
			map[string]string{"setup_code": code, "password": testPassword, "totp_code": env.totp(begin.TOTPSecret, 0)})
		requireStatus(t, rec, http.StatusBadRequest)
	}

	rec = env.request(http.MethodGet, "/api/v1/auth/me", cookie, nil, nil)
	requireStatus(t, rec, http.StatusOK)
	requireStatus(t, env.request(http.MethodGet, "/api/v1/auth/me", nil, nil, nil), http.StatusUnauthorized)

	// Nothing secret reached the audit log or the server log.
	events, _, err := env.srv.db.ListAudit(context.Background(), auditAll())
	if err != nil {
		t.Fatal(err)
	}
	dump, _ := json.Marshal(events)
	for _, secret := range []string{code, begin.TOTPSecret, testPassword, cookie.Value, info.CSRFToken} {
		if bytes.Contains(dump, []byte(secret)) || strings.Contains(env.logs.String(), secret) {
			t.Fatalf("a secret leaked into the audit log or server log")
		}
	}
}

func TestSetupCodeExpires(t *testing.T) {
	env := newTestEnv(t, false)
	env.clock.Set(time.Now().UTC().Add(setupCodeTTL + time.Minute))
	rec := env.request(http.MethodPost, "/api/v1/auth/setup/begin", nil, nil,
		model.SetupBeginInput{SetupCode: env.supervisor.SetupCode, Password: testPassword})
	requireStatus(t, rec, http.StatusBadRequest)
}

func TestLoginFailuresLookIdentical(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	env.nextStep()

	bodies := map[string]string{}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"unknown user":   env.login("nobody", testPassword, env.totp(sup.secret, 0)),
		"bad username":   env.login("NOT A NAME!", testPassword, env.totp(sup.secret, 0)),
		"wrong password": env.login("admin", testPassword+"x", env.totp(sup.secret, 0)),
		"wrong code":     env.login("admin", testPassword, "12345"),
	} {
		requireStatus(t, rec, http.StatusUnauthorized)
		if sessionCookie(rec) != nil {
			t.Fatalf("%s: got a session cookie", name)
		}
		bodies[name] = rec.Body.String()
	}
	for name, body := range bodies {
		if body != bodies["unknown user"] {
			t.Fatalf("%s response differs: %s", name, body)
		}
	}

	rec := env.login("Admin", testPassword, env.totp(sup.secret, 0)) // username is case-insensitive
	requireStatus(t, rec, http.StatusOK)
	if sessionCookie(rec) == nil {
		t.Fatal("no session cookie after login")
	}
}

func TestTOTPCodeCannotBeReused(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()

	// The code that completed setup cannot log in.
	requireStatus(t, env.login("admin", testPassword, env.totp(sup.secret, 0)), http.StatusUnauthorized)
	env.nextStep()
	code := env.totp(sup.secret, 0)
	requireStatus(t, env.login("admin", testPassword, code), http.StatusOK)
	requireStatus(t, env.login("admin", testPassword, code), http.StatusUnauthorized)
	// An older step stays refused after a newer one was used.
	requireStatus(t, env.login("admin", testPassword, env.totp(sup.secret, -1)), http.StatusUnauthorized)
}

func TestConcurrentLoginsShareNoCode(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	env.nextStep()
	code := env.totp(sup.secret, 0)

	const n = 8
	var wg sync.WaitGroup
	results := make([]int, n)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = env.login("admin", testPassword, code).Code
		}()
	}
	wg.Wait()
	ok := 0
	for _, status := range results {
		if status == http.StatusOK {
			ok++
		}
	}
	if ok != 1 {
		t.Fatalf("%d logins succeeded with one TOTP code, want exactly 1 (%v)", ok, results)
	}
}

func TestLoginLockout(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	env.nextStep()

	for i := 0; i < loginFailureThreshold; i++ {
		requireStatus(t, env.login("admin", "wrong wrong wrong", env.totp(sup.secret, 0)), http.StatusUnauthorized)
	}
	// Correct credentials are refused while locked.
	requireStatus(t, env.login("admin", testPassword, env.totp(sup.secret, 0)), http.StatusUnauthorized)
	env.clock.Advance(loginLockDuration - time.Minute)
	requireStatus(t, env.login("admin", testPassword, env.totp(sup.secret, 0)), http.StatusUnauthorized)
	// Attempts made while locked are ignored: they neither extend the lock
	// nor count towards the next one.
	for i := 0; i < loginFailureThreshold+1; i++ {
		requireStatus(t, env.login("admin", "wrong wrong wrong", "000000"), http.StatusUnauthorized)
	}
	env.clock.Advance(2 * time.Minute)
	requireStatus(t, env.login("admin", testPassword, env.totp(sup.secret, 0)), http.StatusOK)

	// A success resets the counter: four more failures do not lock.
	for i := 0; i < loginFailureThreshold-1; i++ {
		requireStatus(t, env.login("admin", "wrong wrong wrong", "000000"), http.StatusUnauthorized)
	}
	env.nextStep()
	requireStatus(t, env.login("admin", testPassword, env.totp(sup.secret, 0)), http.StatusOK)
}

func TestSessionTimeoutsAndLogout(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	me := func(c *personClient) int { return c.do(http.MethodGet, "/api/v1/auth/me", nil).Code }

	// Idle timeout.
	env.clock.Advance(sessionIdleTimeout - time.Minute)
	if me(sup) != http.StatusOK {
		t.Fatal("session ended before the idle timeout")
	}
	env.clock.Advance(sessionIdleTimeout)
	if me(sup) != http.StatusUnauthorized {
		t.Fatal("idle session still valid")
	}

	// Absolute lifetime, even when active.
	env.nextStep()
	rec := env.login("admin", testPassword, env.totp(sup.secret, 0))
	requireStatus(t, rec, http.StatusOK)
	sup.cookie, sup.csrf = sessionCookie(rec), decodeEnvelope[model.SessionInfo](t, rec).CSRFToken
	for elapsed := time.Duration(0); elapsed < sessionMaxLifetime-20*time.Minute; elapsed += 20 * time.Minute {
		env.clock.Advance(20 * time.Minute)
		if me(sup) != http.StatusOK {
			t.Fatalf("active session ended after %s", elapsed)
		}
	}
	env.clock.Advance(21 * time.Minute)
	if me(sup) != http.StatusUnauthorized {
		t.Fatal("session outlived its maximum lifetime")
	}

	// Logout.
	env.nextStep()
	rec = env.login("admin", testPassword, env.totp(sup.secret, 0))
	requireStatus(t, rec, http.StatusOK)
	sup.cookie, sup.csrf = sessionCookie(rec), decodeEnvelope[model.SessionInfo](t, rec).CSRFToken
	requireStatus(t, sup.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusOK)
	if me(sup) != http.StatusUnauthorized {
		t.Fatal("session valid after logout")
	}
}

func TestCSRFAndOriginChecks(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	body := model.CreatePersonInput{Username: "mei"}
	path := "/api/v1/supervisor/people"

	for name, headers := range map[string]map[string]string{
		"no token":          nil,
		"wrong token":       {csrfHeader: "nope"},
		"cross origin":      {csrfHeader: sup.csrf, "Origin": "https://evil.example"},
		"cross site header": {csrfHeader: sup.csrf, "Sec-Fetch-Site": "cross-site"},
	} {
		rec := env.request(http.MethodPost, path, sup.cookie, headers, body)
		requireErrorCode(t, rec, http.StatusForbidden, model.ErrCodeForbidden)
		_ = name
	}
	// Reads need no token; a same-origin write with the token works.
	requireStatus(t, env.request(http.MethodGet, path, sup.cookie, nil, nil), http.StatusOK)
	rec := env.request(http.MethodPost, path, sup.cookie,
		map[string]string{csrfHeader: sup.csrf, "Origin": "http://example.com", "Sec-Fetch-Site": "same-origin"}, body)
	requireStatus(t, rec, http.StatusCreated)

	// Cross-site login attempts are refused before any credential check.
	rec = env.request(http.MethodPost, "/api/v1/auth/login", nil, map[string]string{"Origin": "https://evil.example"},
		model.PersonLoginInput{Username: "admin", Password: testPassword, TOTPCode: "000000"})
	requireStatus(t, rec, http.StatusForbidden)
}

func TestSupervisorRoutesNeedASupervisorSession(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	path := "/api/v1/supervisor/people"

	requireStatus(t, env.request(http.MethodGet, path, nil, nil, nil), http.StatusUnauthorized)
	requireStatus(t, mei.do(http.MethodGet, path, nil), http.StatusForbidden)
	requireStatus(t, mei.do(http.MethodPost, path, model.CreatePersonInput{Username: "jun"}), http.StatusForbidden)
	// The legacy admin token and agent tokens are not sessions.
	requireStatus(t, env.do(http.MethodGet, path, env.adminToken, nil), http.StatusUnauthorized)
	requireStatus(t, env.do(http.MethodGet, path, env.agentTokens[demoAgentClaudeCode], nil), http.StatusUnauthorized)
	// A session is not an admin or agent token.
	requireStatus(t, sup.do(http.MethodGet, "/api/v1/admin/agents", nil), http.StatusUnauthorized)
	requireStatus(t, sup.do(http.MethodGet, "/api/v1/agent/me", nil), http.StatusUnauthorized)

	// Listed people never carry authentication material.
	rec := sup.do(http.MethodGet, path, nil)
	requireStatus(t, rec, http.StatusOK)
	for _, forbidden := range []string{"password", "totp", "setup_code", sup.secret} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("people list exposes %q", forbidden)
		}
	}
}

func TestLastSupervisorIsProtected(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	self := "/api/v1/supervisor/people/" + sup.person.ID
	suspended, no := model.PersonSuspended, false

	requireErrorCode(t, sup.do(http.MethodPatch, self, model.UpdatePersonInput{Status: &suspended}), http.StatusConflict, model.ErrCodeConflict)
	requireErrorCode(t, sup.do(http.MethodPatch, self, model.UpdatePersonInput{Supervisor: &no}), http.StatusConflict, model.ErrCodeConflict)
	requireErrorCode(t, sup.do(http.MethodPost, self+"/reset", nil), http.StatusConflict, model.ErrCodeConflict)

	// A pending second supervisor does not count.
	rec := sup.do(http.MethodPost, "/api/v1/supervisor/people", model.CreatePersonInput{Username: "mei", Supervisor: true})
	requireStatus(t, rec, http.StatusCreated)
	created := decodeEnvelope[model.PersonWithSetupCode](t, rec)
	requireErrorCode(t, sup.do(http.MethodPatch, self, model.UpdatePersonInput{Supervisor: &no}), http.StatusConflict, model.ErrCodeConflict)

	mei := env.completeSetup(created.SetupCode)
	requireStatus(t, sup.do(http.MethodPatch, self, model.UpdatePersonInput{Supervisor: &no}), http.StatusOK)
	// The former supervisor lost access at once; the new one is now the last.
	requireStatus(t, sup.do(http.MethodGet, "/api/v1/supervisor/people", nil), http.StatusForbidden)
	meiPath := "/api/v1/supervisor/people/" + mei.person.ID
	requireErrorCode(t, mei.do(http.MethodPatch, meiPath, model.UpdatePersonInput{Status: &suspended}), http.StatusConflict, model.ErrCodeConflict)
	if n, err := env.srv.db.CountActiveSupervisors(context.Background()); err != nil || n != 1 {
		t.Fatalf("active supervisors = %d, %v", n, err)
	}
}

func TestSuspendEndsSessionsAndBlocksLogin(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	path := "/api/v1/supervisor/people/" + mei.person.ID
	suspended, active := model.PersonSuspended, model.PersonActive

	requireStatus(t, sup.do(http.MethodPatch, path, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
	requireStatus(t, mei.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusUnauthorized)
	env.nextStep()
	requireStatus(t, env.login("mei", testPassword, env.totp(mei.secret, 0)), http.StatusUnauthorized)

	requireStatus(t, sup.do(http.MethodPatch, path, model.UpdatePersonInput{Status: &active}), http.StatusOK)
	env.nextStep()
	requireStatus(t, env.login("mei", testPassword, env.totp(mei.secret, 0)), http.StatusOK)

	// A person who never finished setup cannot be switched to active.
	rec := sup.do(http.MethodPost, "/api/v1/supervisor/people", model.CreatePersonInput{Username: "jun"})
	jun := decodeEnvelope[model.PersonWithSetupCode](t, rec)
	junPath := "/api/v1/supervisor/people/" + jun.Person.ID
	requireErrorCode(t, sup.do(http.MethodPatch, junPath, model.UpdatePersonInput{Status: &active}), http.StatusConflict, model.ErrCodeConflict)
	requireStatus(t, sup.do(http.MethodPatch, junPath, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
	requireErrorCode(t, sup.do(http.MethodPatch, junPath, model.UpdatePersonInput{Status: &active}), http.StatusConflict, model.ErrCodeConflict)
	// A suspended invitation cannot be completed.
	rec = env.request(http.MethodPost, "/api/v1/auth/setup/begin", nil, nil,
		model.SetupBeginInput{SetupCode: jun.SetupCode, Password: testPassword})
	requireStatus(t, rec, http.StatusBadRequest)
}

func TestResetReplacesCredentials(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)

	rec := sup.do(http.MethodPost, "/api/v1/supervisor/people/"+mei.person.ID+"/reset", nil)
	requireStatus(t, rec, http.StatusOK)
	reset := decodeEnvelope[model.PersonWithSetupCode](t, rec)
	requireStatus(t, mei.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusUnauthorized)
	env.nextStep()
	requireStatus(t, env.login("mei", testPassword, env.totp(mei.secret, 0)), http.StatusUnauthorized)

	fresh := env.completeSetup(reset.SetupCode)
	if fresh.secret == mei.secret {
		t.Fatal("reset kept the old TOTP secret")
	}
	requireStatus(t, fresh.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusOK)
}

func TestRoleBindings(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	base := "/api/v1/supervisor/accounts/" + env.providerID + "/people/"

	requireStatus(t, sup.do(http.MethodPut, base+mei.person.ID, map[string]string{"role": "owner"}), http.StatusBadRequest)
	requireStatus(t, sup.do(http.MethodPut, base+"per_missing", model.PutBindingInput{Role: model.RoleGuest}), http.StatusNotFound)
	requireStatus(t, sup.do(http.MethodPut, "/api/v1/supervisor/accounts/prv_missing/people/"+mei.person.ID,
		model.PutBindingInput{Role: model.RoleGuest}), http.StatusNotFound)
	// Only supervisors bind, even for themselves.
	requireStatus(t, mei.do(http.MethodPut, base+mei.person.ID, model.PutBindingInput{Role: model.RoleAdministrator}), http.StatusForbidden)

	requireStatus(t, sup.do(http.MethodPut, base+mei.person.ID, model.PutBindingInput{Role: model.RoleMember}), http.StatusOK)
	requireStatus(t, sup.do(http.MethodPut, base+mei.person.ID, model.PutBindingInput{Role: model.RoleGuest}), http.StatusOK)
	rec := mei.do(http.MethodGet, "/api/v1/auth/me", nil)
	info := decodeEnvelope[model.SessionInfo](t, rec)
	if len(info.Bindings) != 1 || info.Bindings[0].Role != model.RoleGuest || info.Bindings[0].ProviderID != env.providerID {
		t.Fatalf("bindings = %+v", info.Bindings)
	}
	// A supervisor has no cloud access until bound, and self-binding is flagged.
	rec = sup.do(http.MethodGet, "/api/v1/auth/me", nil)
	if got := decodeEnvelope[model.SessionInfo](t, rec).Bindings; len(got) != 0 {
		t.Fatalf("supervisor has bindings by default: %+v", got)
	}
	requireStatus(t, sup.do(http.MethodPut, base+sup.person.ID, model.PutBindingInput{Role: model.RoleAdministrator}), http.StatusOK)
	events := env.listAudit("binding.set")
	if len(events) != 3 || events[0].Severity != "warning" || events[0].Metadata["self"] != true || events[1].Severity != "info" {
		t.Fatalf("binding audit wrong: %+v", events)
	}

	requireStatus(t, sup.do(http.MethodDelete, base+mei.person.ID, nil), http.StatusOK)
	requireStatus(t, sup.do(http.MethodDelete, base+mei.person.ID, nil), http.StatusNotFound)
	rec = sup.do(http.MethodGet, "/api/v1/supervisor/bindings?provider_id="+env.providerID, nil)
	list := decodeEnvelope[listData[model.RoleBinding]](t, rec)
	if list.Total != 1 || list.Items[0].PersonID != sup.person.ID {
		t.Fatalf("bindings after delete = %+v", list)
	}
	env.verifyAudit()
}

func TestRecoverSupervisor(t *testing.T) {
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	ctx := context.Background()

	if _, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: env.dir, Username: "admin", MasterKey: bytes.Repeat([]byte{7}, 32)}); err == nil {
		t.Fatal("recovery accepted a wrong master key")
	}
	requireStatus(t, sup.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusOK)

	out, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: env.dir, Username: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Person.Status != model.PersonPending || !out.Person.Supervisor || out.SetupCode == "" {
		t.Fatalf("unexpected recovery result: %+v", out.Person)
	}
	requireStatus(t, sup.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusUnauthorized)
	env.nextStep()
	requireStatus(t, env.login("admin", testPassword, env.totp(sup.secret, 0)), http.StatusUnauthorized)
	fresh := env.completeSetup(out.SetupCode)
	requireStatus(t, fresh.do(http.MethodGet, "/api/v1/supervisor/people", nil), http.StatusOK)
	if events := env.listAudit("person.supervisor_recovered"); len(events) != 1 || events[0].Severity != "critical" {
		t.Fatalf("recovery audit = %+v", events)
	}

	// Recovery of an unknown username creates that supervisor.
	out, err = RecoverSupervisor(ctx, RecoverOptions{DataDir: env.dir, Username: "rescue"})
	if err != nil || !out.Person.Supervisor {
		t.Fatalf("recover new: %+v, %v", out.Person, err)
	}
	if _, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: t.TempDir(), Username: "admin"}); err == nil {
		t.Fatal("recovery ran on an uninitialized directory")
	}
}

func TestInitForceKeepsExistingSupervisor(t *testing.T) {
	env := newTestEnv(t, false)
	env.supervisorClient()
	res, err := Init(context.Background(), InitOptions{DataDir: env.dir, Force: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Supervisor != nil {
		t.Fatal("init --force issued a second supervisor")
	}
}

// ---- regression tests for the independent review of commit 42be770 ----

// loginReasons counts auth.login_failed audit events by reason.
func (e *testEnv) loginReasons() map[string]int {
	e.t.Helper()
	out := map[string]int{}
	for _, ev := range e.listAudit("auth.login_failed") {
		out[ev.Metadata["reason"].(string)]++
	}
	return out
}

// A burst of parallel logins gets exactly the failure budget, not "the
// budget plus everything already in flight".
func TestLockoutIsExactUnderParallelLogins(t *testing.T) {
	for _, wrong := range []string{"code", "password"} {
		t.Run("wrong "+wrong, func(t *testing.T) {
			env := newTestEnv(t, false)
			sup := env.supervisorClient()
			env.nextStep()
			valid := map[string]bool{}
			for d := int64(-1); d <= 1; d++ {
				valid[env.totp(sup.secret, d)] = true
			}
			const n = 20
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				password, code := testPassword, fmt.Sprintf("%06d", 100000+i)
				if valid[code] {
					code = "999999"
				}
				if wrong == "password" {
					password, code = fmt.Sprintf("a wrong passphrase %d", i), env.totp(sup.secret, 0)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					if rec := env.login("admin", password, code); rec.Code != http.StatusUnauthorized {
						t.Errorf("status %d", rec.Code)
					}
				}()
			}
			wg.Wait()
			reasons := env.loginReasons()
			if got := reasons["wrong "+wrong]; got != loginFailureThreshold {
				t.Fatalf("%d attempts were verified, want exactly %d (%v)", got, loginFailureThreshold, reasons)
			}
			if got := reasons["account temporarily locked"]; got != n-loginFailureThreshold {
				t.Fatalf("%d attempts hit the lock, want %d (%v)", got, n-loginFailureThreshold, reasons)
			}
			// The correct credentials are refused until the lock ends.
			requireStatus(t, env.login("admin", testPassword, env.totp(sup.secret, 0)), http.StatusUnauthorized)
		})
	}
}

// Sending one valid code several times at once (a double click) signs in
// once and never locks the account.
func TestSameCodeBurstDoesNotLock(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	env.nextStep()
	code := env.totp(sup.secret, 0)
	const n = 8
	var wg sync.WaitGroup
	results := make([]int, n)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = env.login("admin", testPassword, code).Code
		}()
	}
	wg.Wait()
	ok := 0
	for _, status := range results {
		if status == http.StatusOK {
			ok++
		}
	}
	auth, err := env.srv.db.GetPersonAuth(context.Background(), sup.person.ID)
	if err != nil {
		t.Fatal(err)
	}
	if ok != 1 || auth.LockedUntil != nil || auth.FailedLogins != 0 {
		t.Fatalf("successes=%d locked=%v failed=%d (%v)", ok, auth.LockedUntil, auth.FailedLogins, results)
	}
	env.nextStep()
	requireStatus(t, env.login("admin", testPassword, env.totp(sup.secret, 0)), http.StatusOK)
}

// Recovery and serve refuse a wrong master key even when the data directory
// holds no provider credential.
func TestWrongMasterKeyIsRefusedWithoutProviders(t *testing.T) {
	ctx := context.Background()
	wrongKey := bytes.Repeat([]byte{9}, 32)
	deleteKeyCheck := func(env *testEnv) {
		t.Helper()
		if _, err := env.srv.db.SQL().Exec(`DELETE FROM meta WHERE key = ?`, store.MetaVaultKeyCheck); err != nil {
			t.Fatal(err)
		}
	}

	env := newTestEnv(t, false) // no providers, nobody set up yet
	if _, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: env.dir, Username: "admin", MasterKey: wrongKey}); !errors.Is(err, errWrongMasterKey) {
		t.Fatalf("fresh data dir, wrong key: %v", err)
	}
	if _, err := New(Config{DataDir: env.dir, MasterKey: wrongKey}); !errors.Is(err, errWrongMasterKey) {
		t.Fatalf("serve with a wrong key: %v", err)
	}
	sup := env.supervisorClient()
	if _, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: env.dir, Username: "admin", MasterKey: wrongKey}); !errors.Is(err, errWrongMasterKey) {
		t.Fatalf("after setup, wrong key: %v", err)
	}
	requireStatus(t, sup.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusOK)

	// A data directory from before the key check: a stored TOTP secret is
	// used instead, and with nothing encrypted at all recovery fails closed.
	deleteKeyCheck(env)
	if _, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: env.dir, Username: "admin", MasterKey: wrongKey}); !errors.Is(err, errWrongMasterKey) {
		t.Fatalf("no key check, TOTP secret present, wrong key: %v", err)
	}
	empty := newTestEnv(t, false)
	deleteKeyCheck(empty)
	for name, key := range map[string][]byte{"wrong": wrongKey, "right": nil} {
		if _, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: empty.dir, Username: "admin", MasterKey: key}); !errors.Is(err, errVaultKeyUnverifiable) {
			t.Fatalf("nothing to verify against, %s key: %v", name, err)
		}
	}

	// The right key still works.
	if _, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: env.dir, Username: "admin"}); err != nil {
		t.Fatalf("right key: %v", err)
	}
}

func TestSameOriginRules(t *testing.T) {
	env := newTestEnv(t, false)
	check := func(host string, tls bool, headers map[string]string) bool {
		req := httptest.NewRequest(http.MethodPost, "http://"+host+"/api/v1/auth/login", nil)
		req.Host = host
		if tls {
			req.TLS = &cryptotls.ConnectionState{}
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return env.srv.sameOrigin(req)
	}
	origin := func(o string) map[string]string { return map[string]string{"Origin": o} }
	cases := []struct {
		name string
		host string
		tls  bool
		h    map[string]string
		want bool
	}{
		{"no origin (non-browser client)", "console.example.com", false, nil, true},
		{"same origin http", "console.example.com", false, origin("http://console.example.com"), true},
		{"same origin, case differs", "Console.Example.com", false, origin("http://console.example.COM"), true},
		{"same origin https", "console.example.com", true, origin("https://console.example.com"), true},
		{"http origin for an https server", "console.example.com", true, origin("http://console.example.com"), false},
		{"https origin for an http server", "console.example.com", false, origin("https://console.example.com"), false},
		{"other host", "console.example.com", false, origin("http://evil.example"), false},
		{"other port", "console.example.com:8787", false, origin("http://console.example.com:9999"), false},
		{"port missing", "console.example.com:8787", false, origin("http://console.example.com"), false},
		{"null origin", "console.example.com", false, origin("null"), false},
		{"userinfo", "console.example.com", false, origin("http://x@console.example.com"), false},
		{"path", "console.example.com", false, origin("http://console.example.com/evil"), false},
		{"query", "console.example.com", false, origin("http://console.example.com?x=1"), false},
		{"fragment", "console.example.com", false, origin("http://console.example.com#x"), false},
		{"scheme-relative", "console.example.com", false, origin("//console.example.com"), false},
		{"other scheme", "console.example.com", false, origin("ftp://console.example.com"), false},
		{"cross-site fetch metadata", "console.example.com", false, map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"same-site fetch metadata", "console.example.com", false, map[string]string{"Sec-Fetch-Site": "same-site"}, false},
	}
	for _, c := range cases {
		if got := check(c.host, c.tls, c.h); got != c.want {
			t.Errorf("%s: sameOrigin = %v, want %v", c.name, got, c.want)
		}
	}

	// Behind a TLS proxy the configured public origin is the only one
	// accepted, whatever Host header the proxy forwards.
	var err error
	if env.srv.publicOrigin, err = parsePublicOrigin("https://CSG.example.com/"); err != nil {
		t.Fatal(err)
	}
	if !check("10.0.0.5:8787", false, origin("https://csg.example.com")) {
		t.Error("public origin refused")
	}
	if check("evil.example", false, origin("http://evil.example")) {
		t.Error("forwarded attacker Host accepted despite a public origin")
	}
	for _, bad := range []string{"csg.example.com", "ftp://csg.example.com", "https://csg.example.com/path", "https://u@csg.example.com"} {
		if _, err := parsePublicOrigin(bad); err == nil {
			t.Errorf("public origin %q accepted", bad)
		}
	}
}

func TestSecureCookieBehindTLSProxy(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	if sup.cookie.Secure {
		t.Fatal("cookie marked Secure on plain HTTP without a public origin")
	}
	env.srv.publicOrigin = "https://csg.example.com"
	env.nextStep()
	rec := env.login("admin", testPassword, env.totp(sup.secret, 0))
	requireStatus(t, rec, http.StatusOK)
	if c := sessionCookie(rec); c == nil || !c.Secure {
		t.Fatalf("cookie not Secure behind an https public origin: %+v", c)
	}
}

func TestLoginNeedsJSONContentType(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	env.nextStep()
	body, _ := json.Marshal(model.PersonLoginInput{Username: "admin", Password: testPassword, TOTPCode: env.totp(sup.secret, 0)})
	for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		rec := httptest.NewRecorder()
		env.srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnsupportedMediaType || sessionCookie(rec) != nil {
			t.Errorf("Content-Type %q: status %d", contentType, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	rec := httptest.NewRecorder()
	env.srv.Handler().ServeHTTP(rec, req)
	requireStatus(t, rec, http.StatusOK)
}

func TestLogoutNeedsCSRFToken(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	requireStatus(t, env.request(http.MethodPost, "/api/v1/auth/logout", sup.cookie, nil, nil), http.StatusForbidden)
	requireStatus(t, sup.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusOK)
}

// A person suspended before finishing setup is brought back with a reset.
func TestResetRecoversSuspendedInvitation(t *testing.T) {
	env := newTestEnv(t, false)
	sup := env.supervisorClient()
	rec := sup.do(http.MethodPost, "/api/v1/supervisor/people", model.CreatePersonInput{Username: "jun"})
	jun := decodeEnvelope[model.PersonWithSetupCode](t, rec)
	path := "/api/v1/supervisor/people/" + jun.Person.ID
	suspended := model.PersonSuspended
	requireStatus(t, sup.do(http.MethodPatch, path, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
	rec = sup.do(http.MethodPost, path+"/reset", nil)
	requireStatus(t, rec, http.StatusOK)
	reset := decodeEnvelope[model.PersonWithSetupCode](t, rec)
	if reset.Person.Status != model.PersonPending {
		t.Fatalf("status after reset = %s", reset.Person.Status)
	}
	client := env.completeSetup(reset.SetupCode)
	requireStatus(t, client.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusOK)
}
