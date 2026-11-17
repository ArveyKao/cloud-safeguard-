package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// cliClient is csg signed in as a person (CONTRACT §17.9).
type cliClient struct {
	env    *testEnv
	token  string
	person *personClient // the same person in the console, for codes
}

func (c *cliClient) do(method, path string, body any) *httptest.ResponseRecorder {
	c.env.t.Helper()
	return c.env.do(method, path, c.token, body)
}

// withCode sends a request with a fresh authenticator code of the person.
func (c *cliClient) withCode(method, path string, body any) *httptest.ResponseRecorder {
	c.env.t.Helper()
	c.env.nextStep()
	return c.doWithHeader(method, path, body, c.env.totp(c.person.secret, 0))
}

func (c *cliClient) doWithHeader(method, path string, body any, code string) *httptest.ResponseRecorder {
	c.env.t.Helper()
	var raw []byte
	if body != nil {
		var err error
		if raw, err = json.Marshal(body); err != nil {
			c.env.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set(authenticatorCodeHeader, code)
	rec := httptest.NewRecorder()
	c.env.srv.Handler().ServeHTTP(rec, req)
	return rec
}

func (e *testEnv) startCLISignIn(name string) model.AgentSignInStart {
	e.t.Helper()
	rec := e.request(http.MethodPost, "/api/v1/person-signin/start", nil, nil, model.PersonSignInStartInput{ClientName: name})
	requireStatus(e.t, rec, http.StatusCreated)
	return decodeEnvelope[model.AgentSignInStart](e.t, rec)
}

func (e *testEnv) pollCLISignIn(deviceCode string) model.PersonSignInResult {
	e.t.Helper()
	rec := e.request(http.MethodPost, "/api/v1/person-signin/token", nil, nil, model.AgentSignInTokenInput{DeviceCode: deviceCode})
	requireStatus(e.t, rec, http.StatusOK)
	return decodeEnvelope[model.PersonSignInResult](e.t, rec)
}

// signInCLI runs the whole command-line sign-in for a person.
func (e *testEnv) signInCLI(p *personClient) *cliClient {
	e.t.Helper()
	start := e.startCLISignIn("laptop")
	requireStatus(e.t, p.do(http.MethodPost, "/api/v1/me/cli-signins/"+start.UserCode+"/approve", nil), http.StatusOK)
	res := e.pollCLISignIn(start.DeviceCode)
	if res.Status != model.SignInApproved || !strings.HasPrefix(res.Token, cliTokenPrefix) || res.Person == nil || res.Person.ID != p.person.ID {
		e.t.Fatalf("command-line sign-in not completed: %+v", res)
	}
	return &cliClient{env: e, token: res.Token, person: p}
}

func TestCLISignInFlow(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	start := a.startCLISignIn("laptop")
	if start.DeviceCode == "" || !strings.Contains(start.VerificationURL, "cli-signin="+start.UserCode) {
		t.Fatalf("start = %+v", start)
	}
	// Nothing until a person approves.
	if res := a.pollCLISignIn(start.DeviceCode); res.Status != model.SignInPending || res.Token != "" {
		t.Fatalf("poll before approval = %+v", res)
	}
	rec := a.mei.do(http.MethodGet, "/api/v1/me/cli-signins/"+start.UserCode, nil)
	requireStatus(t, rec, http.StatusOK)
	if view := decodeEnvelope[model.CLISignIn](t, rec); view.ClientName != "laptop" || view.Status != model.SignInPending {
		t.Fatalf("pending sign-in = %+v", view)
	}
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-signins/"+start.UserCode+"/approve", nil), http.StatusOK)
	res := a.pollCLISignIn(start.DeviceCode)
	if res.Status != model.SignInApproved || res.Person == nil || res.Person.ID != a.mei.person.ID || res.ExpiresAt == nil {
		t.Fatalf("poll after approval = %+v", res)
	}
	// Exactly once.
	if again := a.pollCLISignIn(start.DeviceCode); again.Status != model.SignInExpired || again.Token != "" {
		t.Fatalf("second poll = %+v", again)
	}
	cli := &cliClient{env: a.testEnv, token: res.Token, person: a.mei}

	rec = cli.do(http.MethodGet, "/api/v1/auth/me", nil)
	requireStatus(t, rec, http.StatusOK)
	if info := decodeEnvelope[model.SessionInfo](t, rec); info.Person.ID != a.mei.person.ID || info.Kind != store.SessionCLI || info.CSRFToken != "" {
		t.Fatalf("auth/me = %+v", info)
	}
	requireStatus(t, cli.do(http.MethodGet, "/api/v1/me/requests", nil), http.StatusOK)
	// It needs no CSRF token for a write: deny is a lowering action.
	req := a.request(accessInput("ecs", "write"))
	requireStatus(t, cli.do(http.MethodPost, "/api/v1/me/requests/"+req.ID+"/deny", model.DenyRequestInput{Reason: "not now"}), http.StatusOK)

	// Tokens stay in their lanes.
	requireStatus(t, cli.do(http.MethodGet, "/api/v1/agent/me", nil), http.StatusUnauthorized)
	requireStatus(t, a.do(http.MethodGet, "/api/v1/me/requests", a.token, nil), http.StatusUnauthorized)
	// The token in a cookie is not a console session.
	cookie := &http.Cookie{Name: sessionCookieName, Value: cli.token}
	requireStatus(t, a.testEnv.request(http.MethodGet, "/api/v1/auth/me", cookie, nil, nil), http.StatusUnauthorized)
	// With an Authorization header the cookie is ignored, even a good one.
	bad := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	bad.AddCookie(a.mei.cookie)
	bad.Header.Set("Authorization", "Bearer "+cliTokenPrefix+"forged")
	got := httptest.NewRecorder()
	a.srv.Handler().ServeHTTP(got, bad)
	requireStatus(t, got, http.StatusUnauthorized)

	// The audit log records who signed in where; the token is nowhere.
	ev := a.lastEvent("cli_signin.completed")
	a.requireActor(ev, a.mei)
	raw, _ := json.Marshal(a.listAudit(""))
	if strings.Contains(string(raw), cli.token) || strings.Contains(string(raw), start.DeviceCode) {
		t.Fatal("the audit log contains the token or the device code")
	}
	if strings.Contains(a.logs.String(), cli.token) {
		t.Fatal("the server log contains the token")
	}
}

func TestCLISignInDenyExpiryAndValidation(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	start := a.startCLISignIn("laptop")
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-signins/"+start.UserCode+"/deny", nil), http.StatusOK)
	if res := a.pollCLISignIn(start.DeviceCode); res.Status != model.SignInDenied || res.Token != "" {
		t.Fatalf("denied sign-in = %+v", res)
	}
	late := a.startCLISignIn("laptop")
	a.clock.Advance(signInTTL + time.Second)
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-signins/"+late.UserCode+"/approve", nil), http.StatusNotFound)
	if res := a.pollCLISignIn(late.DeviceCode); res.Status != model.SignInExpired || res.Token != "" {
		t.Fatalf("expired sign-in = %+v", res)
	}
	rec := a.request2Raw(http.MethodPost, "/api/v1/person-signin/start", model.PersonSignInStartInput{ClientName: "bad name!"})
	requireStatus(t, rec, http.StatusBadRequest)
	rec = a.request2Raw(http.MethodPost, "/api/v1/person-signin/token", model.AgentSignInTokenInput{DeviceCode: "nope"})
	requireStatus(t, rec, http.StatusNotFound)
	// A code for an agent sign-in is not a command-line sign-in, and back.
	agentStart := a.startSignIn("some-agent")
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-signins/"+agentStart.UserCode+"/approve", nil), http.StatusNotFound)
	cliStart := a.startCLISignIn("laptop")
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/signins/"+cliStart.UserCode+"/approve", nil), http.StatusNotFound)
}

// request2Raw sends an unauthenticated JSON request.
func (a *accessEnv) request2Raw(method, path string, body any) *httptest.ResponseRecorder {
	return a.testEnv.request(method, path, nil, nil, body)
}

// What an agent that reads the session file could do with it: nothing that
// approves, with or without a code.
func TestCLISessionCannotApprove(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	cli := a.signInCLI(a.mei)
	req := a.request(accessInput("ecs", "write"))
	agentStart := a.startSignIn("rogue-agent")
	cliStart := a.startCLISignIn("other-laptop")
	supCLI := a.signInCLI(a.sup)

	for name, call := range map[string]struct {
		c            *cliClient
		method, path string
		body         any
	}{
		"approve an access request":    {cli, http.MethodPost, "/api/v1/me/requests/" + req.ID + "/approve", nil},
		"approve an agent sign-in":     {cli, http.MethodPost, "/api/v1/me/signins/" + agentStart.UserCode + "/approve", nil},
		"approve a command-line login": {cli, http.MethodPost, "/api/v1/me/cli-signins/" + cliStart.UserCode + "/approve", nil},
		"add a cloud account":          {supCLI, http.MethodPost, "/api/v1/supervisor/accounts", newMockAccount("x", "6543210987654321")},
	} {
		for _, withCode := range []bool{false, true} {
			var rec *httptest.ResponseRecorder
			if withCode {
				rec = call.c.withCode(call.method, call.path, call.body)
			} else {
				rec = call.c.do(call.method, call.path, call.body)
			}
			requireErrorCode(t, rec, http.StatusForbidden, model.ErrCodeConsoleOnly)
			_ = name
		}
	}
	if a.status(req.ID) != model.LeasePending || a.minter.requestCount() != 0 {
		t.Fatal("a command-line session approved a request")
	}
	if res := a.pollSignIn(agentStart.DeviceCode); res.Status != model.SignInPending {
		t.Fatalf("agent sign-in after the refused approval = %+v", res)
	}
	if res := a.pollCLISignIn(cliStart.DeviceCode); res.Status != model.SignInPending {
		t.Fatalf("command-line sign-in after the refused approval = %+v", res)
	}
	rec := a.sup.do(http.MethodGet, "/api/v1/supervisor/accounts", nil)
	if decodeEnvelope[listData[model.Provider]](t, rec).Total != 1 {
		t.Fatal("a command-line session added a cloud account")
	}
	if a.lastEvent("auth.console_only_refused").Metadata["path"] == nil {
		t.Fatal("the refusal was not recorded")
	}
	// The console still can.
	requireStatus(t, a.approve(a.mei, req.ID), http.StatusOK)
}

// Every change that raises access needs a fresh authenticator code from a
// command-line session; the same change works in the console without one.
func TestCLIRaisingChangesNeedACode(t *testing.T) {
	a := newAccessEnv(t, model.RoleGuest)
	sup := a.signInCLI(a.sup)
	mei := a.signInCLI(a.mei)
	jun := a.addPerson(a.sup, "jun", false)
	suspended := model.PersonSuspended
	requireStatus(t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+jun.person.ID, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
	active := model.PersonActive
	yes := true
	region := "cn-shanghai"
	enabled := model.ProviderActive
	raised := model.DefaultPolicySettings()
	raised.MaxLeaseTTLSeconds = 1800 // below the default, but another value goes up
	raised.LeasesPerMinutePerAgent = 60
	account := "/api/v1/supervisor/accounts/" + a.providerID

	type call struct {
		c            *cliClient
		method, path string
		body         any
		changed      func() bool
	}
	calls := map[string]call{
		"add a person": {sup, http.MethodPost, "/api/v1/supervisor/people", model.CreatePersonInput{Username: "kai"}, func() bool {
			_, err := a.srv.db.GetPersonByUsername(context.Background(), "kai")
			return err == nil
		}},
		"reset a person": {sup, http.MethodPost, "/api/v1/supervisor/people/" + a.mei.person.ID + "/reset", nil, func() bool {
			p, _ := a.srv.db.GetPerson(context.Background(), a.mei.person.ID)
			return p.Status == model.PersonPending
		}},
		"activate a person": {sup, http.MethodPatch, "/api/v1/supervisor/people/" + jun.person.ID, model.UpdatePersonInput{Status: &active}, func() bool {
			p, _ := a.srv.db.GetPerson(context.Background(), jun.person.ID)
			return p.Status == model.PersonActive
		}},
		"make a supervisor": {sup, http.MethodPatch, "/api/v1/supervisor/people/" + a.mei.person.ID, model.UpdatePersonInput{Supervisor: &yes}, func() bool {
			p, _ := a.srv.db.GetPerson(context.Background(), a.mei.person.ID)
			return p.Supervisor
		}},
		"give a role above guest": {sup, http.MethodPut, account + "/people/" + a.mei.person.ID, model.PutBindingInput{Role: model.RoleMember}, func() bool {
			b, _ := a.srv.db.GetBinding(context.Background(), a.mei.person.ID, a.providerID)
			return b.Role == model.RoleMember
		}},
		"change an account's region": {sup, http.MethodPatch, account, model.UpdateProviderInput{Region: &region}, func() bool {
			p, _ := a.srv.db.GetProvider(context.Background(), a.providerID)
			return p.Region == region
		}},
		"replace the AccessKey": {sup, http.MethodPost, account + "/rotate", model.RotateProviderCredentialInput{AccessKeyID: "LTAI5tRotatedByCli1", AccessKeySecret: "rotated-secret"}, func() bool {
			p, _ := a.srv.db.GetProvider(context.Background(), a.providerID)
			return strings.HasSuffix(p.AccessKeyIDMasked, "Cli1")
		}},
		"raise the automatic level": {sup, http.MethodPut, account + "/auto-level", model.SetAutoLevelInput{MaxAutoLevel: model.ModeWrite}, func() bool {
			p, _ := a.srv.db.GetProvider(context.Background(), a.providerID)
			return p.MaxAutoLevel == model.ModeWrite
		}},
		"raise a limit": {sup, http.MethodPut, "/api/v1/supervisor/settings", raised, func() bool {
			s, _ := a.srv.db.GetPolicySettings(context.Background())
			return s.LeasesPerMinutePerAgent == 60
		}},
		"set an approval mode above read": {mei, http.MethodPut, "/api/v1/me/approval-mode", model.SetApprovalModeInput{Mode: model.ModeWrite}, func() bool {
			p, _ := a.srv.db.GetPerson(context.Background(), a.mei.person.ID)
			return p.ApprovalMode == model.ModeWrite
		}},
	}
	// "enable a disabled account" needs the account disabled first.
	order := []string{"add a person", "activate a person", "give a role above guest", "set an approval mode above read",
		"make a supervisor", "change an account's region", "replace the AccessKey", "raise the automatic level", "raise a limit", "reset a person"}
	for _, name := range order {
		c := calls[name]
		rec := c.c.do(c.method, c.path, c.body)
		requireErrorCode(t, rec, http.StatusForbidden, model.ErrCodeAuthenticatorCodeRequired)
		if c.changed() {
			t.Fatalf("%s: changed without a code", name)
		}
		rec = c.c.withCode(c.method, c.path, c.body)
		if rec.Code >= 300 {
			t.Fatalf("%s with a code: %d %s", name, rec.Code, rec.Body.String())
		}
		if !c.changed() {
			t.Fatalf("%s: not changed with a code", name)
		}
	}
	// Enabling a disabled account.
	disabled := model.ProviderDisabled
	requireStatus(t, sup.do(http.MethodPatch, account, model.UpdateProviderInput{Status: &disabled}), http.StatusOK)
	requireErrorCode(t, sup.do(http.MethodPatch, account, model.UpdateProviderInput{Status: &enabled}), http.StatusForbidden, model.ErrCodeAuthenticatorCodeRequired)
	requireStatus(t, sup.withCode(http.MethodPatch, account, model.UpdateProviderInput{Status: &enabled}), http.StatusOK)
	// Each accepted code was recorded.
	if n := len(a.listAudit("auth.step_up")); n != len(order)+1 {
		t.Fatalf("auth.step_up events = %d, want %d", n, len(order)+1)
	}
}

// Lowering access works from the command line without a code.
func TestCLILoweringChangesNeedNoCode(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	sup := a.signInCLI(a.sup)
	mei := a.signInCLI(a.mei)
	jun := a.addPerson(a.sup, "jun", true)
	read := a.request(accessInput("ecs", "read"))
	write := a.request(accessInput("ecs", "write"))
	account := "/api/v1/supervisor/accounts/" + a.providerID
	no := false
	suspended := model.PersonSuspended
	disabled := model.ProviderDisabled
	name := "renamed"
	lowered := model.DefaultPolicySettings()
	lowered.MaxLeaseTTLSeconds = 1800

	type step struct {
		label string
		rec   func() *httptest.ResponseRecorder
	}
	for _, s := range []step{
		{"deny a request", func() *httptest.ResponseRecorder {
			return mei.do(http.MethodPost, "/api/v1/me/requests/"+write.ID+"/deny", model.DenyRequestInput{Reason: "no"})
		}},
		{"revoke a credential", func() *httptest.ResponseRecorder {
			return mei.do(http.MethodPost, "/api/v1/me/requests/"+read.ID+"/revoke", nil)
		}},
		{"set the mode to read", func() *httptest.ResponseRecorder {
			return mei.do(http.MethodPut, "/api/v1/me/approval-mode", model.SetApprovalModeInput{Mode: model.ModeRead})
		}},
		{"lower a role to guest", func() *httptest.ResponseRecorder {
			return sup.do(http.MethodPut, account+"/people/"+a.mei.person.ID, model.PutBindingInput{Role: model.RoleGuest})
		}},
		{"remove the supervisor flag", func() *httptest.ResponseRecorder {
			return sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+jun.person.ID, model.UpdatePersonInput{Supervisor: &no})
		}},
		{"suspend a person", func() *httptest.ResponseRecorder {
			return sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+jun.person.ID, model.UpdatePersonInput{Status: &suspended})
		}},
		{"rename an account", func() *httptest.ResponseRecorder {
			return sup.do(http.MethodPatch, account, model.UpdateProviderInput{Name: &name})
		}},
		{"lower the auto level", func() *httptest.ResponseRecorder {
			return sup.do(http.MethodPut, account+"/auto-level", model.SetAutoLevelInput{MaxAutoLevel: model.ModeRead})
		}},
		{"lower a limit", func() *httptest.ResponseRecorder {
			return sup.do(http.MethodPut, "/api/v1/supervisor/settings", lowered)
		}},
		{"test the connection", func() *httptest.ResponseRecorder { return sup.do(http.MethodPost, account+"/test", nil) }},
		{"remove a role", func() *httptest.ResponseRecorder {
			return sup.do(http.MethodDelete, account+"/people/"+a.mei.person.ID, nil)
		}},
		{"disable the account", func() *httptest.ResponseRecorder {
			return sup.do(http.MethodPatch, account, model.UpdateProviderInput{Status: &disabled})
		}},
	} {
		if r := s.rec(); r.Code >= 300 {
			t.Errorf("%s: %d %s", s.label, r.Code, r.Body.String())
		}
	}
	if len(a.listAudit("auth.step_up")) != 0 {
		t.Fatal("a lowering change asked for a code")
	}
}

// A wrong code counts towards the lockout; a code is used once; the lock
// then holds for the console too.
func TestCLICodeIsCheckedLikeASignIn(t *testing.T) {
	a := newAccessEnv(t, model.RoleGuest)
	sup := a.signInCLI(a.sup)
	path := "/api/v1/supervisor/accounts/" + a.providerID + "/people/" + a.mei.person.ID
	body := model.PutBindingInput{Role: model.RoleMember}

	// A code accepted once is refused the second time, and does not count.
	a.nextStep()
	code := a.totp(a.sup.secret, 0)
	requireStatus(t, sup.doWithHeader(http.MethodPut, path, body, code), http.StatusOK)
	// From member, administrator is the raise that needs a code.
	body = model.PutBindingInput{Role: model.RoleAdministrator}
	requireErrorCode(t, sup.doWithHeader(http.MethodPut, path, body, code), http.StatusForbidden, model.ErrCodeAuthenticatorCodeInvalid)

	for i := 0; i < loginFailureThreshold; i++ {
		requireErrorCode(t, sup.doWithHeader(http.MethodPut, path, body, "000000"), http.StatusForbidden, model.ErrCodeAuthenticatorCodeInvalid)
	}
	// Locked: even the right code is refused, here and at the console login.
	requireErrorCode(t, sup.withCode(http.MethodPut, path, body), http.StatusForbidden, model.ErrCodeAuthenticatorCodeInvalid)
	a.nextStep()
	requireStatus(t, a.login(a.sup.person.Username, testPassword, a.totp(a.sup.secret, 0)), http.StatusUnauthorized)
	failed := a.listAudit("auth.step_up_failed")
	if len(failed) < loginFailureThreshold+2 {
		t.Fatalf("auth.step_up_failed events = %d", len(failed))
	}
	// After the lock the code works again.
	a.clock.Advance(loginLockDuration + time.Second)
	requireStatus(t, sup.withCode(http.MethodPut, path, body), http.StatusOK)
}

// A command-line session ends like a console session, and the person can
// end it from the console.
func TestCLISessionLifecycle(t *testing.T) {
	t.Run("logout", func(t *testing.T) {
		a := newAccessEnv(t, model.RoleMember)
		cli := a.signInCLI(a.mei)
		requireStatus(t, cli.do(http.MethodPost, "/api/v1/auth/logout", nil), http.StatusOK)
		requireStatus(t, cli.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusUnauthorized)
		requireStatus(t, a.mei.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusOK) // the console session lives on
	})
	t.Run("idle and maximum lifetime", func(t *testing.T) {
		a := newAccessEnv(t, model.RoleMember)
		cli := a.signInCLI(a.mei)
		a.clock.Advance(sessionIdleTimeout + time.Second)
		requireStatus(t, cli.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusUnauthorized)
		// The console session idled out too: sign in again there first.
		a.nextStep()
		rec := a.login(a.mei.person.Username, testPassword, a.totp(a.mei.secret, 0))
		requireStatus(t, rec, http.StatusOK)
		a.mei.cookie, a.mei.csrf = sessionCookie(rec), decodeEnvelope[model.SessionInfo](t, rec).CSRFToken
		cli = a.signInCLI(a.mei)
		for i := 0; i < int(sessionMaxLifetime/(20*time.Minute))+1; i++ {
			a.clock.Advance(20 * time.Minute)
			cli.do(http.MethodGet, "/api/v1/auth/me", nil)
		}
		requireStatus(t, cli.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusUnauthorized)
	})
	t.Run("suspended or reset", func(t *testing.T) {
		a := newAccessEnv(t, model.RoleMember)
		cli := a.signInCLI(a.mei)
		suspended := model.PersonSuspended
		requireStatus(t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
		requireStatus(t, cli.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusUnauthorized)

		jun := a.addPerson(a.sup, "jun", false)
		junCLI := a.signInCLI(jun)
		requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/supervisor/people/"+jun.person.ID+"/reset", nil), http.StatusOK)
		requireStatus(t, junCLI.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusUnauthorized)
	})
	t.Run("revoked from the console", func(t *testing.T) {
		a := newAccessEnv(t, model.RoleMember)
		first := a.signInCLI(a.mei)
		second := a.signInCLI(a.mei)
		other := a.signInCLI(a.sup)
		rec := second.do(http.MethodGet, "/api/v1/me/cli-sessions", nil)
		requireStatus(t, rec, http.StatusOK)
		list := decodeEnvelope[listData[model.CLISession]](t, rec)
		if list.Total != 2 {
			t.Fatalf("mei's command-line sessions = %+v", list.Items)
		}
		var firstID string
		for _, s := range list.Items {
			if s.ClientName != "laptop" || s.ID == "" {
				t.Fatalf("session = %+v", s)
			}
			if !s.Current {
				firstID = s.ID
			}
		}
		// Someone else's session looks missing.
		otherList := decodeEnvelope[listData[model.CLISession]](t, other.do(http.MethodGet, "/api/v1/me/cli-sessions", nil))
		requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-sessions/"+otherList.Items[0].ID+"/revoke", nil), http.StatusNotFound)
		requireStatus(t, other.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusOK)

		requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-sessions/"+firstID+"/revoke", nil), http.StatusOK)
		requireStatus(t, first.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusUnauthorized)
		requireStatus(t, second.do(http.MethodGet, "/api/v1/auth/me", nil), http.StatusOK)
		a.requireActor(a.lastEvent("cli_session.revoked"), a.mei)
		// The console session is not listed and cannot be revoked this way.
		if list := decodeEnvelope[listData[model.CLISession]](t, a.mei.do(http.MethodGet, "/api/v1/me/cli-sessions", nil)); list.Total != 1 {
			t.Fatalf("after revoking: %+v", list.Items)
		}
	})
	t.Run("a person who is no longer active cannot approve", func(t *testing.T) {
		a := newAccessEnv(t, model.RoleMember)
		start := a.startCLISignIn("laptop")
		requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-signins/"+start.UserCode+"/approve", nil), http.StatusOK)
		suspended := model.PersonSuspended
		requireStatus(t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+a.mei.person.ID, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
		if res := a.pollCLISignIn(start.DeviceCode); res.Status == model.SignInApproved || res.Token != "" {
			t.Fatalf("a suspended person's sign-in produced a session: %+v", res)
		}
	})
}

// A supervisor's command-line session reaches the supervisor routes; a
// person's does not.
func TestCLISessionRespectsTheSupervisorFlag(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	mei := a.signInCLI(a.mei)
	sup := a.signInCLI(a.sup)
	requireErrorCode(t, mei.do(http.MethodGet, "/api/v1/supervisor/people", nil), http.StatusForbidden, model.ErrCodeForbidden)
	requireStatus(t, sup.do(http.MethodGet, "/api/v1/supervisor/people", nil), http.StatusOK)
	requireStatus(t, sup.do(http.MethodGet, "/api/v1/supervisor/audit/verify", nil), http.StatusOK)
	// Actions are recorded under the person, from their command-line session.
	read := a.request(accessInput("ecs", "read"))
	requireStatus(t, sup.do(http.MethodPost, "/api/v1/supervisor/leases/"+read.ID+"/revoke", model.RevokeLeaseInput{Reason: "stop"}), http.StatusOK)
	a.requireActor(a.lastEvent("lease.revoked"), a.sup)
}

// ---- regression tests for the independent review of commit b3b8bd7 ----

// A deterministic version: the lowering commits while the other request is
// between its read and its write. With the lock, the second request reads
// the lowered value and asks for a code.
func TestSettingsRaiseAfterAConcurrentLoweringNeedsACode(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	cli := a.signInCLI(a.sup)
	high := model.DefaultPolicySettings()
	low := high
	low.MaxLeaseTTLSeconds = 1800
	a.srv.settingsMu.Lock()
	done := make(chan int, 1)
	go func() { done <- cli.do(http.MethodPut, "/api/v1/supervisor/settings", high).Code }()
	time.Sleep(50 * time.Millisecond) // the request waits for the lock
	if err := a.srv.db.SetPolicySettings(context.Background(), low); err != nil {
		t.Fatal(err)
	}
	a.srv.settingsMu.Unlock()
	if code := <-done; code != http.StatusForbidden {
		t.Fatalf("raising after the lowering without a code = %d, want 403", code)
	}
	if got, _ := a.srv.db.GetPolicySettings(context.Background()); got.MaxLeaseTTLSeconds != 1800 {
		t.Fatalf("the limit was raised to %d without a code", got.MaxLeaseTTLSeconds)
	}
}

// Lowering a role works from the command line whatever it is lowered to;
// raising one needs a code, and the decision uses the role at write time.
func TestRoleChangesDecideOnTheCurrentRole(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	cli := a.signInCLI(a.sup)
	path := "/api/v1/supervisor/accounts/" + a.providerID + "/people/" + a.mei.person.ID
	role := func() model.Role {
		b, _ := a.srv.db.GetBinding(context.Background(), a.mei.person.ID, a.providerID)
		return b.Role
	}
	requireStatus(t, cli.do(http.MethodPut, path, model.PutBindingInput{Role: model.RoleMember}), http.StatusOK)
	if role() != model.RoleMember {
		t.Fatalf("administrator → member = %s", role())
	}
	requireStatus(t, cli.do(http.MethodPut, path, model.PutBindingInput{Role: model.RoleMember}), http.StatusOK) // unchanged
	requireErrorCode(t, cli.do(http.MethodPut, path, model.PutBindingInput{Role: model.RoleAdministrator}), http.StatusForbidden, model.ErrCodeAuthenticatorCodeRequired)
	if role() != model.RoleMember {
		t.Fatal("member was raised to administrator without a code")
	}
	// The role is lowered while the request waits: it is now a raise.
	a.srv.bindingsMu.Lock()
	done := make(chan int, 1)
	go func() { done <- cli.do(http.MethodPut, path, model.PutBindingInput{Role: model.RoleMember}).Code }()
	time.Sleep(50 * time.Millisecond)
	a.bindDirect(a.mei.person.ID, model.RoleGuest)
	a.srv.bindingsMu.Unlock()
	if code := <-done; code != http.StatusForbidden || role() != model.RoleGuest {
		t.Fatalf("guest → member after a concurrent lowering: %d, role %s", code, role())
	}
	requireStatus(t, cli.withCode(http.MethodPut, path, model.PutBindingInput{Role: model.RoleAdministrator}), http.StatusOK)
	if role() != model.RoleAdministrator {
		t.Fatalf("with a code = %s", role())
	}
}

// An approval that was not collected yet ends when its approver is suspended
// or reset: the old device code gives nothing after they are active again.
func TestSuspendAndResetEndUncollectedApprovals(t *testing.T) {
	for _, how := range []string{"suspend", "reset"} {
		t.Run(how, func(t *testing.T) {
			a := newAccessEnv(t, model.RoleMember)
			cliStart := a.startCLISignIn("laptop")
			requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-signins/"+cliStart.UserCode+"/approve", nil), http.StatusOK)
			agentStart := a.startSignIn("another-agent")
			requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/signins/"+agentStart.UserCode+"/approve", nil), http.StatusOK)

			path := "/api/v1/supervisor/people/" + a.mei.person.ID
			if how == "suspend" {
				suspended, active := model.PersonSuspended, model.PersonActive
				requireStatus(t, a.sup.do(http.MethodPatch, path, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
				requireStatus(t, a.sup.do(http.MethodPatch, path, model.UpdatePersonInput{Status: &active}), http.StatusOK)
			} else {
				rec := a.sup.do(http.MethodPost, path+"/reset", nil)
				requireStatus(t, rec, http.StatusOK)
				a.completeSetup(decodeEnvelope[model.PersonWithSetupCode](t, rec).SetupCode)
			}
			if res := a.pollCLISignIn(cliStart.DeviceCode); res.Status == model.SignInApproved || res.Token != "" {
				t.Fatalf("the command-line approval survived the %s: %+v", how, res)
			}
			if res := a.pollSignIn(agentStart.DeviceCode); res.Status == model.SignInApproved || res.Token != "" {
				t.Fatalf("the agent approval survived the %s: %+v", how, res)
			}
		})
	}
}

// An approval given by mistake can be withdrawn until csg collects it, by
// the person who gave it only.
func TestApprovedSignInCanBeWithdrawnBeforePickup(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	start := a.startCLISignIn("laptop")
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-signins/"+start.UserCode+"/approve", nil), http.StatusOK)
	// Someone else cannot withdraw it, and a command-line session cannot
	// withdraw another person's.
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/me/cli-signins/"+start.UserCode+"/cancel", nil), http.StatusNotFound)
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-signins/"+start.UserCode+"/cancel", nil), http.StatusOK)
	if res := a.pollCLISignIn(start.DeviceCode); res.Status != model.SignInDenied || res.Token != "" {
		t.Fatalf("after withdrawing: %+v", res)
	}
	a.requireActor(a.lastEvent("cli_signin.cancelled"), a.mei)
	// Once collected it is a session: withdrawing is too late, ending it is
	// done in Settings.
	a.signInCLI(a.mei) // a collected sign-in is a session, listed in Settings
	second := a.startCLISignIn("laptop")
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-signins/"+second.UserCode+"/approve", nil), http.StatusOK)
	a.pollCLISignIn(second.DeviceCode)
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-signins/"+second.UserCode+"/cancel", nil), http.StatusNotFound)
}

// The command-line sign-in code is masked wherever the server writes a
// path: the access log and the audit log.
func TestCLISignInCodeIsMaskedInLogs(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	cli := a.signInCLI(a.mei)
	start := a.startCLISignIn("laptop")
	a.mei.do(http.MethodGet, "/api/v1/me/cli-signins/"+start.UserCode, nil)
	cli.do(http.MethodPost, "/api/v1/me/cli-signins/"+start.UserCode+"/approve", nil) // refused: console only
	if strings.Contains(a.logs.String(), start.UserCode) {
		t.Fatal("the access log contains the sign-in code")
	}
	raw, _ := json.Marshal(a.listAudit(""))
	if strings.Contains(string(raw), start.UserCode) {
		t.Fatal("the audit log contains the sign-in code")
	}
	if got := logPath("/api/v1/me/cli-signins/ABC-DEFG/approve"); got != "/api/v1/me/cli-signins/***/approve" {
		t.Fatalf("logPath = %q", got)
	}
}

// Giving a provider its first cloud account makes a new account usable: it
// is console-only like adding one.
func TestConnectingAProviderIsConsoleOnly(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	rec := a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts", newMockAccount("second", "6543210987654321"))
	requireStatus(t, rec, http.StatusCreated)
	second := decodeEnvelope[model.Provider](t, rec)
	if _, err := a.srv.db.SQL().Exec(`UPDATE providers SET cloud_account_id = '', role_arn = 'not-a-role' WHERE id = ?`, second.ID); err != nil {
		t.Fatal(err)
	}
	cli := a.signInCLI(a.sup)
	arn := "acs:ram::7777777777777777:role/cloud-safeguard"
	requireErrorCode(t, cli.withCode(http.MethodPatch, "/api/v1/supervisor/accounts/"+second.ID, model.UpdateProviderInput{RoleARN: &arn}),
		http.StatusForbidden, model.ErrCodeConsoleOnly)
	if got, _ := a.srv.db.GetProvider(context.Background(), second.ID); got.CloudAccountID != "" {
		t.Fatal("a command-line session connected a provider")
	}
	requireStatus(t, a.sup.do(http.MethodPatch, "/api/v1/supervisor/accounts/"+second.ID, model.UpdateProviderInput{RoleARN: &arn}), http.StatusOK)
}

// Adopting a provider removes its roles; a role change that read the role
// before the adoption must not then write a raise without a code.
func TestAdoptionAndARoleChangeAreSerialized(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	rec := a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts", newMockAccount("second", "6543210987654321"))
	requireStatus(t, rec, http.StatusCreated)
	second := decodeEnvelope[model.Provider](t, rec)
	// As an old upgrade leaves it: no cloud account, with a role on it.
	a.bindDirect(a.mei.person.ID, model.RoleAdministrator) // on the demo account, for the request below
	if _, err := a.srv.db.SQL().Exec(`INSERT INTO role_bindings(person_id, provider_id, role, created_by, created_at, updated_at)
		VALUES(?, ?, 'administrator', '', 0, 0)`, a.mei.person.ID, second.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.srv.db.SQL().Exec(`UPDATE providers SET cloud_account_id = '', role_arn = 'not-a-role' WHERE id = ?`, second.ID); err != nil {
		t.Fatal(err)
	}
	cli := a.signInCLI(a.sup)
	binding := "/api/v1/supervisor/accounts/" + second.ID + "/people/" + a.mei.person.ID
	arn := "acs:ram::7777777777777777:role/cloud-safeguard"

	// The adoption holds the role lock: a role change waits for it, then
	// sees no role and asks for a code for member.
	a.srv.bindingsMu.Lock()
	adopted := make(chan int, 1)
	changed := make(chan int, 1)
	go func() {
		adopted <- a.sup.do(http.MethodPatch, "/api/v1/supervisor/accounts/"+second.ID, model.UpdateProviderInput{RoleARN: &arn}).Code
	}()
	time.Sleep(50 * time.Millisecond)
	a.srv.bindingsMu.Unlock()
	if code := <-adopted; code != http.StatusOK {
		t.Fatalf("adoption = %d", code)
	}
	go func() { changed <- cli.do(http.MethodPut, binding, model.PutBindingInput{Role: model.RoleMember}).Code }()
	if code := <-changed; code != http.StatusForbidden {
		t.Fatalf("member after the adoption removed the role, without a code = %d, want 403", code)
	}
	if _, err := a.srv.db.GetBinding(context.Background(), a.mei.person.ID, second.ID); err == nil {
		t.Fatal("a role was written without a code after the adoption")
	}
	// The handler holds bindingsMu while it adopts: prove the lock is taken.
	other := "acs:ram::8888888888888888:role/cloud-safeguard"
	if _, err := a.srv.db.SQL().Exec(`UPDATE providers SET cloud_account_id = '', role_arn = 'x' WHERE id = ?`, second.ID); err != nil {
		t.Fatal(err)
	}
	a.srv.bindingsMu.Lock()
	go func() {
		adopted <- a.sup.do(http.MethodPatch, "/api/v1/supervisor/accounts/"+second.ID, model.UpdateProviderInput{RoleARN: &other}).Code
	}()
	select {
	case code := <-adopted:
		a.srv.bindingsMu.Unlock()
		t.Fatalf("the adoption did not wait for the role lock (%d)", code)
	case <-time.After(100 * time.Millisecond):
	}
	a.srv.bindingsMu.Unlock()
	if code := <-adopted; code != http.StatusOK {
		t.Fatalf("second adoption = %d", code)
	}
}

// Connecting a provider from the command line is refused as console-only
// before any code is asked for, so no code is spent on it.
func TestAdoptionFromTheCommandLineIsRefusedBeforeTheCode(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	rec := a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts", newMockAccount("second", "6543210987654321"))
	requireStatus(t, rec, http.StatusCreated)
	second := decodeEnvelope[model.Provider](t, rec)
	if _, err := a.srv.db.SQL().Exec(`UPDATE providers SET cloud_account_id = '' WHERE id = ?`, second.ID); err != nil {
		t.Fatal(err)
	}
	cli := a.signInCLI(a.sup)
	arn := "acs:ram::7777777777777777:role/cloud-safeguard"
	requireErrorCode(t, cli.do(http.MethodPatch, "/api/v1/supervisor/accounts/"+second.ID, model.UpdateProviderInput{RoleARN: &arn}),
		http.StatusForbidden, model.ErrCodeConsoleOnly)
	requireErrorCode(t, cli.withCode(http.MethodPatch, "/api/v1/supervisor/accounts/"+second.ID, model.UpdateProviderInput{RoleARN: &arn}),
		http.StatusForbidden, model.ErrCodeConsoleOnly)
	if len(a.listAudit("auth.step_up")) != 0 {
		t.Fatal("a code was spent on a console-only request")
	}
}

// Giving a role to someone with none: guest is free, more needs a code.
func TestRoleFromNothing(t *testing.T) {
	a := newAccessEnv(t, "")
	cli := a.signInCLI(a.sup)
	path := "/api/v1/supervisor/accounts/" + a.providerID + "/people/" + a.mei.person.ID
	requireErrorCode(t, cli.do(http.MethodPut, path, model.PutBindingInput{Role: model.RoleMember}), http.StatusForbidden, model.ErrCodeAuthenticatorCodeRequired)
	if _, err := a.srv.db.GetBinding(context.Background(), a.mei.person.ID, a.providerID); err == nil {
		t.Fatal("member was given without a code")
	}
	requireStatus(t, cli.do(http.MethodPut, path, model.PutBindingInput{Role: model.RoleGuest}), http.StatusOK)
}

// Local recovery ends the approvals its person gave that were not collected.
func TestRecoveryEndsUncollectedApprovals(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	start := a.startCLISignIn("laptop")
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/me/cli-signins/"+start.UserCode+"/approve", nil), http.StatusOK)
	if _, err := RecoverSupervisor(context.Background(), RecoverOptions{DataDir: a.dir, Username: a.sup.person.Username}); err != nil {
		t.Fatal(err)
	}
	if res := a.pollCLISignIn(start.DeviceCode); res.Status == model.SignInApproved || res.Token != "" {
		t.Fatalf("the approval survived local recovery: %+v", res)
	}
}

// The approver can see an approval that was not collected (to withdraw it);
// nobody else can.
func TestApproverSeesAnUncollectedApproval(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	start := a.startCLISignIn("laptop")
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/cli-signins/"+start.UserCode+"/approve", nil), http.StatusOK)
	rec := a.mei.do(http.MethodGet, "/api/v1/me/cli-signins/"+start.UserCode, nil)
	requireStatus(t, rec, http.StatusOK)
	if v := decodeEnvelope[model.CLISignIn](t, rec); v.Status != model.SignInApproved {
		t.Fatalf("approver sees %+v", v)
	}
	requireStatus(t, a.sup.do(http.MethodGet, "/api/v1/me/cli-signins/"+start.UserCode, nil), http.StatusNotFound)
	a.pollCLISignIn(start.DeviceCode) // collected
	requireStatus(t, a.mei.do(http.MethodGet, "/api/v1/me/cli-signins/"+start.UserCode, nil), http.StatusNotFound)
}
