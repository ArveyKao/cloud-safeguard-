package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/server"
)

// The person commands end to end against a real control plane (CONTRACT
// §17.9): the supervisor signs csg in by approving a code in the console,
// works from the command line, and runs into the guards.

type personE2E struct {
	*e2e
	secret string // the supervisor's TOTP secret
}

func newPersonE2E(t *testing.T) *personE2E {
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
	e := &personE2E{e2e: &e2e{t: t, url: hs.URL, provider: res.ProviderIDs[0], person: &http.Client{Jar: jar}}}
	var begin model.SetupBeginResult
	e.call(http.MethodPost, "/api/v1/auth/setup/begin", model.SetupBeginInput{SetupCode: res.Supervisor.SetupCode, Password: "an e2e test passphrase"}, &begin, http.StatusOK)
	code, _ := authn.TOTPCode(begin.TOTPSecret, authn.TOTPStep(time.Now()))
	var info model.SessionInfo
	e.call(http.MethodPost, "/api/v1/auth/setup/finish", model.SetupFinishInput{SetupCode: res.Supervisor.SetupCode, TOTPCode: code}, &info, http.StatusOK)
	e.csrf, e.personID, e.secret = info.CSRFToken, info.Person.ID, begin.TOTPSecret
	return e
}

// personApp is csg signed in as the supervisor through the console approval.
func (e *personE2E) personApp() *testApp {
	e.t.Helper()
	ta := newTestApp(e.t)
	var deviceCode string
	ta.app.afterSignInStart = func(start model.AgentSignInStart) {
		deviceCode = start.DeviceCode
		e.call(http.MethodPost, "/api/v1/me/cli-signins/"+start.UserCode+"/approve", nil, nil, http.StatusOK)
	}
	if code := ta.run("person", "login", "--server", e.url, "--name", "e2e-laptop"); code != ExitOK {
		e.t.Fatalf("person login exit %d: %s", code, ta.errOut())
	}
	printed := ta.out() + ta.errOut()
	if strings.Contains(printed, personSessionPrefix) || deviceCode == "" || strings.Contains(printed, deviceCode) {
		e.t.Fatal("person login printed the session token or the device code")
	}
	ta.stdout.Reset()
	ta.stderr.Reset()
	return ta
}

func TestE2EPersonSignInAndGuards(t *testing.T) {
	old := pollSleep
	pollSleep = func(time.Duration) {}
	t.Cleanup(func() { pollSleep = old })
	e := newPersonE2E(t)
	ta := e.personApp()

	// The session is in its own 0600 file; the agent's config is untouched.
	path, _ := ta.app.personConfigPath()
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("person.json: %v %v", st, err)
	}
	if agentCfg, _ := ta.app.configPath(); fileExists(agentCfg) {
		t.Fatal("person login wrote the agent config")
	}
	raw, _ := os.ReadFile(path)
	var saved personConfig
	if json.Unmarshal(raw, &saved) != nil || !saved.Supervisor || saved.Username != "admin" || !strings.HasPrefix(saved.Token, personSessionPrefix) {
		t.Fatalf("person.json = %+v", saved)
	}

	if code := ta.run("person", "whoami"); code != ExitOK || !strings.Contains(ta.out(), "admin (supervisor)") {
		t.Fatalf("whoami exit %d: %s %s", code, ta.out(), ta.errOut())
	}
	ta.stdout.Reset()

	// Reading works.
	for _, args := range [][]string{
		{"me", "accounts"}, {"me", "requests"}, {"me", "agents"}, {"me", "sessions"},
		{"supervisor", "people"}, {"supervisor", "accounts"}, {"supervisor", "roles"},
		{"supervisor", "settings"}, {"supervisor", "audit", "--limit", "5"}, {"supervisor", "audit", "verify"},
		{"supervisor", "requests"},
	} {
		if code := ta.run(args...); code != ExitOK {
			t.Fatalf("%v exit %d: %s", args, code, ta.errOut())
		}
	}
	if !strings.Contains(ta.out(), "audit chain verified") || !strings.Contains(ta.out(), "1234567890123456") {
		t.Fatalf("output: %s", ta.out())
	}

	// Raising access without a code: refused, and nothing is created.
	ta.stderr.Reset()
	if code := ta.run("supervisor", "people", "add", "jun"); code != ExitAuth || !strings.Contains(ta.errOut(), "--code") {
		t.Fatalf("people add without a code: exit %d, %s", code, ta.errOut())
	}
	var people model.ListResponse[model.Person]
	e.call(http.MethodGet, "/api/v1/supervisor/people", nil, &people, http.StatusOK)
	if people.Total != 1 {
		t.Fatalf("a person was added without a code: %d people", people.Total)
	}
	// With a fresh code: added, and the setup code is printed for handing over.
	next, _ := authn.TOTPCode(e.secret, authn.TOTPStep(time.Now())+1)
	ta.stdout.Reset()
	if code := ta.run("supervisor", "people", "add", "jun", "--code", next); code != ExitOK || !strings.Contains(ta.out(), "Setup code") {
		t.Fatalf("people add with a code: exit %d, %s %s", code, ta.out(), ta.errOut())
	}
	// The same code again is refused.
	ta.stderr.Reset()
	if code := ta.run("supervisor", "people", "add", "kai", "--code", next); code == ExitOK {
		t.Fatal("a code was accepted twice")
	}

	// Lowering needs no code.
	for _, args := range [][]string{
		{"supervisor", "roles", "set", "1234567890123456", "jun", "guest"},
		{"supervisor", "roles", "remove", "demo-aliyun", "jun"},
		{"supervisor", "people", "suspend", "jun"},
		{"supervisor", "accounts", "rename", "demo-aliyun", "demo"},
		{"supervisor", "accounts", "test", "demo"},
		{"me", "mode", "demo", "read"},
	} {
		ta.stderr.Reset()
		if code := ta.run(args...); code != ExitOK {
			t.Fatalf("%v exit %d: %s", args, code, ta.errOut())
		}
	}
	// Raising without a code, again refused.
	for _, args := range [][]string{
		{"supervisor", "roles", "set", "1234567890123456", "jun", "member"},
		{"supervisor", "people", "activate", "jun"},
		{"supervisor", "settings", "set", "--requests-per-minute", "60"},
		{"me", "mode", "1234567890123456", "write"},
	} {
		ta.stderr.Reset()
		if code := ta.run(args...); code != ExitAuth {
			t.Fatalf("%v without a code: exit %d, %s", args, code, ta.errOut())
		}
	}

	// Console only, whatever the command line tries.
	for _, args := range [][]string{
		{"supervisor", "accounts", "add"},
		{"me", "approve", "lea_x"},
		{"supervisor", "requests", "approve", "lea_x"},
	} {
		ta.stderr.Reset()
		if code := ta.run(args...); code != ExitUsage || !strings.Contains(ta.errOut(), "console") && !strings.Contains(ta.errOut(), "owner") {
			t.Fatalf("%v: exit %d, %s", args, code, ta.errOut())
		}
	}

	// Sign out: the session ends on the server and the file is gone.
	if code := ta.run("person", "logout"); code != ExitOK {
		t.Fatalf("logout exit %d: %s", code, ta.errOut())
	}
	if fileExists(path) {
		t.Fatal("person.json is still there after logout")
	}
	ta.stderr.Reset()
	if code := ta.run("person", "whoami"); code != ExitAuth {
		t.Fatalf("whoami after logout: exit %d", code)
	}
	// The token no longer works on the server either.
	req, _ := http.NewRequest(http.MethodGet, e.url+"/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+saved.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the token after logout: %d", resp.StatusCode)
	}
}

// Agent and person sign-ins live side by side and never cross: agent
// commands do not use the person's session, person commands do not use the
// agent's token.
func TestE2EAgentAndPersonSessionsStayApart(t *testing.T) {
	old := pollSleep
	pollSleep = func(time.Duration) {}
	t.Cleanup(func() { pollSleep = old })
	e := newPersonE2E(t)
	ta := e.personApp()
	// Sign an agent in on the same "machine" (home directory).
	ta.app.afterSignInStart = func(start model.AgentSignInStart) {
		e.call(http.MethodPost, "/api/v1/me/signins/"+start.UserCode+"/approve", nil, nil, http.StatusOK)
	}
	if code := ta.run("login", "--server", e.url, "--name", "e2e-agent"); code != ExitOK {
		t.Fatalf("agent login exit %d: %s", code, ta.errOut())
	}
	agentCfg := ta.app.loadFileConfig()
	person, _ := ta.app.loadPersonConfig()
	if agentCfg.Token == "" || person.Token == "" || agentCfg.Token == person.Token {
		t.Fatal("the two sign-ins share a token")
	}
	ta.stdout.Reset()
	if code := ta.run("whoami"); code != ExitOK || !strings.Contains(ta.out(), "e2e-agent") {
		t.Fatalf("agent whoami: %d %s %s", code, ta.out(), ta.errOut())
	}
	ta.stdout.Reset()
	if code := ta.run("person", "whoami"); code != ExitOK || !strings.Contains(ta.out(), "admin") {
		t.Fatalf("person whoami: %d %s %s", code, ta.out(), ta.errOut())
	}
	// Removing the person's session does not touch the agent's.
	ta.app.removePersonConfig()
	ta.stderr.Reset()
	if code := ta.run("me", "requests"); code != ExitAuth {
		t.Fatalf("me requests with only an agent token: exit %d", code)
	}
	ta.stdout.Reset()
	if code := ta.run("accounts"); code != ExitOK {
		t.Fatalf("agent accounts after the person signed out: %d %s", code, ta.errOut())
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(filepath.Clean(path))
	return err == nil
}

// /dev/null is a character device but not a terminal: csg must not prompt
// on it.
func TestDevNullIsNotATerminal(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if isTerminal(f) {
		t.Fatal("/dev/null is taken for a terminal")
	}
	ta := newTestApp(t)
	ta.app.Stdin = f
	if ta.app.stdinIsTerminal() {
		t.Fatal("stdinIsTerminal is true for /dev/null")
	}
}

// Equal values for two settings flags both apply; a supervisor flag saved
// at sign-in that is out of date does not block supervisor commands (the
// server decides).
func TestE2ESupervisorSettingsAndStaleFlag(t *testing.T) {
	old := pollSleep
	pollSleep = func(time.Duration) {}
	t.Cleanup(func() { pollSleep = old })
	e := newPersonE2E(t)
	ta := e.personApp()
	// Both lowered to the same value: no code needed, both written.
	if code := ta.run("supervisor", "settings", "set", "--max-credentials", "2", "--requests-per-minute", "2"); code != ExitOK {
		t.Fatalf("settings set: exit %d, %s", code, ta.errOut())
	}
	var s model.PolicySettings
	e.call(http.MethodGet, "/api/v1/supervisor/settings", nil, &s, http.StatusOK)
	if s.MaxConcurrentLeasesPerAgent != 2 || s.LeasesPerMinutePerAgent != 2 {
		t.Fatalf("settings = %+v, want both 2", s)
	}
	// The saved flag says "not a supervisor"; the server still lets them in.
	cfg, _ := ta.app.loadPersonConfig()
	cfg.Supervisor = false
	if _, err := ta.app.savePersonConfig(cfg); err != nil {
		t.Fatal(err)
	}
	ta.stdout.Reset()
	if code := ta.run("supervisor", "people"); code != ExitOK || !strings.Contains(ta.out(), "admin") {
		t.Fatalf("supervisor people with a stale flag: exit %d, %s", code, ta.errOut())
	}
}
