package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Regression tests for the independent review of commit 104d95e.

const reviewLeaseID = "lea_0123456789abcdef0123456789abcdef"

// fakeAgentAPI is a configurable fake of the agent API.
type fakeAgentAPI struct {
	mu            sync.Mutex
	envelope      model.CredentialEnvelope
	credentialErr bool
	revokeErr     bool
	credCalls     int
	revokeCalls   int
	revokeReasons []string
	authHeaders   []string
	signIn        model.AgentSignInStart
	signInResult  model.AgentSignInResult
}

func (f *fakeAgentAPI) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.authHeaders = append(f.authHeaders, r.Header.Get("Authorization"))
		switch {
		case r.URL.Path == "/api/v1/agent-signin/start":
			writeEnvelope(w, http.StatusCreated, f.signIn)
		case r.URL.Path == "/api/v1/agent-signin/token":
			writeEnvelope(w, http.StatusOK, f.signInResult)
		case r.URL.Path == "/api/v1/agent/leases" && r.Method == http.MethodPost:
			lease := testLease(model.LeaseActive)
			lease.ID = reviewLeaseID
			writeEnvelope(w, http.StatusCreated, lease)
		case strings.HasSuffix(r.URL.Path, "/credential"):
			f.credCalls++
			if f.credentialErr {
				writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "boom")
				return
			}
			writeEnvelope(w, http.StatusOK, f.envelope)
		case strings.HasSuffix(r.URL.Path, "/revoke"):
			f.revokeCalls++
			var in model.RevokeLeaseInput
			_ = json.NewDecoder(r.Body).Decode(&in)
			f.revokeReasons = append(f.revokeReasons, in.Reason)
			if f.revokeErr {
				writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "boom")
				return
			}
			writeEnvelope(w, http.StatusOK, testLease(model.LeaseRevoked))
		default:
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected "+r.URL.Path)
		}
	})
}

func maliciousEnvelope() model.CredentialEnvelope {
	env := testCredentialEnvelope()
	env.Credential.LeaseID = reviewLeaseID
	env.Credential.ExpiresAt = time.Now().Add(time.Hour)
	env.Env = append(env.Env,
		model.EnvVar{Name: "X; touch /tmp/csg-pwned; Y", Value: "v"},
		model.EnvVar{Name: "LD_PRELOAD", Value: "/tmp/evil.so"},
		model.EnvVar{Name: "BASH_ENV", Value: "/tmp/evil"})
	return env
}

func newFakeApp(t *testing.T, f *fakeAgentAPI) (*testApp, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)
	return ta, srv
}

// A server cannot put shell code or a dangerous variable into the
// credential file, --export or the child environment.
func TestCredentialNamesFromTheServerAreFiltered(t *testing.T) {
	f := &fakeAgentAPI{envelope: maliciousEnvelope()}
	ta, _ := newFakeApp(t, f)

	ta.app.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_credential","arguments":{"request_id":"` + reviewLeaseID + `"}}}` + "\n")
	if code := ta.run("mcp"); code != ExitOK {
		t.Fatalf("mcp exit %d: %s", code, ta.errOut())
	}
	path, _ := ta.app.credentialPath(reviewLeaseID)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"touch", "LD_PRELOAD", "BASH_ENV"} {
		if strings.Contains(string(content), bad) {
			t.Fatalf("credential file contains %s:\n%s", bad, content)
		}
	}
	// The file is safe to source.
	out, err := exec.Command("sh", "-c", ". "+shellQuote(path)+" && printf %s \"$ALIBABA_CLOUD_ACCESS_KEY_ID\"").CombinedOutput()
	if err != nil || string(out) != "LTAI1234567890ABCD" {
		t.Fatalf("sourcing the file: %q %v", out, err)
	}

	ta.stdout.Reset()
	ta.run("credential", "--lease", reviewLeaseID, "--export")
	if strings.Contains(ta.out(), "touch") || strings.Contains(ta.out(), "LD_PRELOAD") || !strings.Contains(ta.out(), "export ALIBABA_CLOUD_ACCESS_KEY_ID=") {
		t.Fatalf("--export output = %s", ta.out())
	}

	// The command run by csg exec sees neither, nor the CLI's own token.
	t.Setenv("CSG_TOKEN", agentTokenA)
	ta.stdout.Reset()
	code := ta.run("exec", "--capability", "aliyun.cloud.read", "--", "sh", "-c", `printf '[%s][%s][%s]' "$LD_PRELOAD" "$BASH_ENV" "$CSG_TOKEN"`)
	if code != ExitOK || ta.out() != "[][][]" {
		t.Fatalf("child env exit %d: %q", code, ta.out())
	}
}

// An interrupted csg exec passes the signal on and revokes, even with --keep.
func TestExecRevokesWhenInterrupted(t *testing.T) {
	f := &fakeAgentAPI{envelope: maliciousEnvelope()}
	ta, _ := newFakeApp(t, f)
	sigs := make(chan os.Signal, 1)
	old := newSignalChan
	newSignalChan = func() (<-chan os.Signal, func()) { return sigs, func() {} }
	t.Cleanup(func() { newSignalChan = old })
	ta.app.afterChildStart = func() { sigs <- syscall.SIGINT }

	start := time.Now()
	code := ta.run("exec", "--capability", "aliyun.cloud.read", "--keep", "--", "sleep", "20")
	if code != 130 {
		t.Fatalf("exit = %d, want 130: %s", code, ta.errOut())
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("the child was not interrupted")
	}
	if f.revokeCalls != 1 || f.revokeReasons[0] != "csg exec was interrupted" {
		t.Fatalf("revokes = %d %v", f.revokeCalls, f.revokeReasons)
	}
}

// Every way csg exec gives up revokes, and a failed revoke is reported.
func TestExecRevokesOnEveryFailure(t *testing.T) {
	f := &fakeAgentAPI{envelope: maliciousEnvelope(), revokeErr: true}
	ta, _ := newFakeApp(t, f)
	if code := ta.run("exec", "--capability", "aliyun.cloud.read", "--", "/no/such/command"); code == ExitOK {
		t.Fatal("a missing command succeeded")
	}
	if f.revokeCalls != 1 || !strings.Contains(ta.errOut(), "warning: could not revoke") {
		t.Fatalf("start failure: revokes %d, stderr %s", f.revokeCalls, ta.errOut())
	}

	f2 := &fakeAgentAPI{credentialErr: true}
	ta2, _ := newFakeApp(t, f2)
	if code := ta2.run("exec", "--capability", "aliyun.cloud.read", "--", "true"); code == ExitOK {
		t.Fatal("a failed credential fetch succeeded")
	}
	if f2.revokeCalls != 1 || f2.revokeReasons[0] != "csg exec could not fetch the credential" {
		t.Fatalf("fetch failure: revokes %d %v", f2.revokeCalls, f2.revokeReasons)
	}
}

// One oversized message is refused without ending the session; batches are
// answered; a notification never acts.
func TestMCPFramingAndNotifications(t *testing.T) {
	f := &fakeAgentAPI{envelope: maliciousEnvelope()}
	ta, _ := newFakeApp(t, f)
	huge := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", 2<<20) + `"}}`
	lines := []string{
		huge,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`[{"jsonrpc":"2.0","id":3,"method":"ping"},{"jsonrpc":"2.0","method":"ping"},{"jsonrpc":"2.0","id":4,"method":"ping"}]`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_credential","arguments":{"request_id":"` + reviewLeaseID + `"}}}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"revoke","arguments":{"request_id":"` + reviewLeaseID + `"}}}`,
		`[]`,
	}
	ta.app.Stdin = strings.NewReader(strings.Join(lines, "\n") + "\n")
	if code := ta.run("mcp"); code != ExitOK {
		t.Fatalf("mcp exit %d: %s", code, ta.errOut())
	}
	out := strings.Split(strings.TrimSpace(ta.out()), "\n")
	if len(out) != 4 {
		t.Fatalf("replies = %d: %s", len(out), ta.out())
	}
	if !strings.Contains(out[0], `"code":-32600`) || !strings.Contains(out[1], `"id":2`) {
		t.Fatalf("oversized message handling: %s / %s", out[0], out[1])
	}
	var batch []map[string]any
	if err := json.Unmarshal([]byte(out[2]), &batch); err != nil || len(batch) != 2 {
		t.Fatalf("batch reply = %s", out[2])
	}
	if !strings.Contains(out[3], `"code":-32600`) {
		t.Fatalf("empty batch reply = %s", out[3])
	}
	if f.credCalls != 0 || f.revokeCalls != 0 {
		t.Fatalf("notifications acted: %d credential fetches, %d revokes", f.credCalls, f.revokeCalls)
	}
}

// Expired credential files are deleted; csg revoke deletes the file too.
func TestCredentialFilesAreCleanedUp(t *testing.T) {
	f := &fakeAgentAPI{envelope: maliciousEnvelope()}
	ta, _ := newFakeApp(t, f)
	write := func(id string, expires time.Time) string {
		t.Helper()
		env := maliciousEnvelope()
		env.Credential.ExpiresAt = expires
		path, err := ta.app.writeCredentialFile(id, &env, "http://x")
		if err != nil {
			t.Fatal(err)
		}
		return path
	}
	expired := write("lea_00000000000000000000000000000001", time.Now().Add(-time.Minute))
	live := write("lea_00000000000000000000000000000002", time.Now().Add(time.Hour))
	ta.app.Stdin = strings.NewReader("")
	ta.run("mcp")
	if _, err := os.Stat(expired); !os.IsNotExist(err) {
		t.Fatal("an expired credential file was kept")
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatal("a live credential file was deleted")
	}

	fileForRevoke := write(reviewLeaseID, time.Now().Add(time.Hour))
	if code := ta.run("revoke", "--lease", reviewLeaseID); code != ExitOK {
		t.Fatalf("revoke exit %d: %s", code, ta.errOut())
	}
	if _, err := os.Stat(fileForRevoke); !os.IsNotExist(err) {
		t.Fatal("csg revoke left the credential file")
	}
}

// The sign-in sends no saved token, shows server text safely, bounds its
// polling, accepts only an agent token and saves it with mode 0600.
func TestSignInHardening(t *testing.T) {
	f := &fakeAgentAPI{
		signIn: model.AgentSignInStart{DeviceCode: "device-secret-xyz", UserCode: "ABC-\x1b[31mDEF",
			VerificationURL: "https://evil.example/\x1b]52;c;Zm9v\x07approve", ExpiresAt: time.Now().Add(time.Minute), IntervalSeconds: 86400},
		signInResult: model.AgentSignInResult{Status: model.SignInPending},
	}
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	ta := newTestApp(t)
	// A saved admin token for this server must not be sent, and must be
	// noted when replaced.
	if _, err := ta.app.saveFileConfig(fileConfig{Server: srv.URL, Token: adminTokenA, Kind: "admin"}); err != nil {
		t.Fatal(err)
	}
	cfgPath, _ := ta.app.configPath()
	_ = os.Chmod(cfgPath, 0o644)

	var slept []time.Duration
	old := pollSleep
	pollSleep = func(d time.Duration) {
		slept = append(slept, d)
		f.mu.Lock()
		f.signInResult = model.AgentSignInResult{Status: model.SignInApproved,
			Agent: &model.Agent{ID: "agt_1", Name: "a"}, Token: "not-an-agent-token"}
		f.mu.Unlock()
	}
	t.Cleanup(func() { pollSleep = old })

	code := ta.run("login", "--server", srv.URL, "--name", "review-agent")
	if code == ExitOK {
		t.Fatal("a non-agent token was accepted")
	}
	if len(slept) != 1 || slept[0] > time.Minute {
		t.Fatalf("poll waits = %v", slept)
	}
	for _, h := range f.authHeaders {
		if h != "" {
			t.Fatalf("sign-in sent Authorization %q", h)
		}
	}
	shown := ta.errOut()
	if strings.Contains(shown, "\x1b") || strings.Contains(shown, "\x07") || strings.Contains(shown, "device-secret-xyz") {
		t.Fatalf("unsafe output: %q", shown)
	}
	if !strings.Contains(shown, "is not on "+srv.URL) {
		t.Fatalf("no warning about the link: %q", shown)
	}
	if cfg := ta.app.loadFileConfig(); cfg.Token != adminTokenA {
		t.Fatal("a refused sign-in replaced the saved token")
	}

	// Approved with an agent token: saved with 0600, replacing the 0644 file.
	f.signInResult = model.AgentSignInResult{Status: model.SignInApproved,
		Agent: &model.Agent{ID: "agt_1", Name: "a"}, Token: agentTokenA}
	ta.stderr.Reset()
	if code := ta.run("login", "--server", srv.URL, "--name", "review-agent"); code != ExitOK {
		t.Fatalf("login exit %d: %s", code, ta.errOut())
	}
	if st, _ := os.Stat(cfgPath); st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode = %v", st.Mode().Perm())
	}
	if !strings.Contains(ta.errOut(), "replacing the saved an admin token") {
		t.Fatalf("no note about replacing the admin token: %q", ta.errOut())
	}
}

// A symlink at the config path is replaced, not followed.
func TestConfigSaveDoesNotFollowSymlinks(t *testing.T) {
	ta := newTestApp(t)
	cfgPath, _ := ta.app.configPath()
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, cfgPath); err != nil {
		t.Fatal(err)
	}
	if _, err := ta.app.saveFileConfig(fileConfig{Server: "http://x", Token: agentTokenA, Kind: "agent"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatal("the symlink target was overwritten")
	}
	if st, err := os.Lstat(cfgPath); err != nil || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != 0o600 {
		t.Fatalf("config = %v %v", st, err)
	}
}

func TestDisplayHelpers(t *testing.T) {
	if got := displayString("a\x1b[2Jb\x9bc\nd"); got != "a[2Jbcd" {
		t.Fatalf("displayString = %q", got)
	}
	for link, want := range map[string]bool{
		"http://127.0.0.1:8787/?signin=X": true, "https://127.0.0.1:8787/": false,
		"http://127.0.0.1:9999/": false, "http://evil.example/": false, "javascript:alert(1)": false,
	} {
		if got := sameOriginURL(link, "http://127.0.0.1:8787"); got != want {
			t.Errorf("sameOriginURL(%q) = %v", link, got)
		}
	}
	_ = fmt.Sprint()
}
