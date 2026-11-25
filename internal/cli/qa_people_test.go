package cli

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/server"
)

// TestQASupervisorRecover proves QA_BRIEF B / CONTRACT §17.1: the local
// `csg supervisor recover --username NAME` command issues a new setup code
// and ends the person's old sessions.
func TestQASupervisorRecover(t *testing.T) {
	dir := t.TempDir()
	res, err := server.Init(context.Background(), server.InitOptions{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{
		DataDir:        dir,
		PasswordParams: &authn.Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32},
	})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { hs.Close(); srv.Close() })

	jar, _ := cookiejar.New(nil)
	e := &e2e{t: t, url: hs.URL, person: &http.Client{Jar: jar}}
	e.setup(res.Supervisor.SetupCode)
	e.call(http.MethodGet, "/api/v1/auth/me", nil, nil, http.StatusOK)

	ta := newTestApp(t)
	if code := ta.run("supervisor", "recover", "--username", "admin", "--data-dir", dir); code != ExitOK {
		t.Fatalf("supervisor recover exit %d", code)
	}
	out := ta.out()
	if !strings.Contains(out, "Supervisor restored") || !strings.Contains(out, "admin") || !strings.Contains(out, "Setup code") {
		t.Fatal("recover output missing expected lines (Supervisor restored / admin / Setup code)")
	}
	setupCode := ""
	for _, line := range strings.Split(out, "\n") {
		if i := strings.LastIndex(line, ": "); strings.HasPrefix(line, "Setup code") && i >= 0 {
			setupCode = strings.TrimSpace(line[i+2:])
		}
	}
	if setupCode == "" || len(setupCode) < 8 {
		t.Fatal("could not parse setup code from recover output")
	}

	e.call(http.MethodGet, "/api/v1/auth/me", nil, nil, http.StatusUnauthorized)

	jar, _ = cookiejar.New(nil)
	e.person, e.csrf = &http.Client{Jar: jar}, ""
	e.setup(setupCode)
	e.call(http.MethodGet, "/api/v1/supervisor/people", nil, nil, http.StatusOK)
}
