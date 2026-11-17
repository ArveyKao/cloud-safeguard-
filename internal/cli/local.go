package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/server"
)

// defaultDataDir returns the data directory default: $CSG_DATA_DIR or ./data.
func (a *App) defaultDataDir() string {
	if env := strings.TrimSpace(a.Getenv("CSG_DATA_DIR")); env != "" {
		return env
	}
	return "./data"
}

// runInit implements `csg init`.
func (a *App) runInit(args []string) error {
	fs := a.newFlagSet("init", `Usage: csg init [--data-dir DIR] [--demo] [--supervisor NAME] [--json]

Bootstraps a new data directory: master key, SQLite database and the first
supervisor, with a one-time setup code for choosing a password and enrolling
an authenticator app. --demo also adds a mock cloud account. An existing data
directory is never touched: csg serve upgrades it, and csg supervisor recover
issues a new setup code.
`)
	dataDir := fs.String("data-dir", a.defaultDataDir(), "data directory (default: $CSG_DATA_DIR or ./data)")
	demo := fs.Bool("demo", false, "add a mock cloud account")
	supervisor := fs.String("supervisor", server.DefaultSupervisorUsername, "username of the first supervisor")
	jsonOut := fs.Bool("json", false, "print the InitResult as JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("init takes no positional arguments")
	}
	if strings.TrimSpace(*dataDir) == "" {
		return usagef("--data-dir must not be empty")
	}

	res, err := server.Init(context.Background(), server.InitOptions{
		DataDir: *dataDir,
		Demo:    *demo,

		SupervisorUsername: *supervisor,
	})
	if err != nil {
		return fmt.Errorf("cannot initialize data directory %s: %v", *dataDir, err)
	}

	if *jsonOut {
		return a.printJSON(map[string]any{"data": res})
	}

	fmt.Fprintf(a.Stdout, "Data directory: %s\n", res.DataDir)
	if info, statErr := os.Stat(res.DataDir); statErr == nil {
		if perm := info.Mode().Perm(); perm != 0o700 {
			fmt.Fprintf(a.Stderr, "warning: data directory permissions are %04o (expected 0700)\n", perm)
		}
	}
	fmt.Fprintln(a.Stdout)
	if len(res.ProviderIDs) > 0 {
		fmt.Fprintln(a.Stdout, "Demo cloud account added (mock cloud).")
	}
	if res.Supervisor != nil {
		a.printSetupCode("First supervisor", *res.Supervisor)
	}
	fmt.Fprintln(a.Stdout)
	fmt.Fprintf(a.Stdout, "Next: csg serve --data-dir %s\n", res.DataDir)
	return nil
}

// runServe implements `csg serve`.
func (a *App) runServe(args []string) error {
	fs := a.newFlagSet("serve", `Usage: csg serve [--data-dir DIR] [--addr 127.0.0.1:8787] [--public-url URL] [--trusted-proxy ADDRS]
                 [--trust-master-key]

Runs the control plane (HTTP API, embedded console, mock cloud) until SIGINT or
SIGTERM, then shuts down gracefully.
`)
	dataDir := fs.String("data-dir", a.defaultDataDir(), "data directory (default: $CSG_DATA_DIR or ./data)")
	addr := fs.String("addr", "127.0.0.1:8787", "listen address (loopback only by default)")
	publicURL := fs.String("public-url", "", "origin people open the console at, e.g. https://csg.example.com (set it behind a TLS proxy)")
	trustedProxy := fs.String("trusted-proxy", "", "comma-separated addresses or CIDR ranges of reverse proxies whose X-Forwarded-For is trusted")
	trustKey := fs.Bool("trust-master-key", false, trustMasterKeyHelp)
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("serve takes no positional arguments")
	}
	if strings.TrimSpace(*dataDir) == "" {
		return usagef("--data-dir must not be empty")
	}

	srv, err := server.New(server.Config{Addr: *addr, DataDir: *dataDir, PublicOrigin: *publicURL, TrustedProxies: strings.Split(*trustedProxy, ","), TrustMasterKey: *trustKey})
	if err != nil {
		return fmt.Errorf("cannot start control plane: %v", err)
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	bound := srv.Addr()
	if bound == "" {
		bound = *addr
	}
	fmt.Fprintf(a.Stdout, "%s v%s\n", model.ProductName, model.Version)
	fmt.Fprintf(a.Stdout, "  listening:  http://%s\n", bound)
	fmt.Fprintf(a.Stdout, "  console:    http://%s/\n", bound)
	fmt.Fprintf(a.Stdout, "  api:        http://%s/api/v1\n", bound)
	fmt.Fprintf(a.Stdout, "  mock cloud: http://%s/mock-cloud/\n", bound)
	fmt.Fprintln(a.Stdout, "Press Ctrl-C to stop.")

	serveErr := srv.ListenAndServe(ctx)
	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, context.Canceled) {
		return fmt.Errorf("server error: %v", serveErr)
	}
	fmt.Fprintln(a.Stdout, "shutting down: control plane stopped")
	return nil
}

// printSetupCode prints a person's one-time setup code.
func (a *App) printSetupCode(label string, p model.PersonWithSetupCode) {
	fmt.Fprintln(a.Stdout)
	fmt.Fprintf(a.Stdout, "%s: %s\n", label, p.Person.Username)
	fmt.Fprintf(a.Stdout, "Setup code (shown once, valid until %s): %s\n",
		p.SetupExpiresAt.Local().Format("2006-01-02 15:04"), p.SetupCode)
	fmt.Fprintln(a.Stdout, "Open the console, choose a password and enroll an authenticator app with this code.")
}

// runSupervisor implements `csg supervisor recover`.
func (a *App) runSupervisor(args []string) error {
	if len(args) == 0 || args[0] != "recover" {
		return usagef("usage: csg supervisor recover --username NAME [--data-dir DIR] [--json]")
	}
	fs := a.newFlagSet("supervisor recover", `Usage: csg supervisor recover --username NAME [--data-dir DIR] [--trust-master-key] [--json]

Restores console access for a locked-out supervisor. Run it on the server
host: it needs the data directory and its master key. The named person
becomes a supervisor (created if missing, reactivated if suspended); their
password, authenticator and sessions are erased and a new one-time setup code
is printed. Whoever holds that code controls the account, so use it only for
a person you trust as supervisor. The recovery is recorded in the audit log
at critical severity.
`)
	dataDir := fs.String("data-dir", a.defaultDataDir(), "data directory (default: $CSG_DATA_DIR or ./data)")
	username := fs.String("username", "", "supervisor to restore (required)")
	trustKey := fs.Bool("trust-master-key", false, trustMasterKeyHelp)
	jsonOut := fs.Bool("json", false, "print the result as JSON")
	positionals, err := parseFlags(fs, args[1:])
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("supervisor recover takes no positional arguments")
	}
	if strings.TrimSpace(*username) == "" {
		return usagef("--username is required")
	}
	out, err := server.RecoverSupervisor(context.Background(), server.RecoverOptions{DataDir: *dataDir, Username: *username, TrustMasterKey: *trustKey})
	if err != nil {
		return fmt.Errorf("cannot recover supervisor: %v", err)
	}
	if *jsonOut {
		return a.printJSON(map[string]any{"data": out})
	}
	a.printSetupCode("Supervisor restored", out)
	return nil
}

// trustMasterKeyHelp describes --trust-master-key, which only matters for a
// data directory that holds nothing to verify a key against.
const trustMasterKeyHelp = "accept the key in $CSG_MASTER_KEY as this data directory's key when nothing can verify it (an old directory with no master.key and nothing stored); recorded in the audit log"
