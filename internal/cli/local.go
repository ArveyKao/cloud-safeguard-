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
	fs := a.newFlagSet("init", `Usage: csg init [--data-dir DIR] [--demo] [--force] [--supervisor NAME] [--admin-token-file PATH] [--json]

Bootstraps a data directory: master key, SQLite database, admin token, the
built-in capability catalog and the first supervisor (with a one-time setup
code for choosing a password and enrolling an authenticator app). --demo also seeds the mock provider and two demo
agents and prints their one-time tokens.
`)
	dataDir := fs.String("data-dir", a.defaultDataDir(), "data directory (default: $CSG_DATA_DIR or ./data)")
	demo := fs.Bool("demo", false, "seed the mock provider and demo agents")
	force := fs.Bool("force", false, "re-initialize an existing data directory (rotates the admin token)")
	adminTokenFile := fs.String("admin-token-file", "", "also write the admin token to this 0600 file")
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
		Force:   *force,

		SupervisorUsername: *supervisor,
	})
	if err != nil {
		return fmt.Errorf("cannot initialize data directory %s: %v", *dataDir, err)
	}

	if tokenFile := strings.TrimSpace(*adminTokenFile); tokenFile != "" {
		if err := os.WriteFile(tokenFile, []byte(res.AdminToken+"\n"), 0o600); err != nil {
			return fmt.Errorf("cannot write admin token file: %v", err)
		}
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
	fmt.Fprintf(a.Stdout, "Admin token (shown once, store securely): %s\n", res.AdminToken)
	fmt.Fprintf(a.Stdout, "Admin token prefix: %s\n", res.AdminTokenPrefix)
	if len(res.ProviderIDs) > 0 {
		fmt.Fprintf(a.Stdout, "Providers: %s\n", strings.Join(res.ProviderIDs, ", "))
	}
	fmt.Fprintf(a.Stdout, "Capabilities: %s\n", strings.Join(res.CapabilityIDs, ", "))
	if len(res.Agents) > 0 {
		fmt.Fprintln(a.Stdout, "Demo agents (tokens shown once):")
		for _, agent := range res.Agents {
			fmt.Fprintf(a.Stdout, "  %-20s %-12s %s\n", agent.Name, agent.ID, agent.Token)
		}
	}
	if res.Supervisor != nil {
		a.printSetupCode("First supervisor", *res.Supervisor)
	}
	fmt.Fprintln(a.Stdout)
	fmt.Fprintln(a.Stdout, "Store these tokens now: they cannot be retrieved later.")
	fmt.Fprintf(a.Stdout, "Next: csg serve --data-dir %s\n", res.DataDir)
	return nil
}

// runServe implements `csg serve`.
func (a *App) runServe(args []string) error {
	fs := a.newFlagSet("serve", `Usage: csg serve [--data-dir DIR] [--addr 127.0.0.1:8787] [--public-url URL] [--trusted-proxy ADDRS]

Runs the control plane (HTTP API, embedded console, mock cloud) until SIGINT or
SIGTERM, then shuts down gracefully.
`)
	dataDir := fs.String("data-dir", a.defaultDataDir(), "data directory (default: $CSG_DATA_DIR or ./data)")
	addr := fs.String("addr", "127.0.0.1:8787", "listen address (loopback only by default)")
	publicURL := fs.String("public-url", "", "origin people open the console at, e.g. https://csg.example.com (set it behind a TLS proxy)")
	trustedProxy := fs.String("trusted-proxy", "", "comma-separated addresses or CIDR ranges of reverse proxies whose X-Forwarded-For is trusted")
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

	srv, err := server.New(server.Config{Addr: *addr, DataDir: *dataDir, PublicOrigin: *publicURL, TrustedProxies: strings.Split(*trustedProxy, ",")})
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
	fs := a.newFlagSet("supervisor recover", `Usage: csg supervisor recover --username NAME [--data-dir DIR] [--json]

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
	out, err := server.RecoverSupervisor(context.Background(), server.RecoverOptions{DataDir: *dataDir, Username: *username})
	if err != nil {
		return fmt.Errorf("cannot recover supervisor: %v", err)
	}
	if *jsonOut {
		return a.printJSON(map[string]any{"data": out})
	}
	a.printSetupCode("Supervisor restored", out)
	return nil
}
