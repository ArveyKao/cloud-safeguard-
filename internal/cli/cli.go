// Package cli implements the csg command-line interface: the operator/admin
// commands, the agent-side lease workflow and the local init/serve commands.
//
// The CLI is a thin client of the HTTP control plane for everything except
// `init` and `serve`; this keeps the server authoritative for policy, limits,
// credentials and audit.
package cli

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Exit codes frozen by docs/CONTRACT.md §9.
const (
	ExitOK           = 0
	ExitOperationErr = 1 // denied/failed/HTTP error
	ExitUsage        = 2 // usage/validation
	ExitAuth         = 3 // authentication/authorization of the CLI identity
	ExitWaitTimeout  = 4 // wait timeout
)

// errUsageShown signals that a -h flag printed usage; the command succeeds.
var errUsageShown = errors.New("usage shown")

// exitError carries an explicit process exit code and an optional message.
type exitError struct {
	code int
	err  error
}

// Error implements error.
func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

// Unwrap exposes the wrapped error.
func (e *exitError) Unwrap() error { return e.err }

// usagef returns an exit-2 error.
func usagef(format string, args ...any) error {
	return &exitError{code: ExitUsage, err: fmt.Errorf(format, args...)}
}

// authf returns an exit-3 error.
func authf(format string, args ...any) error {
	return &exitError{code: ExitAuth, err: fmt.Errorf(format, args...)}
}

// operationf returns an exit-1 error.
func operationf(format string, args ...any) error {
	return &exitError{code: ExitOperationErr, err: fmt.Errorf(format, args...)}
}

// waitTimeoutf returns an exit-4 error.
func waitTimeoutf(format string, args ...any) error {
	return &exitError{code: ExitWaitTimeout, err: fmt.Errorf(format, args...)}
}

// silentExit returns an error that sets an exit code without printing anything
// (used after the command already printed a message).
func silentExit(code int) error { return &exitError{code: code} }

// App is one CLI invocation. The injectable I/O and environment make the CLI
// unit-testable without process-level globals.
type App struct {
	Stdout     io.Writer
	Stderr     io.Writer
	Stdin      io.Reader
	Getenv     func(string) string
	HomeDir    func() (string, error)
	HTTPClient HTTPDoer // optional; nil uses the default client
}

// NewApp returns an App wired to the real process environment.
func NewApp() *App {
	return &App{
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Stdin:   os.Stdin,
		Getenv:  os.Getenv,
		HomeDir: os.UserHomeDir,
	}
}

// Run executes one csg invocation with the process environment (args without
// the program name) and returns the process exit code.
func Run(args []string) int {
	return NewApp().Run(args)
}

// Run executes one csg invocation (args without the program name) and returns
// the process exit code.
func (a *App) Run(args []string) int {
	if a.Stdout == nil {
		a.Stdout = io.Discard
	}
	if a.Stderr == nil {
		a.Stderr = io.Discard
	}
	if a.Stdin == nil {
		a.Stdin = nil
	}
	if a.Getenv == nil {
		a.Getenv = os.Getenv
	}
	if a.HomeDir == nil {
		a.HomeDir = os.UserHomeDir
	}

	if len(args) == 0 {
		a.printUsage(a.Stderr)
		return ExitUsage
	}

	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "help", "-h", "--help":
		a.printUsage(a.Stdout)
		return ExitOK
	case "version":
		err = a.runVersion(rest)
	case "init":
		err = a.runInit(rest)
	case "serve":
		err = a.runServe(rest)
	case "supervisor":
		err = a.runSupervisor(rest)
	case "login":
		err = a.runLogin(rest)
	case "whoami":
		err = a.runWhoami(rest)
	case "caps":
		err = a.runCaps(rest)
	case "agents":
		err = a.runAgents(rest)
	case "providers":
		err = a.runProviders(rest)
	case "leases":
		err = a.runLeases(rest)
	case "audit":
		err = a.runAudit(rest)
	case "policy":
		err = a.runPolicy(rest)
	case "request":
		err = a.runRequest(rest)
	case "credential":
		err = a.runCredential(rest)
	case "exec":
		err = a.runExec(rest)
	case "revoke":
		err = a.runRevoke(rest)
	case "mock":
		err = a.runMock(rest)
	default:
		fmt.Fprintf(a.Stderr, "error: unknown command %q (see csg help)\n", cmd)
		return ExitUsage
	}
	return a.finish(err)
}

// finish maps an error to an exit code, printing its message when it has one.
//
// Frozen exit codes: 0 ok, 1 operation failed, 2 usage/validation, 3 auth,
// 4 wait timeout. A 401 from the control plane always means "auth".
func (a *App) finish(err error) int {
	if err == nil || errors.Is(err, errUsageShown) {
		return ExitOK
	}

	var ee *exitError
	if errors.As(err, &ee) {
		if ee.err == nil {
			// The command already reported the failure itself.
			return ee.code
		}
		fmt.Fprintf(a.Stderr, "error: %s\n", ee.err.Error())
		return ee.code
	}

	var ae *apiError
	if errors.As(err, &ae) {
		fmt.Fprintf(a.Stderr, "error: %s\n", ae.Message)
		if ae.Status == http.StatusUnauthorized {
			return ExitAuth
		}
		return ExitOperationErr
	}

	fmt.Fprintf(a.Stderr, "error: %s\n", err.Error())
	return ExitOperationErr
}

func (a *App) printUsage(w io.Writer) {
	fmt.Fprint(w, `Cloud Safeguard control plane CLI

Usage: csg <command> [flags]

Local:
  init       Bootstrap a data directory (admin token shown once)
  serve      Run the control plane and embedded console
  supervisor recover  Restore a locked-out supervisor (run on the server host)
  version    Print the version

Authentication:
  login      Validate and save an admin or agent token
  whoami     Show the current identity

Admin:
  caps       list | show ID
  agents     list | get ID | create | set-role ID ROLE | suspend ID | activate ID | rotate-token ID
  providers  list | get ID | add | update ID | rotate ID | test ID
  leases     list | get ID | approve ID | deny ID | revoke ID
  audit      list | verify
  policy     show | set

Agent:
  request    Request a capability lease
  credential Fetch the credential for a lease
  exec       Request a lease and run a command with the credential env
  leases mine  List my leases
  revoke     Revoke a lease you own

Demo:
  mock request METHOD /v1/PATH [JSON_BODY]

Global flags (where applicable): --server URL, --token TOKEN, --json
Exit codes: 0 ok, 1 operation failed, 2 usage/validation, 3 auth, 4 wait timeout
`)
}

// newFlagSet returns a quiet FlagSet that prints its custom usage to stdout on
// -h and never to stderr.
func (a *App) newFlagSet(name, usage string) *flagSet {
	fs := newFlagSet(name)
	fs.SetOutput(io.Discard)
	fs.Usage = func() { fmt.Fprint(a.Stdout, usage) }
	return fs
}

// versionInfo is the payload of `csg version --json`.
type versionInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (a *App) runVersion(args []string) error {
	fs := a.newFlagSet("version", "Usage: csg version [--json]\n")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("version takes no arguments")
	}
	if *jsonOut {
		return a.printJSON(versionInfo{Name: model.ProductName, Version: model.Version})
	}
	fmt.Fprintf(a.Stdout, "csg %s (%s)\n", model.Version, model.ProductName)
	return nil
}
