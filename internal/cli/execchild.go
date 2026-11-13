package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Running a command with a short-lived credential (csg exec), and the rules
// for which environment variables a credential may set.

// credentialEnvName is the only shape of variable a credential may set. The
// names come from the server; anything else (LD_PRELOAD, PATH, a name with
// shell syntax in it) is dropped, so a compromised server cannot inject code
// into a shell that sources the credential or into the child process.
var credentialEnvName = regexp.MustCompile(`^(ALIBABA_CLOUD|AWS|CSG)_[A-Z0-9_]{1,64}$`)

// safeCredentialEnv returns the credential's environment variables whose
// names are allowed, falling back to the credential fields when the server
// sent none.
func safeCredentialEnv(envelope *model.CredentialEnvelope) []model.EnvVar {
	out := make([]model.EnvVar, 0, len(envelope.Env)+3)
	for _, kv := range envelope.Env {
		if credentialEnvName.MatchString(kv.Name) {
			out = append(out, kv)
		}
	}
	if len(envelope.Env) == 0 {
		c := envelope.Credential
		out = append(out,
			model.EnvVar{Name: "ALIBABA_CLOUD_ACCESS_KEY_ID", Value: c.AccessKeyID},
			model.EnvVar{Name: "ALIBABA_CLOUD_ACCESS_KEY_SECRET", Value: c.AccessKeySecret},
			model.EnvVar{Name: "ALIBABA_CLOUD_SECURITY_TOKEN", Value: c.SecurityToken})
	}
	return out
}

// childEnv is the parent environment without the CLI's own control token,
// which is broader than the credential and must not reach the command.
func childEnv(extra []string) []string {
	env := make([]string, 0, len(os.Environ())+len(extra))
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if name == "CSG_TOKEN" {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// newSignalChan subscribes to the signals that interrupt csg exec. Tests
// replace it.
var newSignalChan = func() (<-chan os.Signal, func()) {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	return ch, func() { signal.Stop(ch) }
}

// childGrace is how long an interrupted child gets before it is killed.
var childGrace = 10 * time.Second

// revokeAfterExec revokes a lease and warns if that fails. It uses its own
// short deadline so it runs even when the caller is shutting down.
func (a *App) revokeAfterExec(client *apiClient, leaseID, reason string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := a.revokeLease(ctx, client, leaseID, reason); err != nil {
		fmt.Fprintf(a.Stderr, "warning: could not revoke %s: %v\n", leaseID, err)
		return "revoke failed"
	}
	return "revoked"
}

// fetchForExec fetches the credential of an active lease; if that fails the
// lease is revoked, since nothing will use it.
func (a *App) fetchForExec(client *apiClient, leaseID string) (*model.CredentialEnvelope, error) {
	var envelope model.CredentialEnvelope
	if err := client.post(context.Background(), apiPrefix+"/agent/leases/"+pathEscape(leaseID)+"/credential", nil, &envelope); err != nil {
		a.revokeAfterExec(client, leaseID, "csg exec could not fetch the credential")
		return nil, fmt.Errorf("cannot fetch credential for %s: %w", leaseID, err)
	}
	return &envelope, nil
}

// runWithCredential runs cmdArgs with the credential environment and
// revokes the lease afterwards (unless keep). An interrupt (Ctrl-C, SIGTERM,
// SIGHUP) is passed on to the command and always ends with a revoke, even
// with keep: an aborted run must not leave a live credential behind.
func (a *App) runWithCredential(client *apiClient, leaseID, label string, envelope *model.CredentialEnvelope, keep bool, cmdArgs []string) error {
	envPairs := []string{}
	for _, kv := range safeCredentialEnv(envelope) {
		envPairs = append(envPairs, kv.Name+"="+kv.Value)
	}
	envPairs = append(envPairs, "CSG_LEASE_ID="+leaseID, "CSG_SERVER="+client.baseURL)

	child := exec.Command(cmdArgs[0], cmdArgs[1:]...) //nolint:gosec // user-requested command by design
	child.Stdin, child.Stdout, child.Stderr = a.Stdin, a.Stdout, a.Stderr
	child.Env = childEnv(envPairs)

	signals, stop := newSignalChan()
	defer stop()
	if err := child.Start(); err != nil {
		a.revokeAfterExec(client, leaseID, "csg exec could not start the command")
		return fmt.Errorf("cannot run command %q: %v", cmdArgs[0], err)
	}
	if a.afterChildStart != nil {
		a.afterChildStart()
	}
	done := make(chan error, 1)
	go func() { done <- child.Wait() }()

	var caught os.Signal
	var waitErr error
	var killTimer <-chan time.Time
wait:
	for {
		select {
		case waitErr = <-done:
			break wait
		case s := <-signals:
			if caught == nil {
				caught = s
				killTimer = time.After(childGrace)
			}
			_ = child.Process.Signal(s)
		case <-killTimer:
			_ = child.Process.Kill()
		}
	}

	exitCode := 0
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		exitCode = exitErr.ExitCode()
	}
	note := "kept"
	switch {
	case caught != nil:
		note = a.revokeAfterExec(client, leaseID, "csg exec was interrupted")
		if sig, ok := caught.(syscall.Signal); ok {
			exitCode = 128 + int(sig)
		} else {
			exitCode = 130
		}
	case !keep:
		note = a.revokeAfterExec(client, leaseID, "csg exec completed")
	}
	fmt.Fprintf(a.Stderr, "csg exec: %s %s exit %d (%s)\n", leaseID, label, exitCode, note)
	if exitCode != 0 {
		return &exitError{code: exitCode}
	}
	return nil
}
