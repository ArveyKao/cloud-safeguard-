package cli

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// pollInterval is how often `--wait` and `csg exec` poll a pending lease.
const pollInterval = time.Second

// runRequest implements `csg request` (agent side).
func (a *App) runRequest(args []string) error {
	fs := a.newFlagSet("request", `Usage: csg request --capability ID [--param k=v]... [--ttl DUR] [--reason TEXT]
                   [--break-glass] [--wait DUR] [--json]

Requests a capability lease. Low-risk requests are auto-approved; higher-risk
requests wait for an operator and can be polled with --wait.
`)
	cf := a.addClientFlags(fs)
	capability := fs.String("capability", "", "capability ID (required)")
	var params paramValues
	fs.Var(&params, "param", "capability parameter key=value (repeatable)")
	ttl := fs.String("ttl", "", "requested lease TTL (e.g. 10m); 0/omitted uses the capability default")
	reason := fs.String("reason", "", "justification for the access")
	breakGlass := fs.Bool("break-glass", false, "request break-glass access (required for critical capabilities)")
	wait := fs.String("wait", "", "wait up to DUR for the lease to become active or terminal")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("request takes no positional arguments")
	}
	if strings.TrimSpace(*capability) == "" {
		return usagef("request requires --capability")
	}
	ttlSeconds, err := parseOptionalDurationSeconds(*ttl)
	if err != nil {
		return usagef("--ttl: %v", err)
	}
	waitTimeout, err := parseOptionalDurationSeconds(*wait)
	if err != nil {
		return usagef("--wait: %v", err)
	}

	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	ctx := context.Background()
	input := model.CreateLeaseInput{
		CapabilityID: strings.TrimSpace(*capability),
		Params:       params.mapValue(),
		TTLSeconds:   ttlSeconds,
		Reason:       strings.TrimSpace(*reason),
		BreakGlass:   *breakGlass,
	}
	var lease model.Lease
	if err := client.post(ctx, apiPrefix+"/agent/leases", input, &lease); err != nil {
		return err
	}
	if waitTimeout > 0 {
		lease, err = a.waitForLease(ctx, client, lease, time.Duration(waitTimeout)*time.Second)
		if err != nil {
			// Still show the last observed lease state before the timeout error.
			if *jsonOut {
				_ = a.printJSON(lease)
			} else {
				printLeaseSummary(a.Stdout, lease)
			}
			return err
		}
	}
	return a.emitLease(lease, *jsonOut)
}

// waitForLease polls a pending lease until it is no longer pending or the
// timeout expires. Polling is every second, as frozen by the contract.
func (a *App) waitForLease(ctx context.Context, client *apiClient, lease model.Lease, timeout time.Duration) (model.Lease, error) {
	deadline := time.Now().Add(timeout)
	for lease.Status == model.LeasePending {
		if !time.Now().Before(deadline) {
			return lease, waitTimeoutf("timed out after %s waiting for lease %s (status %s)", timeout, lease.ID, lease.Status)
		}
		time.Sleep(pollInterval)
		var updated model.Lease
		if err := client.get(ctx, apiPrefix+"/agent/leases/"+pathEscape(lease.ID), &updated); err != nil {
			return lease, err
		}
		lease = updated
	}
	return lease, nil
}

// emitLease prints a lease and maps denied/failed terminal states to exit 1.
func (a *App) emitLease(lease model.Lease, jsonOut bool) error {
	if jsonOut {
		if err := a.printJSON(lease); err != nil {
			return err
		}
	} else {
		printLeaseSummary(a.Stdout, lease)
	}
	switch lease.Status {
	case model.LeaseDenied:
		return operationf("lease %s denied: %s", lease.ID, denialSummary(lease))
	case model.LeaseFailed:
		return operationf("lease %s failed: %s", lease.ID, lease.FailureReason)
	}
	return nil
}

// denialSummary condenses the deciding policy reasons of a denied lease.
func denialSummary(lease model.Lease) string {
	var parts []string
	for _, reason := range lease.Decision.Reasons {
		if reason.Outcome == "deny" {
			parts = append(parts, reason.Rule+": "+reason.Detail)
		}
	}
	if len(parts) == 0 {
		if lease.DeniedReason != "" {
			return lease.DeniedReason
		}
		return "denied by policy"
	}
	return strings.Join(parts, "; ")
}

// printLeaseSummary renders the compact agent-facing lease view.
func printLeaseSummary(w io.Writer, lease model.Lease) {
	next := ""
	switch lease.Status {
	case model.LeaseActive:
		next = fmt.Sprintf("fetch the credential: csg credential --lease %s", lease.ID)
	case model.LeasePending:
		next = "waiting for operator approval (csg leases list --status pending)"
	case model.LeaseDenied:
		next = "no credential will be issued"
	case model.LeaseFailed:
		next = "no credential was issued"
	case model.LeaseExpired, model.LeaseRevoked:
		next = "no credential available"
	}
	fmt.Fprintf(w, "lease:     %s\n", lease.ID)
	fmt.Fprintf(w, "status:    %s\n", lease.Status)
	fmt.Fprintf(w, "decision:  %s\n", lease.Decision.Outcome)
	fmt.Fprintf(w, "capability: %s\n", lease.CapabilityID)
	fmt.Fprintf(w, "ttl:       %s\n", formatSeconds(lease.EffectiveTTLSeconds))
	fmt.Fprintf(w, "expires:   %s\n", fmtTimePtr(lease.ExpiresAt))
	if lease.DeniedReason != "" {
		fmt.Fprintf(w, "reason:    %s\n", lease.DeniedReason)
	}
	if lease.FailureReason != "" {
		fmt.Fprintf(w, "failure:   %s\n", lease.FailureReason)
	}
	fmt.Fprintf(w, "next:      %s\n", next)
}

// runCredential implements `csg credential` (agent side).
func (a *App) runCredential(args []string) error {
	fs := a.newFlagSet("credential", `Usage: csg credential --lease ID [--export | --json]

Fetches the short-lived credential for an active lease. Each fetch is audited.
  --export   print export NAME='value' lines for the shell
  (default)  print the JSON CredentialEnvelope
`)
	cf := a.addClientFlags(fs)
	leaseID := fs.String("lease", "", "lease ID (required)")
	export := fs.Bool("export", false, "print shell export lines instead of JSON")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("credential takes no positional arguments")
	}
	if strings.TrimSpace(*leaseID) == "" {
		return usagef("credential requires --lease")
	}
	if *export && *jsonOut {
		return usagef("--export and --json are mutually exclusive")
	}
	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	var envelope model.CredentialEnvelope
	if err := client.post(context.Background(), apiPrefix+"/agent/leases/"+pathEscape(*leaseID)+"/credential", nil, &envelope); err != nil {
		return err
	}
	if *export {
		for _, kv := range safeCredentialEnv(&envelope) {
			fmt.Fprintf(a.Stdout, "export %s='%s'\n", kv.Name, shellSingleQuote(kv.Value))
		}
		return nil
	}
	// The contract's default output is the JSON credential envelope.
	return a.printJSON(envelope)
}

// shellSingleQuote escapes a value for a single-quoted shell string.
func shellSingleQuote(value string) string {
	return strings.ReplaceAll(value, "'", `'\''`)
}

// runRevoke implements `csg revoke` (agent side).
func (a *App) runRevoke(args []string) error {
	fs := a.newFlagSet("revoke", "Usage: csg revoke --lease ID [--reason TEXT] [--json]\n")
	cf := a.addClientFlags(fs)
	leaseID := fs.String("lease", "", "lease ID (required)")
	reason := fs.String("reason", "revoked by agent", "revocation reason")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("revoke takes no positional arguments")
	}
	if strings.TrimSpace(*leaseID) == "" {
		return usagef("revoke requires --lease")
	}
	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	var lease model.Lease
	if err := client.post(context.Background(), apiPrefix+"/agent/leases/"+pathEscape(*leaseID)+"/revoke",
		model.RevokeLeaseInput{Reason: *reason}, &lease); err != nil {
		return err
	}
	// The ID the user named, not one echoed by the server.
	a.removeCredentialFile(strings.TrimSpace(*leaseID))
	if *jsonOut {
		return a.printJSON(lease)
	}
	fmt.Fprintf(a.Stdout, "lease %s revoked\n", lease.ID)
	return nil
}

// runExec implements `csg exec`: request -> wait -> fetch credential -> run the
// child command with the credential environment -> revoke (unless --keep).
func (a *App) runExec(args []string) error {
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		return usagef("exec requires -- before the command: csg exec --capability ID [flags] -- CMD [ARGS...]")
	}
	flagArgs := args[:separator]
	cmdArgs := args[separator+1:]
	if len(cmdArgs) == 0 {
		return usagef("exec requires a command after --")
	}

	fs := a.newFlagSet("exec", `Usage: csg exec --account ID --resource R --permission P --ttl DUR [--name NAME]
                [--reason TEXT] [--keep] [--wait DUR] -- CMD [ARGS...]
       csg exec --capability ID [--param k=v]... [--ttl DUR] [--reason TEXT]
                [--break-glass] [--keep] [--wait DUR] -- CMD [ARGS...]

Asks for access, injects the Alibaba Cloud credential environment variables and
runs CMD. The credential is revoked when CMD exits unless --keep is given. The
child's exit code becomes csg's exit code. The first form is for agents signed
in with csg login; the second is the older capability lease.
`)
	cf := a.addClientFlags(fs)
	af := addAccessFlags(fs)
	capability := fs.String("capability", "", "capability ID (older capability leases)")
	var params paramValues
	fs.Var(&params, "param", "capability parameter key=value (repeatable)")
	ttl, reason := af.ttl, af.reason
	breakGlass := fs.Bool("break-glass", false, "request break-glass access")
	keep := fs.Bool("keep", false, "keep the lease active after the command exits")
	wait := fs.String("wait", "120s", "wait up to DUR for approval (default 2m)")
	positionals, err := parseFlags(fs, flagArgs)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("exec flags must come before --: unexpected arguments %v", positionals)
	}
	if strings.TrimSpace(*af.account) != "" {
		if strings.TrimSpace(*capability) != "" {
			return usagef("use either --account or --capability, not both")
		}
		in, err := af.input()
		if err != nil {
			return err
		}
		waitSeconds, err := parseDurationSeconds(*wait)
		if err != nil {
			return usagef("--wait: %v", err)
		}
		client, err := a.agentClient(cf)
		if err != nil {
			return err
		}
		return a.execWithAccess(client, in, time.Duration(waitSeconds)*time.Second, *keep, cmdArgs)
	}
	if strings.TrimSpace(*capability) == "" {
		return usagef("exec requires --account (or --capability)")
	}
	ttlSeconds, err := parseOptionalDurationSeconds(*ttl)
	if err != nil {
		return usagef("--ttl: %v", err)
	}
	waitSeconds, err := parseDurationSeconds(*wait)
	if err != nil {
		return usagef("--wait: %v", err)
	}

	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	ctx := context.Background()
	capabilityID := strings.TrimSpace(*capability)

	var lease model.Lease
	if err := client.post(ctx, apiPrefix+"/agent/leases", model.CreateLeaseInput{
		CapabilityID: capabilityID,
		Params:       params.mapValue(),
		TTLSeconds:   ttlSeconds,
		Reason:       strings.TrimSpace(*reason),
		BreakGlass:   *breakGlass,
	}, &lease); err != nil {
		return err
	}
	if lease.Status == model.LeasePending {
		lease, err = a.waitForLease(ctx, client, lease, time.Duration(waitSeconds)*time.Second)
		if err != nil {
			printLeaseSummary(a.Stderr, lease)
			// The command will not run: do not leave the request behind.
			a.revokeAfterExec(client, lease.ID, "csg exec gave up waiting")
			return err
		}
	}
	if lease.Status != model.LeaseActive {
		printLeaseSummary(a.Stderr, lease)
		return operationf("lease %s is %s, so no credential is available", lease.ID, lease.Status)
	}
	envelope, err := a.fetchForExec(client, lease.ID)
	if err != nil {
		return err
	}
	return a.runWithCredential(client, lease.ID, "capability "+capabilityID, envelope, *keep, cmdArgs)
}

// revokeLease revokes an agent-owned lease and returns the updated lease.
func (a *App) revokeLease(ctx context.Context, client *apiClient, leaseID, reason string) (model.Lease, error) {
	var lease model.Lease
	err := client.post(ctx, apiPrefix+"/agent/leases/"+pathEscape(leaseID)+"/revoke",
		model.RevokeLeaseInput{Reason: reason}, &lease)
	return lease, err
}
