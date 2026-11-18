package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// pollInterval is how often `--wait` and `csg exec` poll a pending lease.
const pollInterval = time.Second

// runCredential implements `csg credential` (agent side).
func (a *App) runCredential(args []string) error {
	fs := a.newFlagSet("credential", `Usage: csg credential --lease ID [--export | --json | --process aws|aliyun]

Fetches the short-lived credential for an active lease. Each fetch is audited.
  --export          print export NAME='value' lines for the shell
  --process aws     print the JSON of an AWS credential_process
  --process aliyun  print the JSON of the Alibaba Cloud CLI External mode
  (default)         print the JSON CredentialEnvelope
With --process the key is refreshed first when it has less than 5 minutes
left and the request's refresh window allows it, so an SDK that calls the
command again before expiry keeps itself supplied.
`)
	cf := a.addClientFlags(fs)
	leaseID := fs.String("lease", "", "lease ID (required)")
	export := fs.Bool("export", false, "print shell export lines instead of JSON")
	jsonOut := fs.Bool("json", false, "print JSON")
	process := fs.String("process", "", "aws or aliyun: print a credential process answer")
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
	if *process != "" && (*export || *jsonOut) {
		return usagef("--process cannot be combined with --export or --json")
	}
	if *process != "" && *process != "aws" && *process != "aliyun" {
		return usagef("--process must be aws or aliyun")
	}
	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if *process != "" {
		a.refreshIfExpiring(ctx, client, strings.TrimSpace(*leaseID))
	}
	var envelope model.CredentialEnvelope
	if err := client.post(ctx, apiPrefix+"/agent/leases/"+pathEscape(*leaseID)+"/credential", nil, &envelope); err != nil {
		return err
	}
	if *process != "" {
		return a.printProcessCredential(*process, envelope.Credential)
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

// processRefreshMargin is how close to expiry --process refreshes the key.
const processRefreshMargin = 5 * time.Minute

// refreshIfExpiring asks for a new key when the current one has less than
// processRefreshMargin left and the refresh window allows another. A refusal
// is not an error: the current key is still handed out while it lasts.
func (a *App) refreshIfExpiring(ctx context.Context, client *apiClient, id string) {
	var req model.AccessRequest
	if err := client.get(ctx, apiPrefix+"/agent/access-requests/"+pathEscape(id), &req); err != nil {
		return
	}
	now := time.Now()
	if req.Status != model.LeaseActive || req.ExpiresAt == nil || req.ExpiresAt.Sub(now) >= processRefreshMargin ||
		req.RefreshUntil == nil || !req.RefreshUntil.After(*req.ExpiresAt) {
		return
	}
	if err := client.post(ctx, apiPrefix+"/agent/access-requests/"+pathEscape(id)+"/refresh", nil, &req); err != nil {
		fmt.Fprintf(a.Stderr, "csg: could not refresh %s: %s\n", displayString(id), displayString(err.Error()))
	}
}

// printProcessCredential prints a credential in the format an SDK's
// credential process expects.
func (a *App) printProcessCredential(kind string, c model.Credential) error {
	if kind == "aws" {
		return a.printJSON(map[string]any{
			"Version": 1, "AccessKeyId": c.AccessKeyID, "SecretAccessKey": c.AccessKeySecret,
			"SessionToken": c.SecurityToken, "Expiration": c.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	return a.printJSON(map[string]any{
		"mode": "StsToken", "access_key_id": c.AccessKeyID, "access_key_secret": c.AccessKeySecret,
		"sts_token": c.SecurityToken,
	})
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
		return usagef("exec requires -- before the command: csg exec --account ID [flags] -- CMD [ARGS...]")
	}
	flagArgs := args[:separator]
	cmdArgs := args[separator+1:]
	if len(cmdArgs) == 0 {
		return usagef("exec requires a command after --")
	}

	fs := a.newFlagSet("exec", `Usage: csg exec --account ID --resource R --permission P --ttl DUR [--name NAME]
                [--reason TEXT] [--keep] [--wait DUR] -- CMD [ARGS...]

Asks for access, injects the Alibaba Cloud credential environment variables and
runs CMD. The credential is revoked when CMD exits unless --keep is given. The
child's exit code becomes csg's exit code.
`)
	cf := a.addClientFlags(fs)
	af := addAccessFlags(fs)
	keep := fs.Bool("keep", false, "keep the credential after the command exits")
	wait := fs.String("wait", "120s", "wait up to DUR for approval (default 2m)")
	positionals, err := parseFlags(fs, flagArgs)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("exec flags must come before --: unexpected arguments %v", positionals)
	}
	if strings.TrimSpace(*af.account) == "" {
		return usagef("exec requires --account")
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

// revokeLease revokes an agent-owned lease and returns the updated lease.
func (a *App) revokeLease(ctx context.Context, client *apiClient, leaseID, reason string) (model.Lease, error) {
	var lease model.Lease
	err := client.post(ctx, apiPrefix+"/agent/leases/"+pathEscape(leaseID)+"/revoke",
		model.RevokeLeaseInput{Reason: reason}, &lease)
	return lease, err
}
