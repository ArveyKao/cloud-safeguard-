package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Agent-side commands for the §17 flow: sign-in, cloud accounts and access
// requests (CONTRACT §17.3, §17.4).

// pollSleep waits between polls; tests replace it.
var pollSleep = time.Sleep

// signInTimeout bounds how long csg login waits for a person to approve.
const signInTimeout = 10 * time.Minute

var agentNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`)

// defaultAgentName is csg-<hostname>, reduced to the allowed characters.
func defaultAgentName() string {
	host, _ := os.Hostname()
	var b strings.Builder
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			b.WriteRune(r)
		}
	}
	name := "csg-" + b.String()
	if len(name) > 64 {
		name = name[:64]
	}
	if !agentNameRE.MatchString(name) {
		return "csg-agent"
	}
	return name
}

// agentSignIn runs the agent-first sign-in and saves the agent token.
func (a *App) agentSignIn(serverURL, name, description string, jsonOut bool) error {
	name = strings.TrimSpace(name)
	if name == "" {
		name = defaultAgentName()
	}
	if !agentNameRE.MatchString(name) {
		return usagef("--name must be 2-64 characters: letters, digits, dot, dash or underscore")
	}
	client := &apiClient{baseURL: serverURL, http: a.httpClient()}
	ctx := context.Background()

	var start model.AgentSignInStart
	if err := client.post(ctx, apiPrefix+"/agent-signin/start",
		model.AgentSignInStartInput{AgentName: name, Description: strings.TrimSpace(description)}, &start); err != nil {
		return err
	}
	// The device code is the agent's secret: it is never printed.
	fmt.Fprintf(a.Stderr, "To sign in agent %q, open this link and approve the code:\n\n  %s\n\n  code: %s\n\n", name, start.VerificationURL, start.UserCode)
	fmt.Fprintf(a.Stderr, "Waiting for approval (the code expires at %s)...\n", start.ExpiresAt.Local().Format("15:04"))
	if a.afterSignInStart != nil {
		a.afterSignInStart(start)
	}

	interval := time.Duration(start.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(signInTimeout)
	for {
		var res model.AgentSignInResult
		if err := client.post(ctx, apiPrefix+"/agent-signin/token", model.AgentSignInTokenInput{DeviceCode: start.DeviceCode}, &res); err != nil {
			return err
		}
		switch res.Status {
		case model.SignInApproved:
			if res.Agent == nil || res.Token == "" {
				return operationf("the server approved the sign-in but returned no token")
			}
			path, err := a.saveFileConfig(fileConfig{Server: serverURL, Token: res.Token, Kind: "agent"})
			if err != nil {
				return err
			}
			if jsonOut {
				return a.printJSON(map[string]any{"agent": res.Agent, "server": serverURL, "config_path": path})
			}
			fmt.Fprintf(a.Stdout, "signed in as agent %s (%s)\n", res.Agent.Name, res.Agent.ID)
			fmt.Fprintf(a.Stdout, "token saved to %s (mode 0600)\n", path)
			return nil
		case model.SignInDenied:
			return operationf("the sign-in was denied")
		case model.SignInExpired:
			return operationf("the sign-in code expired or was already used; run csg login again")
		}
		if !time.Now().Before(deadline) {
			return waitTimeoutf("timed out waiting for the sign-in to be approved")
		}
		pollSleep(interval)
	}
}

// runAccounts implements `csg accounts`.
func (a *App) runAccounts(args []string) error {
	fs := a.newFlagSet("accounts", `Usage: csg accounts [--json]

Lists the cloud accounts this agent may ask for: the role it inherits from its
owner, the highest permission that role allows, and how far access is issued
without waiting for the owner.
`)
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("accounts takes no positional arguments")
	}
	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	var list struct {
		Items []model.AgentAccount `json:"items"`
	}
	if err := client.get(context.Background(), apiPrefix+"/agent/accounts", &list); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(list.Items)
	}
	if len(list.Items) == 0 {
		fmt.Fprintln(a.Stdout, "no cloud accounts: ask a supervisor to give your owner a role on one")
		return nil
	}
	rows := make([][]string, 0, len(list.Items))
	for _, acct := range list.Items {
		rows = append(rows, []string{acct.CloudAccountID, acct.Name, string(acct.Role), acct.HighestPermission,
			acct.AutomaticUpTo, strings.Join(acct.Resources, ",")})
	}
	writeTable(a.Stdout, []string{"CLOUD ACCOUNT", "NAME", "ROLE", "UP TO", "AUTOMATIC", "RESOURCES"}, rows)
	return nil
}

// accessFlags are the five fields of an access request plus a reason.
type accessFlags struct {
	account, resource, permission, ttl, name, reason *string
}

func addAccessFlags(fs *flagSet) accessFlags {
	return accessFlags{
		account:    fs.String("account", "", "cloud account ID (required)"),
		resource:   fs.String("resource", "", "resource type: ecs, dns or oss (required)"),
		permission: fs.String("permission", "", "read, write or full (required)"),
		ttl:        fs.String("ttl", "", "validity period, e.g. 15m (required)"),
		name:       fs.String("name", "", "one resource (instance ID, domain, bucket); default all"),
		reason:     fs.String("reason", "", "shown to your owner; required for write and full"),
	}
}

func (f accessFlags) input() (model.AccessRequestInput, error) {
	in := model.AccessRequestInput{
		CloudAccountID: strings.TrimSpace(*f.account),
		Resource:       strings.TrimSpace(*f.resource),
		Permission:     strings.ToLower(strings.TrimSpace(*f.permission)),
		ResourceName:   strings.TrimSpace(*f.name),
		Reason:         strings.TrimSpace(*f.reason),
	}
	if in.CloudAccountID == "" || in.Resource == "" || in.Permission == "" || strings.TrimSpace(*f.ttl) == "" {
		return in, usagef("--account, --resource, --permission and --ttl are required")
	}
	ttl, err := parseDurationSeconds(*f.ttl)
	if err != nil {
		return in, usagef("--ttl: %v", err)
	}
	in.TTLSeconds = ttl
	return in, nil
}

// runAccess implements `csg access request|status`.
func (a *App) runAccess(args []string) error {
	if len(args) == 0 {
		return usagef("usage: csg access request|status ...")
	}
	switch args[0] {
	case "request":
		return a.runAccessRequest(args[1:])
	case "status":
		return a.runAccessStatus(args[1:])
	}
	return usagef("unknown access subcommand %q (request, status)", args[0])
}

func (a *App) runAccessRequest(args []string) error {
	fs := a.newFlagSet("access request", `Usage: csg access request --account ID --resource R --permission P --ttl DUR
                          [--name NAME] [--reason TEXT] [--wait DUR] [--json]

Asks for short-lived access. Read access is usually issued at once; write and
full may wait for your owner to approve in the console (--wait polls). Fetch
the credential with csg credential --lease <request id> --export.
`)
	cf := a.addClientFlags(fs)
	af := addAccessFlags(fs)
	wait := fs.String("wait", "", "wait up to DUR for your owner's decision")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("access request takes no positional arguments")
	}
	in, err := af.input()
	if err != nil {
		return err
	}
	waitSeconds, err := parseOptionalDurationSeconds(*wait)
	if err != nil {
		return usagef("--wait: %v", err)
	}
	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	ctx := context.Background()
	var req model.AccessRequest
	if err := client.post(ctx, apiPrefix+"/agent/access-requests", in, &req); err != nil {
		return err
	}
	if waitSeconds > 0 {
		req, err = a.waitForAccess(ctx, client, req, time.Duration(waitSeconds)*time.Second)
		if err != nil {
			a.printAccess(req, *jsonOut)
			return err
		}
	}
	return a.emitAccess(req, *jsonOut)
}

func (a *App) runAccessStatus(args []string) error {
	fs := a.newFlagSet("access status", "Usage: csg access status ID [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("access status takes one request ID")
	}
	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	var req model.AccessRequest
	if err := client.get(context.Background(), apiPrefix+"/agent/access-requests/"+pathEscape(positionals[0]), &req); err != nil {
		return err
	}
	return a.emitAccess(req, *jsonOut)
}

// waitForAccess polls a pending request until the owner decides or timeout.
func (a *App) waitForAccess(ctx context.Context, client *apiClient, req model.AccessRequest, timeout time.Duration) (model.AccessRequest, error) {
	deadline := time.Now().Add(timeout)
	for req.Status == model.LeasePending {
		if !time.Now().Before(deadline) {
			return req, waitTimeoutf("timed out after %s waiting for your owner to approve request %s", timeout, req.ID)
		}
		pollSleep(pollInterval)
		var updated model.AccessRequest
		if err := client.get(ctx, apiPrefix+"/agent/access-requests/"+pathEscape(req.ID), &updated); err != nil {
			return req, err
		}
		req = updated
	}
	return req, nil
}

func (a *App) printAccess(req model.AccessRequest, jsonOut bool) {
	if jsonOut {
		_ = a.printJSON(req)
		return
	}
	scope := req.ResourceName
	if scope == "" {
		scope = "all"
	}
	fmt.Fprintf(a.Stdout, "request:    %s\n", req.ID)
	fmt.Fprintf(a.Stdout, "status:     %s\n", req.Status)
	fmt.Fprintf(a.Stdout, "access:     %s %s (%s) on %s\n", req.Permission, req.Resource, scope, req.CloudAccountID)
	fmt.Fprintf(a.Stdout, "valid for:  %s\n", formatSeconds(req.TTLSeconds))
	if req.ExpiresAt != nil {
		fmt.Fprintf(a.Stdout, "expires:    %s\n", req.ExpiresAt.Local().Format(time.RFC3339))
	}
	switch req.Status {
	case model.LeasePending:
		fmt.Fprintln(a.Stdout, "next:       your owner approves it in the console; check with csg access status "+req.ID)
	case model.LeaseActive:
		fmt.Fprintln(a.Stdout, "next:       eval \"$(csg credential --lease "+req.ID+" --export)\"")
	case model.LeaseDenied:
		fmt.Fprintf(a.Stdout, "reason:     %s\n", req.DeniedReason)
	}
}

// emitAccess prints a request and maps denied/failed to exit 1.
func (a *App) emitAccess(req model.AccessRequest, jsonOut bool) error {
	a.printAccess(req, jsonOut)
	switch req.Status {
	case model.LeaseDenied:
		return silentExit(ExitOperationErr)
	case model.LeaseFailed:
		return operationf("request %s failed: %s", req.ID, req.FailureReason)
	}
	return nil
}

// execWithAccess is `csg exec --account ...`: ask for access, wait, run the
// command with the credential environment, then revoke unless keep.
func (a *App) execWithAccess(client *apiClient, in model.AccessRequestInput, wait time.Duration, keep bool, cmdArgs []string) error {
	ctx := context.Background()
	var req model.AccessRequest
	if err := client.post(ctx, apiPrefix+"/agent/access-requests", in, &req); err != nil {
		return err
	}
	if req.Status == model.LeasePending {
		fmt.Fprintf(a.Stderr, "csg exec: request %s waits for your owner's approval in the console\n", req.ID)
		var err error
		if req, err = a.waitForAccess(ctx, client, req, wait); err != nil {
			return err
		}
	}
	if req.Status != model.LeaseActive {
		return operationf("request %s is %s: %s", req.ID, req.Status, req.DeniedReason)
	}
	var envelope model.CredentialEnvelope
	if err := client.post(ctx, apiPrefix+"/agent/leases/"+pathEscape(req.ID)+"/credential", nil, &envelope); err != nil {
		return fmt.Errorf("cannot fetch credential for request %s: %w", req.ID, err)
	}
	envPairs := buildCredentialEnv(&envelope, client.baseURL, in.Resource+":"+in.Permission)

	child := exec.Command(cmdArgs[0], cmdArgs[1:]...) //nolint:gosec // user-requested command by design
	child.Stdin, child.Stdout, child.Stderr = a.Stdin, a.Stdout, a.Stderr
	child.Env = append(os.Environ(), envPairs...)
	runErr := child.Run()
	exitCode := 0
	if runErr != nil {
		var exitErrChild *exec.ExitError
		if !errors.As(runErr, &exitErrChild) {
			_, _ = a.revokeLease(ctx, client, req.ID, "csg exec could not start the command")
			return fmt.Errorf("cannot run command %q: %v", cmdArgs[0], runErr)
		}
		exitCode = exitErrChild.ExitCode()
	}
	note := "kept"
	if !keep {
		if _, err := a.revokeLease(ctx, client, req.ID, "csg exec completed"); err != nil {
			fmt.Fprintf(a.Stderr, "warning: could not revoke request %s: %v\n", req.ID, err)
			note = "revoke failed"
		} else {
			note = "revoked"
		}
	}
	fmt.Fprintf(a.Stderr, "csg exec: request %s %s %s exit %d (%s)\n", req.ID, in.Permission, in.Resource, exitCode, note)
	if exitCode != 0 {
		return &exitError{code: exitCode}
	}
	return nil
}
