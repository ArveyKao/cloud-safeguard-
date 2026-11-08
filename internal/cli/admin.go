package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// ---- capabilities ----

// runCaps implements `csg caps list|show ID` (admin).
func (a *App) runCaps(args []string) error {
	if len(args) == 0 {
		return usagef("caps requires a subcommand: list | show ID")
	}
	switch args[0] {
	case "list":
		return a.runCapsList(args[1:])
	case "show":
		return a.runCapsShow(args[1:])
	default:
		return usagef("unknown caps subcommand %q (list | show ID)", args[0])
	}
}

func (a *App) runCapsList(args []string) error {
	fs := a.newFlagSet("caps list", "Usage: csg caps list [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("caps list takes no positional arguments")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var res model.ListResponse[model.Capability]
	if err := client.get(context.Background(), apiPrefix+"/admin/capabilities", &res); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(res)
	}
	if len(res.Items) == 0 {
		fmt.Fprintln(a.Stdout, "no capabilities")
		return nil
	}
	rows := make([][]string, 0, len(res.Items))
	for _, c := range res.Items {
		rows = append(rows, []string{
			c.ID,
			c.Name,
			string(c.Risk),
			formatSeconds(c.DefaultTTLSeconds),
			formatSeconds(c.MaxTTLSeconds),
			yesNo(c.Enabled),
			yesNo(c.Builtin),
		})
	}
	writeTable(a.Stdout, []string{"ID", "NAME", "RISK", "DEFAULT_TTL", "MAX_TTL", "ENABLED", "BUILTIN"}, rows)
	return nil
}

func (a *App) runCapsShow(args []string) error {
	fs := a.newFlagSet("caps show", "Usage: csg caps show ID [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("caps show requires exactly one capability ID")
	}
	id := positionals[0]
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var res model.ListResponse[model.Capability]
	if err := client.get(context.Background(), apiPrefix+"/admin/capabilities", &res); err != nil {
		return err
	}
	for _, c := range res.Items {
		if c.ID != id {
			continue
		}
		if *jsonOut {
			return a.printJSON(c)
		}
		printCapability(a.Stdout, c)
		return nil
	}
	return operationf("capability %q not found", id)
}

// printCapability renders one capability in human-readable form.
func printCapability(w io.Writer, c model.Capability) {
	fmt.Fprintf(w, "id:           %s\n", c.ID)
	fmt.Fprintf(w, "name:         %s\n", c.Name)
	fmt.Fprintf(w, "description:  %s\n", c.Description)
	fmt.Fprintf(w, "provider:     %s\n", c.ProviderType)
	fmt.Fprintf(w, "risk:         %s\n", c.Risk)
	fmt.Fprintf(w, "enabled:      %s\n", yesNo(c.Enabled))
	fmt.Fprintf(w, "builtin:      %s\n", yesNo(c.Builtin))
	fmt.Fprintf(w, "ttl:          default %s, max %s\n", formatSeconds(c.DefaultTTLSeconds), formatSeconds(c.MaxTTLSeconds))
	if len(c.Params) == 0 {
		fmt.Fprintln(w, "params:       -")
	} else {
		fmt.Fprintln(w, "params:")
		for _, p := range c.Params {
			req := "optional"
			if p.Required {
				req = "required"
			}
			fmt.Fprintf(w, "  - %s (%s): %s\n", p.Name, req, p.Description)
			if p.Pattern != "" {
				fmt.Fprintf(w, "      pattern: %s\n", p.Pattern)
			}
		}
	}
	fmt.Fprintf(w, "policy:       %s\n", c.PolicyTemplate)
}

// ---- agents ----

// runAgents implements `csg agents ...` (admin).
func (a *App) runAgents(args []string) error {
	if len(args) == 0 {
		return usagef("agents requires a subcommand: list | get ID | create | suspend ID | activate ID | rotate-token ID")
	}
	switch args[0] {
	case "list":
		return a.runAgentsList(args[1:])
	case "get":
		return a.runAgentsGet(args[1:])
	case "create":
		return a.runAgentsCreate(args[1:])
	case "suspend":
		return a.runAgentsStatus(args[1:], "suspend")
	case "activate":
		return a.runAgentsStatus(args[1:], "activate")
	case "rotate-token":
		return a.runAgentsRotate(args[1:])
	default:
		return usagef("unknown agents subcommand %q", args[0])
	}
}

func (a *App) runAgentsList(args []string) error {
	fs := a.newFlagSet("agents list", "Usage: csg agents list [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("agents list takes no positional arguments")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var res model.ListResponse[model.Agent]
	if err := client.get(context.Background(), apiPrefix+"/admin/agents", &res); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(res)
	}
	if len(res.Items) == 0 {
		fmt.Fprintln(a.Stdout, "no agents")
		return nil
	}
	rows := make([][]string, 0, len(res.Items))
	for _, ag := range res.Items {
		rows = append(rows, []string{
			ag.ID,
			ag.Name,
			string(ag.Status),
			joinOrDash(ag.Grants),
			formatSeconds(ag.MaxTTLSeconds),
			fmt.Sprintf("%d", ag.MaxConcurrentLeases),
			fmtTimePtr(ag.LastSeenAt),
		})
	}
	writeTable(a.Stdout, []string{"ID", "NAME", "STATUS", "GRANTS", "MAX_TTL", "MAX_CONC", "LAST_SEEN"}, rows)
	return nil
}

func (a *App) runAgentsGet(args []string) error {
	fs := a.newFlagSet("agents get", "Usage: csg agents get ID [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("agents get requires exactly one agent ID")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var ag model.Agent
	if err := client.get(context.Background(), apiPrefix+"/admin/agents/"+pathEscape(positionals[0]), &ag); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(ag)
	}
	printAgent(a.Stdout, ag)
	return nil
}

func (a *App) runAgentsCreate(args []string) error {
	fs := a.newFlagSet("agents create", `Usage: csg agents create --name NAME [--description D] [--capability id[,id...]] [--max-ttl DUR] [--max-concurrent N] [--json]
`)
	cf := a.addClientFlags(fs)
	name := fs.String("name", "", "agent name (required)")
	description := fs.String("description", "", "agent description")
	var grants stringSliceFlag
	fs.Var(&grants, "capability", "capability ID to grant (repeatable, comma-separated)")
	maxTTL := fs.String("max-ttl", "", "maximum lease TTL for this agent (e.g. 30m)")
	maxConcurrent := fs.Int("max-concurrent", 0, "maximum concurrently active leases")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("agents create takes no positional arguments")
	}
	if strings.TrimSpace(*name) == "" {
		return usagef("agents create requires --name")
	}
	ttlSeconds, err := parseOptionalDurationSeconds(*maxTTL)
	if err != nil {
		return usagef("--max-ttl: %v", err)
	}
	input := model.CreateAgentInput{
		Name:                strings.TrimSpace(*name),
		Description:         *description,
		Grants:              grants.values(),
		MaxTTLSeconds:       ttlSeconds,
		MaxConcurrentLeases: *maxConcurrent,
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var res model.AgentWithToken
	if err := client.post(context.Background(), apiPrefix+"/admin/agents", input, &res); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(res)
	}
	fmt.Fprintf(a.Stdout, "Agent created: %s (%s)\n", res.Agent.ID, res.Agent.Name)
	fmt.Fprintf(a.Stdout, "Token (shown once, store securely): %s\n", res.Token)
	return nil
}

func (a *App) runAgentsStatus(args []string, action string) error {
	fs := a.newFlagSet("agents "+action, "Usage: csg agents "+action+" ID [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("agents %s requires exactly one agent ID", action)
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var ag model.Agent
	if err := client.post(context.Background(), apiPrefix+"/admin/agents/"+pathEscape(positionals[0])+"/"+action, nil, &ag); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(ag)
	}
	fmt.Fprintf(a.Stdout, "agent %s (%s) status is now %s\n", ag.ID, ag.Name, ag.Status)
	return nil
}

func (a *App) runAgentsRotate(args []string) error {
	fs := a.newFlagSet("agents rotate-token", "Usage: csg agents rotate-token ID [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("agents rotate-token requires exactly one agent ID")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var res model.AgentWithToken
	if err := client.post(context.Background(), apiPrefix+"/admin/agents/"+pathEscape(positionals[0])+"/token/rotate", nil, &res); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(res)
	}
	fmt.Fprintf(a.Stdout, "Agent token rotated: %s (%s)\n", res.Agent.ID, res.Agent.Name)
	fmt.Fprintf(a.Stdout, "New token (shown once, store securely): %s\n", res.Token)
	return nil
}

// printAgent renders one agent in human-readable form.
func printAgent(w io.Writer, ag model.Agent) {
	fmt.Fprintf(w, "id:               %s\n", ag.ID)
	fmt.Fprintf(w, "name:             %s\n", ag.Name)
	fmt.Fprintf(w, "description:      %s\n", ag.Description)
	fmt.Fprintf(w, "status:           %s\n", ag.Status)
	fmt.Fprintf(w, "grants:           %s\n", joinOrDash(ag.Grants))
	fmt.Fprintf(w, "max ttl:          %s\n", formatSeconds(ag.MaxTTLSeconds))
	fmt.Fprintf(w, "max concurrent:   %d\n", ag.MaxConcurrentLeases)
	fmt.Fprintf(w, "token prefix:     %s\n", ag.TokenPrefix)
	fmt.Fprintf(w, "last seen:        %s\n", fmtTimePtr(ag.LastSeenAt))
	fmt.Fprintf(w, "created:          %s\n", fmtTime(ag.CreatedAt))
}

// ---- providers ----

// runProviders implements `csg providers ...` (admin).
func (a *App) runProviders(args []string) error {
	if len(args) == 0 {
		return usagef("providers requires a subcommand: list | get ID | add | update ID | rotate ID | test ID")
	}
	switch args[0] {
	case "list":
		return a.runProvidersList(args[1:])
	case "get":
		return a.runProvidersGet(args[1:])
	case "add":
		return a.runProvidersAdd(args[1:])
	case "update":
		return a.runProvidersUpdate(args[1:])
	case "rotate":
		return a.runProvidersRotate(args[1:])
	case "test":
		return a.runProvidersTest(args[1:])
	default:
		return usagef("unknown providers subcommand %q", args[0])
	}
}

func (a *App) runProvidersList(args []string) error {
	fs := a.newFlagSet("providers list", "Usage: csg providers list [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("providers list takes no positional arguments")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var res model.ListResponse[model.Provider]
	if err := client.get(context.Background(), apiPrefix+"/admin/providers", &res); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(res)
	}
	if len(res.Items) == 0 {
		fmt.Fprintln(a.Stdout, "no providers")
		return nil
	}
	rows := make([][]string, 0, len(res.Items))
	for _, p := range res.Items {
		rows = append(rows, []string{
			p.ID,
			p.Name,
			string(p.Mode),
			p.Region,
			p.AccessKeyIDMasked,
			string(p.Status),
		})
	}
	writeTable(a.Stdout, []string{"ID", "NAME", "MODE", "REGION", "MASKED_AK", "STATUS"}, rows)
	return nil
}

func (a *App) runProvidersGet(args []string) error {
	fs := a.newFlagSet("providers get", "Usage: csg providers get ID [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("providers get requires exactly one provider ID")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var p model.Provider
	if err := client.get(context.Background(), apiPrefix+"/admin/providers/"+pathEscape(positionals[0]), &p); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(p)
	}
	printProvider(a.Stdout, p)
	return nil
}

func (a *App) runProvidersAdd(args []string) error {
	fs := a.newFlagSet("providers add", `Usage: csg providers add --name NAME --mode mock|sts --region REGION [--role-arn ARN]
                          [--access-key-id ID] [--access-key-secret-file PATH | --access-key-secret-stdin] [--json]
`)
	cf := a.addClientFlags(fs)
	name := fs.String("name", "", "provider display name (required)")
	mode := fs.String("mode", "", "provider mode: mock | sts (required)")
	region := fs.String("region", "", "cloud region (required)")
	roleARN := fs.String("role-arn", "", "RAM role ARN to assume (sts mode)")
	accessKeyID := fs.String("access-key-id", "", "broker AccessKey ID")
	secretFile := fs.String("access-key-secret-file", "", "read the broker AccessKey secret from this file")
	secretStdin := fs.Bool("access-key-secret-stdin", false, "read the broker AccessKey secret from stdin")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("providers add takes no positional arguments")
	}
	providerMode := model.ProviderMode(strings.ToLower(strings.TrimSpace(*mode)))
	if !providerMode.Valid() {
		return usagef("--mode must be mock or sts")
	}
	if strings.TrimSpace(*name) == "" {
		return usagef("providers add requires --name")
	}
	if strings.TrimSpace(*region) == "" {
		return usagef("providers add requires --region")
	}
	secret, err := a.readSecretFlags(*secretFile, *secretStdin)
	if err != nil {
		return err
	}
	if providerMode == model.ModeSTS {
		if strings.TrimSpace(*accessKeyID) == "" {
			return usagef("--access-key-id is required for sts mode")
		}
		if secret == "" {
			return usagef("an AccessKey secret is required for sts mode (--access-key-secret-file or --access-key-secret-stdin)")
		}
		if strings.TrimSpace(*roleARN) == "" {
			return usagef("--role-arn is required for sts mode")
		}
	}
	input := model.CreateProviderInput{
		Name:            strings.TrimSpace(*name),
		Type:            model.ProviderAliyun,
		Mode:            providerMode,
		Region:          strings.TrimSpace(*region),
		RoleARN:         strings.TrimSpace(*roleARN),
		AccessKeyID:     strings.TrimSpace(*accessKeyID),
		AccessKeySecret: secret,
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var created model.Provider
	if err := client.post(context.Background(), apiPrefix+"/admin/providers", input, &created); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(created)
	}
	fmt.Fprintf(a.Stdout, "Provider created: %s (%s, mode=%s, region=%s)\n", created.ID, created.Name, created.Mode, created.Region)
	fmt.Fprintf(a.Stdout, "Broker AccessKey: %s (secret stored encrypted in the vault)\n", created.AccessKeyIDMasked)
	return nil
}

func (a *App) runProvidersUpdate(args []string) error {
	fs := a.newFlagSet("providers update", `Usage: csg providers update ID [--name N] [--region R] [--role-arn ARN] [--status active|disabled] [--json]
`)
	cf := a.addClientFlags(fs)
	name := fs.String("name", "", "new display name")
	region := fs.String("region", "", "new region")
	roleARN := fs.String("role-arn", "", "new RAM role ARN")
	status := fs.String("status", "", "new status: active | disabled")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("providers update requires exactly one provider ID")
	}
	var input model.UpdateProviderInput
	changed := false
	if *name != "" {
		v := *name
		input.Name = &v
		changed = true
	}
	if *region != "" {
		v := *region
		input.Region = &v
		changed = true
	}
	if *roleARN != "" {
		v := *roleARN
		input.RoleARN = &v
		changed = true
	}
	if *status != "" {
		v := model.ProviderStatus(strings.ToLower(strings.TrimSpace(*status)))
		if v != model.ProviderActive && v != model.ProviderDisabled {
			return usagef("--status must be active or disabled")
		}
		input.Status = &v
		changed = true
	}
	if !changed {
		return usagef("providers update requires at least one of --name, --region, --role-arn, --status")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var updated model.Provider
	if err := client.patch(context.Background(), apiPrefix+"/admin/providers/"+pathEscape(positionals[0]), input, &updated); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(updated)
	}
	printProvider(a.Stdout, updated)
	return nil
}

func (a *App) runProvidersRotate(args []string) error {
	fs := a.newFlagSet("providers rotate", `Usage: csg providers rotate ID --access-key-id ID [--access-key-secret-file PATH | --access-key-secret-stdin] [--json]

Rotates the broker AccessKey once; existing leases and agents are unaffected.
`)
	cf := a.addClientFlags(fs)
	accessKeyID := fs.String("access-key-id", "", "new broker AccessKey ID (required)")
	secretFile := fs.String("access-key-secret-file", "", "read the new broker AccessKey secret from this file")
	secretStdin := fs.Bool("access-key-secret-stdin", false, "read the new broker AccessKey secret from stdin")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("providers rotate requires exactly one provider ID")
	}
	if strings.TrimSpace(*accessKeyID) == "" {
		return usagef("providers rotate requires --access-key-id")
	}
	secret, err := a.readSecretFlags(*secretFile, *secretStdin)
	if err != nil {
		return err
	}
	if secret == "" {
		return usagef("a new AccessKey secret is required (--access-key-secret-file or --access-key-secret-stdin)")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var updated model.Provider
	if err := client.post(context.Background(), apiPrefix+"/admin/providers/"+pathEscape(positionals[0])+"/rotate", model.RotateProviderCredentialInput{
		AccessKeyID:     strings.TrimSpace(*accessKeyID),
		AccessKeySecret: secret,
	}, &updated); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(updated)
	}
	fmt.Fprintf(a.Stdout, "Provider credential rotated: %s (%s)\n", updated.ID, updated.Name)
	fmt.Fprintf(a.Stdout, "Broker AccessKey: %s\n", updated.AccessKeyIDMasked)
	fmt.Fprintln(a.Stdout, "Existing leases are unaffected; new leases mint with the new credential.")
	return nil
}

func (a *App) runProvidersTest(args []string) error {
	fs := a.newFlagSet("providers test", "Usage: csg providers test ID [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("providers test requires exactly one provider ID")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var result providerTestResult
	if err := client.post(context.Background(), apiPrefix+"/admin/providers/"+pathEscape(positionals[0])+"/test", nil, &result); err != nil {
		return err
	}
	if *jsonOut {
		if err := a.printJSON(result); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.Stdout, "provider test: ok=%v message=%s tested_at=%s\n", result.OK, result.Message, fmtTime(result.TestedAt))
	}
	if !result.OK {
		return operationf("provider test failed: %s", result.Message)
	}
	return nil
}

// printProvider renders one provider in human-readable form (never secrets).
func printProvider(w io.Writer, p model.Provider) {
	fmt.Fprintf(w, "id:               %s\n", p.ID)
	fmt.Fprintf(w, "name:             %s\n", p.Name)
	fmt.Fprintf(w, "type:             %s\n", p.Type)
	fmt.Fprintf(w, "mode:             %s\n", p.Mode)
	fmt.Fprintf(w, "region:           %s\n", p.Region)
	fmt.Fprintf(w, "role arn:         %s\n", p.RoleARN)
	fmt.Fprintf(w, "access key:       %s\n", p.AccessKeyIDMasked)
	fmt.Fprintf(w, "status:           %s\n", p.Status)
	if p.LastTestOK != nil {
		fmt.Fprintf(w, "last test:        ok=%v at %s\n", *p.LastTestOK, fmtTimePtr(p.LastTestedAt))
	} else {
		fmt.Fprintf(w, "last test:        never\n")
	}
	fmt.Fprintf(w, "created:          %s\n", fmtTime(p.CreatedAt))
	fmt.Fprintf(w, "updated:          %s\n", fmtTime(p.UpdatedAt))
}

// readSecretFlags reads a secret from exactly one of --*-file or --*-stdin.
// The value is returned to the caller and never logged.
func (a *App) readSecretFlags(file string, fromStdin bool) (string, error) {
	file = strings.TrimSpace(file)
	if file != "" && fromStdin {
		return "", usagef("use only one of the secret file flag or the stdin flag")
	}
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", usagef("cannot read secret file: %v", err)
		}
		secret := strings.TrimRight(string(data), "\r\n")
		if secret == "" {
			return "", usagef("secret file is empty")
		}
		return secret, nil
	}
	if fromStdin {
		if a.Stdin == nil {
			return "", usagef("cannot read secret from stdin")
		}
		data, err := io.ReadAll(io.LimitReader(a.Stdin, 1<<20))
		if err != nil {
			return "", usagef("cannot read secret from stdin: %v", err)
		}
		secret := strings.TrimRight(string(data), "\r\n")
		if secret == "" {
			return "", usagef("no secret on stdin")
		}
		return secret, nil
	}
	return "", nil
}
