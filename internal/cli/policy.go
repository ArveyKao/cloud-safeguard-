package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// runPolicy implements `csg policy show|set` (admin).
func (a *App) runPolicy(args []string) error {
	if len(args) == 0 {
		return usagef("policy requires a subcommand: show | set")
	}
	switch args[0] {
	case "show":
		return a.runPolicyShow(args[1:])
	case "set":
		return a.runPolicySet(args[1:])
	default:
		return usagef("unknown policy subcommand %q (show | set)", args[0])
	}
}

func (a *App) runPolicyShow(args []string) error {
	fs := a.newFlagSet("policy show", "Usage: csg policy show [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("policy show takes no positional arguments")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var settings model.PolicySettings
	if err := client.get(context.Background(), apiPrefix+"/admin/policy", &settings); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(settings)
	}
	printPolicySettings(a.Stdout, settings)
	return nil
}

func (a *App) runPolicySet(args []string) error {
	fs := a.newFlagSet("policy set", `Usage: csg policy set [--auto-approve-max-risk R] [--auto-approve-max-ttl DUR]
                        [--max-lease-ttl DUR] [--pending-timeout DUR] [--max-concurrent N]
                        [--leases-per-minute N] [--require-reason-risk R] [--json]

Only the provided flags change; the rest keep their current values.
`)
	cf := a.addClientFlags(fs)
	autoRisk := fs.String("auto-approve-max-risk", "", "auto-approve capabilities at or below this risk")
	autoTTL := fs.String("auto-approve-max-ttl", "", "auto-approve leases up to this TTL (e.g. 15m)")
	maxLeaseTTL := fs.String("max-lease-ttl", "", "absolute lease TTL ceiling")
	pendingTimeout := fs.String("pending-timeout", "", "how long a pending lease may wait for a decision")
	maxConcurrent := fs.Int("max-concurrent", 0, "maximum concurrently active leases per agent")
	leasesPerMinute := fs.Int("leases-per-minute", 0, "lease requests per minute per agent")
	requireReason := fs.String("require-reason-risk", "", "risk tier at or above which a reason is required")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("policy set takes no positional arguments")
	}

	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	ctx := context.Background()

	var settings model.PolicySettings
	if err := client.get(ctx, apiPrefix+"/admin/policy", &settings); err != nil {
		return err
	}

	changed := false
	if *autoRisk != "" {
		risk, err := parseRiskTier(*autoRisk)
		if err != nil {
			return usagef("--auto-approve-max-risk: %v", err)
		}
		settings.AutoApproveMaxRisk = risk
		changed = true
	}
	if *autoTTL != "" {
		seconds, err := parseDurationSeconds(*autoTTL)
		if err != nil {
			return usagef("--auto-approve-max-ttl: %v", err)
		}
		settings.AutoApproveMaxTTLSeconds = seconds
		changed = true
	}
	if *maxLeaseTTL != "" {
		seconds, err := parseDurationSeconds(*maxLeaseTTL)
		if err != nil {
			return usagef("--max-lease-ttl: %v", err)
		}
		settings.MaxLeaseTTLSeconds = seconds
		changed = true
	}
	if *pendingTimeout != "" {
		seconds, err := parseDurationSeconds(*pendingTimeout)
		if err != nil {
			return usagef("--pending-timeout: %v", err)
		}
		settings.PendingTimeoutSeconds = seconds
		changed = true
	}
	if *maxConcurrent > 0 {
		settings.MaxConcurrentLeasesPerAgent = *maxConcurrent
		changed = true
	}
	if *leasesPerMinute > 0 {
		settings.LeasesPerMinutePerAgent = *leasesPerMinute
		changed = true
	}
	if *requireReason != "" {
		risk, err := parseRiskTier(*requireReason)
		if err != nil {
			return usagef("--require-reason-risk: %v", err)
		}
		settings.RequireReasonForRisk = risk
		changed = true
	}
	if !changed {
		return usagef("policy set requires at least one setting flag")
	}
	if err := settings.Validate(); err != nil {
		return usagef("invalid policy settings: %v", err)
	}

	var updated model.PolicySettings
	if err := client.put(ctx, apiPrefix+"/admin/policy", settings, &updated); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(updated)
	}
	fmt.Fprintln(a.Stdout, "policy updated:")
	printPolicySettings(a.Stdout, updated)
	return nil
}

// printPolicySettings renders the global guardrails.
func printPolicySettings(w io.Writer, s model.PolicySettings) {
	fmt.Fprintf(w, "auto approve max risk:    %s\n", s.AutoApproveMaxRisk)
	fmt.Fprintf(w, "auto approve max ttl:     %s\n", formatSeconds(s.AutoApproveMaxTTLSeconds))
	fmt.Fprintf(w, "max lease ttl:            %s\n", formatSeconds(s.MaxLeaseTTLSeconds))
	fmt.Fprintf(w, "pending timeout:          %s\n", formatSeconds(s.PendingTimeoutSeconds))
	fmt.Fprintf(w, "max concurrent per agent: %d\n", s.MaxConcurrentLeasesPerAgent)
	fmt.Fprintf(w, "leases per minute/agent:  %d\n", s.LeasesPerMinutePerAgent)
	fmt.Fprintf(w, "require reason for risk:  %s\n", s.RequireReasonForRisk)
}
