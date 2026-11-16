package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// runLeases implements `csg leases mine` and `csg leases get`: the agent's
// own requests.
func (a *App) runLeases(args []string) error {
	if len(args) == 0 {
		return usagef("leases requires a subcommand: mine | get ID")
	}
	switch args[0] {
	case "mine":
		return a.runLeasesMine(args[1:])
	case "get":
		return a.runLeasesGet(args[1:])
	default:
		return usagef("unknown leases subcommand %q (mine | get ID)", args[0])
	}
}

func (a *App) runLeasesMine(args []string) error {
	fs := a.newFlagSet("leases mine", "Usage: csg leases mine [--status S] [--json]\n")
	cf := a.addClientFlags(fs)
	status := fs.String("status", "", "filter by lease status")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("leases mine takes no positional arguments")
	}
	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	query := url.Values{}
	if *status != "" {
		if !model.LeaseStatus(strings.ToLower(*status)).Valid() {
			return usagef("unknown --status %q", *status)
		}
		query.Set("status", strings.ToLower(*status))
	}
	path := apiPrefix + "/agent/leases"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var res model.ListResponse[model.Lease]
	if err := client.get(context.Background(), path, &res); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(res)
	}
	printLeaseTable(a.Stdout, res.Items)
	return nil
}

func (a *App) runLeasesGet(args []string) error {
	fs := a.newFlagSet("leases get", "Usage: csg leases get ID [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("leases get requires exactly one lease ID")
	}
	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	var lease model.Lease
	if err := client.get(context.Background(), apiPrefix+"/agent/leases/"+pathEscape(positionals[0]), &lease); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(lease)
	}
	printLeaseDetail(a.Stdout, lease)
	return nil
}

// printLeaseTable renders the lease list view.
func printLeaseTable(w io.Writer, leases []model.Lease) {
	if len(leases) == 0 {
		fmt.Fprintln(w, "no leases")
		return
	}
	rows := make([][]string, 0, len(leases))
	for _, l := range leases {
		rows = append(rows, []string{
			l.ID,
			string(l.Status),
			l.AgentName,
			l.CapabilityName,
			string(l.Risk),
			formatSeconds(l.EffectiveTTLSeconds),
			fmtTime(l.CreatedAt),
			fmtTimePtr(l.ExpiresAt),
		})
	}
	writeTable(w, []string{"ID", "STATUS", "AGENT", "CAPABILITY", "RISK", "TTL", "CREATED", "EXPIRES"}, rows)
}

// printLeaseDetail renders one lease with its explainable decision.
func printLeaseDetail(w io.Writer, l model.Lease) {
	fmt.Fprintf(w, "id:               %s\n", l.ID)
	fmt.Fprintf(w, "status:           %s\n", l.Status)
	fmt.Fprintf(w, "agent:            %s (%s)\n", l.AgentName, l.AgentID)
	fmt.Fprintf(w, "capability:       %s (%s)\n", l.CapabilityName, l.CapabilityID)
	fmt.Fprintf(w, "provider:         %s (%s)\n", l.ProviderName, l.ProviderMode)
	fmt.Fprintf(w, "risk:             %s\n", l.Risk)
	if len(l.Params) > 0 {
		keys := make([]string, 0, len(l.Params))
		for k := range l.Params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+l.Params[k])
		}
		fmt.Fprintf(w, "params:           %s\n", strings.Join(parts, ", "))
	}
	if l.Reason != "" {
		fmt.Fprintf(w, "reason:           %s\n", l.Reason)
	}
	fmt.Fprintf(w, "break glass:      %s\n", yesNo(l.BreakGlass))
	fmt.Fprintf(w, "requested ttl:    %s\n", formatSeconds(l.RequestedTTLSeconds))
	fmt.Fprintf(w, "effective ttl:    %s\n", formatSeconds(l.EffectiveTTLSeconds))
	fmt.Fprintf(w, "decision:         %s\n", l.Decision.Outcome)
	for _, reason := range l.Decision.Reasons {
		fmt.Fprintf(w, "  - %s [%s]: %s\n", reason.Rule, reason.Outcome, reason.Detail)
	}
	if l.ApprovedBy != "" {
		fmt.Fprintf(w, "approved by:      %s\n", l.ApprovedBy)
	}
	if l.ApprovalNote != "" {
		fmt.Fprintf(w, "approval note:    %s\n", l.ApprovalNote)
	}
	if l.DeniedReason != "" {
		fmt.Fprintf(w, "denied reason:    %s\n", l.DeniedReason)
	}
	if l.FailureReason != "" {
		fmt.Fprintf(w, "failure reason:   %s\n", l.FailureReason)
	}
	if l.RevokeReason != "" {
		fmt.Fprintf(w, "revoke reason:    %s\n", l.RevokeReason)
	}
	fmt.Fprintf(w, "credential:       available=%v fingerprint=%s\n", l.CredentialAvailable, orDash(l.CredentialFingerprint))
	fmt.Fprintf(w, "session name:     %s\n", orDash(l.SessionName))
	fmt.Fprintf(w, "created:          %s\n", fmtTime(l.CreatedAt))
	fmt.Fprintf(w, "approved:         %s\n", fmtTimePtr(l.ApprovedAt))
	fmt.Fprintf(w, "issued:           %s\n", fmtTimePtr(l.IssuedAt))
	fmt.Fprintf(w, "expires:          %s\n", fmtTimePtr(l.ExpiresAt))
	fmt.Fprintf(w, "revoked:          %s\n", fmtTimePtr(l.RevokedAt))
}

// orDash returns "-" for empty strings.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
