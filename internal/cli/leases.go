package cli

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// providerTestResult is the payload of POST /admin/providers/{id}/test.
type providerTestResult struct {
	OK       bool      `json:"ok"`
	Message  string    `json:"message"`
	TestedAt time.Time `json:"tested_at"`
}

// runLeases implements the admin lease commands plus the agent-side `leases mine`.
func (a *App) runLeases(args []string) error {
	if len(args) == 0 {
		return usagef("leases requires a subcommand: list | mine | get ID | approve ID | deny ID | revoke ID")
	}
	switch args[0] {
	case "list":
		return a.runLeasesList(args[1:])
	case "mine":
		return a.runLeasesMine(args[1:])
	case "get":
		return a.runLeasesGet(args[1:])
	case "approve":
		return a.runLeasesApprove(args[1:])
	case "deny":
		return a.runLeasesDeny(args[1:])
	case "revoke":
		return a.runLeasesRevoke(args[1:])
	default:
		return usagef("unknown leases subcommand %q", args[0])
	}
}

func (a *App) runLeasesList(args []string) error {
	fs := a.newFlagSet("leases list", `Usage: csg leases list [--status S] [--agent ID] [--capability ID] [--limit N] [--offset N] [--json]
`)
	cf := a.addClientFlags(fs)
	status := fs.String("status", "", "filter by lease status")
	agentID := fs.String("agent", "", "filter by agent ID")
	capabilityID := fs.String("capability", "", "filter by capability ID")
	limit := fs.Int("limit", 0, "page size (default 50, max 200)")
	offset := fs.Int("offset", 0, "page offset")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("leases list takes no positional arguments")
	}
	query := url.Values{}
	if *status != "" {
		if !model.LeaseStatus(strings.ToLower(*status)).Valid() {
			return usagef("unknown --status %q", *status)
		}
		query.Set("status", strings.ToLower(*status))
	}
	if *agentID != "" {
		query.Set("agent_id", *agentID)
	}
	if *capabilityID != "" {
		query.Set("capability_id", *capabilityID)
	}
	if *limit > 0 {
		query.Set("limit", strconv.Itoa(*limit))
	}
	if *offset > 0 {
		query.Set("offset", strconv.Itoa(*offset))
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var res model.ListResponse[model.Lease]
	path := apiPrefix + "/admin/leases"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	if err := client.get(context.Background(), path, &res); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(res)
	}
	printLeaseTable(a.Stdout, res.Items)
	return nil
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
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var lease model.Lease
	if err := client.get(context.Background(), apiPrefix+"/admin/leases/"+pathEscape(positionals[0]), &lease); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(lease)
	}
	printLeaseDetail(a.Stdout, lease)
	return nil
}

func (a *App) runLeasesApprove(args []string) error {
	fs := a.newFlagSet("leases approve", "Usage: csg leases approve ID [--ttl DUR] [--note TEXT] [--json]\n")
	cf := a.addClientFlags(fs)
	ttl := fs.String("ttl", "", "approved TTL (default: the requested/effective TTL)")
	note := fs.String("note", "", "approval note")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("leases approve requires exactly one lease ID")
	}
	ttlSeconds, err := parseOptionalDurationSeconds(*ttl)
	if err != nil {
		return usagef("--ttl: %v", err)
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var lease model.Lease
	if err := client.post(context.Background(), apiPrefix+"/admin/leases/"+pathEscape(positionals[0])+"/approve",
		model.ApproveLeaseInput{TTLSeconds: ttlSeconds, Note: *note}, &lease); err != nil {
		return err
	}
	if *jsonOut {
		if err := a.printJSON(lease); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.Stdout, "lease %s is now %s\n", lease.ID, lease.Status)
		printLeaseDetail(a.Stdout, lease)
	}
	if lease.Status == model.LeaseFailed {
		return operationf("lease %s could not mint a credential: %s", lease.ID, lease.FailureReason)
	}
	return nil
}

func (a *App) runLeasesDeny(args []string) error {
	fs := a.newFlagSet("leases deny", "Usage: csg leases deny ID --reason TEXT [--json]\n")
	cf := a.addClientFlags(fs)
	reason := fs.String("reason", "", "denial reason (required, 1-500 chars)")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("leases deny requires exactly one lease ID")
	}
	trimmed := strings.TrimSpace(*reason)
	if trimmed == "" {
		return usagef("leases deny requires --reason")
	}
	if len(trimmed) > 500 {
		return usagef("--reason must be at most 500 characters")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var lease model.Lease
	if err := client.post(context.Background(), apiPrefix+"/admin/leases/"+pathEscape(positionals[0])+"/deny",
		model.DenyLeaseInput{Reason: trimmed}, &lease); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(lease)
	}
	fmt.Fprintf(a.Stdout, "lease %s denied: %s\n", lease.ID, lease.DeniedReason)
	return nil
}

func (a *App) runLeasesRevoke(args []string) error {
	fs := a.newFlagSet("leases revoke", "Usage: csg leases revoke ID [--reason TEXT] [--json]\n")
	cf := a.addClientFlags(fs)
	reason := fs.String("reason", "revoked by operator", "revocation reason")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("leases revoke requires exactly one lease ID")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var lease model.Lease
	if err := client.post(context.Background(), apiPrefix+"/admin/leases/"+pathEscape(positionals[0])+"/revoke",
		model.RevokeLeaseInput{Reason: *reason}, &lease); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(lease)
	}
	fmt.Fprintf(a.Stdout, "lease %s revoked\n", lease.ID)
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
