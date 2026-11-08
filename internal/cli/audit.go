package cli

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// runAudit implements `csg audit list|verify` (admin).
func (a *App) runAudit(args []string) error {
	if len(args) == 0 {
		return usagef("audit requires a subcommand: list | verify")
	}
	switch args[0] {
	case "list":
		return a.runAuditList(args[1:])
	case "verify":
		return a.runAuditVerify(args[1:])
	default:
		return usagef("unknown audit subcommand %q (list | verify)", args[0])
	}
}

func (a *App) runAuditList(args []string) error {
	fs := a.newFlagSet("audit list", `Usage: csg audit list [--action A] [--severity S] [--limit N] [--offset N] [--json]
`)
	cf := a.addClientFlags(fs)
	action := fs.String("action", "", "filter by action (e.g. lease.denied)")
	severity := fs.String("severity", "", "filter by severity: info | warning | critical")
	limit := fs.Int("limit", 0, "page size (default 50, max 200)")
	offset := fs.Int("offset", 0, "page offset")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("audit list takes no positional arguments")
	}
	query := url.Values{}
	if *action != "" {
		query.Set("action", *action)
	}
	if *severity != "" {
		sev := strings.ToLower(strings.TrimSpace(*severity))
		if sev != "info" && sev != "warning" && sev != "critical" {
			return usagef("--severity must be info, warning or critical")
		}
		query.Set("severity", sev)
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
	path := apiPrefix + "/admin/audit"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var res model.ListResponse[model.AuditEvent]
	if err := client.get(context.Background(), path, &res); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(res)
	}
	if len(res.Items) == 0 {
		fmt.Fprintln(a.Stdout, "no audit events")
		return nil
	}
	rows := make([][]string, 0, len(res.Items))
	for _, ev := range res.Items {
		rows = append(rows, []string{
			strconv.FormatInt(ev.Seq, 10),
			fmtTime(ev.Time),
			ev.Action,
			actorLabel(ev),
			ev.Status,
			ev.Severity,
			targetLabel(ev),
		})
	}
	writeTable(a.Stdout, []string{"SEQ", "TIME", "ACTION", "ACTOR", "STATUS", "SEVERITY", "TARGET"}, rows)
	return nil
}

func (a *App) runAuditVerify(args []string) error {
	fs := a.newFlagSet("audit verify", "Usage: csg audit verify [--json]\n")
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("audit verify takes no positional arguments")
	}
	client, err := a.adminClient(cf)
	if err != nil {
		return err
	}
	var res model.AuditVerifyResult
	if err := client.get(context.Background(), apiPrefix+"/admin/audit/verify", &res); err != nil {
		return err
	}
	if *jsonOut {
		if err := a.printJSON(res); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(a.Stdout, "audit chain: ok=%v events=%d\n", res.OK, res.Events)
		if !res.OK {
			fmt.Fprintf(a.Stdout, "first invalid seq: %d\n", res.FirstInvalidSeq)
		}
		if res.Message != "" {
			fmt.Fprintf(a.Stdout, "message: %s\n", res.Message)
		}
	}
	if !res.OK {
		return operationf("audit chain verification failed at seq %d", res.FirstInvalidSeq)
	}
	return nil
}

// actorLabel renders the actor column for an audit event.
func actorLabel(ev model.AuditEvent) string {
	switch {
	case ev.ActorName != "" && ev.ActorID != "" && ev.ActorName != ev.ActorID:
		return ev.ActorName + " (" + ev.ActorID + ")"
	case ev.ActorName != "":
		return ev.ActorName
	case ev.ActorID != "":
		return ev.ActorID
	default:
		return "-"
	}
}

// targetLabel renders the target column for an audit event.
func targetLabel(ev model.AuditEvent) string {
	switch {
	case ev.TargetType != "" && ev.TargetID != "":
		return ev.TargetType + "/" + ev.TargetID
	case ev.TargetID != "":
		return ev.TargetID
	default:
		return "-"
	}
}
