package cli

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Supervisor commands over a command-line session (CONTRACT §17.9). Every
// supervisor route has a command except adding a cloud account, which is
// done in the console. Changes that raise access take --code (or ask for it
// in a terminal).

// supervisorAPI is the person's client for supervisor routes. Whether the
// person is a supervisor is the server's answer (403), not a flag saved at
// sign-in that may be out of date.
func (a *App) supervisorAPI() (*apiClient, error) {
	c, _, err := a.personAPI()
	return c, err
}

func (a *App) runSupervisorCommands(args []string) error {
	area, rest := args[0], args[1:]
	switch area {
	case "people":
		return a.runSupPeople(rest)
	case "roles":
		return a.runSupRoles(rest)
	case "accounts":
		return a.runSupAccounts(rest)
	case "settings":
		return a.runSupSettings(rest)
	case "audit":
		return a.runSupAudit(rest)
	case "requests":
		return a.runSupRequests(rest)
	case "long-lived":
		return a.runLongLived(rest, true)
	}
	return usagef("unknown supervisor area %q (people, roles, accounts, settings, audit, requests, long-lived, recover)", area)
}

// supFlags are the flags shared by supervisor subcommands.
type supFlags struct {
	code    *string
	jsonOut *bool
}

func (a *App) supFlagSet(name, usage string) (*flagSet, supFlags) {
	fs := a.newFlagSet(name, usage)
	return fs, supFlags{
		code:    fs.String("code", "", "code from your authenticator app, for a change that raises access"),
		jsonOut: fs.Bool("json", false, "print JSON"),
	}
}

func subcommand(args []string) (string, []string) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "list", args
	}
	return args[0], args[1:]
}

// ---- people ----

func (a *App) runSupPeople(args []string) error {
	sub, rest := subcommand(args)
	fs, f := a.supFlagSet("supervisor people "+sub, `Usage: csg supervisor people [list]
       csg supervisor people add USERNAME [--display-name NAME] [--supervisor] [--code CODE]
       csg supervisor people suspend|activate|reset|make-supervisor|remove-supervisor USERNAME [--code CODE]

add and reset print a one-time setup code to give to the person; whoever holds
it holds the account. add, activate, reset and make-supervisor raise access and
need a code from your authenticator app.
`)
	displayName := fs.String("display-name", "", "display name (add)")
	supervisor := fs.Bool("supervisor", false, "make the new person a supervisor (add)")
	positionals, err := parseFlags(fs, rest)
	if err != nil {
		return err
	}
	c, err := a.supervisorAPI()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if sub == "list" {
		var list model.ListResponse[model.Person]
		if err := c.get(ctx, apiPrefix+"/supervisor/people", &list); err != nil {
			return err
		}
		if *f.jsonOut {
			return a.printJSON(list)
		}
		rows := [][]string{}
		for _, p := range sortedPeople(list.Items) {
			rows = append(rows, []string{p.Username, displayString(p.DisplayName), string(p.Status), yesNo(p.Supervisor), fmtTimePtr(p.LastLoginAt)})
		}
		writeTable(a.Stdout, []string{"USERNAME", "NAME", "STATUS", "SUPERVISOR", "LAST SIGN-IN"}, rows)
		return nil
	}
	if len(positionals) != 1 {
		return usagef("supervisor people %s takes one username", sub)
	}
	if sub == "add" {
		var out model.PersonWithSetupCode
		in := model.CreatePersonInput{Username: positionals[0], DisplayName: *displayName, Supervisor: *supervisor}
		if err := a.raising(c, *f.code, http.MethodPost, apiPrefix+"/supervisor/people", in, &out); err != nil {
			return err
		}
		if *f.jsonOut {
			return a.printJSON(out)
		}
		a.printSetupCode("Person added", out)
		return nil
	}
	person, err := a.findPerson(c, positionals[0])
	if err != nil {
		return err
	}
	path := apiPrefix + "/supervisor/people/" + pathEscape(person.ID)
	var update model.UpdatePersonInput
	yes, no := true, false
	active, suspended := model.PersonActive, model.PersonSuspended
	switch sub {
	case "reset":
		var out model.PersonWithSetupCode
		if err := a.raising(c, *f.code, http.MethodPost, path+"/reset", map[string]any{}, &out); err != nil {
			return err
		}
		if *f.jsonOut {
			return a.printJSON(out)
		}
		a.printSetupCode("Person reset", out)
		return nil
	case "suspend":
		update.Status = &suspended
	case "activate":
		update.Status = &active
	case "make-supervisor":
		update.Supervisor = &yes
	case "remove-supervisor":
		update.Supervisor = &no
	case "allow-long-lived":
		update.LongLived = &yes
	case "disallow-long-lived":
		update.LongLived = &no
	default:
		return usagef("unknown people subcommand %q", sub)
	}
	var out model.Person
	if err := a.raising(c, *f.code, http.MethodPatch, path, update, &out); err != nil {
		return err
	}
	if *f.jsonOut {
		return a.printJSON(out)
	}
	fmt.Fprintf(a.Stdout, "%s: status %s, supervisor %s, long-lived credentials %s\n", out.Username, out.Status, yesNo(out.Supervisor),
		yesNo(out.Supervisor || out.LongLived))
	return nil
}

// ---- roles ----

func (a *App) runSupRoles(args []string) error {
	sub, rest := subcommand(args)
	fs, f := a.supFlagSet("supervisor roles "+sub, `Usage: csg supervisor roles [list] [--account ACCOUNT]
       csg supervisor roles set ACCOUNT USERNAME guest|member|administrator [--code CODE]
       csg supervisor roles remove ACCOUNT USERNAME

ACCOUNT is a cloud account ID, an account's ID or its name. A role above guest
needs a code from your authenticator app. Supervisors are Administrator on
every account without a role.
`)
	accountFilter := fs.String("account", "", "only this cloud account (list)")
	positionals, err := parseFlags(fs, rest)
	if err != nil {
		return err
	}
	c, err := a.supervisorAPI()
	if err != nil {
		return err
	}
	ctx := context.Background()
	switch sub {
	case "list":
		path := apiPrefix + "/supervisor/bindings"
		if *accountFilter != "" {
			acct, err := a.findAccount(c, *accountFilter)
			if err != nil {
				return err
			}
			path += "?provider_id=" + url.QueryEscape(acct.ID)
		}
		var list model.ListResponse[model.RoleBinding]
		if err := c.get(ctx, path, &list); err != nil {
			return err
		}
		if *f.jsonOut {
			return a.printJSON(list)
		}
		var people model.ListResponse[model.Person]
		var accounts model.ListResponse[model.Provider]
		_ = c.get(ctx, apiPrefix+"/supervisor/people", &people)
		_ = c.get(ctx, apiPrefix+"/supervisor/accounts", &accounts)
		names := map[string]string{}
		for _, p := range people.Items {
			names[p.ID] = p.Username
		}
		for _, p := range accounts.Items {
			names[p.ID] = p.Name + " " + p.CloudAccountID
		}
		rows := [][]string{}
		for _, b := range list.Items {
			rows = append(rows, []string{orDash(names[b.ProviderID]), orDash(names[b.PersonID]), string(b.Role)})
		}
		writeTable(a.Stdout, []string{"CLOUD ACCOUNT", "PERSON", "ROLE"}, rows)
		return nil
	case "set", "remove":
		want := 2
		if sub == "set" {
			want = 3
		}
		if len(positionals) != want {
			return usagef("supervisor roles %s takes ACCOUNT USERNAME%s", sub, map[bool]string{true: " ROLE", false: ""}[sub == "set"])
		}
		acct, err := a.findAccount(c, positionals[0])
		if err != nil {
			return err
		}
		person, err := a.findPerson(c, positionals[1])
		if err != nil {
			return err
		}
		path := apiPrefix + "/supervisor/accounts/" + pathEscape(acct.ID) + "/people/" + pathEscape(person.ID)
		if sub == "remove" {
			if err := c.do(ctx, http.MethodDelete, path, nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(a.Stdout, "%s has no role on %s any more\n", person.Username, acct.Name)
			return nil
		}
		role := model.Role(strings.ToLower(positionals[2]))
		if !role.Valid() {
			return usagef("role must be guest, member or administrator")
		}
		var out model.RoleBinding
		if err := a.raising(c, *f.code, http.MethodPut, path, model.PutBindingInput{Role: role}, &out); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "%s is %s on %s\n", person.Username, out.Role, acct.Name)
		return nil
	}
	return usagef("unknown roles subcommand %q", sub)
}

// ---- cloud accounts ----

func (a *App) runSupAccounts(args []string) error {
	sub, rest := subcommand(args)
	fs, f := a.supFlagSet("supervisor accounts "+sub, `Usage: csg supervisor accounts [list]
       csg supervisor accounts show|test|disable ACCOUNT
       csg supervisor accounts rename ACCOUNT NAME
       csg supervisor accounts enable ACCOUNT [--code CODE]
       csg supervisor accounts set-region ACCOUNT REGION [--code CODE]
       csg supervisor accounts set-role-arn ACCOUNT ARN [--code CODE]
       csg supervisor accounts rotate ACCOUNT --key-id ID --code CODE < secret   (secret piped in)

Adding a cloud account is done in the console only. rotate reads the new
AccessKey secret from a pipe or file on standard input (never from the
terminal), so its --code must be given as a flag.
`)
	keyID := fs.String("key-id", "", "the new AccessKey ID (rotate)")
	positionals, err := parseFlags(fs, rest)
	if err != nil {
		return err
	}
	c, err := a.supervisorAPI()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if sub == "list" {
		var list model.ListResponse[model.Provider]
		if err := c.get(ctx, apiPrefix+"/supervisor/accounts", &list); err != nil {
			return err
		}
		if *f.jsonOut {
			return a.printJSON(list)
		}
		rows := [][]string{}
		for _, p := range list.Items {
			rows = append(rows, []string{orDash(p.CloudAccountID), p.Name, string(p.Mode), p.Region, string(p.Status), p.AccessKeyIDMasked})
		}
		writeTable(a.Stdout, []string{"CLOUD ACCOUNT", "NAME", "MODE", "REGION", "STATUS", "ACCESS KEY"}, rows)
		return nil
	}
	if sub == "add" {
		return usagef("adding a cloud account is done in the console only (Cloud accounts → + Add cloud account)")
	}
	if len(positionals) < 1 {
		return usagef("supervisor accounts %s takes an ACCOUNT", sub)
	}
	acct, err := a.findAccount(c, positionals[0])
	if err != nil {
		return err
	}
	path := apiPrefix + "/supervisor/accounts/" + pathEscape(acct.ID)
	arg := func() (string, error) {
		if len(positionals) != 2 {
			return "", usagef("supervisor accounts %s takes ACCOUNT and one value", sub)
		}
		return positionals[1], nil
	}
	var update model.UpdateProviderInput
	switch sub {
	case "show":
		var p model.Provider
		if err := c.get(ctx, path, &p); err != nil {
			return err
		}
		return a.printJSON(p)
	case "test":
		var res struct {
			OK      bool   `json:"ok"`
			Message string `json:"message"`
		}
		if err := c.post(ctx, path+"/test", map[string]any{}, &res); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "%s: %s\n", map[bool]string{true: "ok", false: "failed"}[res.OK], displayString(res.Message))
		if !res.OK {
			return silentExit(ExitOperationErr)
		}
		return nil
	case "disable", "enable":
		status := model.ProviderDisabled
		if sub == "enable" {
			status = model.ProviderActive
		}
		update.Status = &status
	case "rename":
		v, err := arg()
		if err != nil {
			return err
		}
		update.Name = &v
	case "set-region":
		v, err := arg()
		if err != nil {
			return err
		}
		update.Region = &v
	case "set-role-arn":
		v, err := arg()
		if err != nil {
			return err
		}
		update.RoleARN = &v
	case "rotate":
		if strings.TrimSpace(*keyID) == "" || strings.TrimSpace(*f.code) == "" {
			return usagef("rotate needs --key-id and --code; the new secret is read from standard input")
		}
		// Typed at a terminal, the secret would be echoed and stay in the
		// scrollback: it must come from a file or a pipe.
		if a.stdinIsTerminal() {
			return usagef("pipe the new AccessKey secret in, e.g. from your password manager or `< secret.txt`; it is not read from the terminal, where it would be shown")
		}
		secret, err := bufio.NewReader(a.Stdin).ReadString('\n')
		secret = strings.TrimRight(secret, "\r\n")
		if secret == "" {
			if err != nil {
				return usagef("no AccessKey secret on standard input")
			}
			return usagef("the AccessKey secret on standard input is empty")
		}
		var out model.Provider
		if err := a.raising(c, *f.code, http.MethodPost, path+"/rotate",
			model.RotateProviderCredentialInput{AccessKeyID: strings.TrimSpace(*keyID), AccessKeySecret: secret}, &out); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "%s: AccessKey replaced (%s). Run csg supervisor accounts test %s\n", out.Name, out.AccessKeyIDMasked, positionals[0])
		return nil
	default:
		return usagef("unknown accounts subcommand %q", sub)
	}
	var out model.Provider
	if err := a.raising(c, *f.code, http.MethodPatch, path, update, &out); err != nil {
		return err
	}
	if *f.jsonOut {
		return a.printJSON(out)
	}
	fmt.Fprintf(a.Stdout, "%s (%s): %s, region %s, role %s\n", out.Name, orDash(out.CloudAccountID), out.Status, out.Region, out.RoleARN)
	return nil
}

// ---- settings ----

func (a *App) runSupSettings(args []string) error {
	sub, rest := subcommand(args)
	if sub == "list" {
		sub = "show"
	}
	fs, f := a.supFlagSet("supervisor settings "+sub, `Usage: csg supervisor settings [show]
       csg supervisor settings set [--max-validity DUR] [--approval-timeout DUR]
                                   [--max-credentials N] [--requests-per-minute N]
                                   [--max-refresh DUR] [--code CODE]

Values not given are left as they are. Raising any value needs a code from
your authenticator app; lowering does not.
`)
	maxValidity := fs.String("max-validity", "", "longest validity of a credential")
	timeout := fs.String("approval-timeout", "", "how long a request waits for approval")
	maxCreds := fs.String("max-credentials", "", "credentials and waiting requests per agent")
	perMinute := fs.String("requests-per-minute", "", "requests per agent per minute")
	maxRefresh := fs.String("max-refresh", "", "longest an agent may keep refreshing one request's credential")
	if _, err := parseFlags(fs, rest); err != nil {
		return err
	}
	c, err := a.supervisorAPI()
	if err != nil {
		return err
	}
	ctx := context.Background()
	var s model.PolicySettings
	if err := c.get(ctx, apiPrefix+"/supervisor/settings", &s); err != nil {
		return err
	}
	if sub == "set" {
		if *maxValidity != "" {
			if s.MaxLeaseTTLSeconds, err = parseDurationSeconds(*maxValidity); err != nil {
				return usagef("--max-validity: %v", err)
			}
		}
		if *timeout != "" {
			if s.PendingTimeoutSeconds, err = parseDurationSeconds(*timeout); err != nil {
				return usagef("--approval-timeout: %v", err)
			}
		}
		if *maxRefresh != "" {
			if s.MaxRefreshLifetimeSeconds, err = parseDurationSeconds(*maxRefresh); err != nil {
				return usagef("--max-refresh: %v", err)
			}
		}
		for _, v := range []struct {
			name, value string
			dst         *int
		}{
			{"--max-credentials", *maxCreds, &s.MaxConcurrentLeasesPerAgent},
			{"--requests-per-minute", *perMinute, &s.LeasesPerMinutePerAgent},
		} {
			if v.value == "" {
				continue
			}
			n, err := strconv.Atoi(v.value)
			if err != nil || n <= 0 {
				return usagef("%s takes a positive number", v.name)
			}
			*v.dst = n
		}
		if err := a.raising(c, *f.code, http.MethodPut, apiPrefix+"/supervisor/settings", s, &s); err != nil {
			return err
		}
	} else if sub != "show" {
		return usagef("unknown settings subcommand %q (show, set)", sub)
	}
	if *f.jsonOut {
		return a.printJSON(s)
	}
	fmt.Fprintf(a.Stdout, "longest validity:           %s\n", formatSeconds(s.MaxLeaseTTLSeconds))
	fmt.Fprintf(a.Stdout, "approval timeout:           %s\n", formatSeconds(s.PendingTimeoutSeconds))
	fmt.Fprintf(a.Stdout, "credentials per agent:      %d\n", s.MaxConcurrentLeasesPerAgent)
	fmt.Fprintf(a.Stdout, "requests per agent/minute:  %d\n", s.LeasesPerMinutePerAgent)
	fmt.Fprintf(a.Stdout, "longest refresh window:     %s\n", formatSeconds(s.MaxRefreshLifetimeSeconds))
	return nil
}

// ---- audit ----

func (a *App) runSupAudit(args []string) error {
	sub, rest := subcommand(args)
	fs, f := a.supFlagSet("supervisor audit "+sub, "Usage: csg supervisor audit [list] [--action A] [--limit N]\n       csg supervisor audit verify\n")
	action := fs.String("action", "", "only events with this action, e.g. lease.revoked")
	limit := fs.Int("limit", 50, "number of events (at most 200)")
	if _, err := parseFlags(fs, rest); err != nil {
		return err
	}
	c, err := a.supervisorAPI()
	if err != nil {
		return err
	}
	ctx := context.Background()
	if sub == "verify" {
		var res model.AuditVerifyResult
		if err := c.get(ctx, apiPrefix+"/supervisor/audit/verify", &res); err != nil {
			return err
		}
		if *f.jsonOut {
			return a.printJSON(res)
		}
		if !res.OK {
			fmt.Fprintf(a.Stdout, "audit chain broken at event %d: %s\n", res.FirstInvalidSeq, displayString(res.Message))
			return silentExit(ExitOperationErr)
		}
		fmt.Fprintf(a.Stdout, "audit chain verified: %d events\n", res.Events)
		return nil
	}
	if sub != "list" {
		return usagef("unknown audit subcommand %q (list, verify)", sub)
	}
	q := url.Values{}
	q.Set("limit", strconv.Itoa(*limit))
	if *action != "" {
		q.Set("action", *action)
	}
	var list model.ListResponse[model.AuditEvent]
	if err := c.get(ctx, apiPrefix+"/supervisor/audit?"+q.Encode(), &list); err != nil {
		return err
	}
	if *f.jsonOut {
		return a.printJSON(list)
	}
	rows := [][]string{}
	for _, ev := range list.Items {
		rows = append(rows, []string{fmtTime(ev.Time), ev.ActorType + " " + displayString(ev.ActorName), ev.Action, ev.Status, ev.TargetID})
	}
	writeTable(a.Stdout, []string{"TIME", "WHO", "WHAT", "OUTCOME", "TARGET"}, rows)
	return nil
}

// ---- requests (the emergency stop) ----

func (a *App) runSupRequests(args []string) error {
	sub, rest := subcommand(args)
	fs, f := a.supFlagSet("supervisor requests "+sub, `Usage: csg supervisor requests [list] [--status S]
       csg supervisor requests deny ID --reason TEXT
       csg supervisor requests revoke ID [--reason TEXT]

A supervisor can stop any request or credential, never approve one for
someone else's agent.
`)
	status := fs.String("status", "", "only requests in this state (list)")
	reason := fs.String("reason", "", "recorded in the activity log")
	positionals, err := parseFlags(fs, rest)
	if err != nil {
		return err
	}
	c, err := a.supervisorAPI()
	if err != nil {
		return err
	}
	ctx := context.Background()
	switch sub {
	case "list":
		path := apiPrefix + "/supervisor/leases"
		if *status != "" {
			path += "?status=" + url.QueryEscape(*status)
		}
		var list model.ListResponse[model.Lease]
		if err := c.get(ctx, path, &list); err != nil {
			return err
		}
		if *f.jsonOut {
			return a.printJSON(list)
		}
		printLeaseTable(a.Stdout, list.Items)
		return nil
	case "deny", "revoke":
		if len(positionals) != 1 {
			return usagef("supervisor requests %s takes one ID", sub)
		}
		var body any
		if sub == "deny" {
			if strings.TrimSpace(*reason) == "" {
				return usagef("deny needs --reason")
			}
			body = model.DenyLeaseInput{Reason: strings.TrimSpace(*reason)}
		} else {
			body = model.RevokeLeaseInput{Reason: strings.TrimSpace(*reason)}
		}
		var out model.Lease
		if err := c.post(ctx, apiPrefix+"/supervisor/leases/"+pathEscape(positionals[0])+"/"+sub, body, &out); err != nil {
			return err
		}
		fmt.Fprintf(a.Stdout, "request %s is %s\n", out.ID, out.Status)
		return nil
	case "approve":
		return usagef("a supervisor cannot approve a request; only the agent's owner can, in the console")
	}
	return usagef("unknown requests subcommand %q", sub)
}
