package cli

import (
	"context"
	"fmt"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// runLongLived implements `csg me long-lived [list|revoke ID]` and, for a
// supervisor, `csg supervisor long-lived [list|revoke ID]` (CONTRACT §17.14).
// Creating one is done in the console only.
func (a *App) runLongLived(args []string, supervisor bool) error {
	sub, rest := subcommand(args)
	scope, base := "me", apiPrefix+"/me/long-lived"
	if supervisor {
		scope, base = "supervisor", apiPrefix+"/supervisor/long-lived"
	}
	fs := a.newFlagSet(scope+" long-lived", `Usage: csg `+scope+` long-lived [list] [--json]
       csg `+scope+` long-lived revoke ID

Long-lived credentials: cloud users with an access key that does not expire.
Revoking deletes the key, its policy and the user in the cloud. Creating one
is done in the console only.
`)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, rest)
	if err != nil {
		return err
	}
	client, _, err := a.personAPI()
	if err != nil {
		return err
	}
	ctx := context.Background()
	switch sub {
	case "", "list":
		var list model.ListResponse[model.LongLivedCredential]
		if err := client.get(ctx, base, &list); err != nil {
			return err
		}
		if *jsonOut {
			return a.printJSON(list)
		}
		rows := [][]string{}
		for _, c := range list.Items {
			scopeName := c.ResourceName
			if scopeName == "" {
				scopeName = "all"
			}
			rows = append(rows, []string{c.ID, displayString(c.CloudAccountID), c.Permission + " " + c.Resource + " (" + displayString(scopeName) + ")",
				displayString(c.CloudUser), displayString(c.OwnerName), string(c.Status)})
		}
		writeTable(a.Stdout, []string{"ID", "CLOUD ACCOUNT", "ACCESS", "CLOUD USER", "OWNER", "STATUS"}, rows)
		return nil
	case "revoke":
		if len(positionals) != 1 {
			return usagef("long-lived revoke takes one ID")
		}
		var out model.LongLivedCredential
		if err := client.post(ctx, base+"/"+pathEscape(positionals[0])+"/revoke", map[string]any{}, &out); err != nil {
			return err
		}
		if *jsonOut {
			return a.printJSON(out)
		}
		fmt.Fprintf(a.Stdout, "%s: %s", out.ID, out.Status)
		if out.FailureReason != "" {
			fmt.Fprintf(a.Stdout, " (%s)", displayString(out.FailureReason))
		}
		fmt.Fprintln(a.Stdout)
		return nil
	case "create":
		return usagef("a long-lived credential is created in the console only, where its secret is shown once")
	}
	return usagef("unknown long-lived subcommand %q (list, revoke)", sub)
}
