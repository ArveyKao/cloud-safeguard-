package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// agentMe is the payload of GET /api/v1/agent/me.
type agentMe struct {
	Agent        model.Agent `json:"agent"`
	ActiveLeases int         `json:"active_leases"`
	ServerTime   time.Time   `json:"server_time"`
}

// runLogin implements `csg login`.
func (a *App) runLogin(args []string) error {
	fs := a.newFlagSet("login", `Usage: csg login --server URL [--name NAME] [--description TEXT] [--json]

Signs this agent in. csg shows a short code and a link; a person opens the
link in the console, checks the code and approves. The agent then belongs to
that person and inherits their role on each cloud account. No token is copied
by hand; the result is saved to ~/.config/cloud-safeguard/config.json with
0600 permissions.
`)
	server := fs.String("server", "", "control plane URL (default: $CSG_SERVER or saved config)")
	name := fs.String("name", "", "agent name shown to the person who approves (default: csg-<hostname>)")
	description := fs.String("description", "", "optional description shown with the sign-in")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("login takes no positional arguments")
	}
	serverURL, err := a.resolveServer(&clientFlags{server: *server})
	if err != nil {
		return err
	}
	return a.agentSignIn(serverURL, *name, *description, *jsonOut)
}

// runWhoami implements `csg whoami`.
func (a *App) runWhoami(args []string) error {
	fs := a.newFlagSet("whoami", `Usage: csg whoami [--json] [--server URL] [--token TOKEN]

Shows the identity behind the configured token.
`)
	cf := a.addClientFlags(fs)
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("whoami takes no positional arguments")
	}

	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	var me agentMe
	if err := client.get(context.Background(), apiPrefix+"/agent/me", &me); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(me)
	}
	fmt.Fprintf(a.Stdout, "agent:         %s (%s)\n", me.Agent.Name, me.Agent.ID)
	fmt.Fprintf(a.Stdout, "status:        %s\n", me.Agent.Status)
	fmt.Fprintf(a.Stdout, "active requests: %d\n", me.ActiveLeases)
	fmt.Fprintf(a.Stdout, "server:        %s\n", client.baseURL)
	return nil
}
