package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/token"
)

// agentMe is the payload of GET /api/v1/agent/me.
type agentMe struct {
	Agent        model.Agent `json:"agent"`
	ActiveLeases int         `json:"active_leases"`
	ServerTime   time.Time   `json:"server_time"`
}

// runLogin implements `csg login`.
func (a *App) runLogin(args []string) error {
	fs := a.newFlagSet("login", `Usage: csg login --server URL --token TOKEN [--json]

Validates an admin or agent token against the control plane and saves it to
~/.config/cloud-safeguard/config.json with 0600 permissions.
`)
	server := fs.String("server", "", "control plane URL (required)")
	tokenFlag := fs.String("token", "", "admin (csg_adm_) or agent (csg_agt_) bearer token (required)")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("login takes no positional arguments")
	}
	if strings.TrimSpace(*server) == "" || strings.TrimSpace(*tokenFlag) == "" {
		return usagef("login requires --server and --token")
	}

	serverURL := normalizeServer(*server)
	if err := validateServerURL(serverURL); err != nil {
		return usagef("%v", err)
	}
	tokenValue := strings.TrimSpace(*tokenFlag)
	kind := token.Kind(tokenValue)
	if kind == "" {
		return usagef("token must start with %s (admin) or %s (agent)", token.AdminPrefix, token.AgentPrefix)
	}

	cfg := &resolvedConfig{Server: serverURL, Token: tokenValue, Kind: kind}
	client := a.newAPIClient(cfg)
	ctx := context.Background()

	var identity string
	switch kind {
	case "admin":
		var res model.LoginResult
		if err := client.post(ctx, apiPrefix+"/admin/login", nil, &res); err != nil {
			return err
		}
		identity = "admin"
	case "agent":
		var me agentMe
		if err := client.get(ctx, apiPrefix+"/agent/me", &me); err != nil {
			return err
		}
		identity = fmt.Sprintf("agent %s (%s)", me.Agent.Name, me.Agent.ID)
	}

	path, err := a.saveFileConfig(fileConfig{Server: serverURL, Token: tokenValue, Kind: kind})
	if err != nil {
		return err
	}

	if *jsonOut {
		return a.printJSON(map[string]any{
			"role":        kind,
			"server":      serverURL,
			"config_path": path,
		})
	}
	fmt.Fprintf(a.Stdout, "logged in as %s at %s\n", identity, serverURL)
	fmt.Fprintf(a.Stdout, "config saved to %s (mode 0600)\n", path)
	return nil
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

	cfg, err := a.resolveConfig(cf)
	if err != nil {
		return err
	}
	client := a.newAPIClient(cfg)
	ctx := context.Background()

	switch cfg.Kind {
	case "admin":
		var res model.LoginResult
		if err := client.post(ctx, apiPrefix+"/admin/login", nil, &res); err != nil {
			return err
		}
		if *jsonOut {
			return a.printJSON(map[string]any{
				"role":    "admin",
				"server":  cfg.Server,
				"version": res.Version,
			})
		}
		fmt.Fprintf(a.Stdout, "role:      admin\nserver:    %s\nversion:   %s\n", cfg.Server, res.Version)
		return nil
	case "agent":
		var me agentMe
		if err := client.get(ctx, apiPrefix+"/agent/me", &me); err != nil {
			return err
		}
		if *jsonOut {
			return a.printJSON(me)
		}
		fmt.Fprintf(a.Stdout, "agent:         %s (%s)\n", me.Agent.Name, me.Agent.ID)
		fmt.Fprintf(a.Stdout, "status:        %s\n", me.Agent.Status)
		fmt.Fprintf(a.Stdout, "role:          %s\n", me.Agent.Role)
		fmt.Fprintf(a.Stdout, "grants:        %s\n", joinOrDash(me.Agent.Grants))
		fmt.Fprintf(a.Stdout, "max ttl:       %s\n", formatSeconds(me.Agent.MaxTTLSeconds))
		fmt.Fprintf(a.Stdout, "max concurrent:%s\n", fmt.Sprintf(" %d", me.Agent.MaxConcurrentLeases))
		fmt.Fprintf(a.Stdout, "active leases: %d\n", me.ActiveLeases)
		fmt.Fprintf(a.Stdout, "server:        %s\n", cfg.Server)
		return nil
	default:
		return authf("configured token is %s", tokenKindLabel(cfg.Kind))
	}
}
