package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// People on the command line (CONTRACT §17.9). A person signs in by
// approving a short code in the console; the session token is kept in its
// own file, apart from the agent's, and agent commands never read it.

// personSessionPrefix starts every command-line session token.
const personSessionPrefix = "csg_ses_"

// authenticatorCodeHeader carries a fresh authenticator code with a change
// that raises access.
const authenticatorCodeHeader = "X-CSG-Authenticator-Code"

// personConfig is ~/.config/cloud-safeguard/person.json.
type personConfig struct {
	Server     string    `json:"server"`
	Token      string    `json:"token"`
	Username   string    `json:"username"`
	Supervisor bool      `json:"supervisor"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (a *App) personConfigPath() (string, error) {
	home, err := a.HomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate home directory: %v", err)
	}
	return filepath.Join(home, ".config", "cloud-safeguard", "person.json"), nil
}

func (a *App) loadPersonConfig() (personConfig, bool) {
	var cfg personConfig
	path, err := a.personConfigPath()
	if err != nil {
		return cfg, false
	}
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &cfg) != nil {
		return personConfig{}, false
	}
	return cfg, strings.HasPrefix(cfg.Token, personSessionPrefix) && cfg.Server != ""
}

func (a *App) savePersonConfig(cfg personConfig) (string, error) {
	path, err := a.personConfigPath()
	if err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("cannot encode the session: %v", err)
	}
	return path, writePrivateFile(path, append(data, '\n'))
}

func (a *App) removePersonConfig() {
	if path, err := a.personConfigPath(); err == nil {
		_ = os.Remove(path)
	}
}

// writePrivateFile writes data with mode 0600 through a temporary file that
// is renamed over path, so the content is never in a file with a looser mode
// and a symlink at path is replaced rather than followed.
func writePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cannot create %s: %v", filepath.Dir(path), err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("cannot write %s: %v", path, err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write %s: %v", path, err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write %s: %v", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cannot write %s: %v", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("cannot write %s: %v", path, err)
	}
	return nil
}

// personAPI is the API client of the signed-in person.
func (a *App) personAPI() (*apiClient, personConfig, error) {
	cfg, ok := a.loadPersonConfig()
	if !ok {
		return nil, cfg, authf("not signed in as a person: run csg person login --server URL")
	}
	return &apiClient{baseURL: cfg.Server, token: cfg.Token, http: a.httpClient()}, cfg, nil
}

// stdinIsTerminal reports whether the CLI can ask the user for input.
func (a *App) stdinIsTerminal() bool {
	f, ok := a.Stdin.(*os.File)
	return ok && isTerminal(f)
}

// raising sends a request that may raise access. With --code the code goes
// with it. Without one, when the server asks for a code: in a terminal the
// user is asked and the request is sent again once; otherwise the command
// fails and says to pass --code. The server refuses such a request before it
// changes anything, so sending it again is safe.
func (a *App) raising(c *apiClient, code, method, path string, body, out any) error {
	ctx := context.Background()
	c.authCode = strings.TrimSpace(code)
	err := c.do(ctx, method, path, body, out)
	var ae *apiError
	if !errors.As(err, &ae) || ae.Code != model.ErrCodeAuthenticatorCodeRequired || c.authCode != "" {
		return err
	}
	if !a.stdinIsTerminal() {
		return authf("this change raises access: run it again with --code and a fresh code from your authenticator app")
	}
	fmt.Fprint(a.Stderr, "This change raises access. Code from your authenticator app: ")
	line, readErr := bufio.NewReader(a.Stdin).ReadString('\n')
	if readErr != nil && line == "" {
		return authf("no authenticator code was entered")
	}
	c.authCode = strings.TrimSpace(line)
	return c.do(ctx, method, path, body, out)
}

// ---- csg person ----

func (a *App) runPerson(args []string) error {
	if len(args) == 0 {
		return usagef("usage: csg person login|logout|whoami")
	}
	switch args[0] {
	case "login":
		return a.runPersonLogin(args[1:])
	case "logout":
		return a.runPersonLogout(args[1:])
	case "whoami":
		return a.runPersonWhoami(args[1:])
	}
	return usagef("unknown person subcommand %q (login, logout, whoami)", args[0])
}

func (a *App) runPersonLogin(args []string) error {
	fs := a.newFlagSet("person login", `Usage: csg person login --server URL [--name NAME] [--json]

Signs you in to csg as yourself. csg shows a link and a short code; open the
link in the console (where you are signed in with your password and
authenticator), check the code and approve. The session lasts up to 12 hours
(30 minutes without use) and is saved to ~/.config/cloud-safeguard/person.json
with mode 0600, apart from any agent sign-in.

From the command line you can read everything and lower access. Anything that
raises access asks for a code from your authenticator app. Approving requests
and sign-ins, and adding a cloud account, are done in the console only.
`)
	server := fs.String("server", "", "control plane URL (default: $CSG_SERVER or the saved agent config)")
	name := fs.String("name", "", "name shown to you when you approve (default: csg-<hostname>)")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("person login takes no positional arguments")
	}
	serverURL, err := a.resolveServer(&clientFlags{server: *server})
	if err != nil {
		return err
	}
	clientName := strings.TrimSpace(*name)
	if clientName == "" {
		clientName = defaultAgentName()
	}
	if !agentNameRE.MatchString(clientName) {
		return usagef("--name must be 2-64 characters: letters, digits, dot, dash or underscore")
	}
	a.warnIfCleartext(serverURL)
	// No token on this client: a sign-in never sends a saved token.
	client := &apiClient{baseURL: serverURL, http: a.httpClient()}
	ctx := context.Background()
	var start model.AgentSignInStart
	if err := client.post(ctx, apiPrefix+"/person-signin/start", model.PersonSignInStartInput{ClientName: clientName}, &start); err != nil {
		return err
	}
	link := displayString(start.VerificationURL)
	fmt.Fprintf(a.Stderr, "To sign in csg as yourself, open this link in the console and approve the code:\n\n  %s\n\n  code: %s\n\n", link, displayString(start.UserCode))
	if !sameOriginURL(link, serverURL) {
		fmt.Fprintf(a.Stderr, "note: this link is not on %s, the server you gave. Only open it if you expected that.\n", serverURL)
	}
	fmt.Fprintf(a.Stderr, "Waiting for approval (the code expires at %s)...\n", start.ExpiresAt.Local().Format("15:04"))
	if a.afterSignInStart != nil {
		a.afterSignInStart(start)
	}
	interval := time.Duration(start.IntervalSeconds) * time.Second
	if interval < time.Second {
		interval = time.Second
	}
	if interval > time.Minute {
		interval = time.Minute
	}
	deadline := time.Now().Add(signInTimeout)
	for {
		var res model.PersonSignInResult
		if err := client.post(ctx, apiPrefix+"/person-signin/token", model.AgentSignInTokenInput{DeviceCode: start.DeviceCode}, &res); err != nil {
			return err
		}
		switch res.Status {
		case model.SignInApproved:
			if res.Person == nil || !strings.HasPrefix(res.Token, personSessionPrefix) || res.ExpiresAt == nil {
				return operationf("the server approved the sign-in but returned no session")
			}
			cfg := personConfig{Server: serverURL, Token: res.Token, Username: res.Person.Username,
				Supervisor: res.Person.Supervisor, ExpiresAt: *res.ExpiresAt}
			path, err := a.savePersonConfig(cfg)
			if err != nil {
				return err
			}
			if *jsonOut {
				return a.printJSON(map[string]any{"person": res.Person, "server": serverURL, "expires_at": res.ExpiresAt, "session_path": path})
			}
			fmt.Fprintf(a.Stdout, "signed in as %s%s until %s\n", displayString(res.Person.Username), supervisorSuffix(res.Person.Supervisor),
				res.ExpiresAt.Local().Format("2006-01-02 15:04"))
			fmt.Fprintf(a.Stdout, "session saved to %s (mode 0600)\n", path)
			return nil
		case model.SignInDenied:
			return operationf("the sign-in was denied")
		case model.SignInExpired:
			return operationf("the sign-in code expired or was already used; run csg person login again")
		}
		left := time.Until(deadline)
		if left <= 0 {
			return waitTimeoutf("timed out waiting for the sign-in to be approved")
		}
		pollSleep(min(interval, left))
	}
}

func supervisorSuffix(supervisor bool) string {
	if supervisor {
		return " (supervisor)"
	}
	return ""
}

func (a *App) runPersonLogout(args []string) error {
	fs := a.newFlagSet("person logout", "Usage: csg person logout\n\nEnds the command-line session and removes it from this machine.\n")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("person logout takes no arguments")
	}
	client, _, err := a.personAPI()
	if err != nil {
		return err
	}
	err = client.post(context.Background(), apiPrefix+"/auth/logout", map[string]any{}, nil)
	var ae *apiError
	if err != nil && !(errors.As(err, &ae) && ae.Status == http.StatusUnauthorized) {
		return err
	}
	// Ended on the server, or already over there: forget it here either way.
	a.removePersonConfig()
	fmt.Fprintln(a.Stdout, "signed out")
	return nil
}

func (a *App) runPersonWhoami(args []string) error {
	fs := a.newFlagSet("person whoami", "Usage: csg person whoami [--json]\n")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("person whoami takes no arguments")
	}
	client, cfg, err := a.personAPI()
	if err != nil {
		return err
	}
	var info model.SessionInfo
	if err := client.get(context.Background(), apiPrefix+"/auth/me", &info); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
			return authf("the command-line session has ended: run csg person login again")
		}
		return err
	}
	if *jsonOut {
		return a.printJSON(info)
	}
	fmt.Fprintf(a.Stdout, "person:     %s%s\n", displayString(info.Person.Username), supervisorSuffix(info.Person.Supervisor))
	fmt.Fprintf(a.Stdout, "server:     %s\n", cfg.Server)
	fmt.Fprintf(a.Stdout, "expires:    %s at the latest (30 minutes without use)\n", info.ExpiresAt.Local().Format("2006-01-02 15:04"))
	return nil
}

// ---- csg me ----

func (a *App) runMe(args []string) error {
	if len(args) == 0 {
		return usagef("usage: csg me requests|deny|revoke|agents|revoke-agent|accounts|mode|sessions|end-session")
	}
	rest := args[1:]
	switch args[0] {
	case "requests":
		return a.runMeRequests(rest)
	case "deny":
		return a.runMeDecide(rest, "deny")
	case "revoke":
		return a.runMeDecide(rest, "revoke")
	case "approve":
		return usagef("approving a request is done in the console only, so an agent can never approve itself")
	case "agents":
		return a.runMeAgents(rest)
	case "revoke-agent":
		return a.runMeRevokeAgent(rest)
	case "accounts":
		return a.runMeAccounts(rest)
	case "mode":
		return a.runMeMode(rest)
	case "sessions":
		return a.runMeSessions(rest)
	case "end-session":
		return a.runMeEndSession(rest)
	}
	return usagef("unknown me subcommand %q", args[0])
}

func (a *App) runMeRequests(args []string) error {
	fs := a.newFlagSet("me requests", "Usage: csg me requests [--status pending|active|...] [--json]\n\nThe requests of your agents, newest first.\n")
	status := fs.String("status", "", "only requests in this state")
	jsonOut := fs.Bool("json", false, "print JSON")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("me requests takes no positional arguments")
	}
	client, _, err := a.personAPI()
	if err != nil {
		return err
	}
	path := apiPrefix + "/me/requests"
	if s := strings.TrimSpace(*status); s != "" {
		path += "?status=" + url.QueryEscape(s)
	}
	var list model.ListResponse[model.AccessRequest]
	if err := client.get(context.Background(), path, &list); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(list)
	}
	printRequestTable(a.Stdout, list.Items)
	return nil
}

func printRequestTable(w io.Writer, items []model.AccessRequest) {
	if len(items) == 0 {
		fmt.Fprintln(w, "no requests")
		return
	}
	rows := make([][]string, 0, len(items))
	for _, r := range items {
		scope := r.ResourceName
		if scope == "" {
			scope = "all"
		}
		rows = append(rows, []string{r.ID, string(r.Status), r.AgentName, r.CloudAccountID,
			r.Permission + " " + r.Resource + " (" + scope + ")", formatSeconds(r.TTLSeconds), r.Reason})
	}
	writeTable(w, []string{"ID", "STATUS", "AGENT", "ACCOUNT", "ACCESS", "VALID FOR", "REASON"}, rows)
}

func (a *App) runMeDecide(args []string, action string) error {
	fs := a.newFlagSet("me "+action, fmt.Sprintf("Usage: csg me %s ID [--reason TEXT]\n", action))
	reason := fs.String("reason", "", "shown in the activity log")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("me %s takes one request ID", action)
	}
	client, _, err := a.personAPI()
	if err != nil {
		return err
	}
	var body any = map[string]any{}
	if action == "deny" {
		body = model.DenyRequestInput{Reason: strings.TrimSpace(*reason)}
	} else if r := strings.TrimSpace(*reason); r != "" {
		body = model.RevokeLeaseInput{Reason: r}
	}
	var out model.AccessRequest
	if err := client.post(context.Background(), apiPrefix+"/me/requests/"+pathEscape(positionals[0])+"/"+action, body, &out); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "request %s is %s\n", out.ID, out.Status)
	return nil
}

func (a *App) runMeAgents(args []string) error {
	fs := a.newFlagSet("me agents", "Usage: csg me agents [--json]\n")
	jsonOut := fs.Bool("json", false, "print JSON")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	client, _, err := a.personAPI()
	if err != nil {
		return err
	}
	var list model.ListResponse[model.Agent]
	if err := client.get(context.Background(), apiPrefix+"/me/agents", &list); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(list)
	}
	if len(list.Items) == 0 {
		fmt.Fprintln(a.Stdout, "no agents")
		return nil
	}
	rows := [][]string{}
	for _, ag := range list.Items {
		rows = append(rows, []string{ag.ID, ag.Name, string(ag.Status), fmtTimePtr(ag.LastSeenAt)})
	}
	writeTable(a.Stdout, []string{"ID", "NAME", "STATUS", "LAST SEEN"}, rows)
	return nil
}

func (a *App) runMeRevokeAgent(args []string) error {
	fs := a.newFlagSet("me revoke-agent", "Usage: csg me revoke-agent ID\n\nRevokes one of your agents for good, with every credential it holds.\n")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("me revoke-agent takes one agent ID")
	}
	client, _, err := a.personAPI()
	if err != nil {
		return err
	}
	var out model.Agent
	if err := client.post(context.Background(), apiPrefix+"/me/agents/"+pathEscape(positionals[0])+"/revoke", map[string]any{}, &out); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "agent %s (%s) revoked\n", displayString(out.Name), out.ID)
	return nil
}

func (a *App) runMeAccounts(args []string) error {
	fs := a.newFlagSet("me accounts", "Usage: csg me accounts [--json]\n\nYour role on each cloud account and what your agents get there without asking.\n")
	jsonOut := fs.Bool("json", false, "print JSON")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	client, _, err := a.personAPI()
	if err != nil {
		return err
	}
	var list model.ListResponse[model.PersonAccount]
	if err := client.get(context.Background(), apiPrefix+"/me/accounts", &list); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(list)
	}
	if len(list.Items) == 0 {
		fmt.Fprintln(a.Stdout, "no cloud accounts: ask a supervisor for a role on one")
		return nil
	}
	rows := [][]string{}
	for _, acct := range list.Items {
		auto := acct.AutomaticUpTo
		if auto == "" {
			auto = "-"
		}
		mode := string(acct.ApprovalMode)
		if acct.ApprovalModeExpiresAt != nil {
			mode += " until " + acct.ApprovalModeExpiresAt.Local().Format("2006-01-02 15:04")
		}
		rows = append(rows, []string{acct.CloudAccountID, acct.Name, string(acct.Role), acct.HighestPermission, mode, auto, string(acct.Status)})
	}
	writeTable(a.Stdout, []string{"CLOUD ACCOUNT", "NAME", "ROLE", "UP TO", "MODE", "AUTOMATIC", "STATUS"}, rows)
	return nil
}

func (a *App) runMeMode(args []string) error {
	fs := a.newFlagSet("me mode", `Usage: csg me mode ACCOUNT read|write|full [--for DUR] [--code CODE]

Sets how much your agents get without asking you on one cloud account (its
cloud account ID or name, from csg me accounts), never beyond your role
there. Anything above read asks for a code from your authenticator app.
`)
	forDur := fs.String("for", "", "fall back to read after this long (e.g. 2h); default: until changed")
	code := fs.String("code", "", "code from your authenticator app")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 2 {
		return usagef("me mode takes an ACCOUNT and a mode: read, write or full")
	}
	mode := model.ApprovalMode(strings.ToLower(positionals[1]))
	if !mode.Valid() {
		return usagef("mode must be read, write or full")
	}
	seconds, err := parseOptionalDurationSeconds(*forDur)
	if err != nil {
		return usagef("--for: %v", err)
	}
	client, _, err := a.personAPI()
	if err != nil {
		return err
	}
	var list model.ListResponse[model.PersonAccount]
	if err := client.get(context.Background(), apiPrefix+"/me/accounts", &list); err != nil {
		return err
	}
	var matches []model.PersonAccount
	for _, acct := range list.Items {
		if acct.CloudAccountID == positionals[0] || acct.ProviderID == positionals[0] {
			matches = []model.PersonAccount{acct}
			break
		}
		if strings.EqualFold(acct.Name, positionals[0]) {
			matches = append(matches, acct)
		}
	}
	switch len(matches) {
	case 0:
		return usagef("no cloud account %q among yours (see csg me accounts)", positionals[0])
	case 1:
	default:
		return usagef("%d of your cloud accounts are named %q: use the cloud account ID", len(matches), positionals[0])
	}
	var out model.PersonAccount
	if err := a.raising(client, *code, http.MethodPut, apiPrefix+"/me/accounts/"+pathEscape(matches[0].ProviderID)+"/mode",
		model.SetApprovalModeInput{Mode: mode, ExpiresInSeconds: seconds}, &out); err != nil {
		return err
	}
	fmt.Fprintf(a.Stdout, "%s: approval mode is %s", displayString(out.Name), out.ApprovalMode)
	if out.ApprovalModeExpiresAt != nil {
		fmt.Fprintf(a.Stdout, " until %s", out.ApprovalModeExpiresAt.Local().Format("2006-01-02 15:04"))
	}
	fmt.Fprintf(a.Stdout, "; agents get up to %s without asking\n", orDash(out.AutomaticUpTo))
	return nil
}

func (a *App) runMeSessions(args []string) error {
	fs := a.newFlagSet("me sessions", "Usage: csg me sessions [--json]\n\nYour command-line sign-ins.\n")
	jsonOut := fs.Bool("json", false, "print JSON")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	client, _, err := a.personAPI()
	if err != nil {
		return err
	}
	var list model.ListResponse[model.CLISession]
	if err := client.get(context.Background(), apiPrefix+"/me/cli-sessions", &list); err != nil {
		return err
	}
	if *jsonOut {
		return a.printJSON(list)
	}
	rows := [][]string{}
	for _, s := range list.Items {
		current := ""
		if s.Current {
			current = "this one"
		}
		rows = append(rows, []string{s.ID, s.ClientName, s.RemoteAddr, fmtTime(s.CreatedAt), fmtTime(s.LastSeenAt), current})
	}
	writeTable(a.Stdout, []string{"ID", "CLIENT", "FROM", "SIGNED IN", "LAST USED", ""}, rows)
	return nil
}

func (a *App) runMeEndSession(args []string) error {
	fs := a.newFlagSet("me end-session", "Usage: csg me end-session ID\n")
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 1 {
		return usagef("me end-session takes one session ID")
	}
	client, _, err := a.personAPI()
	if err != nil {
		return err
	}
	if err := client.post(context.Background(), apiPrefix+"/me/cli-sessions/"+pathEscape(positionals[0])+"/revoke", map[string]any{}, nil); err != nil {
		return err
	}
	fmt.Fprintln(a.Stdout, "session ended")
	return nil
}

// ---- lookups ----

// findPerson resolves a username or person ID.
func (a *App) findPerson(c *apiClient, ref string) (model.Person, error) {
	var list model.ListResponse[model.Person]
	if err := c.get(context.Background(), apiPrefix+"/supervisor/people", &list); err != nil {
		return model.Person{}, err
	}
	ref = strings.TrimSpace(ref)
	for _, p := range list.Items {
		if p.ID == ref || strings.EqualFold(p.Username, ref) {
			return p, nil
		}
	}
	return model.Person{}, operationf("no person %q", ref)
}

// findAccount resolves a provider ID, a cloud account ID or a name.
func (a *App) findAccount(c *apiClient, ref string) (model.Provider, error) {
	var list model.ListResponse[model.Provider]
	if err := c.get(context.Background(), apiPrefix+"/supervisor/accounts", &list); err != nil {
		return model.Provider{}, err
	}
	ref = strings.TrimSpace(ref)
	var byName []model.Provider
	for _, p := range list.Items {
		if p.ID == ref || (p.CloudAccountID != "" && p.CloudAccountID == ref) {
			return p, nil
		}
		if strings.EqualFold(p.Name, ref) {
			byName = append(byName, p)
		}
	}
	switch len(byName) {
	case 1:
		return byName[0], nil
	case 0:
		return model.Provider{}, operationf("no cloud account %q", ref)
	}
	return model.Provider{}, operationf("several cloud accounts are named %q; use the cloud account ID", ref)
}

// sortedPeople is people by username.
func sortedPeople(items []model.Person) []model.Person {
	sort.Slice(items, func(i, j int) bool { return items[i].Username < items[j].Username })
	return items
}
