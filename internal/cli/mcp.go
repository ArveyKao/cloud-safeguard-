package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// `csg mcp` is a Model Context Protocol server on stdio (CONTRACT §17.7). It
// is a thin client of the agent API: it holds the agent token from csg login
// and nothing else.
//
// Credentials never enter the model's context: get_credential writes them to
// a file only the user can read and returns its path, so the secret does not
// end up in a transcript, a log or a model provider's request.

// mcpProtocolVersions are the protocol revisions this server speaks, newest
// first.
var mcpProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

var leaseIDRE = regexp.MustCompile(`^lea_[0-9a-f]{32}$`)

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type mcpText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpToolResult struct {
	Content []mcpText `json:"content"`
	IsError bool      `json:"isError"`
}

func schema(required []string, props map[string]any) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

var mcpTools = []mcpTool{
	{
		Name:        "list_accounts",
		Description: "List the cloud accounts you may ask for access to, the role you inherit from the person who owns you, the highest permission it allows, and how far access is issued without waiting for that person.",
		InputSchema: schema(nil, map[string]any{}),
	},
	{
		Name: "request_access",
		Description: "Ask for short-lived cloud access. read lets you look; write also changes existing resources; full also creates and deletes them. " +
			"Access above your owner's role is denied. Depending on your owner's settings the request is issued at once or waits for their approval in the console: " +
			"then tell the user and call check_status later. You can never get IAM or RAM management.",
		InputSchema: schema([]string{"cloud_account_id", "resource", "permission", "ttl_seconds"}, map[string]any{
			"cloud_account_id": str("Cloud account ID, from list_accounts."),
			"resource":         str("Resource type, from list_accounts (for example ecs, dns, oss)."),
			"permission":       map[string]any{"type": "string", "enum": []string{"read", "write", "full"}},
			"ttl_seconds":      map[string]any{"type": "integer", "minimum": 1, "description": "How long the credential stays valid. Ask for no more than the task needs."},
			"resource_name":    str("Optional: one resource (instance ID, domain, bucket). Omit for all resources of that type."),
			"reason":           str("Why you need it. Required for write and full; your owner sees it."),
		}),
	},
	{
		Name:        "check_status",
		Description: "Check an access request: pending, active, denied, expired or revoked.",
		InputSchema: schema([]string{"request_id"}, map[string]any{"request_id": str("The id returned by request_access.")}),
	},
	{
		Name: "get_credential",
		Description: "Prepare the credential of an active request. The secret is written to a file only the user can read and is NOT returned here; " +
			"run `source <path>` in the shell that runs the cloud command (aliyun CLI, SDKs, terraform).",
		InputSchema: schema([]string{"request_id"}, map[string]any{"request_id": str("The id returned by request_access.")}),
	},
	{
		Name:        "revoke",
		Description: "End an access request early and delete its credential file. Do this as soon as the task is done.",
		InputSchema: schema([]string{"request_id"}, map[string]any{
			"request_id": str("The id returned by request_access."),
			"reason":     str("Optional reason."),
		}),
	},
}

// runMCP implements `csg mcp`.
func (a *App) runMCP(args []string) error {
	fs := a.newFlagSet("mcp", `Usage: csg mcp

Runs the Cloud Safeguard MCP server on stdin/stdout for Claude, Cursor and
other MCP clients. Sign the agent in first with csg login. Example client
configuration:

  "cloud-safeguard": { "command": "csg", "args": ["mcp"] }

Tools: list_accounts, request_access, check_status, get_credential, revoke.
Credentials are written to ~/.config/cloud-safeguard/credentials/ (mode 0600)
and never returned to the model.
`)
	cf := a.addClientFlags(fs)
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("mcp takes no arguments")
	}
	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	if a.Stdin == nil {
		return usagef("mcp needs stdin")
	}
	a.sweepCredentialFiles(time.Now())
	reader := bufio.NewReaderSize(a.Stdin, 64*1024)
	enc := json.NewEncoder(a.Stdout)
	nullID := json.RawMessage("null")
	for {
		line, tooLong, err := readMCPLine(reader, maxMCPMessage)
		if tooLong {
			// One oversized message is refused; the session goes on.
			if err := enc.Encode(mcpResponse{JSONRPC: "2.0", ID: nullID, Error: &mcpError{Code: -32600, Message: "message too large"}}); err != nil {
				return err
			}
		} else if trimmed := strings.TrimSpace(string(line)); trimmed != "" {
			if out := a.handleMCPLine(client, []byte(trimmed)); out != nil {
				if err := enc.Encode(out); err != nil {
					return err
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// maxMCPMessage bounds one JSON-RPC message.
const maxMCPMessage = 1 << 20

// readMCPLine reads one newline-terminated line. A line longer than max is
// read to its end and discarded, and tooLong is set.
func readMCPLine(r *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	for {
		chunk, isPrefix, err := r.ReadLine()
		if !tooLong {
			if len(line)+len(chunk) > max {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if err != nil || !isPrefix {
			return line, tooLong, err
		}
	}
}

// handleMCPLine answers one message or one batch; nil means no reply.
func (a *App) handleMCPLine(client *apiClient, line []byte) any {
	nullID := json.RawMessage("null")
	parseError := mcpResponse{JSONRPC: "2.0", ID: nullID, Error: &mcpError{Code: -32700, Message: "parse error"}}
	if line[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(line, &batch); err != nil {
			return parseError
		}
		if len(batch) == 0 {
			return mcpResponse{JSONRPC: "2.0", ID: nullID, Error: &mcpError{Code: -32600, Message: "empty batch"}}
		}
		var out []mcpResponse
		for _, raw := range batch {
			var req mcpRequest
			if err := json.Unmarshal(raw, &req); err != nil {
				out = append(out, mcpResponse{JSONRPC: "2.0", ID: nullID, Error: &mcpError{Code: -32600, Message: "invalid request"}})
				continue
			}
			if resp, reply := a.handleMCP(client, req); reply {
				out = append(out, resp)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	var req mcpRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return parseError
	}
	if resp, reply := a.handleMCP(client, req); reply {
		return resp
	}
	return nil
}

// handleMCP answers one message; reply is false for notifications.
func (a *App) handleMCP(client *apiClient, req mcpRequest) (mcpResponse, bool) {
	isNotification := len(req.ID) == 0 || string(req.ID) == "null"
	resp := mcpResponse{JSONRPC: "2.0", ID: req.ID}
	// A notification gets no answer, so it must not do anything either: a
	// tools/call without an id would otherwise fetch or revoke unseen.
	if isNotification {
		return resp, false
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := mcpProtocolVersions[0]
		for _, v := range mcpProtocolVersions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		resp.Result = map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "cloud-safeguard", "version": model.Version},
			"instructions": "Use list_accounts to see where you may ask for access, request_access to get short-lived scoped credentials, " +
				"get_credential to prepare them for a shell, and revoke when done. Ask for the lowest permission and shortest validity that does the job.",
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": mcpTools}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &mcpError{Code: -32602, Message: "invalid params"}
			break
		}
		text, err := a.callMCPTool(client, p.Name, p.Arguments)
		if err != nil {
			resp.Result = mcpToolResult{Content: []mcpText{{Type: "text", Text: err.Error()}}, IsError: true}
		} else {
			resp.Result = mcpToolResult{Content: []mcpText{{Type: "text", Text: text}}}
		}
	default:
		if isNotification {
			return resp, false
		}
		resp.Error = &mcpError{Code: -32601, Message: "method not found: " + req.Method}
	}
	if isNotification {
		return resp, false
	}
	return resp, true
}

// requestView is what the model sees about a request: no secrets.
func requestView(req model.AccessRequest) map[string]any {
	v := map[string]any{
		"id": req.ID, "status": req.Status, "cloud_account_id": req.CloudAccountID,
		"resource": req.Resource, "permission": req.Permission, "ttl_seconds": req.TTLSeconds,
	}
	if req.ResourceName != "" {
		v["resource_name"] = req.ResourceName
	}
	if req.ExpiresAt != nil {
		v["expires_at"] = req.ExpiresAt.UTC().Format(time.RFC3339)
	}
	switch req.Status {
	case model.LeasePending:
		v["next"] = "Waiting for the person who owns you to approve it in the Cloud Safeguard console. Tell the user, then call check_status."
	case model.LeaseActive:
		v["next"] = "Call get_credential to prepare it for a shell."
	case model.LeaseDenied:
		v["denied_reason"] = req.DeniedReason
	case model.LeaseRevoked:
		v["revoke_reason"] = req.RevokeReason
	}
	return v
}

func toJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

// mcpErr turns an API error into a message for the model.
func mcpErr(err error) error {
	var ae *apiError
	if errors.As(err, &ae) {
		return fmt.Errorf("%s", ae.Message)
	}
	return err
}

func (a *App) callMCPTool(client *apiClient, name string, raw json.RawMessage) (string, error) {
	ctx := context.Background()
	var args map[string]any
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", fmt.Errorf("arguments must be a JSON object")
		}
	}
	getStr := func(key string) string {
		s, _ := args[key].(string)
		return strings.TrimSpace(s)
	}
	requestID := func() (string, error) {
		id := getStr("request_id")
		if !leaseIDRE.MatchString(id) {
			return "", fmt.Errorf("request_id must be an id returned by request_access")
		}
		return id, nil
	}
	switch name {
	case "list_accounts":
		var list struct {
			Items []model.AgentAccount `json:"items"`
		}
		if err := client.get(ctx, apiPrefix+"/agent/accounts", &list); err != nil {
			return "", mcpErr(err)
		}
		if len(list.Items) == 0 {
			return "No cloud accounts. The person who owns you has no role on any cloud account yet; a supervisor gives them one.", nil
		}
		return toJSON(list.Items), nil

	case "request_access":
		ttl, ok := args["ttl_seconds"].(float64)
		if !ok || ttl != float64(int(ttl)) || ttl < 1 {
			return "", fmt.Errorf("ttl_seconds must be a positive whole number")
		}
		in := model.AccessRequestInput{
			CloudAccountID: getStr("cloud_account_id"), Resource: getStr("resource"), Permission: getStr("permission"),
			TTLSeconds: int(ttl), ResourceName: getStr("resource_name"), Reason: getStr("reason"),
		}
		var req model.AccessRequest
		if err := client.post(ctx, apiPrefix+"/agent/access-requests", in, &req); err != nil {
			return "", mcpErr(err)
		}
		return toJSON(requestView(req)), nil

	case "check_status":
		id, err := requestID()
		if err != nil {
			return "", err
		}
		var req model.AccessRequest
		if err := client.get(ctx, apiPrefix+"/agent/access-requests/"+pathEscape(id), &req); err != nil {
			return "", mcpErr(err)
		}
		return toJSON(requestView(req)), nil

	case "get_credential":
		id, err := requestID()
		if err != nil {
			return "", err
		}
		var envelope model.CredentialEnvelope
		if err := client.post(ctx, apiPrefix+"/agent/leases/"+pathEscape(id)+"/credential", nil, &envelope); err != nil {
			return "", mcpErr(err)
		}
		a.sweepCredentialFiles(time.Now())
		path, err := a.writeCredentialFile(id, &envelope, client.baseURL)
		if err != nil {
			return "", err
		}
		return toJSON(map[string]any{
			"request_id": id,
			"file":       path,
			"expires_at": envelope.Credential.ExpiresAt.UTC().Format(time.RFC3339),
			"use":        "source " + shellQuote(path) + "  # in the shell that runs the cloud command",
			"note":       "The credential is in the file, readable only by this user; it is not shown here. Revoke it when done.",
		}), nil

	case "revoke":
		id, err := requestID()
		if err != nil {
			return "", err
		}
		reason := getStr("reason")
		if reason == "" {
			reason = "revoked by the agent through MCP"
		}
		var lease model.Lease
		revokeErr := client.post(ctx, apiPrefix+"/agent/leases/"+pathEscape(id)+"/revoke", model.RevokeLeaseInput{Reason: reason}, &lease)
		removed := a.removeCredentialFile(id)
		if revokeErr != nil {
			return "", mcpErr(revokeErr)
		}
		return toJSON(map[string]any{"request_id": id, "status": lease.Status, "credential_file_deleted": removed}), nil
	}
	return "", fmt.Errorf("unknown tool %q", name)
}

// credentialPath is ~/.config/cloud-safeguard/credentials/<request id>.env.
func (a *App) credentialPath(id string) (string, error) {
	if !leaseIDRE.MatchString(id) {
		return "", fmt.Errorf("invalid request id")
	}
	cfg, err := a.configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), "credentials", id+".env"), nil
}

// writeCredentialFile writes export lines to a 0600 file in a 0700 directory.
func (a *App) writeCredentialFile(id string, envelope *model.CredentialEnvelope, server string) (string, error) {
	path, err := a.credentialPath(id)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("cannot create the credentials directory: %v", err)
	}
	_ = os.Chmod(filepath.Dir(path), 0o700)
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s\n", credentialFileHeader, envelope.Credential.ExpiresAt.UTC().Format(time.RFC3339))
	for _, kv := range safeCredentialEnv(envelope) {
		fmt.Fprintf(&b, "export %s=%s\n", kv.Name, shellQuote(kv.Value))
	}
	fmt.Fprintf(&b, "export CSG_LEASE_ID=%s\nexport CSG_SERVER=%s\n", shellQuote(id), shellQuote(server))
	// Create with 0600 from the start; replace an older file atomically.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("cannot write the credential file: %v", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", fmt.Errorf("cannot write the credential file: %v", err)
	}
	return path, nil
}

func (a *App) removeCredentialFile(id string) bool {
	path, err := a.credentialPath(id)
	if err != nil {
		return false
	}
	return os.Remove(path) == nil
}

// shellQuote single-quotes a value for POSIX shells.
func shellQuote(s string) string { return "'" + shellSingleQuote(s) + "'" }

// credentialFileHeader starts the first line of every credential file; the
// expiry follows it.
const credentialFileHeader = "# Cloud Safeguard credential, valid until "

// sweepCredentialFiles deletes credential files whose credential has expired,
// so secrets do not pile up on disk. Files it cannot read are left alone.
func (a *App) sweepCredentialFiles(now time.Time) {
	cfg, err := a.configPath()
	if err != nil {
		return
	}
	dir := filepath.Join(filepath.Dir(cfg), "credentials")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".env")
		if !e.Type().IsRegular() || !leaseIDRE.MatchString(id) || id+".env" != e.Name() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		first, _ := bufio.NewReader(io.LimitReader(f, 256)).ReadString('\n')
		f.Close()
		stamp, ok := strings.CutPrefix(strings.TrimSpace(first), strings.TrimSpace(credentialFileHeader))
		if !ok {
			continue
		}
		expires, err := time.Parse(time.RFC3339, strings.TrimSpace(stamp))
		if err == nil && !now.Before(expires) {
			_ = os.Remove(path)
		}
	}
}
