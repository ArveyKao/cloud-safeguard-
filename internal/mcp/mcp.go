// Package mcp is the Model Context Protocol layer shared by `csg mcp` (stdio,
// CONTRACT §17.7) and the server's remote endpoint (/mcp, §17.10): JSON-RPC
// messages, the tool list and the tool calls. Both are thin clients of the
// agent API; how a call reaches the API and how a credential is handed over
// is up to the host.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// MaxMessage bounds one JSON-RPC message or batch.
const MaxMessage = 1 << 20

// LeaseIDRE matches a request (lease) id.
var LeaseIDRE = regexp.MustCompile(`^lea_[0-9a-f]{32}$`)

const apiPrefix = "/api/v1"

// Request is one JSON-RPC request or notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Error is a JSON-RPC error.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Response is one JSON-RPC response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Tool is one entry of tools/list.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Text is a text content block.
type Text struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ToolResult is the result of tools/call.
type ToolResult struct {
	Content []Text `json:"content"`
	IsError bool   `json:"isError"`
}

// Backend calls the agent API as the signed-in agent. An error's message is
// shown to the model, so it must hold nothing secret.
type Backend interface {
	Call(ctx context.Context, method, path string, in, out any) error
}

// Server answers MCP messages for one agent.
type Server struct {
	Backend Backend
	// Versions are the protocol revisions spoken, newest first.
	Versions []string
	// CredentialDescription describes get_credential: how the secret is
	// handed over.
	CredentialDescription string
	// RevokeDescription describes revoke.
	RevokeDescription string
	// PrepareCredential hands over the credential of an active request and
	// returns what the model is told: never the secret itself.
	PrepareCredential func(ctx context.Context, requestID string) (map[string]any, error)
	// AfterRevoke, when set, runs after a revoke call (successful or not)
	// and may add fields to the answer.
	AfterRevoke func(requestID string) map[string]any
}

func schema(required []string, props map[string]any) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

// Tools returns the tool list.
func (s *Server) Tools() []Tool {
	return []Tool{
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
				"resource":         str("Resource type, from list_accounts (for example ecs, dns, oss on Alibaba Cloud, s3 on AWS)."),
				"permission":       map[string]any{"type": "string", "enum": []string{"read", "write", "full"}},
				"ttl_seconds":      map[string]any{"type": "integer", "minimum": 1, "description": "How long one key stays valid. Ask for no more than the task needs; refresh_credential gives a new key later."},
				"max_lifetime_seconds": map[string]any{"type": "integer", "minimum": 1,
					"description": "Optional: how long you may keep refreshing the key with refresh_credential, from first issue. Default 8 hours."},
				"resource_name": str("Optional: one resource (instance ID, domain, bucket). Omit for all resources of that type."),
				"reason":        str("Why you need it. Required for write and full; your owner sees it."),
			}),
		},
		{
			Name:        "check_status",
			Description: "Check an access request: pending, active, denied, expired or revoked.",
			InputSchema: schema([]string{"request_id"}, map[string]any{"request_id": str("The id returned by request_access.")}),
		},
		{
			Name:        "get_credential",
			Description: s.CredentialDescription,
			InputSchema: schema([]string{"request_id"}, map[string]any{"request_id": str("The id returned by request_access.")}),
		},
		{
			Name: "refresh_credential",
			Description: "Get a new key for an active request before the current one expires, within the request's refresh window " +
				"(refresh_until in check_status), then hand it over as get_credential does. The earlier key keeps working until its own expiry. " +
				"At most once a minute per request.",
			InputSchema: schema([]string{"request_id"}, map[string]any{"request_id": str("The id returned by request_access.")}),
		},
		{
			Name: "request_long_lived_credential",
			Description: "Ask for a long-lived cloud key (a cloud user with an access key that does not expire), for things like a CDN origin " +
				"or a bucket sync. Only if the person who owns you is allowed by a supervisor. You never receive the key: the answer is a " +
				"console link. Give it to the user; they open it, check it and create the key themselves.",
			InputSchema: schema([]string{"cloud_account_id", "resource", "permission", "reason"}, map[string]any{
				"cloud_account_id": str("Cloud account ID, from list_accounts."),
				"resource":         str("Resource type, from list_accounts."),
				"permission":       map[string]any{"type": "string", "enum": []string{"read", "write", "full"}},
				"resource_name":    str("Optional: one resource (bucket, instance ID, domain). Omit for all of that type."),
				"reason":           str("What the key is for. Shown to the person who creates it."),
			}),
		},
		{
			Name:        "revoke",
			Description: s.RevokeDescription,
			InputSchema: schema([]string{"request_id"}, map[string]any{
				"request_id": str("The id returned by request_access."),
				"reason":     str("Optional reason."),
			}),
		},
	}
}

var nullID = json.RawMessage("null")

// ErrorResponse is a response with only an error and a null id.
func ErrorResponse(code int, message string) Response {
	return Response{JSONRPC: "2.0", ID: nullID, Error: &Error{Code: code, Message: message}}
}

// HandleMessage answers one message or one batch; nil means no reply (only
// notifications were sent).
func (s *Server) HandleMessage(ctx context.Context, msg []byte) any {
	msg = []byte(strings.TrimSpace(string(msg)))
	if len(msg) == 0 {
		return ErrorResponse(-32700, "parse error")
	}
	if msg[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(msg, &batch); err != nil {
			return ErrorResponse(-32700, "parse error")
		}
		if len(batch) == 0 {
			return ErrorResponse(-32600, "empty batch")
		}
		var out []Response
		for _, raw := range batch {
			var req Request
			if err := json.Unmarshal(raw, &req); err != nil {
				out = append(out, ErrorResponse(-32600, "invalid request"))
				continue
			}
			if resp, reply := s.Handle(ctx, req); reply {
				out = append(out, resp)
			}
		}
		if len(out) == 0 {
			return nil
		}
		return out
	}
	var req Request
	if err := json.Unmarshal(msg, &req); err != nil {
		return ErrorResponse(-32700, "parse error")
	}
	if resp, reply := s.Handle(ctx, req); reply {
		return resp
	}
	return nil
}

// IsNotification reports whether a request expects no answer.
func IsNotification(req Request) bool {
	return len(req.ID) == 0 || string(req.ID) == "null"
}

// Handle answers one message; reply is false for notifications.
func (s *Server) Handle(ctx context.Context, req Request) (Response, bool) {
	resp := Response{JSONRPC: "2.0", ID: req.ID}
	// A notification gets no answer, so it must not do anything either: a
	// tools/call without an id would otherwise fetch or revoke unseen.
	if IsNotification(req) {
		return resp, false
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := s.Versions[0]
		for _, v := range s.Versions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		resp.Result = map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "cloud-safeguard", "version": model.Version},
			"instructions": "Use list_accounts to see where you may ask for access, request_access to get short-lived scoped credentials, " +
				"get_credential to prepare them for a shell, refresh_credential for a new key before one expires, and revoke when done. Ask for the lowest permission and shortest validity that does the job.",
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": s.Tools()}
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			resp.Error = &Error{Code: -32602, Message: "invalid params"}
			break
		}
		text, err := s.callTool(ctx, p.Name, p.Arguments)
		if err != nil {
			resp.Result = ToolResult{Content: []Text{{Type: "text", Text: err.Error()}}, IsError: true}
		} else {
			resp.Result = ToolResult{Content: []Text{{Type: "text", Text: text}}}
		}
	default:
		resp.Error = &Error{Code: -32601, Message: "method not found: " + req.Method}
	}
	return resp, true
}

// RequestView is what the model sees about a request: no secrets.
func RequestView(req model.AccessRequest) map[string]any {
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
	if req.RefreshUntil != nil {
		v["refresh_until"] = req.RefreshUntil.UTC().Format(time.RFC3339)
	}
	if req.MaxLifetimeSeconds > 0 {
		v["max_lifetime_seconds"] = req.MaxLifetimeSeconds
		v["refresh_count"] = req.RefreshCount
	}
	switch req.Status {
	case model.LeasePending:
		v["next"] = "Waiting for the person who owns you to approve it in the Cloud Safeguard console. Tell the user, then call check_status."
	case model.LeaseActive:
		v["next"] = "Call get_credential to prepare it for a shell; call refresh_credential for a new key before expires_at, until refresh_until."
	case model.LeaseDenied:
		v["denied_reason"] = req.DeniedReason
	case model.LeaseRevoked:
		v["revoke_reason"] = req.RevokeReason
	}
	return v
}

// ToJSON renders a tool answer.
func ToJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func (s *Server) callTool(ctx context.Context, name string, raw json.RawMessage) (string, error) {
	var args map[string]any
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &args); err != nil {
			return "", errors.New("arguments must be a JSON object")
		}
	}
	getStr := func(key string) string {
		s, _ := args[key].(string)
		return strings.TrimSpace(s)
	}
	requestID := func() (string, error) {
		id := getStr("request_id")
		if !LeaseIDRE.MatchString(id) {
			return "", errors.New("request_id must be an id returned by request_access")
		}
		return id, nil
	}
	switch name {
	case "list_accounts":
		var list struct {
			Items []model.AgentAccount `json:"items"`
		}
		if err := s.Backend.Call(ctx, "GET", apiPrefix+"/agent/accounts", nil, &list); err != nil {
			return "", err
		}
		if len(list.Items) == 0 {
			return "No cloud accounts. The person who owns you has no role on any cloud account yet; a supervisor gives them one.", nil
		}
		return ToJSON(list.Items), nil

	case "request_access":
		ttl, ok := args["ttl_seconds"].(float64)
		if !ok || ttl != float64(int(ttl)) || ttl < 1 {
			return "", errors.New("ttl_seconds must be a positive whole number")
		}
		in := model.AccessRequestInput{
			CloudAccountID: getStr("cloud_account_id"), Resource: getStr("resource"), Permission: getStr("permission"),
			TTLSeconds: int(ttl), ResourceName: getStr("resource_name"), Reason: getStr("reason"),
		}
		if v, present := args["max_lifetime_seconds"]; present {
			lifetime, ok := v.(float64)
			if !ok || lifetime != float64(int(lifetime)) || lifetime < 1 {
				return "", errors.New("max_lifetime_seconds must be a positive whole number")
			}
			in.MaxLifetimeSeconds = int(lifetime)
		}
		var req model.AccessRequest
		if err := s.Backend.Call(ctx, "POST", apiPrefix+"/agent/access-requests", in, &req); err != nil {
			return "", err
		}
		return ToJSON(RequestView(req)), nil

	case "check_status":
		id, err := requestID()
		if err != nil {
			return "", err
		}
		var req model.AccessRequest
		if err := s.Backend.Call(ctx, "GET", apiPrefix+"/agent/access-requests/"+url.PathEscape(id), nil, &req); err != nil {
			return "", err
		}
		return ToJSON(RequestView(req)), nil

	case "get_credential":
		id, err := requestID()
		if err != nil {
			return "", err
		}
		out, err := s.PrepareCredential(ctx, id)
		if err != nil {
			return "", err
		}
		return ToJSON(out), nil

	case "request_long_lived_credential":
		in := model.LongLivedRequestInput{CloudAccountID: getStr("cloud_account_id"), Resource: getStr("resource"),
			Permission: getStr("permission"), ResourceName: getStr("resource_name"), Reason: getStr("reason")}
		var out model.LongLivedRequestResult
		if err := s.Backend.Call(ctx, "POST", apiPrefix+"/agent/long-lived", in, &out); err != nil {
			return "", err
		}
		return ToJSON(map[string]any{
			"id": out.ID, "status": out.Status, "link": out.Link, "link_expires_at": out.ExpiresAt.UTC().Format(time.RFC3339),
			"next": "Give the user this link. They open it signed in to the Cloud Safeguard console, check it and create the key; " +
				"the secret is shown only to them. You will not receive it.",
		}), nil

	case "refresh_credential":
		id, err := requestID()
		if err != nil {
			return "", err
		}
		var req model.AccessRequest
		if err := s.Backend.Call(ctx, "POST", apiPrefix+"/agent/access-requests/"+url.PathEscape(id)+"/refresh", nil, &req); err != nil {
			return "", err
		}
		out, err := s.PrepareCredential(ctx, id)
		if err != nil {
			return "", err
		}
		return ToJSON(out), nil

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
		revokeErr := s.Backend.Call(ctx, "POST", apiPrefix+"/agent/leases/"+url.PathEscape(id)+"/revoke", model.RevokeLeaseInput{Reason: reason}, &lease)
		var extra map[string]any
		if s.AfterRevoke != nil {
			extra = s.AfterRevoke(id)
		}
		if revokeErr != nil {
			return "", revokeErr
		}
		out := map[string]any{"request_id": id, "status": lease.Status}
		for k, v := range extra {
			out[k] = v
		}
		return ToJSON(out), nil
	}
	return "", fmt.Errorf("unknown tool %q", name)
}
