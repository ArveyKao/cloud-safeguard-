package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/mcp"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// Remote MCP endpoint (CONTRACT §17.10): Streamable HTTP without
// server-sent events. Each request carries one JSON-RPC message or a batch
// and is answered as application/json. The tools call the agent API in
// process, so every rule, limit and audit of that API applies.
const (
	credentialLinkTTL     = 60 * time.Second
	maxOpenCredentialLink = 20
	credentialLinkPrefix  = "/api/v1/credential-links/"
)

var (
	remoteMCPVersions  = []string{"2025-06-18", "2025-03-26"}
	credentialLinkRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	shellEnvNames      = []string{"ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET", "ALIBABA_CLOUD_SECURITY_TOKEN", "CSG_LEASE_ID", "CSG_SERVER", "CSG_CAPABILITY"}
	errBackendInternal = errors.New("internal error")
)

// bufferedResponse captures a handler's response in memory.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponse() *bufferedResponse { return &bufferedResponse{header: http.Header{}} }

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(code int) {
	if b.status == 0 {
		b.status = code
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

// apiError reads the message of an error envelope.
func (b *bufferedResponse) apiError() error {
	var body model.ErrorBody
	if json.Unmarshal(b.body.Bytes(), &body) == nil && body.Error.Message != "" {
		if b.status >= 500 {
			return errBackendInternal
		}
		return errors.New(body.Error.Message)
	}
	return fmt.Errorf("request failed with status %d", b.status)
}

// decodeData reads the data of a success envelope into out.
func (b *bufferedResponse) decodeData(out any) error {
	if b.status < 200 || b.status > 299 {
		return b.apiError()
	}
	if out == nil {
		return nil
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b.body.Bytes(), &env); err != nil {
		return errBackendInternal
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return errBackendInternal
	}
	return nil
}

// inProcessRequest builds a request to the agent API for the agent in ctx,
// carrying the original request's peer, forwarding headers, host and TLS
// state so addresses and URLs come out as for a direct call.
func inProcessRequest(ctx context.Context, orig *http.Request, method, path string, in any) (*http.Request, error) {
	var body io.Reader = http.NoBody
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if v := orig.Header.Values("X-Forwarded-For"); len(v) > 0 {
		req.Header["X-Forwarded-For"] = v
	}
	req.RemoteAddr, req.Host, req.TLS = orig.RemoteAddr, orig.Host, orig.TLS
	return req, nil
}

// inProcessBackend calls the agent API without a network round trip.
type inProcessBackend struct {
	s    *Server
	orig *http.Request
}

func (b inProcessBackend) Call(ctx context.Context, method, path string, in, out any) error {
	req, err := inProcessRequest(ctx, b.orig, method, path, in)
	if err != nil {
		return errBackendInternal
	}
	resp := newBufferedResponse()
	b.s.agentAPI.ServeHTTP(resp, req)
	return resp.decodeData(out)
}

// remoteMCPServer is the MCP server for one request of a signed-in agent.
func (s *Server) remoteMCPServer(r *http.Request, ag model.Agent) *mcp.Server {
	backend := inProcessBackend{s: s, orig: r}
	return &mcp.Server{
		Backend:  backend,
		Versions: remoteMCPVersions,
		CredentialDescription: "Prepare the credential of an active request for a shell. The secret is NOT returned here: you get a one-time link, valid for 60 seconds, " +
			"and run the given eval command in the shell that runs the cloud command (aliyun CLI, SDKs, terraform). Never print the variables it sets.",
		RevokeDescription: "End an access request early. Do this as soon as the task is done.",
		PrepareCredential: func(ctx context.Context, id string) (map[string]any, error) {
			return s.prepareCredentialLink(ctx, backend, ag, id)
		},
	}
}

// prepareCredentialLink checks that the request is the agent's and active,
// and creates a one-time link to its credential.
func (s *Server) prepareCredentialLink(ctx context.Context, backend inProcessBackend, ag model.Agent, id string) (map[string]any, error) {
	var lease model.Lease
	if err := backend.Call(ctx, http.MethodGet, "/api/v1/agent/leases/"+id, nil, &lease); err != nil {
		return nil, err
	}
	now := s.nowUTC()
	if lease.Status != model.LeaseActive {
		return nil, fmt.Errorf("the request is %s; a credential is only available while it is active", lease.Status)
	}
	if lease.ExpiresAt == nil || !lease.ExpiresAt.After(now) {
		return nil, errors.New("the credential has expired")
	}
	linkToken, linkHash, err := authn.NewSecret(32)
	if err != nil {
		return nil, errBackendInternal
	}
	if err := s.db.CreateCredentialLink(ctx, linkHash, lease.ID, ag.ID, now, now.Add(credentialLinkTTL), maxOpenCredentialLink); err != nil {
		if errors.Is(err, store.ErrOAuthLimit) {
			return nil, errors.New("too many unused credential links; use or let them expire first")
		}
		s.logf("create credential link: %v", err)
		return nil, errBackendInternal
	}
	s.agentAudit(ctx, ag, "lease.credential_link_created", "ok", "info", "lease", lease.ID, map[string]any{
		"remote_addr": s.clientAddr(backend.orig), "link_expires_at": now.Add(credentialLinkTTL),
	})
	link := s.expectedOrigin(backend.orig) + credentialLinkPrefix + linkToken
	return map[string]any{
		"request_id":         lease.ID,
		"credential_expires": lease.ExpiresAt.UTC().Format(time.RFC3339),
		"run":                `eval "$(curl -fsS -X POST ` + shellQuoteValue(link) + `)"`,
		"note": "Run this once, within 60 seconds, in the shell that runs the cloud command; it sets the credential's environment variables there. " +
			"The link works once. The secret is not shown here; do not print it. Revoke the request when done.",
	}, nil
}

// handleMCP is the remote MCP endpoint. requireAgent has authenticated the
// agent.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	ag, ok := agentFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "agent token required")
		return
	}
	if v := r.Header.Get("MCP-Protocol-Version"); v != "" && !containsString(remoteMCPVersions, v) {
		s.writeError(w, http.StatusBadRequest, model.ErrCodeInvalidRequest, "unsupported MCP-Protocol-Version")
		return
	}
	if !isJSONRequest(r) {
		s.writeError(w, http.StatusUnsupportedMediaType, model.ErrCodeInvalidRequest, "Content-Type must be application/json")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, mcp.MaxMessage+1))
	if err != nil {
		s.badRequest(w, "unreadable body")
		return
	}
	if len(body) > mcp.MaxMessage {
		s.writeMCPJSON(w, http.StatusRequestEntityTooLarge, mcp.ErrorResponse(-32600, "message too large"))
		return
	}
	out := s.remoteMCPServer(r, ag).HandleMessage(r.Context(), body)
	if out == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	s.writeMCPJSON(w, http.StatusOK, out)
}

func (s *Server) writeMCPJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.logf("write mcp response: %v", err)
	}
}

// mcpChallenge adds the OAuth challenge (RFC 9728) to a 401 from the agent
// authentication, so a client learns where to sign in.
type mcpChallenge struct {
	http.ResponseWriter
	challenge string
}

func (c mcpChallenge) WriteHeader(code int) {
	if code == http.StatusUnauthorized {
		c.ResponseWriter.Header().Set("WWW-Authenticate", c.challenge)
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c mcpChallenge) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// mcpGate guards /mcp: a browser request from another origin is refused
// (DNS rebinding), only POST is served, and an unauthenticated request is
// told where to sign in.
func (s *Server) mcpGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if raw := r.Header.Get("Origin"); raw != "" {
			if origin, ok := normalizeOrigin(raw); !ok || origin != s.expectedOrigin(r) {
				s.writeError(w, http.StatusForbidden, model.ErrCodeForbidden, "cross-site request refused")
				return
			}
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			s.writeError(w, http.StatusMethodNotAllowed, model.ErrCodeInvalidRequest, "this MCP server answers POST only; it does not stream")
			return
		}
		challenge := `Bearer resource_metadata="` + s.protectedResourceMetadataURL(r) + `"`
		next.ServeHTTP(mcpChallenge{ResponseWriter: w, challenge: challenge}, r)
	})
}

// handleCredentialLink releases a credential once, through a link made by
// get_credential, as shell export lines. Every release check of the
// credential endpoint applies again now.
func (s *Server) handleCredentialLink(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, message string) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		// curl -f prints nothing on failure; a shell that evals the body
		// anyway only runs a comment and an echo to stderr.
		fmt.Fprintf(w, "echo %s >&2\n", shellQuoteValue("Cloud Safeguard: "+message))
	}
	linkToken := r.PathValue("token")
	if !credentialLinkRE.MatchString(linkToken) {
		fail(http.StatusNotFound, "this credential link is unknown, used or expired; call get_credential again")
		return
	}
	ctx := r.Context()
	leaseID, agentID, err := s.db.UseCredentialLink(ctx, authn.HashSecret(linkToken), s.nowUTC())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			fail(http.StatusNotFound, "this credential link is unknown, used or expired; call get_credential again")
			return
		}
		s.logf("use credential link: %v", err)
		fail(http.StatusInternalServerError, "internal error")
		return
	}
	ag, err := s.db.GetAgent(ctx, agentID)
	if err != nil {
		s.logf("credential link: read agent: %v", err)
		fail(http.StatusForbidden, "the agent no longer exists")
		return
	}
	problem := ""
	if ag.Status != model.AgentActive {
		problem = "agent is " + string(ag.Status)
	} else if problem, err = s.agentOwnerProblem(ctx, ag); err != nil {
		s.logf("credential link: check owner: %v", err)
		fail(http.StatusInternalServerError, "internal error")
		return
	}
	if problem != "" {
		s.systemAudit(ctx, "auth.agent_auth_failed", "denied", "warning", "agent", ag.ID, map[string]any{
			"remote_addr": s.clientAddr(r), "reason": problem, "via": "credential link",
		})
		fail(http.StatusForbidden, problem)
		return
	}
	req, err := inProcessRequest(context.WithValue(ctx, agentContextKey{}, ag), r, http.MethodPost, "/api/v1/agent/leases/"+leaseID+"/credential", nil)
	if err != nil {
		fail(http.StatusInternalServerError, "internal error")
		return
	}
	resp := newBufferedResponse()
	s.agentAPI.ServeHTTP(resp, req)
	var envelope model.CredentialEnvelope
	if err := resp.decodeData(&envelope); err != nil {
		status := resp.status
		if status < 400 {
			status = http.StatusInternalServerError
		}
		fail(status, err.Error())
		return
	}
	values := map[string]string{}
	for _, kv := range envelope.Env {
		values[kv.Name] = kv.Value
	}
	var b strings.Builder
	for _, name := range shellEnvNames {
		if v := values[name]; v != "" {
			fmt.Fprintf(&b, "export %s=%s\n", name, shellQuoteValue(v))
		}
	}
	fmt.Fprintf(&b, "echo %s >&2\n", shellQuoteValue("Cloud Safeguard: credential for "+leaseID+" set in this shell, valid until "+
		envelope.Credential.ExpiresAt.UTC().Format(time.RFC3339)))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, b.String())
}

// shellQuoteValue single-quotes a value for POSIX shells.
func shellQuoteValue(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }
