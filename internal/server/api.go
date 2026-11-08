package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/policy"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/token"
)

// agentContextKey keys the authenticated agent in a request context.
type agentContextKey struct{}

// agentFromContext returns the authenticated agent for an agent request.
func agentFromContext(ctx context.Context) (model.Agent, bool) {
	ag, ok := ctx.Value(agentContextKey{}).(model.Agent)
	return ag, ok
}

// buildHandler assembles the complete HTTP surface: health, agent API, admin
// API, mock cloud, and the embedded SPA.
func (s *Server) buildHandler() http.Handler {
	agentMux := http.NewServeMux()
	agentMux.HandleFunc("GET /api/v1/agent/me", s.handleAgentMe)
	agentMux.HandleFunc("GET /api/v1/agent/capabilities", s.handleAgentCapabilities)
	agentMux.HandleFunc("POST /api/v1/agent/leases", s.handleAgentCreateLease)
	agentMux.HandleFunc("GET /api/v1/agent/leases", s.handleAgentListLeases)
	agentMux.HandleFunc("GET /api/v1/agent/leases/{id}", s.handleAgentGetLease)
	agentMux.HandleFunc("POST /api/v1/agent/leases/{id}/credential", s.handleAgentFetchCredential)
	agentMux.HandleFunc("POST /api/v1/agent/leases/{id}/revoke", s.handleAgentRevokeLease)
	agentMux.HandleFunc("POST /api/v1/agent/heartbeat", s.handleAgentHeartbeat)
	agentMux.HandleFunc("/", s.handleUnknownAPI)

	adminMux := http.NewServeMux()
	adminMux.HandleFunc("POST /api/v1/admin/login", s.handleAdminLogin)
	adminMux.HandleFunc("GET /api/v1/admin/overview", s.handleAdminOverview)
	adminMux.HandleFunc("GET /api/v1/admin/providers", s.handleAdminListProviders)
	adminMux.HandleFunc("POST /api/v1/admin/providers", s.handleAdminCreateProvider)
	adminMux.HandleFunc("GET /api/v1/admin/providers/{id}", s.handleAdminGetProvider)
	adminMux.HandleFunc("PATCH /api/v1/admin/providers/{id}", s.handleAdminUpdateProvider)
	adminMux.HandleFunc("POST /api/v1/admin/providers/{id}/rotate", s.handleAdminRotateProvider)
	adminMux.HandleFunc("POST /api/v1/admin/providers/{id}/test", s.handleAdminTestProvider)
	adminMux.HandleFunc("GET /api/v1/admin/capabilities", s.handleAdminListCapabilities)
	adminMux.HandleFunc("POST /api/v1/admin/capabilities", s.handleAdminCreateCapability)
	adminMux.HandleFunc("PATCH /api/v1/admin/capabilities/{id}", s.handleAdminUpdateCapability)
	adminMux.HandleFunc("GET /api/v1/admin/agents", s.handleAdminListAgents)
	adminMux.HandleFunc("POST /api/v1/admin/agents", s.handleAdminCreateAgent)
	adminMux.HandleFunc("GET /api/v1/admin/agents/{id}", s.handleAdminGetAgent)
	adminMux.HandleFunc("PATCH /api/v1/admin/agents/{id}", s.handleAdminUpdateAgent)
	adminMux.HandleFunc("POST /api/v1/admin/agents/{id}/suspend", s.handleAdminSuspendAgent)
	adminMux.HandleFunc("POST /api/v1/admin/agents/{id}/activate", s.handleAdminActivateAgent)
	adminMux.HandleFunc("POST /api/v1/admin/agents/{id}/token/rotate", s.handleAdminRotateAgentToken)
	adminMux.HandleFunc("GET /api/v1/admin/leases", s.handleAdminListLeases)
	adminMux.HandleFunc("GET /api/v1/admin/leases/{id}", s.handleAdminGetLease)
	adminMux.HandleFunc("POST /api/v1/admin/leases/{id}/approve", s.handleAdminApproveLease)
	adminMux.HandleFunc("POST /api/v1/admin/leases/{id}/deny", s.handleAdminDenyLease)
	adminMux.HandleFunc("POST /api/v1/admin/leases/{id}/revoke", s.handleAdminRevokeLease)
	adminMux.HandleFunc("GET /api/v1/admin/audit", s.handleAdminListAudit)
	adminMux.HandleFunc("GET /api/v1/admin/audit/verify", s.handleAdminVerifyAudit)
	adminMux.HandleFunc("GET /api/v1/admin/policy", s.handleAdminGetPolicy)
	adminMux.HandleFunc("PUT /api/v1/admin/policy", s.handleAdminPutPolicy)
	adminMux.HandleFunc("/", s.handleUnknownAPI)

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", s.handleHealth)
	root.Handle("/api/v1/agent/", s.requireAgent(agentMux))
	root.Handle("/api/v1/admin/", s.requireAdmin(adminMux))
	root.HandleFunc("/mock-cloud/", s.handleMockCloud)
	root.HandleFunc("/", s.handleStatic)

	return s.withAccessLog(s.recoverPanics(root))
}

// ================= middleware =================

// requireAgent authenticates an agent bearer token and rejects suspended or
// revoked agents on every agent endpoint.
func (s *Server) requireAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain, ok := bearerToken(r)
		if !ok {
			s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "missing or malformed bearer token")
			return
		}
		if token.Kind(plain) != "agent" {
			// A token of the wrong kind is always 401 (CONTRACT §2).
			s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "agent token required")
			return
		}
		ag, err := s.db.GetAgentByTokenHash(r.Context(), token.Hash(plain))
		if err != nil {
			s.systemAudit(r.Context(), "auth.agent_auth_failed", "denied", "warning", "agent", "", map[string]any{
				"remote_addr":  remoteHost(r),
				"token_prefix": token.DisplayPrefix(plain),
				"reason":       "unknown token",
			})
			s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "invalid agent token")
			return
		}
		if ag.Status != model.AgentActive {
			s.systemAudit(r.Context(), "auth.agent_auth_failed", "denied", "warning", "agent", ag.ID, map[string]any{
				"remote_addr":  remoteHost(r),
				"token_prefix": token.DisplayPrefix(plain),
				"reason":       "agent is " + string(ag.Status),
			})
			s.writeError(w, http.StatusForbidden, model.ErrCodeForbidden, "agent is "+string(ag.Status))
			return
		}
		// Refresh last_seen_at at most once per 60 s.
		now := s.nowUTC()
		if ag.LastSeenAt == nil || now.Sub(*ag.LastSeenAt) >= time.Minute {
			if err := s.db.TouchAgentSeen(r.Context(), ag.ID, now); err == nil {
				seen := now
				ag.LastSeenAt = &seen
			}
		}
		ctx := context.WithValue(r.Context(), agentContextKey{}, ag)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireAdmin authenticates the single admin bearer token.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain, ok := bearerToken(r)
		if !ok {
			s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "missing or malformed bearer token")
			return
		}
		if token.Kind(plain) != "admin" {
			s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "admin token required")
			return
		}
		stored, err := s.db.GetMeta(r.Context(), store.MetaAdminTokenHash)
		if err != nil {
			s.logf("admin auth: read token hash: %v", err)
			s.writeError(w, http.StatusInternalServerError, model.ErrCodeInternal, "authentication is not configured")
			return
		}
		if !token.HashEqual(token.Hash(plain), stored) {
			s.systemAudit(r.Context(), "auth.admin_auth_failed", "denied", "warning", "admin", "admin", map[string]any{
				"remote_addr": remoteHost(r),
			})
			s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "invalid admin token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// responseRecorder captures the response status for the access log.
type responseRecorder struct {
	http.ResponseWriter
	status int
}

func (rw *responseRecorder) WriteHeader(code int) {
	if rw.status != 0 {
		return
	}
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseRecorder) Write(b []byte) (int, error) {
	if rw.status == 0 {
		rw.status = http.StatusOK
	}
	return rw.ResponseWriter.Write(b)
}

func (rw *responseRecorder) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (rw *responseRecorder) Unwrap() http.ResponseWriter { return rw.ResponseWriter }

// withAccessLog logs "method path status duration_ms" lines. Never logs
// headers, bodies or query strings (they can carry secrets).
func (s *Server) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		s.logf("%s %s %d %dms", r.Method, r.URL.Path, status, time.Since(start).Milliseconds())
	})
}

// recoverPanics turns a handler panic into a JSON 500 without leaking details.
func (s *Server) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logf("panic serving %s %s: %v", r.Method, r.URL.Path, rec)
				s.writeError(w, http.StatusInternalServerError, model.ErrCodeInternal, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ================= JSON helpers =================

// dataEnvelope is the success envelope: {"data": <payload>}.
type dataEnvelope struct {
	Data any `json:"data"`
}

// listData is the collection payload inside the success envelope.
type listData[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

// writeData writes a success envelope.
func (s *Server) writeData(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(dataEnvelope{Data: payload}); err != nil {
		s.logf("write response: %v", err)
	}
}

// writeList writes a {"data":{"items":[...],"total":N}} envelope.
func writeList[T any](s *Server, w http.ResponseWriter, status int, items []T, total int) {
	if items == nil {
		items = []T{}
	}
	s.writeData(w, status, listData[T]{Items: items, Total: total})
}

// writeError writes the standard error envelope.
func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	s.writeErrorDetails(w, status, code, message, nil)
}

// writeErrorDetails writes the standard error envelope with details.
func (s *Server) writeErrorDetails(w http.ResponseWriter, status int, code, message string, details map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	body := model.ErrorBody{Error: model.ErrorDetail{Code: code, Message: message, Details: details}}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.logf("write error response: %v", err)
	}
}

// badRequest writes a 400 invalid_request error.
func (s *Server) badRequest(w http.ResponseWriter, message string) {
	s.writeError(w, http.StatusBadRequest, model.ErrCodeInvalidRequest, message)
}

// storeErrorResponse maps a store error onto the API error envelope.
func (s *Server) storeErrorResponse(w http.ResponseWriter, err error, notFoundMessage string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		if notFoundMessage == "" {
			notFoundMessage = "not found"
		}
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, notFoundMessage)
	case errors.Is(err, store.ErrConflict):
		s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "resource already exists")
	default:
		s.logf("store error: %v", err)
		s.writeError(w, http.StatusInternalServerError, model.ErrCodeInternal, "internal error")
	}
}

// decodeJSON decodes an optional JSON request body (limit 1 MiB). An empty body
// decodes to the zero value of dst.
func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	if r.Body == nil {
		return nil
	}
	if r.ContentLength == 0 {
		return nil
	}
	body := http.MaxBytesReader(w, r.Body, maxRequestBody)
	dec := json.NewDecoder(body)
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return nil // empty body
		}
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return errors.New("request body exceeds the 1 MiB limit")
		}
		return err
	}
	// Reject trailing data so clients cannot smuggle a second document.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain a single JSON document")
	}
	return nil
}

// ================= auth / request helpers =================

// bearerToken extracts a bearer token from the Authorization header.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", false
	}
	scheme, rest, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	value := strings.TrimSpace(rest)
	if value == "" {
		return "", false
	}
	return value, true
}

// remoteHost returns the client IP (without port) for audit metadata.
func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// intQuery parses an optional integer query parameter.
func intQuery(r *http.Request, key string, defaultValue int) (int, error) {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return defaultValue, nil
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", key)
	}
	return v, nil
}

// limitOffset parses the standard pagination query parameters.
func limitOffset(r *http.Request) (limit, offset int, err error) {
	limit, err = intQuery(r, "limit", 50)
	if err != nil {
		return 0, 0, err
	}
	offset, err = intQuery(r, "offset", 0)
	if err != nil {
		return 0, 0, err
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		return 0, 0, errors.New("offset must not be negative")
	}
	return limit, offset, nil
}

// timeQuery parses an optional timestamp query parameter. It accepts RFC3339
// and integer unix seconds/milliseconds (the console sends RFC3339).
func timeQuery(r *http.Request, key string) (time.Time, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t.UTC(), nil
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if n > 1_000_000_000_000 { // milliseconds
			return time.UnixMilli(n).UTC(), nil
		}
		return time.Unix(n, 0).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("%s must be an RFC3339 timestamp or unix time", key)
}

// ================= misc helpers =================

// newID generates a domain identifier with the given prefix.
func newID(prefix string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return prefix + hex.EncodeToString(buf), nil
}

// maskAccessKeyID renders an AccessKey ID for display: first4****last4.
func maskAccessKeyID(id string) string {
	if id == "" {
		return ""
	}
	if len(id) <= 8 {
		return "****"
	}
	return id[:4] + "****" + id[len(id)-4:]
}

// sanitizeMessage normalizes an error message for persistence/audit responses.
// It strips control characters and truncates long provider messages; callers
// must only pass messages that cannot contain secrets.
func sanitizeMessage(msg string) string {
	msg = strings.TrimSpace(msg)
	var b strings.Builder
	for _, r := range msg {
		if r == '\n' || r == '\r' || r == '\t' {
			b.WriteRune(' ')
			continue
		}
		if r < 0x20 {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	const maxLen = 500
	if len(out) > maxLen {
		out = out[:maxLen] + "…"
	}
	return out
}

// sanitizeSessionName keeps a role-session name within Alibaba Cloud limits
// ([A-Za-z0-9._-], 2-64 chars) as required by CONTRACT §8.1.
func sanitizeSessionName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
		if b.Len() >= 64 {
			break
		}
	}
	out := b.String()
	for len(out) < 2 {
		out += "x"
	}
	return out
}

// ================= audit helpers =================

// appendAudit appends an audit event, logging (never leaking) append failures.
func (s *Server) appendAudit(ctx context.Context, ev model.AuditEvent) {
	if err := s.db.AppendAudit(ctx, &ev); err != nil {
		s.logf("audit append failed: %v", err)
	}
}

// agentAudit appends an audit event attributed to an agent.
func (s *Server) agentAudit(ctx context.Context, ag model.Agent, action, status, severity, targetType, targetID string, metadata map[string]any) {
	s.appendAudit(ctx, model.AuditEvent{
		ActorType:  "agent",
		ActorID:    ag.ID,
		ActorName:  ag.Name,
		Action:     action,
		Status:     status,
		Severity:   severity,
		TargetType: targetType,
		TargetID:   targetID,
		Metadata:   metadata,
	})
}

// adminAudit appends an audit event attributed to the operator.
func (s *Server) adminAudit(ctx context.Context, action, status, severity, targetType, targetID string, metadata map[string]any) {
	s.appendAudit(ctx, model.AuditEvent{
		ActorType:  "admin",
		ActorID:    "admin",
		ActorName:  "operator",
		Action:     action,
		Status:     status,
		Severity:   severity,
		TargetType: targetType,
		TargetID:   targetID,
		Metadata:   metadata,
	})
}

// systemAudit appends an audit event attributed to the control plane itself.
func (s *Server) systemAudit(ctx context.Context, action, status, severity, targetType, targetID string, metadata map[string]any) {
	s.appendAudit(ctx, model.AuditEvent{
		ActorType:  "system",
		ActorID:    "system",
		ActorName:  model.ProductName,
		Action:     action,
		Status:     status,
		Severity:   severity,
		TargetType: targetType,
		TargetID:   targetID,
		Metadata:   metadata,
	})
}

// logf writes a control-plane log line. Callers must never pass secrets.
func (s *Server) logf(format string, args ...any) {
	if s.logWriter != nil {
		s.logWriter.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

// denySeverity returns the audit severity for a denial/revocation event.
func denySeverity(breakGlass bool) string {
	if breakGlass {
		return "critical"
	}
	return "warning"
}

// approveSeverity returns the audit severity for an auto/manual approval.
func approveSeverity(breakGlass bool) string {
	if breakGlass {
		return "critical"
	}
	return "info"
}

// denyDecisionReasons extracts the deny reasons of a policy decision as
// non-secret metadata for the audit log.
func denyDecisionReasons(decision model.PolicyDecision) []string {
	out := make([]string, 0, 4)
	for _, r := range decision.Reasons {
		if r.Outcome == policy.OutcomeDeny {
			out = append(out, r.Rule)
		}
	}
	return out
}
