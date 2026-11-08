// Package mockcloud implements the built-in demo cloud used by mock-mode
// providers. It accepts a locally signed short-lived token minted by the mock
// provider and enforces the exact scoped IAM policy carried in that token. It
// exists so the full lease -> credential -> cloud call -> audit loop can be
// demonstrated and tested without any real cloud account.
//
// FROZEN CONTRACT: NewHandler and Deps are consumed by the HTTP server (which
// mounts the handler under /mock-cloud/). The agent-toolkit owner implements
// this package.
package mockcloud

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// Deps is everything the mock cloud needs.
type Deps struct {
	// Store is used to confirm the lease behind a presented token is still
	// active (so revocation is effective immediately) and to append audit
	// events for each cloud API call.
	Store store.Store
	// SigningKey is the 32-byte HMAC key used to validate mock STS tokens
	// (vault.DeriveKey(masterKey, "mock-sts")).
	SigningKey []byte
}

// maxBodyBytes bounds mock-cloud request bodies (the control plane caps bodies
// at 1 MiB; the mock cloud must not be a bypass).
const maxBodyBytes = 1 << 20

// validRecordTypes are the DNS record types the mock cloud accepts.
var validRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "TXT": true, "MX": true,
}

// handler is the mock cloud implementation.
type handler struct {
	store      store.Store
	signingKey []byte
	now        func() time.Time
	state      *cloudState
}

// authContext is the validated identity behind one mock-cloud request.
type authContext struct {
	lease     model.Lease
	payload   provider.MockTokenPayload
	policy    policyDoc
	agentName string
}

// cloudError is an Aliyun-shaped API error.
type cloudError struct {
	status  int
	code    string
	message string
}

// route binds one HTTP route to the IAM action it requires and the resource it
// authorizes against.
type route struct {
	service  string
	action   string
	resource func(r *http.Request, ac *authContext) string
	handle   func(h *handler, r *http.Request, ac *authContext) (int, map[string]any, *cloudError)
}

// NewHandler returns the http.Handler for the mock cloud API surface. It
// accepts requests either with the "/mock-cloud" prefix already stripped or
// with the full prefix (the server mounts it under /mock-cloud/).
func NewHandler(deps Deps) http.Handler {
	h := &handler{
		store:      deps.Store,
		signingKey: deps.SigningKey,
		now:        time.Now,
		state:      newCloudState(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/ecs/instances", h.wrap(route{
		service: ecsService,
		action:  "ecs:DescribeInstances",
		resource: func(_ *http.Request, ac *authContext) string {
			return ac.ecsInstanceWildcard()
		},
		handle: handleECSListInstances,
	}))
	mux.HandleFunc("GET /v1/ecs/instances/{id}", h.wrap(route{
		service: ecsService,
		action:  "ecs:DescribeInstances",
		resource: func(r *http.Request, ac *authContext) string {
			return ac.ecsInstanceResource(r.PathValue("id"))
		},
		handle: handleECSGetInstance,
	}))
	for _, op := range []struct {
		verb   string
		action string
		status string
	}{
		{"restart", "ecs:RebootInstance", instanceRunning},
		{"start", "ecs:StartInstance", instanceRunning},
		{"stop", "ecs:StopInstance", instanceStopped},
	} {
		op := op
		mux.HandleFunc("POST /v1/ecs/instances/{id}/"+op.verb, h.wrap(route{
			service: ecsService,
			action:  op.action,
			resource: func(r *http.Request, ac *authContext) string {
				return ac.ecsInstanceResource(r.PathValue("id"))
			},
			handle: func(h *handler, r *http.Request, ac *authContext) (int, map[string]any, *cloudError) {
				return handleECSInstanceOp(h, r, ac, op.status)
			},
		}))
	}
	mux.HandleFunc("GET /v1/dns/zones", h.wrap(route{
		service:  dnsService,
		action:   "alidns:DescribeDomains",
		resource: func(_ *http.Request, _ *authContext) string { return "*" },
		handle:   handleDNSListZones,
	}))
	mux.HandleFunc("GET /v1/dns/zones/{zone}/records", h.wrap(route{
		service:  dnsService,
		action:   "alidns:DescribeDomainRecords",
		resource: func(r *http.Request, ac *authContext) string { return ac.alidnsResource(r.PathValue("zone")) },
		handle:   handleDNSListRecords,
	}))
	mux.HandleFunc("POST /v1/dns/zones/{zone}/records", h.wrap(route{
		service:  dnsService,
		action:   "alidns:AddDomainRecord",
		resource: func(r *http.Request, ac *authContext) string { return ac.alidnsResource(r.PathValue("zone")) },
		handle:   handleDNSAddRecord,
	}))
	mux.HandleFunc("DELETE /v1/dns/zones/{zone}/records/{rid}", h.wrap(route{
		service:  dnsService,
		action:   "alidns:DeleteDomainRecord",
		resource: func(r *http.Request, ac *authContext) string { return ac.alidnsResource(r.PathValue("zone")) },
		handle:   handleDNSDeleteRecord,
	}))
	mux.HandleFunc("/", h.handleUnknownRoute)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mock-cloud" || strings.HasPrefix(r.URL.Path, "/mock-cloud/") {
			r = r.Clone(r.Context())
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/mock-cloud")
			if r.URL.Path == "" {
				r.URL.Path = "/"
			}
		}
		mux.ServeHTTP(w, r)
	})
}

// wrap performs the frozen validation pipeline for one route:
// token signature/format -> expiry -> mock provider -> active lease ->
// policy allow -> handler.
func (h *handler) wrap(rt route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := newRequestID()
		ac, cerr := h.authenticate(r)
		if cerr != nil {
			h.auditAPIDenied(reqID, rt, cerr)
			writeCloudError(w, reqID, cerr)
			return
		}

		resource := rt.resource(r, ac)
		if !policyAllows(ac.policy, rt.action, resource) {
			cerr := &cloudError{
				status:  http.StatusForbidden,
				code:    "Forbidden.RAM",
				message: fmt.Sprintf("The action %q on resource %q is not allowed by this credential's policy", rt.action, resource),
			}
			h.auditAPICalled(reqID, ac, rt, resource, cerr.status, cerr.code, "denied", cerr.message)
			writeCloudError(w, reqID, cerr)
			return
		}

		status, payload, cerr := rt.handle(h, r, ac)
		if cerr != nil {
			outcome := "failed"
			if cerr.status == http.StatusForbidden {
				outcome = "denied"
			}
			h.auditAPICalled(reqID, ac, rt, resource, cerr.status, cerr.code, outcome, cerr.message)
			writeCloudError(w, reqID, cerr)
			return
		}
		h.auditAPICalled(reqID, ac, rt, resource, status, "", "ok", "")
		writeJSON(w, reqID, status, payload)
	}
}

// authenticate implements the frozen auth pipeline shared by all routes.
func (h *handler) authenticate(r *http.Request) (*authContext, *cloudError) {
	// 1. Token format and signature.
	token := bearerToken(r)
	if token == "" {
		return nil, &cloudError{
			status:  http.StatusUnauthorized,
			code:    "InvalidSecurityToken",
			message: "The security token is missing or malformed",
		}
	}
	payload, err := provider.VerifyMockToken(token, h.signingKey)
	if err != nil {
		return nil, &cloudError{
			status:  http.StatusUnauthorized,
			code:    "InvalidSecurityToken",
			message: "The security token is invalid",
		}
	}

	// 2. Token expiry.
	now := h.now().UTC()
	expiry, err := payload.Expiry()
	if err != nil || !now.Before(expiry) {
		return nil, &cloudError{
			status:  http.StatusUnauthorized,
			code:    "InvalidSecurityToken.Expired",
			message: "The security token has expired",
		}
	}

	// 3. Provider must exist and be in mock mode.
	prov, err := h.store.GetProvider(r.Context(), payload.ProviderID)
	if err != nil || prov.Mode != model.ModeMock {
		return nil, &cloudError{
			status:  http.StatusUnauthorized,
			code:    "InvalidSecurityToken",
			message: "The security token is not valid for this account",
		}
	}

	// 4. Lease must still be active and unexpired (immediate revocation).
	lease, err := h.store.GetLease(r.Context(), payload.LeaseID)
	if err != nil {
		return nil, &cloudError{
			status:  http.StatusUnauthorized,
			code:    "InvalidSecurityToken.Revoked",
			message: "The security token has been revoked",
		}
	}
	if lease.ProviderID != payload.ProviderID {
		return nil, &cloudError{
			status:  http.StatusUnauthorized,
			code:    "InvalidSecurityToken",
			message: "The security token is not valid for this account",
		}
	}
	switch lease.Status {
	case model.LeaseActive:
		// continue
	case model.LeaseExpired:
		return nil, &cloudError{
			status:  http.StatusUnauthorized,
			code:    "InvalidSecurityToken.Expired",
			message: "The security token has expired",
		}
	default:
		return nil, &cloudError{
			status:  http.StatusUnauthorized,
			code:    "InvalidSecurityToken.Revoked",
			message: "The security token has been revoked",
		}
	}
	if lease.ExpiresAt == nil || !now.Before(*lease.ExpiresAt) {
		return nil, &cloudError{
			status:  http.StatusUnauthorized,
			code:    "InvalidSecurityToken.Expired",
			message: "The security token has expired",
		}
	}

	// 5. Policy document carried in the token must be usable.
	doc, err := parsePolicyDoc(payload.Policy)
	if err != nil {
		return nil, &cloudError{
			status:  http.StatusUnauthorized,
			code:    "InvalidSecurityToken",
			message: "The security token carries an invalid policy",
		}
	}

	ac := &authContext{lease: lease, payload: payload, policy: doc}
	if agent, err := h.store.GetAgent(r.Context(), lease.AgentID); err == nil {
		ac.agentName = agent.Name
	}
	return ac, nil
}

// handleUnknownRoute answers unsupported paths with an Aliyun-shaped 404 and an
// audit entry. It never echoes the request body or headers.
func (h *handler) handleUnknownRoute(w http.ResponseWriter, r *http.Request) {
	reqID := newRequestID()
	cerr := &cloudError{
		status:  http.StatusNotFound,
		code:    "InvalidAction.NotFound",
		message: "The specified mock-cloud route is not supported",
	}
	h.auditAPIDenied(reqID, route{}, cerr)
	writeCloudError(w, reqID, cerr)
}

// auditAPICalled appends a cloud.api_called audit event for an authenticated
// request.
func (h *handler) auditAPICalled(reqID string, ac *authContext, rt route, resource string, httpStatus int, code, outcome, reason string) {
	severity := "info"
	if outcome == "denied" {
		severity = "warning"
	}
	metadata := map[string]any{
		"service":     rt.service,
		"action":      rt.action,
		"resource":    resource,
		"http_status": httpStatus,
		"request_id":  reqID,
	}
	if code != "" {
		metadata["code"] = code
	}
	if reason != "" {
		metadata["reason"] = reason
	}
	ev := model.AuditEvent{
		Time:       h.now().UTC(),
		ActorType:  "agent",
		ActorID:    ac.lease.AgentID,
		ActorName:  ac.agentName,
		Action:     "cloud.api_called",
		Status:     outcome,
		Severity:   severity,
		TargetType: "lease",
		TargetID:   ac.lease.ID,
		Metadata:   metadata,
	}
	h.appendAudit(&ev)
}

// auditAPIDenied appends a cloud.api_denied audit event for a request that
// could not be authenticated or routed.
func (h *handler) auditAPIDenied(reqID string, rt route, cerr *cloudError) {
	metadata := map[string]any{
		"reason":      cerr.code,
		"http_status": cerr.status,
		"request_id":  reqID,
	}
	if rt.service != "" {
		metadata["service"] = rt.service
	}
	if rt.action != "" {
		metadata["action"] = rt.action
	}
	ev := model.AuditEvent{
		Time:      h.now().UTC(),
		ActorType: "system",
		ActorID:   "system",
		ActorName: "Cloud Safeguard",
		Action:    "cloud.api_denied",
		Status:    "denied",
		Severity:  "warning",
		Metadata:  metadata,
	}
	h.appendAudit(&ev)
}

// appendAudit is best effort: a mock cloud response must not depend on the
// audit writer succeeding.
func (h *handler) appendAudit(ev *model.AuditEvent) {
	if h.store == nil {
		return
	}
	_ = h.store.AppendAudit(context.Background(), ev)
}

// ---- resource helpers ----

// ecsInstanceWildcard is the list-instances resource ARN.
func (ac *authContext) ecsInstanceWildcard() string {
	return fmt.Sprintf("acs:ecs:%s:%s:instance/*", ac.payload.Region, ac.payload.AccountID)
}

// ecsInstanceResource is a single-instance resource ARN.
func (ac *authContext) ecsInstanceResource(id string) string {
	return fmt.Sprintf("acs:ecs:%s:%s:instance/%s", ac.payload.Region, ac.payload.AccountID, id)
}

// alidnsResource is a single-domain resource ARN.
func (ac *authContext) alidnsResource(zone string) string {
	return fmt.Sprintf("acs:alidns:%s:%s:domain/%s", ac.payload.Region, ac.payload.AccountID, zone)
}

// ---- HTTP helpers ----

// bearerToken extracts a Bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return ""
	}
	return fields[1]
}

// newRequestID returns a 32-character uppercase-hex Aliyun-style request id.
func newRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("REQ%016X", uint64(time.Now().UnixNano()))
	}
	return strings.ToUpper(hex.EncodeToString(buf))
}

// writeJSON writes an Aliyun-shaped success response with the request id.
func writeJSON(w http.ResponseWriter, reqID string, status int, payload map[string]any) {
	if payload == nil {
		payload = map[string]any{}
	}
	payload["RequestId"] = reqID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeCloudError writes an Aliyun-shaped error response.
func writeCloudError(w http.ResponseWriter, reqID string, cerr *cloudError) {
	status := cerr.status
	if status == 0 {
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Csg-Error-Code", cerr.code)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"Code":      cerr.code,
		"Message":   cerr.message,
		"RequestId": reqID,
	})
}

// readJSONBody decodes a bounded JSON request body into dst.
func readJSONBody(r *http.Request, dst any) *cloudError {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return &cloudError{http.StatusBadRequest, "InvalidParameter", "The request body could not be read"}
	}
	if len(body) > maxBodyBytes {
		return &cloudError{http.StatusBadRequest, "InvalidParameter", "The request body is too large"}
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return &cloudError{http.StatusBadRequest, "InvalidParameter", "The request body is not valid JSON"}
	}
	return nil
}
