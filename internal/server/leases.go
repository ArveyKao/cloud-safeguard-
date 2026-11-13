package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/arveykao/cloud-safeguard/internal/capcatalog"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/policy"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// providerAAD binds an encrypted broker credential to its provider record.
func providerAAD(providerID string) string { return "provider/" + providerID + "/credential" }

// leaseAAD binds an encrypted lease credential to its lease record.
func leaseAAD(leaseID string) string { return "lease/" + leaseID + "/credential" }

// brokerCredential is the vault payload of a provider's long-lived broker key.
type brokerCredential struct {
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
}

// httpError is a handler error carrying an API status/code.
type httpError struct {
	status  int
	code    string
	message string
}

func (e *httpError) Error() string { return e.message }

func errNotFoundAPI(message string) *httpError {
	return &httpError{status: http.StatusNotFound, code: model.ErrCodeNotFound, message: message}
}

func errBadRequestAPI(message string) *httpError {
	return &httpError{status: http.StatusBadRequest, code: model.ErrCodeInvalidRequest, message: message}
}

func errConflictAPI(message string) *httpError {
	return &httpError{status: http.StatusConflict, code: model.ErrCodeConflict, message: message}
}

// writeHandlerError maps a handler error onto the API envelope.
func (s *Server) writeHandlerError(w http.ResponseWriter, err error) {
	var he *httpError
	if errors.As(err, &he) {
		s.writeError(w, he.status, he.code, he.message)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "not found")
		return
	}
	if errors.Is(err, store.ErrConflict) {
		s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "resource already exists")
		return
	}
	s.logf("handler error: %v", err)
	s.writeError(w, http.StatusInternalServerError, model.ErrCodeInternal, "internal error")
}

// ================= agent lease endpoints =================

// handleAgentCreateLease implements POST /api/v1/agent/leases.
func (s *Server) handleAgentCreateLease(w http.ResponseWriter, r *http.Request) {
	ag, ok := agentFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "agent token required")
		return
	}
	var in model.CreateLeaseInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	lease, err := s.createLease(r.Context(), ag, in)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusCreated, lease)
}

// createLease runs the policy engine and persists the lease (in every
// outcome), minting credentials when auto-approved.
func (s *Server) createLease(ctx context.Context, ag model.Agent, in model.CreateLeaseInput) (model.Lease, error) {
	// An agent that belongs to a person has no role or grants of its own
	// (CONTRACT §17.2): everything it may do comes from its owner's role on a
	// cloud account, through access requests. Letting it also use capability
	// leases would leave credentials that ignore that role.
	if ag.OwnerID != "" {
		return model.Lease{}, &httpError{status: http.StatusForbidden, code: model.ErrCodeForbidden,
			message: "this agent belongs to a person; request access with POST /api/v1/agent/access-requests"}
	}
	// IDs reserved for access templates are never served from the database.
	if capcatalog.IsAccessTemplateID(in.CapabilityID) {
		return model.Lease{}, errNotFoundAPI("capability not found")
	}
	unlockAgent := s.lockAgentRequests(ag.ID)
	defer unlockAgent()
	now := s.nowUTC()

	capability, err := s.db.GetCapability(ctx, in.CapabilityID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return model.Lease{}, errNotFoundAPI("capability not found")
		}
		return model.Lease{}, err
	}
	if in.TTLSeconds < 0 {
		return model.Lease{}, errBadRequestAPI("ttl_seconds must not be negative")
	}
	// Params are validated before policy and before a lease row is created.
	if err := capcatalog.ValidateParams(capability, in.Params); err != nil {
		return model.Lease{}, errBadRequestAPI(err.Error())
	}

	providers, err := s.db.ListProviders(ctx)
	if err != nil {
		return model.Lease{}, err
	}
	var selected *model.Provider
	for i := range providers {
		if providers[i].Type == capability.ProviderType {
			selected = &providers[i]
			break
		}
	}

	settings, err := s.db.GetPolicySettings(ctx)
	if err != nil {
		return model.Lease{}, err
	}
	activeCount, err := s.db.CountActiveLeases(ctx, ag.ID)
	if err != nil {
		return model.Lease{}, err
	}
	lastMinute, err := s.db.CountLeasesSince(ctx, ag.ID, now.Add(-time.Minute))
	if err != nil {
		return model.Lease{}, err
	}

	decision := policy.Evaluate(policy.Input{
		Agent:                   ag,
		Capability:              capability,
		Provider:                selected,
		Settings:                settings,
		RequestedTTLSeconds:     in.TTLSeconds,
		Reason:                  in.Reason,
		BreakGlass:              in.BreakGlass,
		ActiveLeaseCount:        activeCount,
		LeasesCreatedLastMinute: lastMinute,
		PolicyViolation:         policyViolation(capability, in.Params),
	})

	return s.submitLease(ctx, ag, capability, selected, decision, nil, in, now)
}

// submitLease persists a decided lease request (in every outcome) and, when
// the decision is auto-approve, mints and activates it. It is the shared
// second half of the §16 capability request and the §17 access request.
func (s *Server) submitLease(ctx context.Context, ag model.Agent, capability model.Capability, selected *model.Provider, decision model.PolicyDecision, auditExtra map[string]any, in model.CreateLeaseInput, now time.Time) (model.Lease, error) {
	leaseID, err := newID("lea_")
	if err != nil {
		return model.Lease{}, err
	}
	lease := model.Lease{
		ID:                  leaseID,
		AgentID:             ag.ID,
		AgentName:           ag.Name,
		CapabilityID:        capability.ID,
		CapabilityName:      capability.Name,
		Risk:                capability.Risk,
		Params:              in.Params,
		Reason:              in.Reason,
		RequestedTTLSeconds: in.TTLSeconds,
		EffectiveTTLSeconds: decision.EffectiveTTLSeconds,
		Status:              model.LeasePending,
		Decision:            decision,
		BreakGlass:          in.BreakGlass,
		CreatedAt:           now,
	}
	if selected != nil {
		lease.ProviderID = selected.ID
		lease.ProviderName = selected.Name
		lease.ProviderMode = selected.Mode
	}
	lease.SessionName = sanitizeSessionName("csg-" + ag.ID + "-" + lease.ID)
	switch decision.Outcome {
	case model.OutcomeDeny:
		lease.Status = model.LeaseDenied
		lease.DeniedReason = policy.DenySummary(decision)
	case model.OutcomeRequireApproval:
		lease.Status = model.LeasePending
	default:
		// Auto-approve: the row is created pending, then promoted to active once
		// the credential has been minted and stored.
		lease.Status = model.LeasePending
	}

	if err := s.db.CreateLease(ctx, lease); err != nil {
		return model.Lease{}, err
	}

	requestedStatus := "ok"
	if decision.Outcome == model.OutcomeDeny {
		requestedStatus = "denied"
	}
	requested := map[string]any{
		"capability":  capability.ID,
		"risk":        string(capability.Risk),
		"params":      in.Params,
		"ttl_seconds": decision.EffectiveTTLSeconds,
		"decision":    string(decision.Outcome),
		"break_glass": in.BreakGlass,
	}
	for k, v := range auditExtra {
		requested[k] = v
	}
	s.agentAudit(ctx, ag, "lease.requested", requestedStatus, "info", "lease", lease.ID, requested)

	switch decision.Outcome {
	case model.OutcomeAutoApprove:
		if s.hookBeforeAutoLock != nil {
			s.hookBeforeAutoLock(lease.ID)
		}
		unlock := s.lockLease(lease.ID)
		defer unlock()
		// The pending row was visible before this lock was taken: an operator
		// may have approved, denied or revoked it meanwhile. Only a lease that
		// is still pending under the lock may be minted.
		if current, err := s.db.GetLease(ctx, lease.ID); err != nil {
			return model.Lease{}, err
		} else if current.Status != model.LeasePending {
			return model.Lease{}, errConflictAPI("lease " + lease.ID + " is " + string(current.Status) + "; auto-approval skipped")
		}
		// Same capability lock as approval. The decision above was made against
		// an earlier read; if the capability changed since, do not mint.
		unlockCapability := s.lockCapabilityRead(capability.ID)
		defer unlockCapability()
		fresh, err := s.capabilityByID(ctx, capability.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return model.Lease{}, err
		}
		if err != nil || !sameCapabilityDefinition(capability, fresh) {
			if _, rerr := s.revokeLeaseAsSystem(ctx, lease, "capability changed during auto-approval"); rerr != nil {
				var he *httpError
				if !errors.As(rerr, &he) || he.status != http.StatusConflict {
					s.logf("lease %s: revoke after capability change: %v", lease.ID, rerr)
				}
			}
			return model.Lease{}, errConflictAPI("capability " + capability.ID + " changed while this request was being decided; request again")
		}
		approvedAt := now
		lease.ApprovedAt = &approvedAt
		lease.ApprovedBy = "auto"
		if err := s.mintCredentialForLease(ctx, &lease, capability, selected, decision.EffectiveTTLSeconds); err != nil {
			if ferr := s.failLease(ctx, &lease, err); ferr != nil {
				return model.Lease{}, ferr
			}
			s.agentAudit(ctx, ag, "lease.failed", "failed", "warning", "lease", lease.ID, map[string]any{
				"reason": lease.FailureReason,
			})
			return lease, nil
		}
		issuedAt := now
		expiresAt := now.Add(time.Duration(decision.EffectiveTTLSeconds) * time.Second)
		lease.Status = model.LeaseActive
		lease.IssuedAt = &issuedAt
		lease.ExpiresAt = &expiresAt
		if err := s.activateLease(ctx, lease); err != nil {
			return model.Lease{}, err
		}
		s.agentAudit(ctx, ag, "lease.auto_approved", "ok", approveSeverity(lease.BreakGlass), "lease", lease.ID, map[string]any{
			"ttl_seconds": decision.EffectiveTTLSeconds,
		})
		s.agentAudit(ctx, ag, "lease.credential_issued", "ok", "info", "lease", lease.ID, map[string]any{
			"fingerprint": lease.CredentialFingerprint,
			"expires_at":  expiresAt.UTC().Format(time.RFC3339Nano),
		})
	case model.OutcomeDeny:
		s.agentAudit(ctx, ag, "lease.denied", "denied", denySeverity(lease.BreakGlass), "lease", lease.ID, map[string]any{
			"reasons": denyDecisionReasons(decision),
			"summary": lease.DeniedReason,
		})
	}
	return lease, nil
}

// policyViolation returns a non-empty, human-readable violation when the
// capability cannot render a policy that satisfies the IAM prohibition
// (CONTRACT §16.3). The server computes it so the policy engine stays free of
// the capability catalog.
//
// It fails closed on every render error, not only on prohibition violations: a
// template that cannot be rendered can never mint a credential, so letting the
// request through only to fail at mint time would be worse than an explainable
// deny.
func policyViolation(capability model.Capability, params map[string]string) string {
	if isRetiredCapability(capability.ID) {
		return "capability " + capability.ID + " is retired and can never be leased"
	}
	if _, err := capcatalog.RenderPolicy(capability, params); err != nil {
		return sanitizeMessage(err.Error())
	}
	return ""
}

// mintCredentialForLease renders the policy, mints a provider credential and
// stores it encrypted with the lease-bound AAD. It mutates lease's credential
// availability fields but leaves lifecycle fields to the caller.
func (s *Server) mintCredentialForLease(ctx context.Context, lease *model.Lease, capability model.Capability, prov *model.Provider, durationSeconds int) error {
	if prov == nil {
		return errors.New("no provider available for capability")
	}
	policyJSON, err := capcatalog.RenderPolicy(capability, lease.Params)
	if err != nil {
		return fmt.Errorf("render policy: %w", err)
	}
	encCred, err := s.db.GetProviderCredential(ctx, prov.ID)
	if err != nil {
		return fmt.Errorf("read provider credential: %w", err)
	}
	plain, err := s.vault.Decrypt(encCred, providerAAD(prov.ID))
	if err != nil {
		return errors.New("provider credential cannot be decrypted")
	}
	var broker brokerCredential
	if err := json.Unmarshal(plain, &broker); err != nil {
		return errors.New("provider credential is malformed")
	}
	minter, err := s.minterFactory(*prov)
	if err != nil {
		return fmt.Errorf("provider %s: %w", prov.Mode, err)
	}
	credential, err := minter.Mint(ctx, provider.MintRequest{
		LeaseID:               lease.ID,
		Provider:              *prov,
		BrokerAccessKeyID:     broker.AccessKeyID,
		BrokerAccessKeySecret: broker.AccessKeySecret,
		PolicyJSON:            policyJSON,
		SessionName:           lease.SessionName,
		DurationSeconds:       durationSeconds,
		SigningKey:            s.signingKey,
	})
	if err != nil {
		return err
	}
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		return errors.New("encode lease credential")
	}
	encrypted, err := s.vault.Encrypt(credentialJSON, leaseAAD(lease.ID))
	if err != nil {
		return errors.New("encrypt lease credential")
	}
	fingerprint := maskAccessKeyID(credential.AccessKeyID)
	if err := s.db.SetLeaseCredential(ctx, lease.ID, encrypted, fingerprint); err != nil {
		return err
	}
	lease.CredentialAvailable = true
	lease.CredentialFingerprint = fingerprint
	return nil
}

// handleAgentListLeases implements GET /api/v1/agent/leases.
func (s *Server) handleAgentListLeases(w http.ResponseWriter, r *http.Request) {
	ag, ok := agentFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "agent token required")
		return
	}
	filter := store.LeaseFilter{AgentID: ag.ID}
	status := r.URL.Query().Get("status")
	if status != "" {
		st := model.LeaseStatus(status)
		if !st.Valid() {
			s.badRequest(w, "invalid lease status "+status)
			return
		}
		filter.Statuses = []model.LeaseStatus{st}
	}
	limit, offset, err := limitOffset(r)
	if err != nil {
		s.badRequest(w, err.Error())
		return
	}
	filter.Limit, filter.Offset = limit, offset
	items, total, err := s.db.ListLeases(r.Context(), filter)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	for i := range items {
		items[i] = agentLeaseView(items[i])
	}
	writeList(s, w, http.StatusOK, items, total)
}

// handleAgentGetLease implements GET /api/v1/agent/leases/{id}.
func (s *Server) handleAgentGetLease(w http.ResponseWriter, r *http.Request) {
	ag, ok := agentFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "agent token required")
		return
	}
	lease, err := s.db.GetLease(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "lease not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	// Cross-agent access is indistinguishable from a missing lease.
	if lease.AgentID != ag.ID {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "lease not found")
		return
	}
	s.writeData(w, http.StatusOK, agentLeaseView(lease))
}

// agentLeaseView removes what the agent must not read from a lease: the
// note a person wrote when approving an access request is for people.
func agentLeaseView(lease model.Lease) model.Lease {
	if capcatalog.IsAccessTemplateID(lease.CapabilityID) {
		lease.ApprovalNote = ""
	}
	return lease
}

// revokeReason validates an optional revoke reason.
func revokeReason(raw, fallback string) (string, error) {
	reason := strings.TrimSpace(raw)
	if !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > maxReasonLength {
		return "", errBadRequestAPI(fmt.Sprintf("reason must be at most %d characters", maxReasonLength))
	}
	if reason == "" {
		return fallback, nil
	}
	return sanitizeMessage(reason), nil
}

// handleAgentFetchCredential implements POST /api/v1/agent/leases/{id}/credential.
func (s *Server) handleAgentFetchCredential(w http.ResponseWriter, r *http.Request) {
	ag, ok := agentFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "agent token required")
		return
	}
	lease, err := s.db.GetLease(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "lease not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	if lease.AgentID != ag.ID {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "lease not found")
		return
	}
	if lease.Status != model.LeaseActive {
		s.writeError(w, http.StatusConflict, model.ErrCodeLeaseNotActive,
			"lease is "+string(lease.Status)+"; credentials are only available for active leases")
		return
	}
	now := s.nowUTC()
	if lease.ExpiresAt == nil || !lease.ExpiresAt.After(now) {
		s.writeError(w, http.StatusConflict, model.ErrCodeLeaseNotActive, "lease credential has expired")
		return
	}
	encrypted, err := s.db.GetLeaseCredential(r.Context(), lease.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusGone, model.ErrCodeCredentialUnavailable, "credential is not available")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	plain, err := s.vault.Decrypt(encrypted, leaseAAD(lease.ID))
	if err != nil {
		s.logf("lease %s: decrypt credential: %v", lease.ID, err)
		s.writeError(w, http.StatusGone, model.ErrCodeCredentialUnavailable, "credential is not available")
		return
	}
	var credential model.Credential
	if err := json.Unmarshal(plain, &credential); err != nil {
		s.logf("lease %s: decode credential: %v", lease.ID, err)
		s.writeError(w, http.StatusGone, model.ErrCodeCredentialUnavailable, "credential is not available")
		return
	}

	// Check again now that the credential is in hand. A revoke writes the
	// terminal status before it erases the credential, so if the lease still
	// reads active here, no revocation had happened when the credential was
	// read. The same goes for the agent and its owner.
	if problem, err := s.credentialReleaseProblem(r.Context(), ag.ID, lease.ID); err != nil {
		s.writeHandlerError(w, err)
		return
	} else if problem != "" {
		s.writeError(w, http.StatusConflict, model.ErrCodeLeaseNotActive, problem)
		return
	}

	envelope := s.credentialEnvelope(credential, lease, r)
	s.agentAudit(r.Context(), ag, "lease.credential_fetched", "ok", "info", "lease", lease.ID, map[string]any{
		"remote_addr": s.clientAddr(r),
	})
	s.writeData(w, http.StatusOK, envelope)
}

// credentialEnvelope builds the agent-facing credential payload with the exact
// environment-variable names and order frozen by CONTRACT §3.
func (s *Server) credentialEnvelope(credential model.Credential, lease model.Lease, r *http.Request) model.CredentialEnvelope {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	baseURL := scheme + "://" + r.Host
	return model.CredentialEnvelope{
		Credential: credential,
		Env: []model.EnvVar{
			{Name: "ALIBABA_CLOUD_ACCESS_KEY_ID", Value: credential.AccessKeyID},
			{Name: "ALIBABA_CLOUD_ACCESS_KEY_SECRET", Value: credential.AccessKeySecret},
			{Name: "ALIBABA_CLOUD_SECURITY_TOKEN", Value: credential.SecurityToken},
			{Name: "CSG_LEASE_ID", Value: lease.ID},
			{Name: "CSG_SERVER", Value: baseURL},
			{Name: "CSG_CAPABILITY", Value: lease.CapabilityID},
		},
	}
}

// handleAgentRevokeLease implements POST /api/v1/agent/leases/{id}/revoke.
func (s *Server) handleAgentRevokeLease(w http.ResponseWriter, r *http.Request) {
	ag, ok := agentFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "agent token required")
		return
	}
	var in model.RevokeLeaseInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	lease, err := s.db.GetLease(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "lease not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	if lease.AgentID != ag.ID {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "lease not found")
		return
	}
	reason, err := revokeReason(in.Reason, "revoked by agent")
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	updated, err := s.revokeLease(r.Context(), lease, reason, &ag)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, updated)
}

// ================= admin lease endpoints =================

// handleAdminListLeases implements GET /api/v1/admin/leases.
func (s *Server) handleAdminListLeases(w http.ResponseWriter, r *http.Request) {
	filter := store.LeaseFilter{
		AgentID:      r.URL.Query().Get("agent_id"),
		CapabilityID: r.URL.Query().Get("capability_id"),
	}
	if status := r.URL.Query().Get("status"); status != "" {
		st := model.LeaseStatus(status)
		if !st.Valid() {
			s.badRequest(w, "invalid lease status "+status)
			return
		}
		filter.Statuses = []model.LeaseStatus{st}
	}
	limit, offset, err := limitOffset(r)
	if err != nil {
		s.badRequest(w, err.Error())
		return
	}
	filter.Limit, filter.Offset = limit, offset
	items, total, err := s.db.ListLeases(r.Context(), filter)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	writeList(s, w, http.StatusOK, items, total)
}

// handleAdminGetLease implements GET /api/v1/admin/leases/{id}.
func (s *Server) handleAdminGetLease(w http.ResponseWriter, r *http.Request) {
	lease, err := s.db.GetLease(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "lease not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, lease)
}

// handleAdminApproveLease implements POST /api/v1/admin/leases/{id}/approve.
func (s *Server) handleAdminApproveLease(w http.ResponseWriter, r *http.Request) {
	var in model.ApproveLeaseInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	lease, err := s.approveLease(r.Context(), r.PathValue("id"), in, nil)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, lease)
}

// approveLease approves a pending lease and mints its credential. approver
// is nil for the operator (admin token) and the signed-in person otherwise.
//
// Who may approve what:
//   - a §17 access request (its capability is an access template): only the
//     person who owns the requesting agent. Nobody else, including the
//     operator and supervisors (CONTRACT §17.5).
//   - a §16 capability lease: only the operator.
//
// A person asking about a lease that is not theirs gets "not found", the
// same as for a lease that does not exist.
func (s *Server) approveLease(ctx context.Context, leaseID string, in model.ApproveLeaseInput, approver *model.Person) (model.Lease, error) {
	// Serialize with any other approval of this lease; the status read below
	// happens under the lock, so a second approval sees the first one's result.
	unlock := s.lockLease(leaseID)
	defer unlock()
	notFound := errNotFoundAPI("lease not found")
	if approver != nil {
		notFound = errNotFoundAPI("request not found")
	}
	lease, err := s.db.GetLease(ctx, leaseID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return model.Lease{}, notFound
		}
		return model.Lease{}, err
	}
	ag, err := s.db.GetAgent(ctx, lease.AgentID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return model.Lease{}, err
	}
	agentMissing := err != nil
	accessRequest := capcatalog.IsAccessTemplateID(lease.CapabilityID)
	switch {
	case approver == nil && accessRequest:
		return model.Lease{}, errConflictAPI("only the person who owns the agent can approve this request")
	case approver != nil && (!accessRequest || agentMissing || ag.OwnerID == "" || ag.OwnerID != approver.ID):
		return model.Lease{}, notFound
	}
	if lease.Status != model.LeasePending {
		return model.Lease{}, errConflictAPI("lease is " + string(lease.Status) + ", only pending leases can be approved")
	}
	now := s.nowUTC()
	settings, err := s.db.GetPolicySettings(ctx)
	if err != nil {
		return model.Lease{}, err
	}
	if now.Sub(lease.CreatedAt) > time.Duration(settings.PendingTimeoutSeconds)*time.Second {
		// The sweeper may not have run yet; expire it inline then report 409.
		s.expireLease(ctx, lease, "pending request timed out")
		return model.Lease{}, errConflictAPI("lease approval window has expired")
	}
	// Hold the capability's read lock from here until the lease is active, so
	// no edit of this capability can commit in between (an edit that narrows
	// the policy would otherwise leave this lease active with the old one).
	unlockCapability := s.lockCapabilityRead(lease.CapabilityID)
	defer unlockCapability()
	capability, err := s.capabilityByID(ctx, lease.CapabilityID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return model.Lease{}, errConflictAPI("capability no longer exists")
		}
		return model.Lease{}, err
	}
	if agentMissing {
		return model.Lease{}, errConflictAPI("agent no longer exists")
	}
	if lease.ProviderID == "" {
		return model.Lease{}, errConflictAPI("lease has no provider")
	}
	prov, err := s.db.GetProvider(ctx, lease.ProviderID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return model.Lease{}, errConflictAPI("provider no longer exists")
		}
		return model.Lease{}, err
	}
	if !capability.Enabled {
		return model.Lease{}, errConflictAPI("capability is disabled")
	}
	if prov.Status != model.ProviderActive {
		return model.Lease{}, errConflictAPI("provider is not active")
	}
	// Re-check the authorization that held when the lease was requested: an
	// approval can arrive after a suspension, a grant removal, a demotion, a
	// lowered role binding or a capability edit, and must never mint in those
	// cases (CONTRACT §16.5, §17.5). activateLease repeats this after minting.
	if problem, err := s.leaseAuthorityProblem(ctx, ag, capability, lease); err != nil {
		return model.Lease{}, err
	} else if problem != "" {
		return model.Lease{}, errConflictAPI(problem)
	}
	if problem, err := s.agentOwnerProblem(ctx, ag); err != nil {
		return model.Lease{}, err
	} else if problem != "" {
		return model.Lease{}, errConflictAPI(problem)
	}

	// The limit on simultaneously active credentials holds at approval too
	// (requests are counted when they are made, but several can be pending).
	if accessRequest {
		active, err := s.db.CountActiveLeases(ctx, ag.ID)
		if err != nil {
			return model.Lease{}, err
		}
		if active >= ag.MaxConcurrentLeases {
			return model.Lease{}, errConflictAPI(fmt.Sprintf(
				"%d credentials of this agent are active; the limit is %d. Revoke one or wait for it to expire.", active, ag.MaxConcurrentLeases))
		}
	}

	if in.TTLSeconds < 0 {
		return model.Lease{}, errBadRequestAPI("ttl_seconds must be positive")
	}
	ttl := in.TTLSeconds
	if ttl == 0 { // omitted: keep the requested validity period
		ttl = lease.RequestedTTLSeconds
	}
	if ttl <= 0 {
		ttl = lease.EffectiveTTLSeconds
	}
	if ttl <= 0 {
		return model.Lease{}, errBadRequestAPI("ttl_seconds must be positive")
	}
	// The owner approves exactly what was asked for; only the operator may
	// set another validity period on a §16 lease.
	if accessRequest && ttl != lease.RequestedTTLSeconds {
		return model.Lease{}, errBadRequestAPI("the validity period of an access request cannot be changed at approval")
	}
	maxTTL := capability.MaxTTLSeconds
	if ag.MaxTTLSeconds < maxTTL {
		maxTTL = ag.MaxTTLSeconds
	}
	if settings.MaxLeaseTTLSeconds < maxTTL {
		maxTTL = settings.MaxLeaseTTLSeconds
	}
	if ttl > maxTTL {
		return model.Lease{}, errBadRequestAPI(fmt.Sprintf("ttl_seconds %d exceeds the allowed maximum %d", ttl, maxTTL))
	}

	audit := func(action, status, severity string, metadata map[string]any) {
		if approver == nil {
			s.adminAudit(ctx, action, status, severity, "lease", lease.ID, metadata)
			return
		}
		metadata["agent_id"] = ag.ID
		metadata["agent_name"] = ag.Name
		s.personAudit(ctx, *approver, action, status, severity, "lease", lease.ID, metadata)
	}
	approvedAt := now
	lease.ApprovedBy = "admin"
	if approver != nil {
		lease.ApprovedBy = "owner:" + approver.ID
	}
	lease.ApprovalNote = in.Note
	lease.ApprovedAt = &approvedAt
	lease.EffectiveTTLSeconds = ttl
	if err := s.mintCredentialForLease(ctx, &lease, capability, &prov, ttl); err != nil {
		if ferr := s.failLease(ctx, &lease, err); ferr != nil {
			return model.Lease{}, ferr
		}
		audit("lease.failed", "failed", "warning", map[string]any{"reason": lease.FailureReason})
		// Contract: provider failure returns 200 with the failed lease.
		return lease, nil
	}
	issuedAt := now
	expiresAt := now.Add(time.Duration(ttl) * time.Second)
	lease.Status = model.LeaseActive
	lease.IssuedAt = &issuedAt
	lease.ExpiresAt = &expiresAt
	if err := s.activateLease(ctx, lease); err != nil {
		return model.Lease{}, err
	}
	audit("lease.approved", "ok", approveSeverity(lease.BreakGlass), map[string]any{
		"ttl_seconds": ttl,
		"note":        in.Note,
	})
	audit("lease.credential_issued", "ok", "info", map[string]any{
		"fingerprint": lease.CredentialFingerprint,
		"expires_at":  expiresAt.UTC().Format(time.RFC3339Nano),
	})
	return lease, nil
}

// handleAdminDenyLease implements POST /api/v1/admin/leases/{id}/deny.
func (s *Server) handleAdminDenyLease(w http.ResponseWriter, r *http.Request) {
	var in model.DenyLeaseInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	reason := in.Reason
	if len(reason) < 1 || len(reason) > 500 {
		s.badRequest(w, "reason is required and must be 1-500 characters")
		return
	}
	lease, err := s.db.GetLease(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "lease not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	if lease.Status != model.LeasePending {
		s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "lease is "+string(lease.Status)+", only pending leases can be denied")
		return
	}
	lease.Status = model.LeaseDenied
	lease.DeniedReason = reason
	lease.CredentialAvailable = false
	lease.CredentialFingerprint = ""
	// Compare-and-set: a lease that was approved, revoked or expired since
	// the read above is not overwritten.
	if err := s.db.UpdateLeaseIfStatus(r.Context(), lease, model.LeasePending); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "lease is no longer pending")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	// A denied lease never keeps ciphertext, even one left by a failed activation.
	if err := s.db.ClearLeaseCredential(r.Context(), lease.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logf("lease %s: scrub credential on deny: %v", lease.ID, err)
	}
	s.adminAudit(r.Context(), "lease.denied", "denied", denySeverity(lease.BreakGlass), "lease", lease.ID,
		s.leaseAgentMetadata(r.Context(), lease, map[string]any{"reason": reason}))
	s.writeData(w, http.StatusOK, lease)
}

// handleAdminRevokeLease implements POST /api/v1/admin/leases/{id}/revoke.
func (s *Server) handleAdminRevokeLease(w http.ResponseWriter, r *http.Request) {
	var in model.RevokeLeaseInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	lease, err := s.db.GetLease(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "lease not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	fallback := "revoked by operator"
	if sc, ok := sessionFromContext(r.Context()); ok {
		fallback = "revoked by supervisor " + sc.person.Username
	}
	reason, err := revokeReason(in.Reason, fallback)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	updated, err := s.revokeLease(r.Context(), lease, reason, nil)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, updated)
}

// activateLease persists a freshly minted lease as active, but only if it is
// still pending in the store. Approval and auto-approval read the lease, check
// it and mint before writing; a revoke, demotion or expiry can land in between.
// Without the compare-and-set the final write would resurrect a revoked lease
// with a live credential. On conflict the just-stored credential is scrubbed and
// the caller gets 409, so no credential is ever issued for that lease.
func (s *Server) activateLease(ctx context.Context, lease model.Lease) error {
	// Authorization is checked again AFTER minting, from fresh store reads. A
	// grant removal, suspension or capability edit that landed while the
	// credential was being minted does not necessarily change the lease's
	// status, so the compare-and-set below would not see it. Changes that land
	// after this recheck revoke affected pending leases (revokeUnauthorizedLeases,
	// revokePendingLeasesForCapability), which the compare-and-set does see.
	if problem, err := s.recheckLeaseAuthorization(ctx, lease); err != nil {
		s.abortActivation(ctx, lease, "authorization could not be re-checked")
		return err
	} else if problem != "" {
		s.abortActivation(ctx, lease, problem)
		if _, rerr := s.revokeLeaseAsSystem(ctx, lease, "authorization changed during issuance: "+problem); rerr != nil {
			var he *httpError
			if !errors.As(rerr, &he) || he.status != http.StatusConflict {
				s.logf("lease %s: revoke after failed recheck: %v", lease.ID, rerr)
			}
		}
		return errConflictAPI("lease " + lease.ID + " was not activated: " + problem)
	}
	if s.hookAfterLeaseRecheck != nil {
		s.hookAfterLeaseRecheck(lease.ID)
	}
	err := s.db.UpdateLeaseIfStatus(ctx, lease, model.LeasePending)
	if err == nil {
		return nil
	}
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		s.abortActivation(ctx, lease, "lease left pending before activation completed")
		return errConflictAPI("lease " + lease.ID + " changed while it was being activated (revoked, expired or its agent changed); no credential was issued")
	}
	// Any other failure: the lease did not become active, so its freshly
	// stored credential must not stay behind.
	s.abortActivation(ctx, lease, "activation write failed")
	return err
}

// failLease records a mint failure. The lease moves to failed only if it is
// still pending; if it changed meanwhile (or the credential write was refused
// because it is no longer pending), the caller gets 409 and nothing is
// overwritten.
func (s *Server) failLease(ctx context.Context, lease *model.Lease, mintErr error) error {
	if errors.Is(mintErr, store.ErrConflict) {
		// The credential write itself was refused: the lease left pending while
		// minting. Nothing was stored.
		s.systemAudit(ctx, "lease.activation_aborted", "denied", "warning", "lease", lease.ID, map[string]any{
			"reason": "lease left pending while its credential was minted; nothing was stored",
		})
		return errConflictAPI("lease " + lease.ID + " changed while its credential was being minted; no credential was issued")
	}
	lease.Status = model.LeaseFailed
	lease.FailureReason = sanitizeMessage(mintErr.Error())
	lease.CredentialAvailable = false
	lease.CredentialFingerprint = ""
	err := s.db.UpdateLeaseIfStatus(ctx, *lease, model.LeasePending)
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		return errConflictAPI("lease " + lease.ID + " changed while its credential was being minted; no credential was issued")
	}
	if err != nil {
		s.logf("lease %s: persist failed state: %v", lease.ID, err)
	}
	return nil
}

// capLock is a reference-counted per-capability read/write lock.
type capLock struct {
	mu   sync.RWMutex
	refs int
}

func (s *Server) acquireCapLock(id string) *capLock {
	s.capLocksMu.Lock()
	defer s.capLocksMu.Unlock()
	if s.capLocks == nil {
		s.capLocks = map[string]*capLock{}
	}
	l := s.capLocks[id]
	if l == nil {
		l = &capLock{}
		s.capLocks[id] = l
	}
	l.refs++
	return l
}

func (s *Server) releaseCapLock(id string, l *capLock) {
	s.capLocksMu.Lock()
	defer s.capLocksMu.Unlock()
	l.refs--
	if l.refs == 0 {
		delete(s.capLocks, id)
	}
}

// lockCapabilityRead is held by an activation of a lease of this capability.
func (s *Server) lockCapabilityRead(id string) func() {
	l := s.acquireCapLock(id)
	l.mu.RLock()
	return func() { l.mu.RUnlock(); s.releaseCapLock(id, l) }
}

// lockCapabilityWrite is held by an edit of this capability.
func (s *Server) lockCapabilityWrite(id string) func() {
	l := s.acquireCapLock(id)
	l.mu.Lock()
	return func() { l.mu.Unlock(); s.releaseCapLock(id, l) }
}

// sameCapabilityDefinition reports whether two reads of a capability grant the
// same thing, so a lease decided against the first may be minted with the second.
func sameCapabilityDefinition(a, b model.Capability) bool {
	if a.PolicyTemplate != b.PolicyTemplate || a.Access != b.Access || a.Enabled != b.Enabled ||
		a.Risk != b.Risk || a.MaxTTLSeconds != b.MaxTTLSeconds || len(a.Params) != len(b.Params) {
		return false
	}
	for i := range a.Params {
		if a.Params[i] != b.Params[i] {
			return false
		}
	}
	return true
}

// leaseLock is a reference-counted per-lease mutex.
type leaseLock struct {
	mu   sync.Mutex
	refs int
}

// lockLease serializes minting and activation for one lease and returns the
// unlock function. Entries are dropped when the last holder releases them.
func (s *Server) lockLease(id string) func() {
	s.leaseLocksMu.Lock()
	if s.leaseLocks == nil {
		s.leaseLocks = map[string]*leaseLock{}
	}
	l := s.leaseLocks[id]
	if l == nil {
		l = &leaseLock{}
		s.leaseLocks[id] = l
	}
	l.refs++
	s.leaseLocksMu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		s.leaseLocksMu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(s.leaseLocks, id)
		}
		s.leaseLocksMu.Unlock()
	}
}

// abortActivation scrubs the credential just stored for a lease that will not
// become active, and audits why. If another activation of the same lease won
// meanwhile (the lease is active), the stored credential is that winner's and
// is left alone.
func (s *Server) abortActivation(ctx context.Context, lease model.Lease, reason string) {
	if current, err := s.db.GetLease(ctx, lease.ID); err == nil && current.Status == model.LeaseActive {
		s.systemAudit(ctx, "lease.activation_aborted", "denied", "warning", "lease", lease.ID, map[string]any{
			"reason": sanitizeMessage(reason) + "; another activation already won, its credential is kept",
		})
		return
	}
	if cerr := s.db.ClearLeaseCredential(ctx, lease.ID); cerr != nil && !errors.Is(cerr, store.ErrNotFound) {
		s.logf("lease %s: scrub credential after aborted activation: %v", lease.ID, cerr)
	}
	s.systemAudit(ctx, "lease.activation_aborted", "denied", "warning", "lease", lease.ID, map[string]any{
		"reason": sanitizeMessage(reason) + "; credential scrubbed",
	})
}

// recheckLeaseAuthorization re-reads the lease's agent and capability and
// returns the first reason the lease may no longer be activated, or "".
func (s *Server) recheckLeaseAuthorization(ctx context.Context, lease model.Lease) (string, error) {
	ag, err := s.db.GetAgent(ctx, lease.AgentID)
	if errors.Is(err, store.ErrNotFound) {
		return "agent no longer exists", nil
	}
	if err != nil {
		return "", err
	}
	capability, err := s.capabilityByID(ctx, lease.CapabilityID)
	if errors.Is(err, store.ErrNotFound) {
		return "capability no longer exists", nil
	}
	if err != nil {
		return "", err
	}
	if !capability.Enabled {
		return "capability is disabled", nil
	}
	if lease.ProviderID != "" {
		prov, err := s.db.GetProvider(ctx, lease.ProviderID)
		if errors.Is(err, store.ErrNotFound) {
			return "provider no longer exists", nil
		}
		if err != nil {
			return "", err
		}
		if prov.Status != model.ProviderActive {
			return "provider is not active", nil
		}
	}
	settings, err := s.db.GetPolicySettings(ctx)
	if err != nil {
		return "", err
	}
	maxTTL := capability.MaxTTLSeconds
	if ag.MaxTTLSeconds < maxTTL {
		maxTTL = ag.MaxTTLSeconds
	}
	if settings.MaxLeaseTTLSeconds < maxTTL {
		maxTTL = settings.MaxLeaseTTLSeconds
	}
	if lease.EffectiveTTLSeconds > maxTTL {
		return fmt.Sprintf("ttl %ds now exceeds the allowed maximum %ds", lease.EffectiveTTLSeconds, maxTTL), nil
	}
	if problem, err := s.agentOwnerProblem(ctx, ag); err != nil || problem != "" {
		return problem, err
	}
	return s.leaseAuthorityProblem(ctx, ag, capability, lease)
}

// capabilityByID resolves a lease's capability: an access template from the
// code catalog (CONTRACT §17.4) or a stored capability. IDs reserved for
// access templates never resolve to a stored row.
func (s *Server) capabilityByID(ctx context.Context, id string) (model.Capability, error) {
	if capcatalog.IsAccessTemplateID(id) {
		template, ok := capcatalog.AccessTemplateByID(id)
		if !ok {
			return model.Capability{}, store.ErrNotFound
		}
		return template.Capability, nil
	}
	return s.db.GetCapability(ctx, id)
}

// leaseAuthorityProblem is the single definition of "may this agent hold
// this lease now". It returns "" when the lease is still authorized.
//
//   - §16 capability lease: the agent's own role and grants
//     (leaseAuthorizationProblem).
//   - §17 access request: the agent has an owner, and the owner's current
//     role on the lease's cloud account permits the template's level. The
//     binding is read here, at every check; it is never copied onto the
//     agent or the lease.
func (s *Server) leaseAuthorityProblem(ctx context.Context, ag model.Agent, capability model.Capability, lease model.Lease) (string, error) {
	if !capcatalog.IsAccessTemplateID(capability.ID) {
		if ag.OwnerID != "" {
			// Only possible for a lease made before this rule, or by an
			// operator edit: it does not follow the owner's role, so it ends.
			return "an agent that belongs to a person may hold access requests only", nil
		}
		return leaseAuthorizationProblem(ag, capability, lease), nil
	}
	if ag.Status != model.AgentActive {
		return "agent is " + string(ag.Status), nil
	}
	if ag.OwnerID == "" {
		return "agent has no owner", nil
	}
	if lease.ProviderID == "" {
		return "request has no cloud account", nil
	}
	binding, err := s.db.GetBinding(ctx, ag.OwnerID, lease.ProviderID)
	if errors.Is(err, store.ErrNotFound) {
		return "the agent's owner has no role on this cloud account", nil
	}
	if err != nil {
		return "", err
	}
	if !binding.Role.Permits(capability.Access) {
		template, _ := capcatalog.AccessTemplateByID(capability.ID)
		return "the owner's role " + string(binding.Role) + " does not permit " + string(template.Permission) + " access", nil
	}
	if violation := policyViolation(capability, lease.Params); violation != "" {
		return "access template " + capability.ID + " renders a prohibited policy: " + violation, nil
	}
	return "", nil
}

// leaseAuthorizationProblem is the single definition of "may this lease be
// activated now" shared by approval (before minting) and activateLease (after
// minting). It returns "" when the lease is still authorized.
func leaseAuthorizationProblem(ag model.Agent, capability model.Capability, lease model.Lease) string {
	if ag.Status != model.AgentActive {
		return "agent is " + string(ag.Status)
	}
	if !agentHasGrant(ag, capability.ID) {
		return "capability " + capability.ID + " is no longer granted to agent " + ag.ID
	}
	if !ag.Role.Permits(capability.Access) {
		return "role " + string(ag.Role) + " does not permit " + string(capability.Access) + " access"
	}
	if violation := policyViolation(capability, lease.Params); violation != "" {
		return "capability " + capability.ID + " renders a prohibited policy: " + violation
	}
	return ""
}

// isRetiredCapability reports whether a capability is kept only for history.
func isRetiredCapability(id string) bool {
	for _, retired := range retiredCapabilityIDs {
		if id == retired {
			return true
		}
	}
	return false
}

// credentialReleaseProblem re-reads the lease, the agent and the agent's
// owner and reports why a credential must not be handed out, or "".
func (s *Server) credentialReleaseProblem(ctx context.Context, agentID, leaseID string) (string, error) {
	lease, err := s.db.GetLease(ctx, leaseID)
	if errors.Is(err, store.ErrNotFound) {
		return "lease no longer exists", nil
	}
	if err != nil {
		return "", err
	}
	if lease.Status != model.LeaseActive {
		return "lease is " + string(lease.Status) + "; credentials are only available for active leases", nil
	}
	if lease.ExpiresAt == nil || !lease.ExpiresAt.After(s.nowUTC()) {
		return "lease credential has expired", nil
	}
	ag, err := s.db.GetAgent(ctx, agentID)
	if errors.Is(err, store.ErrNotFound) {
		return "agent no longer exists", nil
	}
	if err != nil {
		return "", err
	}
	if ag.Status != model.AgentActive {
		return "agent is " + string(ag.Status), nil
	}
	if problem, err := s.agentOwnerProblem(ctx, ag); err != nil || problem != "" {
		return problem, err
	}
	// What an owned agent may hold depends on its owner's role, which can
	// change at any time: read it again now (CONTRACT §17.2).
	if ag.OwnerID != "" || capcatalog.IsAccessTemplateID(lease.CapabilityID) {
		return s.recheckLeaseAuthorization(ctx, lease)
	}
	return "", nil
}

// revalidateLeases re-runs the full activation check (recheckLeaseAuthorization)
// against every pending and active lease matching filter, and revokes each one
// that no longer passes. Every authority-reducing change calls it after its own
// write commits. Together with the post-mint recheck and the compare-and-set
// activation this leaves no window: a lease activated before this scan is seen
// as active and revoked; one still pending is revoked and its activation then
// fails; one whose recheck runs after the change's commit fails the recheck.
func (s *Server) revalidateLeases(ctx context.Context, filter store.LeaseFilter, reason string) ([]string, error) {
	return s.revalidateLeasesAs(ctx, filter, reason, nil)
}

// revalidateLeasesAs is revalidateLeases with audit attribution. With a nil
// cause the revocations are recorded as the operator's (the legacy admin
// API). Otherwise they are recorded as the control plane's, and cause (for
// example caused_by, owner_id) is added to each event, so the audit log
// names who triggered the revocation (§17.6).
func (s *Server) revalidateLeasesAs(ctx context.Context, filter store.LeaseFilter, reason string, cause map[string]any) ([]string, error) {
	// One consistent snapshot: paging over a set that shrinks as leases
	// expire or are revoked would skip rows.
	filter.Statuses = []model.LeaseStatus{model.LeasePending, model.LeaseActive}
	leases, err := s.db.ListAllLeases(ctx, filter)
	if err != nil {
		return nil, err
	}
	revoked := make([]string, 0, len(leases))
	for _, lease := range leases {
		problem, err := s.recheckLeaseAuthorization(ctx, lease)
		if err != nil {
			return nil, err
		}
		if problem == "" {
			continue
		}
		// The caller's reason is recorded exactly (the contract fixes some, e.g.
		// "role changed to guest"); the specific failed check is logged.
		s.logf("lease %s revoked on revalidation: %s", lease.ID, problem)
		if cause == nil {
			_, err = s.revokeLease(ctx, lease, reason, nil)
		} else {
			_, err = s.revokeLeaseWithCause(ctx, lease, reason, cause)
		}
		if err != nil {
			var he *httpError
			if errors.As(err, &he) && he.status == http.StatusConflict {
				continue
			}
			return nil, err
		}
		revoked = append(revoked, lease.ID)
	}
	return revoked, nil
}

// revokeLeaseWithCause revokes a lease on behalf of the control plane and
// records what triggered it.
func (s *Server) revokeLeaseWithCause(ctx context.Context, lease model.Lease, reason string, cause map[string]any) (model.Lease, error) {
	updated, previousStatus, err := s.markLeaseRevoked(ctx, lease, reason)
	if err != nil {
		return model.Lease{}, err
	}
	metadata := map[string]any{
		"actor":           "system",
		"reason":          reason,
		"previous_status": string(previousStatus),
		"agent_id":        lease.AgentID,
		"agent_name":      lease.AgentName,
	}
	for k, v := range cause {
		metadata[k] = v
	}
	s.systemAudit(ctx, "lease.revoked", "denied", denySeverity(updated.BreakGlass), "lease", updated.ID, metadata)
	return updated, nil
}

// revokePendingLeasesForCapability revokes every pending lease of a capability
// after an edit that narrows or invalidates it (disabled, access or policy
// changed). An approval racing the edit then loses its compare-and-set.
func (s *Server) revokePendingLeasesForCapability(ctx context.Context, capabilityID, reason string) ([]string, error) {
	leases, err := s.leasesForCapability(ctx, capabilityID, []model.LeaseStatus{model.LeasePending})
	if err != nil {
		return nil, err
	}
	revoked := make([]string, 0, len(leases))
	for _, lease := range leases {
		if _, err := s.revokeLease(ctx, lease, reason, nil); err != nil {
			var he *httpError
			if errors.As(err, &he) && he.status == http.StatusConflict {
				continue
			}
			return nil, err
		}
		revoked = append(revoked, lease.ID)
	}
	return revoked, nil
}

// revokeLease kills a pending or active lease, scrubbing its credential.
// actor is the agent for agent-initiated revocations, nil for admin ones.
func (s *Server) revokeLease(ctx context.Context, lease model.Lease, reason string, actor *model.Agent) (model.Lease, error) {
	updated, previousStatus, err := s.markLeaseRevoked(ctx, lease, reason)
	if err != nil {
		return model.Lease{}, err
	}
	metadata := s.leaseAgentMetadata(ctx, updated, map[string]any{
		"reason":          reason,
		"previous_status": string(previousStatus),
	})
	if actor != nil {
		metadata["actor"] = "agent:" + actor.ID
		s.agentAudit(ctx, *actor, "lease.revoked", "denied", denySeverity(updated.BreakGlass), "lease", updated.ID, metadata)
	} else {
		metadata["actor"] = "admin"
		if sc, ok := sessionFromContext(ctx); ok {
			metadata["actor"] = "person:" + sc.person.ID
		}
		s.adminAudit(ctx, "lease.revoked", "denied", denySeverity(updated.BreakGlass), "lease", updated.ID, metadata)
	}
	return updated, nil
}

// revokeLeaseAsSystem revokes a lease as a control-plane maintenance action
// (startup cleanup), attributing the audit event to the system actor.
func (s *Server) revokeLeaseAsSystem(ctx context.Context, lease model.Lease, reason string) (model.Lease, error) {
	updated, previousStatus, err := s.markLeaseRevoked(ctx, lease, reason)
	if err != nil {
		return model.Lease{}, err
	}
	s.systemAudit(ctx, "lease.revoked", "denied", denySeverity(updated.BreakGlass), "lease", updated.ID, map[string]any{
		"actor":           "system",
		"reason":          reason,
		"previous_status": string(previousStatus),
	})
	return updated, nil
}

// markLeaseRevoked moves a pending or active lease to revoked and scrubs its
// credential, returning the updated lease and the status it had before.
func (s *Server) markLeaseRevoked(ctx context.Context, lease model.Lease, reason string) (model.Lease, model.LeaseStatus, error) {
	if lease.Status != model.LeasePending && lease.Status != model.LeaseActive {
		return model.Lease{}, "", errConflictAPI("lease is " + string(lease.Status) + "; only pending or active leases can be revoked")
	}
	previousStatus := lease.Status
	now := s.nowUTC()
	// Terminal status first, then scrub: once the row is revoked no activation
	// can store a credential (SetLeaseCredential needs pending), so the scrub
	// below cannot miss a blob written concurrently.
	lease.Status = model.LeaseRevoked
	lease.RevokedAt = &now
	lease.RevokeReason = reason
	lease.CredentialAvailable = false
	lease.CredentialFingerprint = ""
	if err := s.db.UpdateLease(ctx, lease); err != nil {
		return model.Lease{}, "", err
	}
	if err := s.db.ClearLeaseCredential(ctx, lease.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return model.Lease{}, "", err
	}
	return lease, previousStatus, nil
}

// retireCapabilityLeases revokes every pending or active lease on a retired
// capability. It runs on every startup (CONTRACT §16.6): the capability row is
// kept so historic leases stay readable, but no lease on it may ever become
// active again.
//
// It covers more than the retired capability: every pending or active lease
// whose capability is missing, retired, or now renders a policy that fails the
// IAM prohibition is revoked. A v1 credential was minted without the mandatory
// deny statement, so a v1 custom capability that allowed RAM must not keep a
// live lease after the upgrade disabled it.
//
// It fails closed: an error stops the server from starting.
func (s *Server) retireCapabilityLeases(ctx context.Context) error {
	leases, err := s.db.ListAllLeases(ctx, store.LeaseFilter{
		Statuses: []model.LeaseStatus{model.LeasePending, model.LeaseActive},
	})
	if err != nil {
		return fmt.Errorf("list pending and active leases: %w", err)
	}
	capabilities := map[string]*model.Capability{}
	for _, lease := range leases {
		capability, seen := capabilities[lease.CapabilityID]
		if !seen {
			c, err := s.capabilityByID(ctx, lease.CapabilityID)
			switch {
			case err == nil:
				capability = &c
			case errors.Is(err, store.ErrNotFound):
				capability = nil
			default:
				return fmt.Errorf("read capability %s: %w", lease.CapabilityID, err)
			}
			capabilities[lease.CapabilityID] = capability
		}
		reason := ""
		switch {
		case capability == nil:
			reason = "capability no longer exists"
		case isRetiredCapability(capability.ID):
			reason = "capability retired"
		case policyViolation(*capability, lease.Params) != "":
			reason = "policy violates the IAM prohibition"
		case !capability.Enabled:
			// Disabling a capability revokes its live leases (CONTRACT §16.5);
			// this also covers capabilities an upgrade migration disabled, such
			// as a v1 template that allowed a bare "*".
			reason = "capability disabled"
		}
		if reason == "" {
			continue
		}
		if _, err := s.revokeLeaseAsSystem(ctx, lease, reason); err != nil {
			var he *httpError
			if errors.As(err, &he) && he.status == http.StatusConflict {
				continue // already terminal
			}
			return fmt.Errorf("revoke lease %s: %w", lease.ID, err)
		}
	}
	return nil
}

// leasesForCapability returns every lease of one capability in the given
// statuses, paging through the store.
func (s *Server) leasesForCapability(ctx context.Context, capabilityID string, statuses []model.LeaseStatus) ([]model.Lease, error) {
	return s.db.ListAllLeases(ctx, store.LeaseFilter{CapabilityID: capabilityID, Statuses: statuses})
}

// ================= sweeper =================

// sweepOnce expires timed-out pending leases and past-TTL active leases. It is
// exported to the package only so tests can drive it directly.
func (s *Server) sweepOnce(ctx context.Context) {
	now := s.nowUTC()
	if err := s.db.DeleteStaleSessions(ctx, now, sessionIdleTimeout); err != nil {
		s.logf("sweeper: delete stale sessions: %v", err)
	}
	if err := s.db.DeleteOldSignIns(ctx, now.Add(-signInRetention)); err != nil {
		s.logf("sweeper: delete old sign-ins: %v", err)
	}
	settings, err := s.db.GetPolicySettings(ctx)
	if err != nil {
		s.logf("sweeper: read policy settings: %v", err)
		return
	}
	pendingTimeout := time.Duration(settings.PendingTimeoutSeconds) * time.Second
	if pending, err := s.db.ListPendingLeases(ctx); err != nil {
		s.logf("sweeper: list pending leases: %v", err)
	} else {
		for _, lease := range pending {
			if !lease.CreatedAt.IsZero() && now.Sub(lease.CreatedAt) >= pendingTimeout {
				s.expireLease(ctx, lease, "pending request timed out")
			}
		}
	}
	if active, err := s.db.ListActiveLeases(ctx); err != nil {
		s.logf("sweeper: list active leases: %v", err)
	} else {
		for _, lease := range active {
			if lease.ExpiresAt != nil && !lease.ExpiresAt.After(now) {
				s.expireLease(ctx, lease, "lease TTL elapsed")
			}
		}
	}
}

// expireLease moves a pending or active lease to expired and scrubs its
// credential. It re-reads the lease first so a concurrent revoke is not
// clobbered.
func (s *Server) expireLease(ctx context.Context, lease model.Lease, reason string) {
	current, err := s.db.GetLease(ctx, lease.ID)
	if err != nil || current.Status != lease.Status {
		return
	}
	// Terminal status first, then scrub (see markLeaseRevoked).
	current.Status = model.LeaseExpired
	current.CredentialAvailable = false
	current.CredentialFingerprint = ""
	if err := s.db.UpdateLeaseIfStatus(ctx, current, lease.Status); err != nil {
		if !errors.Is(err, store.ErrConflict) {
			s.logf("sweeper: expire lease %s: %v", current.ID, err)
		}
		return
	}
	if err := s.db.ClearLeaseCredential(ctx, current.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logf("sweeper: clear credential for %s: %v", current.ID, err)
	}
	s.systemAudit(ctx, "lease.expired", "ok", "warning", "lease", current.ID, map[string]any{
		"previous_status": string(lease.Status),
		"reason":          reason,
	})
}

// lockAgentRequests serializes the requests of one agent, so the rate and
// concurrency limits are checked against a count that cannot change before
// the request is stored. Single process per data dir (ADR-002).
func (s *Server) lockAgentRequests(agentID string) func() {
	s.agentLocksMu.Lock()
	if s.agentLocks == nil {
		s.agentLocks = map[string]*sync.Mutex{}
	}
	lock, ok := s.agentLocks[agentID]
	if !ok {
		lock = &sync.Mutex{}
		s.agentLocks[agentID] = lock
	}
	s.agentLocksMu.Unlock()
	lock.Lock()
	return lock.Unlock
}

// leaseAgentMetadata adds the lease's agent, and the person who owns it, to
// audit metadata, so every event names both (CONTRACT §17.6).
func (s *Server) leaseAgentMetadata(ctx context.Context, lease model.Lease, metadata map[string]any) map[string]any {
	metadata["agent_id"] = lease.AgentID
	metadata["agent_name"] = lease.AgentName
	if ag, err := s.db.GetAgent(ctx, lease.AgentID); err == nil && ag.OwnerID != "" {
		metadata["owner_id"] = ag.OwnerID
	}
	return metadata
}
