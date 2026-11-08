package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

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
	})

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
	s.agentAudit(ctx, ag, "lease.requested", requestedStatus, "info", "lease", lease.ID, map[string]any{
		"capability":  capability.ID,
		"risk":        string(capability.Risk),
		"params":      in.Params,
		"ttl_seconds": decision.EffectiveTTLSeconds,
		"decision":    string(decision.Outcome),
		"break_glass": in.BreakGlass,
	})

	switch decision.Outcome {
	case model.OutcomeAutoApprove:
		approvedAt := now
		lease.ApprovedAt = &approvedAt
		lease.ApprovedBy = "auto"
		if err := s.mintCredentialForLease(ctx, &lease, capability, selected, decision.EffectiveTTLSeconds); err != nil {
			lease.Status = model.LeaseFailed
			lease.FailureReason = sanitizeMessage(err.Error())
			if uerr := s.db.UpdateLease(ctx, lease); uerr != nil {
				s.logf("lease %s: persist failed state: %v", lease.ID, uerr)
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
		if err := s.db.UpdateLease(ctx, lease); err != nil {
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
	s.writeData(w, http.StatusOK, lease)
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

	envelope := s.credentialEnvelope(credential, lease, r)
	s.agentAudit(r.Context(), ag, "lease.credential_fetched", "ok", "info", "lease", lease.ID, map[string]any{
		"remote_addr": remoteHost(r),
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
	reason := in.Reason
	if reason == "" {
		reason = "revoked by agent"
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
		s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "lease is "+string(lease.Status)+", only pending leases can be approved")
		return
	}
	now := s.nowUTC()
	settings, err := s.db.GetPolicySettings(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if now.Sub(lease.CreatedAt) > time.Duration(settings.PendingTimeoutSeconds)*time.Second {
		// The sweeper may not have run yet; expire it inline then report 409.
		s.expireLease(r.Context(), lease, "pending request timed out")
		s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "lease approval window has expired")
		return
	}
	capability, err := s.db.GetCapability(r.Context(), lease.CapabilityID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "capability no longer exists")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	ag, err := s.db.GetAgent(r.Context(), lease.AgentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "agent no longer exists")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	if lease.ProviderID == "" {
		s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "lease has no provider")
		return
	}
	prov, err := s.db.GetProvider(r.Context(), lease.ProviderID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "provider no longer exists")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	if !capability.Enabled {
		s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "capability is disabled")
		return
	}
	if prov.Status != model.ProviderActive {
		s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "provider is not active")
		return
	}

	ttl := in.TTLSeconds
	if ttl <= 0 {
		ttl = lease.RequestedTTLSeconds
	}
	if ttl <= 0 {
		ttl = lease.EffectiveTTLSeconds
	}
	if ttl <= 0 {
		s.badRequest(w, "ttl_seconds must be positive")
		return
	}
	maxTTL := capability.MaxTTLSeconds
	if ag.MaxTTLSeconds < maxTTL {
		maxTTL = ag.MaxTTLSeconds
	}
	if settings.MaxLeaseTTLSeconds < maxTTL {
		maxTTL = settings.MaxLeaseTTLSeconds
	}
	if ttl > maxTTL {
		s.badRequest(w, fmt.Sprintf("ttl_seconds %d exceeds the allowed maximum %d", ttl, maxTTL))
		return
	}

	approvedAt := now
	lease.ApprovedBy = "admin"
	lease.ApprovalNote = in.Note
	lease.ApprovedAt = &approvedAt
	lease.EffectiveTTLSeconds = ttl
	if err := s.mintCredentialForLease(r.Context(), &lease, capability, &prov, ttl); err != nil {
		lease.Status = model.LeaseFailed
		lease.FailureReason = sanitizeMessage(err.Error())
		if uerr := s.db.UpdateLease(r.Context(), lease); uerr != nil {
			s.logf("lease %s: persist failed state: %v", lease.ID, uerr)
		}
		s.adminAudit(r.Context(), "lease.failed", "failed", "warning", "lease", lease.ID, map[string]any{
			"reason": lease.FailureReason,
		})
		// Contract: provider failure returns 200 with the failed lease.
		s.writeData(w, http.StatusOK, lease)
		return
	}
	issuedAt := now
	expiresAt := now.Add(time.Duration(ttl) * time.Second)
	lease.Status = model.LeaseActive
	lease.IssuedAt = &issuedAt
	lease.ExpiresAt = &expiresAt
	if err := s.db.UpdateLease(r.Context(), lease); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "lease.approved", "ok", approveSeverity(lease.BreakGlass), "lease", lease.ID, map[string]any{
		"ttl_seconds": ttl,
		"note":        in.Note,
	})
	s.adminAudit(r.Context(), "lease.credential_issued", "ok", "info", "lease", lease.ID, map[string]any{
		"fingerprint": lease.CredentialFingerprint,
		"expires_at":  expiresAt.UTC().Format(time.RFC3339Nano),
	})
	s.writeData(w, http.StatusOK, lease)
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
	if err := s.db.UpdateLease(r.Context(), lease); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "lease.denied", "denied", denySeverity(lease.BreakGlass), "lease", lease.ID, map[string]any{
		"reason": reason,
	})
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
	reason := in.Reason
	if reason == "" {
		reason = "revoked by operator"
	}
	updated, err := s.revokeLease(r.Context(), lease, reason, nil)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, updated)
}

// revokeLease kills a pending or active lease, scrubbing its credential.
// actor is the agent for agent-initiated revocations, nil for admin ones.
func (s *Server) revokeLease(ctx context.Context, lease model.Lease, reason string, actor *model.Agent) (model.Lease, error) {
	if lease.Status != model.LeasePending && lease.Status != model.LeaseActive {
		return model.Lease{}, errConflictAPI("lease is " + string(lease.Status) + "; only pending or active leases can be revoked")
	}
	previousStatus := lease.Status
	now := s.nowUTC()
	if err := s.db.ClearLeaseCredential(ctx, lease.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		return model.Lease{}, err
	}
	lease.Status = model.LeaseRevoked
	lease.RevokedAt = &now
	lease.RevokeReason = reason
	lease.CredentialAvailable = false
	lease.CredentialFingerprint = ""
	if err := s.db.UpdateLease(ctx, lease); err != nil {
		return model.Lease{}, err
	}
	metadata := map[string]any{
		"reason":          reason,
		"previous_status": string(previousStatus),
	}
	if actor != nil {
		metadata["actor"] = "agent:" + actor.ID
		s.agentAudit(ctx, *actor, "lease.revoked", "denied", denySeverity(lease.BreakGlass), "lease", lease.ID, metadata)
	} else {
		metadata["actor"] = "admin"
		s.adminAudit(ctx, "lease.revoked", "denied", denySeverity(lease.BreakGlass), "lease", lease.ID, metadata)
	}
	return lease, nil
}

// ================= sweeper =================

// sweepOnce expires timed-out pending leases and past-TTL active leases. It is
// exported to the package only so tests can drive it directly.
func (s *Server) sweepOnce(ctx context.Context) {
	now := s.nowUTC()
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
	if err := s.db.ClearLeaseCredential(ctx, current.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logf("sweeper: clear credential for %s: %v", current.ID, err)
	}
	current.Status = model.LeaseExpired
	current.CredentialAvailable = false
	current.CredentialFingerprint = ""
	if err := s.db.UpdateLease(ctx, current); err != nil {
		s.logf("sweeper: expire lease %s: %v", current.ID, err)
		return
	}
	s.systemAudit(ctx, "lease.expired", "ok", "warning", "lease", current.ID, map[string]any{
		"previous_status": string(lease.Status),
		"reason":          reason,
	})
}
