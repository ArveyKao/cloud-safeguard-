package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/arveykao/cloud-safeguard/internal/capcatalog"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/policy"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// Access requests (CONTRACT §17.4, §17.5).
//
// An owned agent names a cloud account, a resource type, a permission and a
// validity period. The server maps the pair onto a vetted template, checks
// the owner's role on that account, and then either issues the credential
// (read) or waits for the owner's approval (write, full).

// Decision rule names specific to access requests.
const (
	ruleOwnerBound       = "owner_bound_to_account"
	ruleOwnerRolePermits = "owner_role_permits"
	ruleAutomatic        = "automatic_by_mode"
	ruleOwnerApproval    = "owner_approval_required"
)

const maxReasonLength = 500

// maxResourceNameLength bounds resource_name before pattern validation (253
// is the longest DNS name).
const maxResourceNameLength = 253

// minProviderTTL is the shortest credential a provider mode can mint.
func minProviderTTL(mode model.ProviderMode) int {
	if mode == model.ModeSTS {
		return provider.STSMinDuration
	}
	return provider.MockMinDuration
}

// handleAgentCreateAccessRequest implements POST /api/v1/agent/access-requests.
func (s *Server) handleAgentCreateAccessRequest(w http.ResponseWriter, r *http.Request) {
	ag, _ := agentFromContext(r.Context())
	var in model.AccessRequestInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	lease, err := s.createAccessRequest(r.Context(), ag, in)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	view, err := s.accessRequestView(r.Context(), lease)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusCreated, view)
}

// createAccessRequest verifies an access request in the order of §17.4 and
// hands it to the lease pipeline. Malformed requests are 400 and leave no
// record; a well-formed request the owner's role does not allow is recorded
// as denied and never reaches approval.
func (s *Server) createAccessRequest(ctx context.Context, ag model.Agent, in model.AccessRequestInput) (model.Lease, error) {
	if ag.OwnerID == "" {
		return model.Lease{}, &httpError{status: http.StatusForbidden, code: model.ErrCodeForbidden,
			message: "this agent has no owner; sign in again so a person can approve it"}
	}
	accountID := strings.TrimSpace(in.CloudAccountID)
	if accountID == "" {
		return model.Lease{}, errBadRequestAPI("cloud_account_id is required")
	}
	resource := strings.TrimSpace(in.Resource)
	if resource == "" {
		return model.Lease{}, errBadRequestAPI("resource is required")
	}
	permission := capcatalog.Permission(strings.TrimSpace(in.Permission))
	if !permission.Valid() {
		return model.Lease{}, errBadRequestAPI("permission must be read, write or full")
	}
	if in.TTLSeconds <= 0 {
		return model.Lease{}, errBadRequestAPI("ttl_seconds is required and must be positive")
	}
	reason := strings.TrimSpace(in.Reason)
	if !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > maxReasonLength {
		return model.Lease{}, errBadRequestAPI(fmt.Sprintf("reason must be at most %d characters", maxReasonLength))
	}
	if permission != capcatalog.PermissionRead && reason == "" {
		return model.Lease{}, errBadRequestAPI("reason is required for write and full requests; it is shown to the person who approves")
	}

	// The cloud account and the owner's role on it. An unknown account and an
	// account the owner has no role on look the same to the agent.
	noAccess := &httpError{status: http.StatusForbidden, code: model.ErrCodeForbidden,
		message: "your owner has no role on cloud account " + sanitizeMessage(accountID)}
	prov, err := s.db.GetProviderByCloudAccountID(ctx, accountID)
	if errors.Is(err, store.ErrNotFound) {
		s.agentAudit(ctx, ag, "access.refused", "denied", "warning", "agent", ag.ID, map[string]any{
			"cloud_account_id": sanitizeMessage(accountID), "reason": "unknown cloud account",
		})
		return model.Lease{}, noAccess
	}
	if err != nil {
		return model.Lease{}, err
	}
	binding, err := s.db.GetBinding(ctx, ag.OwnerID, prov.ID)
	if errors.Is(err, store.ErrNotFound) {
		s.agentAudit(ctx, ag, "access.refused", "denied", "warning", "provider", prov.ID, map[string]any{
			"cloud_account_id": accountID, "reason": "owner has no role on this cloud account",
		})
		return model.Lease{}, noAccess
	}
	if err != nil {
		return model.Lease{}, err
	}
	if prov.Status != model.ProviderActive {
		return model.Lease{}, errConflictAPI("cloud account " + accountID + " is disabled")
	}

	template, ok := capcatalog.LookupAccessTemplate(prov.Type, resource, permission)
	if !ok {
		return model.Lease{}, errBadRequestAPI("unknown resource " + sanitizeMessage(resource) +
			"; available: " + strings.Join(capcatalog.AccessResources(prov.Type), ", "))
	}
	capability := template.Capability
	name := strings.TrimSpace(in.ResourceName)
	if name == "" {
		name = capcatalog.AllResources
	} else if name == capcatalog.AllResources {
		return model.Lease{}, errBadRequestAPI("leave resource_name out to ask for all resources")
	}
	if len(name) > maxResourceNameLength {
		return model.Lease{}, errBadRequestAPI(fmt.Sprintf("resource_name must be at most %d characters", maxResourceNameLength))
	}
	params := map[string]string{capcatalog.ResourceNameParam: name}
	if err := capcatalog.ValidateParams(capability, params); err != nil {
		return model.Lease{}, errBadRequestAPI("resource_name must be " + capcatalog.ResourceNameHint(prov.Type, resource))
	}

	settings, err := s.db.GetPolicySettings(ctx)
	if err != nil {
		return model.Lease{}, err
	}
	minTTL := minProviderTTL(prov.Mode)
	maxTTL := capability.MaxTTLSeconds
	if ag.MaxTTLSeconds < maxTTL {
		maxTTL = ag.MaxTTLSeconds
	}
	if settings.MaxLeaseTTLSeconds < maxTTL {
		maxTTL = settings.MaxLeaseTTLSeconds
	}
	if in.TTLSeconds < minTTL {
		return model.Lease{}, errBadRequestAPI(fmt.Sprintf("ttl_seconds %d is below the minimum %d for this cloud account", in.TTLSeconds, minTTL))
	}
	if in.TTLSeconds > maxTTL {
		return model.Lease{}, errBadRequestAPI(fmt.Sprintf("ttl_seconds %d exceeds the allowed maximum %d", in.TTLSeconds, maxTTL))
	}

	// From the counts below until the request is stored, no other request of
	// this agent may run: otherwise a burst would pass the limits together.
	unlockAgent := s.lockAgentRequests(ag.ID)
	defer unlockAgent()
	now := s.nowUTC()
	// Waiting requests count too: an agent cannot queue an unbounded number
	// of approvals for its owner.
	open, err := s.db.ListAllLeases(ctx, store.LeaseFilter{AgentID: ag.ID,
		Statuses: []model.LeaseStatus{model.LeasePending, model.LeaseActive}})
	if err != nil {
		return model.Lease{}, err
	}
	activeCount := len(open)
	lastMinute, err := s.db.CountLeasesSince(ctx, ag.ID, now.Add(-time.Minute))
	if err != nil {
		return model.Lease{}, err
	}

	decision := model.PolicyDecision{EffectiveTTLSeconds: in.TTLSeconds, Outcome: model.OutcomeAutoApprove}
	var auditExtra map[string]any
	add := func(rule, outcome, detail string) {
		decision.Reasons = append(decision.Reasons, model.DecisionReason{Rule: rule, Outcome: outcome, Detail: detail})
		if outcome == policy.OutcomeDeny {
			decision.Outcome = model.OutcomeDeny
		}
	}
	add(ruleOwnerBound, policy.OutcomeAllow,
		fmt.Sprintf("the agent's owner is %s on cloud account %s", binding.Role, accountID))
	if binding.Role.Permits(capability.Access) {
		add(ruleOwnerRolePermits, policy.OutcomeAllow,
			fmt.Sprintf("role %s permits %s access", binding.Role, permission))
	} else {
		add(ruleOwnerRolePermits, policy.OutcomeDeny,
			fmt.Sprintf("the owner's role %s on this cloud account does not permit %s access", binding.Role, permission))
	}
	if violation := policyViolation(capability, params); violation != "" {
		add(policy.RuleIAMProhibited, policy.OutcomeDeny, violation)
	} else {
		add(policy.RuleIAMProhibited, policy.OutcomeAllow, "the policy grants no IAM or RAM management")
	}
	if activeCount >= ag.MaxConcurrentLeases {
		add(policy.RuleConcurrency, policy.OutcomeDeny,
			fmt.Sprintf("%d credentials or requests of this agent are active or waiting; the limit is %d", activeCount, ag.MaxConcurrentLeases))
	}
	if lastMinute >= settings.LeasesPerMinutePerAgent {
		add(policy.RuleRateLimit, policy.OutcomeDeny,
			fmt.Sprintf("%d requests in the last minute; the limit is %d", lastMinute, settings.LeasesPerMinutePerAgent))
	}
	if decision.Outcome != model.OutcomeDeny {
		// What is automatic: the lower of the owner's approval mode and the
		// cloud account's highest automatic level (§17.5). The role check
		// above already held; a mode never widens it.
		owner, err := s.db.GetPerson(ctx, ag.OwnerID)
		if err != nil {
			return model.Lease{}, err
		}
		mode, level, automatic := automaticLevel(owner, prov, now)
		auditExtra = map[string]any{"approval_mode": string(mode), "max_auto_level": string(level)}
		if permission.Rank() <= automatic.Rank() {
			add(ruleAutomatic, policy.OutcomeAllow, fmt.Sprintf(
				"%s access is issued without approval (owner's mode %s, account's highest automatic level %s)",
				permission, mode, level))
		} else {
			decision.Outcome = model.OutcomeRequireApproval
			add(ruleOwnerApproval, policy.OutcomeRequireApproval, fmt.Sprintf(
				"%s access waits for the owner's approval (owner's mode %s, account's highest automatic level %s)",
				permission, mode, level))
		}
	}

	return s.submitLease(ctx, ag, capability, &prov, decision, auditExtra, model.CreateLeaseInput{
		CapabilityID: capability.ID,
		Params:       params,
		TTLSeconds:   in.TTLSeconds,
		Reason:       reason,
	}, now)
}

// accessRequestView renders a lease of an access template for the API.
func (s *Server) accessRequestView(ctx context.Context, lease model.Lease) (model.AccessRequest, error) {
	template, ok := capcatalog.AccessTemplateByID(lease.CapabilityID)
	if !ok {
		return model.AccessRequest{}, errNotFoundAPI("request not found")
	}
	view := model.AccessRequest{
		ID: lease.ID, AgentID: lease.AgentID, AgentName: lease.AgentName,
		CloudAccountName: lease.ProviderName,
		Resource:         template.Resource, Permission: string(template.Permission),
		TTLSeconds: lease.RequestedTTLSeconds, Reason: lease.Reason,
		Status: lease.Status, Decision: lease.Decision,
		DeniedReason: lease.DeniedReason, RevokeReason: lease.RevokeReason, FailureReason: lease.FailureReason,
		ApprovedBy: lease.ApprovedBy, CredentialAvailable: lease.CredentialAvailable,
		CreatedAt: lease.CreatedAt, ApprovedAt: lease.ApprovedAt, IssuedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt,
	}
	if name := lease.Params[capcatalog.ResourceNameParam]; name != capcatalog.AllResources {
		view.ResourceName = name
	}
	if prov, err := s.db.GetProvider(ctx, lease.ProviderID); err == nil {
		view.CloudAccountID = prov.CloudAccountID
	} else if !errors.Is(err, store.ErrNotFound) {
		return model.AccessRequest{}, err
	}
	if ag, err := s.db.GetAgent(ctx, lease.AgentID); err == nil {
		view.OwnerID = ag.OwnerID
	} else if !errors.Is(err, store.ErrNotFound) {
		return model.AccessRequest{}, err
	}
	return view, nil
}

// handleAgentGetAccessRequest implements GET /api/v1/agent/access-requests/{id}.
func (s *Server) handleAgentGetAccessRequest(w http.ResponseWriter, r *http.Request) {
	ag, _ := agentFromContext(r.Context())
	lease, err := s.db.GetLease(r.Context(), r.PathValue("id"))
	if err != nil || lease.AgentID != ag.ID || !capcatalog.IsAccessTemplateID(lease.CapabilityID) {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.writeHandlerError(w, err)
			return
		}
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "request not found")
		return
	}
	view, err := s.accessRequestView(r.Context(), lease)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, view)
}

// handleAgentListAccounts implements GET /api/v1/agent/accounts: the cloud
// accounts the agent's owner has a role on.
func (s *Server) handleAgentListAccounts(w http.ResponseWriter, r *http.Request) {
	ag, _ := agentFromContext(r.Context())
	accounts := []model.AgentAccount{}
	if ag.OwnerID != "" {
		bindings, err := s.db.ListBindings(r.Context(), ag.OwnerID, "")
		if err != nil {
			s.writeHandlerError(w, err)
			return
		}
		for _, b := range bindings {
			prov, err := s.db.GetProvider(r.Context(), b.ProviderID)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				s.writeHandlerError(w, err)
				return
			}
			if prov.Status != model.ProviderActive || prov.CloudAccountID == "" {
				continue
			}
			highest := capcatalog.PermissionRead
			for _, p := range capcatalog.Permissions() {
				if b.Role.Permits(p.Access()) {
					highest = p
				}
			}
			owner, err := s.db.GetPerson(r.Context(), ag.OwnerID)
			if err != nil {
				s.writeHandlerError(w, err)
				return
			}
			_, _, automatic := automaticLevel(owner, prov, s.nowUTC())
			if automatic.Rank() > highest.Rank() {
				automatic = model.ApprovalMode(highest)
			}
			accounts = append(accounts, model.AgentAccount{
				CloudAccountID: prov.CloudAccountID, Name: prov.Name, ProviderType: prov.Type,
				Role: b.Role, HighestPermission: string(highest), AutomaticUpTo: string(automatic),
				Resources: capcatalog.AccessResources(prov.Type),
			})
		}
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].CloudAccountID < accounts[j].CloudAccountID })
	writeList(s, w, http.StatusOK, accounts, len(accounts))
}

// ---- the owner's side ----

// ownedAccessLeases returns the access-request leases of the person's
// agents, newest first, optionally filtered by status.
func (s *Server) ownedAccessLeases(ctx context.Context, personID string, statuses []model.LeaseStatus) ([]model.Lease, error) {
	agents, err := s.db.ListAgentsByOwner(ctx, personID)
	if err != nil {
		return nil, err
	}
	var out []model.Lease
	for _, ag := range agents {
		// Newest 200 per agent: the history of an agent can be long, the
		// inbox must stay cheap.
		leases, _, err := s.db.ListLeases(ctx, store.LeaseFilter{AgentID: ag.ID, Statuses: statuses, Limit: 200})
		if err != nil {
			return nil, err
		}
		for _, lease := range leases {
			if capcatalog.IsAccessTemplateID(lease.CapabilityID) {
				out = append(out, lease)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// handleListMyRequests implements GET /api/v1/me/requests?status=pending.
func (s *Server) handleListMyRequests(w http.ResponseWriter, r *http.Request) {
	actor, _ := sessionFromContext(r.Context())
	var statuses []model.LeaseStatus
	if raw := r.URL.Query().Get("status"); raw != "" {
		status := model.LeaseStatus(raw)
		if !status.Valid() {
			s.badRequest(w, "unknown status")
			return
		}
		statuses = []model.LeaseStatus{status}
	}
	leases, err := s.ownedAccessLeases(r.Context(), actor.person.ID, statuses)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if len(leases) > 200 {
		leases = leases[:200]
	}
	views := make([]model.AccessRequest, 0, len(leases))
	for _, lease := range leases {
		view, err := s.accessRequestView(r.Context(), lease)
		if err != nil {
			s.writeHandlerError(w, err)
			return
		}
		views = append(views, view)
	}
	writeList(s, w, http.StatusOK, views, len(views))
}

// handleApproveMyRequest implements POST /api/v1/me/requests/{id}/approve.
func (s *Server) handleApproveMyRequest(w http.ResponseWriter, r *http.Request) {
	actor, _ := sessionFromContext(r.Context())
	var in struct {
		Note string `json:"note,omitempty"`
	}
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	if utf8.RuneCountInString(in.Note) > maxReasonLength {
		s.badRequest(w, fmt.Sprintf("note must be at most %d characters", maxReasonLength))
		return
	}
	lease, err := s.approveLease(r.Context(), r.PathValue("id"), model.ApproveLeaseInput{Note: in.Note}, &actor.person)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	view, err := s.accessRequestView(r.Context(), lease)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, view)
}

// handleDenyMyRequest implements POST /api/v1/me/requests/{id}/deny.
func (s *Server) handleDenyMyRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	var in model.DenyRequestInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	reason := strings.TrimSpace(in.Reason)
	if utf8.RuneCountInString(reason) > maxReasonLength {
		s.badRequest(w, fmt.Sprintf("reason must be at most %d characters", maxReasonLength))
		return
	}
	if reason == "" {
		reason = "denied by the agent's owner"
	}
	id := r.PathValue("id")
	unlock := s.lockLease(id)
	defer unlock()
	lease, ag, ok := s.ownedAccessLease(ctx, id, actor.person.ID)
	if !ok {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "request not found")
		return
	}
	if lease.Status != model.LeasePending {
		s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "request is "+string(lease.Status)+", only pending requests can be denied")
		return
	}
	lease.Status = model.LeaseDenied
	lease.DeniedReason = sanitizeMessage(reason)
	lease.CredentialAvailable = false
	lease.CredentialFingerprint = ""
	if err := s.db.UpdateLeaseIfStatus(ctx, lease, model.LeasePending); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "request is no longer pending")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	if err := s.db.ClearLeaseCredential(ctx, lease.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.logf("lease %s: scrub credential on deny: %v", lease.ID, err)
	}
	s.personAudit(ctx, actor.person, "lease.denied", "denied", "info", "lease", lease.ID, map[string]any{
		"reason": lease.DeniedReason, "agent_id": ag.ID, "agent_name": ag.Name,
	})
	view, err := s.accessRequestView(ctx, lease)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, view)
}

// handleRevokeMyRequest implements POST /api/v1/me/requests/{id}/revoke: the
// owner ends an issued (or still pending) request early.
func (s *Server) handleRevokeMyRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	lease, ag, ok := s.ownedAccessLease(ctx, r.PathValue("id"), actor.person.ID)
	if !ok {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "request not found")
		return
	}
	revoked, err := s.revokeLeaseWithCause(ctx, lease, "revoked by the agent's owner", map[string]any{
		"cause": "owner_revoked", "owner_id": actor.person.ID, "agent_id": ag.ID,
	})
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	view, err := s.accessRequestView(ctx, revoked)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, view)
}

// ownedAccessLease loads an access-request lease that belongs to one of the
// person's agents. Anything else (missing, someone else's, a §16 lease) is
// reported as not found.
func (s *Server) ownedAccessLease(ctx context.Context, leaseID, personID string) (model.Lease, model.Agent, bool) {
	lease, err := s.db.GetLease(ctx, leaseID)
	if err != nil || !capcatalog.IsAccessTemplateID(lease.CapabilityID) {
		return model.Lease{}, model.Agent{}, false
	}
	ag, err := s.db.GetAgent(ctx, lease.AgentID)
	if err != nil || ag.OwnerID == "" || ag.OwnerID != personID {
		return model.Lease{}, model.Agent{}, false
	}
	return lease, ag, true
}

// ---- approval modes (CONTRACT §17.5) ----

// maxModeExpiry bounds a temporary approval mode.
const maxModeExpiry = 30 * 24 * time.Hour

// handleSetMyApprovalMode implements PUT /api/v1/me/approval-mode. A person
// sets only their own mode; it applies to all their agents.
func (s *Server) handleSetMyApprovalMode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	var in model.SetApprovalModeInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	if !in.Mode.Valid() {
		s.badRequest(w, "mode must be read, write or full")
		return
	}
	if in.ExpiresInSeconds < 0 || time.Duration(in.ExpiresInSeconds)*time.Second > maxModeExpiry {
		s.badRequest(w, "expires_in_seconds must be between 0 and 30 days")
		return
	}
	now := s.nowUTC()
	var expiresAt *time.Time
	if in.ExpiresInSeconds > 0 && in.Mode != model.ModeRead {
		t := now.Add(time.Duration(in.ExpiresInSeconds) * time.Second)
		expiresAt = &t
	}
	previous := actor.person.EffectiveApprovalMode(now)
	if err := s.db.SetApprovalMode(ctx, actor.person.ID, in.Mode, expiresAt, now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "your account is not active")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	severity := "info"
	if in.Mode.Rank() > previous.Rank() {
		severity = "warning"
	}
	metadata := map[string]any{"mode": string(in.Mode), "previous_mode": string(previous)}
	if expiresAt != nil {
		metadata["expires_at"] = expiresAt.Format(time.RFC3339)
	}
	s.personAudit(ctx, actor.person, "person.approval_mode_changed", "ok", severity, "person", actor.person.ID, metadata)
	updated, err := s.db.GetPerson(ctx, actor.person.ID)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, updated)
}

// handleSetAccountAutoLevel implements
// PUT /api/v1/supervisor/accounts/{provider}/auto-level.
func (s *Server) handleSetAccountAutoLevel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	var in model.SetAutoLevelInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	if !in.MaxAutoLevel.Valid() {
		s.badRequest(w, "max_auto_level must be read, write or full")
		return
	}
	prov, err := s.db.GetProvider(ctx, r.PathValue("provider"))
	if err != nil {
		s.storeErrorResponse(w, err, "cloud account not found")
		return
	}
	if err := s.db.SetProviderMaxAutoLevel(ctx, prov.ID, in.MaxAutoLevel, s.nowUTC()); err != nil {
		s.storeErrorResponse(w, err, "cloud account not found")
		return
	}
	severity := "info"
	if in.MaxAutoLevel.Rank() > prov.MaxAutoLevel.Rank() {
		severity = "warning"
	}
	s.personAudit(ctx, actor.person, "provider.auto_level_changed", "ok", severity, "provider", prov.ID, map[string]any{
		"max_auto_level": string(in.MaxAutoLevel), "previous": string(prov.MaxAutoLevel), "cloud_account_id": prov.CloudAccountID,
	})
	updated, err := s.db.GetProvider(ctx, prov.ID)
	if err != nil {
		s.storeErrorResponse(w, err, "cloud account not found")
		return
	}
	s.writeData(w, http.StatusOK, updated)
}

// automaticLevel returns the owner's effective approval mode, the cloud
// account's highest automatic level, and the lower of the two: requests at
// or below it are issued without asking (CONTRACT §17.5). Unknown or
// missing values count as read, so they can never widen anything.
func automaticLevel(owner model.Person, prov model.Provider, now time.Time) (mode, level, automatic model.ApprovalMode) {
	mode = owner.EffectiveApprovalMode(now)
	level = prov.MaxAutoLevel
	if !level.Valid() {
		level = model.ModeRead
	}
	automatic = mode
	if level.Rank() < automatic.Rank() {
		automatic = level
	}
	return mode, level, automatic
}
