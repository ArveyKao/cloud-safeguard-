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
	"github.com/arveykao/cloud-safeguard/internal/mcp"
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
	if in.MaxLifetimeSeconds < 0 {
		return model.Lease{}, errBadRequestAPI("max_lifetime_seconds must be positive when given")
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
	role, err := s.personRole(ctx, ag.OwnerID, prov.ID)
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
	if settings.MaxLeaseTTLSeconds < maxTTL {
		maxTTL = settings.MaxLeaseTTLSeconds
	}
	if in.TTLSeconds < minTTL {
		return model.Lease{}, errBadRequestAPI(fmt.Sprintf("ttl_seconds %d is below the minimum %d for this cloud account", in.TTLSeconds, minTTL))
	}
	if in.TTLSeconds > maxTTL {
		return model.Lease{}, errBadRequestAPI(fmt.Sprintf("ttl_seconds %d exceeds the allowed maximum %d", in.TTLSeconds, maxTTL))
	}
	// The refresh window (CONTRACT §17.12): declared, or 8 hours, never above
	// the supervisor's limit and never shorter than one key.
	limit := min(settings.MaxRefreshLifetimeSeconds, model.MaxRefreshLifetimeLimit)
	lifetime := in.MaxLifetimeSeconds
	if lifetime == 0 {
		lifetime = min(model.DefaultRefreshLifetimeSeconds, limit)
	}
	if lifetime > limit {
		return model.Lease{}, errBadRequestAPI(fmt.Sprintf("max_lifetime_seconds %d exceeds the allowed maximum %d", lifetime, limit))
	}
	if lifetime < in.TTLSeconds {
		if in.MaxLifetimeSeconds != 0 {
			return model.Lease{}, errBadRequestAPI("max_lifetime_seconds must be at least ttl_seconds")
		}
		lifetime = in.TTLSeconds
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
		fmt.Sprintf("the agent's owner is %s on cloud account %s", role, accountID))
	if role.Permits(capability.Access) {
		add(ruleOwnerRolePermits, policy.OutcomeAllow,
			fmt.Sprintf("role %s permits %s access", role, permission))
	} else {
		add(ruleOwnerRolePermits, policy.OutcomeDeny,
			fmt.Sprintf("the owner's role %s on this cloud account does not permit %s access", role, permission))
	}
	if violation := policyViolation(capability, params); violation != "" {
		add(policy.RuleIAMProhibited, policy.OutcomeDeny, violation)
	} else {
		add(policy.RuleIAMProhibited, policy.OutcomeAllow, "the policy grants no IAM or RAM management")
	}
	if activeCount >= settings.MaxConcurrentLeasesPerAgent {
		add(policy.RuleConcurrency, policy.OutcomeDeny,
			fmt.Sprintf("%d credentials or requests of this agent are active or waiting; the limit is %d", activeCount, settings.MaxConcurrentLeasesPerAgent))
	}
	if lastMinute >= settings.LeasesPerMinutePerAgent {
		add(policy.RuleRateLimit, policy.OutcomeDeny,
			fmt.Sprintf("%d requests in the last minute; the limit is %d", lastMinute, settings.LeasesPerMinutePerAgent))
	}
	if decision.Outcome != model.OutcomeDeny {
		// What is automatic: the owner's approval mode on this cloud account
		// (§17.11). The role check above already held; a mode never widens it.
		mode, err := s.accountMode(ctx, ag.OwnerID, prov.ID, now)
		if err != nil {
			return model.Lease{}, err
		}
		auditExtra = map[string]any{"approval_mode": string(mode)}
		if permission.Rank() <= mode.Rank() {
			// The detail is shown to the agent, so it does not name the owner's
			// mode; that is in the audit event.
			add(ruleAutomatic, policy.OutcomeAllow, fmt.Sprintf("%s access is issued without approval", permission))
		} else {
			decision.Outcome = model.OutcomeRequireApproval
			add(ruleOwnerApproval, policy.OutcomeRequireApproval, fmt.Sprintf("%s access waits for the owner's approval", permission))
		}
	}

	return s.submitLease(ctx, ag, capability, &prov, decision, auditExtra, model.CreateLeaseInput{
		CapabilityID:       capability.ID,
		Params:             params,
		TTLSeconds:         in.TTLSeconds,
		Reason:             reason,
		MaxLifetimeSeconds: lifetime,
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
		MaxLifetimeSeconds: lease.MaxLifetimeSeconds, RefreshUntil: lease.RefreshUntil, RefreshCount: lease.RefreshCount,
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
		owner, err := s.db.GetPerson(r.Context(), ag.OwnerID)
		if err != nil {
			s.writeHandlerError(w, err)
			return
		}
		bindings, err := s.personBindings(r.Context(), owner)
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
			var highest capcatalog.Permission
			for _, p := range capcatalog.Permissions() {
				if b.Role.Permits(p.Access()) {
					highest = p
				}
			}
			if highest == "" {
				continue // an unknown role allows nothing
			}
			automatic, err := s.accountMode(r.Context(), owner.ID, prov.ID, s.nowUTC())
			if err != nil {
				s.writeHandlerError(w, err)
				return
			}
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
	revoked, err := s.revokeLeaseByPerson(ctx, lease, "revoked by the agent's owner", map[string]any{
		"cause": "owner_revoked", "owner_id": actor.person.ID, "agent_id": ag.ID,
		"caused_by": "person:" + actor.person.ID, "caused_by_username": actor.person.Username,
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
// person's agents. Anything else (missing, someone else's, not an access
// request) is
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

// ---- approval modes per cloud account (CONTRACT §17.11) ----

// maxModeExpiry bounds a temporary approval mode.
const maxModeExpiry = 30 * 24 * time.Hour

// accountMode is a person's approval mode on a cloud account as it applies
// at now: read when none was chosen, it expired, or it is unknown.
func (s *Server) accountMode(ctx context.Context, personID, providerID string, now time.Time) (model.ApprovalMode, error) {
	m, err := s.db.GetAccountMode(ctx, personID, providerID)
	if err != nil {
		return "", err
	}
	return m.Effective(now), nil
}

// handleSetMyAccountMode implements PUT /api/v1/me/accounts/{provider}/mode.
// A person sets only their own mode, on an account where they have a role;
// it applies to all their agents there.
func (s *Server) handleSetMyAccountMode(w http.ResponseWriter, r *http.Request) {
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
	prov, err := s.db.GetProvider(ctx, r.PathValue("provider"))
	if err == nil {
		_, err = s.personRole(ctx, actor.person.ID, prov.ID)
	}
	if err != nil {
		s.storeErrorResponse(w, err, "cloud account not found")
		return
	}
	// A mode above read lets agents get more without asking: it is a
	// standing approval, so a command-line session needs the code.
	if in.Mode != model.ModeRead && !s.stepUp(w, r) {
		return
	}
	now := s.nowUTC()
	var expiresAt *time.Time
	if in.ExpiresInSeconds > 0 && in.Mode != model.ModeRead {
		t := now.Add(time.Duration(in.ExpiresInSeconds) * time.Second)
		expiresAt = &t
	}
	previous, err := s.accountMode(ctx, actor.person.ID, prov.ID, now)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if err := s.db.SetAccountMode(ctx, actor.person.ID, prov.ID, in.Mode, expiresAt, now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "your account is not active, or you no longer have a role on this cloud account")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	severity := "info"
	if in.Mode.Rank() > previous.Rank() {
		severity = "warning"
	}
	metadata := map[string]any{"mode": string(in.Mode), "previous_mode": string(previous),
		"provider_id": prov.ID, "cloud_account_id": prov.CloudAccountID}
	if expiresAt != nil {
		metadata["expires_at"] = expiresAt.Format(time.RFC3339)
	}
	s.personAudit(ctx, actor.person, "person.approval_mode_changed", "ok", severity, "provider", prov.ID, metadata)
	account, ok, err := s.personAccount(ctx, actor.person, prov.ID, now)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if !ok {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "cloud account not found")
		return
	}
	s.writeData(w, http.StatusOK, account)
}

// handleListMyAccounts implements GET /api/v1/me/accounts: the cloud accounts
// the signed-in person has a role on, with their mode and what their agents
// get there. Everyone sees only their own accounts; supervisors manage all of
// them under /supervisor/accounts.
func (s *Server) handleListMyAccounts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	bindings, err := s.personBindings(ctx, actor.person)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	modes, err := s.db.ListAccountModes(ctx, actor.person.ID)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	now := s.nowUTC()
	accounts := make([]model.PersonAccount, 0, len(bindings))
	for _, b := range bindings {
		prov, err := s.db.GetProvider(ctx, b.ProviderID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			s.writeHandlerError(w, err)
			return
		}
		accounts = append(accounts, personAccountView(prov, b.Role, modes[prov.ID], now))
	}
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].Name < accounts[j].Name })
	writeList(s, w, http.StatusOK, accounts, len(accounts))
}

// personAccount is one of the person's cloud accounts as GET /me/accounts
// shows it; ok is false when they have no role there.
func (s *Server) personAccount(ctx context.Context, person model.Person, providerID string, now time.Time) (model.PersonAccount, bool, error) {
	prov, err := s.db.GetProvider(ctx, providerID)
	if errors.Is(err, store.ErrNotFound) {
		return model.PersonAccount{}, false, nil
	}
	if err != nil {
		return model.PersonAccount{}, false, err
	}
	role, err := s.personRole(ctx, person.ID, providerID)
	if errors.Is(err, store.ErrNotFound) {
		return model.PersonAccount{}, false, nil
	}
	if err != nil {
		return model.PersonAccount{}, false, err
	}
	mode, err := s.db.GetAccountMode(ctx, person.ID, providerID)
	if err != nil {
		return model.PersonAccount{}, false, err
	}
	return personAccountView(prov, role, mode, now), true, nil
}

// personAccountView combines an account, the person's role there and their
// mode. An unknown role allows nothing, and a disabled account (or one
// without a cloud account ID) issues nothing: it shows no automatic level
// rather than one requests would not get.
func personAccountView(prov model.Provider, role model.Role, mode model.AccountMode, now time.Time) model.PersonAccount {
	var highest capcatalog.Permission
	for _, p := range capcatalog.Permissions() {
		if role.Permits(p.Access()) {
			highest = p
		}
	}
	effective := mode.Effective(now)
	automatic := effective
	if automatic.Rank() > model.ApprovalMode(highest).Rank() {
		automatic = model.ApprovalMode(highest)
	}
	if prov.Status != model.ProviderActive || prov.CloudAccountID == "" {
		automatic = ""
	}
	view := model.PersonAccount{
		ProviderID: prov.ID, CloudAccountID: prov.CloudAccountID, Name: prov.Name,
		ProviderType: prov.Type, Status: prov.Status, Role: role,
		HighestPermission: string(highest), ApprovalMode: effective, AutomaticUpTo: string(automatic),
	}
	if effective == mode.Mode {
		view.ApprovalModeExpiresAt = mode.ExpiresAt
	}
	return view
}

// personRole is a person's role on one cloud account: an active supervisor is
// Administrator on every account (§17), anyone else has their role binding.
// store.ErrNotFound when the person has no role there.
func (s *Server) personRole(ctx context.Context, personID, providerID string) (model.Role, error) {
	person, err := s.db.GetPerson(ctx, personID)
	if err != nil {
		return "", err
	}
	if person.Supervisor && person.Status == model.PersonActive {
		return model.RoleAdministrator, nil
	}
	binding, err := s.db.GetBinding(ctx, personID, providerID)
	if err != nil {
		return "", err
	}
	return binding.Role, nil
}

// personBindings is every role a person has, one per cloud account. For an
// active supervisor it is Administrator on every cloud account.
func (s *Server) personBindings(ctx context.Context, person model.Person) ([]model.RoleBinding, error) {
	if !person.Supervisor || person.Status != model.PersonActive {
		return s.db.ListBindings(ctx, person.ID, "")
	}
	providers, err := s.db.ListProviders(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]model.RoleBinding, 0, len(providers))
	for _, p := range providers {
		out = append(out, model.RoleBinding{PersonID: person.ID, ProviderID: p.ID, Role: model.RoleAdministrator})
	}
	return out, nil
}

// ---- refresh (CONTRACT §17.12) ----

// refreshInterval is the shortest time between two refreshes of one request.
const refreshInterval = 60 * time.Second

// handleAgentRefreshAccessRequest implements
// POST /api/v1/agent/access-requests/{id}/refresh: a new key under the same
// request, with the same policy, within the request's refresh window.
func (s *Server) handleAgentRefreshAccessRequest(w http.ResponseWriter, r *http.Request) {
	ag, _ := agentFromContext(r.Context())
	lease, err := s.refreshAccessRequest(r.Context(), ag, r.PathValue("id"))
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

func (s *Server) refreshAccessRequest(ctx context.Context, ag model.Agent, id string) (model.Lease, error) {
	notFound := errNotFoundAPI("request not found")
	if !mcp.LeaseIDRE.MatchString(id) {
		return model.Lease{}, notFound
	}
	unlock := s.lockLease(id)
	defer unlock()
	lease, err := s.db.GetLease(ctx, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (lease.AgentID != ag.ID || !capcatalog.IsAccessTemplateID(lease.CapabilityID))) {
		return model.Lease{}, notFound
	}
	if err != nil {
		return model.Lease{}, err
	}
	now := s.nowUTC()
	if lease.Status != model.LeaseActive {
		return model.Lease{}, errConflictAPI("request is " + string(lease.Status) + "; only an active request can be refreshed")
	}
	if lease.ExpiresAt == nil || !lease.ExpiresAt.After(now) {
		return model.Lease{}, errConflictAPI("the credential has expired; make a new request")
	}
	if lease.RefreshUntil == nil {
		return model.Lease{}, errConflictAPI("this request cannot be refreshed; make a new request")
	}
	prov, err := s.db.GetProvider(ctx, lease.ProviderID)
	if errors.Is(err, store.ErrNotFound) {
		return model.Lease{}, errConflictAPI("the cloud account no longer exists")
	}
	if err != nil {
		return model.Lease{}, err
	}
	// The window as stored, cut to the supervisor's current limit, which
	// may have been lowered since the request was issued.
	windowEnd := *lease.RefreshUntil
	if limit := s.refreshLimit(ctx); limit > 0 && lease.IssuedAt != nil {
		if capped := lease.IssuedAt.Add(time.Duration(limit) * time.Second); capped.Before(windowEnd) {
			windowEnd = capped
		}
	}
	ttl := lease.EffectiveTTLSeconds
	if remaining := int(windowEnd.Sub(now) / time.Second); remaining < ttl {
		ttl = remaining
	}
	if ttl < minProviderTTL(prov.Mode) {
		return model.Lease{}, errConflictAPI(fmt.Sprintf("the refresh window ends at %s, too soon for another key; make a new request",
			windowEnd.UTC().Format(time.RFC3339)))
	}
	// One attempt a minute, failed ones included: the attempt is recorded
	// before the cloud is asked.
	if err := s.db.ReserveRefreshAttempt(ctx, lease.ID, now, refreshInterval); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return model.Lease{}, &httpError{status: http.StatusTooManyRequests, code: model.ErrCodeRateLimited,
				message: "this request was refreshed, or a refresh was tried, less than a minute ago"}
		}
		return model.Lease{}, err
	}
	// Every check of a release, but not the approval: a request approved
	// above the mode may be refreshed within its window.
	if problem, err := s.credentialReleaseProblem(ctx, ag.ID, lease.ID); err != nil {
		return model.Lease{}, err
	} else if problem != "" {
		return model.Lease{}, errConflictAPI(problem)
	}
	capability, err := s.capabilityByID(ctx, lease.CapabilityID)
	if err != nil {
		return model.Lease{}, err
	}
	encrypted, fingerprint, _, err := s.mintCredential(ctx, lease, capability, &prov, ttl)
	if err != nil {
		s.agentAudit(ctx, ag, "lease.refresh_failed", "failed", "warning", "lease", lease.ID, map[string]any{
			"reason": sanitizeMessage(err.Error()),
		})
		return model.Lease{}, &httpError{status: http.StatusBadGateway, code: model.ErrCodeProviderError,
			message: "the cloud did not issue a new key: " + sanitizeMessage(err.Error())}
	}
	newExpiry := now.Add(time.Duration(ttl) * time.Second)
	if err := s.db.RefreshLeaseCredential(ctx, lease.ID, encrypted, fingerprint, *lease.ExpiresAt, newExpiry, windowEnd, now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return model.Lease{}, errConflictAPI("the request changed while it was refreshed; check its status")
		}
		return model.Lease{}, err
	}
	// The new key is stored: check again, as at activation, so a revoke or a
	// role change that raced the mint cannot leave it behind.
	if problem, err := s.credentialReleaseProblem(ctx, ag.ID, lease.ID); err != nil || problem != "" {
		if current, gerr := s.db.GetLease(ctx, lease.ID); gerr == nil && current.Status == model.LeaseActive {
			if _, rerr := s.revokeLeaseAsSystem(ctx, current, "no longer authorized at refresh: "+problem); rerr != nil {
				s.logf("lease %s: revoke after refresh: %v", lease.ID, rerr)
			}
		}
		if err != nil {
			return model.Lease{}, err
		}
		return model.Lease{}, errConflictAPI(problem)
	}
	updated, err := s.db.GetLease(ctx, lease.ID)
	if err != nil {
		return model.Lease{}, err
	}
	s.agentAudit(ctx, ag, "lease.refreshed", "ok", "info", "lease", lease.ID, map[string]any{
		"fingerprint": fingerprint, "expires_at": newExpiry.Format(time.RFC3339Nano),
		"refresh_until": windowEnd.UTC().Format(time.RFC3339), "refresh_count": updated.RefreshCount,
	})
	return updated, nil
}
