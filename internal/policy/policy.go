// Package policy implements the explainable risk-based policy engine that
// decides whether a capability lease request is auto-approved, requires human
// approval, or is denied.
//
// The semantics are normative (docs/CONTRACT.md §6): rules are evaluated in a
// fixed order and every evaluated rule is recorded as a DecisionReason so the
// CLI and console can explain exactly why a lease was granted or refused.
// Precedence is deny > require_approval > allow.
package policy

import (
	"fmt"
	"strings"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Stable rule keys. These strings are part of the API contract (they appear in
// lease decision reasons and tests assert on them); do not rename.
const (
	RuleCapabilityGranted   = "capability_granted"
	RuleRolePermits         = "role_permits"
	RuleIAMProhibited       = "iam_prohibited"
	RuleCapabilityEnabled   = "capability_enabled"
	RuleProviderAvailable   = "provider_available"
	RuleProviderActive      = "provider_active"
	RuleReasonRequired      = "reason_required"
	RuleBreakGlassRequired  = "break_glass_required"
	RuleTTLWithinCapability = "ttl_within_capability"
	RuleTTLWithinAgent      = "ttl_within_agent"
	RuleTTLWithinGlobal     = "ttl_within_global"
	RuleConcurrency         = "concurrency_available"
	RuleRateLimit           = "rate_limit"
	RuleBreakGlassApproval  = "break_glass_approval"
	RuleAdminApproval       = "admin_requires_approval"
	RuleRiskAboveAuto       = "risk_above_auto"
	RuleTTLAboveAuto        = "ttl_above_auto"
	RuleAutoApprove         = "auto_approve"
)

// DecisionReason outcomes (model.DecisionReason.Outcome).
const (
	OutcomeAllow           = "allow"
	OutcomeRequireApproval = string(model.OutcomeRequireApproval)
	OutcomeDeny            = string(model.OutcomeDeny)
)

// Input is everything the engine needs to decide one lease request.
type Input struct {
	// Agent is the requesting agent (its grants and per-agent limits).
	Agent model.Agent
	// Capability is the capability being requested.
	Capability model.Capability
	// Provider is the provider that would mint the credential; it may be nil
	// when no provider of the capability's provider type exists.
	Provider *model.Provider
	// Settings are the global guardrails.
	Settings model.PolicySettings
	// RequestedTTLSeconds is the requested lease duration; 0 means "use the
	// capability default".
	RequestedTTLSeconds int
	// Reason is the agent's justification.
	Reason string
	// BreakGlass must be true for critical capabilities.
	BreakGlass bool
	// PolicyViolation is non-empty when the capability's rendered IAM policy
	// violates the IAM prohibition (CONTRACT §16.3). It is computed by the
	// server — the policy engine never reaches into the capability catalog — and
	// its value is the human-readable violation used as the rule detail.
	PolicyViolation string
	// ActiveLeaseCount is the number of currently active leases the agent holds.
	ActiveLeaseCount int
	// LeasesCreatedLastMinute is the number of leases the agent created in the
	// last 60 seconds (rate limiting input).
	LeasesCreatedLastMinute int
}

// CandidateTTL returns the effective candidate TTL for a request: the requested
// TTL when positive, otherwise the capability default.
func CandidateTTL(capability model.Capability, requestedTTLSeconds int) int {
	if requestedTTLSeconds > 0 {
		return requestedTTLSeconds
	}
	return capability.DefaultTTLSeconds
}

// Evaluate runs the policy engine and returns an explainable decision.
func Evaluate(in Input) model.PolicyDecision {
	ttl := CandidateTTL(in.Capability, in.RequestedTTLSeconds)

	reasons := make([]model.DecisionReason, 0, 17)
	denied := false
	needsApproval := false

	add := func(rule, outcome, detail string) {
		reasons = append(reasons, model.DecisionReason{Rule: rule, Outcome: outcome, Detail: detail})
		switch outcome {
		case OutcomeDeny:
			denied = true
		case OutcomeRequireApproval:
			needsApproval = true
		}
	}

	// Rule 1: capability_granted
	if grantsContains(in.Agent.Grants, in.Capability.ID) {
		add(RuleCapabilityGranted, OutcomeAllow,
			fmt.Sprintf("capability %s is granted to agent %s", in.Capability.ID, in.Agent.ID))
	} else {
		add(RuleCapabilityGranted, OutcomeDeny,
			fmt.Sprintf("capability %s is not granted to agent %s", in.Capability.ID, in.Agent.ID))
	}

	// Rule 2: role_permits
	if in.Agent.Role.Permits(in.Capability.Access) {
		add(RuleRolePermits, OutcomeAllow,
			fmt.Sprintf("role %s permits %s access required by capability %s",
				in.Agent.Role, in.Capability.Access, in.Capability.ID))
	} else {
		add(RuleRolePermits, OutcomeDeny,
			fmt.Sprintf("role %s does not permit %s access required by capability %s",
				in.Agent.Role, in.Capability.Access, in.Capability.ID))
	}

	// Rule 3: iam_prohibited
	if in.PolicyViolation == "" {
		add(RuleIAMProhibited, OutcomeAllow,
			fmt.Sprintf("capability %s renders a policy that respects the IAM prohibition", in.Capability.ID))
	} else {
		add(RuleIAMProhibited, OutcomeDeny,
			fmt.Sprintf("capability %s renders a prohibited policy: %s", in.Capability.ID, in.PolicyViolation))
	}

	// Rule 4: capability_enabled
	if in.Capability.Enabled {
		add(RuleCapabilityEnabled, OutcomeAllow,
			fmt.Sprintf("capability %s is enabled", in.Capability.ID))
	} else {
		add(RuleCapabilityEnabled, OutcomeDeny,
			fmt.Sprintf("capability %s is disabled", in.Capability.ID))
	}

	// Rule 5: provider_available
	if in.Provider != nil {
		add(RuleProviderAvailable, OutcomeAllow,
			fmt.Sprintf("provider %s available for provider type %s", in.Provider.ID, in.Capability.ProviderType))
	} else {
		add(RuleProviderAvailable, OutcomeDeny,
			fmt.Sprintf("no active provider of type %s exists for capability %s", in.Capability.ProviderType, in.Capability.ID))
	}

	// Rule 6: provider_active
	switch {
	case in.Provider == nil:
		add(RuleProviderActive, OutcomeAllow, "provider status check skipped: no provider available")
	case in.Provider.Status == model.ProviderActive:
		add(RuleProviderActive, OutcomeAllow,
			fmt.Sprintf("provider %s is active", in.Provider.ID))
	default:
		add(RuleProviderActive, OutcomeDeny,
			fmt.Sprintf("provider %s is %s", in.Provider.ID, in.Provider.Status))
	}

	// Rule 7: reason_required
	threshold := in.Settings.RequireReasonForRisk
	switch {
	case strings.TrimSpace(in.Reason) != "":
		add(RuleReasonRequired, OutcomeAllow,
			fmt.Sprintf("reason provided for %s risk request", in.Capability.Risk))
	case in.Capability.Risk.Rank() >= threshold.Rank():
		add(RuleReasonRequired, OutcomeDeny,
			fmt.Sprintf("reason is required for %s risk requests (threshold %s)", in.Capability.Risk, threshold))
	default:
		add(RuleReasonRequired, OutcomeAllow,
			fmt.Sprintf("reason not required for %s risk (threshold %s)", in.Capability.Risk, threshold))
	}

	// Rule 8: break_glass_required
	if in.Capability.Risk == model.RiskCritical {
		if in.BreakGlass {
			add(RuleBreakGlassRequired, OutcomeAllow,
				"break_glass=true provided for critical capability")
		} else {
			add(RuleBreakGlassRequired, OutcomeDeny,
				"critical capability requires break_glass=true")
		}
	} else {
		add(RuleBreakGlassRequired, OutcomeAllow,
			fmt.Sprintf("break-glass flag not required for %s risk", in.Capability.Risk))
	}

	// Rule 9: ttl_within_capability
	if ttl > in.Capability.MaxTTLSeconds {
		add(RuleTTLWithinCapability, OutcomeDeny,
			fmt.Sprintf("requested %ds exceeds capability max %ds", ttl, in.Capability.MaxTTLSeconds))
	} else {
		add(RuleTTLWithinCapability, OutcomeAllow,
			fmt.Sprintf("requested %ds within capability max %ds", ttl, in.Capability.MaxTTLSeconds))
	}

	// Rule 10: ttl_within_agent
	if ttl > in.Agent.MaxTTLSeconds {
		add(RuleTTLWithinAgent, OutcomeDeny,
			fmt.Sprintf("requested %ds exceeds agent max %ds", ttl, in.Agent.MaxTTLSeconds))
	} else {
		add(RuleTTLWithinAgent, OutcomeAllow,
			fmt.Sprintf("requested %ds within agent max %ds", ttl, in.Agent.MaxTTLSeconds))
	}

	// Rule 11: ttl_within_global
	if ttl > in.Settings.MaxLeaseTTLSeconds {
		add(RuleTTLWithinGlobal, OutcomeDeny,
			fmt.Sprintf("requested %ds exceeds global max %ds", ttl, in.Settings.MaxLeaseTTLSeconds))
	} else {
		add(RuleTTLWithinGlobal, OutcomeAllow,
			fmt.Sprintf("requested %ds within global max %ds", ttl, in.Settings.MaxLeaseTTLSeconds))
	}

	// Rule 12: concurrency_available
	concurrencyLimit := in.Settings.MaxConcurrentLeasesPerAgent
	if in.Agent.MaxConcurrentLeases > 0 && in.Agent.MaxConcurrentLeases < concurrencyLimit {
		concurrencyLimit = in.Agent.MaxConcurrentLeases
	}
	if in.ActiveLeaseCount >= concurrencyLimit {
		add(RuleConcurrency, OutcomeDeny,
			fmt.Sprintf("agent holds %d active leases, limit is %d", in.ActiveLeaseCount, concurrencyLimit))
	} else {
		add(RuleConcurrency, OutcomeAllow,
			fmt.Sprintf("agent holds %d active leases, below limit %d", in.ActiveLeaseCount, concurrencyLimit))
	}

	// Rule 13: rate_limit
	rateLimit := in.Settings.LeasesPerMinutePerAgent
	if in.LeasesCreatedLastMinute >= rateLimit {
		add(RuleRateLimit, OutcomeDeny,
			fmt.Sprintf("agent created %d leases in the last 60s, limit is %d", in.LeasesCreatedLastMinute, rateLimit))
	} else {
		add(RuleRateLimit, OutcomeAllow,
			fmt.Sprintf("agent created %d leases in the last 60s, below limit %d", in.LeasesCreatedLastMinute, rateLimit))
	}

	// Rule 14: break_glass_approval
	if in.BreakGlass {
		add(RuleBreakGlassApproval, OutcomeRequireApproval,
			"break-glass requests always require human approval")
	} else {
		add(RuleBreakGlassApproval, OutcomeAllow,
			"human approval not required by break-glass flag")
	}

	// Rule 14b: admin_requires_approval — admin-level access (account-wide,
	// custom or builtin) is never auto-approved, whatever its declared risk.
	if in.Capability.Access == model.AccessAdmin {
		add(RuleAdminApproval, OutcomeRequireApproval,
			"admin-level access always requires human approval")
	} else {
		add(RuleAdminApproval, OutcomeAllow,
			fmt.Sprintf("%s access does not by itself require approval", in.Capability.Access))
	}

	// Rule 15: risk_above_auto
	autoRisk := in.Settings.AutoApproveMaxRisk
	if in.Capability.Risk.Rank() > autoRisk.Rank() {
		add(RuleRiskAboveAuto, OutcomeRequireApproval,
			fmt.Sprintf("risk %s exceeds auto-approve maximum %s", in.Capability.Risk, autoRisk))
	} else {
		add(RuleRiskAboveAuto, OutcomeAllow,
			fmt.Sprintf("risk %s within auto-approve maximum %s", in.Capability.Risk, autoRisk))
	}

	// Rule 16: ttl_above_auto
	if ttl > in.Settings.AutoApproveMaxTTLSeconds {
		add(RuleTTLAboveAuto, OutcomeRequireApproval,
			fmt.Sprintf("requested %ds exceeds auto-approve TTL %ds", ttl, in.Settings.AutoApproveMaxTTLSeconds))
	} else {
		add(RuleTTLAboveAuto, OutcomeAllow,
			fmt.Sprintf("requested %ds within auto-approve TTL %ds", ttl, in.Settings.AutoApproveMaxTTLSeconds))
	}

	// Rule 17: auto_approve — recorded only when nothing blocked the request, so
	// the reason list reads as a clean justification.
	decision := model.OutcomeAutoApprove
	switch {
	case denied:
		decision = model.OutcomeDeny
	case needsApproval:
		decision = model.OutcomeRequireApproval
	default:
		add(RuleAutoApprove, OutcomeAllow,
			fmt.Sprintf("all guardrails satisfied: risk %s, ttl %ds within auto-approve limits", in.Capability.Risk, ttl))
	}

	return model.PolicyDecision{
		Outcome:             decision,
		EffectiveTTLSeconds: ttl,
		Reasons:             reasons,
	}
}

// grantsContains reports whether grants includes capabilityID.
func grantsContains(grants []string, capabilityID string) bool {
	for _, g := range grants {
		if g == capabilityID {
			return true
		}
	}
	return false
}

// DenySummary renders a short human-readable denial reason from a decision.
// It is used for lease.DeniedReason and is never empty for denied decisions.
func DenySummary(decision model.PolicyDecision) string {
	var parts []string
	for _, r := range decision.Reasons {
		if r.Outcome == OutcomeDeny {
			parts = append(parts, r.Rule+": "+r.Detail)
		}
	}
	if len(parts) == 0 {
		return "denied by policy"
	}
	return "denied by policy (" + strings.Join(parts, "; ") + ")"
}
