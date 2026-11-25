// Package policy names the rules and outcomes recorded in an access
// request's decision (docs/CONTRACT.md §17.4), so the CLI and console can
// explain exactly why a request was granted, held for approval or refused.
// Precedence is deny > require_approval > allow.
package policy

import (
	"strings"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Stable rule keys. These strings are part of the API contract (they appear in
// decision reasons and tests assert on them); do not rename.
const (
	RuleIAMProhibited = "iam_prohibited"
	RuleConcurrency   = "concurrency_available"
	RuleRateLimit     = "rate_limit"
)

// DecisionReason outcomes (model.DecisionReason.Outcome).
const (
	OutcomeAllow           = "allow"
	OutcomeRequireApproval = string(model.OutcomeRequireApproval)
	OutcomeDeny            = string(model.OutcomeDeny)
)

// DenySummary renders a short human-readable denial reason from a decision:
// the details of the rules that denied, for the agent and the person to read.
// The rule names stay in decision.Reasons. It is used for lease.DeniedReason
// and is never empty for denied decisions.
func DenySummary(decision model.PolicyDecision) string {
	var parts []string
	for _, r := range decision.Reasons {
		if r.Outcome == OutcomeDeny {
			detail := r.Detail
			if detail == "" {
				detail = r.Rule
			}
			parts = append(parts, detail)
		}
	}
	if len(parts) == 0 {
		return "denied by policy"
	}
	return strings.Join(parts, "; ")
}
