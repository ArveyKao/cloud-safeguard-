package policy

import (
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

func baseSettings() model.PolicySettings { return model.DefaultPolicySettings() }

func baseAgent() model.Agent {
	return model.Agent{
		ID:                  "agt_test",
		Name:                "test-agent",
		Status:              model.AgentActive,
		Grants:              []string{"cap.read", "cap.medium", "cap.high", "cap.critical"},
		MaxTTLSeconds:       1800,
		MaxConcurrentLeases: 3,
	}
}

func baseCapability() model.Capability {
	return model.Capability{
		ID:                "cap.read",
		Name:              "Read",
		ProviderType:      model.ProviderAliyun,
		Risk:              model.RiskLow,
		PolicyTemplate:    `{"Version":"1"}`,
		DefaultTTLSeconds: 900,
		MaxTTLSeconds:     1800,
		Enabled:           true,
	}
}

func baseProvider() *model.Provider {
	return &model.Provider{
		ID:     "prv_test",
		Name:   "test-provider",
		Type:   model.ProviderAliyun,
		Mode:   model.ModeMock,
		Region: "cn-hangzhou",
		Status: model.ProviderActive,
	}
}

func baseInput() Input {
	return Input{
		Agent:                   baseAgent(),
		Capability:              baseCapability(),
		Provider:                baseProvider(),
		Settings:                baseSettings(),
		RequestedTTLSeconds:     0,
		Reason:                  "automated read-only inventory refresh",
		BreakGlass:              false,
		ActiveLeaseCount:        0,
		LeasesCreatedLastMinute: 0,
	}
}

// reasonFor returns the decision reason for a rule key.
func reasonFor(t *testing.T, d model.PolicyDecision, rule string) model.DecisionReason {
	t.Helper()
	for _, r := range d.Reasons {
		if r.Rule == rule {
			return r
		}
	}
	t.Fatalf("decision has no reason for rule %q (reasons: %v)", rule, d.Reasons)
	return model.DecisionReason{}
}

func TestEvaluateRules(t *testing.T) {
	tests := []struct {
		name string
		// mutate adjusts the base input.
		mutate func(*Input)
		// wantDecision is the expected final outcome.
		wantDecision model.DecisionOutcome
		// wantTTL is the expected EffectiveTTLSeconds (0 means "900, the capability default").
		wantTTL int
		// wantRules maps rule key -> expected outcome for rules that must be present.
		wantRules map[string]string
		// wantDetail contains substrings expected in the named rule's detail.
		wantDetail map[string][]string
	}{
		{
			name:         "auto approve baseline low risk read",
			mutate:       func(*Input) {},
			wantDecision: model.OutcomeAutoApprove,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleCapabilityGranted:   OutcomeAllow,
				RuleCapabilityEnabled:   OutcomeAllow,
				RuleProviderAvailable:   OutcomeAllow,
				RuleProviderActive:      OutcomeAllow,
				RuleReasonRequired:      OutcomeAllow,
				RuleBreakGlassRequired:  OutcomeAllow,
				RuleTTLWithinCapability: OutcomeAllow,
				RuleTTLWithinAgent:      OutcomeAllow,
				RuleTTLWithinGlobal:     OutcomeAllow,
				RuleConcurrency:         OutcomeAllow,
				RuleRateLimit:           OutcomeAllow,
				RuleBreakGlassApproval:  OutcomeAllow,
				RuleRiskAboveAuto:       OutcomeAllow,
				RuleTTLAboveAuto:        OutcomeAllow,
				RuleAutoApprove:         OutcomeAllow,
			},
			wantDetail: map[string][]string{
				RuleTTLWithinCapability: {"900", "1800"},
				RuleAutoApprove:         {"low", "900"},
			},
		},
		{
			name: "capability not granted denies",
			mutate: func(in *Input) {
				in.Capability = anotherCapability("cap.not-granted")
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleCapabilityGranted: OutcomeDeny,
			},
			wantDetail: map[string][]string{
				RuleCapabilityGranted: {"cap.not-granted", "agt_test"},
			},
		},
		{
			name: "capability disabled denies",
			mutate: func(in *Input) {
				in.Capability.Enabled = false
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleCapabilityEnabled: OutcomeDeny,
			},
		},
		{
			name: "missing provider denies provider_available",
			mutate: func(in *Input) {
				in.Provider = nil
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleProviderAvailable: OutcomeDeny,
			},
			wantDetail: map[string][]string{
				RuleProviderAvailable: {"aliyun"},
			},
		},
		{
			name: "disabled provider denies provider_active",
			mutate: func(in *Input) {
				in.Provider.Status = model.ProviderDisabled
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleProviderActive: OutcomeDeny,
			},
		},
		{
			name: "missing reason for medium risk denies",
			mutate: func(in *Input) {
				in.Capability = mediumCapability()
				in.Reason = "   "
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleReasonRequired: OutcomeDeny,
			},
			wantDetail: map[string][]string{
				RuleReasonRequired: {"medium"},
			},
		},
		{
			name: "low risk does not require a reason",
			mutate: func(in *Input) {
				in.Reason = ""
			},
			wantDecision: model.OutcomeAutoApprove,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleReasonRequired: OutcomeAllow,
			},
		},
		{
			name: "critical without break-glass denies",
			mutate: func(in *Input) {
				in.Capability = criticalCapability()
				in.BreakGlass = false
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleBreakGlassRequired: OutcomeDeny,
			},
		},
		{
			name: "critical with break-glass requires approval",
			mutate: func(in *Input) {
				in.Capability = criticalCapability()
				in.BreakGlass = true
			},
			wantDecision: model.OutcomeRequireApproval,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleBreakGlassRequired: OutcomeAllow,
				RuleBreakGlassApproval: OutcomeRequireApproval,
				RuleRiskAboveAuto:      OutcomeRequireApproval,
			},
			wantDetail: map[string][]string{
				RuleBreakGlassApproval: {"break-glass", "human approval"},
			},
		},
		{
			name: "break-glass flag forces approval even for medium risk",
			mutate: func(in *Input) {
				in.Capability = mediumCapability()
				in.BreakGlass = true
			},
			wantDecision: model.OutcomeRequireApproval,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleBreakGlassRequired: OutcomeAllow,
				RuleBreakGlassApproval: OutcomeRequireApproval,
				RuleRiskAboveAuto:      OutcomeRequireApproval,
			},
		},
		{
			name: "ttl above capability max denies",
			mutate: func(in *Input) {
				in.RequestedTTLSeconds = 3600 // agent/global also allow 3600? agent max 1800 -> also denies
				in.Agent.MaxTTLSeconds = 3600
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      3600,
			wantRules: map[string]string{
				RuleTTLWithinCapability: OutcomeDeny,
			},
			wantDetail: map[string][]string{
				RuleTTLWithinCapability: {"3600", "1800"},
			},
		},
		{
			name: "ttl above agent max denies",
			mutate: func(in *Input) {
				in.RequestedTTLSeconds = 1200
				in.Agent.MaxTTLSeconds = 600
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      1200,
			wantRules: map[string]string{
				RuleTTLWithinCapability: OutcomeAllow,
				RuleTTLWithinAgent:      OutcomeDeny,
			},
			wantDetail: map[string][]string{
				RuleTTLWithinAgent: {"1200", "600"},
			},
		},
		{
			name: "ttl above global max denies",
			mutate: func(in *Input) {
				in.Settings.MaxLeaseTTLSeconds = 1200
				in.Settings.AutoApproveMaxTTLSeconds = 900
				in.RequestedTTLSeconds = 1201
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      1201,
			wantRules: map[string]string{
				RuleTTLWithinGlobal: OutcomeDeny,
			},
			wantDetail: map[string][]string{
				RuleTTLWithinGlobal: {"1201", "1200"},
			},
		},
		{
			name: "concurrency at limit denies",
			mutate: func(in *Input) {
				in.ActiveLeaseCount = 3
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleConcurrency: OutcomeDeny,
			},
		},
		{
			name: "concurrency uses tighter agent limit",
			mutate: func(in *Input) {
				in.Agent.MaxConcurrentLeases = 1
				in.ActiveLeaseCount = 1
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleConcurrency: OutcomeDeny,
			},
			wantDetail: map[string][]string{
				RuleConcurrency: {"limit is 1"},
			},
		},
		{
			name: "rate limit reached denies",
			mutate: func(in *Input) {
				in.LeasesCreatedLastMinute = 6
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleRateLimit: OutcomeDeny,
			},
			wantDetail: map[string][]string{
				RuleRateLimit: {"6", "60s"},
			},
		},
		{
			name: "rate below limit allows",
			mutate: func(in *Input) {
				in.LeasesCreatedLastMinute = 5
			},
			wantDecision: model.OutcomeAutoApprove,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleRateLimit: OutcomeAllow,
			},
		},
		{
			name: "medium risk above auto threshold requires approval",
			mutate: func(in *Input) {
				in.Capability = mediumCapability()
			},
			wantDecision: model.OutcomeRequireApproval,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleRiskAboveAuto: OutcomeRequireApproval,
			},
			wantDetail: map[string][]string{
				RuleRiskAboveAuto: {"medium", "low"},
			},
		},
		{
			name: "ttl above auto threshold requires approval",
			mutate: func(in *Input) {
				in.RequestedTTLSeconds = 1200 // within cap/agent/global maxima
			},
			wantDecision: model.OutcomeRequireApproval,
			wantTTL:      1200,
			wantRules: map[string]string{
				RuleTTLAboveAuto: OutcomeRequireApproval,
			},
			wantDetail: map[string][]string{
				RuleTTLAboveAuto: {"1200", "900"},
			},
		},
		{
			name: "deny beats require approval",
			mutate: func(in *Input) {
				// Missing grant (deny) + medium risk with no reason (deny) +
				// TTL above auto (require): final decision must be deny.
				in.Capability = mediumCapability()
				in.Capability.ID = "cap.not-granted"
				in.Reason = ""
				in.RequestedTTLSeconds = 1200
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      1200,
			wantRules: map[string]string{
				RuleCapabilityGranted: OutcomeDeny,
				RuleRiskAboveAuto:     OutcomeRequireApproval,
				RuleTTLAboveAuto:      OutcomeRequireApproval,
			},
		},
		{
			name: "requested ttl overrides capability default",
			mutate: func(in *Input) {
				in.RequestedTTLSeconds = 240
			},
			wantDecision: model.OutcomeAutoApprove,
			wantTTL:      240,
			wantRules: map[string]string{
				RuleAutoApprove: OutcomeAllow,
			},
		},
		{
			name: "effective ttl is candidate even when denied",
			mutate: func(in *Input) {
				in.Capability.Enabled = false
				in.RequestedTTLSeconds = 777
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      777,
			wantRules: map[string]string{
				RuleCapabilityEnabled: OutcomeDeny,
			},
		},
		{
			name: "tighter auto policy settings change the outcome",
			mutate: func(in *Input) {
				in.Settings.AutoApproveMaxTTLSeconds = 300
			},
			wantDecision: model.OutcomeRequireApproval,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleTTLAboveAuto: OutcomeRequireApproval,
			},
		},
		{
			name: "global settings max caps an otherwise valid request",
			mutate: func(in *Input) {
				in.Settings.MaxLeaseTTLSeconds = 600
				in.Settings.AutoApproveMaxTTLSeconds = 300
			},
			wantDecision: model.OutcomeDeny,
			wantTTL:      900,
			wantRules: map[string]string{
				RuleTTLWithinGlobal: OutcomeDeny,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := baseInput()
			tt.mutate(&in)
			got := Evaluate(in)

			if got.Outcome != tt.wantDecision {
				t.Fatalf("outcome = %q, want %q (reasons: %v)", got.Outcome, tt.wantDecision, got.Reasons)
			}
			if got.EffectiveTTLSeconds != tt.wantTTL {
				t.Errorf("EffectiveTTLSeconds = %d, want %d", got.EffectiveTTLSeconds, tt.wantTTL)
			}
			for rule, wantOutcome := range tt.wantRules {
				r := reasonFor(t, got, rule)
				if r.Outcome != wantOutcome {
					t.Errorf("rule %s outcome = %q, want %q (detail: %q)", rule, r.Outcome, wantOutcome, r.Detail)
				}
				if r.Detail == "" {
					t.Errorf("rule %s has an empty detail", rule)
				}
			}
			for rule, substrings := range tt.wantDetail {
				r := reasonFor(t, got, rule)
				for _, want := range substrings {
					if !strings.Contains(r.Detail, want) {
						t.Errorf("rule %s detail %q does not contain %q", rule, r.Detail, want)
					}
				}
			}
		})
	}
}

func TestEvaluateRecordsEveryRule(t *testing.T) {
	d := Evaluate(baseInput())
	if d.Outcome != model.OutcomeAutoApprove {
		t.Fatalf("baseline outcome = %q, want auto_approve", d.Outcome)
	}
	if len(d.Reasons) != 15 {
		t.Fatalf("len(Reasons) = %d, want 15 (14 guardrails + auto_approve)", len(d.Reasons))
	}
	seen := make(map[string]bool, len(d.Reasons))
	for _, r := range d.Reasons {
		if seen[r.Rule] {
			t.Errorf("rule %q appears more than once", r.Rule)
		}
		seen[r.Rule] = true
	}
	wantRules := []string{
		RuleCapabilityGranted, RuleCapabilityEnabled, RuleProviderAvailable,
		RuleProviderActive, RuleReasonRequired, RuleBreakGlassRequired,
		RuleTTLWithinCapability, RuleTTLWithinAgent, RuleTTLWithinGlobal,
		RuleConcurrency, RuleRateLimit, RuleBreakGlassApproval,
		RuleRiskAboveAuto, RuleTTLAboveAuto, RuleAutoApprove,
	}
	for _, rule := range wantRules {
		if !seen[rule] {
			t.Errorf("rule %q missing from reasons", rule)
		}
	}
}

func TestEvaluateRuleOrderIsStable(t *testing.T) {
	d := Evaluate(baseInput())
	want := []string{
		RuleCapabilityGranted, RuleCapabilityEnabled, RuleProviderAvailable,
		RuleProviderActive, RuleReasonRequired, RuleBreakGlassRequired,
		RuleTTLWithinCapability, RuleTTLWithinAgent, RuleTTLWithinGlobal,
		RuleConcurrency, RuleRateLimit, RuleBreakGlassApproval,
		RuleRiskAboveAuto, RuleTTLAboveAuto, RuleAutoApprove,
	}
	if len(d.Reasons) != len(want) {
		t.Fatalf("len(Reasons) = %d, want %d", len(d.Reasons), len(want))
	}
	for i, rule := range want {
		if d.Reasons[i].Rule != rule {
			t.Fatalf("reason[%d].Rule = %q, want %q", i, d.Reasons[i].Rule, rule)
		}
	}
}

func TestEvaluateNoAutoApproveReasonWhenBlocked(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*Input)
	}{
		{"denied", func(in *Input) { in.Capability.Enabled = false }},
		{"requires approval", func(in *Input) { in.Capability = mediumCapability() }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := baseInput()
			tt.mutate(&in)
			d := Evaluate(in)
			for _, r := range d.Reasons {
				if r.Rule == RuleAutoApprove {
					t.Fatalf("blocked decision (%s) must not contain an auto_approve allow reason", d.Outcome)
				}
			}
		})
	}
}

func TestCandidateTTL(t *testing.T) {
	c := baseCapability()
	tests := []struct {
		requested int
		want      int
	}{
		{0, 900},
		{-5, 900}, // negative is validated before policy, but the derivation is defensive
		{240, 240},
		{1800, 1800},
	}
	for _, tt := range tests {
		if got := CandidateTTL(c, tt.requested); got != tt.want {
			t.Errorf("CandidateTTL(requested=%d) = %d, want %d", tt.requested, got, tt.want)
		}
	}
}

func TestDenySummary(t *testing.T) {
	in := baseInput()
	in.Capability.Enabled = false
	d := Evaluate(in)
	if d.Outcome != model.OutcomeDeny {
		t.Fatalf("outcome = %q, want deny", d.Outcome)
	}
	summary := DenySummary(d)
	if !strings.Contains(summary, RuleCapabilityEnabled) {
		t.Fatalf("DenySummary = %q, want it to name the %s rule", summary, RuleCapabilityEnabled)
	}
	if !strings.Contains(summary, "disabled") {
		t.Fatalf("DenySummary = %q, want it to include the rule detail", summary)
	}
	if got := DenySummary(model.PolicyDecision{Outcome: model.OutcomeDeny}); got != "denied by policy" {
		t.Fatalf("DenySummary(empty) = %q", got)
	}
}

func anotherCapability(id string) model.Capability {
	c := baseCapability()
	c.ID = id
	c.Name = "Another"
	return c
}

func mediumCapability() model.Capability {
	c := baseCapability()
	c.ID = "cap.medium"
	c.Name = "Manage DNS"
	c.Risk = model.RiskMedium
	return c
}

func criticalCapability() model.Capability {
	c := baseCapability()
	c.ID = "cap.critical"
	c.Name = "Break glass"
	c.Risk = model.RiskCritical
	return c
}
