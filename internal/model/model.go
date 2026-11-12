// Package model holds the shared domain types of Cloud Safeguard.
//
// FROZEN CONTRACT: the API server (core-api), the CLI/providers package
// (agent-toolkit) and the web console all consume these types and their JSON
// tags. Do not rename fields or change JSON tags without coordinating with the
// Lead first. New optional fields may be added; existing ones may not change
// meaning.
package model

import (
	"fmt"
	"regexp"
	"time"
)

const (
	// ProductName is the user-facing product name.
	ProductName = "Cloud Safeguard"
	// Version is the control-plane version reported by the API and CLI.
	Version = "0.1.0"
	// APIVersion is the REST API version prefix.
	APIVersion = "v1"
)

// RiskTier classifies the blast radius of a capability. It drives the
// approval policy: risk tiers at or below the auto-approve threshold are
// granted without human interaction, everything above waits for a human.
type RiskTier string

const (
	RiskLow      RiskTier = "low"
	RiskMedium   RiskTier = "medium"
	RiskHigh     RiskTier = "high"
	RiskCritical RiskTier = "critical"
)

// Valid reports whether the risk tier is one of the known values.
func (r RiskTier) Valid() bool {
	switch r {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
		return true
	}
	return false
}

// Rank maps a risk tier to an ordered integer: low=1, medium=2, high=3,
// critical=4. Unknown tiers rank 0.
func (r RiskTier) Rank() int {
	switch r {
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	case RiskCritical:
		return 4
	}
	return 0
}

// ParseRiskTier parses a risk tier string. It accepts the canonical lowercase
// values only; callers should normalize user input first.
func ParseRiskTier(s string) (RiskTier, bool) {
	r := RiskTier(s)
	return r, r.Valid()
}

// AgentRole is the coarse-grained role of an agent identity (CONTRACT §16.1).
// Roles apply to agents only: the operator/admin token is not a role.
//
// A role permits a set of capability access levels:
//
//	guest         -> read
//	member        -> read, write
//	administrator -> read, write, admin
type AgentRole string

const (
	RoleGuest         AgentRole = "guest"
	RoleMember        AgentRole = "member"
	RoleAdministrator AgentRole = "administrator"
)

// Valid reports whether the role is one of the known values.
func (r AgentRole) Valid() bool {
	switch r {
	case RoleGuest, RoleMember, RoleAdministrator:
		return true
	}
	return false
}

// Rank maps a role to an ordered integer: guest=1, member=2, administrator=3.
// Unknown roles rank 0.
func (r AgentRole) Rank() int {
	switch r {
	case RoleGuest:
		return 1
	case RoleMember:
		return 2
	case RoleAdministrator:
		return 3
	}
	return 0
}

// Permits reports whether the role permits the given capability access level.
// An invalid role or access level never permits anything (fail closed).
func (r AgentRole) Permits(access AccessLevel) bool {
	if !r.Valid() || !access.Valid() {
		return false
	}
	return r.Rank() >= access.Rank()
}

// ParseAgentRole parses a role string. It accepts the canonical lowercase
// values only; callers should normalize user input first.
func ParseAgentRole(s string) (AgentRole, bool) {
	r := AgentRole(s)
	return r, r.Valid()
}

// AgentRoles returns the known roles in ascending order of privilege.
func AgentRoles() []AgentRole { return []AgentRole{RoleGuest, RoleMember, RoleAdministrator} }

// LowestRolePermitting returns the least privileged role that permits every
// given access level. It returns guest for an empty list, and false when an
// access level is invalid (no role can cover it).
func LowestRolePermitting(accesses []AccessLevel) (AgentRole, bool) {
	role := RoleGuest
	for _, a := range accesses {
		if !a.Valid() {
			return RoleGuest, false
		}
		for _, candidate := range AgentRoles() {
			if candidate.Permits(a) {
				if candidate.Rank() > role.Rank() {
					role = candidate
				}
				break
			}
		}
	}
	return role, true
}

// AccessLevel is the kind of cloud access a capability grants (CONTRACT §16.1).
type AccessLevel string

const (
	AccessRead  AccessLevel = "read"
	AccessWrite AccessLevel = "write"
	AccessAdmin AccessLevel = "admin"
)

// Valid reports whether the access level is one of the known values.
func (a AccessLevel) Valid() bool {
	switch a {
	case AccessRead, AccessWrite, AccessAdmin:
		return true
	}
	return false
}

// Rank maps an access level to an ordered integer: read=1, write=2, admin=3.
// Unknown levels rank 0.
func (a AccessLevel) Rank() int {
	switch a {
	case AccessRead:
		return 1
	case AccessWrite:
		return 2
	case AccessAdmin:
		return 3
	}
	return 0
}

// ParseAccessLevel parses an access level string. It accepts the canonical
// lowercase values only; callers should normalize user input first.
func ParseAccessLevel(s string) (AccessLevel, bool) {
	a := AccessLevel(s)
	return a, a.Valid()
}

// ProviderType is the cloud vendor family of a provider.
type ProviderType string

const (
	ProviderAliyun ProviderType = "aliyun"
)

// Valid reports whether the provider type is supported.
func (p ProviderType) Valid() bool { return p == ProviderAliyun }

// ProviderMode selects how a provider mints short-lived credentials.
//
//   - sts:  call the real cloud STS AssumeRole API (requires a RAM role and a
//     broker AccessKey with sts:AssumeRole permission).
//   - mock: mint a locally signed, self-contained short-lived token against the
//     built-in mock cloud. No network, no real credentials. Used for demos,
//     tests and local evaluation.
type ProviderMode string

const (
	ModeSTS  ProviderMode = "sts"
	ModeMock ProviderMode = "mock"
)

// Valid reports whether the provider mode is supported.
func (m ProviderMode) Valid() bool { return m == ModeSTS || m == ModeMock }

// ProviderStatus is the lifecycle state of a provider.
type ProviderStatus string

const (
	ProviderActive   ProviderStatus = "active"
	ProviderDisabled ProviderStatus = "disabled"
)

// Provider is a cloud account wired into Cloud Safeguard. The broker
// AccessKey/Secret pair is stored encrypted in the vault and is never returned
// by the API; only a masked display form is exposed.
type Provider struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Type is the cloud vendor family, e.g. "aliyun".
	Type ProviderType `json:"type"`
	// Mode is "sts" for a real cloud account or "mock" for the built-in demo
	// cloud.
	Mode ProviderMode `json:"mode"`
	// Region is the default region used for STS calls and audit metadata.
	Region string `json:"region"`
	// RoleARN is the RAM role assumed when minting credentials (sts mode).
	RoleARN string `json:"role_arn,omitempty"`
	// CloudAccountID is the cloud's own account ID (for Alibaba Cloud the
	// numeric UID), taken from RoleARN when the provider is created. It never
	// changes afterwards and is unique across providers; access requests
	// name the account by it (CONTRACT §17.2). Empty when unknown: such a
	// provider cannot serve access requests.
	CloudAccountID string `json:"cloud_account_id,omitempty"`
	// MaxAutoLevel is the highest permission that may be issued on this
	// cloud account without the owner's approval, whatever a person's
	// approval mode is (CONTRACT §17.5). A supervisor sets it; default read.
	MaxAutoLevel ApprovalMode `json:"max_auto_level"`
	// AccessKeyIDMasked is a display-only form such as "LTAI****9f2c". The raw
	// broker AccessKey ID is never returned by the API.
	AccessKeyIDMasked string         `json:"access_key_id_masked"`
	Status            ProviderStatus `json:"status"`
	// LastTestedAt / LastTestOK report the most recent connection test.
	LastTestedAt *time.Time `json:"last_tested_at,omitempty"`
	LastTestOK   *bool      `json:"last_test_ok,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// CreateProviderInput is the admin request body for POST /admin/providers.
type CreateProviderInput struct {
	Name            string       `json:"name"`
	Type            ProviderType `json:"type"`
	Mode            ProviderMode `json:"mode"`
	Region          string       `json:"region"`
	RoleARN         string       `json:"role_arn,omitempty"`
	AccessKeyID     string       `json:"access_key_id"`
	AccessKeySecret string       `json:"access_key_secret"`
}

// UpdateProviderInput is the admin request body for PATCH /admin/providers/{id}.
// Nil fields are left unchanged.
type UpdateProviderInput struct {
	Name    *string         `json:"name,omitempty"`
	Region  *string         `json:"region,omitempty"`
	RoleARN *string         `json:"role_arn,omitempty"`
	Status  *ProviderStatus `json:"status,omitempty"`
}

// RotateProviderCredentialInput rotates the broker AccessKey/Secret pair.
type RotateProviderCredentialInput struct {
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
}

// CapabilityParam describes one parameter of a parameterized capability.
type CapabilityParam struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	// Pattern is an optional RE2 regular expression the value must match.
	Pattern string `json:"pattern,omitempty"`
}

// Capability is a named, least-privilege cloud permission bundle. Agents are
// granted capabilities (not credentials); a lease renders a capability's
// policy template against request parameters and asks the provider for a
// short-lived credential carrying exactly that policy.
type Capability struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	// ProviderType must match the leased provider's Type.
	ProviderType ProviderType `json:"provider_type"`
	Risk         RiskTier     `json:"risk"`
	// Access is the kind of cloud access this capability grants. It gates which
	// agent roles may request it (CONTRACT §16.1) and how strictly the IAM
	// prohibition inspects the rendered policy (§16.3).
	Access AccessLevel `json:"access"`
	// PolicyTemplate is a JSON IAM policy document that may contain
	// {{placeholder}} references to capability params, e.g.
	// "acs:alidns:*:*:domain/{{domain}}".
	PolicyTemplate string `json:"policy_template"`
	// Params declares placeholders used by PolicyTemplate and validated on every
	// lease request.
	Params []CapabilityParam `json:"params"`
	// DefaultTTLSeconds applies when a request omits ttl_seconds.
	DefaultTTLSeconds int `json:"default_ttl_seconds"`
	// MaxTTLSeconds is the absolute ceiling for a lease of this capability.
	MaxTTLSeconds int `json:"max_ttl_seconds"`
	// Enabled=false blocks new leases for this capability.
	Enabled bool `json:"enabled"`
	// Builtin marks capabilities shipped with the product.
	Builtin   bool      `json:"builtin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AgentStatus is the lifecycle state of an agent identity.
type AgentStatus string

const (
	AgentActive    AgentStatus = "active"
	AgentSuspended AgentStatus = "suspended"
	AgentRevoked   AgentStatus = "revoked"
)

// Agent is a non-human identity (an AI agent or automation runner) that can
// request capability leases. The bearer token itself is only ever returned
// once, at creation or rotation time.
type Agent struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Status      AgentStatus `json:"status"`
	// Role is the agent's role. It bounds which capability access levels the
	// agent may hold and request (CONTRACT §16.1).
	Role AgentRole `json:"role"`
	// Grants are capability IDs this agent may request. They are always a subset
	// of the capabilities the role permits.
	Grants []string `json:"grants"`
	// MaxTTLSeconds caps any single lease this agent may hold.
	MaxTTLSeconds int `json:"max_ttl_seconds"`
	// MaxConcurrentLeases caps simultaneously active leases.
	MaxConcurrentLeases int `json:"max_concurrent_leases"`
	// OwnerID is the person this agent belongs to (CONTRACT §17.1). It is set
	// when the agent signs in and never changes. It is empty for agents
	// created through the legacy admin API (§16), which stays available
	// until §17 replaces it; those agents are not tied to any person.
	OwnerID string `json:"owner_id,omitempty"`
	// TokenPrefix is a display-only hint (e.g. "csg_agt_7f3a").
	TokenPrefix string     `json:"token_prefix"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// CreateAgentInput is the admin request body for POST /admin/agents.
type CreateAgentInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Role is optional and defaults to guest.
	Role AgentRole `json:"role,omitempty"`
	// Grants is optional: omitted or empty means "every enabled capability the
	// role permits at creation time".
	Grants              []string `json:"grants"`
	MaxTTLSeconds       int      `json:"max_ttl_seconds"`
	MaxConcurrentLeases int      `json:"max_concurrent_leases"`
}

// UpdateAgentInput is the admin request body for PATCH /admin/agents/{id}.
type UpdateAgentInput struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	// Role changes the agent's role. Without grants, a role change resets the
	// grants to every enabled capability the new role permits, and revokes the
	// agent's pending/active leases the new role no longer permits.
	Role                *AgentRole   `json:"role,omitempty"`
	Grants              *[]string    `json:"grants,omitempty"`
	MaxTTLSeconds       *int         `json:"max_ttl_seconds,omitempty"`
	MaxConcurrentLeases *int         `json:"max_concurrent_leases,omitempty"`
	Status              *AgentStatus `json:"status,omitempty"`
}

// AgentWithToken is returned exactly once when an agent is created or its
// token is rotated.
type AgentWithToken struct {
	Agent Agent  `json:"agent"`
	Token string `json:"token"`
}

// LeaseStatus is the lifecycle state of a lease request.
type LeaseStatus string

const (
	// LeasePending waits for a human decision.
	LeasePending LeaseStatus = "pending"
	// LeaseActive owns a minted, unexpired credential.
	LeaseActive LeaseStatus = "active"
	// LeaseDenied was refused by policy or by a human.
	LeaseDenied LeaseStatus = "denied"
	// LeaseExpired ran past its TTL or approval window.
	LeaseExpired LeaseStatus = "expired"
	// LeaseRevoked was killed by an agent or admin before its TTL.
	LeaseRevoked LeaseStatus = "revoked"
	// LeaseFailed could not mint credentials (provider error).
	LeaseFailed LeaseStatus = "failed"
)

// Valid reports whether the lease status is known.
func (s LeaseStatus) Valid() bool {
	switch s {
	case LeasePending, LeaseActive, LeaseDenied, LeaseExpired, LeaseRevoked, LeaseFailed:
		return true
	}
	return false
}

// DecisionOutcome is the policy engine verdict for a lease request.
type DecisionOutcome string

const (
	// OutcomeAutoApprove grants the lease without human interaction.
	OutcomeAutoApprove DecisionOutcome = "auto_approve"
	// OutcomeRequireApproval parks the lease in the approval queue.
	OutcomeRequireApproval DecisionOutcome = "require_approval"
	// OutcomeDeny rejects the lease immediately.
	OutcomeDeny DecisionOutcome = "deny"
)

// DecisionReason is one explainable rule evaluation recorded on a lease.
type DecisionReason struct {
	// Rule is a stable machine-readable rule name, e.g. "ttl_within_capability".
	Rule string `json:"rule"`
	// Outcome is "allow", "require_approval" or "deny".
	Outcome string `json:"outcome"`
	// Detail is a human-readable explanation shown in the console and CLI.
	Detail string `json:"detail"`
}

// PolicyDecision is the explainable result of the policy engine.
type PolicyDecision struct {
	Outcome             DecisionOutcome  `json:"outcome"`
	EffectiveTTLSeconds int              `json:"effective_ttl_seconds"`
	Reasons             []DecisionReason `json:"reasons"`
}

// Lease is the central object of the platform: one time-boxed request for a
// scoped cloud credential. Credentials are never embedded in a Lease; they are
// stored encrypted server-side and fetched through a dedicated endpoint while
// the lease is active.
type Lease struct {
	ID             string       `json:"id"`
	AgentID        string       `json:"agent_id"`
	AgentName      string       `json:"agent_name"`
	CapabilityID   string       `json:"capability_id"`
	CapabilityName string       `json:"capability_name"`
	ProviderID     string       `json:"provider_id"`
	ProviderName   string       `json:"provider_name"`
	ProviderMode   ProviderMode `json:"provider_mode"`
	Risk           RiskTier     `json:"risk"`
	// Params are the validated capability parameters, e.g. {"domain":"example.com"}.
	Params map[string]string `json:"params,omitempty"`
	// Reason is the agent's stated justification.
	Reason              string         `json:"reason"`
	RequestedTTLSeconds int            `json:"requested_ttl_seconds"`
	EffectiveTTLSeconds int            `json:"effective_ttl_seconds"`
	Status              LeaseStatus    `json:"status"`
	Decision            PolicyDecision `json:"decision"`
	BreakGlass          bool           `json:"break_glass"`
	// ApprovedBy is "auto", an admin actor label, or empty.
	ApprovedBy    string `json:"approved_by,omitempty"`
	ApprovalNote  string `json:"approval_note,omitempty"`
	DeniedReason  string `json:"denied_reason,omitempty"`
	RevokeReason  string `json:"revoke_reason,omitempty"`
	FailureReason string `json:"failure_reason,omitempty"`
	// SessionName is the STS role-session name (aliyun mode) or the mock
	// session name, used for tracing in the cloud provider's audit trail.
	SessionName string `json:"session_name"`
	// CredentialAvailable is true while a fetchable credential exists.
	CredentialAvailable bool `json:"credential_available"`
	// CredentialFingerprint is a non-secret masked hint, e.g. "AKID****9f2c".
	CredentialFingerprint string     `json:"credential_fingerprint,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	ApprovedAt            *time.Time `json:"approved_at,omitempty"`
	IssuedAt              *time.Time `json:"issued_at,omitempty"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"`
	RevokedAt             *time.Time `json:"revoked_at,omitempty"`
}

// CreateLeaseInput is the agent request body for POST /agent/leases.
type CreateLeaseInput struct {
	CapabilityID string            `json:"capability_id"`
	Params       map[string]string `json:"params,omitempty"`
	// TTLSeconds 0 means "use the capability default".
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Reason     string `json:"reason,omitempty"`
	// BreakGlass must be true to request a critical capability; it forces human
	// approval and critical-severity audit.
	BreakGlass bool `json:"break_glass,omitempty"`
}

// ApproveLeaseInput is the admin request body for POST /admin/leases/{id}/approve.
type ApproveLeaseInput struct {
	// TTLSeconds 0 means "use the lease's requested/effective TTL".
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Note       string `json:"note,omitempty"`
}

// DenyLeaseInput is the admin request body for POST /admin/leases/{id}/deny.
type DenyLeaseInput struct {
	Reason string `json:"reason"`
}

// RevokeLeaseInput is the request body for lease revocation (agent or admin).
type RevokeLeaseInput struct {
	Reason string `json:"reason"`
}

// Credential is a short-lived cloud credential minted for a lease. It must
// never be persisted in plaintext or logged.
type Credential struct {
	ProviderID      string       `json:"provider_id"`
	ProviderMode    ProviderMode `json:"provider_mode"`
	LeaseID         string       `json:"lease_id"`
	AccessKeyID     string       `json:"access_key_id"`
	AccessKeySecret string       `json:"access_key_secret"`
	SecurityToken   string       `json:"security_token"`
	ExpiresAt       time.Time    `json:"expires_at"`
}

// EnvVar is a ready-to-use environment variable injected by `csg exec`.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CredentialEnvelope is the agent-facing credential payload returned by
// POST /agent/leases/{id}/credential. It contains a credential plus the exact
// environment variables Alibaba Cloud CLIs/SDKs expect, so agents never need
// to know how to convert credentials themselves.
type CredentialEnvelope struct {
	Credential Credential `json:"credential"`
	// Env contains ALIBABA_CLOUD_ACCESS_KEY_ID, ALIBABA_CLOUD_ACCESS_KEY_SECRET,
	// ALIBABA_CLOUD_SECURITY_TOKEN, plus CSG_LEASE_ID / CSG_SERVER.
	Env []EnvVar `json:"env"`
}

// AuditEvent is one tamper-evident entry in the append-only audit log.
type AuditEvent struct {
	Seq        int64          `json:"seq"`
	ID         string         `json:"id"`
	Time       time.Time      `json:"time"`
	ActorType  string         `json:"actor_type"` // agent | admin | system
	ActorID    string         `json:"actor_id"`
	ActorName  string         `json:"actor_name"`
	Action     string         `json:"action"`
	Status     string         `json:"status"`   // ok | denied | failed
	Severity   string         `json:"severity"` // info | warning | critical
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	PrevHash   string         `json:"prev_hash"`
	Hash       string         `json:"hash"`
}

// AuditVerifyResult is returned by GET /admin/audit/verify.
type AuditVerifyResult struct {
	OK              bool   `json:"ok"`
	Events          int64  `json:"events"`
	FirstInvalidSeq int64  `json:"first_invalid_seq,omitempty"`
	Message         string `json:"message"`
}

// PolicySettings are the global guardrails that drive auto-approval. They are
// editable from the console.
type PolicySettings struct {
	// AutoApproveMaxRisk: requests whose capability risk is <= this tier and
	// whose TTL is <= AutoApproveMaxTTLSeconds are granted automatically.
	AutoApproveMaxRisk RiskTier `json:"auto_approve_max_risk"`
	// AutoApproveMaxTTLSeconds caps the TTL of an automatically granted lease.
	AutoApproveMaxTTLSeconds int `json:"auto_approve_max_ttl_seconds"`
	// MaxLeaseTTLSeconds is the absolute TTL ceiling for any lease.
	MaxLeaseTTLSeconds int `json:"max_lease_ttl_seconds"`
	// PendingTimeoutSeconds is how long a pending request survives before it
	// expires without a decision.
	PendingTimeoutSeconds int `json:"pending_timeout_seconds"`
	// MaxConcurrentLeasesPerAgent caps simultaneously active leases.
	MaxConcurrentLeasesPerAgent int `json:"max_concurrent_leases_per_agent"`
	// LeasesPerMinutePerAgent rate-limits lease creation per agent.
	LeasesPerMinutePerAgent int `json:"leases_per_minute_per_agent"`
	// RequireReasonForRisk requires a non-empty reason at or above this tier.
	RequireReasonForRisk RiskTier `json:"require_reason_for_risk"`
}

// DefaultPolicySettings returns the shipped guardrails: read-only requests are
// auto-approved for up to 15 minutes; everything else needs a human; the hard
// ceiling is one hour.
func DefaultPolicySettings() PolicySettings {
	return PolicySettings{
		AutoApproveMaxRisk:          RiskLow,
		AutoApproveMaxTTLSeconds:    900,
		MaxLeaseTTLSeconds:          3600,
		PendingTimeoutSeconds:       600,
		MaxConcurrentLeasesPerAgent: 3,
		LeasesPerMinutePerAgent:     6,
		RequireReasonForRisk:        RiskMedium,
	}
}

// Validate checks the policy settings for obviously invalid combinations.
func (p PolicySettings) Validate() error {
	if !p.AutoApproveMaxRisk.Valid() {
		return fmt.Errorf("auto_approve_max_risk: unknown risk tier %q", p.AutoApproveMaxRisk)
	}
	if !p.RequireReasonForRisk.Valid() {
		return fmt.Errorf("require_reason_for_risk: unknown risk tier %q", p.RequireReasonForRisk)
	}
	if p.AutoApproveMaxTTLSeconds <= 0 {
		return fmt.Errorf("auto_approve_max_ttl_seconds must be positive")
	}
	if p.MaxLeaseTTLSeconds < p.AutoApproveMaxTTLSeconds {
		return fmt.Errorf("max_lease_ttl_seconds must be >= auto_approve_max_ttl_seconds")
	}
	if p.PendingTimeoutSeconds <= 0 {
		return fmt.Errorf("pending_timeout_seconds must be positive")
	}
	if p.MaxConcurrentLeasesPerAgent <= 0 {
		return fmt.Errorf("max_concurrent_leases_per_agent must be positive")
	}
	if p.LeasesPerMinutePerAgent <= 0 {
		return fmt.Errorf("leases_per_minute_per_agent must be positive")
	}
	return nil
}

// OverviewCounts are the headline numbers on the console dashboard.
type OverviewCounts struct {
	Agents          int `json:"agents"`
	ActiveAgents    int `json:"active_agents"`
	Capabilities    int `json:"capabilities"`
	Providers       int `json:"providers"`
	ActiveLeases    int `json:"active_leases"`
	PendingLeases   int `json:"pending_leases"`
	Events24h       int `json:"events_24h"`
	DeniedLeases24h int `json:"denied_leases_24h"`
}

// RiskBreakdown counts active+pending leases by risk tier.
type RiskBreakdown struct {
	Low      int `json:"low"`
	Medium   int `json:"medium"`
	High     int `json:"high"`
	Critical int `json:"critical"`
}

// VaultStatus is a non-secret view of the credential vault.
type VaultStatus struct {
	Configured     bool   `json:"configured"`
	KeyFingerprint string `json:"key_fingerprint"`
	SecretsStored  int    `json:"secrets_stored"`
}

// Overview is returned by GET /admin/overview for the dashboard.
type Overview struct {
	Counts        OverviewCounts `json:"counts"`
	RiskBreakdown RiskBreakdown  `json:"risk_breakdown"`
	Policy        PolicySettings `json:"policy"`
	Vault         VaultStatus    `json:"vault"`
	PendingLeases []Lease        `json:"pending_leases"`
	ActiveLeases  []Lease        `json:"active_leases"`
	RecentEvents  []AuditEvent   `json:"recent_events"`
	Providers     []Provider     `json:"providers"`
	Version       string         `json:"version"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	ServerTime    time.Time      `json:"server_time"`
}

// LoginResult is returned by POST /admin/login.
type LoginResult struct {
	OK      bool   `json:"ok"`
	Role    string `json:"role"` // "admin"
	Version string `json:"version"`
}

// Health is returned by GET /healthz.
type Health struct {
	Status  string    `json:"status"`
	Version string    `json:"version"`
	Name    string    `json:"name"`
	Time    time.Time `json:"time"`
}

// ListResponse is the standard envelope for collection endpoints.
type ListResponse[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

// ErrorDetail is one machine-readable API error.
type ErrorDetail struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// ErrorBody is the standard error envelope: {"error": {...}}.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// Stable API error codes used by the control plane and consumed by the CLI and
// the web console.
const (
	ErrCodeInvalidRequest        = "invalid_request"
	ErrCodeUnauthorized          = "unauthorized"
	ErrCodeForbidden             = "forbidden"
	ErrCodeNotFound              = "not_found"
	ErrCodeConflict              = "conflict"
	ErrCodeRateLimited           = "rate_limited"
	ErrCodeInternal              = "internal"
	ErrCodeLeaseNotActive        = "lease_not_active"
	ErrCodeCredentialUnavailable = "credential_unavailable"
	ErrCodeProviderError         = "provider_error"
	ErrCodePolicyDenied          = "policy_denied"
)

var aliyunRoleARN = regexp.MustCompile(`^acs:ram::([0-9]{6,32}):role/[A-Za-z0-9._/-]+$`)

// CloudAccountIDFromRoleARN extracts the cloud account ID from a role ARN,
// or returns "" when the ARN does not have the provider type's form.
func CloudAccountIDFromRoleARN(t ProviderType, roleARN string) string {
	if t != ProviderAliyun {
		return ""
	}
	if m := aliyunRoleARN.FindStringSubmatch(roleARN); m != nil {
		return m[1]
	}
	return ""
}
