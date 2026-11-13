package model

import "time"

// Role is a person's role on one cloud account (CONTRACT §17.2). It shares
// the guest < member < administrator ladder with the §16 agent role.
type Role = AgentRole

// PersonStatus is the lifecycle state of a human account.
type PersonStatus string

const (
	// PersonPending has a setup code but no password or TOTP yet.
	PersonPending   PersonStatus = "pending"
	PersonActive    PersonStatus = "active"
	PersonSuspended PersonStatus = "suspended"
)

// Valid reports whether the status is one of the known values.
func (s PersonStatus) Valid() bool {
	switch s {
	case PersonPending, PersonActive, PersonSuspended:
		return true
	}
	return false
}

// Person is a human account (CONTRACT §17.1). Password hashes, TOTP secrets
// and setup codes are never part of this type.
type Person struct {
	ID          string       `json:"id"`
	Username    string       `json:"username"`
	DisplayName string       `json:"display_name"`
	Status      PersonStatus `json:"status"`
	// Supervisor is the platform flag: may manage cloud accounts, people and
	// role bindings. It grants no cloud access.
	Supervisor bool `json:"supervisor"`
	// ApprovalMode is the level up to which this person's agents get access
	// without asking (CONTRACT §17.5). Only the person sets it.
	ApprovalMode ApprovalMode `json:"approval_mode"`
	// ApprovalModeExpiresAt, when set, is when the mode falls back to read.
	ApprovalModeExpiresAt *time.Time `json:"approval_mode_expires_at,omitempty"`
	LastLoginAt           *time.Time `json:"last_login_at,omitempty"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// RoleBinding gives one person a role on one cloud account.
type RoleBinding struct {
	PersonID string `json:"person_id"`
	// ProviderID is the internal ID of the cloud account (provider).
	ProviderID string    `json:"provider_id"`
	Role       Role      `json:"role"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// CreatePersonInput is the supervisor request body for creating a person.
type CreatePersonInput struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Supervisor  bool   `json:"supervisor,omitempty"`
}

// PersonWithSetupCode is returned exactly once when a person is created or
// reset. The setup code lets that person choose a password and enrol TOTP.
type PersonWithSetupCode struct {
	Person         Person    `json:"person"`
	SetupCode      string    `json:"setup_code"`
	SetupExpiresAt time.Time `json:"setup_expires_at"`
}

// UpdatePersonInput is the supervisor request body for changing a person.
// Nil fields are left unchanged. Status accepts active or suspended only.
type UpdatePersonInput struct {
	DisplayName *string       `json:"display_name,omitempty"`
	Status      *PersonStatus `json:"status,omitempty"`
	Supervisor  *bool         `json:"supervisor,omitempty"`
}

// PutBindingInput is the supervisor request body for setting a role binding.
type PutBindingInput struct {
	Role Role `json:"role"`
}

// SetupBeginInput starts account setup: the person proves the setup code and
// chooses a password.
type SetupBeginInput struct {
	SetupCode string `json:"setup_code"`
	Password  string `json:"password"`
}

// SetupBeginResult carries the TOTP secret to load into an authenticator app.
type SetupBeginResult struct {
	Username   string `json:"username"`
	TOTPSecret string `json:"totp_secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

// SetupFinishInput completes setup by proving the authenticator works.
type SetupFinishInput struct {
	SetupCode string `json:"setup_code"`
	TOTPCode  string `json:"totp_code"`
}

// PersonLoginInput is the request body for POST /auth/login.
type PersonLoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code"`
}

// SessionInfo describes the signed-in person. CSRFToken must be sent in the
// X-CSRF-Token header of every state-changing request.
type SessionInfo struct {
	Person    Person        `json:"person"`
	Bindings  []RoleBinding `json:"bindings"`
	CSRFToken string        `json:"csrf_token"`
	ExpiresAt time.Time     `json:"expires_at"`
}

// ---- agent-first sign-in (CONTRACT §17.3 item 2) ----

// SignInStatus is the state of an agent sign-in.
type SignInStatus string

const (
	SignInPending  SignInStatus = "pending"
	SignInApproved SignInStatus = "approved"
	SignInDenied   SignInStatus = "denied"
	// SignInConsumed: the agent collected its token. Stored only; the API
	// reports it as expired.
	SignInConsumed SignInStatus = "consumed"
	// SignInExpired also covers a sign-in whose token was already collected.
	SignInExpired SignInStatus = "expired"
)

// AgentSignInStartInput is the agent's request to begin signing in.
type AgentSignInStartInput struct {
	AgentName   string `json:"agent_name"`
	Description string `json:"description,omitempty"`
}

// AgentSignInStart is returned to the agent. DeviceCode is a secret the
// agent keeps and polls with; UserCode is what the agent shows its human.
type AgentSignInStart struct {
	DeviceCode      string    `json:"device_code"`
	UserCode        string    `json:"user_code"`
	VerificationURL string    `json:"verification_url"`
	ExpiresAt       time.Time `json:"expires_at"`
	IntervalSeconds int       `json:"interval_seconds"`
}

// AgentSignIn is what a person sees before approving or denying.
type AgentSignIn struct {
	UserCode    string       `json:"user_code"`
	AgentName   string       `json:"agent_name"`
	Description string       `json:"description"`
	Status      SignInStatus `json:"status"`
	// RemoteAddr is where the sign-in was started from.
	RemoteAddr string    `json:"remote_addr"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// AgentSignInTokenInput is the agent's poll for the outcome.
type AgentSignInTokenInput struct {
	DeviceCode string `json:"device_code"`
}

// AgentSignInResult is the poll answer. Agent and Token are set exactly once,
// when Status is approved; the token is never retrievable again.
type AgentSignInResult struct {
	Status SignInStatus `json:"status"`
	Agent  *Agent       `json:"agent,omitempty"`
	Token  string       `json:"token,omitempty"`
}

// ---- access requests (CONTRACT §17.4, §17.5) ----

// AccessRequestInput is the agent's request for short-lived access. All
// fields except ResourceName are required; Reason is required for write and
// full.
type AccessRequestInput struct {
	// CloudAccountID is the cloud's own account ID.
	CloudAccountID string `json:"cloud_account_id"`
	// Resource is a resource type: ecs, dns, oss.
	Resource string `json:"resource"`
	// Permission is read, write or full.
	Permission string `json:"permission"`
	// TTLSeconds is the validity period. There is no default.
	TTLSeconds int `json:"ttl_seconds"`
	// ResourceName narrows the request to one resource; empty means all
	// resources of that type in the account.
	ResourceName string `json:"resource_name,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// AccessRequest is an access request as shown to the agent and to its owner.
// Its ID is also the lease ID used to fetch or revoke the credential.
type AccessRequest struct {
	ID               string `json:"id"`
	AgentID          string `json:"agent_id"`
	AgentName        string `json:"agent_name"`
	OwnerID          string `json:"owner_id"`
	CloudAccountID   string `json:"cloud_account_id"`
	CloudAccountName string `json:"cloud_account_name"`
	Resource         string `json:"resource"`
	Permission       string `json:"permission"`
	// ResourceName is empty when the request covers all resources.
	ResourceName        string         `json:"resource_name,omitempty"`
	TTLSeconds          int            `json:"ttl_seconds"`
	Reason              string         `json:"reason"`
	Status              LeaseStatus    `json:"status"`
	Decision            PolicyDecision `json:"decision"`
	DeniedReason        string         `json:"denied_reason,omitempty"`
	RevokeReason        string         `json:"revoke_reason,omitempty"`
	FailureReason       string         `json:"failure_reason,omitempty"`
	ApprovedBy          string         `json:"approved_by,omitempty"`
	CredentialAvailable bool           `json:"credential_available"`
	CreatedAt           time.Time      `json:"created_at"`
	ApprovedAt          *time.Time     `json:"approved_at,omitempty"`
	IssuedAt            *time.Time     `json:"issued_at,omitempty"`
	// ExpiresAt is the credential's deadline: issue time + TTLSeconds.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// AgentAccount is one cloud account an agent may ask for, with the role it
// inherits from its owner there.
type AgentAccount struct {
	CloudAccountID string       `json:"cloud_account_id"`
	Name           string       `json:"name"`
	ProviderType   ProviderType `json:"provider_type"`
	Role           Role         `json:"role"`
	// HighestPermission is the highest permission the role allows.
	HighestPermission string `json:"highest_permission"`
	// AutomaticUpTo is the highest permission issued here without waiting
	// for the owner: the lowest of the role, the owner's approval mode and
	// the account's highest automatic level.
	AutomaticUpTo string   `json:"automatic_up_to"`
	Resources     []string `json:"resources"`
}

// DenyRequestInput is the owner's request body for denying a request.
type DenyRequestInput struct {
	Reason string `json:"reason,omitempty"`
}

// ---- approval modes (CONTRACT §17.5) ----

// ApprovalMode is a permission level used as a threshold: requests at or
// below it are issued automatically. It is also used for a cloud account's
// highest automatic level.
type ApprovalMode string

const (
	ModeRead  ApprovalMode = "read"
	ModeWrite ApprovalMode = "write"
	ModeFull  ApprovalMode = "full"
)

// Rank orders modes: read=1, write=2, full=3. Unknown values rank 0, so an
// unknown mode never makes anything automatic.
func (m ApprovalMode) Rank() int {
	switch m {
	case ModeRead:
		return 1
	case ModeWrite:
		return 2
	case ModeFull:
		return 3
	}
	return 0
}

// Valid reports whether m is a known mode.
func (m ApprovalMode) Valid() bool { return m.Rank() > 0 }

// EffectiveApprovalMode is the person's mode at time now: read once a mode
// has expired, and read for any unknown value.
func (p Person) EffectiveApprovalMode(now time.Time) ApprovalMode {
	if !p.ApprovalMode.Valid() {
		return ModeRead
	}
	if p.ApprovalModeExpiresAt != nil && !now.Before(*p.ApprovalModeExpiresAt) {
		return ModeRead
	}
	return p.ApprovalMode
}

// SetApprovalModeInput is the person's request body for choosing a mode.
type SetApprovalModeInput struct {
	Mode ApprovalMode `json:"mode"`
	// ExpiresInSeconds optionally limits a write or full mode; 0 means until
	// changed.
	ExpiresInSeconds int `json:"expires_in_seconds,omitempty"`
}

// SetAutoLevelInput is the supervisor's request body for a cloud account's
// highest automatic level.
type SetAutoLevelInput struct {
	MaxAutoLevel ApprovalMode `json:"max_auto_level"`
}

// AsOf returns p as it applies at time now: an expired or unknown mode is
// shown as read, without its stale expiry. Every API response uses it, so
// what people see is what decides their agents' requests.
func (p Person) AsOf(now time.Time) Person {
	effective := p.EffectiveApprovalMode(now)
	if effective != p.ApprovalMode {
		p.ApprovalMode = effective
		p.ApprovalModeExpiresAt = nil
	}
	return p
}

// PersonAccount is one cloud account a person has a role on, as shown to
// that person in the console.
type PersonAccount struct {
	ProviderID     string         `json:"provider_id"`
	CloudAccountID string         `json:"cloud_account_id"`
	Name           string         `json:"name"`
	ProviderType   ProviderType   `json:"provider_type"`
	Status         ProviderStatus `json:"status"`
	Role           Role           `json:"role"`
	// HighestPermission is the highest permission the role allows.
	HighestPermission string `json:"highest_permission"`
	// MaxAutoLevel is the account's highest automatic level (set by a
	// supervisor); AutomaticUpTo is what the person's agents get without
	// asking here: the lowest of role, mode and level.
	MaxAutoLevel  ApprovalMode `json:"max_auto_level"`
	AutomaticUpTo string       `json:"automatic_up_to"`
}
