package model

import "time"

// Role is a person's role on one cloud account (CONTRACT §17.2). It shares
// the guest < member < administrator ladder with model.AgentRole.
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
	// Supervisor is the platform flag: may manage cloud accounts, people,
	// role bindings and limits, and is Administrator on every cloud account
	// while active (CONTRACT §17.1).
	Supervisor bool `json:"supervisor"`
	// SetupIssued records who issued the setup code the person's current
	// password and authenticator were set up with. Whoever holds a setup
	// code can complete the setup, so this is what traces an account a
	// supervisor might have set up themselves; the console shows it to the
	// person. Nil for accounts set up before it was recorded.
	SetupIssued *SetupIssue `json:"setup_issued,omitempty"`
	LastLoginAt *time.Time  `json:"last_login_at,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
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
	// Kind is "console" or "cli" (CONTRACT §17.9).
	Kind string `json:"kind"`
}

// ---- people on the command line (CONTRACT §17.9) ----

// PersonSignInStartInput begins a command-line sign-in of a person.
type PersonSignInStartInput struct {
	ClientName string `json:"client_name,omitempty"`
}

// PersonSignInResult is the client's poll answer. Token, Person and
// ExpiresAt are set exactly once, when Status is approved.
type PersonSignInResult struct {
	Status    SignInStatus `json:"status"`
	Token     string       `json:"token,omitempty"`
	Person    *Person      `json:"person,omitempty"`
	ExpiresAt *time.Time   `json:"expires_at,omitempty"`
}

// CLISignIn is a pending command-line sign-in as its approver sees it.
type CLISignIn struct {
	UserCode   string       `json:"user_code"`
	ClientName string       `json:"client_name"`
	Status     SignInStatus `json:"status"`
	RemoteAddr string       `json:"remote_addr"`
	CreatedAt  time.Time    `json:"created_at"`
	ExpiresAt  time.Time    `json:"expires_at"`
}

// CLISession is one of a person's command-line sessions.
type CLISession struct {
	ID         string    `json:"id"`
	ClientName string    `json:"client_name"`
	RemoteAddr string    `json:"remote_addr"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	// Current is true for the session the request came with.
	Current bool `json:"current"`
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
	// MaxLifetimeSeconds is how long the agent may keep refreshing the
	// credential, from first issue (CONTRACT §17.12). 0 means the default.
	MaxLifetimeSeconds int `json:"max_lifetime_seconds,omitempty"`
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
	// ExpiresAt is the current key's deadline.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// MaxLifetimeSeconds and RefreshUntil bound refreshes (CONTRACT §17.12);
	// RefreshUntil is set once the first key is issued.
	MaxLifetimeSeconds int        `json:"max_lifetime_seconds"`
	RefreshUntil       *time.Time `json:"refresh_until,omitempty"`
	RefreshCount       int        `json:"refresh_count"`
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
	// for the owner: the lower of the role and the owner's approval mode on
	// this account.
	AutomaticUpTo string   `json:"automatic_up_to"`
	Resources     []string `json:"resources"`
}

// DenyRequestInput is the owner's request body for denying a request.
type DenyRequestInput struct {
	Reason string `json:"reason,omitempty"`
}

// ---- approval modes (CONTRACT §17.11) ----

// ApprovalMode is a permission level used as a threshold: requests at or
// below it on a cloud account are issued automatically.
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

// AccountMode is a person's approval mode on one cloud account. Only that
// person sets it (CONTRACT §17.11).
type AccountMode struct {
	ProviderID string       `json:"provider_id"`
	Mode       ApprovalMode `json:"mode"`
	// ExpiresAt, when set, is when the mode falls back to read.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Effective is the mode at time now: read once it has expired, and read for
// any unknown value, so it can never widen anything.
func (m AccountMode) Effective(now time.Time) ApprovalMode {
	if !m.Mode.Valid() || (m.ExpiresAt != nil && !now.Before(*m.ExpiresAt)) {
		return ModeRead
	}
	return m.Mode
}

// SetApprovalModeInput is the person's request body for choosing a mode.
type SetApprovalModeInput struct {
	Mode ApprovalMode `json:"mode"`
	// ExpiresInSeconds optionally limits a write or full mode; 0 means until
	// changed.
	ExpiresInSeconds int `json:"expires_in_seconds,omitempty"`
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
	// ApprovalMode is the person's mode here as it applies now (read once
	// expired); AutomaticUpTo is what their agents get without asking: the
	// lower of the role and the mode.
	ApprovalMode          ApprovalMode `json:"approval_mode"`
	ApprovalModeExpiresAt *time.Time   `json:"approval_mode_expires_at,omitempty"`
	AutomaticUpTo         string       `json:"automatic_up_to"`
}

// SetupIssue says who issued a person's setup code, how and when.
type SetupIssue struct {
	// ByID is the supervisor's person ID, or "system" for csg commands.
	ByID   string `json:"by_id"`
	ByName string `json:"by_name"`
	// Kind is created, reset, recovered or bootstrap.
	Kind string    `json:"kind"`
	At   time.Time `json:"at"`
}

// Kinds of setup issue.
const (
	SetupCreated   = "created"
	SetupReset     = "reset"
	SetupRecovered = "recovered"
	SetupBootstrap = "bootstrap"
)
