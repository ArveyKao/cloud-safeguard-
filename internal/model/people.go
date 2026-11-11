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
	Supervisor  bool       `json:"supervisor"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
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
