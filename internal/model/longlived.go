package model

import "time"

// Long-lived credentials (CONTRACT §17.14): a cloud user with an access key
// that does not expire, created only after a person confirms in the console.

// LongLivedStatus is the state of a long-lived credential.
type LongLivedStatus string

const (
	// LongLivedPending: asked, waiting for the person to confirm.
	LongLivedPending LongLivedStatus = "pending"
	// LongLivedCreating: being created in the cloud.
	LongLivedCreating LongLivedStatus = "creating"
	// LongLivedActive: the cloud user and key exist.
	LongLivedActive LongLivedStatus = "active"
	// LongLivedDenied: the person declined.
	LongLivedDenied LongLivedStatus = "denied"
	// LongLivedExpired: nobody confirmed within the hour.
	LongLivedExpired LongLivedStatus = "expired"
	// LongLivedFailed: creating failed; anything created was deleted.
	LongLivedFailed LongLivedStatus = "failed"
	// LongLivedRevoking: being deleted in the cloud.
	LongLivedRevoking LongLivedStatus = "revoking"
	// LongLivedRevoked: the key, policy and user are deleted.
	LongLivedRevoked LongLivedStatus = "revoked"
	// LongLivedRevokeFailed: a deletion failed; the key may still exist.
	LongLivedRevokeFailed LongLivedStatus = "revoke_failed"
)

// LongLivedCredential is one long-lived credential as stored and shown. It
// never holds the secret.
type LongLivedCredential struct {
	ID               string          `json:"id"`
	ProviderID       string          `json:"provider_id"`
	CloudAccountID   string          `json:"cloud_account_id"`
	CloudAccountName string          `json:"cloud_account_name"`
	ProviderType     ProviderType    `json:"provider_type"`
	OwnerID          string          `json:"owner_id"`
	OwnerName        string          `json:"owner_name,omitempty"`
	AgentID          string          `json:"agent_id,omitempty"`
	AgentName        string          `json:"agent_name,omitempty"`
	CapabilityID     string          `json:"capability_id"`
	Resource         string          `json:"resource"`
	Permission       string          `json:"permission"`
	ResourceName     string          `json:"resource_name,omitempty"`
	Reason           string          `json:"reason"`
	Status           LongLivedStatus `json:"status"`
	CloudUser        string          `json:"cloud_user,omitempty"`
	CloudPolicy      string          `json:"cloud_policy,omitempty"`
	AccessKeyID      string          `json:"access_key_id,omitempty"`
	FailureReason    string          `json:"failure_reason,omitempty"`
	RevokeReason     string          `json:"revoke_reason,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	ExpiresAt        time.Time       `json:"expires_at"`
	DecidedAt        *time.Time      `json:"decided_at,omitempty"`
	RevokedAt        *time.Time      `json:"revoked_at,omitempty"`
}

// LongLivedRequestInput asks for a long-lived credential.
type LongLivedRequestInput struct {
	CloudAccountID string `json:"cloud_account_id"`
	Resource       string `json:"resource"`
	Permission     string `json:"permission"`
	ResourceName   string `json:"resource_name,omitempty"`
	Reason         string `json:"reason"`
}

// LongLivedRequestResult is the answer to a request: only a console link.
type LongLivedRequestResult struct {
	ID        string          `json:"id"`
	Status    LongLivedStatus `json:"status"`
	Link      string          `json:"link"`
	ExpiresAt time.Time       `json:"expires_at"`
}

// LongLivedSecret is the one answer that carries the secret, to the person
// who confirmed, once.
type LongLivedSecret struct {
	Credential      LongLivedCredential `json:"credential"`
	AccessKeyID     string              `json:"access_key_id"`
	AccessKeySecret string              `json:"access_key_secret"`
	Env             []EnvVar            `json:"env"`
}

// SetUserAdminKeyInput is the supervisor's body for enabling long-lived
// credentials on a cloud account.
type SetUserAdminKeyInput struct {
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
}
