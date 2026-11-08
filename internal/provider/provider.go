// Package provider converts a scoped policy into short-lived cloud
// credentials.
//
// FROZEN CONTRACT: the Minter interface and MintRequest are consumed by the
// HTTP server and the CLI. The agent-toolkit owner implements "sts" (Alibaba
// Cloud STS AssumeRole) and "mock" (locally signed demo token); replace
// provider_stub.go. Other owners must not edit this package.
package provider

import (
	"context"
	"errors"
	"fmt"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// ErrNotImplemented is a placeholder used until implementations land.
var ErrNotImplemented = errors.New("provider: not implemented")

// MintRequest carries everything needed to mint one lease credential.
type MintRequest struct {
	// LeaseID is embedded in mock tokens and used as audit correlation.
	LeaseID string
	// Provider is the target account configuration (without secrets).
	Provider model.Provider
	// BrokerAccessKeyID / BrokerAccessKeySecret are the decrypted long-lived
	// broker credentials. They are used only inside this call and must never be
	// logged, persisted, or returned to the caller.
	BrokerAccessKeyID     string
	BrokerAccessKeySecret string
	// PolicyJSON is the rendered, least-privilege IAM policy document for this
	// lease (already validated JSON).
	PolicyJSON []byte
	// SessionName is the role-session / correlation name (alphanumeric, <=64
	// chars for Alibaba Cloud).
	SessionName string
	// DurationSeconds is the credential lifetime in seconds.
	DurationSeconds int
	// SigningKey is a 32-byte HMAC key derived from the master key; used by the
	// mock provider only. Real providers ignore it.
	SigningKey []byte
}

// Minter mints short-lived credentials for one scoped request.
type Minter interface {
	// Mint returns a credential valid for DurationSeconds carrying PolicyJSON.
	Mint(ctx context.Context, req MintRequest) (model.Credential, error)
	// Test validates the provider configuration and (for sts mode) the broker
	// credentials, without minting a lease. It should be cheap and non-mutating.
	Test(ctx context.Context, req MintRequest) error
}

// New returns the Minter for a provider mode.
func New(mode model.ProviderMode) (Minter, error) {
	switch mode {
	case model.ModeSTS:
		return stsMinter{}, nil
	case model.ModeMock:
		return mockMinter{}, nil
	default:
		return nil, fmt.Errorf("provider: unsupported mode %q", mode)
	}
}
