// Package server implements the Cloud Safeguard control plane: the REST API
// consumed by the agent CLI and the web console, the embedded dashboard, and
// the background lease sweeper.
//
// FROZEN CONTRACT: Config, Server, New, Handler, ListenAndServe, Addr, Close,
// InitOptions, InitResult, InitAgent and Init are consumed by the CLI. The
// core-api owner implements this package; replace server_stub.go and add files.
// Other owners must not edit it.
package server

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
)

// ErrNotImplemented is a placeholder used until the implementation lands.
var ErrNotImplemented = errors.New("server: not implemented")

// Config configures the control plane.
type Config struct {
	// Addr is the listen address, e.g. "127.0.0.1:8787".
	Addr string
	// DataDir holds the SQLite database, master.key and runtime files.
	DataDir string
	// MasterKey optionally overrides the master key loaded from DataDir.
	MasterKey []byte
	// Version overrides the reported version (default model.Version).
	Version string
	// MinterFactory optionally overrides provider minters (tests inject fakes).
	// When nil the server uses provider.New(provider.Mode).
	MinterFactory func(p model.Provider) (provider.Minter, error)
	// Now optionally overrides the clock (tests use a fixed clock).
	Now func() time.Time
}

// Server is a running control-plane instance.
type Server struct{}

// New opens the store, loads the vault and builds the HTTP handler. It does not
// bind a socket.
func New(cfg Config) (*Server, error) {
	return nil, ErrNotImplemented
}

// Handler returns the fully routed HTTP handler (API, mock cloud, dashboard).
func (s *Server) Handler() http.Handler { return http.NotFoundHandler() }

// ListenAndServe binds Config.Addr and serves until ctx is cancelled, then
// shuts down gracefully. Addr() reports the effective address after binding.
func (s *Server) ListenAndServe(ctx context.Context) error { return ErrNotImplemented }

// Addr reports the bound listen address ("127.0.0.1:8787"), or the configured
// address before binding.
func (s *Server) Addr() string { return "" }

// Close releases the store and stops background workers.
func (s *Server) Close() error { return nil }

// InitOptions configures first-run bootstrap.
type InitOptions struct {
	// DataDir is created if missing.
	DataDir string
	// Demo seeds the mock cloud provider, demo agents and built-in
	// capabilities, making the product immediately demoable.
	Demo bool
	// Force allows re-initializing an existing data directory (rotates the
	// admin token). Off by default: Init refuses to touch an existing install.
	Force bool
	// MasterKey optionally supplies the master key instead of generating one.
	MasterKey []byte
}

// InitAgent is one demo agent created by Init with its one-time token.
type InitAgent struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

// InitResult summarizes a bootstrap. AdminToken and agent Tokens are shown
// exactly once and are never retrievable again.
type InitResult struct {
	DataDir          string      `json:"data_dir"`
	AdminToken       string      `json:"admin_token"`
	AdminTokenPrefix string      `json:"admin_token_prefix"`
	ProviderIDs      []string    `json:"provider_ids"`
	CapabilityIDs    []string    `json:"capability_ids"`
	Agents           []InitAgent `json:"agents"`
}

// Init bootstraps a new data directory: master key, database, admin token,
// built-in capabilities, and (with Demo) the mock provider plus demo agents.
func Init(ctx context.Context, opts InitOptions) (InitResult, error) {
	return InitResult{}, ErrNotImplemented
}
