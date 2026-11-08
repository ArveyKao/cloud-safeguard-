// Package mockcloud implements the built-in demo cloud used by mock-mode
// providers. It accepts a locally signed short-lived token minted by the mock
// provider and enforces the exact scoped IAM policy carried in that token. It
// exists so the full lease -> credential -> cloud call -> audit loop can be
// demonstrated and tested without any real cloud account.
//
// FROZEN CONTRACT: NewHandler and Deps are consumed by the HTTP server (which
// mounts the handler under /mock-cloud/). The agent-toolkit owner implements
// this package; replace mockcloud_stub.go. Other owners must not edit it.
package mockcloud

import (
	"net/http"

	"github.com/arveykao/cloud-safeguard/internal/store"
)

// Deps is everything the mock cloud needs.
type Deps struct {
	// Store is used to confirm the lease behind a presented token is still
	// active (so revocation is effective immediately) and to append audit
	// events for each cloud API call.
	Store store.Store
	// SigningKey is the 32-byte HMAC key used to validate mock STS tokens
	// (vault.DeriveKey(masterKey, "mock-sts")).
	SigningKey []byte
}

// NewHandler returns the http.Handler for the mock cloud API surface. It must
// be mounted at the path prefix "/mock-cloud/".
func NewHandler(deps Deps) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"mock cloud not implemented"}`, http.StatusNotImplemented)
	})
}
