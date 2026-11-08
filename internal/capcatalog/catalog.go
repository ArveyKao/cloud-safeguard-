// Package capcatalog ships the built-in least-privilege capability catalog and
// renders parameterized IAM policy templates into concrete policy documents.
//
// FROZEN CONTRACT: Builtin, Lookup, RenderPolicy and ValidateParams are
// consumed by the HTTP server (demo seeding, lease minting) and the CLI. The
// agent-toolkit owner implements this package; replace catalog_stub.go. Other
// owners must not edit it.
package capcatalog

import (
	"errors"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// ErrNotImplemented is a placeholder used until the implementation lands.
var ErrNotImplemented = errors.New("capcatalog: not implemented")

// Builtin returns the capability catalog shipped with Cloud Safeguard. IDs are
// stable and documented in docs/CONTRACT.md.
func Builtin() []model.Capability {
	return nil
}

// Lookup returns a built-in capability by ID.
func Lookup(id string) (model.Capability, bool) {
	return model.Capability{}, false
}

// ValidateParams checks that required params are present and that every value
// matches its declared pattern. Unknown params are rejected.
func ValidateParams(cap model.Capability, params map[string]string) error {
	return ErrNotImplemented
}

// RenderPolicy substitutes {{param}} placeholders in the capability's policy
// template, validates that the result is well-formed JSON and returns it.
func RenderPolicy(cap model.Capability, params map[string]string) ([]byte, error) {
	return nil, ErrNotImplemented
}
