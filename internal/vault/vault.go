// Package vault implements the envelope encryption used to protect cloud
// AccessKey/Secret pairs and short-lived credentials at rest.
//
// FROZEN CONTRACT: signatures below are consumed by the HTTP server, the CLI
// bootstrap and the mock cloud. The core-api owner implements the real crypto
// (replace vault_stub.go). Other owners must not edit this package.
//
// Format guarantees:
//   - AES-256-GCM with a random 12-byte nonce per ciphertext.
//   - Ciphertext serialized as "v1:" + base64.RawStdEncoding(nonce||ciphertext||tag).
//   - Callers pass a non-secret AAD string that binds a secret to its record,
//     e.g. "provider/prv_ab12/credential" or "lease/lea_cd34/credential".
//   - The master key is 32 random bytes, stored in <dataDir>/master.key with
//     mode 0600, or supplied via CSG_MASTER_KEY (base64 standard encoding).
package vault

import (
	"errors"
)

// ErrInvalidKey is returned when the provided master key is not 32 bytes.
var ErrInvalidKey = errors.New("vault: master key must be 32 bytes")

// ErrDecrypt is returned when a ciphertext cannot be authenticated/decrypted.
var ErrDecrypt = errors.New("vault: cannot decrypt ciphertext")

// ErrNotImplemented is a placeholder used until the implementation lands.
var ErrNotImplemented = errors.New("vault: not implemented")

// Vault seals and opens secrets with a master key.
type Vault struct {
	key []byte
}

// New validates the 32-byte master key and returns a Vault.
func New(key []byte) (*Vault, error) {
	return nil, ErrNotImplemented
}

// LoadOrCreateKey loads <dataDir>/master.key or creates it with 0600
// permissions and 32 random bytes. If CSG_MASTER_KEY is set it takes
// precedence (base64 standard encoding, 32 bytes decoded).
func LoadOrCreateKey(dataDir string) ([]byte, error) {
	return nil, ErrNotImplemented
}

// KeyFingerprint returns a non-secret identifier for a master key
// (first 8 bytes of SHA-256, hex). Used in the console vault status.
func KeyFingerprint(key []byte) string {
	return ""
}

// DeriveKey deterministically derives a 32-byte subkey for a named purpose
// (HMAC-SHA256(masterKey, "csg/"+purpose)). Used to sign mock STS tokens so the
// mock cloud can validate them without storing another secret.
func DeriveKey(masterKey []byte, purpose string) []byte {
	return nil
}

// Encrypt seals plaintext and returns the "v1:..." string.
func (v *Vault) Encrypt(plaintext []byte, aad string) (string, error) {
	return "", ErrNotImplemented
}

// Decrypt opens a "v1:..." string and returns the plaintext.
func (v *Vault) Decrypt(ciphertext, aad string) ([]byte, error) {
	return nil, ErrNotImplemented
}
