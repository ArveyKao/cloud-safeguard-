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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// ErrInvalidKey is returned when the provided master key is not 32 bytes.
var ErrInvalidKey = errors.New("vault: master key must be 32 bytes")

// ErrDecrypt is returned when a ciphertext cannot be authenticated/decrypted.
var ErrDecrypt = errors.New("vault: cannot decrypt ciphertext")

// ErrNotImplemented is a placeholder used until the implementation lands.
//
// Deprecated: kept for signature compatibility with the frozen base commit.
var ErrNotImplemented = errors.New("vault: not implemented")

// ciphertextPrefix identifies the current ciphertext wire format.
const ciphertextPrefix = "v1:"

// nonceSize is the AES-GCM nonce size used by this package.
const nonceSize = 12

// masterKeySize is the required length of the master key in bytes.
const masterKeySize = 32

// masterKeyEnv is the environment variable that overrides the key file.
const masterKeyEnv = "CSG_MASTER_KEY"

// masterKeyFile is the name of the master key inside the data directory.
const masterKeyFile = "master.key"

// Vault seals and opens secrets with a master key.
type Vault struct {
	key []byte
}

// New validates the 32-byte master key and returns a Vault. The key is copied
// so callers cannot mutate it after construction.
func New(key []byte) (*Vault, error) {
	if len(key) != masterKeySize {
		return nil, ErrInvalidKey
	}
	k := make([]byte, masterKeySize)
	copy(k, key)
	return &Vault{key: k}, nil
}

// LoadOrCreateKey loads <dataDir>/master.key or creates it with 0600
// permissions and 32 random bytes. If CSG_MASTER_KEY is set it takes
// precedence (base64 standard encoding, 32 bytes decoded).
func LoadOrCreateKey(dataDir string) ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv(masterKeyEnv)); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("vault: %s is not valid base64: %w", masterKeyEnv, err)
		}
		if len(key) != masterKeySize {
			return nil, fmt.Errorf("vault: %s decoded to %d bytes: %w", masterKeyEnv, len(key), ErrInvalidKey)
		}
		return key, nil
	}

	path := filepath.Join(dataDir, masterKeyFile)
	key, err := readKeyFile(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}

	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("vault: create data dir: %w", err)
	}
	key = make([]byte, masterKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("vault: generate master key: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			// Another process won the race; read the key it created.
			return readKeyFile(path)
		}
		return nil, fmt.Errorf("vault: create master key: %w", err)
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		return nil, fmt.Errorf("vault: write master key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("vault: write master key: %w", err)
	}
	// Best effort: enforce 0600 even if the process umask relaxed it.
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("vault: set master key permissions: %w", err)
	}
	return key, nil
}

// readKeyFile reads and validates an existing master key file.
func readKeyFile(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(key) != masterKeySize {
		return nil, fmt.Errorf("vault: master key %q is %d bytes: %w", path, len(key), ErrInvalidKey)
	}
	return key, nil
}

// KeyFingerprint returns a non-secret identifier for a master key
// (first 8 bytes of SHA-256, hex). Used in the console vault status.
func KeyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

// DeriveKey deterministically derives a 32-byte subkey for a named purpose
// (HMAC-SHA256(masterKey, "csg/"+purpose)). Used to sign mock STS tokens so the
// mock cloud can validate them without storing another secret.
func DeriveKey(masterKey []byte, purpose string) []byte {
	mac := hmac.New(sha256.New, masterKey)
	mac.Write([]byte("csg/" + purpose))
	return mac.Sum(nil)
}

// Encrypt seals plaintext and returns the "v1:..." string. AAD binds the
// ciphertext to its logical record; decryption with a different AAD fails.
func (v *Vault) Encrypt(plaintext []byte, aad string) (string, error) {
	aead, err := v.aead()
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("vault: generate nonce: %w", err)
	}
	// nonce || ciphertext || tag
	sealed := aead.Seal(nonce, nonce, plaintext, []byte(aad))
	return ciphertextPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Decrypt opens a "v1:..." string and returns the plaintext.
func (v *Vault) Decrypt(ciphertext, aad string) ([]byte, error) {
	if !strings.HasPrefix(ciphertext, ciphertextPrefix) {
		return nil, ErrDecrypt
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(ciphertext, ciphertextPrefix))
	if err != nil {
		return nil, ErrDecrypt
	}
	if len(raw) < nonceSize+16 { // nonce + GCM tag minimum
		return nil, ErrDecrypt
	}
	aead, err := v.aead()
	if err != nil {
		return nil, err
	}
	nonce, sealed := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := aead.Open(nil, nonce, sealed, []byte(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// aead builds the AES-256-GCM primitive for the vault key.
func (v *Vault) aead() (cipher.AEAD, error) {
	if v == nil || len(v.key) != masterKeySize {
		return nil, ErrInvalidKey
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, fmt.Errorf("vault: init aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: init gcm: %w", err)
	}
	return gcm, nil
}
