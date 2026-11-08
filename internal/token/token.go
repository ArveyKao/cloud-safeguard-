// Package token generates and hashes opaque bearer tokens for agent and admin
// identities. Only the SHA-256 hash of a token is ever stored; the plaintext is
// returned exactly once, at creation or rotation time.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// Token prefixes. The prefix lets the CLI and the server route a bearer token
// to the right identity domain without a second lookup.
const (
	AgentPrefix = "csg_agt_"
	AdminPrefix = "csg_adm_"
)

// ErrEntropy is returned when the system random source fails.
var ErrEntropy = errors.New("token: cannot read system randomness")

const entropyBytes = 32

// Generate creates a new token with the given prefix. It returns the plaintext
// token (show once) and the hex SHA-256 hash to persist.
func Generate(prefix string) (plain string, hash string, err error) {
	if prefix != AgentPrefix && prefix != AdminPrefix {
		return "", "", errors.New("token: unknown prefix")
	}
	buf := make([]byte, entropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", ErrEntropy
	}
	plain = prefix + base64.RawURLEncoding.EncodeToString(buf)
	return plain, Hash(plain), nil
}

// Hash returns the lowercase hex SHA-256 hash of a token.
func Hash(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// HashEqual compares two token hashes in constant time.
func HashEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Kind classifies a plaintext token by its prefix: "agent", "admin" or "".
func Kind(plain string) string {
	switch {
	case strings.HasPrefix(plain, AgentPrefix):
		return "agent"
	case strings.HasPrefix(plain, AdminPrefix):
		return "admin"
	default:
		return ""
	}
}

// DisplayPrefix returns the first 12 characters of a token for display in the
// console (e.g. "csg_agt_7f3a"). It never exposes enough of the token to be
// useful.
func DisplayPrefix(plain string) string {
	if len(plain) <= 12 {
		return plain
	}
	return plain[:12]
}
