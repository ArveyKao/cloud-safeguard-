// Package token generates and hashes opaque bearer tokens for agent and admin
// identities. Only the SHA-256 hash of a token is ever stored; the plaintext is
// returned exactly once, at creation or rotation time.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// AgentPrefix starts every agent token, the only bearer token there is.
// People sign in with a password and an authenticator code instead.
const AgentPrefix = "csg_agt_"

// ErrEntropy is returned when the system random source fails.
var ErrEntropy = errors.New("token: cannot read system randomness")

const entropyBytes = 32

// Generate creates a new token with the given prefix. It returns the plaintext
// token (show once) and the hex SHA-256 hash to persist.
func Generate(prefix string) (plain string, hash string, err error) {
	if prefix != AgentPrefix {
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

// Kind classifies a plaintext token by its prefix: "agent" or "".
func Kind(plain string) string {
	switch {
	case strings.HasPrefix(plain, AgentPrefix):
		return "agent"
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
