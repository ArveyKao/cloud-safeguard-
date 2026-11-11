package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// NewSecret returns a random URL-safe secret with n bytes of entropy and the
// hex SHA-256 hash to store. Only the hash is ever persisted.
func NewSecret(n int) (plain, hash string, err error) {
	if n < 16 {
		return "", "", errors.New("authn: secret too short")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", "", errors.New("authn: cannot read system randomness")
	}
	plain = base64.RawURLEncoding.EncodeToString(buf)
	return plain, HashSecret(plain), nil
}

// HashSecret returns the lowercase hex SHA-256 of a high-entropy secret.
func HashSecret(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// Equal compares two strings in constant time.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
