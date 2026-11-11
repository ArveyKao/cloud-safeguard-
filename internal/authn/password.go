// Package authn implements the human authentication primitives of Cloud
// Safeguard (CONTRACT §17.3): Argon2id password hashing, RFC 6238 TOTP codes
// and opaque random secrets. It holds no state and performs no I/O besides
// reading system randomness.
package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Password length limits. The upper bound keeps a hostile client from making
// the server hash megabytes of input.
const (
	MinPasswordLength = 12
	MaxPasswordBytes  = 256
)

// Params are the Argon2id cost parameters.
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	SaltLen   int
	KeyLen    uint32
}

// DefaultParams follow the OWASP Argon2id guidance (64 MiB, 3 passes).
var DefaultParams = Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 2, SaltLen: 16, KeyLen: 32}

// Upper bounds accepted when verifying a stored hash, so a corrupted or
// hostile row cannot make the server allocate unbounded memory.
const (
	maxMemoryKiB = 1024 * 1024
	maxTime      = 16
	maxThreads   = 16
	maxSaltLen   = 64
	maxKeyLen    = 64
)

// Errors returned by the password functions.
var (
	ErrPasswordTooShort = fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	ErrPasswordTooLong  = fmt.Errorf("password must be at most %d bytes", MaxPasswordBytes)
	ErrPasswordInvalid  = errors.New("password must be valid UTF-8 without control characters")
	ErrHashFormat       = errors.New("authn: malformed password hash")
)

// ValidatePassword checks a new password against the length and character
// rules. It does not judge strength beyond length.
func ValidatePassword(password string) error {
	if len(password) > MaxPasswordBytes {
		return ErrPasswordTooLong
	}
	if !utf8.ValidString(password) {
		return ErrPasswordInvalid
	}
	for _, r := range password {
		if r < 0x20 || r == 0x7f {
			return ErrPasswordInvalid
		}
	}
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	return nil
}

// HashPassword validates password and returns its Argon2id hash in PHC string
// format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>.
func HashPassword(password string, p Params) (string, error) {
	if err := ValidatePassword(password); err != nil {
		return "", err
	}
	if err := p.check(); err != nil {
		return "", err
	}
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", errors.New("authn: cannot read system randomness")
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches the encoded hash. A
// malformed hash returns ErrHashFormat and never matches. Over-long passwords
// never match and are not hashed.
func VerifyPassword(encoded, password string) (bool, error) {
	p, salt, want, err := parseHash(encoded)
	if err != nil {
		return false, err
	}
	if len(password) > MaxPasswordBytes {
		return false, nil
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func (p Params) check() error {
	if p.MemoryKiB < 8*uint32(p.Threads) || p.MemoryKiB > maxMemoryKiB ||
		p.Time < 1 || p.Time > maxTime ||
		p.Threads < 1 || p.Threads > maxThreads ||
		p.SaltLen < 8 || p.SaltLen > maxSaltLen ||
		p.KeyLen < 16 || p.KeyLen > maxKeyLen {
		return errors.New("authn: invalid Argon2id parameters")
	}
	return nil
}

func parseHash(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrHashFormat
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return Params{}, nil, nil, ErrHashFormat
	}
	var p Params
	fields := strings.Split(parts[3], ",")
	if len(fields) != 3 {
		return Params{}, nil, nil, ErrHashFormat
	}
	for i, prefix := range []string{"m=", "t=", "p="} {
		raw, ok := strings.CutPrefix(fields[i], prefix)
		if !ok {
			return Params{}, nil, nil, ErrHashFormat
		}
		n, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return Params{}, nil, nil, ErrHashFormat
		}
		switch i {
		case 0:
			p.MemoryKiB = uint32(n)
		case 1:
			p.Time = uint32(n)
		case 2:
			if n > 255 {
				return Params{}, nil, nil, ErrHashFormat
			}
			p.Threads = uint8(n)
		}
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, ErrHashFormat
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, ErrHashFormat
	}
	p.SaltLen = len(salt)
	p.KeyLen = uint32(len(key))
	if p.check() != nil {
		return Params{}, nil, nil, ErrHashFormat
	}
	return p, salt, key, nil
}
