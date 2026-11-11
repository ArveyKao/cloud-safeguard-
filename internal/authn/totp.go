package authn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 default; what authenticator apps implement.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters (RFC 6238 defaults, supported by every authenticator app).
const (
	TOTPDigits = 6
	TOTPPeriod = 30 * time.Second
	// TOTPSkew is how many periods before and after the current one are
	// accepted, to tolerate clock drift.
	TOTPSkew       = 1
	totpSecretSize = 20
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrTOTPSecret is returned for a secret that is not valid base32.
var ErrTOTPSecret = errors.New("authn: malformed TOTP secret")

// NewTOTPSecret returns a fresh random base32 TOTP secret (160 bits).
func NewTOTPSecret() (string, error) {
	buf := make([]byte, totpSecretSize)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.New("authn: cannot read system randomness")
	}
	return totpEncoding.EncodeToString(buf), nil
}

// TOTPStep returns the time-step counter for t.
func TOTPStep(t time.Time) int64 { return t.Unix() / int64(TOTPPeriod/time.Second) }

// TOTPCode returns the code for the given step.
func TOTPCode(secret string, step int64) (string, error) {
	key, err := totpEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) < 10 {
		return "", ErrTOTPSecret
	}
	if step < 0 {
		return "", errors.New("authn: negative TOTP step")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", TOTPDigits, value%1_000_000), nil
}

// VerifyTOTP checks code against the steps around now. It returns the matched
// step so the caller can refuse to accept the same or an older step again
// (replay protection): pass the last accepted step as lastStep, or -1 for
// none. Every candidate step is evaluated so timing does not reveal which one
// matched.
func VerifyTOTP(secret, code string, now time.Time, lastStep int64) (step int64, ok bool, err error) {
	code = strings.TrimSpace(code)
	if len(code) != TOTPDigits {
		return 0, false, nil
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false, nil
		}
	}
	current := TOTPStep(now)
	matched := int64(-1)
	for delta := int64(-TOTPSkew); delta <= TOTPSkew; delta++ {
		candidate := current + delta
		if candidate < 0 {
			continue
		}
		want, err := TOTPCode(secret, candidate)
		if err != nil {
			return 0, false, err
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && candidate > lastStep && matched < 0 {
			matched = candidate
		}
	}
	if matched < 0 {
		return 0, false, nil
	}
	return matched, true, nil
}

// OTPAuthURL builds the otpauth:// URI an authenticator app scans.
func OTPAuthURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(TOTPDigits))
	q.Set("period", fmt.Sprint(int(TOTPPeriod/time.Second)))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
