package provider

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Mock token format constants (docs/CONTRACT.md §8.2). The mock provider mints
// them and the mock cloud verifies them, so the format is frozen.
const (
	// MockTokenVersion is the current "v" payload field value.
	MockTokenVersion = 1
	// mockTokenPrefix is the textual prefix of every mock STS token.
	mockTokenPrefix = "cgk1."
	// MockAccountID is the synthetic Alibaba Cloud account ID used by the
	// built-in mock cloud fixtures.
	MockAccountID = "1234567890123456"
	// MockDefaultRegion is the region used when a mock provider has no region.
	MockDefaultRegion = "cn-hangzhou"

	// MockMinDuration / MockMaxDuration bound the lifetime of mock tokens.
	MockMinDuration = 5
	MockMaxDuration = 3600
)

// ErrInvalidMockToken is returned when a mock token is malformed, tampered
// with, or signed by a different key. It never includes the token itself.
var ErrInvalidMockToken = errors.New("provider: invalid mock token")

// MockTokenPayload is the signed payload embedded in a "cgk1." mock STS token.
// Field order is part of the frozen format: the payload is marshalled from this
// struct in exactly this order and the signature covers those bytes.
type MockTokenPayload struct {
	V           int             `json:"v"`
	LeaseID     string          `json:"lease_id"`
	ProviderID  string          `json:"provider_id"`
	AccountID   string          `json:"account_id"`
	Region      string          `json:"region"`
	ExpiresAt   string          `json:"expires_at"`
	SessionName string          `json:"session_name"`
	Policy      json.RawMessage `json:"policy"`
}

// Expiry parses the payload's expires_at field.
func (p MockTokenPayload) Expiry() (time.Time, error) {
	return time.Parse(time.RFC3339Nano, p.ExpiresAt)
}

// mockMinter mints locally signed mock STS tokens. No network, no real
// credentials: it exists for the demo and test path.
type mockMinter struct{}

// Mint implements Minter for the mock provider.
func (mockMinter) Mint(ctx context.Context, req MintRequest) (model.Credential, error) {
	if err := ctx.Err(); err != nil {
		return model.Credential{}, err
	}
	if len(req.SigningKey) != 32 {
		return model.Credential{}, fmt.Errorf("provider mock: signing key must be 32 bytes")
	}
	if req.LeaseID == "" {
		return model.Credential{}, fmt.Errorf("provider mock: lease id is required")
	}
	if req.DurationSeconds < MockMinDuration || req.DurationSeconds > MockMaxDuration {
		return model.Credential{}, fmt.Errorf(
			"provider mock: duration %ds outside allowed range %d-%ds",
			req.DurationSeconds, MockMinDuration, MockMaxDuration)
	}
	if !json.Valid(req.PolicyJSON) {
		return model.Credential{}, fmt.Errorf("provider mock: policy is not valid JSON")
	}

	region := req.Provider.Region
	if region == "" {
		region = MockDefaultRegion
	}
	expiresAt := time.Now().UTC().Add(time.Duration(req.DurationSeconds) * time.Second)

	payload := MockTokenPayload{
		V:           MockTokenVersion,
		LeaseID:     req.LeaseID,
		ProviderID:  req.Provider.ID,
		AccountID:   MockAccountID,
		Region:      region,
		ExpiresAt:   expiresAt.Format(time.RFC3339Nano),
		SessionName: SanitizeSessionName(req.SessionName),
		Policy:      append(json.RawMessage(nil), req.PolicyJSON...),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return model.Credential{}, fmt.Errorf("provider mock: cannot encode token payload")
	}

	token, err := mintMockToken(req.SigningKey, body)
	if err != nil {
		return model.Credential{}, err
	}

	accessKeyID, err := randomAccessKeyID()
	if err != nil {
		return model.Credential{}, err
	}
	accessKeySecret, err := randomAccessKeySecret()
	if err != nil {
		return model.Credential{}, err
	}

	return model.Credential{
		ProviderID:      req.Provider.ID,
		ProviderMode:    model.ModeMock,
		LeaseID:         req.LeaseID,
		AccessKeyID:     accessKeyID,
		AccessKeySecret: accessKeySecret,
		SecurityToken:   token,
		ExpiresAt:       expiresAt,
	}, nil
}

// Test implements Minter for the mock provider: the signing key is the only
// thing that can be wrong without a network call.
func (mockMinter) Test(ctx context.Context, req MintRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(req.SigningKey) != 32 {
		return fmt.Errorf("provider mock: signing key must be 32 bytes (got %d)", len(req.SigningKey))
	}
	return nil
}

// VerifyMockToken validates a mock STS token and returns its payload. It checks
// the format, the HMAC signature (constant time) and the payload version. It
// does not check expiry or lease state: callers (the mock cloud) do that in
// their own validation order.
func VerifyMockToken(token string, signingKey []byte) (MockTokenPayload, error) {
	var payload MockTokenPayload
	if len(signingKey) != 32 {
		return payload, fmt.Errorf("%w: signing key is not configured", ErrInvalidMockToken)
	}
	if !strings.HasPrefix(token, mockTokenPrefix) {
		return payload, fmt.Errorf("%w: bad prefix", ErrInvalidMockToken)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "cgk1" || parts[1] == "" || parts[2] == "" {
		return payload, fmt.Errorf("%w: malformed token", ErrInvalidMockToken)
	}

	gotSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(gotSig) == 0 {
		return payload, fmt.Errorf("%w: malformed signature", ErrInvalidMockToken)
	}
	wantSig := mockTokenSignature(signingKey, parts[1])
	if subtle.ConstantTimeCompare(gotSig, wantSig) != 1 {
		return payload, fmt.Errorf("%w: signature mismatch", ErrInvalidMockToken)
	}

	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return payload, fmt.Errorf("%w: malformed payload", ErrInvalidMockToken)
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return payload, fmt.Errorf("%w: malformed payload", ErrInvalidMockToken)
	}
	if payload.V != MockTokenVersion {
		return payload, fmt.Errorf("%w: unsupported version", ErrInvalidMockToken)
	}
	if payload.LeaseID == "" || payload.ProviderID == "" || payload.AccountID == "" {
		return payload, fmt.Errorf("%w: missing required claims", ErrInvalidMockToken)
	}
	if payload.Region == "" {
		payload.Region = MockDefaultRegion
	}
	if len(payload.Policy) == 0 || !json.Valid(payload.Policy) || string(payload.Policy) == "null" {
		return payload, fmt.Errorf("%w: missing policy document", ErrInvalidMockToken)
	}
	if _, err := payload.Expiry(); err != nil {
		return payload, fmt.Errorf("%w: malformed expiry", ErrInvalidMockToken)
	}
	return payload, nil
}

// mintMockToken builds "cgk1.<payload>.<sig>" from already-marshalled payload
// bytes.
func mintMockToken(signingKey, payloadJSON []byte) (string, error) {
	if len(signingKey) != 32 {
		return "", fmt.Errorf("provider mock: signing key must be 32 bytes")
	}
	body := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := base64.RawURLEncoding.EncodeToString(mockTokenSignature(signingKey, body))
	return mockTokenPrefix + body + "." + sig, nil
}

// mockTokenSignature is HMAC-SHA256(signingKey, "cgk1."+base64url(payload)).
func mockTokenSignature(signingKey []byte, encodedPayload string) []byte {
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(mockTokenPrefix + encodedPayload))
	return mac.Sum(nil)
}

// randomAccessKeyID builds an Alibaba-Cloud-shaped "LTAI" + 8 uppercase hex
// chars access key id for mock credentials.
func randomAccessKeyID() (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("provider mock: cannot read system randomness")
	}
	return "LTAI" + strings.ToUpper(hex.EncodeToString(buf)), nil
}

// randomAccessKeySecret builds a base64url-encoded 24-byte random secret.
func randomAccessKeySecret() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("provider mock: cannot read system randomness")
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// SanitizeSessionName maps a session name to the Alibaba Cloud STS charset
// [A-Za-z0-9._-], truncates it to 64 characters and guarantees the 2-character
// minimum. It never returns an empty string.
func SanitizeSessionName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		}
		if b.Len() >= 64 {
			break
		}
	}
	out := b.String()
	if len(out) < 2 {
		return "csg"
	}
	return out
}
