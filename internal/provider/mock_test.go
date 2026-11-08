package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

func testMockSigningKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	return key
}

func testMockMintRequest(t *testing.T) MintRequest {
	t.Helper()
	return MintRequest{
		LeaseID: "lea_mock001",
		Provider: model.Provider{
			ID:     "prv_mock01",
			Name:   "demo-aliyun",
			Type:   model.ProviderAliyun,
			Mode:   model.ModeMock,
			Region: "cn-hangzhou",
		},
		PolicyJSON:      []byte(`{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:Describe*"],"Resource":["*"]}]}`),
		SessionName:     "csg-agt_123-lea_mock001",
		DurationSeconds: 900,
		SigningKey:      testMockSigningKey(),
	}
}

func TestMockMintVerifyRoundtrip(t *testing.T) {
	req := testMockMintRequest(t)
	minter, err := New(model.ModeMock)
	if err != nil {
		t.Fatalf("New(mock) error = %v", err)
	}

	before := time.Now().UTC()
	cred, err := minter.Mint(context.Background(), req)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	after := time.Now().UTC()

	if cred.ProviderID != "prv_mock01" || cred.ProviderMode != model.ModeMock || cred.LeaseID != "lea_mock001" {
		t.Errorf("credential metadata = %+v", cred)
	}
	if !strings.HasPrefix(cred.AccessKeyID, "LTAI") || len(cred.AccessKeyID) != 12 {
		t.Errorf("AccessKeyID = %q, want LTAI + 8 chars", cred.AccessKeyID)
	}
	if got := cred.AccessKeyID[4:]; got != strings.ToUpper(got) {
		t.Errorf("AccessKeyID hex = %q, want uppercase", got)
	}
	secretBytes, err := base64.RawURLEncoding.DecodeString(cred.AccessKeySecret)
	if err != nil || len(secretBytes) != 24 {
		t.Errorf("AccessKeySecret = %q, want base64url(24 bytes) (err=%v)", cred.AccessKeySecret, err)
	}
	if !strings.HasPrefix(cred.SecurityToken, "cgk1.") {
		t.Errorf("SecurityToken = %.20q..., want cgk1. prefix", cred.SecurityToken)
	}
	if parts := strings.Split(cred.SecurityToken, "."); len(parts) != 3 {
		t.Errorf("SecurityToken has %d dot-separated parts, want 3", len(parts))
	}
	wantExpiryStart := before.Add(900 * time.Second)
	wantExpiryEnd := after.Add(900 * time.Second)
	if cred.ExpiresAt.Before(wantExpiryStart.Add(-time.Second)) || cred.ExpiresAt.After(wantExpiryEnd.Add(time.Second)) {
		t.Errorf("ExpiresAt = %v, want ~%v", cred.ExpiresAt, wantExpiryStart)
	}

	// Verify roundtrip.
	payload, err := VerifyMockToken(cred.SecurityToken, req.SigningKey)
	if err != nil {
		t.Fatalf("VerifyMockToken() error = %v", err)
	}
	if payload.V != 1 || payload.LeaseID != req.LeaseID || payload.ProviderID != req.Provider.ID {
		t.Errorf("payload identity = %+v", payload)
	}
	if payload.AccountID != MockAccountID {
		t.Errorf("payload AccountID = %q, want %q", payload.AccountID, MockAccountID)
	}
	if payload.Region != "cn-hangzhou" {
		t.Errorf("payload Region = %q", payload.Region)
	}
	if payload.SessionName != "csg-agt_123-lea_mock001" {
		t.Errorf("payload SessionName = %q", payload.SessionName)
	}
	if string(payload.Policy) != string(req.PolicyJSON) {
		t.Errorf("payload Policy = %s, want %s", payload.Policy, req.PolicyJSON)
	}
	expiry, err := payload.Expiry()
	if err != nil {
		t.Fatalf("payload.Expiry() error = %v", err)
	}
	if !expiry.After(time.Now()) {
		t.Errorf("payload expiry %v is in the past", expiry)
	}
	if !expiry.Equal(cred.ExpiresAt) {
		t.Errorf("payload expiry %v != credential expiry %v", expiry, cred.ExpiresAt)
	}
}

func TestMockTokenPayloadFieldFormat(t *testing.T) {
	req := testMockMintRequest(t)
	minter, _ := New(model.ModeMock)
	cred, err := minter.Mint(context.Background(), req)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	parts := strings.Split(cred.SecurityToken, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d", len(parts))
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload is not raw base64url: %v", err)
	}

	// The payload must be encoded from a struct with exactly the frozen field
	// order (CONTRACT §8.2): v, lease_id, provider_id, account_id, region,
	// expires_at, session_name, policy.
	wantOrder := []string{`"v"`, `"lease_id"`, `"provider_id"`, `"account_id"`, `"region"`, `"expires_at"`, `"session_name"`, `"policy"`}
	last := -1
	for _, key := range wantOrder {
		idx := strings.Index(string(body), key)
		if idx < 0 {
			t.Fatalf("payload missing field %s: %s", key, body)
		}
		if idx <= last {
			t.Fatalf("payload field %s is out of order: %s", key, body)
		}
		last = idx
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if len(raw) != len(wantOrder) {
		t.Fatalf("payload has %d fields, want %d: %s", len(raw), len(wantOrder), body)
	}

	// Signature is base64url HMAC over "cgk1."+payload segment.
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 32 {
		t.Fatalf("signature = %d bytes (err=%v), want 32", len(sig), err)
	}
}

func TestMockTokenTamperRejected(t *testing.T) {
	req := testMockMintRequest(t)
	minter, _ := New(model.ModeMock)
	cred, err := minter.Mint(context.Background(), req)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	parts := strings.Split(cred.SecurityToken, ".")
	if len(parts) != 3 {
		t.Fatalf("token parts = %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	// Tampered payload with the original signature: flip a byte.
	tamperedPayload := append([]byte(nil), payload...)
	tamperedPayload[len(tamperedPayload)-2] ^= 0x01
	tamperedToken := "cgk1." + base64.RawURLEncoding.EncodeToString(tamperedPayload) + "." + parts[2]

	// Tampered signature: flip a byte of the decoded signature.
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	tamperedSig := append([]byte(nil), sig...)
	tamperedSig[0] ^= 0xFF
	tamperedSigToken := "cgk1." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(tamperedSig)

	// Re-signed payload but with the wrong signing key.
	wrongKey := testMockSigningKey()
	wrongKey[0] ^= 0xFF

	tests := []struct {
		name  string
		token string
		key   []byte
	}{
		{"tampered payload", tamperedToken, req.SigningKey},
		{"tampered signature", tamperedSigToken, req.SigningKey},
		{"wrong signing key", cred.SecurityToken, wrongKey},
		{"empty token", "", req.SigningKey},
		{"no prefix", strings.TrimPrefix(cred.SecurityToken, "cgk1."), req.SigningKey},
		{"two parts", "cgk1.abc", req.SigningKey},
		{"four parts", cred.SecurityToken + ".extra", req.SigningKey},
		{"bad base64 payload", "cgk1.!!!." + parts[2], req.SigningKey},
		{"bad base64 signature", "cgk1." + parts[1] + ".!!!", req.SigningKey},
		{"wrong version prefix", "cgk2." + parts[1] + "." + parts[2], req.SigningKey},
		{"short signing key", cred.SecurityToken, []byte("short")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyMockToken(tc.token, tc.key); err == nil {
				t.Fatalf("VerifyMockToken() = nil error for %s", tc.name)
			} else if !errors.Is(err, ErrInvalidMockToken) {
				t.Fatalf("VerifyMockToken() error = %v, want ErrInvalidMockToken", err)
			}
		})
	}
}

func TestMockTokenMissingClaimsRejected(t *testing.T) {
	key := testMockSigningKey()
	policy := json.RawMessage(`{"Version":"1","Statement":[]}`)

	tests := []struct {
		name    string
		payload MockTokenPayload
	}{
		{"missing lease", MockTokenPayload{V: 1, ProviderID: "prv", AccountID: MockAccountID, Region: "cn-hangzhou", ExpiresAt: time.Now().UTC().Format(time.RFC3339Nano), Policy: policy}},
		{"missing provider", MockTokenPayload{V: 1, LeaseID: "lea", AccountID: MockAccountID, Region: "cn-hangzhou", ExpiresAt: time.Now().UTC().Format(time.RFC3339Nano), Policy: policy}},
		{"missing account", MockTokenPayload{V: 1, LeaseID: "lea", ProviderID: "prv", Region: "cn-hangzhou", ExpiresAt: time.Now().UTC().Format(time.RFC3339Nano), Policy: policy}},
		{"bad expiry", MockTokenPayload{V: 1, LeaseID: "lea", ProviderID: "prv", AccountID: MockAccountID, Region: "cn-hangzhou", ExpiresAt: "not-a-time", Policy: policy}},
		{"no policy", MockTokenPayload{V: 1, LeaseID: "lea", ProviderID: "prv", AccountID: MockAccountID, Region: "cn-hangzhou", ExpiresAt: time.Now().UTC().Format(time.RFC3339Nano)}},
		{"wrong version", MockTokenPayload{V: 2, LeaseID: "lea", ProviderID: "prv", AccountID: MockAccountID, Region: "cn-hangzhou", ExpiresAt: time.Now().UTC().Format(time.RFC3339Nano), Policy: policy}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			token, err := mintMockToken(key, body)
			if err != nil {
				t.Fatalf("mintMockToken: %v", err)
			}
			if _, err := VerifyMockToken(token, key); err == nil {
				t.Fatalf("VerifyMockToken() = nil for %s", tc.name)
			}
		})
	}
}

func TestMockMintValidation(t *testing.T) {
	minter, _ := New(model.ModeMock)
	base := testMockMintRequest(t)

	tests := []struct {
		name    string
		mutate  func(*MintRequest)
		wantErr string
	}{
		{"bad signing key", func(r *MintRequest) { r.SigningKey = []byte("short") }, "signing key must be 32 bytes"},
		{"missing lease id", func(r *MintRequest) { r.LeaseID = "" }, "lease id is required"},
		{"duration too short", func(r *MintRequest) { r.DurationSeconds = 4 }, "outside allowed range"},
		{"duration too long", func(r *MintRequest) { r.DurationSeconds = 3601 }, "outside allowed range"},
		{"invalid policy", func(r *MintRequest) { r.PolicyJSON = []byte("{") }, "not valid JSON"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			_, err := minter.Mint(context.Background(), req)
			if err == nil {
				t.Fatalf("Mint() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Mint() error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}

	// Valid boundary durations must mint.
	for _, d := range []int{5, 3600} {
		req := base
		req.DurationSeconds = d
		if _, err := minter.Mint(context.Background(), req); err != nil {
			t.Fatalf("Mint() duration %d error = %v", d, err)
		}
	}
}

func TestMockTest(t *testing.T) {
	minter, _ := New(model.ModeMock)
	if err := minter.Test(context.Background(), MintRequest{SigningKey: testMockSigningKey()}); err != nil {
		t.Fatalf("Test() error = %v", err)
	}
	if err := minter.Test(context.Background(), MintRequest{SigningKey: []byte("short")}); err == nil {
		t.Fatal("Test() with short signing key = nil error")
	}
	if err := minter.Test(context.Background(), MintRequest{}); err == nil {
		t.Fatal("Test() with no signing key = nil error")
	}
}

func TestMockMintDoesNotLeakBrokerSecrets(t *testing.T) {
	req := testMockMintRequest(t)
	req.BrokerAccessKeyID = "LTAI5tRealBrokerKey"
	req.BrokerAccessKeySecret = "real-broker-secret-value"
	minter, _ := New(model.ModeMock)
	cred, err := minter.Mint(context.Background(), req)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if strings.Contains(cred.SecurityToken, req.BrokerAccessKeySecret) {
		t.Fatalf("mock token embeds the broker secret")
	}
	if strings.Contains(cred.SecurityToken, req.BrokerAccessKeyID) {
		t.Fatalf("mock token embeds the broker access key id")
	}
}

func TestMockSessionNameSanitized(t *testing.T) {
	req := testMockMintRequest(t)
	req.SessionName = "csg agent/123 :lease"
	minter, _ := New(model.ModeMock)
	cred, err := minter.Mint(context.Background(), req)
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	payload, err := VerifyMockToken(cred.SecurityToken, req.SigningKey)
	if err != nil {
		t.Fatalf("VerifyMockToken() error = %v", err)
	}
	if payload.SessionName != "csgagent123lease" {
		t.Fatalf("SessionName = %q, want sanitized %q", payload.SessionName, "csgagent123lease")
	}
}

func TestVerifyMockTokenReturnsExpiredPayloadForEnforcementLayer(t *testing.T) {
	// Signature verification intentionally does not enforce expiry: the mock
	// cloud applies the frozen validation order (expiry is a separate 401).
	key := testMockSigningKey()
	payload := MockTokenPayload{
		V:           1,
		LeaseID:     "lea_expired",
		ProviderID:  "prv_mock01",
		AccountID:   MockAccountID,
		Region:      "cn-hangzhou",
		ExpiresAt:   time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano),
		SessionName: "csg",
		Policy:      json.RawMessage(`{"Version":"1","Statement":[]}`),
	}
	body, _ := json.Marshal(payload)
	token, err := mintMockToken(key, body)
	if err != nil {
		t.Fatalf("mintMockToken: %v", err)
	}
	got, err := VerifyMockToken(token, key)
	if err != nil {
		t.Fatalf("VerifyMockToken() error = %v, want signature-only validation", err)
	}
	expiry, err := got.Expiry()
	if err != nil {
		t.Fatalf("Expiry() error = %v", err)
	}
	if !expiry.Before(time.Now()) {
		t.Fatalf("expiry %v should be in the past", expiry)
	}
}

func TestMockTokenPolicyTamperChangesSignature(t *testing.T) {
	req := testMockMintRequest(t)
	minter, _ := New(model.ModeMock)
	cred, _ := minter.Mint(context.Background(), req)

	// Re-encode the payload with an escalated policy and keep the old
	// signature: it must not verify.
	parts := strings.Split(cred.SecurityToken, ".")
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload MockTokenPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	payload.Policy = json.RawMessage(`{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`)
	evilBody, _ := json.Marshal(payload)
	evilToken := "cgk1." + base64.RawURLEncoding.EncodeToString(evilBody) + "." + parts[2]
	if _, err := VerifyMockToken(evilToken, req.SigningKey); err == nil {
		t.Fatal("VerifyMockToken() accepted a token with an escalated policy")
	}
}
