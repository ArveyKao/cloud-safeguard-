package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testKey returns a deterministic 32-byte key for tests.
func testKey(fill byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = fill
	}
	return k
}

func TestNewWrongKeySize(t *testing.T) {
	for _, size := range []int{0, 1, 16, 24, 31, 33, 64} {
		if _, err := New(make([]byte, size)); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("New(%d bytes) error = %v, want ErrInvalidKey", size, err)
		}
	}
	if _, err := New(nil); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("New(nil) error = %v, want ErrInvalidKey", err)
	}
}

func TestNewCopiesKey(t *testing.T) {
	key := testKey(0x11)
	v, err := New(key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key[0] = 0xFF // mutating the caller's slice must not change the vault key
	ct, err := v.Encrypt([]byte("secret"), "aad")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// A vault built from the original key value (all 0x11) must decrypt.
	orig, _ := New(testKey(0x11))
	if _, err := orig.Decrypt(ct, "aad"); err != nil {
		t.Fatalf("Decrypt with original key: %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	v, err := New(testKey(0x42))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	cases := []struct {
		name      string
		plaintext []byte
		aad       string
	}{
		{"simple", []byte("LTAI5tSecretAccessKey"), "provider/prv_1/credential"},
		{"empty plaintext", []byte{}, "lease/lea_1/credential"},
		{"binary", []byte{0x00, 0xFF, 0x01, 0x80, 0x7F}, "aad"},
		{"json", []byte(`{"access_key_id":"AKID","access_key_secret":"SECRET"}`), "provider/prv_2/credential"},
		{"long", bytes.Repeat([]byte("x"), 1<<16), "lease/lea_2/credential"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := v.Encrypt(tc.plaintext, tc.aad)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if !strings.HasPrefix(ct, "v1:") {
				t.Fatalf("ciphertext %q does not have v1: prefix", ct)
			}
			pt, err := v.Decrypt(ct, tc.aad)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if !bytes.Equal(pt, tc.plaintext) {
				t.Fatalf("roundtrip mismatch: got %q want %q", pt, tc.plaintext)
			}
		})
	}
}

func TestEncryptUsesFreshNonce(t *testing.T) {
	v, _ := New(testKey(0x07))
	a, err := v.Encrypt([]byte("same"), "aad")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := v.Encrypt([]byte("same"), "aad")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if a == b {
		t.Fatal("two encryptions of the same plaintext are identical; nonce is not random")
	}
}

func TestDecryptAADMismatch(t *testing.T) {
	v, _ := New(testKey(0x09))
	ct, err := v.Encrypt([]byte("secret"), "lease/lea_a/credential")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := v.Decrypt(ct, "lease/lea_b/credential"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Decrypt with wrong AAD error = %v, want ErrDecrypt", err)
	}
	if _, err := v.Decrypt(ct, ""); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Decrypt with empty AAD error = %v, want ErrDecrypt", err)
	}
}

func TestDecryptTamper(t *testing.T) {
	v, _ := New(testKey(0x0B))
	ct, err := v.Encrypt([]byte("secret"), "provider/prv_1/credential")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(ct, "v1:"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Flip a bit in the ciphertext body (not in the nonce).
	tampers := map[string]func([]byte) []byte{
		"ciphertext byte": func(r []byte) []byte {
			out := append([]byte(nil), r...)
			out[nonceSize] ^= 0x01
			return out
		},
		"tag byte": func(r []byte) []byte {
			out := append([]byte(nil), r...)
			out[len(out)-1] ^= 0x80
			return out
		},
		"nonce byte": func(r []byte) []byte {
			out := append([]byte(nil), r...)
			out[0] ^= 0xFF
			return out
		},
		"truncated": func(r []byte) []byte { return r[:len(r)-1] },
	}
	for name, mutate := range tampers {
		t.Run(name, func(t *testing.T) {
			tampered := "v1:" + base64.RawStdEncoding.EncodeToString(mutate(raw))
			if _, err := v.Decrypt(tampered, "provider/prv_1/credential"); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("Decrypt tampered (%s) error = %v, want ErrDecrypt", name, err)
			}
		})
	}
}

func TestDecryptBadFormat(t *testing.T) {
	v, _ := New(testKey(0x0D))
	bad := []string{
		"",
		"not-a-vault-string",
		"v2:AAAA",
		"v1:",
		"v1:!!!notbase64!!!",
		"v1:AAAA", // too short for nonce+tag
	}
	for _, ct := range bad {
		if _, err := v.Decrypt(ct, "aad"); !errors.Is(err, ErrDecrypt) {
			t.Errorf("Decrypt(%q) error = %v, want ErrDecrypt", ct, err)
		}
	}
}

func TestDecryptWrongKey(t *testing.T) {
	v1, _ := New(testKey(0x01))
	v2, _ := New(testKey(0x02))
	ct, err := v1.Encrypt([]byte("broker-secret"), "provider/prv_1/credential")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := v2.Decrypt(ct, "provider/prv_1/credential"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Decrypt with wrong key error = %v, want ErrDecrypt", err)
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	t.Setenv("CSG_MASTER_KEY", "")
	dir := t.TempDir()

	key1, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("key length = %d, want 32", len(key1))
	}

	info, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("stat master.key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("master.key mode = %o, want 0600", perm)
	}

	// Loading again returns the same key and does not rewrite the file.
	key2, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKey (second): %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("LoadOrCreateKey returned a different key on the second call")
	}
}

func TestLoadOrCreateKeyCreatesDataDir(t *testing.T) {
	t.Setenv("CSG_MASTER_KEY", "")
	base := t.TempDir()
	dir := filepath.Join(base, "nested", "data")

	key, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat data dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("data dir mode = %o, want no group/other access", perm)
	}
}

func TestLoadOrCreateKeyRejectsBadFile(t *testing.T) {
	t.Setenv("CSG_MASTER_KEY", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "master.key"), []byte("short"), 0o600); err != nil {
		t.Fatalf("write bad key file: %v", err)
	}
	if _, err := LoadOrCreateKey(dir); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("LoadOrCreateKey error = %v, want ErrInvalidKey", err)
	}
}

func TestLoadOrCreateKeyEnvOverride(t *testing.T) {
	dir := t.TempDir()
	// Seed a key file with one key...
	t.Setenv("CSG_MASTER_KEY", "")
	fileKey, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}

	// ...then set the env override to a different key.
	envKey := testKey(0xAB)
	t.Setenv("CSG_MASTER_KEY", base64.StdEncoding.EncodeToString(envKey))
	got, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateKey with env: %v", err)
	}
	if !bytes.Equal(got, envKey) {
		t.Fatal("CSG_MASTER_KEY did not override the key file")
	}
	if bytes.Equal(got, fileKey) {
		t.Fatal("CSG_MASTER_KEY override returned the key-file key")
	}
}

func TestLoadOrCreateKeyEnvInvalid(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CSG_MASTER_KEY", "not-base64!!")
	if _, err := LoadOrCreateKey(dir); err == nil {
		t.Fatal("LoadOrCreateKey accepted invalid base64 CSG_MASTER_KEY")
	}
	t.Setenv("CSG_MASTER_KEY", base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if _, err := LoadOrCreateKey(dir); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("LoadOrCreateKey wrong-size env error = %v, want ErrInvalidKey", err)
	}
}

func TestKeyFingerprint(t *testing.T) {
	key := testKey(0x5A)
	fp := KeyFingerprint(key)
	if len(fp) != hex.EncodedLen(8) {
		t.Fatalf("fingerprint length = %d, want %d", len(fp), hex.EncodedLen(8))
	}
	if _, err := hex.DecodeString(fp); err != nil {
		t.Fatalf("fingerprint is not hex: %v", err)
	}
	if fp != KeyFingerprint(testKey(0x5A)) {
		t.Fatal("fingerprint is not deterministic")
	}
	if fp == KeyFingerprint(testKey(0x5B)) {
		t.Fatal("fingerprint collision for different keys")
	}
}

func TestDeriveKey(t *testing.T) {
	master := testKey(0x33)
	a := DeriveKey(master, "mock-sts")
	b := DeriveKey(master, "mock-sts")
	if len(a) != 32 {
		t.Fatalf("derived key length = %d, want 32", len(a))
	}
	if !bytes.Equal(a, b) {
		t.Fatal("DeriveKey is not deterministic")
	}
	if bytes.Equal(a, DeriveKey(master, "audit-hmac")) {
		t.Fatal("DeriveKey ignored the purpose")
	}
	if bytes.Equal(a, DeriveKey(testKey(0x34), "mock-sts")) {
		t.Fatal("DeriveKey ignored the master key")
	}
}
