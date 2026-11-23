package authn

import (
	"strings"
	"testing"
	"time"
)

var fastParams = Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery", fastParams)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("unexpected format %q", h)
	}
	if ok, err := VerifyPassword(h, "correct horse battery"); err != nil || !ok {
		t.Fatalf("verify = %v, %v", ok, err)
	}
	if ok, _ := VerifyPassword(h, "correct horse batterz"); ok {
		t.Fatal("wrong password verified")
	}
	h2, _ := HashPassword("correct horse battery", fastParams)
	if h == h2 {
		t.Fatal("salt was reused")
	}
}

func TestPasswordRules(t *testing.T) {
	for name, pw := range map[string]string{
		"short":   "elevenchars",
		"long":    strings.Repeat("a", MaxPasswordBytes+1),
		"control": "has a\nnewline in it",
		"utf8":    "bad\xffbytes are here",
	} {
		if _, err := HashPassword(pw, fastParams); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := ValidatePassword("十二个字符的密码应该可以用"); err != nil {
		t.Errorf("12 runes rejected: %v", err)
	}
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	good, _ := HashPassword("correct horse battery", fastParams)
	for _, h := range []string{
		"", "plain", "$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		strings.Replace(good, "v=19", "v=16", 1),
		strings.Replace(good, "m=64", "m=4294967295", 1),
		strings.Replace(good, "t=1", "t=0", 1),
		strings.Replace(good, "p=1", "p=0", 1),
		good + "$extra",
		"$argon2id$v=19$m=64,t=1,p=1$$",
	} {
		if ok, err := VerifyPassword(h, "correct horse battery"); ok || err == nil {
			t.Errorf("%q: ok=%v err=%v", h, ok, err)
		}
	}
	if ok, err := VerifyPassword(good, strings.Repeat("a", MaxPasswordBytes+1)); ok || err != nil {
		t.Errorf("over-long password: ok=%v err=%v", ok, err)
	}
}

// RFC 6238 Appendix B, SHA-1, truncated to 6 digits.
func TestTOTPVectors(t *testing.T) {
	secret := totpEncoding.EncodeToString([]byte("12345678901234567890"))
	for unix, want := range map[int64]string{
		59: "287082", 1111111109: "081804", 1111111111: "050471",
		1234567890: "005924", 2000000000: "279037", 20000000000: "353130",
	} {
		got, err := TOTPCode(secret, TOTPStep(time.Unix(unix, 0)))
		if err != nil || got != want {
			t.Errorf("t=%d: got %q err %v, want %q", unix, got, err, want)
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	step := TOTPStep(now)
	code := func(s int64) string { c, _ := TOTPCode(secret, s); return c }

	for delta := int64(-1); delta <= 1; delta++ {
		got, ok, err := VerifyTOTP(secret, code(step+delta), now, -1)
		if err != nil || !ok || got != step+delta {
			t.Errorf("delta %d: step=%d ok=%v err=%v", delta, got, ok, err)
		}
	}
	for _, delta := range []int64{-2, 2} {
		if _, ok, _ := VerifyTOTP(secret, code(step+delta), now, -1); ok {
			t.Errorf("delta %d accepted", delta)
		}
	}
	// A used step, and any older one, is refused.
	if _, ok, _ := VerifyTOTP(secret, code(step), now, step); ok {
		t.Error("replayed step accepted")
	}
	if _, ok, _ := VerifyTOTP(secret, code(step-1), now, step); ok {
		t.Error("older step accepted after a newer one")
	}
	if _, ok, _ := VerifyTOTP(secret, code(step+1), now, step); !ok {
		t.Error("newer step refused")
	}
	for _, bad := range []string{"", "12345", "1234567", "12345a", " 12 34 "} {
		if _, ok, _ := VerifyTOTP(secret, bad, now, -1); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, _, err := VerifyTOTP("not base32 !", "123456", now, -1); err == nil {
		t.Error("malformed secret did not error")
	}
}

func TestSecrets(t *testing.T) {
	a, ha, err := NewSecret(32)
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := NewSecret(32)
	if a == b || HashSecret(a) != ha || len(a) < 43 {
		t.Fatal("bad secret generation")
	}
	if _, _, err := NewSecret(8); err == nil {
		t.Fatal("short secret accepted")
	}
	if !Equal("x", "x") || Equal("x", "y") {
		t.Fatal("Equal broken")
	}
}

func TestCheckTOTPTellsReuseFromGuess(t *testing.T) {
	secret, _ := NewTOTPSecret()
	now := time.Unix(1_800_000_000, 0)
	step := TOTPStep(now)
	code, _ := TOTPCode(secret, step)
	if _, r, _ := CheckTOTP(secret, code, now, -1); r != TOTPAccepted {
		t.Fatalf("fresh code = %v", r)
	}
	if _, r, _ := CheckTOTP(secret, code, now, step); r != TOTPReused {
		t.Fatalf("used code = %v, want reused", r)
	}
	older, _ := TOTPCode(secret, step-1)
	if _, r, _ := CheckTOTP(secret, older, now, step); r != TOTPReused {
		t.Fatalf("older code = %v, want reused", r)
	}
	wrong := "000000"
	for _, s := range []int64{step - 1, step, step + 1} {
		if c, _ := TOTPCode(secret, s); c == wrong {
			wrong = "999999"
		}
	}
	if _, r, _ := CheckTOTP(secret, wrong, now, step); r != TOTPWrong {
		t.Fatalf("wrong code = %v", r)
	}
}

func TestVerifyRejectsHostileHashParameters(t *testing.T) {
	good, _ := HashPassword("correct horse battery", fastParams)
	for name, h := range map[string]string{
		"1 GiB":       strings.Replace(good, "m=64", "m=1048576", 1),
		"257 MiB":     strings.Replace(good, "m=64", "m=263168", 1),
		"many passes": strings.Replace(good, "t=1", "t=11", 1),
		"many lanes":  strings.Replace(good, "p=1", "p=9", 1),
		"over-long":   good + strings.Repeat("A", 600),
	} {
		if ok, err := VerifyPassword(h, "correct horse battery"); ok || err == nil {
			t.Errorf("%s: ok=%v err=%v", name, ok, err)
		}
	}
	if err := DefaultParams.check(); err != nil {
		t.Fatalf("default parameters rejected: %v", err)
	}
}
