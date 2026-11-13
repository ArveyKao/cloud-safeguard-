package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// ---- harness ----

// testApp is one CLI invocation with fully injected I/O, environment and home.
type testApp struct {
	app    *App
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	env    map[string]string
	home   string
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	ta := &testApp{
		stdout: &bytes.Buffer{},
		stderr: &bytes.Buffer{},
		env:    map[string]string{},
		home:   t.TempDir(),
	}
	ta.app = &App{
		Stdout: ta.stdout,
		Stderr: ta.stderr,
		Stdin:  strings.NewReader(""),
		Getenv: func(key string) string { return ta.env[key] },
		HomeDir: func() (string, error) {
			return ta.home, nil
		},
	}
	return ta
}

func (ta *testApp) run(args ...string) int { return ta.app.Run(args) }

func (ta *testApp) out() string { return ta.stdout.String() }

func (ta *testApp) errOut() string { return ta.stderr.String() }

func (ta *testApp) useServer(serverURL, token string) {
	ta.env["CSG_SERVER"] = serverURL
	ta.env["CSG_TOKEN"] = token
}

// writeEnvelope writes the control-plane success envelope.
func writeEnvelope(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

// writeErrorEnvelope writes the control-plane error envelope.
func writeErrorEnvelope(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{"code": code, "message": message},
	})
}

// decodeBody decodes a JSON request body.
func decodeBody(t *testing.T, r *http.Request, out any) {
	t.Helper()
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		t.Fatalf("cannot decode request body: %v", err)
	}
}

// requireAuth checks the bearer token on a fake request.
func requireAuth(t *testing.T, r *http.Request, want string) {
	t.Helper()
	if got := r.Header.Get("Authorization"); got != "Bearer "+want {
		t.Fatalf("Authorization = %q, want bearer token %q", got, want)
	}
}

// testLease builds a lease fixture for fake responses.
func testLease(status model.LeaseStatus) model.Lease {
	created := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	outcome := model.OutcomeAutoApprove
	switch status {
	case model.LeasePending:
		outcome = model.OutcomeRequireApproval
	case model.LeaseDenied:
		outcome = model.OutcomeDeny
	}
	lease := model.Lease{
		ID:                  "lea_test01",
		AgentID:             "agt_demo1",
		AgentName:           "claude-code",
		CapabilityID:        "aliyun.cloud.read",
		CapabilityName:      "Cloud read-only inventory",
		ProviderID:          "prv_demo1",
		ProviderName:        "demo-aliyun",
		ProviderMode:        model.ModeMock,
		Risk:                model.RiskLow,
		Reason:              "demo reason",
		RequestedTTLSeconds: 900,
		EffectiveTTLSeconds: 900,
		Status:              status,
		Decision: model.PolicyDecision{
			Outcome:             outcome,
			EffectiveTTLSeconds: 900,
			Reasons: []model.DecisionReason{
				{Rule: "capability_granted", Outcome: "allow", Detail: "granted"},
				{Rule: "auto_approve", Outcome: "allow", Detail: "no deny/require triggered"},
			},
		},
		CreatedAt: created,
	}
	if status == model.LeaseActive {
		expires := created.Add(15 * time.Minute)
		lease.ExpiresAt = &expires
	}
	if status == model.LeaseDenied {
		lease.DeniedReason = "risk_above_auto: capability risk medium exceeds auto-approve max low"
		lease.Decision.Reasons = append(lease.Decision.Reasons,
			model.DecisionReason{Rule: "risk_above_auto", Outcome: "require_approval", Detail: "medium > low"})
	}
	return lease
}

// ---- basic commands and parsing ----

func TestVersionCommand(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.run("version"); code != ExitOK {
		t.Fatalf("version exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), model.Version) {
		t.Fatalf("version output = %q", ta.out())
	}

	ta = newTestApp(t)
	if code := ta.run("version", "--json"); code != ExitOK {
		t.Fatalf("version --json exit = %d", code)
	}
	var payload struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(ta.stdout.Bytes(), &payload); err != nil {
		t.Fatalf("version --json output is not JSON: %v", err)
	}
	if payload.Version != model.Version || payload.Name != model.ProductName {
		t.Fatalf("version payload = %+v", payload)
	}
}

func TestUsageExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"unknown command", []string{"frobnicate"}},
		{"caps without subcommand", []string{"caps"}},
		{"agents unknown sub", []string{"agents", "explode"}},
		{"leases without sub", []string{"leases"}},
		{"audit without sub", []string{"audit"}},
		{"policy without sub", []string{"policy"}},
		{"mock without sub", []string{"mock"}},
		{"request without capability", []string{"request"}},
		{"credential without lease", []string{"credential"}},
		{"revoke without lease", []string{"revoke"}},
		{"exec without separator", []string{"exec", "--capability", "aliyun.cloud.read"}},
		{"exec without command", []string{"exec", "--capability", "aliyun.cloud.read", "--"}},
		{"login without flags", []string{"login"}},
		{"version with args", []string{"version", "extra"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t)
			code := ta.run(tc.args...)
			if code != ExitUsage {
				t.Fatalf("exit = %d, want %d; stderr = %q", code, ExitUsage, ta.errOut())
			}
			if !strings.HasPrefix(ta.errOut(), "error: ") && len(tc.args) > 0 {
				t.Fatalf("stderr = %q, want 'error: ...'", ta.errOut())
			}
		})
	}
}

func TestHelpSucceeds(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.run("help"); code != ExitOK {
		t.Fatalf("help exit = %d", code)
	}
	for _, want := range []string{"init", "serve", "request", "credential", "exec", "audit"} {
		if !strings.Contains(ta.out(), want) {
			t.Fatalf("help output missing %q", want)
		}
	}
}

func TestParseDurationSeconds(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"90s", 90, false},
		{"10m", 600, false},
		{"1h", 3600, false},
		{"900", 900, false},
		{" 15m ", 900, false},
		{"1h30m", 5400, false},
		{"2s", 2, false},
		{"", 0, true},
		{"0", 0, true},
		{"-5", 0, true},
		{"abc", 0, true},
		{"1.5", 0, true},
	}
	for _, tc := range tests {
		got, err := parseDurationSeconds(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseDurationSeconds(%q) = %d, want error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDurationSeconds(%q) error = %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseDurationSeconds(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestParseOptionalDurationSeconds(t *testing.T) {
	if got, err := parseOptionalDurationSeconds(""); err != nil || got != 0 {
		t.Fatalf("optional empty = (%d, %v), want (0, nil)", got, err)
	}
	if got, err := parseOptionalDurationSeconds("10m"); err != nil || got != 600 {
		t.Fatalf("optional 10m = (%d, %v)", got, err)
	}
}

func TestParseRiskTier(t *testing.T) {
	for _, want := range []model.RiskTier{model.RiskLow, model.RiskMedium, model.RiskHigh, model.RiskCritical} {
		got, err := parseRiskTier(strings.ToUpper(string(want)))
		if err != nil || got != want {
			t.Fatalf("parseRiskTier(%q) = (%v, %v)", want, got, err)
		}
	}
	if _, err := parseRiskTier("extreme"); err == nil {
		t.Fatal("parseRiskTier(extreme) = nil error")
	}
}

func TestParamValues(t *testing.T) {
	var params paramValues
	for _, input := range []string{"domain=arveykao.com", "instance_id=i-2ze0demo001"} {
		if err := params.Set(input); err != nil {
			t.Fatalf("Set(%q) error = %v", input, err)
		}
	}
	got := params.mapValue()
	if got["domain"] != "arveykao.com" || got["instance_id"] != "i-2ze0demo001" {
		t.Fatalf("params = %v", got)
	}
	var bad paramValues
	if err := bad.Set("noequals"); err == nil {
		t.Fatal("Set(noequals) = nil error")
	}
	if err := bad.Set("=value"); err == nil {
		t.Fatal("Set(=value) = nil error")
	}
	if empty := (paramValues{}).mapValue(); empty != nil {
		t.Fatalf("empty params map = %v, want nil", empty)
	}
}

func TestStringSliceFlag(t *testing.T) {
	var grants stringSliceFlag
	if err := grants.Set("aliyun.cloud.read, aliyun.dns.manage"); err != nil {
		t.Fatalf("Set error = %v", err)
	}
	if err := grants.Set("aliyun.cert.dns01"); err != nil {
		t.Fatalf("Set error = %v", err)
	}
	want := []string{"aliyun.cloud.read", "aliyun.dns.manage", "aliyun.cert.dns01"}
	if strings.Join(grants.values(), ",") != strings.Join(want, ",") {
		t.Fatalf("grants = %v, want %v", grants.values(), want)
	}
}

func TestShellSingleQuote(t *testing.T) {
	if got := shellSingleQuote("abc"); got != "abc" {
		t.Fatalf("shellSingleQuote(abc) = %q", got)
	}
	if got := shellSingleQuote("a'b"); got != `a'\''b` {
		t.Fatalf("shellSingleQuote(a'b) = %q", got)
	}
}

func TestSafeCredentialEnv(t *testing.T) {
	envelope := model.CredentialEnvelope{
		Credential: model.Credential{AccessKeyID: "LTAI1234", AccessKeySecret: "secret", SecurityToken: "token"},
		Env: []model.EnvVar{
			{Name: "ALIBABA_CLOUD_ACCESS_KEY_ID", Value: "LTAI1234"},
			{Name: "ALIBABA_CLOUD_SECURITY_TOKEN", Value: "token"},
			{Name: "AWS_SESSION_TOKEN", Value: "aws"},
			{Name: "CSG_LEASE_ID", Value: "lea_test01"},
			// A compromised server must not be able to set any of these.
			{Name: "X; touch /tmp/pwned; Y", Value: "v"},
			{Name: "LD_PRELOAD", Value: "/tmp/evil.so"},
			{Name: "PATH", Value: "/tmp"},
			{Name: "BASH_ENV", Value: "/tmp/x"},
			{Name: "alibaba_cloud_lower", Value: "v"},
			{Name: "ALIBABA_CLOUD_$(id)", Value: "v"},
			{Name: "ALIBABA_CLOUD_A\nB", Value: "v"},
		},
	}
	got := map[string]string{}
	for _, kv := range safeCredentialEnv(&envelope) {
		got[kv.Name] = kv.Value
	}
	want := map[string]string{"ALIBABA_CLOUD_ACCESS_KEY_ID": "LTAI1234", "ALIBABA_CLOUD_SECURITY_TOKEN": "token",
		"AWS_SESSION_TOKEN": "aws", "CSG_LEASE_ID": "lea_test01"}
	if len(got) != len(want) {
		t.Fatalf("env = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("env[%s] = %q", k, got[k])
		}
	}

	// Fallback when the server sends no env list.
	fallback := safeCredentialEnv(&model.CredentialEnvelope{Credential: model.Credential{
		AccessKeyID: "AK", AccessKeySecret: "SK", SecurityToken: "ST",
	}})
	if len(fallback) != 3 || fallback[1].Name != "ALIBABA_CLOUD_ACCESS_KEY_SECRET" || fallback[1].Value != "SK" {
		t.Fatalf("fallback = %v", fallback)
	}
}

// TestUnreachableServerIsOperationError proves network failures exit 1, not 2/3.
func TestUnreachableServerIsOperationError(t *testing.T) {
	ta := newTestApp(t)
	ta.useServer("http://127.0.0.1:1", "csg_adm_test")
	code := ta.run("caps", "list")
	if code != ExitOperationErr {
		t.Fatalf("exit = %d, want %d; stderr = %q", code, ExitOperationErr, ta.errOut())
	}
	if !strings.Contains(ta.errOut(), "cannot reach control plane") {
		t.Fatalf("stderr = %q", ta.errOut())
	}
}

// TestResponseMissingEnvelopeIsError covers malformed server responses.
func TestResponseMissingEnvelopeIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[],"total":0}`)
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, "csg_adm_test")
	if code := ta.run("caps", "list"); code != ExitOperationErr {
		t.Fatalf("exit = %d, want %d; stderr = %q", code, ExitOperationErr, ta.errOut())
	}
	if !strings.Contains(ta.errOut(), "data envelope") {
		t.Fatalf("stderr = %q", ta.errOut())
	}
}
