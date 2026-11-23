package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// canary values used to prove secrets never leave the vault/credential path.
const (
	canaryBrokerAKID   = "LTAIcanaryBrokerAKID42"
	canaryBrokerSecret = "csg-canary-broker-secret-7f3a9b1c"
)

// createCanaryProvider creates an sts cloud account holding canary credentials.
func createCanaryProvider(t *testing.T, a *accessEnv) model.Provider {
	t.Helper()
	rec := a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts", model.CreateProviderInput{
		Name:            "canary-sts",
		Type:            model.ProviderAliyun,
		Mode:            model.ModeSTS,
		Region:          "cn-hangzhou",
		RoleARN:         "acs:ram::6543210987654321:role/canary",
		AccessKeyID:     canaryBrokerAKID,
		AccessKeySecret: canaryBrokerSecret,
	})
	requireStatus(t, rec, http.StatusCreated)
	return decodeEnvelope[model.Provider](t, rec)
}

// TestProviderSecretsNeverReturnedByAPI proves the broker AccessKey pair is
// write-only across every supervisor, person and agent response.
func TestProviderSecretsNeverReturnedByAPI(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	provider := createCanaryProvider(t, a)

	// Ask for access and fetch the (fake, short-lived) credential.
	req := a.request(accessInput("ecs", "read"))
	if req.Status != model.LeaseActive {
		t.Fatalf("request status = %q", req.Status)
	}

	responses := map[string]string{
		"create account": a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts", model.CreateProviderInput{
			Name: "canary-2", Type: model.ProviderAliyun, Mode: model.ModeSTS, Region: "cn-hangzhou",
			RoleARN: "acs:ram::7777777777777777:role/canary", AccessKeyID: canaryBrokerAKID, AccessKeySecret: canaryBrokerSecret,
		}).Body.String(),
		"list accounts":    a.sup.do(http.MethodGet, "/api/v1/supervisor/accounts", nil).Body.String(),
		"get account":      a.sup.do(http.MethodGet, "/api/v1/supervisor/accounts/"+provider.ID, nil).Body.String(),
		"test account":     a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts/"+provider.ID+"/test", nil).Body.String(),
		"my accounts":      a.sup.do(http.MethodGet, "/api/v1/me/accounts", nil).Body.String(),
		"agent's accounts": a.do(http.MethodGet, "/api/v1/agent/accounts", a.token, nil).Body.String(),
		"audit list":       a.sup.do(http.MethodGet, "/api/v1/supervisor/audit?limit=200", nil).Body.String(),
		"rotate account": a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts/"+provider.ID+"/rotate", model.RotateProviderCredentialInput{
			AccessKeyID: canaryBrokerAKID, AccessKeySecret: canaryBrokerSecret,
		}).Body.String(),
	}
	for name, body := range responses {
		if body == "" {
			t.Errorf("%s: empty response", name)
		}
		if strings.Contains(body, canaryBrokerAKID) {
			t.Errorf("%s response leaks the raw broker AccessKey ID", name)
		}
		if strings.Contains(body, canaryBrokerSecret) {
			t.Errorf("%s response leaks the broker AccessKey secret", name)
		}
	}

	// The masked form IS allowed.
	if !strings.Contains(a.sup.do(http.MethodGet, "/api/v1/supervisor/accounts", nil).Body.String(), "LTAI****ID42") {
		t.Fatal("masked AccessKey ID missing from the account list")
	}

	// The credential endpoint exposes only the request's credential, never the broker pair.
	credRec := a.credential(req.ID)
	requireStatus(t, credRec, http.StatusOK)
	credBody := credRec.Body.String()
	if strings.Contains(credBody, canaryBrokerAKID) || strings.Contains(credBody, canaryBrokerSecret) {
		t.Fatal("credential endpoint response leaks the broker credential")
	}
	envelope := decodeEnvelope[model.CredentialEnvelope](t, credRec)
	if envelope.Credential.AccessKeyID == "" || envelope.Credential.AccessKeySecret == "" {
		t.Fatal("credential endpoint did not return the request's credential")
	}

	// Audit metadata must never contain either secret.
	events, _, err := a.srv.db.ListAudit(context.Background(), store.AuditFilter{Limit: 200})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	for _, ev := range events {
		raw, _ := json.Marshal(ev)
		if bytes.Contains(raw, []byte(canaryBrokerSecret)) || bytes.Contains(raw, []byte(canaryBrokerAKID)) {
			t.Fatalf("audit event %d (%s) contains a secret", ev.Seq, ev.Action)
		}
	}
}

// TestNoSecretsInDatabaseLogsOrAudit scans the on-disk database files, access
// logs and audit events for plaintext secrets (A8).
func TestNoSecretsInDatabaseLogsOrAudit(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	createCanaryProvider(t, a)

	// Generate traffic including credential issuance and fetch.
	req := a.request(accessInput("ecs", "read"))
	envelope, rec := a.fetchCredential(a.token, req.ID)
	requireStatus(t, rec, http.StatusOK)
	a.sup.do(http.MethodGet, "/api/v1/supervisor/audit?limit=200", nil)
	a.mei.do(http.MethodGet, "/api/v1/me/requests", nil)

	canaries := map[string]string{
		"broker AccessKey ID":       canaryBrokerAKID,
		"broker secret":             canaryBrokerSecret,
		"agent token":               a.token,
		"session cookie":            a.sup.cookie.Value,
		"CSRF token":                a.sup.csrf,
		"TOTP secret":               a.sup.secret,
		"password":                  testPassword,
		"supervisor's setup code":   a.supervisor.SetupCode,
		"request credential secret": envelope.Credential.AccessKeySecret,
	}
	for name, canary := range canaries {
		if canary == "" {
			t.Fatalf("no value to look for: %s", name)
		}
	}

	// Nothing sensitive may appear in the access log (which also proves
	// Authorization and Cookie values are never logged).
	logOutput := a.logs.String()
	if logOutput == "" {
		t.Fatal("access log is empty")
	}
	for name, canary := range canaries {
		if strings.Contains(logOutput, canary) {
			t.Errorf("server log leaks %s", name)
		}
	}
	if lower := strings.ToLower(logOutput); strings.Contains(lower, "authorization") || strings.Contains(lower, "cookie") {
		t.Error("server log contains an Authorization or Cookie header")
	}

	// Close the server so SQLite checkpoints/removes the WAL before scanning.
	if err := a.srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The CSRF token is stored as issued; it is useless without the session
	// cookie, which is stored only as a hash.
	delete(canaries, "CSRF token")
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, store.DBFileName) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(a.dir, name))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		scanned++
		for label, canary := range canaries {
			if bytes.Contains(data, []byte(canary)) {
				t.Errorf("database file %s contains plaintext %s", name, label)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no database files were scanned")
	}

	// The audit chain still verifies after reopen.
	db, err := store.Open(context.Background(), a.dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer db.Close()
	result, err := db.VerifyAudit(context.Background())
	if err != nil || !result.OK {
		t.Fatalf("audit verify after reopen = %+v, %v", result, err)
	}
}

// TestAccessLogFormat checks the documented "method path status duration_ms"
// line format and that paths with query strings are logged without the query.
func TestAccessLogFormat(t *testing.T) {
	a := newAccessEnv(t, "")
	env := a.testEnv
	env.logs.Reset()
	env.do(http.MethodGet, "/healthz", "", nil)
	a.sup.do(http.MethodGet, "/api/v1/supervisor/audit?secret=should-not-be-logged", nil)

	lines := strings.Split(strings.TrimSpace(env.logs.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected access log lines, got %q", env.logs.String())
	}
	var healthLine, auditLine string
	for _, line := range lines {
		if strings.Contains(line, "GET /healthz") {
			healthLine = line
		}
		if strings.Contains(line, "GET /api/v1/supervisor/audit") {
			auditLine = line
		}
	}
	if healthLine == "" || !strings.Contains(healthLine, " 200 ") {
		t.Fatalf("health access log line = %q", healthLine)
	}
	if auditLine == "" {
		t.Fatalf("audit access log line missing: %q", env.logs.String())
	}
	if strings.Contains(auditLine, "should-not-be-logged") {
		t.Fatalf("access log leaked the query string: %q", auditLine)
	}
	if !strings.HasSuffix(auditLine, "ms") {
		t.Fatalf("access log line does not end with a duration: %q", auditLine)
	}
}

// TestRequestBodyLimit checks the 1 MiB request body cap, for an agent and
// for a person.
func TestRequestBodyLimit(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	huge := make([]byte, maxRequestBody+1024)
	for i := range huge {
		huge[i] = 'a'
	}
	body := append([]byte(`{"cloud_account_id":"`), huge...)
	body = append(body, []byte(`"}`)...)
	before := a.leaseCount()
	rec := a.do(http.MethodPost, "/api/v1/agent/access-requests", a.token, body)
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	body = append([]byte(`{"username":"`), huge...)
	body = append(body, []byte(`"}`)...)
	rec = a.sup.do(http.MethodPost, "/api/v1/supervisor/people", body)
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	if a.leaseCount() != before {
		t.Fatal("an oversized request was stored")
	}
}
