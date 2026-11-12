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

// createCanaryProvider creates an sts provider holding canary credentials.
func createCanaryProvider(t *testing.T, env *testEnv) model.Provider {
	t.Helper()
	rec := env.admin(http.MethodPost, "/api/v1/admin/providers", model.CreateProviderInput{
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
// write-only across every admin/agent response.
func TestProviderSecretsNeverReturnedByAPI(t *testing.T) {
	env := newTestEnv(t, true)
	provider := createCanaryProvider(t, env)

	// Create a lease and fetch the (fake, short-lived) credential.
	lease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "secret exposure test",
	})
	if lease.Status != model.LeaseActive {
		t.Fatalf("lease status = %q", lease.Status)
	}

	responses := map[string]string{
		"create provider": env.admin(http.MethodPost, "/api/v1/admin/providers", model.CreateProviderInput{
			Name: "canary-2", Type: model.ProviderAliyun, Mode: model.ModeSTS, Region: "cn-hangzhou",
			RoleARN: "acs:ram::7777777777777777:role/canary", AccessKeyID: canaryBrokerAKID, AccessKeySecret: canaryBrokerSecret,
		}).Body.String(),
		"list providers": env.admin(http.MethodGet, "/api/v1/admin/providers", nil).Body.String(),
		"get provider":   env.admin(http.MethodGet, "/api/v1/admin/providers/"+provider.ID, nil).Body.String(),
		"test provider":  env.admin(http.MethodPost, "/api/v1/admin/providers/"+provider.ID+"/test", nil).Body.String(),
		"overview":       env.admin(http.MethodGet, "/api/v1/admin/overview", nil).Body.String(),
		"audit list":     env.admin(http.MethodGet, "/api/v1/admin/audit?limit=200", nil).Body.String(),
		"provider rotate": env.admin(http.MethodPost, "/api/v1/admin/providers/"+provider.ID+"/rotate", model.RotateProviderCredentialInput{
			AccessKeyID: canaryBrokerAKID, AccessKeySecret: canaryBrokerSecret,
		}).Body.String(),
	}
	for name, body := range responses {
		if strings.Contains(body, canaryBrokerAKID) {
			t.Errorf("%s response leaks the raw broker AccessKey ID", name)
		}
		if strings.Contains(body, canaryBrokerSecret) {
			t.Errorf("%s response leaks the broker AccessKey secret", name)
		}
	}

	// The masked form IS allowed.
	if !strings.Contains(env.admin(http.MethodGet, "/api/v1/admin/providers", nil).Body.String(), "LTAI****ID42") {
		t.Fatal("masked AccessKey ID missing from provider list")
	}

	// The credential endpoint exposes only the lease credential, never the broker pair.
	credBody := env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases/"+lease.ID+"/credential", nil).Body.String()
	if strings.Contains(credBody, canaryBrokerAKID) || strings.Contains(credBody, canaryBrokerSecret) {
		t.Fatal("credential endpoint response leaks the broker credential")
	}
	envelope := decodeEnvelope[model.CredentialEnvelope](t, env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases/"+lease.ID+"/credential", nil))
	if !strings.Contains(credBody, envelope.Credential.AccessKeyID) {
		t.Fatal("credential endpoint did not return the lease credential")
	}

	// Audit metadata must never contain either secret.
	events, _, err := env.srv.db.ListAudit(context.Background(), store.AuditFilter{Limit: 200})
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
// logs and audit events for canary plaintext secrets (A8).
func TestNoSecretsInDatabaseLogsOrAudit(t *testing.T) {
	env := newTestEnv(t, true)
	createCanaryProvider(t, env)

	// Generate traffic including credential issuance and fetch.
	lease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "scan test",
	})
	envelope, rec := env.fetchCredential("claude-code", lease.ID)
	requireStatus(t, rec, http.StatusOK)
	env.admin(http.MethodGet, "/api/v1/admin/overview", nil)
	env.admin(http.MethodPost, "/api/v1/admin/login", nil)
	env.admin(http.MethodGet, "/api/v1/admin/audit?limit=200", nil)

	agentToken := env.agentTokens["claude-code"]
	adminToken := env.adminToken
	leaseSecret := envelope.Credential.AccessKeySecret

	// Nothing sensitive may appear in the access log (which also proves
	// Authorization values are never logged).
	logOutput := env.logs.String()
	if logOutput == "" {
		t.Fatal("access log is empty")
	}
	for name, canary := range map[string]string{
		"broker AccessKey ID":     canaryBrokerAKID,
		"broker secret":           canaryBrokerSecret,
		"agent token":             agentToken,
		"admin token":             adminToken,
		"lease credential secret": leaseSecret,
	} {
		if strings.Contains(logOutput, canary) {
			t.Errorf("server log leaks %s", name)
		}
	}
	if strings.Contains(strings.ToLower(logOutput), "authorization") {
		t.Error("server log contains an Authorization header")
	}

	// Close the server so SQLite checkpoints/removes the WAL before scanning.
	if err := env.srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	canaries := map[string]string{
		"broker AccessKey ID":     canaryBrokerAKID,
		"broker secret":           canaryBrokerSecret,
		"agent token":             agentToken,
		"admin token":             adminToken,
		"lease credential secret": leaseSecret,
	}
	entries, err := os.ReadDir(env.dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, store.DBFileName) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(env.dir, name))
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

	// The encrypted blobs exist and the audit chain still verifies after reopen.
	db, err := store.Open(context.Background(), env.dir)
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
	env := newTestEnv(t, true)
	env.do(http.MethodGet, "/healthz", "", nil)
	env.admin(http.MethodGet, "/api/v1/admin/overview?secret=should-not-be-logged", nil)

	lines := strings.Split(strings.TrimSpace(env.logs.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected access log lines, got %q", env.logs.String())
	}
	var healthLine, overviewLine string
	for _, line := range lines {
		if strings.Contains(line, "GET /healthz") {
			healthLine = line
		}
		if strings.Contains(line, "GET /api/v1/admin/overview") {
			overviewLine = line
		}
	}
	if healthLine == "" || !strings.Contains(healthLine, " 200 ") {
		t.Fatalf("health access log line = %q", healthLine)
	}
	if overviewLine == "" {
		t.Fatalf("overview access log line missing: %q", env.logs.String())
	}
	if strings.Contains(overviewLine, "should-not-be-logged") {
		t.Fatalf("access log leaked the query string: %q", overviewLine)
	}
	if !strings.HasSuffix(overviewLine, "ms") {
		t.Fatalf("access log line does not end with a duration: %q", overviewLine)
	}
}

// TestRequestBodyLimit checks the 1 MiB request body cap.
func TestRequestBodyLimit(t *testing.T) {
	env := newTestEnv(t, true)
	huge := make([]byte, maxRequestBody+1024)
	for i := range huge {
		huge[i] = 'a'
	}
	body := append([]byte(`{"capability_id":"`), huge...)
	body = append(body, []byte(`"}`)...)
	rec := env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases", body)
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
}
