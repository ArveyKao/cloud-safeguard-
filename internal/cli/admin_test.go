package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

func TestCapsListAndShow(t *testing.T) {
	caps := []model.Capability{
		{
			ID: "aliyun.cloud.read", Name: "Cloud read-only inventory", ProviderType: model.ProviderAliyun,
			Risk: model.RiskLow, PolicyTemplate: `{"Version":"1","Statement":[]}`,
			DefaultTTLSeconds: 900, MaxTTLSeconds: 1800, Enabled: true, Builtin: true,
		},
		{
			ID: "aliyun.dns.manage", Name: "Manage DNS records", ProviderType: model.ProviderAliyun,
			Risk: model.RiskMedium, PolicyTemplate: `{"Version":"1","Statement":[]}`,
			DefaultTTLSeconds: 900, MaxTTLSeconds: 1800, Enabled: true, Builtin: true,
			Params: []model.CapabilityParam{{Name: "domain", Required: true, Pattern: `^[a-z]+$`, Description: "domain"}},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/admin/capabilities" {
			t.Errorf("unexpected path %s", r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "nope")
			return
		}
		requireAuth(t, r, adminTokenA)
		writeEnvelope(w, http.StatusOK, model.ListResponse[model.Capability]{Items: caps, Total: len(caps)})
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, adminTokenA)

	if code := ta.run("caps", "list"); code != ExitOK {
		t.Fatalf("caps list exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "aliyun.cloud.read") || !strings.Contains(ta.out(), "aliyun.dns.manage") {
		t.Fatalf("caps list output = %q", ta.out())
	}

	ta.stdout.Reset()
	if code := ta.run("caps", "list", "--json"); code != ExitOK {
		t.Fatalf("caps list --json exit = %d", code)
	}
	var listed model.ListResponse[model.Capability]
	if err := json.Unmarshal(ta.stdout.Bytes(), &listed); err != nil {
		t.Fatalf("caps list --json output: %v", err)
	}
	if listed.Total != 2 || len(listed.Items) != 2 {
		t.Fatalf("caps list --json payload = %+v", listed)
	}

	ta.stdout.Reset()
	if code := ta.run("caps", "show", "aliyun.dns.manage"); code != ExitOK {
		t.Fatalf("caps show exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "aliyun.dns.manage") || !strings.Contains(ta.out(), "domain") {
		t.Fatalf("caps show output = %q", ta.out())
	}

	ta.stdout.Reset()
	ta.stderr.Reset()
	if code := ta.run("caps", "show", "does.not.exist"); code != ExitOperationErr {
		t.Fatalf("caps show unknown exit = %d, want %d", code, ExitOperationErr)
	}
	if !strings.Contains(ta.errOut(), "not found") {
		t.Fatalf("stderr = %q", ta.errOut())
	}
}

func TestAgentsCommands(t *testing.T) {
	agent := model.Agent{
		ID: "agt_demo1", Name: "claude-code", Description: "primary", Status: model.AgentActive,
		Grants: []string{"aliyun.cloud.read"}, MaxTTLSeconds: 3600, MaxConcurrentLeases: 3,
	}
	var createdInput model.CreateAgentInput
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r, adminTokenA)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/admin/agents":
			writeEnvelope(w, http.StatusOK, model.ListResponse[model.Agent]{Items: []model.Agent{agent}, Total: 1})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/admin/agents/agt_demo1":
			writeEnvelope(w, http.StatusOK, agent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/agents":
			decodeBody(t, r, &createdInput)
			created := agent
			created.ID = "agt_new"
			writeEnvelope(w, http.StatusCreated, model.AgentWithToken{Agent: created, Token: "csg_agt_NEWTOKEN"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/agents/agt_demo1/suspend":
			suspended := agent
			suspended.Status = model.AgentSuspended
			writeEnvelope(w, http.StatusOK, suspended)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/agents/agt_demo1/activate":
			writeEnvelope(w, http.StatusOK, agent)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/agents/agt_demo1/token/rotate":
			writeEnvelope(w, http.StatusOK, model.AgentWithToken{Agent: agent, Token: "csg_agt_ROTATED"})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected")
		}
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, adminTokenA)

	if code := ta.run("agents", "list"); code != ExitOK {
		t.Fatalf("agents list exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "agt_demo1") {
		t.Fatalf("agents list output = %q", ta.out())
	}

	ta.stdout.Reset()
	if code := ta.run("agents", "get", "agt_demo1", "--json"); code != ExitOK {
		t.Fatalf("agents get exit = %d", code)
	}
	var got model.Agent
	if err := json.Unmarshal(ta.stdout.Bytes(), &got); err != nil {
		t.Fatalf("agents get --json: %v", err)
	}
	if got.Name != "claude-code" {
		t.Fatalf("agents get payload = %+v", got)
	}

	ta.stdout.Reset()
	if code := ta.run("agents", "create", "--name", "new-agent", "--description", "d",
		"--capability", "aliyun.cloud.read,aliyun.dns.manage", "--capability", "aliyun.ecs.instance.ops",
		"--max-ttl", "30m", "--max-concurrent", "2"); code != ExitOK {
		t.Fatalf("agents create exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "csg_agt_NEWTOKEN") {
		t.Fatalf("agents create output missing token: %q", ta.out())
	}
	if createdInput.Name != "new-agent" || createdInput.Description != "d" {
		t.Fatalf("create input = %+v", createdInput)
	}
	wantGrants := []string{"aliyun.cloud.read", "aliyun.dns.manage", "aliyun.ecs.instance.ops"}
	if strings.Join(createdInput.Grants, ",") != strings.Join(wantGrants, ",") {
		t.Fatalf("create grants = %v, want %v", createdInput.Grants, wantGrants)
	}
	if createdInput.MaxTTLSeconds != 1800 || createdInput.MaxConcurrentLeases != 2 {
		t.Fatalf("create limits = %+v", createdInput)
	}
	// Token appears exactly once (one-time display).
	if strings.Count(ta.out(), "csg_agt_NEWTOKEN") != 1 {
		t.Fatalf("new token appeared more than once: %q", ta.out())
	}

	ta.stdout.Reset()
	if code := ta.run("agents", "suspend", "agt_demo1"); code != ExitOK {
		t.Fatalf("agents suspend exit = %d", code)
	}
	if !strings.Contains(ta.out(), "suspended") {
		t.Fatalf("suspend output = %q", ta.out())
	}
	if code := ta.run("agents", "activate", "agt_demo1"); code != ExitOK {
		t.Fatalf("agents activate exit = %d", code)
	}
	ta.stdout.Reset()
	if code := ta.run("agents", "rotate-token", "agt_demo1"); code != ExitOK {
		t.Fatalf("agents rotate-token exit = %d", code)
	}
	if !strings.Contains(ta.out(), "csg_agt_ROTATED") {
		t.Fatalf("rotate output = %q", ta.out())
	}
}

func TestAgentsCreateValidation(t *testing.T) {
	ta := newTestApp(t)
	ta.useServer("http://127.0.0.1:1", adminTokenA)
	if code := ta.run("agents", "create"); code != ExitUsage {
		t.Fatalf("create without name exit = %d, want %d", code, ExitUsage)
	}
	if code := ta.run("agents", "create", "--name", "x", "--max-ttl", "bogus"); code != ExitUsage {
		t.Fatalf("create bad ttl exit = %d, want %d", code, ExitUsage)
	}
}

func TestProvidersAddRotateTest(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secretFile, []byte("s3cret-value\n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	var created model.CreateProviderInput
	var rotated model.RotateProviderCredentialInput
	provider := model.Provider{
		ID: "prv_demo1", Name: "demo", Type: model.ProviderAliyun, Mode: model.ModeSTS,
		Region: "cn-hangzhou", AccessKeyIDMasked: "LTAI****cret", Status: model.ProviderActive,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r, adminTokenA)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/providers":
			decodeBody(t, r, &created)
			writeEnvelope(w, http.StatusCreated, provider)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/providers/prv_demo1/rotate":
			decodeBody(t, r, &rotated)
			writeEnvelope(w, http.StatusOK, provider)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/providers/prv_demo1/test":
			writeEnvelope(w, http.StatusOK, providerTestResult{OK: true, Message: "credentials valid"})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected")
		}
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, adminTokenA)

	if code := ta.run("providers", "add", "--name", "demo", "--mode", "sts", "--region", "cn-hangzhou",
		"--role-arn", "acs:ram::1234567890123456:role/csg-demo",
		"--access-key-id", "LTAI5tDemoBroker", "--access-key-secret-file", secretFile); code != ExitOK {
		t.Fatalf("providers add exit = %d, stderr = %s", code, ta.errOut())
	}
	if created.Name != "demo" || created.Mode != model.ModeSTS || created.RoleARN == "" {
		t.Fatalf("create input = %+v", created)
	}
	if created.AccessKeyID != "LTAI5tDemoBroker" || created.AccessKeySecret != "s3cret-value" {
		t.Fatalf("create input credentials wrong: AK=%q", created.AccessKeyID)
	}
	// Never echo the secret.
	if strings.Contains(ta.out(), "s3cret-value") || strings.Contains(ta.errOut(), "s3cret-value") {
		t.Fatalf("secret leaked to CLI output: stdout=%q stderr=%q", ta.out(), ta.errOut())
	}

	// Rotate reading the secret from stdin.
	ta.stdout.Reset()
	ta.stderr.Reset()
	ta.app.Stdin = strings.NewReader("rotated-secret\n")
	if code := ta.run("providers", "rotate", "prv_demo1", "--access-key-id", "LTAI5tRotated",
		"--access-key-secret-stdin"); code != ExitOK {
		t.Fatalf("providers rotate exit = %d, stderr = %s", code, ta.errOut())
	}
	if rotated.AccessKeyID != "LTAI5tRotated" || rotated.AccessKeySecret != "rotated-secret" {
		t.Fatalf("rotate input = %+v", rotated)
	}
	if strings.Contains(ta.out(), "rotated-secret") || strings.Contains(ta.errOut(), "rotated-secret") {
		t.Fatalf("rotated secret leaked: %q", ta.out())
	}

	ta.stdout.Reset()
	if code := ta.run("providers", "test", "prv_demo1"); code != ExitOK {
		t.Fatalf("providers test exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "ok=true") {
		t.Fatalf("providers test output = %q", ta.out())
	}
}

func TestProvidersAddValidation(t *testing.T) {
	ta := newTestApp(t)
	ta.useServer("http://127.0.0.1:1", adminTokenA)
	tests := [][]string{
		{"providers", "add", "--mode", "mock", "--region", "cn-hangzhou"},                 // no name
		{"providers", "add", "--name", "p", "--mode", "bogus", "--region", "cn-hangzhou"}, // bad mode
		{"providers", "add", "--name", "p", "--mode", "mock"},                             // no region
		{"providers", "add", "--name", "p", "--mode", "sts", "--region", "cn-hangzhou"},   // no sts creds
		{"providers", "update", "prv_1"},                                                  // no changes
		{"providers", "update", "prv_1", "--status", "bogus"},                             // bad status
		{"providers", "rotate", "prv_1"},                                                  // no key
		{"providers", "add", "--name", "p", "--mode", "mock", "--region", "r", "--access-key-secret-file", "", "--access-key-secret-stdin"},
	}
	for _, args := range tests {
		if code := ta.run(args...); code != ExitUsage {
			t.Fatalf("%v exit = %d, want %d; stderr = %q", args, code, ExitUsage, ta.errOut())
		}
	}
}

func TestProvidersTestFailureExitsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusOK, providerTestResult{OK: false, Message: "signing key missing"})
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, adminTokenA)
	if code := ta.run("providers", "test", "prv_1"); code != ExitOperationErr {
		t.Fatalf("exit = %d, want %d", code, ExitOperationErr)
	}
	if !strings.Contains(ta.errOut(), "provider test failed") {
		t.Fatalf("stderr = %q", ta.errOut())
	}
}

func TestAdminLeaseCommands(t *testing.T) {
	var approved model.ApproveLeaseInput
	var denied model.DenyLeaseInput
	var revoked model.RevokeLeaseInput
	var listQuery string
	activeLease := testLease(model.LeaseActive)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r, adminTokenA)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/admin/leases":
			listQuery = r.URL.RawQuery
			writeEnvelope(w, http.StatusOK, model.ListResponse[model.Lease]{
				Items: []model.Lease{testLease(model.LeasePending)}, Total: 1,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/admin/leases/lea_test01":
			writeEnvelope(w, http.StatusOK, activeLease)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/leases/lea_test01/approve":
			decodeBody(t, r, &approved)
			writeEnvelope(w, http.StatusOK, activeLease)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/leases/lea_test01/deny":
			decodeBody(t, r, &denied)
			writeEnvelope(w, http.StatusOK, testLease(model.LeaseDenied))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/admin/leases/lea_test01/revoke":
			decodeBody(t, r, &revoked)
			writeEnvelope(w, http.StatusOK, testLease(model.LeaseRevoked))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected")
		}
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, adminTokenA)

	if code := ta.run("leases", "list", "--status", "pending", "--agent", "agt_1", "--limit", "10", "--json"); code != ExitOK {
		t.Fatalf("leases list exit = %d, stderr = %s", code, ta.errOut())
	}
	for _, want := range []string{"status=pending", "agent_id=agt_1", "limit=10"} {
		if !strings.Contains(listQuery, want) {
			t.Fatalf("list query = %q, missing %q", listQuery, want)
		}
	}
	var listed model.ListResponse[model.Lease]
	if err := json.Unmarshal(ta.stdout.Bytes(), &listed); err != nil {
		t.Fatalf("leases list --json: %v", err)
	}
	if listed.Total != 1 {
		t.Fatalf("leases list payload = %+v", listed)
	}

	ta.stdout.Reset()
	if code := ta.run("leases", "get", "lea_test01"); code != ExitOK {
		t.Fatalf("leases get exit = %d", code)
	}
	if !strings.Contains(ta.out(), "lea_test01") || !strings.Contains(ta.out(), "decision:") {
		t.Fatalf("leases get output = %q", ta.out())
	}

	ta.stdout.Reset()
	if code := ta.run("leases", "approve", "lea_test01", "--ttl", "10m", "--note", "ok"); code != ExitOK {
		t.Fatalf("leases approve exit = %d, stderr = %s", code, ta.errOut())
	}
	if approved.TTLSeconds != 600 || approved.Note != "ok" {
		t.Fatalf("approve input = %+v", approved)
	}

	if code := ta.run("leases", "deny", "lea_test01"); code != ExitUsage {
		t.Fatalf("deny without reason exit = %d, want %d", code, ExitUsage)
	}
	if code := ta.run("leases", "deny", "lea_test01", "--reason", "not needed"); code != ExitOK {
		t.Fatalf("leases deny exit = %d, stderr = %s", code, ta.errOut())
	}
	if denied.Reason != "not needed" {
		t.Fatalf("deny input = %+v", denied)
	}

	if code := ta.run("leases", "revoke", "lea_test01"); code != ExitOK {
		t.Fatalf("leases revoke exit = %d", code)
	}
	if revoked.Reason != "revoked by operator" {
		t.Fatalf("revoke input = %+v", revoked)
	}
}

func TestLeasesApproveFailedExitsOne(t *testing.T) {
	failed := testLease(model.LeaseActive)
	failed.Status = model.LeaseFailed
	failed.FailureReason = "InvalidAccessKeyId.NotFound: bad key"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusOK, failed)
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, adminTokenA)
	if code := ta.run("leases", "approve", "lea_test01"); code != ExitOperationErr {
		t.Fatalf("exit = %d, want %d; stderr = %q", code, ExitOperationErr, ta.errOut())
	}
	if !strings.Contains(ta.errOut(), "could not mint") {
		t.Fatalf("stderr = %q", ta.errOut())
	}
}

func TestAuditCommands(t *testing.T) {
	var auditQuery string
	event := model.AuditEvent{
		Seq: 3, ID: "evt_3", Action: "lease.denied", ActorType: "agent",
		ActorID: "agt_1", ActorName: "claude-code", Status: "denied", Severity: "warning",
		TargetType: "lease", TargetID: "lea_test01",
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r, adminTokenA)
		switch r.URL.Path {
		case "/api/v1/admin/audit":
			auditQuery = r.URL.RawQuery
			writeEnvelope(w, http.StatusOK, model.ListResponse[model.AuditEvent]{Items: []model.AuditEvent{event}, Total: 1})
		case "/api/v1/admin/audit/verify":
			writeEnvelope(w, http.StatusOK, model.AuditVerifyResult{OK: true, Events: 7, Message: "chain ok"})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected")
		}
	}))
	defer srv.Close()
	_ = mux

	ta := newTestApp(t)
	ta.useServer(srv.URL, adminTokenA)

	if code := ta.run("audit", "list", "--action", "lease.denied", "--severity", "warning", "--limit", "5"); code != ExitOK {
		t.Fatalf("audit list exit = %d, stderr = %s", code, ta.errOut())
	}
	for _, want := range []string{"action=lease.denied", "severity=warning", "limit=5"} {
		if !strings.Contains(auditQuery, want) {
			t.Fatalf("audit query = %q missing %q", auditQuery, want)
		}
	}
	if !strings.Contains(ta.out(), "lease.denied") {
		t.Fatalf("audit list output = %q", ta.out())
	}

	ta.stdout.Reset()
	if code := ta.run("audit", "verify", "--json"); code != ExitOK {
		t.Fatalf("audit verify exit = %d, stderr = %s", code, ta.errOut())
	}
	var verify model.AuditVerifyResult
	if err := json.Unmarshal(ta.stdout.Bytes(), &verify); err != nil {
		t.Fatalf("audit verify --json: %v", err)
	}
	if !verify.OK || verify.Events != 7 {
		t.Fatalf("audit verify payload = %+v", verify)
	}

	// Negative verify result exits 1.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, http.StatusOK, model.AuditVerifyResult{OK: false, FirstInvalidSeq: 3, Message: "hash mismatch"})
	}))
	defer broken.Close()
	ta = newTestApp(t)
	ta.useServer(broken.URL, adminTokenA)
	if code := ta.run("audit", "verify"); code != ExitOperationErr {
		t.Fatalf("broken chain exit = %d, want %d", code, ExitOperationErr)
	}
	if !strings.Contains(ta.errOut(), "verification failed") {
		t.Fatalf("stderr = %q", ta.errOut())
	}
}

func TestPolicyCommands(t *testing.T) {
	defaults := model.DefaultPolicySettings()
	var updated model.PolicySettings
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r, adminTokenA)
		switch r.Method {
		case http.MethodGet:
			writeEnvelope(w, http.StatusOK, defaults)
		case http.MethodPut:
			decodeBody(t, r, &updated)
			writeEnvelope(w, http.StatusOK, updated)
		default:
			t.Errorf("unexpected method %s", r.Method)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected")
		}
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, adminTokenA)

	if code := ta.run("policy", "show", "--json"); code != ExitOK {
		t.Fatalf("policy show exit = %d, stderr = %s", code, ta.errOut())
	}
	var shown model.PolicySettings
	if err := json.Unmarshal(ta.stdout.Bytes(), &shown); err != nil {
		t.Fatalf("policy show --json: %v", err)
	}
	if shown.MaxLeaseTTLSeconds != defaults.MaxLeaseTTLSeconds {
		t.Fatalf("policy show payload = %+v", shown)
	}

	ta.stdout.Reset()
	if code := ta.run("policy", "set", "--auto-approve-max-risk", "medium", "--auto-approve-max-ttl", "10m",
		"--max-concurrent", "5", "--require-reason-risk", "high"); code != ExitOK {
		t.Fatalf("policy set exit = %d, stderr = %s", code, ta.errOut())
	}
	if updated.AutoApproveMaxRisk != model.RiskMedium {
		t.Fatalf("updated auto risk = %q", updated.AutoApproveMaxRisk)
	}
	if updated.AutoApproveMaxTTLSeconds != 600 {
		t.Fatalf("updated auto ttl = %d", updated.AutoApproveMaxTTLSeconds)
	}
	if updated.MaxConcurrentLeasesPerAgent != 5 {
		t.Fatalf("updated max concurrent = %d", updated.MaxConcurrentLeasesPerAgent)
	}
	if updated.RequireReasonForRisk != model.RiskHigh {
		t.Fatalf("updated require reason = %q", updated.RequireReasonForRisk)
	}
	// Not-provided settings are preserved.
	if updated.MaxLeaseTTLSeconds != defaults.MaxLeaseTTLSeconds || updated.PendingTimeoutSeconds != defaults.PendingTimeoutSeconds {
		t.Fatalf("unprovided settings changed: %+v", updated)
	}

	// No flags is a usage error.
	if code := ta.run("policy", "set"); code != ExitUsage {
		t.Fatalf("policy set without flags exit = %d, want %d", code, ExitUsage)
	}
	// Invalid combination is rejected client-side.
	if code := ta.run("policy", "set", "--max-lease-ttl", "1m"); code != ExitUsage {
		t.Fatalf("policy set invalid exit = %d, want %d; stderr = %q", code, ExitUsage, ta.errOut())
	}
	if code := ta.run("policy", "set", "--auto-approve-max-ttl", "bogus"); code != ExitUsage {
		t.Fatalf("policy set bad duration exit = %d, want %d", code, ExitUsage)
	}
}
