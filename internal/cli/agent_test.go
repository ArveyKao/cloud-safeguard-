package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// accessView is a lease as the access-request endpoints return it.
func accessView(l model.Lease) model.AccessRequest {
	return model.AccessRequest{ID: l.ID, Status: l.Status, DeniedReason: l.DeniedReason}
}

// leaseServer wires a fake agent API for request/credential/revoke flows.
type leaseServer struct {
	mu          sync.Mutex
	createInput model.AccessRequestInput
	revokeInput model.RevokeLeaseInput
	getCalls    int
	revokeCalls int
	createLease model.Lease
	getLease    model.Lease
	credential  model.CredentialEnvelope
}

func (ls *leaseServer) handler(t *testing.T, token string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r, token)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/agent/access-requests":
			decodeBody(t, r, &ls.createInput)
			writeEnvelope(w, http.StatusCreated, accessView(ls.createLease))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/agent/access-requests/"):
			ls.mu.Lock()
			ls.getCalls++
			ls.mu.Unlock()
			writeEnvelope(w, http.StatusOK, accessView(ls.getLease))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/agent/leases/"):
			ls.mu.Lock()
			ls.getCalls++
			ls.mu.Unlock()
			writeEnvelope(w, http.StatusOK, ls.getLease)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/credential"):
			writeEnvelope(w, http.StatusOK, ls.credential)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/revoke"):
			decodeBody(t, r, &ls.revokeInput)
			ls.mu.Lock()
			ls.revokeCalls++
			ls.mu.Unlock()
			revoked := testLease(model.LeaseRevoked)
			writeEnvelope(w, http.StatusOK, revoked)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected")
		}
	})
}

func testCredentialEnvelope() model.CredentialEnvelope {
	return model.CredentialEnvelope{
		Credential: model.Credential{
			ProviderID:      "prv_demo1",
			ProviderMode:    model.ModeMock,
			LeaseID:         "lea_test01",
			AccessKeyID:     "LTAI1234567890ABCD",
			AccessKeySecret: "c2VjcmV0LXNlY3JldC1zZWNyZXQ",
			SecurityToken:   "cgk1.mock-token-value",
		},
		Env: []model.EnvVar{
			{Name: "ALIBABA_CLOUD_ACCESS_KEY_ID", Value: "LTAI1234567890ABCD"},
			{Name: "ALIBABA_CLOUD_ACCESS_KEY_SECRET", Value: "c2VjcmV0LXNlY3JldC1zZWNyZXQ"},
			{Name: "ALIBABA_CLOUD_SECURITY_TOKEN", Value: "cgk1.mock-token-value"},
			{Name: "CSG_LEASE_ID", Value: "lea_test01"},
			{Name: "CSG_SERVER", Value: "http://127.0.0.1:8787"},
			{Name: "CSG_CAPABILITY", Value: "aliyun.cloud.read"},
		},
	}
}

func TestCredentialExportAndJSON(t *testing.T) {
	ls := &leaseServer{createLease: testLease(model.LeaseActive), credential: testCredentialEnvelope()}
	srv := httptest.NewServer(ls.handler(t, agentTokenA))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)

	if code := ta.run("credential", "--lease", "lea_test01", "--export"); code != ExitOK {
		t.Fatalf("credential --export exit = %d, stderr = %s", code, ta.errOut())
	}
	for _, want := range []string{
		"export ALIBABA_CLOUD_ACCESS_KEY_ID='LTAI1234567890ABCD'",
		"export ALIBABA_CLOUD_SECURITY_TOKEN='cgk1.mock-token-value'",
		"export CSG_LEASE_ID='lea_test01'",
	} {
		if !strings.Contains(ta.out(), want) {
			t.Fatalf("export output = %q missing %q", ta.out(), want)
		}
	}

	ta.stdout.Reset()
	if code := ta.run("credential", "--lease", "lea_test01", "--json"); code != ExitOK {
		t.Fatalf("credential --json exit = %d", code)
	}
	var envelope model.CredentialEnvelope
	if err := json.Unmarshal(ta.stdout.Bytes(), &envelope); err != nil {
		t.Fatalf("credential --json output: %v", err)
	}
	if envelope.Credential.LeaseID != "lea_test01" || len(envelope.Env) == 0 {
		t.Fatalf("credential payload = %+v", envelope)
	}

	if code := ta.run("credential", "--lease", "lea_test01", "--json", "--export"); code != ExitUsage {
		t.Fatalf("credential conflicting flags exit = %d, want %d", code, ExitUsage)
	}
}

func TestCredentialInactiveLease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErrorEnvelope(w, http.StatusConflict, model.ErrCodeLeaseNotActive, "lease is not active")
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)
	if code := ta.run("credential", "--lease", "lea_x"); code != ExitOperationErr {
		t.Fatalf("exit = %d, want %d", code, ExitOperationErr)
	}
	if !strings.Contains(ta.errOut(), "lease is not active") {
		t.Fatalf("stderr = %q", ta.errOut())
	}
}

func TestExecInjectsEnvAndRevokes(t *testing.T) {
	ls := &leaseServer{createLease: testLease(model.LeaseActive), credential: testCredentialEnvelope()}
	srv := httptest.NewServer(ls.handler(t, agentTokenA))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)
	code := ta.run("exec", "--account", "1234567890123456", "--resource", "ecs", "--permission", "read", "--ttl", "10m", "--reason", "exec demo", "--",
		"sh", "-c", `printf '%s|%s|%s' "$ALIBABA_CLOUD_ACCESS_KEY_ID" "$ALIBABA_CLOUD_SECURITY_TOKEN" "$CSG_LEASE_ID"; exit 3`)
	if code != 3 {
		t.Fatalf("exit = %d, want child exit 3; stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "LTAI1234567890ABCD|cgk1.mock-token-value|lea_test01") {
		t.Fatalf("child stdout = %q (env not injected)", ta.out())
	}
	if strings.Contains(ta.errOut(), "cgk1.mock-token-value") || strings.Contains(ta.errOut(), "c2VjcmV0") {
		t.Fatalf("secret leaked to stderr summary: %q", ta.errOut())
	}
	if !strings.Contains(ta.errOut(), "csg exec: lea_test01") || !strings.Contains(ta.errOut(), "exit 3") {
		t.Fatalf("summary stderr = %q", ta.errOut())
	}
	if ls.revokeCalls != 1 {
		t.Fatalf("revoke calls = %d, want 1", ls.revokeCalls)
	}
	if in := ls.createInput; in.CloudAccountID != "1234567890123456" || in.Resource != "ecs" || in.Permission != "read" ||
		in.TTLSeconds != 600 || in.Reason != "exec demo" {
		t.Fatalf("request input = %+v", in)
	}
	if ls.revokeInput.Reason != "csg exec completed" {
		t.Fatalf("revoke reason = %q", ls.revokeInput.Reason)
	}
}

func TestExecKeepLeavesLeaseActive(t *testing.T) {
	ls := &leaseServer{createLease: testLease(model.LeaseActive), credential: testCredentialEnvelope()}
	srv := httptest.NewServer(ls.handler(t, agentTokenA))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)
	if code := ta.run("exec", "--account", "1234567890123456", "--resource", "ecs", "--permission", "read", "--ttl", "10m", "--keep", "--", "true"); code != ExitOK {
		t.Fatalf("exec --keep exit = %d, stderr = %s", code, ta.errOut())
	}
	if ls.revokeCalls != 0 {
		t.Fatalf("revoke calls = %d, want 0 with --keep", ls.revokeCalls)
	}
	if !strings.Contains(ta.errOut(), "kept") {
		t.Fatalf("summary stderr = %q", ta.errOut())
	}
}

func TestExecPendingTimesOut(t *testing.T) {
	pending := testLease(model.LeasePending)
	ls := &leaseServer{createLease: pending, getLease: pending, credential: testCredentialEnvelope()}
	srv := httptest.NewServer(ls.handler(t, agentTokenA))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)
	if code := ta.run("exec", "--account", "1234567890123456", "--resource", "ecs", "--permission", "read", "--ttl", "10m", "--wait", "1s", "--", "true"); code != ExitWaitTimeout {
		t.Fatalf("exit = %d, want %d; stderr = %s", code, ExitWaitTimeout, ta.errOut())
	}
}

func TestExecMissingCommandIsError(t *testing.T) {
	ls := &leaseServer{createLease: testLease(model.LeaseActive), credential: testCredentialEnvelope()}
	srv := httptest.NewServer(ls.handler(t, agentTokenA))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)
	// A command that cannot be started: revoke the unused credential and exit 1.
	if code := ta.run("exec", "--account", "1234567890123456", "--resource", "ecs", "--permission", "read", "--ttl", "10m", "--", "/definitely/not/a/command"); code != ExitOperationErr {
		t.Fatalf("exit = %d, want %d; stderr = %s", code, ExitOperationErr, ta.errOut())
	}
	if ls.revokeCalls != 1 {
		t.Fatalf("revoke calls = %d, want 1", ls.revokeCalls)
	}
}

func TestRevokeAgent(t *testing.T) {
	ls := &leaseServer{createLease: testLease(model.LeaseActive)}
	srv := httptest.NewServer(ls.handler(t, agentTokenA))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)
	if code := ta.run("revoke", "--lease", "lea_test01", "--reason", "done"); code != ExitOK {
		t.Fatalf("revoke exit = %d, stderr = %s", code, ta.errOut())
	}
	if ls.revokeInput.Reason != "done" {
		t.Fatalf("revoke input = %+v", ls.revokeInput)
	}
	if !strings.Contains(ta.out(), "request lea_test01 revoked") {
		t.Fatalf("output = %q", ta.out())
	}

	ta.stdout.Reset()
	ta.stderr.Reset()
	if code := ta.run("revoke", "--request", "lea_test01", "--reason", "alias"); code != ExitOK {
		t.Fatalf("revoke --request exit = %d, stderr = %s", code, ta.errOut())
	}
	if ls.revokeInput.Reason != "alias" {
		t.Fatalf("revoke --request input = %+v", ls.revokeInput)
	}
	if !strings.Contains(ta.out(), "request lea_test01 revoked") {
		t.Fatalf("revoke --request output = %q", ta.out())
	}
}

func TestLeasesMine(t *testing.T) {
	item := testAccessLease(model.LeaseActive)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r, agentTokenA)
		switch {
		case r.URL.Path == "/api/v1/agent/leases" && r.Method == http.MethodGet:
			if got := r.URL.Query().Get("status"); got != "" && got != "active" {
				t.Errorf("status query = %q", got)
			}
			writeEnvelope(w, http.StatusOK, model.ListResponse[model.Lease]{Items: []model.Lease{item}, Total: 1})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/agent/leases/"):
			writeEnvelope(w, http.StatusOK, item)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected")
		}
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)
	if code := ta.run("leases", "mine", "--status", "active", "--json"); code != ExitOK {
		t.Fatalf("leases mine exit = %d, stderr = %s", code, ta.errOut())
	}
	var listed model.ListResponse[model.Lease]
	if err := json.Unmarshal(ta.stdout.Bytes(), &listed); err != nil {
		t.Fatalf("leases mine --json: %v", err)
	}
	if listed.Total != 1 {
		t.Fatalf("leases mine payload = %+v", listed)
	}
	// --json keeps the lease payload shape (capability_name, risk, …).
	if listed.Items[0].CapabilityName == "" || listed.Items[0].Risk == "" {
		t.Fatalf("leases mine --json dropped lease fields: %+v", listed.Items[0])
	}

	ta.stdout.Reset()
	if code := ta.run("leases", "mine"); code != ExitOK {
		t.Fatalf("leases mine table exit = %d, stderr = %s", code, ta.errOut())
	}
	out := ta.out()
	for _, want := range []string{"ID", "STATUS", "AGENT", "ACCOUNT", "ACCESS", "VALID FOR", "CREATED", "EXPIRES",
		"write ecs (i-2ze0demo001)", "demo-aliyun", "15m0s"} {
		if !strings.Contains(out, want) {
			t.Fatalf("leases mine table missing %q in %q", want, out)
		}
	}
	for _, banned := range []string{"CAPABILITY", "RISK", "TTL"} {
		if strings.Contains(out, banned) {
			t.Fatalf("leases mine table still has %q: %q", banned, out)
		}
	}

	ta.stdout.Reset()
	if code := ta.run("leases", "get", item.ID); code != ExitOK {
		t.Fatalf("leases get exit = %d, stderr = %s", code, ta.errOut())
	}
	detail := ta.out()
	for _, want := range []string{"account:", "access:", "write ecs (i-2ze0demo001)", "valid for:"} {
		if !strings.Contains(detail, want) {
			t.Fatalf("leases get missing %q in %q", want, detail)
		}
	}
	for _, banned := range []string{"capability:", "risk:", "requested ttl:", "effective ttl:"} {
		if strings.Contains(detail, banned) {
			t.Fatalf("leases get still has %q: %q", banned, detail)
		}
	}
}

func TestAccessStatusOmitsValidForWhenTerminal(t *testing.T) {
	req := model.AccessRequest{
		ID: "lea_denied1", Status: model.LeaseDenied, CloudAccountID: "1234567890123456",
		Resource: "ecs", Permission: "write", ResourceName: "i-2ze0demo001",
		TTLSeconds: 900, DeniedReason: "not now",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r, agentTokenA)
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/agent/access-requests/"+req.ID {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected")
			return
		}
		writeEnvelope(w, http.StatusOK, req)
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, agentTokenA)
	if code := ta.run("access", "status", req.ID); code != ExitOperationErr {
		t.Fatalf("denied access status exit = %d, want %d; stderr = %s", code, ExitOperationErr, ta.errOut())
	}
	out := ta.out()
	if strings.Contains(out, "valid for:") {
		t.Fatalf("denied status still prints valid for: %q", out)
	}
	if !strings.Contains(out, "write ecs (i-2ze0demo001)") || !strings.Contains(out, "not now") {
		t.Fatalf("denied status output = %q", out)
	}

	req.Status = model.LeaseActive
	req.DeniedReason = ""
	ta.stdout.Reset()
	ta.stderr.Reset()
	if code := ta.run("access", "status", req.ID); code != ExitOK {
		t.Fatalf("active access status exit = %d, stderr = %s", code, ta.errOut())
	}
	if !strings.Contains(ta.out(), "valid for:  15m0s") {
		t.Fatalf("active status missing valid for: %q", ta.out())
	}
}

func TestMeModeAcceptsAccountFlag(t *testing.T) {
	const personTok = "csg_ses_testsessiontoken000000000000000000"
	var gotPath string
	var gotBody model.SetApprovalModeInput
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r, personTok)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/me/accounts":
			writeEnvelope(w, http.StatusOK, model.ListResponse[model.PersonAccount]{
				Items: []model.PersonAccount{{
					ProviderID: "prv_demo1", CloudAccountID: "1234567890123456", Name: "demo-aliyun",
					Role: model.RoleAdministrator, ApprovalMode: model.ModeRead, AutomaticUpTo: "read",
				}},
				Total: 1,
			})
		case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/api/v1/me/accounts/"):
			gotPath = r.URL.Path
			decodeBody(t, r, &gotBody)
			writeEnvelope(w, http.StatusOK, model.PersonAccount{
				ProviderID: "prv_demo1", CloudAccountID: "1234567890123456", Name: "demo-aliyun",
				Role: model.RoleAdministrator, ApprovalMode: gotBody.Mode, AutomaticUpTo: string(gotBody.Mode),
			})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			writeErrorEnvelope(w, http.StatusNotFound, "not_found", "unexpected")
		}
	}))
	defer srv.Close()

	ta := newTestApp(t)
	if _, err := ta.app.savePersonConfig(personConfig{
		Server: srv.URL, Token: personTok, Username: "mei", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if code := ta.run("me", "mode", "--account", "1234567890123456", "write", "--code", "123456"); code != ExitOK {
		t.Fatalf("me mode --account exit = %d, stderr = %s", code, ta.errOut())
	}
	if gotPath != "/api/v1/me/accounts/prv_demo1/mode" || gotBody.Mode != model.ModeWrite {
		t.Fatalf("PUT path/body = %s %+v", gotPath, gotBody)
	}
	if !strings.Contains(ta.out(), "approval mode is write") {
		t.Fatalf("output = %q", ta.out())
	}

	// Positional ACCOUNT still works.
	gotPath = ""
	ta.stdout.Reset()
	if code := ta.run("me", "mode", "demo-aliyun", "read", "--code", "123456"); code != ExitOK {
		t.Fatalf("me mode positional exit = %d, stderr = %s", code, ta.errOut())
	}
	if gotPath != "/api/v1/me/accounts/prv_demo1/mode" || gotBody.Mode != model.ModeRead {
		t.Fatalf("positional PUT path/body = %s %+v", gotPath, gotBody)
	}
}

func TestMockRequestSuccess(t *testing.T) {
	const mockToken = "cgk1.payload.signature"
	var authHeader, method, path, body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		method = r.Method
		path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"RequestId":"REQ1","RegionId":"cn-hangzhou","Instances":[{"InstanceId":"i-2ze0demo001"}]}`)
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, "")
	ta.env["ALIBABA_CLOUD_SECURITY_TOKEN"] = mockToken

	if code := ta.run("mock", "request", "GET", "/v1/ecs/instances", "--json"); code != ExitOK {
		t.Fatalf("mock request exit = %d, stderr = %s", code, ta.errOut())
	}
	if method != http.MethodGet || path != "/mock-cloud/v1/ecs/instances" {
		t.Fatalf("request = %s %s, want GET /mock-cloud/v1/ecs/instances", method, path)
	}
	if authHeader != "Bearer "+mockToken {
		t.Fatalf("Authorization = %q", authHeader)
	}
	var payload struct {
		Method   string          `json:"method"`
		Path     string          `json:"path"`
		Status   int             `json:"status"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(ta.stdout.Bytes(), &payload); err != nil {
		t.Fatalf("mock request --json output = %q: %v", ta.out(), err)
	}
	if payload.Status != 200 || payload.Method != "GET" {
		t.Fatalf("mock request payload = %+v", payload)
	}
	if strings.Contains(ta.out(), mockToken) || strings.Contains(ta.errOut(), mockToken) {
		t.Fatalf("mock token leaked into output: %q", ta.out())
	}

	// POST with a JSON body is passed through.
	ta.stdout.Reset()
	if code := ta.run("mock", "request", "POST", "/v1/dns/zones/arveykao.com/records",
		`{"name":"www","type":"A","value":"1.2.3.4"}`); code != ExitOK {
		t.Fatalf("mock POST exit = %d", code)
	}
	if method != http.MethodPost || path != "/mock-cloud/v1/dns/zones/arveykao.com/records" {
		t.Fatalf("POST request = %s %s", method, path)
	}
	if !strings.Contains(body, `"name":"www"`) {
		t.Fatalf("POST body = %q", body)
	}
	if !strings.Contains(ta.out(), "REQ1") {
		t.Fatalf("raw response not printed: %q", ta.out())
	}
}

func TestMockRequestErrorHandling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"Code":"Forbidden.RAM","Message":"not allowed","RequestId":"REQ2"}`)
	}))
	defer srv.Close()

	ta := newTestApp(t)
	ta.useServer(srv.URL, "")
	ta.env["ALIBABA_CLOUD_SECURITY_TOKEN"] = "cgk1.token.sig"
	if code := ta.run("mock", "request", "POST", "/v1/ecs/instances/i-2ze0demo001/restart"); code != ExitOperationErr {
		t.Fatalf("exit = %d, want %d", code, ExitOperationErr)
	}
	if !strings.Contains(ta.out(), "Forbidden.RAM") {
		t.Fatalf("stdout = %q", ta.out())
	}
	if !strings.Contains(ta.errOut(), "Forbidden.RAM") {
		t.Fatalf("stderr = %q", ta.errOut())
	}

	// Missing mock token is a usage error.
	ta = newTestApp(t)
	ta.useServer(srv.URL, "")
	if code := ta.run("mock", "request", "GET", "/v1/ecs/instances"); code != ExitUsage {
		t.Fatalf("missing token exit = %d, want %d", code, ExitUsage)
	}

	// Invalid JSON body is a usage error.
	ta.env["ALIBABA_CLOUD_SECURITY_TOKEN"] = "cgk1.token.sig"
	if code := ta.run("mock", "request", "POST", "/v1/dns/zones/x/records", "not-json"); code != ExitUsage {
		t.Fatalf("invalid body exit = %d, want %d", code, ExitUsage)
	}
}

func TestMockRequestPathAndMethodValidation(t *testing.T) {
	ta := newTestApp(t)
	ta.useServer("http://127.0.0.1:1", "")
	ta.env["ALIBABA_CLOUD_SECURITY_TOKEN"] = "cgk1.token.sig"
	if code := ta.run("mock", "request"); code != ExitUsage {
		t.Fatalf("missing positionals exit = %d, want %d", code, ExitUsage)
	}
	if code := ta.run("mock", "request", "GET"); code != ExitUsage {
		t.Fatalf("missing path exit = %d, want %d", code, ExitUsage)
	}
}
