package mockcloud

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// fakeStore embeds the Store interface so only the methods the mock cloud
// actually consumes need implementing; any unexpected call panics loudly.
type fakeStore struct {
	store.Store

	mu        sync.Mutex
	providers map[string]model.Provider
	agents    map[string]model.Agent
	leases    map[string]model.Lease
	audit     []model.AuditEvent
	seq       int64
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		providers: make(map[string]model.Provider),
		agents:    make(map[string]model.Agent),
		leases:    make(map[string]model.Lease),
	}
}

func (f *fakeStore) GetProvider(_ context.Context, id string) (model.Provider, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.providers[id]
	if !ok {
		return model.Provider{}, store.ErrNotFound
	}
	return p, nil
}

func (f *fakeStore) GetAgent(_ context.Context, id string) (model.Agent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.agents[id]
	if !ok {
		return model.Agent{}, store.ErrNotFound
	}
	return a, nil
}

func (f *fakeStore) GetLease(_ context.Context, id string) (model.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.leases[id]
	if !ok {
		return model.Lease{}, store.ErrNotFound
	}
	return l, nil
}

func (f *fakeStore) AppendAudit(_ context.Context, ev *model.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	ev.Seq = f.seq
	if ev.ID == "" {
		ev.ID = fmt.Sprintf("evt_%04d", f.seq)
	}
	f.audit = append(f.audit, *ev)
	return nil
}

func (f *fakeStore) events() []model.AuditEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]model.AuditEvent(nil), f.audit...)
}

// ---- test environment ----

const (
	testProviderID = "prv_mock01"
	testAgentID    = "agt_123"
	testLeaseID    = "lea_001"

	readPolicyTemplate = `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:Describe*","alidns:Describe*","oss:List*","sts:GetCallerIdentity"],"Resource":["*"]}]}`
	breakGlassPolicy   = `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

	// accountAdminPolicy is what the control plane actually mints for
	// aliyun.account.admin: account-wide Allow plus the mandatory IAM deny that
	// capcatalog.RenderPolicy appends to every document (CONTRACT §16.3). It is
	// spelled out literally here so this package documents the exact wire form
	// the mock cloud must enforce.
	accountAdminPolicy = `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},` +
		`{"Effect":"Deny","Action":["ram:*","sts:AssumeRole"],"Resource":"*"}]}`
)

func dnsManagePolicy(domain string) string {
	return `{"Version":"1","Statement":[{"Effect":"Allow","Action":["alidns:DescribeDomainRecords","alidns:AddDomainRecord","alidns:UpdateDomainRecord","alidns:DeleteDomainRecord","alidns:SetDomainRecordStatus"],"Resource":["acs:alidns:*:*:domain/` + domain + `"]}]}`
}

func testSigningKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*11 + 3)
	}
	return key
}

type testEnv struct {
	t       *testing.T
	store   *fakeStore
	key     []byte
	handler http.Handler
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	key := testSigningKey()
	st := newFakeStore()
	st.providers[testProviderID] = model.Provider{
		ID:     testProviderID,
		Name:   "demo-aliyun",
		Type:   model.ProviderAliyun,
		Mode:   model.ModeMock,
		Region: "cn-hangzhou",
		Status: model.ProviderActive,
	}
	st.agents[testAgentID] = model.Agent{ID: testAgentID, Name: "claude-code", Status: model.AgentActive}
	now := time.Now().UTC()
	expires := now.Add(15 * time.Minute)
	st.leases[testLeaseID] = model.Lease{
		ID:                  testLeaseID,
		AgentID:             testAgentID,
		AgentName:           "claude-code",
		CapabilityID:        "aliyun.cloud.read",
		ProviderID:          testProviderID,
		ProviderMode:        model.ModeMock,
		Status:              model.LeaseActive,
		CredentialAvailable: true,
		CreatedAt:           now,
		ExpiresAt:           &expires,
	}
	return &testEnv{
		t:       t,
		store:   st,
		key:     key,
		handler: NewHandler(Deps{Store: st, SigningKey: key}),
	}
}

// token mints a correctly signed mock token for the fixture lease.
func (e *testEnv) token(policyJSON string, mutate func(*provider.MockTokenPayload)) string {
	e.t.Helper()
	payload := provider.MockTokenPayload{
		V:           provider.MockTokenVersion,
		LeaseID:     testLeaseID,
		ProviderID:  testProviderID,
		AccountID:   provider.MockAccountID,
		Region:      "cn-hangzhou",
		ExpiresAt:   time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano),
		SessionName: "csg-agt_123-lea_001",
		Policy:      json.RawMessage(policyJSON),
	}
	if mutate != nil {
		mutate(&payload)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		e.t.Fatalf("marshal token payload: %v", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, e.key)
	mac.Write([]byte("cgk1." + b64))
	return "cgk1." + b64 + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (e *testEnv) updateLease(mutate func(*model.Lease)) {
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	lease := e.store.leases[testLeaseID]
	mutate(&lease)
	e.store.leases[testLeaseID] = lease
}

func (e *testEnv) request(method, path, token, body string) (*httptest.ResponseRecorder, map[string]any) {
	e.t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)

	var parsed map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			e.t.Fatalf("%s %s: response is not JSON: %q", method, path, rec.Body.String())
		}
	}
	return rec, parsed
}

func (e *testEnv) events() []model.AuditEvent { return e.store.events() }

func stringField(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v, ok := m[key]
	if !ok {
		t.Fatalf("response missing field %q: %v", key, m)
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("response field %q is not a string: %T", key, v)
	}
	return s
}

// ---- tests ----

func TestECSListAllowed(t *testing.T) {
	env := newTestEnv(t)
	token := env.token(readPolicyTemplate, nil)
	rec, body := env.request(http.MethodGet, "/v1/ecs/instances", token, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
	reqID := stringField(t, body, "RequestId")
	if len(reqID) != 32 {
		t.Fatalf("RequestId = %q, want 32 chars", reqID)
	}
	if got := stringField(t, body, "RegionId"); got != "cn-hangzhou" {
		t.Fatalf("RegionId = %q", got)
	}
	instances, ok := body["Instances"].([]any)
	if !ok || len(instances) != 3 {
		t.Fatalf("Instances = %v, want 3 fixtures", body["Instances"])
	}
	first, ok := instances[0].(map[string]any)
	if !ok {
		t.Fatalf("Instances[0] = %T", instances[0])
	}
	if got := stringField(t, first, "InstanceId"); got != "i-2ze0demo001" {
		t.Fatalf("Instances[0].InstanceId = %q", got)
	}
	if got := stringField(t, first, "InstanceName"); got != "web-01" {
		t.Fatalf("Instances[0].InstanceName = %q", got)
	}
	if got := stringField(t, first, "Status"); got != "running" {
		t.Fatalf("Instances[0].Status = %q", got)
	}
	if got := stringField(t, first, "RegionId"); got != "cn-hangzhou" {
		t.Fatalf("Instances[0].RegionId = %q", got)
	}

	events := env.events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Action != "cloud.api_called" || ev.Status != "ok" || ev.Severity != "info" {
		t.Fatalf("audit event = %+v", ev)
	}
	if ev.ActorType != "agent" || ev.ActorID != testAgentID || ev.ActorName != "claude-code" {
		t.Fatalf("audit actor = %s/%s/%s", ev.ActorType, ev.ActorID, ev.ActorName)
	}
	if ev.TargetType != "lease" || ev.TargetID != testLeaseID {
		t.Fatalf("audit target = %s/%s", ev.TargetType, ev.TargetID)
	}
	if got := ev.Metadata["service"]; got != "ecs" {
		t.Fatalf("metadata service = %v", got)
	}
	if got := ev.Metadata["action"]; got != "ecs:DescribeInstances" {
		t.Fatalf("metadata action = %v", got)
	}
	if got := ev.Metadata["resource"]; got != "acs:ecs:cn-hangzhou:1234567890123456:instance/*" {
		t.Fatalf("metadata resource = %v", got)
	}
	if got := ev.Metadata["http_status"]; got != http.StatusOK {
		t.Fatalf("metadata http_status = %v (%T)", got, got)
	}
	if got := ev.Metadata["request_id"]; got != reqID {
		t.Fatalf("metadata request_id = %v, want %s", got, reqID)
	}
	if _, ok := ev.Metadata["reason"]; ok {
		t.Fatalf("success audit event must not carry a reason: %v", ev.Metadata)
	}
}

func TestWriteOutOfScopeForbidden(t *testing.T) {
	env := newTestEnv(t)
	token := env.token(readPolicyTemplate, nil)

	rec, body := env.request(http.MethodPost, "/v1/ecs/instances/i-2ze0demo001/restart", token, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if code := stringField(t, body, "Code"); code != "Forbidden.RAM" {
		t.Fatalf("Code = %q, want Forbidden.RAM", code)
	}
	if msg := stringField(t, body, "Message"); !strings.Contains(msg, "ecs:RebootInstance") {
		t.Fatalf("Message = %q, want action mentioned", msg)
	}
	if stringField(t, body, "RequestId") == "" {
		t.Fatal("missing RequestId in error response")
	}

	events := env.events()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	ev := events[0]
	if ev.Action != "cloud.api_called" || ev.Status != "denied" || ev.Severity != "warning" {
		t.Fatalf("audit event = %+v", ev)
	}
	if reason, _ := ev.Metadata["reason"].(string); reason == "" {
		t.Fatalf("denied audit event has no reason: %v", ev.Metadata)
	}

	// The fixture instance must still be running.
	env2 := env
	bg := env2.token(breakGlassPolicy, nil)
	_, listBody := env2.request(http.MethodGet, "/v1/ecs/instances", bg, "")
	instances := listBody["Instances"].([]any)
	first := instances[0].(map[string]any)
	if got := stringField(t, first, "Status"); got != "running" {
		t.Fatalf("instance status after denied restart = %q, want running", got)
	}
}

func TestBreakGlassTokenAllowsWrites(t *testing.T) {
	env := newTestEnv(t)
	token := env.token(breakGlassPolicy, nil)

	rec, body := env.request(http.MethodPost, "/v1/ecs/instances/i-2ze0demo002/start", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	inst := body["Instance"].(map[string]any)
	if got := stringField(t, inst, "Status"); got != "running" {
		t.Fatalf("started instance status = %q, want running", got)
	}

	rec, body = env.request(http.MethodPost, "/v1/ecs/instances/i-2ze0demo003/stop", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("stop status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	inst = body["Instance"].(map[string]any)
	if got := stringField(t, inst, "Status"); got != "stopped" {
		t.Fatalf("stopped instance status = %q, want stopped", got)
	}

	rec, body = env.request(http.MethodPost, "/v1/ecs/instances/i-2ze0demo001/restart", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("restart status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	inst = body["Instance"].(map[string]any)
	if got := stringField(t, inst, "Status"); got != "running" {
		t.Fatalf("restarted instance status = %q, want running", got)
	}
}

func TestAuthFailures(t *testing.T) {
	past := time.Now().UTC().Add(-time.Minute)

	tests := []struct {
		name     string
		token    func(env *testEnv) string
		setup    func(env *testEnv)
		wantCode string
	}{
		{
			name:     "missing token",
			token:    func(*testEnv) string { return "" },
			wantCode: "InvalidSecurityToken",
		},
		{
			name:     "garbage token",
			token:    func(*testEnv) string { return "not-a-token" },
			wantCode: "InvalidSecurityToken",
		},
		{
			name:     "malformed cgk1 token",
			token:    func(*testEnv) string { return "cgk1.abc.def" },
			wantCode: "InvalidSecurityToken",
		},
		{
			name: "tampered payload",
			token: func(env *testEnv) string {
				token := env.token(readPolicyTemplate, nil)
				parts := strings.Split(token, ".")
				body, err := base64.RawURLEncoding.DecodeString(parts[1])
				if err != nil {
					t.Fatalf("decode payload: %v", err)
				}
				body[0] ^= 0x01
				return parts[0] + "." + base64.RawURLEncoding.EncodeToString(body) + "." + parts[2]
			},
			wantCode: "InvalidSecurityToken",
		},
		{
			name: "wrong signing key",
			token: func(env *testEnv) string {
				otherKey := testSigningKey()
				otherKey[0] ^= 0xFF
				envCopy := *env
				envCopy.key = otherKey
				return envCopy.token(readPolicyTemplate, nil)
			},
			wantCode: "InvalidSecurityToken",
		},
		{
			name: "expired token",
			token: func(env *testEnv) string {
				return env.token(readPolicyTemplate, func(p *provider.MockTokenPayload) {
					p.ExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
				})
			},
			wantCode: "InvalidSecurityToken.Expired",
		},
		{
			name:  "revoked lease",
			token: func(env *testEnv) string { return env.token(readPolicyTemplate, nil) },
			setup: func(env *testEnv) {
				env.updateLease(func(l *model.Lease) { l.Status = model.LeaseRevoked })
			},
			wantCode: "InvalidSecurityToken.Revoked",
		},
		{
			name:  "expired lease status",
			token: func(env *testEnv) string { return env.token(readPolicyTemplate, nil) },
			setup: func(env *testEnv) {
				env.updateLease(func(l *model.Lease) { l.Status = model.LeaseExpired })
			},
			wantCode: "InvalidSecurityToken.Expired",
		},
		{
			name:  "lease past expires_at",
			token: func(env *testEnv) string { return env.token(readPolicyTemplate, nil) },
			setup: func(env *testEnv) {
				env.updateLease(func(l *model.Lease) { l.ExpiresAt = &past })
			},
			wantCode: "InvalidSecurityToken.Expired",
		},
		{
			name:  "lease without expiry",
			token: func(env *testEnv) string { return env.token(readPolicyTemplate, nil) },
			setup: func(env *testEnv) {
				env.updateLease(func(l *model.Lease) { l.ExpiresAt = nil })
			},
			wantCode: "InvalidSecurityToken.Expired",
		},
		{
			name:  "unknown lease",
			token: func(env *testEnv) string { return env.token(readPolicyTemplate, nil) },
			setup: func(env *testEnv) {
				env.store.mu.Lock()
				delete(env.store.leases, testLeaseID)
				env.store.mu.Unlock()
			},
			wantCode: "InvalidSecurityToken.Revoked",
		},
		{
			name:  "non-mock provider",
			token: func(env *testEnv) string { return env.token(readPolicyTemplate, nil) },
			setup: func(env *testEnv) {
				env.store.mu.Lock()
				p := env.store.providers[testProviderID]
				p.Mode = model.ModeSTS
				env.store.providers[testProviderID] = p
				env.store.mu.Unlock()
			},
			wantCode: "InvalidSecurityToken",
		},
		{
			name:  "missing provider",
			token: func(env *testEnv) string { return env.token(readPolicyTemplate, nil) },
			setup: func(env *testEnv) {
				env.store.mu.Lock()
				delete(env.store.providers, testProviderID)
				env.store.mu.Unlock()
			},
			wantCode: "InvalidSecurityToken",
		},
		{
			name:  "lease provider mismatch",
			token: func(env *testEnv) string { return env.token(readPolicyTemplate, nil) },
			setup: func(env *testEnv) {
				env.updateLease(func(l *model.Lease) { l.ProviderID = "prv_other" })
			},
			wantCode: "InvalidSecurityToken",
		},
		{
			name: "token for another lease",
			token: func(env *testEnv) string {
				return env.token(readPolicyTemplate, func(p *provider.MockTokenPayload) {
					p.LeaseID = "lea_does_not_exist"
				})
			},
			wantCode: "InvalidSecurityToken.Revoked",
		},
		{
			name: "token without policy",
			token: func(env *testEnv) string {
				return env.token("", func(p *provider.MockTokenPayload) {
					p.Policy = nil
				})
			},
			wantCode: "InvalidSecurityToken",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			if tc.setup != nil {
				tc.setup(env)
			}
			token := tc.token(env)

			// Send with a Basic-style Authorization header for the missing
			// token case to prove non-Bearer schemes are rejected too.
			req := httptest.NewRequest(http.MethodGet, "/v1/ecs/instances", nil)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			} else {
				req.Header.Set("Authorization", "Basic Zm9vOmJhcg==")
			}
			rec := httptest.NewRecorder()
			env.handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401; body = %s", rec.Code, rec.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("error response is not JSON: %q", rec.Body.String())
			}
			if code := stringField(t, body, "Code"); code != tc.wantCode {
				t.Fatalf("Code = %q, want %q", code, tc.wantCode)
			}
			if stringField(t, body, "RequestId") == "" {
				t.Fatal("missing RequestId")
			}

			events := env.events()
			if len(events) != 1 {
				t.Fatalf("audit events = %d, want 1", len(events))
			}
			ev := events[0]
			if ev.Action != "cloud.api_denied" || ev.ActorType != "system" || ev.Status != "denied" || ev.Severity != "warning" {
				t.Fatalf("audit event = %+v", ev)
			}
			if got := ev.Metadata["reason"]; got != tc.wantCode {
				t.Fatalf("audit reason = %v, want %s", got, tc.wantCode)
			}
		})
	}
}

func TestUnknownResources(t *testing.T) {
	env := newTestEnv(t)
	token := env.token(readPolicyTemplate, nil)

	rec, body := env.request(http.MethodGet, "/v1/ecs/instances/i-doesnotexist", token, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown instance status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if code := stringField(t, body, "Code"); code != "InvalidInstance.NotFound" {
		t.Fatalf("Code = %q, want InvalidInstance.NotFound", code)
	}

	rec, body = env.request(http.MethodGet, "/v1/dns/zones/nope.example/records", token, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown zone status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if code := stringField(t, body, "Code"); code != "InvalidDomain.NotFound" {
		t.Fatalf("Code = %q, want InvalidDomain.NotFound", code)
	}

	dnsToken := env.token(dnsManagePolicy("arveykao.com"), nil)
	rec, body = env.request(http.MethodDelete, "/v1/dns/zones/arveykao.com/records/dns-rec-9999", dnsToken, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown record status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if code := stringField(t, body, "Code"); code != "InvalidDomainRecord.NotFound" {
		t.Fatalf("Code = %q, want InvalidDomainRecord.NotFound", code)
	}

	rec, body = env.request(http.MethodGet, "/v1/does/not/exist", token, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if code := stringField(t, body, "Code"); code != "InvalidAction.NotFound" {
		t.Fatalf("Code = %q, want InvalidAction.NotFound", code)
	}

	// Every request, including failures, produced one audit event.
	if got := len(env.events()); got != 4 {
		t.Fatalf("audit events = %d, want 4", got)
	}
}

func TestDNSRecordLifecycle(t *testing.T) {
	env := newTestEnv(t)
	token := env.token(dnsManagePolicy("arveykao.com"), nil)

	// Cross-domain reads are out of scope for this credential.
	rec, body := env.request(http.MethodGet, "/v1/dns/zones", token, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("zones list with domain-scoped token status = %d, want 403", rec.Code)
	}
	if code := stringField(t, body, "Code"); code != "Forbidden.RAM" {
		t.Fatalf("Code = %q", code)
	}

	// Create.
	rec, body = env.request(http.MethodPost, "/v1/dns/zones/arveykao.com/records", token,
		`{"name":"demo-s4","type":"TXT","value":"cloud-safeguard-demo","ttl":600}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	record := body["Record"].(map[string]any)
	recordID := stringField(t, record, "RecordId")
	if recordID == "" {
		t.Fatal("created record has no RecordId")
	}
	if got := stringField(t, record, "RR"); got != "demo-s4" {
		t.Fatalf("RR = %q", got)
	}
	if got := stringField(t, record, "Type"); got != "TXT" {
		t.Fatalf("Type = %q", got)
	}
	if got := stringField(t, record, "Status"); got != "ENABLE" {
		t.Fatalf("Status = %q", got)
	}
	if got := record["TTL"]; got != float64(600) {
		t.Fatalf("TTL = %v", got)
	}

	// List contains the new record.
	rec, body = env.request(http.MethodGet, "/v1/dns/zones/arveykao.com/records", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	domainRecords := body["DomainRecords"].(map[string]any)
	records := domainRecords["Record"].([]any)
	if len(records) != 4 {
		t.Fatalf("record count after create = %d, want 4", len(records))
	}
	found := false
	for _, item := range records {
		if item.(map[string]any)["RecordId"] == recordID {
			found = true
		}
	}
	if !found {
		t.Fatalf("created record %s not returned by list", recordID)
	}

	// Delete.
	rec, body = env.request(http.MethodDelete, "/v1/dns/zones/arveykao.com/records/"+recordID, token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := stringField(t, body, "RecordId"); got != recordID {
		t.Fatalf("deleted RecordId = %q, want %q", got, recordID)
	}

	// Delete removes it from the list.
	rec, body = env.request(http.MethodGet, "/v1/dns/zones/arveykao.com/records", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	records = body["DomainRecords"].(map[string]any)["Record"].([]any)
	if len(records) != 3 {
		t.Fatalf("record count after delete = %d, want 3", len(records))
	}

	// Fixtures include the three contractual records.
	var rrs []string
	for _, item := range records {
		rr := item.(map[string]any)
		rrs = append(rrs, fmt.Sprintf("%v/%v/%v", rr["RR"], rr["Type"], rr["Value"]))
	}
	for _, want := range []string{"@/A/8.153.177.205", "www/A/8.153.177.205", "_acme-challenge/TXT/demo-token-123"} {
		found := false
		for _, got := range rrs {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("fixture record %q missing; got %v", want, rrs)
		}
	}

	// A different domain is out of scope for the same credential.
	rec, body = env.request(http.MethodPost, "/v1/dns/zones/guanlanstudio.com/records", token,
		`{"name":"www","type":"A","value":"1.2.3.4","ttl":600}`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-domain create status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
}

func TestDNSAddRecordValidation(t *testing.T) {
	env := newTestEnv(t)
	token := env.token(dnsManagePolicy("arveykao.com"), nil)

	tests := []struct {
		name string
		body string
	}{
		{"invalid JSON", `not json`},
		{"missing name", `{"type":"A","value":"1.2.3.4"}`},
		{"bad type", `{"name":"x","type":"BOGUS","value":"1.2.3.4"}`},
		{"missing value", `{"name":"x","type":"A"}`},
		{"ttl too low", `{"name":"x","type":"A","value":"1.2.3.4","ttl":59}`},
		{"ttl too high", `{"name":"x","type":"A","value":"1.2.3.4","ttl":86401}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec, body := env.request(http.MethodPost, "/v1/dns/zones/arveykao.com/records", token, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
			}
			if code := stringField(t, body, "Code"); code != "InvalidParameter" {
				t.Fatalf("Code = %q, want InvalidParameter", code)
			}
		})
	}

	// Default TTL is 600 and apex "@" names are accepted.
	rec, body := env.request(http.MethodPost, "/v1/dns/zones/arveykao.com/records", token,
		`{"name":"@","type":"A","value":"9.9.9.9"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("apex create status = %d; body = %s", rec.Code, rec.Body.String())
	}
	record := body["Record"].(map[string]any)
	if got := record["TTL"]; got != float64(600) {
		t.Fatalf("default TTL = %v, want 600", got)
	}
}

func TestDNSZonesListAllowed(t *testing.T) {
	env := newTestEnv(t)
	token := env.token(readPolicyTemplate, nil)
	rec, body := env.request(http.MethodGet, "/v1/dns/zones", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body.String())
	}
	domains := body["Domains"].([]any)
	if len(domains) != 2 {
		t.Fatalf("Domains = %d, want 2", len(domains))
	}
	first := domains[0].(map[string]any)
	if got := stringField(t, first, "DomainName"); got != "arveykao.com" {
		t.Fatalf("DomainName = %q", got)
	}
	if got := stringField(t, first, "DomainId"); got != "dns-demo-arveykao" {
		t.Fatalf("DomainId = %q", got)
	}
}

func TestDenyStatementOverridesAllow(t *testing.T) {
	env := newTestEnv(t)
	token := env.token(`{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"ecs:RebootInstance","Resource":"*"}]}`, nil)

	rec, _ := env.request(http.MethodGet, "/v1/ecs/instances", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("allowed list status = %d, want 200", rec.Code)
	}
	rec, body := env.request(http.MethodPost, "/v1/ecs/instances/i-2ze0demo001/restart", token, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("denied restart status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if code := stringField(t, body, "Code"); code != "Forbidden.RAM" {
		t.Fatalf("Code = %q", code)
	}
}

func TestFullPrefixMountedPath(t *testing.T) {
	env := newTestEnv(t)
	token := env.token(readPolicyTemplate, nil)
	rec, body := env.request(http.MethodGet, "/mock-cloud/v1/ecs/instances", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if _, ok := body["Instances"]; !ok {
		t.Fatalf("response missing Instances: %v", body)
	}
}

func TestAuditEventMix(t *testing.T) {
	env := newTestEnv(t)
	readToken := env.token(readPolicyTemplate, nil)

	// 200 allowed.
	if rec, _ := env.request(http.MethodGet, "/v1/ecs/instances", readToken, ""); rec.Code != 200 {
		t.Fatalf("allowed call status = %d", rec.Code)
	}
	// 403 denied.
	if rec, _ := env.request(http.MethodPost, "/v1/ecs/instances/i-2ze0demo001/restart", readToken, ""); rec.Code != 403 {
		t.Fatalf("denied call status = %d", rec.Code)
	}
	// 401 invalid token.
	if rec, _ := env.request(http.MethodGet, "/v1/ecs/instances", "bogus", ""); rec.Code != 401 {
		t.Fatalf("invalid token status = %d", rec.Code)
	}
	// 404 unknown resource.
	if rec, _ := env.request(http.MethodGet, "/v1/ecs/instances/i-nope", readToken, ""); rec.Code != 404 {
		t.Fatalf("unknown resource status = %d", rec.Code)
	}

	events := env.events()
	if len(events) != 4 {
		t.Fatalf("audit events = %d, want 4", len(events))
	}
	counts := map[string]int{}
	for _, ev := range events {
		counts[ev.Action+"/"+ev.Status]++
	}
	want := map[string]int{
		"cloud.api_called/ok":     1,
		"cloud.api_called/denied": 1,
		"cloud.api_denied/denied": 1,
		"cloud.api_called/failed": 1,
	}
	for k, v := range want {
		if counts[k] != v {
			t.Fatalf("audit event %s count = %d, want %d (all: %v)", k, counts[k], v, counts)
		}
	}
	for i := 1; i < len(events); i++ {
		if events[i].Seq <= events[i-1].Seq {
			t.Fatalf("audit seq not increasing: %d then %d", events[i-1].Seq, events[i].Seq)
		}
	}
}

func TestNoTokenLeakage(t *testing.T) {
	env := newTestEnv(t)
	readToken := env.token(readPolicyTemplate, nil)
	dnsToken := env.token(dnsManagePolicy("arveykao.com"), nil)

	var bodies []string
	collect := func(method, path, token, body string) {
		rec, _ := env.request(method, path, token, body)
		bodies = append(bodies, rec.Body.String())
	}
	collect(http.MethodGet, "/v1/ecs/instances", readToken, "")
	collect(http.MethodPost, "/v1/ecs/instances/i-2ze0demo001/restart", readToken, "")
	collect(http.MethodGet, "/v1/ecs/instances", "garbage", "")
	collect(http.MethodGet, "/v1/dns/zones/arveykao.com/records", dnsToken, "")
	collect(http.MethodPost, "/v1/dns/zones/arveykao.com/records", dnsToken,
		`{"name":"leak-check","type":"TXT","value":"hello"}`)

	all := strings.Join(bodies, "\n")
	auditJSON, err := json.Marshal(env.events())
	if err != nil {
		t.Fatalf("marshal audit events: %v", err)
	}
	for name, token := range map[string]string{"read token": readToken, "dns token": dnsToken} {
		if strings.Contains(all, token) {
			t.Fatalf("%s leaked into a response body", name)
		}
		if strings.Contains(string(auditJSON), token) {
			t.Fatalf("%s leaked into the audit log", name)
		}
		if strings.Contains(all, "Authorization") || strings.Contains(string(auditJSON), "Authorization") {
			t.Fatalf("Authorization header leaked")
		}
	}

	// Metadata keys must never be token-shaped.
	for _, ev := range env.events() {
		for k := range ev.Metadata {
			lower := strings.ToLower(k)
			if strings.Contains(lower, "token") || strings.Contains(lower, "secret") || strings.Contains(lower, "authorization") {
				t.Fatalf("audit metadata key %q is secret-shaped: %v", k, ev.Metadata)
			}
		}
	}
}

func TestECSTransitionInvalidStatusNoOp(t *testing.T) {
	// Unknown instances never mutate state and always 404.
	env := newTestEnv(t)
	token := env.token(breakGlassPolicy, nil)
	rec, body := env.request(http.MethodPost, "/v1/ecs/instances/i-nope/stop", token, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if code := stringField(t, body, "Code"); code != "InvalidInstance.NotFound" {
		t.Fatalf("Code = %q", code)
	}
}

// TestAccountAdminLeaseIsDeniedOnRAM is the end-to-end proof of the IAM
// prohibition inside the mock cloud (CONTRACT §16.8): the account-wide admin
// credential works on ECS and is still refused on RAM, because every minted
// document carries the mandatory deny for ram:*.
func TestAccountAdminLeaseIsDeniedOnRAM(t *testing.T) {
	env := newTestEnv(t)
	token := env.token(accountAdminPolicy, nil)

	// ECS read is allowed.
	rec, body := env.request(http.MethodGet, "/v1/ecs/instances", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ECS list status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if instances, ok := body["Instances"].([]any); !ok || len(instances) != 3 {
		t.Fatalf("ECS list = %v, want 3 fixtures", body["Instances"])
	}
	// So is an ECS write: this credential really is account-wide.
	rec, _ = env.request(http.MethodPost, "/v1/ecs/instances/i-2ze0demo002/start", token, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ECS start status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}

	// RAM is not, even though the Allow statement covers every action.
	rec, body = env.request(http.MethodGet, "/v1/ram/users", token, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("RAM list status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	if code := stringField(t, body, "Code"); code != "Forbidden.RAM" {
		t.Fatalf("RAM list Code = %q, want Forbidden.RAM", code)
	}
	if got := rec.Header().Get("X-Csg-Error-Code"); got != "Forbidden.RAM" {
		t.Fatalf("X-Csg-Error-Code = %q, want Forbidden.RAM", got)
	}
	if body["Users"] != nil {
		t.Fatalf("denied RAM response leaked a user list: %v", body["Users"])
	}

	// The denial is attributable: a warning-severity cloud.api_called naming
	// the RAM action.
	denied := false
	for _, ev := range env.events() {
		if ev.Action != "cloud.api_called" || ev.Status != "denied" {
			continue
		}
		if action, _ := ev.Metadata["action"].(string); action != "ram:ListUsers" {
			continue
		}
		denied = true
		if ev.Severity != "warning" {
			t.Fatalf("RAM denial severity = %q, want warning", ev.Severity)
		}
		if service, _ := ev.Metadata["service"].(string); service != "ram" {
			t.Fatalf("RAM denial service = %q, want ram", service)
		}
		if ev.TargetID != testLeaseID {
			t.Fatalf("RAM denial target = %q, want the lease", ev.TargetID)
		}
	}
	if !denied {
		t.Fatal("RAM denial was not audited as cloud.api_called/denied")
	}
}

// TestRAMRouteNeedsTheDenyStatement shows what the mandatory deny buys: the
// mock cloud enforces exactly the document it is handed, so RAM is only
// unreachable because RenderPolicy always appends the deny.
func TestRAMRouteNeedsTheDenyStatement(t *testing.T) {
	env := newTestEnv(t)

	// A read-only credential has no Allow covering ram:ListUsers.
	rec, body := env.request(http.MethodGet, "/v1/ram/users", env.token(readPolicyTemplate, nil), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("read credential on RAM status = %d, want 403", rec.Code)
	}
	if code := stringField(t, body, "Code"); code != "Forbidden.RAM" {
		t.Fatalf("Code = %q, want Forbidden.RAM", code)
	}

	// A hand-made document that allows RAM and omits the deny would pass: the
	// control plane is what makes that document impossible to mint.
	ramAllow := `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ram:ListUsers"],"Resource":["*"]}]}`
	rec, body = env.request(http.MethodGet, "/v1/ram/users", env.token(ramAllow, nil), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("hand-made ram:ListUsers policy status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	users, ok := body["Users"].(map[string]any)
	if !ok {
		t.Fatalf("RAM list body = %v, want a Users object", body)
	}
	if list, ok := users["User"].([]any); !ok || len(list) != 2 {
		t.Fatalf("RAM fixtures = %v, want 2 users", users["User"])
	}

	// Add the mandatory deny and the same request is refused.
	ramAllowWithDeny := `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ram:ListUsers"],"Resource":["*"]},` +
		`{"Effect":"Deny","Action":["ram:*","sts:AssumeRole"],"Resource":"*"}]}`
	rec, body = env.request(http.MethodGet, "/v1/ram/users", env.token(ramAllowWithDeny, nil), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ram:ListUsers with the mandatory deny status = %d, want 403", rec.Code)
	}
	if code := stringField(t, body, "Code"); code != "Forbidden.RAM" {
		t.Fatalf("Code = %q, want Forbidden.RAM", code)
	}
}
