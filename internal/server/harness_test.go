package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
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

// fixedTestTime is the deterministic clock used by all server tests.
var fixedTestTime = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

// fakeClock is a controllable clock injected through Config.Now.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// fakeMinter is an injectable provider.Minter used by the server tests. It is
// deterministic and supports failure injection.
type fakeMinter struct {
	mu       sync.Mutex
	now      func() time.Time
	fail     error
	requests []provider.MintRequest
	seq      int
}

func (m *fakeMinter) Mint(ctx context.Context, req provider.MintRequest) (model.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = append(m.requests, req)
	if m.fail != nil {
		return model.Credential{}, m.fail
	}
	m.seq++
	expiresAt := m.now().Add(time.Duration(req.DurationSeconds) * time.Second)
	return model.Credential{
		ProviderID:      req.Provider.ID,
		ProviderMode:    req.Provider.Mode,
		LeaseID:         req.LeaseID,
		AccessKeyID:     fmt.Sprintf("LTAIfake%04dAKID", m.seq),
		AccessKeySecret: "fake-lease-secret-" + req.LeaseID,
		SecurityToken:   "cgk1.fake." + req.LeaseID,
		ExpiresAt:       expiresAt,
	}, nil
}

func (m *fakeMinter) Test(ctx context.Context, req provider.MintRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fail
}

func (m *fakeMinter) setFailure(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail = err
}

func (m *fakeMinter) lastRequest(t *testing.T) provider.MintRequest {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.requests) == 0 {
		t.Fatal("fake minter was never called")
	}
	return m.requests[len(m.requests)-1]
}

func (m *fakeMinter) requestCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.requests)
}

// testEnv is a fully bootstrapped control plane served through httptest.
type testEnv struct {
	t           *testing.T
	srv         *Server
	dir         string
	adminToken  string
	clock       *fakeClock
	minter      *fakeMinter
	logs        *bytes.Buffer
	agentTokens map[string]string
	agentIDs    map[string]string
	providerID  string
}

// newTestEnv bootstraps a data dir (optionally with the demo seed) and starts a
// Server with a fake clock and fake minter.
func newTestEnv(t *testing.T, demo bool) *testEnv {
	t.Helper()
	dir := t.TempDir()
	initRes, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: demo})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	clock := newFakeClock(fixedTestTime)
	minter := &fakeMinter{now: clock.Now}
	srv, err := New(Config{
		Addr:    "127.0.0.1:0",
		DataDir: dir,
		Now:     clock.Now,
		MinterFactory: func(p model.Provider) (provider.Minter, error) {
			return minter, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logs := &bytes.Buffer{}
	srv.logWriter = log.New(logs, "", 0)
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("server Close: %v", err)
		}
	})

	env := &testEnv{
		t:           t,
		srv:         srv,
		dir:         dir,
		adminToken:  initRes.AdminToken,
		clock:       clock,
		minter:      minter,
		logs:        logs,
		agentTokens: map[string]string{},
		agentIDs:    map[string]string{},
	}
	for _, agent := range initRes.Agents {
		env.agentTokens[agent.Name] = agent.Token
		env.agentIDs[agent.Name] = agent.ID
	}
	if len(initRes.ProviderIDs) > 0 {
		env.providerID = initRes.ProviderIDs[0]
	}
	return env
}

// do performs an HTTP request against the control plane handler.
func (e *testEnv) do(method, path, token string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	var reader *bytes.Reader
	switch b := body.(type) {
	case nil:
		reader = bytes.NewReader(nil)
	case []byte:
		reader = bytes.NewReader(b)
	case string:
		reader = bytes.NewReader([]byte(b))
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	return rec
}

// admin performs an admin-authenticated request.
func (e *testEnv) admin(method, path string, body any) *httptest.ResponseRecorder {
	return e.do(method, path, e.adminToken, body)
}

// agent performs an agent-authenticated request.
func (e *testEnv) agent(agentName, method, path string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	token, ok := e.agentTokens[agentName]
	if !ok {
		e.t.Fatalf("no token for agent %q", agentName)
	}
	return e.do(method, path, token, body)
}

// decodeEnvelope decodes the standard {"data": ...} envelope.
func decodeEnvelope[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var envelope struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response envelope (status %d, body %.400s): %v", rec.Code, rec.Body.String(), err)
	}
	return envelope.Data
}

// decodeError decodes the standard error envelope.
func decodeError(t *testing.T, rec *httptest.ResponseRecorder) model.ErrorBody {
	t.Helper()
	var body model.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error envelope (status %d, body %.400s): %v", rec.Code, rec.Body.String(), err)
	}
	return body
}

// requireStatus asserts the recorder status code.
func requireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body %.600s)", rec.Code, want, rec.Body.String())
	}
}

// requireErrorCode asserts status + error code of an API error response.
func requireErrorCode(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	requireStatus(t, rec, wantStatus)
	body := decodeError(t, rec)
	if body.Error.Code != wantCode {
		t.Fatalf("error code = %q, want %q (message %q)", body.Error.Code, wantCode, body.Error.Message)
	}
}

// createLease is a helper that POSTs a lease request for an agent.
func (e *testEnv) createLease(agentName string, in model.CreateLeaseInput) (model.Lease, *httptest.ResponseRecorder) {
	e.t.Helper()
	rec := e.agent(agentName, http.MethodPost, "/api/v1/agent/leases", in)
	return decodeEnvelope[model.Lease](e.t, rec), rec
}

// fetchCredential POSTs the credential endpoint for a lease.
func (e *testEnv) fetchCredential(agentName, leaseID string) (model.CredentialEnvelope, *httptest.ResponseRecorder) {
	e.t.Helper()
	rec := e.agent(agentName, http.MethodPost, "/api/v1/agent/leases/"+leaseID+"/credential", nil)
	return decodeEnvelope[model.CredentialEnvelope](e.t, rec), rec
}

// getLease returns an admin view of one lease.
func (e *testEnv) getLease(id string) model.Lease {
	e.t.Helper()
	rec := e.admin(http.MethodGet, "/api/v1/admin/leases/"+id, nil)
	requireStatus(e.t, rec, http.StatusOK)
	return decodeEnvelope[model.Lease](e.t, rec)
}

// listAudit returns audit events filtered by action (newest first).
func (e *testEnv) listAudit(action string) []model.AuditEvent {
	e.t.Helper()
	items, _, err := e.srv.db.ListAudit(context.Background(), store.AuditFilter{Action: action, Limit: 200})
	if err != nil {
		e.t.Fatalf("ListAudit(%s): %v", action, err)
	}
	return items
}

// verifyAudit calls the audit verify endpoint and returns the result.
func (e *testEnv) verifyAudit() model.AuditVerifyResult {
	e.t.Helper()
	rec := e.admin(http.MethodGet, "/api/v1/admin/audit/verify", nil)
	requireStatus(e.t, rec, http.StatusOK)
	result := decodeEnvelope[model.AuditVerifyResult](e.t, rec)
	if !result.OK {
		e.t.Fatalf("audit chain did not verify: %+v", result)
	}
	return result
}

// hasAction reports whether an audit action was recorded.
func (e *testEnv) hasAction(action string) bool {
	return len(e.listAudit(action)) > 0
}

// structContains fails when the JSON-marshalled value contains a forbidden
// substring (used by the secret-exposure tests).
func structContains(t *testing.T, v any, substr string) bool {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return strings.Contains(string(raw), substr)
}
