package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// QA_BRIEF A (first half) gap coverage. Bullets already proved by other
// internal/**/_test.go files are not repeated here; see the worker report.

// The HTTP layer enforces the total waiting-sign-in limit (CONTRACT §17.3),
// not only the per-address cap covered by TestAgentSignInLimits.
func TestQAAgentSignInTotalLimit(t *testing.T) {
	env := newTestEnv(t, false)
	for i := 0; i < maxOpenSignIns; i++ {
		addr := fmt.Sprintf("198.51.100.%d:4000", (i/maxOpenSignInsPerAddr)+1)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/agent-signin/start",
			strings.NewReader(`{"agent_name":"flood"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		env.srv.Handler().ServeHTTP(rec, req)
		requireStatus(t, rec, http.StatusCreated)
	}
	rec := env.request(http.MethodPost, "/api/v1/agent-signin/start", nil, nil,
		model.AgentSignInStartInput{AgentName: "overflow"})
	requireErrorCode(t, rec, http.StatusTooManyRequests, model.ErrCodeRateLimited)
}

// Access-flow audit actions from section A are recorded and the chain verifies
// through the supervisor API (Activity page's verify source).
func TestQAAccessAuditRecordsAndVerifies(t *testing.T) {
	a := newAccessEnv(t, model.RoleGuest)

	read := a.request(accessInput("ecs", "read"))
	if read.Status != model.LeaseActive {
		t.Fatalf("guest read = %s", read.Status)
	}
	requireStatus(t, a.credential(read.ID), http.StatusOK)

	a.bind(a.mei, model.RoleMember)
	approved := a.request(accessInput("ecs", "write"))
	if approved.Status != model.LeasePending {
		t.Fatalf("member write = %s", approved.Status)
	}
	requireStatus(t, a.approve(a.mei, approved.ID), http.StatusOK)
	requireStatus(t, a.credential(approved.ID), http.StatusOK)

	denied := a.request(accessInput("dns", "write"))
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/requests/"+denied.ID+"/deny",
		model.DenyRequestInput{Reason: "not now"}), http.StatusOK)

	stopped := a.request(accessInput("oss", "write"))
	requireStatus(t, a.approve(a.mei, stopped.ID), http.StatusOK)
	requireStatus(t, a.sup.do(http.MethodPost, "/api/v1/supervisor/leases/"+stopped.ID+"/revoke",
		model.RevokeLeaseInput{Reason: "stop"}), http.StatusOK)

	for _, action := range []string{
		"agent_signin.approved", "agent_signin.completed",
		"lease.requested", "lease.auto_approved", "lease.approved",
		"lease.denied", "lease.revoked", "lease.credential_fetched", "binding.set",
	} {
		if !a.hasAction(action) {
			t.Errorf("missing audit action %s", action)
		}
	}
	a.verifyAudit()

	rec := a.sup.do(http.MethodGet, "/api/v1/supervisor/audit/verify", nil)
	requireStatus(t, rec, http.StatusOK)
	if v := decodeEnvelope[model.AuditVerifyResult](t, rec); !v.OK || v.Events == 0 {
		t.Fatalf("supervisor audit verify = %+v", v)
	}
	requireStatus(t, a.mei.do(http.MethodGet, "/api/v1/supervisor/audit", nil), http.StatusForbidden)
}
