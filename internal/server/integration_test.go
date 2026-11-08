package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// TestRealMockProviderEndToEnd exercises the cross-package demo path with the
// real provider minters (no fake): auto-approve -> real mock STS token ->
// mock-cloud read allowed -> out-of-policy write denied -> revoke -> immediate
// 401. It is the server-side equivalent of demo scenarios S1/S2.
func TestRealMockProviderEndToEnd(t *testing.T) {
	dir := t.TempDir()
	initRes, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: true})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	srv, err := New(Config{DataDir: dir}) // real provider.New(mock)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()
	handler := srv.Handler()

	agentToken := ""
	for _, agent := range initRes.Agents {
		if agent.Name == "claude-code" {
			agentToken = agent.Token
		}
	}
	if agentToken == "" {
		t.Fatal("demo init did not create claude-code")
	}

	// Auto-approved lease.
	createRec := rawRequest(t, handler, http.MethodPost, "/api/v1/agent/leases", agentToken, model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "integration: read inventory",
	})
	requireStatus(t, createRec, http.StatusCreated)
	lease := decodeEnvelope[model.Lease](t, createRec)
	if lease.Status != model.LeaseActive || lease.ProviderMode != model.ModeMock {
		t.Fatalf("lease = %+v, want active mock lease", lease)
	}

	// Fetch the real mock credential.
	credRec := rawRequest(t, handler, http.MethodPost, "/api/v1/agent/leases/"+lease.ID+"/credential", agentToken, nil)
	requireStatus(t, credRec, http.StatusOK)
	envelope := decodeEnvelope[model.CredentialEnvelope](t, credRec)
	token := envelope.Credential.SecurityToken
	if !strings.HasPrefix(token, "cgk1.") {
		t.Fatalf("mock security token = %q, want cgk1. prefix", token)
	}
	if envelope.Credential.ProviderMode != model.ModeMock {
		t.Fatalf("credential mode = %q", envelope.Credential.ProviderMode)
	}

	// The mock cloud accepts the token for the read action.
	cloudRec := rawRequest(t, handler, http.MethodGet, "/mock-cloud/v1/ecs/instances", token, nil)
	if cloudRec.Code != http.StatusOK {
		t.Fatalf("mock cloud read status = %d (body %.400s)", cloudRec.Code, cloudRec.Body.String())
	}
	var listResponse struct {
		Instances []struct {
			InstanceID string `json:"InstanceId"`
		} `json:"Instances"`
	}
	if err := json.Unmarshal(cloudRec.Body.Bytes(), &listResponse); err != nil {
		t.Fatalf("decode mock cloud list: %v", err)
	}
	if len(listResponse.Instances) != 3 {
		t.Fatalf("mock cloud instances = %d, want 3", len(listResponse.Instances))
	}
	foundDemo := false
	for _, instance := range listResponse.Instances {
		if instance.InstanceID == "i-2ze0demo001" {
			foundDemo = true
		}
	}
	if !foundDemo {
		t.Fatal("mock cloud fixtures missing i-2ze0demo001")
	}

	// Least privilege: the same credential cannot restart an instance.
	writeRec := rawRequest(t, handler, http.MethodPost, "/mock-cloud/v1/ecs/instances/i-2ze0demo001/restart", token, nil)
	if writeRec.Code != http.StatusForbidden {
		t.Fatalf("out-of-policy write status = %d, want 403 (body %.400s)", writeRec.Code, writeRec.Body.String())
	}
	if !strings.Contains(writeRec.Body.String(), "Forbidden.RAM") {
		t.Fatalf("write denial body = %.300s, want Forbidden.RAM", writeRec.Body.String())
	}

	// Revocation is immediate for the mock cloud.
	revokeRec := rawRequest(t, handler, http.MethodPost, "/api/v1/agent/leases/"+lease.ID+"/revoke", agentToken, model.RevokeLeaseInput{Reason: "integration done"})
	requireStatus(t, revokeRec, http.StatusOK)
	afterRevoke := rawRequest(t, handler, http.MethodGet, "/mock-cloud/v1/ecs/instances", token, nil)
	if afterRevoke.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token status = %d, want 401 (body %.300s)", afterRevoke.Code, afterRevoke.Body.String())
	}
	if !strings.Contains(afterRevoke.Body.String(), "InvalidSecurityToken") {
		t.Fatalf("revoked token body = %.300s", afterRevoke.Body.String())
	}

	// A forged/duplicate mock token is rejected with an Aliyun-shaped 401.
	forged := rawRequest(t, handler, http.MethodGet, "/mock-cloud/v1/ecs/instances", "cgk1.eyJ2IjoxfQ.forged", nil)
	if forged.Code != http.StatusUnauthorized {
		t.Fatalf("forged mock token status = %d, want 401", forged.Code)
	}
	if !strings.Contains(forged.Body.String(), "InvalidSecurityToken") {
		t.Fatalf("forged mock token body = %.300s", forged.Body.String())
	}

	// The real mock provider passes its configuration test (signing key present).
	providerTest := rawRequest(t, handler, http.MethodPost,
		"/api/v1/admin/providers/"+initRes.ProviderIDs[0]+"/test", initRes.AdminToken, nil)
	if providerTest.Code != http.StatusOK {
		t.Fatalf("provider test status = %d (body %.300s)", providerTest.Code, providerTest.Body.String())
	}
	tested := decodeEnvelope[providerTestResult](t, providerTest)
	if !tested.OK {
		t.Fatalf("real mock provider test failed: %+v", tested)
	}

	// The cloud API calls are attributable in the audit chain.
	if !srv.hasAuditAction(t, "cloud.api_called") {
		t.Fatal("missing cloud.api_called audit event")
	}
	result, err := srv.db.VerifyAudit(context.Background())
	if err != nil || !result.OK {
		t.Fatalf("audit verify = %+v, %v", result, err)
	}
}

// hasAuditAction reports whether the server's audit log contains an action.
func (s *Server) hasAuditAction(t *testing.T, action string) bool {
	t.Helper()
	items, _, err := s.db.ListAudit(context.Background(), store.AuditFilter{Action: action, Limit: 100})
	if err != nil {
		t.Fatalf("ListAudit(%s): %v", action, err)
	}
	return len(items) > 0
}
