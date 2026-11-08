package server

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// reasonOutcome returns the recorded outcome for a policy rule, or "".
func reasonOutcome(d model.PolicyDecision, rule string) string {
	for _, r := range d.Reasons {
		if r.Rule == rule {
			return r.Outcome
		}
	}
	return ""
}

// requireRuleOutcome asserts that a policy decision recorded a rule outcome.
func requireRuleOutcome(t *testing.T, d model.PolicyDecision, rule, want string) {
	t.Helper()
	if got := reasonOutcome(d, rule); got != want {
		t.Fatalf("decision rule %s = %q, want %q (reasons: %v)", rule, got, want, d.Reasons)
	}
}

func TestAutoApproveLeaseFlow(t *testing.T) {
	env := newTestEnv(t, true)

	lease, rec := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "inventory refresh for demo",
	})
	requireStatus(t, rec, http.StatusCreated)

	if lease.Status != model.LeaseActive {
		t.Fatalf("status = %q, want active", lease.Status)
	}
	if lease.Decision.Outcome != model.OutcomeAutoApprove {
		t.Fatalf("decision = %q, want auto_approve", lease.Decision.Outcome)
	}
	requireRuleOutcome(t, lease.Decision, "auto_approve", "allow")
	if lease.EffectiveTTLSeconds != 900 {
		t.Fatalf("effective TTL = %d, want 900", lease.EffectiveTTLSeconds)
	}
	if lease.ApprovedBy != "auto" {
		t.Fatalf("approved_by = %q, want auto", lease.ApprovedBy)
	}
	if lease.IssuedAt == nil || lease.ExpiresAt == nil {
		t.Fatal("active lease is missing issued_at/expires_at")
	}
	if want := fixedTestTime.Add(900 * time.Second); !lease.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at = %v, want %v", lease.ExpiresAt, want)
	}
	if !lease.CredentialAvailable || lease.CredentialFingerprint == "" {
		t.Fatalf("credential availability not set: %+v", lease)
	}
	// Session name is csg-<agentID>-<leaseID>, truncated to the 64-char cloud limit.
	wantSessionPrefix := "csg-" + env.agentIDs["claude-code"] + "-"
	if !strings.HasPrefix(lease.SessionName, wantSessionPrefix) {
		t.Fatalf("session_name = %q, want prefix %q", lease.SessionName, wantSessionPrefix)
	}
	if len(lease.SessionName) > 64 {
		t.Fatalf("session_name length = %d, want <= 64", len(lease.SessionName))
	}

	// The minter received the rendered least-privilege policy.
	req := env.minter.lastRequest(t)
	if req.LeaseID != lease.ID || req.DurationSeconds != 900 {
		t.Fatalf("mint request = %+v", req)
	}
	if !strings.Contains(string(req.PolicyJSON), "ecs:Describe*") {
		t.Fatalf("mint policy = %s, want cloud-read actions", req.PolicyJSON)
	}
	if req.BrokerAccessKeyID != "LTAI5tDemoMockBroker" || req.BrokerAccessKeySecret == "" {
		t.Fatalf("broker credential not passed to minter (akid %q)", req.BrokerAccessKeyID)
	}
	if len(req.SigningKey) != 32 {
		t.Fatalf("signing key length = %d, want 32", len(req.SigningKey))
	}

	// Fetch the credential and check the frozen envelope shape/order.
	envelope, credRec := env.fetchCredential("claude-code", lease.ID)
	requireStatus(t, credRec, http.StatusOK)
	if envelope.Credential.LeaseID != lease.ID {
		t.Fatalf("credential lease = %q, want %q", envelope.Credential.LeaseID, lease.ID)
	}
	if envelope.Credential.AccessKeySecret == "" || envelope.Credential.SecurityToken == "" {
		t.Fatal("credential envelope has empty secret/token")
	}
	wantEnv := []string{
		"ALIBABA_CLOUD_ACCESS_KEY_ID",
		"ALIBABA_CLOUD_ACCESS_KEY_SECRET",
		"ALIBABA_CLOUD_SECURITY_TOKEN",
		"CSG_LEASE_ID",
		"CSG_SERVER",
		"CSG_CAPABILITY",
	}
	if len(envelope.Env) != len(wantEnv) {
		t.Fatalf("env has %d entries, want %d: %+v", len(envelope.Env), len(wantEnv), envelope.Env)
	}
	for i, name := range wantEnv {
		if envelope.Env[i].Name != name {
			t.Fatalf("env[%d] = %q, want %q", i, envelope.Env[i].Name, name)
		}
		if envelope.Env[i].Value == "" {
			t.Fatalf("env[%d] (%s) has empty value", i, name)
		}
	}
	if envelope.Env[4].Value != "http://example.com" {
		t.Fatalf("CSG_SERVER = %q, want http://example.com", envelope.Env[4].Value)
	}
	if envelope.Env[5].Value != "aliyun.cloud.read" {
		t.Fatalf("CSG_CAPABILITY = %q", envelope.Env[5].Value)
	}

	// Required audit trail.
	for _, action := range []string{"lease.requested", "lease.auto_approved", "lease.credential_issued", "lease.credential_fetched"} {
		if !env.hasAction(action) {
			t.Errorf("missing audit action %s", action)
		}
	}
	env.verifyAudit()

	// Agent revokes its own lease; the credential dies immediately.
	revokeRec := env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases/"+lease.ID+"/revoke", model.RevokeLeaseInput{Reason: "task finished"})
	requireStatus(t, revokeRec, http.StatusOK)
	revoked := decodeEnvelope[model.Lease](t, revokeRec)
	if revoked.Status != model.LeaseRevoked || revoked.RevokeReason != "task finished" || revoked.RevokedAt == nil {
		t.Fatalf("revoked lease = %+v", revoked)
	}
	if revoked.CredentialAvailable {
		t.Fatal("revoked lease still reports a credential")
	}
	_, fetchAfter := env.fetchCredential("claude-code", lease.ID)
	requireErrorCode(t, fetchAfter, http.StatusConflict, model.ErrCodeLeaseNotActive)

	// The stored credential blob was scrubbed.
	if _, err := env.srv.db.GetLeaseCredential(t.Context(), lease.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("lease credential was not cleared (err = %v)", err)
	}
	if !env.hasAction("lease.revoked") {
		t.Fatal("missing lease.revoked audit event")
	}
	env.verifyAudit()
}

func TestHumanApprovalFlow(t *testing.T) {
	env := newTestEnv(t, true)

	lease, rec := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		TTLSeconds:   600,
		Reason:       "add ACME validation record",
	})
	requireStatus(t, rec, http.StatusCreated)
	if lease.Status != model.LeasePending {
		t.Fatalf("status = %q, want pending", lease.Status)
	}
	if lease.Decision.Outcome != model.OutcomeRequireApproval {
		t.Fatalf("decision = %q, want require_approval", lease.Decision.Outcome)
	}
	requireRuleOutcome(t, lease.Decision, "risk_above_auto", "require_approval")
	if lease.EffectiveTTLSeconds != 600 {
		t.Fatalf("effective TTL = %d, want requested 600", lease.EffectiveTTLSeconds)
	}

	// No credential exists before approval.
	_, pendingFetch := env.fetchCredential("claude-code", lease.ID)
	requireErrorCode(t, pendingFetch, http.StatusConflict, model.ErrCodeLeaseNotActive)
	if env.minter.requestCount() != 0 {
		t.Fatal("minter was called for a pending lease")
	}

	// Operator approves with a shorter TTL + note.
	approveRec := env.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", model.ApproveLeaseInput{
		TTLSeconds: 300,
		Note:       "approved for demo",
	})
	requireStatus(t, approveRec, http.StatusOK)
	approved := decodeEnvelope[model.Lease](t, approveRec)
	if approved.Status != model.LeaseActive || approved.ApprovedBy != "admin" {
		t.Fatalf("approved lease = %+v", approved)
	}
	if approved.EffectiveTTLSeconds != 300 || approved.ApprovalNote != "approved for demo" {
		t.Fatalf("approval TTL/note not applied: %+v", approved)
	}
	if approved.ExpiresAt == nil || !approved.ExpiresAt.Equal(fixedTestTime.Add(300*time.Second)) {
		t.Fatalf("expires_at = %v", approved.ExpiresAt)
	}

	// Mint received the rendered, domain-scoped policy.
	req := env.minter.lastRequest(t)
	if !strings.Contains(string(req.PolicyJSON), "acs:alidns:*:*:domain/arveykao.com") {
		t.Fatalf("rendered policy = %s, want domain-scoped resource", req.PolicyJSON)
	}
	if req.DurationSeconds != 300 {
		t.Fatalf("mint duration = %d, want 300", req.DurationSeconds)
	}

	// Credential is now fetchable.
	envelope, credRec := env.fetchCredential("claude-code", lease.ID)
	requireStatus(t, credRec, http.StatusOK)
	if envelope.Credential.LeaseID != lease.ID {
		t.Fatalf("credential lease = %q", envelope.Credential.LeaseID)
	}
	for _, action := range []string{"lease.approved", "lease.credential_issued", "lease.credential_fetched"} {
		if !env.hasAction(action) {
			t.Errorf("missing audit action %s", action)
		}
	}
	env.verifyAudit()

	// A second request is denied by the operator.
	second, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "second record",
	})
	if second.Status != model.LeasePending {
		t.Fatalf("second lease status = %q, want pending", second.Status)
	}
	denyRec := env.admin(http.MethodPost, "/api/v1/admin/leases/"+second.ID+"/deny", model.DenyLeaseInput{
		Reason: "only one DNS change approved",
	})
	requireStatus(t, denyRec, http.StatusOK)
	denied := decodeEnvelope[model.Lease](t, denyRec)
	if denied.Status != model.LeaseDenied || denied.DeniedReason != "only one DNS change approved" {
		t.Fatalf("denied lease = %+v", denied)
	}
	_, deniedFetch := env.fetchCredential("claude-code", second.ID)
	requireErrorCode(t, deniedFetch, http.StatusConflict, model.ErrCodeLeaseNotActive)
	if !env.hasAction("lease.denied") {
		t.Fatal("missing lease.denied audit event")
	}

	// Denying a non-pending lease is a conflict.
	again := env.admin(http.MethodPost, "/api/v1/admin/leases/"+second.ID+"/deny", model.DenyLeaseInput{Reason: "again"})
	requireErrorCode(t, again, http.StatusConflict, model.ErrCodeConflict)
	env.verifyAudit()
}

func TestCreateLeaseValidation(t *testing.T) {
	env := newTestEnv(t, true)

	// Unknown capability.
	rec := env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases", model.CreateLeaseInput{CapabilityID: "cap_does_not_exist"})
	requireErrorCode(t, rec, http.StatusNotFound, model.ErrCodeNotFound)

	// Missing required param.
	rec = env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases", model.CreateLeaseInput{CapabilityID: "aliyun.dns.manage"})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// Param does not match the declared pattern.
	rec = env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "NOT A DOMAIN"},
	})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// Unknown param is rejected.
	rec = env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Params:       map[string]string{"domain": "example.com"},
	})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// Negative TTL and invalid JSON.
	rec = env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases", map[string]any{
		"capability_id": "aliyun.cloud.read",
		"ttl_seconds":   -1,
	})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	rec = env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases", []byte(`{not json`))
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// No lease rows were created by invalid requests.
	items, total, err := env.srv.db.ListLeases(t.Context(), store.LeaseFilter{})
	if err != nil {
		t.Fatalf("ListLeases: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("invalid requests created %d leases, want 0", total)
	}
}

func TestPolicyDenials(t *testing.T) {
	env := newTestEnv(t, true)

	// Not granted: hermes only holds aliyun.cloud.read.
	lease, rec := env.createLease("hermes-researcher", model.CreateLeaseInput{
		CapabilityID: "aliyun.ecs.instance.ops",
		Params:       map[string]string{"instance_id": "i-2ze0demo001"},
		Reason:       "restart web server",
	})
	requireStatus(t, rec, http.StatusCreated)
	if lease.Status != model.LeaseDenied || lease.Decision.Outcome != model.OutcomeDeny {
		t.Fatalf("denied lease = %+v", lease)
	}
	requireRuleOutcome(t, lease.Decision, "capability_granted", "deny")
	if !strings.Contains(lease.DeniedReason, "capability_granted") {
		t.Fatalf("denied_reason = %q, want rule name", lease.DeniedReason)
	}
	_, fetchRec := env.fetchCredential("hermes-researcher", lease.ID)
	requireErrorCode(t, fetchRec, http.StatusConflict, model.ErrCodeLeaseNotActive)
	if env.minter.requestCount() != 0 {
		t.Fatal("denied lease minted a credential")
	}

	// TTL above capability max is denied.
	denied, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		TTLSeconds:   1801,
		Reason:       "too long",
	})
	if denied.Status != model.LeaseDenied {
		t.Fatalf("over-max TTL lease status = %q, want denied", denied.Status)
	}
	requireRuleOutcome(t, denied.Decision, "ttl_within_capability", "deny")

	// TTL above the agent max is denied (hermes max 900s).
	agentTTL, _ := env.createLease("hermes-researcher", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		TTLSeconds:   1200,
		Reason:       "long read",
	})
	if agentTTL.Status != model.LeaseDenied {
		t.Fatalf("agent-max TTL lease status = %q, want denied", agentTTL.Status)
	}
	requireRuleOutcome(t, agentTTL.Decision, "ttl_within_agent", "deny")

	// TTL above the auto-approve window but within limits requires approval.
	slower, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		TTLSeconds:   1200,
		Reason:       "long inventory",
	})
	if slower.Status != model.LeasePending || slower.Decision.Outcome != model.OutcomeRequireApproval {
		t.Fatalf("long TTL lease = %+v, want pending", slower)
	}
	requireRuleOutcome(t, slower.Decision, "ttl_above_auto", "require_approval")
	env.verifyAudit()
}

func TestConcurrencyLimit(t *testing.T) {
	env := newTestEnv(t, true)
	// claude-code max_concurrent_leases = 3.
	for i := 0; i < 3; i++ {
		lease, rec := env.createLease("claude-code", model.CreateLeaseInput{
			CapabilityID: "aliyun.cloud.read",
			Reason:       "parallel read",
		})
		requireStatus(t, rec, http.StatusCreated)
		if lease.Status != model.LeaseActive {
			t.Fatalf("lease %d status = %q, want active", i, lease.Status)
		}
	}
	blocked, rec := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "one too many",
	})
	requireStatus(t, rec, http.StatusCreated)
	if blocked.Status != model.LeaseDenied {
		t.Fatalf("over-concurrency lease status = %q, want denied", blocked.Status)
	}
	requireRuleOutcome(t, blocked.Decision, "concurrency_available", "deny")
	if !strings.Contains(blocked.DeniedReason, "concurrency_available") {
		t.Fatalf("denied_reason = %q", blocked.DeniedReason)
	}

	// After one lease is revoked, a new request fits again.
	active, err := env.srv.db.ListActiveLeases(t.Context())
	if err != nil || len(active) != 3 {
		t.Fatalf("active leases = %d, %v", len(active), err)
	}
	revokeRec := env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases/"+active[0].ID+"/revoke", nil)
	requireStatus(t, revokeRec, http.StatusOK)
	next, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "fits now",
	})
	if next.Status != model.LeaseActive {
		t.Fatalf("lease after revoke status = %q, want active (reasons %v)", next.Status, next.Decision.Reasons)
	}
}

func TestRateLimit(t *testing.T) {
	env := newTestEnv(t, true)
	// claude-code is allowed 6 leases per minute; create and revoke six.
	for i := 0; i < 6; i++ {
		lease, rec := env.createLease("claude-code", model.CreateLeaseInput{
			CapabilityID: "aliyun.cloud.read",
			Reason:       "rapid read",
		})
		requireStatus(t, rec, http.StatusCreated)
		revokeRec := env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases/"+lease.ID+"/revoke", nil)
		requireStatus(t, revokeRec, http.StatusOK)
	}
	blocked, rec := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "seventh request",
	})
	requireStatus(t, rec, http.StatusCreated)
	if blocked.Status != model.LeaseDenied {
		t.Fatalf("rate-limited lease status = %q, want denied", blocked.Status)
	}
	requireRuleOutcome(t, blocked.Decision, "rate_limit", "deny")

	// After a minute the window clears.
	env.clock.Advance(61 * time.Second)
	allowed, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "new minute",
	})
	if allowed.Status != model.LeaseActive {
		t.Fatalf("lease after rate window status = %q, want active (reasons %v)", allowed.Status, allowed.Decision.Reasons)
	}
}

func TestBreakGlassFlow(t *testing.T) {
	env := newTestEnv(t, true)

	// Critical capability without the break-glass flag is denied.
	denied, rec := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.iam.break_glass",
		Reason:       "emergency",
	})
	requireStatus(t, rec, http.StatusCreated)
	if denied.Status != model.LeaseDenied {
		t.Fatalf("break-glass without flag status = %q, want denied", denied.Status)
	}
	requireRuleOutcome(t, denied.Decision, "break_glass_required", "deny")

	// With the flag it requires approval.
	pending, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.iam.break_glass",
		Reason:       "emergency account recovery",
		BreakGlass:   true,
	})
	if pending.Status != model.LeasePending {
		t.Fatalf("break-glass with flag status = %q, want pending", pending.Status)
	}
	requireRuleOutcome(t, pending.Decision, "break_glass_approval", "require_approval")
	if !pending.BreakGlass {
		t.Fatal("lease.break_glass = false, want true")
	}

	// Approval is audited at critical severity.
	approveRec := env.admin(http.MethodPost, "/api/v1/admin/leases/"+pending.ID+"/approve", model.ApproveLeaseInput{Note: "approved emergency"})
	requireStatus(t, approveRec, http.StatusOK)
	approved := decodeEnvelope[model.Lease](t, approveRec)
	if approved.Status != model.LeaseActive {
		t.Fatalf("approved break-glass lease status = %q, want active", approved.Status)
	}
	critical := false
	for _, ev := range env.listAudit("lease.approved") {
		if ev.Severity == "critical" && ev.TargetID == pending.ID {
			critical = true
		}
	}
	if !critical {
		t.Fatal("break-glass approval was not audited at critical severity")
	}

	// Revocation is critical-severity and kills the credential.
	revokeRec := env.admin(http.MethodPost, "/api/v1/admin/leases/"+pending.ID+"/revoke", model.RevokeLeaseInput{Reason: "emergency over"})
	requireStatus(t, revokeRec, http.StatusOK)
	_, fetchRec := env.fetchCredential("claude-code", pending.ID)
	requireErrorCode(t, fetchRec, http.StatusConflict, model.ErrCodeLeaseNotActive)
	critical = false
	for _, ev := range env.listAudit("lease.revoked") {
		if ev.Severity == "critical" && ev.TargetID == pending.ID {
			critical = true
		}
	}
	if !critical {
		t.Fatal("break-glass revocation was not audited at critical severity")
	}
	env.verifyAudit()
}

func TestAgentIsolation(t *testing.T) {
	env := newTestEnv(t, true)

	claudeLease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "claude inventory",
	})

	// Hermes cannot see, fetch or revoke claude-code's lease.
	rec := env.agent("hermes-researcher", http.MethodGet, "/api/v1/agent/leases/"+claudeLease.ID, nil)
	requireErrorCode(t, rec, http.StatusNotFound, model.ErrCodeNotFound)
	rec = env.agent("hermes-researcher", http.MethodPost, "/api/v1/agent/leases/"+claudeLease.ID+"/credential", nil)
	requireErrorCode(t, rec, http.StatusNotFound, model.ErrCodeNotFound)
	rec = env.agent("hermes-researcher", http.MethodPost, "/api/v1/agent/leases/"+claudeLease.ID+"/revoke", nil)
	requireErrorCode(t, rec, http.StatusNotFound, model.ErrCodeNotFound)

	// Hermes' own list does not leak claude-code's lease.
	rec = env.agent("hermes-researcher", http.MethodGet, "/api/v1/agent/leases", nil)
	requireStatus(t, rec, http.StatusOK)
	hermesLeases := decodeEnvelope[model.ListResponse[model.Lease]](t, rec)
	if hermesLeases.Total != 0 || len(hermesLeases.Items) != 0 {
		t.Fatalf("hermes sees %d leases, want 0", hermesLeases.Total)
	}

	// The admin sees all leases.
	rec = env.admin(http.MethodGet, "/api/v1/admin/leases", nil)
	requireStatus(t, rec, http.StatusOK)
	allLeases := decodeEnvelope[model.ListResponse[model.Lease]](t, rec)
	if allLeases.Total != 1 || allLeases.Items[0].ID != claudeLease.ID {
		t.Fatalf("admin leases = %+v", allLeases)
	}

	// Ownership errors are indistinguishable from not-found (no ID probing).
	rec = env.agent("hermes-researcher", http.MethodGet, "/api/v1/agent/leases/lea_does_not_exist", nil)
	requireErrorCode(t, rec, http.StatusNotFound, model.ErrCodeNotFound)
}

func TestCredentialAfterExpiry(t *testing.T) {
	env := newTestEnv(t, true)
	lease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "short read",
	})
	if lease.Status != model.LeaseActive {
		t.Fatalf("lease status = %q, want active", lease.Status)
	}

	// Before TTL the credential is fetchable.
	if _, rec := env.fetchCredential("claude-code", lease.ID); rec.Code != http.StatusOK {
		t.Fatalf("pre-expiry credential fetch status = %d", rec.Code)
	}

	// Past the TTL, the fetch is refused even before the sweeper runs.
	env.clock.Advance(901 * time.Second)
	_, rec := env.fetchCredential("claude-code", lease.ID)
	requireErrorCode(t, rec, http.StatusConflict, model.ErrCodeLeaseNotActive)

	// The sweeper expires the lease and scrubs the credential.
	env.srv.sweepOnce(t.Context())
	expired := env.getLease(lease.ID)
	if expired.Status != model.LeaseExpired {
		t.Fatalf("lease status after sweep = %q, want expired", expired.Status)
	}
	if expired.CredentialAvailable {
		t.Fatal("expired lease still reports a credential")
	}
	if _, err := env.srv.db.GetLeaseCredential(t.Context(), lease.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired lease credential was not scrubbed (err = %v)", err)
	}
	var expiredAudit bool
	for _, ev := range env.listAudit("lease.expired") {
		if ev.TargetID == lease.ID && ev.Severity == "warning" {
			expiredAudit = true
		}
	}
	if !expiredAudit {
		t.Fatal("missing lease.expired audit event")
	}
	env.verifyAudit()
}

func TestPendingLeaseTimeout(t *testing.T) {
	env := newTestEnv(t, true)
	lease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "needs approval",
	})
	if lease.Status != model.LeasePending {
		t.Fatalf("lease status = %q, want pending", lease.Status)
	}

	// Approving after the pending window expires fails with a conflict.
	env.clock.Advance(601 * time.Second)
	approveRec := env.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", model.ApproveLeaseInput{})
	requireErrorCode(t, approveRec, http.StatusConflict, model.ErrCodeConflict)
	if got := env.getLease(lease.ID); got.Status != model.LeaseExpired {
		t.Fatalf("lease status = %q, want expired", got.Status)
	}
	env.verifyAudit()
}

func TestApproveValidation(t *testing.T) {
	env := newTestEnv(t, true)

	dnsLease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "dns change",
	})

	// TTL above the capability maximum is rejected.
	rec := env.admin(http.MethodPost, "/api/v1/admin/leases/"+dnsLease.ID+"/approve", model.ApproveLeaseInput{TTLSeconds: 1801})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// Approval succeeds with the default TTL.
	rec = env.admin(http.MethodPost, "/api/v1/admin/leases/"+dnsLease.ID+"/approve", model.ApproveLeaseInput{})
	requireStatus(t, rec, http.StatusOK)
	// Approving an already active lease conflicts.
	rec = env.admin(http.MethodPost, "/api/v1/admin/leases/"+dnsLease.ID+"/approve", model.ApproveLeaseInput{})
	requireErrorCode(t, rec, http.StatusConflict, model.ErrCodeConflict)

	// Deny validation: reason is mandatory and bounded.
	pending2, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "second dns change",
	})
	rec = env.admin(http.MethodPost, "/api/v1/admin/leases/"+pending2.ID+"/deny", model.DenyLeaseInput{Reason: ""})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	rec = env.admin(http.MethodPost, "/api/v1/admin/leases/"+pending2.ID+"/deny", model.DenyLeaseInput{Reason: strings.Repeat("x", 501)})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// Revoking a terminal lease conflicts.
	rec = env.admin(http.MethodPost, "/api/v1/admin/leases/"+pending2.ID+"/revoke", nil)
	requireStatus(t, rec, http.StatusOK)
	rec = env.admin(http.MethodPost, "/api/v1/admin/leases/"+pending2.ID+"/revoke", nil)
	requireErrorCode(t, rec, http.StatusConflict, model.ErrCodeConflict)
}

func TestAgentRevokesPendingLease(t *testing.T) {
	env := newTestEnv(t, true)
	lease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "not needed anymore",
	})
	rec := env.agent("claude-code", http.MethodPost, "/api/v1/agent/leases/"+lease.ID+"/revoke", model.RevokeLeaseInput{Reason: "changed my mind"})
	requireStatus(t, rec, http.StatusOK)
	revoked := decodeEnvelope[model.Lease](t, rec)
	if revoked.Status != model.LeaseRevoked {
		t.Fatalf("status = %q, want revoked", revoked.Status)
	}
	// The pending lease can no longer be approved.
	approveRec := env.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", model.ApproveLeaseInput{})
	requireErrorCode(t, approveRec, http.StatusConflict, model.ErrCodeConflict)
}

func TestMintFailure(t *testing.T) {
	env := newTestEnv(t, true)
	env.minter.setFailure(errors.New("STS boom: AccessDenied"))

	lease, rec := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "provider failure test",
	})
	requireStatus(t, rec, http.StatusCreated)
	if lease.Status != model.LeaseFailed {
		t.Fatalf("lease status = %q, want failed", lease.Status)
	}
	if !strings.Contains(lease.FailureReason, "STS boom") {
		t.Fatalf("failure_reason = %q", lease.FailureReason)
	}
	if lease.CredentialAvailable {
		t.Fatal("failed lease reports a credential")
	}
	_, fetchRec := env.fetchCredential("claude-code", lease.ID)
	requireErrorCode(t, fetchRec, http.StatusConflict, model.ErrCodeLeaseNotActive)
	if !env.hasAction("lease.failed") {
		t.Fatal("missing lease.failed audit event")
	}

	// Approval-time mint failures return 200 with a failed lease and no credential.
	env.minter.setFailure(errors.New("STS\ninjected\nnewline"))
	pending, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "approval failure test",
	})
	approveRec := env.admin(http.MethodPost, "/api/v1/admin/leases/"+pending.ID+"/approve", model.ApproveLeaseInput{})
	requireStatus(t, approveRec, http.StatusOK)
	failed := decodeEnvelope[model.Lease](t, approveRec)
	if failed.Status != model.LeaseFailed {
		t.Fatalf("approve-failed lease status = %q, want failed", failed.Status)
	}
	if strings.ContainsAny(failed.FailureReason, "\n\r") {
		t.Fatalf("failure_reason is not sanitized: %q", failed.FailureReason)
	}
}

func TestBackgroundSweeperExpiresLeases(t *testing.T) {
	oldInterval := sweepInterval
	sweepInterval = 5 * time.Millisecond
	t.Cleanup(func() { sweepInterval = oldInterval })

	env := newTestEnv(t, true)
	lease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "sweeper test",
	})
	if lease.Status != model.LeaseActive {
		t.Fatalf("lease status = %q, want active", lease.Status)
	}
	env.clock.Advance(901 * time.Second)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := env.getLease(lease.ID); got.Status == model.LeaseExpired {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("background sweeper did not expire the lease (status %q)", env.getLease(lease.ID).Status)
}

func TestAgentLeaseListFilters(t *testing.T) {
	env := newTestEnv(t, true)
	activeLease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "list test active",
	})
	if activeLease.Status != model.LeaseActive {
		t.Fatalf("expected active lease, got %q", activeLease.Status)
	}
	pendingLease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "list test pending",
	})
	if pendingLease.Status != model.LeasePending {
		t.Fatalf("expected pending lease, got %q", pendingLease.Status)
	}

	// Filter by status.
	rec := env.agent("claude-code", http.MethodGet, "/api/v1/agent/leases?status=active", nil)
	requireStatus(t, rec, http.StatusOK)
	activeList := decodeEnvelope[model.ListResponse[model.Lease]](t, rec)
	if activeList.Total != 1 || activeList.Items[0].ID != activeLease.ID {
		t.Fatalf("active filter = %+v", activeList)
	}

	// Pagination preserves the total.
	rec = env.agent("claude-code", http.MethodGet, "/api/v1/agent/leases?limit=1", nil)
	requireStatus(t, rec, http.StatusOK)
	page := decodeEnvelope[model.ListResponse[model.Lease]](t, rec)
	if page.Total != 2 || len(page.Items) != 1 {
		t.Fatalf("pagination total=%d len=%d, want 2/1", page.Total, len(page.Items))
	}

	// Invalid status is a 400.
	rec = env.agent("claude-code", http.MethodGet, "/api/v1/agent/leases?status=bogus", nil)
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// Admin filters by agent and capability.
	rec = env.admin(http.MethodGet, "/api/v1/admin/leases?capability_id=aliyun.dns.manage", nil)
	requireStatus(t, rec, http.StatusOK)
	byCapability := decodeEnvelope[model.ListResponse[model.Lease]](t, rec)
	if byCapability.Total != 1 || byCapability.Items[0].ID != pendingLease.ID {
		t.Fatalf("capability filter = %+v", byCapability)
	}
	rec = env.admin(http.MethodGet, "/api/v1/admin/leases?agent_id="+env.agentIDs["hermes-researcher"], nil)
	requireStatus(t, rec, http.StatusOK)
	byAgent := decodeEnvelope[model.ListResponse[model.Lease]](t, rec)
	if byAgent.Total != 0 {
		t.Fatalf("agent filter = %+v, want 0", byAgent)
	}
}
