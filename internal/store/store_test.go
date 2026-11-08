package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/vaultcrypto"
)

var testTime = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return db
}

func testProvider() model.Provider {
	return model.Provider{
		ID:                "prv_test1",
		Name:              "test-provider",
		Type:              model.ProviderAliyun,
		Mode:              model.ModeMock,
		Region:            "cn-hangzhou",
		RoleARN:           "acs:ram::1234567890123456:role/csg-demo",
		AccessKeyIDMasked: "LTAI****oker",
		Status:            model.ProviderActive,
		CreatedAt:         testTime,
		UpdatedAt:         testTime,
	}
}

func testCapability() model.Capability {
	return model.Capability{
		ID:                "cap_test1",
		Name:              "Test capability",
		Description:       "unit test capability",
		ProviderType:      model.ProviderAliyun,
		Risk:              model.RiskLow,
		PolicyTemplate:    `{"Version":"1","Statement":[]}`,
		Params:            []model.CapabilityParam{{Name: "domain", Required: true, Pattern: `^[a-z]+\.com$`}},
		DefaultTTLSeconds: 900,
		MaxTTLSeconds:     1800,
		Enabled:           true,
		Builtin:           true,
		CreatedAt:         testTime,
		UpdatedAt:         testTime,
	}
}

func testAgent() model.Agent {
	return model.Agent{
		ID:                  "agt_test1",
		Name:                "test-agent",
		Description:         "unit test agent",
		Status:              model.AgentActive,
		Grants:              []string{"cap_test1"},
		MaxTTLSeconds:       1800,
		MaxConcurrentLeases: 3,
		TokenPrefix:         "csg_agt_abcd",
		CreatedAt:           testTime,
		UpdatedAt:           testTime,
	}
}

func testLease(id string, status model.LeaseStatus, createdAt time.Time) model.Lease {
	l := model.Lease{
		ID:                  id,
		AgentID:             "agt_test1",
		AgentName:           "test-agent",
		CapabilityID:        "cap_test1",
		CapabilityName:      "Test capability",
		ProviderID:          "prv_test1",
		ProviderName:        "test-provider",
		ProviderMode:        model.ModeMock,
		Risk:                model.RiskLow,
		Params:              map[string]string{"domain": "example.com"},
		Reason:              "unit test",
		RequestedTTLSeconds: 0,
		EffectiveTTLSeconds: 900,
		Status:              status,
		Decision: model.PolicyDecision{
			Outcome:             model.OutcomeAutoApprove,
			EffectiveTTLSeconds: 900,
			Reasons: []model.DecisionReason{
				{Rule: "capability_granted", Outcome: "allow", Detail: "ok"},
			},
		},
		SessionName: "csg-agt_test1-" + id,
		CreatedAt:   createdAt,
	}
	if status == model.LeaseActive {
		issued := createdAt
		expires := createdAt.Add(900 * time.Second)
		l.IssuedAt = &issued
		l.ExpiresAt = &expires
		l.ApprovedBy = "auto"
		l.CredentialAvailable = true
		l.CredentialFingerprint = "AKID****9f2c"
	}
	return l
}

func TestOpenMigratesAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	db, err := Open(ctx, dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	version, err := db.GetMeta(ctx, MetaSchemaVersion)
	if err != nil {
		t.Fatalf("GetMeta(schema_version): %v", err)
	}
	if version != "1" {
		t.Fatalf("schema_version = %q, want \"1\"", version)
	}
	if err := db.SetMeta(ctx, "keepme", "value1"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	dbPath := db.Path()
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("db file mode = %o, want 0600", perm)
	}
	if filepath.Base(dbPath) != DBFileName {
		t.Errorf("db file name = %q, want %q", filepath.Base(dbPath), DBFileName)
	}

	// Re-open: migrations must be a no-op and data must be preserved.
	db2, err := Open(ctx, dir)
	if err != nil {
		t.Fatalf("Open (second): %v", err)
	}
	defer db2.Close()
	got, err := db2.GetMeta(ctx, "keepme")
	if err != nil {
		t.Fatalf("GetMeta after reopen: %v", err)
	}
	if got != "value1" {
		t.Fatalf("meta value after reopen = %q, want value1", got)
	}
	version2, err := db2.GetMeta(ctx, MetaSchemaVersion)
	if err != nil || version2 != "1" {
		t.Fatalf("schema_version after reopen = %q, %v", version2, err)
	}
}

func TestMeta(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if _, err := db.GetMeta(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetMeta(missing) error = %v, want ErrNotFound", err)
	}
	if err := db.SetMeta(ctx, "a", "1"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	if err := db.SetMeta(ctx, "a", "2"); err != nil {
		t.Fatalf("SetMeta overwrite: %v", err)
	}
	got, err := db.GetMeta(ctx, "a")
	if err != nil || got != "2" {
		t.Fatalf("GetMeta = %q, %v", got, err)
	}
}

func TestProviderCRUD(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	encCred := "v1:encrypted-broker-credential"
	p := testProvider()

	if err := db.CreateProvider(ctx, p, encCred); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	// Duplicate ID → ErrConflict.
	if err := db.CreateProvider(ctx, p, encCred); !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateProvider duplicate error = %v, want ErrConflict", err)
	}

	got, err := db.GetProvider(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	if got.Name != p.Name || got.Mode != p.Mode || got.AccessKeyIDMasked != p.AccessKeyIDMasked {
		t.Fatalf("GetProvider = %+v, want %+v", got, p)
	}
	if !got.CreatedAt.Equal(testTime) {
		t.Fatalf("CreatedAt = %v, want %v", got.CreatedAt, testTime)
	}

	list, err := db.ListProviders(ctx)
	if err != nil {
		t.Fatalf("ListProviders: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len(ListProviders) = %d, want 1", len(list))
	}

	p.Name = "renamed"
	p.Status = model.ProviderDisabled
	p.UpdatedAt = testTime.Add(time.Minute)
	ok := true
	p.LastTestOK = &ok
	tested := testTime.Add(2 * time.Minute)
	p.LastTestedAt = &tested
	if err := db.UpdateProvider(ctx, p); err != nil {
		t.Fatalf("UpdateProvider: %v", err)
	}
	got, err = db.GetProvider(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetProvider after update: %v", err)
	}
	if got.Name != "renamed" || got.Status != model.ProviderDisabled {
		t.Fatalf("provider not updated: %+v", got)
	}
	if got.LastTestOK == nil || !*got.LastTestOK || got.LastTestedAt == nil || !got.LastTestedAt.Equal(tested) {
		t.Fatalf("last test fields not persisted: %+v", got)
	}

	if err := db.UpdateProvider(ctx, model.Provider{ID: "prv_missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateProvider(missing) error = %v, want ErrNotFound", err)
	}
	if _, err := db.GetProvider(ctx, "prv_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetProvider(missing) error = %v, want ErrNotFound", err)
	}

	cred, err := db.GetProviderCredential(ctx, p.ID)
	if err != nil || cred != encCred {
		t.Fatalf("GetProviderCredential = %q, %v", cred, err)
	}
	if n, err := db.CountProviderCredentials(ctx); err != nil || n != 1 {
		t.Fatalf("CountProviderCredentials = %d, %v", n, err)
	}

	if err := db.UpdateProviderCredential(ctx, p.ID, "v1:rotated"); err != nil {
		t.Fatalf("UpdateProviderCredential: %v", err)
	}
	cred, _ = db.GetProviderCredential(ctx, p.ID)
	if cred != "v1:rotated" {
		t.Fatalf("credential after rotate = %q", cred)
	}
}

func TestCapabilityCRUD(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	c := testCapability()

	if err := db.CreateCapability(ctx, c); err != nil {
		t.Fatalf("CreateCapability: %v", err)
	}
	if err := db.CreateCapability(ctx, c); !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateCapability duplicate error = %v, want ErrConflict", err)
	}
	got, err := db.GetCapability(ctx, c.ID)
	if err != nil {
		t.Fatalf("GetCapability: %v", err)
	}
	if len(got.Params) != 1 || got.Params[0].Name != "domain" || !got.Builtin || !got.Enabled {
		t.Fatalf("GetCapability = %+v", got)
	}
	got.Enabled = false
	got.Description = "updated"
	got.UpdatedAt = testTime.Add(time.Minute)
	if err := db.UpdateCapability(ctx, got); err != nil {
		t.Fatalf("UpdateCapability: %v", err)
	}
	again, _ := db.GetCapability(ctx, c.ID)
	if again.Enabled || again.Description != "updated" {
		t.Fatalf("capability not updated: %+v", again)
	}
	list, err := db.ListCapabilities(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListCapabilities = %v, %v", list, err)
	}
	if _, err := db.GetCapability(ctx, "cap_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetCapability(missing) error = %v, want ErrNotFound", err)
	}
}

func TestAgentCRUD(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	a := testAgent()
	hash := strings.Repeat("a1", 32)

	if err := db.CreateAgent(ctx, a, hash); err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	got, err := db.GetAgent(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	if got.Name != a.Name || len(got.Grants) != 1 || got.Grants[0] != "cap_test1" {
		t.Fatalf("GetAgent = %+v", got)
	}
	// Token hash resolution.
	byToken, err := db.GetAgentByTokenHash(ctx, hash)
	if err != nil || byToken.ID != a.ID {
		t.Fatalf("GetAgentByTokenHash = %+v, %v", byToken, err)
	}
	if _, err := db.GetAgentByTokenHash(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAgentByTokenHash(unknown) error = %v, want ErrNotFound", err)
	}

	seen := testTime.Add(30 * time.Second)
	if err := db.TouchAgentSeen(ctx, a.ID, seen); err != nil {
		t.Fatalf("TouchAgentSeen: %v", err)
	}
	got, _ = db.GetAgent(ctx, a.ID)
	if got.LastSeenAt == nil || !got.LastSeenAt.Equal(seen) {
		t.Fatalf("LastSeenAt = %v, want %v", got.LastSeenAt, seen)
	}

	got.Status = model.AgentSuspended
	if err := db.UpdateAgent(ctx, got); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	again, _ := db.GetAgent(ctx, a.ID)
	if again.Status != model.AgentSuspended {
		t.Fatalf("agent status = %q, want suspended", again.Status)
	}

	newHash := strings.Repeat("b2", 32)
	if err := db.UpdateAgentTokenHash(ctx, a.ID, newHash); err != nil {
		t.Fatalf("UpdateAgentTokenHash: %v", err)
	}
	if _, err := db.GetAgentByTokenHash(ctx, hash); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old token hash still resolves: %v", err)
	}
	if _, err := db.GetAgentByTokenHash(ctx, newHash); err != nil {
		t.Fatalf("new token hash does not resolve: %v", err)
	}

	// Unique token hash constraint.
	if err := db.CreateAgent(ctx, model.Agent{ID: "agt_dup", Name: "dup"}, newHash); !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateAgent duplicate token hash error = %v, want ErrConflict", err)
	}

	list, err := db.ListAgents(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListAgents = %v, %v", list, err)
	}
	if _, err := db.GetAgent(ctx, "agt_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetAgent(missing) error = %v, want ErrNotFound", err)
	}
}

func TestLeaseCRUDAndQueries(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	pendingOld := testLease("lea_pending_old", model.LeasePending, testTime)
	pendingNew := testLease("lea_pending_new", model.LeasePending, testTime.Add(10*time.Second))
	active := testLease("lea_active", model.LeaseActive, testTime.Add(20*time.Second))
	active2 := testLease("lea_active2", model.LeaseActive, testTime.Add(30*time.Second))
	active2.AgentID = "agt_other"
	denied := testLease("lea_denied", model.LeaseDenied, testTime.Add(40*time.Second))
	denied.DeniedReason = "denied by policy"

	for _, l := range []model.Lease{pendingOld, pendingNew, active, active2, denied} {
		if err := db.CreateLease(ctx, l); err != nil {
			t.Fatalf("CreateLease(%s): %v", l.ID, err)
		}
	}
	if err := db.CreateLease(ctx, pendingOld); !errors.Is(err, ErrConflict) {
		t.Fatalf("CreateLease duplicate error = %v, want ErrConflict", err)
	}

	got, err := db.GetLease(ctx, active.ID)
	if err != nil {
		t.Fatalf("GetLease: %v", err)
	}
	if got.AgentID != active.AgentID || got.Status != model.LeaseActive || got.Params["domain"] != "example.com" {
		t.Fatalf("GetLease = %+v", got)
	}
	if got.Decision.Outcome != model.OutcomeAutoApprove || len(got.Decision.Reasons) != 1 {
		t.Fatalf("decision not round-tripped: %+v", got.Decision)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(*active.ExpiresAt) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, active.ExpiresAt)
	}

	// Credential blob lifecycle.
	encCred := "v1:lease-credential-blob"
	if err := db.SetLeaseCredential(ctx, active.ID, encCred, "LTAI****ABCD"); err != nil {
		t.Fatalf("SetLeaseCredential: %v", err)
	}
	blob, err := db.GetLeaseCredential(ctx, active.ID)
	if err != nil || blob != encCred {
		t.Fatalf("GetLeaseCredential = %q, %v", blob, err)
	}
	got, _ = db.GetLease(ctx, active.ID)
	if !got.CredentialAvailable || got.CredentialFingerprint != "LTAI****ABCD" {
		t.Fatalf("credential flags not persisted: %+v", got)
	}
	if err := db.ClearLeaseCredential(ctx, active.ID); err != nil {
		t.Fatalf("ClearLeaseCredential: %v", err)
	}
	if _, err := db.GetLeaseCredential(ctx, active.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetLeaseCredential after clear error = %v, want ErrNotFound", err)
	}
	got, _ = db.GetLease(ctx, active.ID)
	if got.CredentialAvailable || got.CredentialFingerprint != "" {
		t.Fatalf("credential flags not cleared: %+v", got)
	}

	// Update lifecycle.
	got.Status = model.LeaseRevoked
	revoked := testTime.Add(time.Hour)
	got.RevokedAt = &revoked
	got.RevokeReason = "test revoke"
	if err := db.UpdateLease(ctx, got); err != nil {
		t.Fatalf("UpdateLease: %v", err)
	}
	got2, _ := db.GetLease(ctx, active.ID)
	if got2.Status != model.LeaseRevoked || got2.RevokeReason != "test revoke" {
		t.Fatalf("lease not updated: %+v", got2)
	}

	// Filters.
	items, total, err := db.ListLeases(ctx, LeaseFilter{Statuses: []model.LeaseStatus{model.LeasePending}})
	if err != nil {
		t.Fatalf("ListLeases pending: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("pending leases total=%d len=%d, want 2/2", total, len(items))
	}
	if items[0].ID != pendingNew.ID { // newest first
		t.Fatalf("ListLeases order: first = %s, want %s", items[0].ID, pendingNew.ID)
	}

	items, total, err = db.ListLeases(ctx, LeaseFilter{AgentID: "agt_test1"})
	if err != nil {
		t.Fatalf("ListLeases by agent: %v", err)
	}
	if total != 4 || len(items) != 4 {
		t.Fatalf("leases by agent total=%d len=%d, want 4/4", total, len(items))
	}

	items, total, err = db.ListLeases(ctx, LeaseFilter{CapabilityID: "cap_test1", Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("ListLeases paged: %v", err)
	}
	if total != 5 || len(items) != 1 {
		t.Fatalf("paged leases total=%d len=%d, want 5/1", total, len(items))
	}

	// Sweeper queries.
	pending, err := db.ListPendingLeases(ctx)
	if err != nil || len(pending) != 2 {
		t.Fatalf("ListPendingLeases = %d, %v", len(pending), err)
	}
	actives, err := db.ListActiveLeases(ctx)
	// lea_active was revoked above, so only lea_active2 (another agent) remains.
	if err != nil || len(actives) != 1 {
		t.Fatalf("ListActiveLeases = %d, %v", len(actives), err)
	}
	if n, err := db.CountActiveLeases(ctx, "agt_test1"); err != nil || n != 0 {
		t.Fatalf("CountActiveLeases = %d, %v", n, err)
	}
	if n, err := db.CountLeasesSince(ctx, "agt_test1", testTime.Add(15*time.Second)); err != nil || n != 2 {
		t.Fatalf("CountLeasesSince = %d, %v", n, err)
	}
	risk, err := db.CountLeasesByRisk(ctx, []model.LeaseStatus{model.LeasePending, model.LeaseActive})
	if err != nil {
		t.Fatalf("CountLeasesByRisk: %v", err)
	}
	if risk.Low != 3 { // two pending + one still-active lease
		t.Fatalf("risk breakdown low = %d, want 3", risk.Low)
	}
	if n, err := db.CountLeasesCreatedSinceByStatus(ctx, model.LeaseDenied, testTime); err != nil || n != 1 {
		t.Fatalf("CountLeasesCreatedSinceByStatus = %d, %v", n, err)
	}
}

func TestPolicySettings(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	got, err := db.GetPolicySettings(ctx)
	if err != nil {
		t.Fatalf("GetPolicySettings: %v", err)
	}
	if got != model.DefaultPolicySettings() {
		t.Fatalf("default settings = %+v, want model defaults", got)
	}

	s := model.DefaultPolicySettings()
	s.AutoApproveMaxRisk = model.RiskMedium
	s.MaxLeaseTTLSeconds = 7200
	if err := db.SetPolicySettings(ctx, s); err != nil {
		t.Fatalf("SetPolicySettings: %v", err)
	}
	got, _ = db.GetPolicySettings(ctx)
	if got.AutoApproveMaxRisk != model.RiskMedium || got.MaxLeaseTTLSeconds != 7200 {
		t.Fatalf("settings not persisted: %+v", got)
	}

	bad := model.DefaultPolicySettings()
	bad.AutoApproveMaxRisk = "nonsense"
	if err := db.SetPolicySettings(ctx, bad); err == nil {
		t.Fatal("SetPolicySettings accepted invalid settings")
	}
}

func TestAuditChainVerify(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	for i := 0; i < 5; i++ {
		ev := model.AuditEvent{
			ActorType:  "system",
			ActorID:    "system",
			ActorName:  "Cloud Safeguard",
			Action:     "test.action",
			Status:     "ok",
			Severity:   "info",
			TargetType: "test",
			TargetID:   fmt.Sprintf("target-%d", i),
			Metadata:   map[string]any{"index": i, "note": "metadata"},
		}
		if err := db.AppendAudit(ctx, &ev); err != nil {
			t.Fatalf("AppendAudit(%d): %v", i, err)
		}
		if ev.Seq != int64(i+1) {
			t.Fatalf("event %d seq = %d, want %d", i, ev.Seq, i+1)
		}
		if !strings.HasPrefix(ev.ID, "evt_") {
			t.Fatalf("event ID = %q, want evt_ prefix", ev.ID)
		}
		if len(ev.Hash) != 64 {
			t.Fatalf("hash length = %d, want 64", len(ev.Hash))
		}
		if i == 0 && ev.PrevHash != auditGenesisHash {
			t.Fatalf("first prev_hash = %q, want genesis zeros", ev.PrevHash)
		}
	}

	// Each event chains from the previous hash.
	events, total, err := db.ListAudit(ctx, AuditFilter{})
	if err != nil || total != 5 {
		t.Fatalf("ListAudit total = %d, %v", total, err)
	}
	if events[0].Seq != 5 || events[4].Seq != 1 {
		t.Fatalf("ListAudit not newest first: %v", events)
	}
	for i := 1; i < len(events); i++ {
		newer := events[i-1]
		older := events[i]
		if newer.PrevHash != older.Hash {
			t.Fatalf("event %d prev_hash does not chain to event %d hash", newer.Seq, older.Seq)
		}
	}

	res, err := db.VerifyAudit(ctx)
	if err != nil {
		t.Fatalf("VerifyAudit: %v", err)
	}
	if !res.OK || res.Events != 5 {
		t.Fatalf("VerifyAudit = %+v, want ok with 5 events", res)
	}
}

func TestAuditEmptyChainVerifies(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	res, err := db.VerifyAudit(ctx)
	if err != nil {
		t.Fatalf("VerifyAudit: %v", err)
	}
	if !res.OK || res.Events != 0 {
		t.Fatalf("VerifyAudit(empty) = %+v", res)
	}
}

// TestAuditHashFormula independently reproduces the documented hash formula.
func TestAuditHashFormula(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	ev := model.AuditEvent{
		Time:       testTime,
		ActorType:  "admin",
		ActorID:    "admin",
		ActorName:  "operator",
		Action:     "policy.updated",
		Status:     "ok",
		Severity:   "warning",
		TargetType: "policy",
		TargetID:   "policy",
		Metadata:   map[string]any{"before": "a", "after": "b"},
	}
	if err := db.AppendAudit(ctx, &ev); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}

	metadataJSON := `{"after":"b","before":"a"}` // encoding/json sorts map keys
	canonical := fmt.Sprintf(
		`{"seq":1,"time":%q,"actor_type":"admin","actor_id":"admin","actor_name":"operator","action":"policy.updated","status":"ok","severity":"warning","target_type":"policy","target_id":"policy","metadata":%s}`,
		testTime.UTC().Format(time.RFC3339Nano), metadataJSON,
	)
	sum := sha256.Sum256([]byte("csg-audit-v1\n" + auditGenesisHash + "\n" + canonical))
	want := hex.EncodeToString(sum[:])
	if ev.Hash != want {
		t.Fatalf("hash mismatch:\n got %s\nwant %s\ncanonical %s", ev.Hash, want, canonical)
	}
}

func TestAuditTamperDetection(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	for i := 0; i < 3; i++ {
		ev := model.AuditEvent{
			ActorType: "system", ActorID: "system", ActorName: "Cloud Safeguard",
			Action: "test.action", Status: "ok", Severity: "info",
		}
		if err := db.AppendAudit(ctx, &ev); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}
	if _, err := db.SQL().ExecContext(ctx,
		`UPDATE audit SET severity = 'critical' WHERE seq = 2`); err != nil {
		t.Fatalf("tamper UPDATE: %v", err)
	}
	res, err := db.VerifyAudit(ctx)
	if err != nil {
		t.Fatalf("VerifyAudit: %v", err)
	}
	if res.OK {
		t.Fatal("VerifyAudit did not detect a tampered row")
	}
	if res.FirstInvalidSeq != 2 {
		t.Fatalf("FirstInvalidSeq = %d, want 2", res.FirstInvalidSeq)
	}
	if !strings.Contains(res.Message, "hash mismatch") {
		t.Fatalf("Message = %q, want hash mismatch", res.Message)
	}
}

func TestAuditSeqGapDetection(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	for i := 0; i < 4; i++ {
		ev := model.AuditEvent{
			ActorType: "system", ActorID: "system", ActorName: "Cloud Safeguard",
			Action: "test.action", Status: "ok", Severity: "info",
		}
		if err := db.AppendAudit(ctx, &ev); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}
	if _, err := db.SQL().ExecContext(ctx, `DELETE FROM audit WHERE seq = 2`); err != nil {
		t.Fatalf("delete row: %v", err)
	}
	res, err := db.VerifyAudit(ctx)
	if err != nil {
		t.Fatalf("VerifyAudit: %v", err)
	}
	if res.OK {
		t.Fatal("VerifyAudit did not detect a seq gap")
	}
	if res.FirstInvalidSeq != 2 {
		t.Fatalf("FirstInvalidSeq = %d, want 2", res.FirstInvalidSeq)
	}
}

func TestAuditConcurrentAppends(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	const goroutines = 8
	const perGoroutine = 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				ev := model.AuditEvent{
					ActorType: "agent", ActorID: fmt.Sprintf("agt_%d", g), ActorName: "agent",
					Action: "lease.requested", Status: "ok", Severity: "info",
					Metadata: map[string]any{"g": g, "i": i},
				}
				if err := db.AppendAudit(ctx, &ev); err != nil {
					errs <- err
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent AppendAudit: %v", err)
	}

	res, err := db.VerifyAudit(ctx)
	if err != nil {
		t.Fatalf("VerifyAudit: %v", err)
	}
	want := int64(goroutines * perGoroutine)
	if !res.OK || res.Events != want {
		t.Fatalf("VerifyAudit = %+v, want ok with %d events", res, want)
	}
}

func TestAuditFilters(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	fixtures := []model.AuditEvent{
		{Time: testTime, ActorType: "admin", ActorID: "admin", ActorName: "operator", Action: "provider.created", Status: "ok", Severity: "info"},
		{Time: testTime.Add(time.Minute), ActorType: "admin", ActorID: "admin", ActorName: "operator", Action: "policy.updated", Status: "ok", Severity: "warning"},
		{Time: testTime.Add(2 * time.Minute), ActorType: "agent", ActorID: "agt_1", ActorName: "agent", Action: "lease.requested", Status: "denied", Severity: "warning"},
		{Time: testTime.Add(3 * time.Minute), ActorType: "system", ActorID: "system", ActorName: "Cloud Safeguard", Action: "lease.expired", Status: "ok", Severity: "warning"},
	}
	for i := range fixtures {
		ev := fixtures[i]
		if err := db.AppendAudit(ctx, &ev); err != nil {
			t.Fatalf("AppendAudit: %v", err)
		}
	}

	tests := []struct {
		name   string
		filter AuditFilter
		want   int
	}{
		{"all", AuditFilter{}, 4},
		{"by action", AuditFilter{Action: "policy.updated"}, 1},
		{"by actor type", AuditFilter{ActorType: "admin"}, 2},
		{"by actor id", AuditFilter{ActorID: "agt_1"}, 1},
		{"by severity", AuditFilter{Severity: "warning"}, 3},
		{"by since", AuditFilter{Since: testTime.Add(2 * time.Minute)}, 2},
		{"paged", AuditFilter{Limit: 2, Offset: 1}, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items, total, err := db.ListAudit(ctx, tt.filter)
			if err != nil {
				t.Fatalf("ListAudit: %v", err)
			}
			if total != tt.want {
				t.Fatalf("total = %d, want %d", total, tt.want)
			}
			wantLen := tt.want
			if tt.filter.Limit > 0 && wantLen > tt.filter.Limit {
				wantLen = tt.filter.Limit
			}
			if len(items) != wantLen {
				t.Fatalf("len(items) = %d, want %d", len(items), wantLen)
			}
		})
	}
}

// TestNoPlaintextSecretsInDatabaseFiles proves broker/lease secrets never reach
// the SQLite database or WAL in plaintext.
func TestNoPlaintextSecretsInDatabaseFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	const brokerAKID = "LTAIcanaryBROKERAKID9f3c2b"
	const brokerSecret = "csg-canary-broker-secret-9f3c2b7a"
	const leaseAKID = "LTAIcanaryLEASEAKID1234"
	const leaseSecret = "csg-canary-lease-secret-4d8e1f"

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i * 7)
	}
	v, err := vault.New(masterKey)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}

	db, err := Open(ctx, dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	brokerCred, err := v.Encrypt([]byte(`{"access_key_id":"`+brokerAKID+`","access_key_secret":"`+brokerSecret+`"}`), "provider/prv_test1/credential")
	if err != nil {
		t.Fatalf("Encrypt broker: %v", err)
	}
	if err := db.CreateProvider(ctx, testProvider(), brokerCred); err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}

	leaseCred, err := v.Encrypt([]byte(`{"access_key_id":"`+leaseAKID+`","access_key_secret":"`+leaseSecret+`"}`), "lease/lea_test/credential")
	if err != nil {
		t.Fatalf("Encrypt lease: %v", err)
	}
	lease := testLease("lea_test", model.LeaseActive, testTime)
	if err := db.CreateLease(ctx, lease); err != nil {
		t.Fatalf("CreateLease: %v", err)
	}
	if err := db.SetLeaseCredential(ctx, lease.ID, leaseCred, "LTAI****1234"); err != nil {
		t.Fatalf("SetLeaseCredential: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Scan every database file (main DB, WAL, shared-memory index) for the
	// plaintext canaries.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	scanned := 0
	canaries := []string{brokerAKID, brokerSecret, leaseAKID, leaseSecret}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, DBFileName) {
			continue // master.key etc. are not database files
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		scanned++
		for _, canary := range canaries {
			if bytes.Contains(data, []byte(canary)) {
				t.Fatalf("plaintext secret %q found in database file %s", canary, name)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no database files were scanned")
	}
	// Sanity check: the encrypted blobs themselves are present.
	db2, err := Open(ctx, dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	blob, err := db2.GetProviderCredential(ctx, "prv_test1")
	if err != nil || !strings.HasPrefix(blob, "v1:") {
		t.Fatalf("encrypted provider credential = %q, %v", blob, err)
	}
	// And the ciphertext actually decrypts to the canary, proving encryption
	// (not accidental omission) is what protects it.
	plain, err := v.Decrypt(blob, "provider/prv_test1/credential")
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	var stored map[string]string
	if err := json.Unmarshal(plain, &stored); err != nil {
		t.Fatalf("unmarshal credential: %v", err)
	}
	if stored["access_key_secret"] != brokerSecret {
		t.Fatalf("decrypted secret = %q", stored["access_key_secret"])
	}
}
