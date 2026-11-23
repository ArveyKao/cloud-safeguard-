package server

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/token"
)

// downgradeToV1 turns a freshly initialized data dir back into a schema-1
// database: it drops the columns schema 2 added and resets the version.
func downgradeToV1(t *testing.T, dir string) {
	t.Helper()
	raw, err := sql.Open("sqlite", filepath.Join(dir, store.DBFileName))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer raw.Close()
	for _, stmt := range []string{
		`ALTER TABLE agents DROP COLUMN role`,
		`ALTER TABLE capabilities DROP COLUMN access`,
		`DROP INDEX IF EXISTS idx_agents_owner`,
		`ALTER TABLE agents DROP COLUMN owner_id`,
		`ALTER TABLE persons DROP COLUMN setup_issued_by`,
		`ALTER TABLE persons DROP COLUMN setup_issued_by_name`,
		`ALTER TABLE persons DROP COLUMN setup_issued_kind`,
		`ALTER TABLE persons DROP COLUMN setup_issued_at`,
		`ALTER TABLE persons DROP COLUMN approval_mode`,
		`ALTER TABLE persons DROP COLUMN approval_mode_expires_at`,
		`ALTER TABLE providers DROP COLUMN max_auto_level`,
		`DROP INDEX IF EXISTS idx_providers_cloud_account`,
		`ALTER TABLE providers DROP COLUMN cloud_account_id`,
		`UPDATE meta SET value = '1' WHERE key = 'schema_version'`,
	} {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

func countMigrationEvents(t *testing.T, srv *Server) int {
	t.Helper()
	events, _, err := srv.db.ListAudit(context.Background(), store.AuditFilter{Action: "schema.migrated", Limit: 10})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	return len(events)
}

func TestSchemaMigrationIsAuditedOnce(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: true}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	downgradeToV1(t, dir)
	// Init never upgrades an existing install; serving does.
	if _, err := Init(context.Background(), InitOptions{DataDir: dir}); err == nil {
		t.Fatal("Init ran on an existing data directory")
	}
	for start := 1; start <= 2; start++ {
		srv, err := New(Config{DataDir: dir})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if n := countMigrationEvents(t, srv); n != 1 {
			t.Fatalf("start %d: schema.migrated events = %d, want exactly 1", start, n)
		}
		res, err := srv.db.VerifyAudit(context.Background())
		if err != nil || !res.OK {
			t.Fatalf("audit chain after migration = %+v, %v", res, err)
		}
		if err := srv.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

// The upgrade to schema 8 (CONTRACT §17.7a): the admin token is deleted,
// agents without an owner are revoked, and leases of the removed capability
// model are revoked at startup. All of it is recorded in the audit log, and
// agents that belong to a person are left alone.
func TestUpgradeRemovesTheAdminTokenAndTheOldAgentModel(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if _, err := Init(ctx, InitOptions{DataDir: dir, Demo: true}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	db, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	now := time.Now().UTC()
	expires := now.Add(15 * time.Minute)
	tokens := map[string]string{}
	addAgent := func(id, owner string, status model.AgentStatus) {
		plain, hash, err := token.Generate(token.AgentPrefix)
		if err != nil {
			t.Fatal(err)
		}
		tokens[id] = plain
		ag := model.Agent{ID: id, Name: id, Status: status, Role: model.RoleAdministrator, Grants: []string{"aliyun.cloud.read"},
			OwnerID: owner, MaxTTLSeconds: 3600, MaxConcurrentLeases: 3, TokenPrefix: token.DisplayPrefix(plain), CreatedAt: now, UpdatedAt: now}
		if err := db.CreateAgent(ctx, ag, hash); err != nil {
			t.Fatalf("CreateAgent(%s): %v", id, err)
		}
	}
	people, _ := db.ListPersons(ctx)
	addAgent("agt_old_active", "", model.AgentActive)
	addAgent("agt_old_suspended", "", model.AgentSuspended)
	addAgent("agt_owned", people[0].ID, model.AgentActive)
	providers, _ := db.ListProviders(ctx)
	for _, lease := range []model.Lease{
		{ID: "lea_old_active", Status: model.LeaseActive, IssuedAt: &now, ExpiresAt: &expires, CredentialAvailable: true},
		{ID: "lea_old_pending", Status: model.LeasePending},
		{ID: "lea_old_expired", Status: model.LeaseExpired},
	} {
		lease.AgentID, lease.AgentName, lease.CapabilityID = "agt_old_active", "agt_old_active", "aliyun.cloud.read"
		lease.ProviderID, lease.ProviderMode, lease.EffectiveTTLSeconds, lease.CreatedAt = providers[0].ID, model.ModeMock, 900, now
		if err := db.CreateLease(ctx, lease); err != nil {
			t.Fatalf("CreateLease(%s): %v", lease.ID, err)
		}
	}
	for key, value := range map[string]string{"admin_token_hash": "0123abcd", "admin_token_prefix": "csg_adm_0123", "schema_version": "7"} {
		if err := db.SetMeta(ctx, key, value); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	for start := 1; start <= 2; start++ {
		srv, err := New(Config{DataDir: dir})
		if err != nil {
			t.Fatalf("start %d: New: %v", start, err)
		}
		for _, key := range []string{"admin_token_hash", "admin_token_prefix"} {
			if _, err := srv.db.GetMeta(ctx, key); err == nil {
				t.Fatalf("meta %s survived the upgrade", key)
			}
		}
		for id, want := range map[string]model.AgentStatus{
			"agt_old_active": model.AgentRevoked, "agt_old_suspended": model.AgentRevoked, "agt_owned": model.AgentActive,
		} {
			if ag, err := srv.db.GetAgent(ctx, id); err != nil || ag.Status != want {
				t.Fatalf("agent %s = %q, %v; want %q", id, ag.Status, err, want)
			}
		}
		// The old agents' tokens are dead.
		for id, want := range map[string]int{"agt_old_active": 403, "agt_old_suspended": 403} {
			if rec := rawRequest(t, srv.Handler(), "GET", "/api/v1/agent/me", tokens[id], nil); rec.Code != want {
				t.Fatalf("GET /agent/me as %s = %d, want %d", id, rec.Code, want)
			}
		}
		for id, want := range map[string]model.LeaseStatus{
			"lea_old_active": model.LeaseRevoked, "lea_old_pending": model.LeaseRevoked, "lea_old_expired": model.LeaseExpired,
		} {
			got, err := srv.db.GetLease(ctx, id)
			if err != nil || got.Status != want || got.CredentialAvailable {
				t.Fatalf("lease %s = %q (credential %v), %v; want %q", id, got.Status, got.CredentialAvailable, err, want)
			}
		}
		// Recorded once, whatever the number of restarts.
		migrated, _, err := srv.db.ListAudit(ctx, store.AuditFilter{Action: "schema.migrated", Limit: 10})
		if err != nil || len(migrated) != 1 {
			t.Fatalf("start %d: schema.migrated events = %d, %v", start, len(migrated), err)
		}
		if migrated[0].Metadata["deleted_admin_token"] != true {
			t.Fatalf("schema.migrated does not say the admin token was deleted: %+v", migrated[0].Metadata)
		}
		// No agent keeps a role or grants of its own.
		for _, id := range []string{"agt_old_active", "agt_owned"} {
			if ag, _ := srv.db.GetAgent(ctx, id); ag.Role != model.RoleGuest || len(ag.Grants) != 0 {
				t.Fatalf("agent %s keeps role %q and grants %v", id, ag.Role, ag.Grants)
			}
		}
		// The startup revocations name the agent.
		for _, ev := range srv.listAuditFor(t, "lease.revoked") {
			if ev.Metadata["agent_id"] != "agt_old_active" {
				t.Fatalf("startup revocation does not name the agent: %+v", ev.Metadata)
			}
		}
		revokedAgents, _ := migrated[0].Metadata["revoked_agents"].([]any)
		if len(revokedAgents) != 2 || revokedAgents[0] != "agt_old_active" || revokedAgents[1] != "agt_old_suspended" {
			t.Fatalf("schema.migrated does not list the revoked agents: %+v", migrated[0].Metadata)
		}
		revoked, _, err := srv.db.ListAudit(ctx, store.AuditFilter{Action: "lease.revoked", Limit: 10})
		if err != nil || len(revoked) != 2 {
			t.Fatalf("start %d: lease.revoked events = %d, %v", start, len(revoked), err)
		}
		if res, err := srv.db.VerifyAudit(ctx); err != nil || !res.OK {
			t.Fatalf("audit chain after the upgrade = %+v, %v", res, err)
		}
		if err := srv.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
