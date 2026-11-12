package server

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
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
	for _, viaInit := range []bool{false, true} {
		name := "upgrade by serve"
		if viaInit {
			name = "upgrade by init --force"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: true}); err != nil {
				t.Fatalf("Init: %v", err)
			}
			downgradeToV1(t, dir)
			if viaInit {
				if _, err := Init(context.Background(), InitOptions{DataDir: dir, Force: true}); err != nil {
					t.Fatalf("Init --force: %v", err)
				}
			}
			srv, err := New(Config{DataDir: dir})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer srv.Close()
			if n := countMigrationEvents(t, srv); n != 1 {
				t.Fatalf("schema.migrated events = %d, want exactly 1", n)
			}
			res, err := srv.db.VerifyAudit(context.Background())
			if err != nil || !res.OK {
				t.Fatalf("audit chain after migration = %+v, %v", res, err)
			}
		})
	}
}

// Review 4, finding 2: a v1 custom capability allowing a bare "*" minted
// credentials without the mandatory deny. After the upgrade it is disabled, the
// grant is dropped, and its live lease is revoked on startup.
func TestUpgradeRevokesLeasesOnV1WildcardCapability(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	initRes, err := Init(ctx, InitOptions{DataDir: dir, Demo: true})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	var agentID string
	for _, a := range initRes.Agents {
		if a.Name == "hermes-researcher" {
			agentID = a.ID
		}
	}
	db, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	now := time.Now().UTC()
	expires := now.Add(15 * time.Minute)
	star := model.Capability{
		ID: "cap_v1_star", Name: "v1 everything", ProviderType: model.ProviderAliyun,
		Risk: model.RiskLow, Access: model.AccessAdmin,
		PolicyTemplate:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
		DefaultTTLSeconds: 900, MaxTTLSeconds: 1800, Enabled: true, CreatedAt: now, UpdatedAt: now,
	}
	if err := db.CreateCapability(ctx, star); err != nil {
		t.Fatalf("CreateCapability: %v", err)
	}
	ag, _ := db.GetAgent(ctx, agentID)
	ag.Grants = append(ag.Grants, star.ID)
	if err := db.UpdateAgent(ctx, ag); err != nil {
		t.Fatalf("UpdateAgent: %v", err)
	}
	providers, _ := db.ListProviders(ctx)
	if err := db.CreateLease(ctx, model.Lease{
		ID: "lea_v1_star", AgentID: agentID, AgentName: ag.Name, CapabilityID: star.ID,
		ProviderID: providers[0].ID, ProviderMode: model.ModeMock, Risk: model.RiskLow,
		Status: model.LeaseActive, EffectiveTTLSeconds: 900, CreatedAt: now, IssuedAt: &now, ExpiresAt: &expires,
	}); err != nil {
		t.Fatalf("CreateLease: %v", err)
	}
	db.Close()
	downgradeToV1(t, dir)

	srv, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()
	c, _ := srv.db.GetCapability(ctx, star.ID)
	if c.Enabled {
		t.Fatal("v1 wildcard capability still enabled after the upgrade")
	}
	got, _ := srv.db.GetLease(ctx, "lea_v1_star")
	if got.Status != model.LeaseRevoked {
		t.Fatalf("v1 wildcard lease after upgrade = %q, want revoked", got.Status)
	}
	after, _ := srv.db.GetAgent(ctx, agentID)
	for _, g := range after.Grants {
		if g == star.ID {
			t.Fatal("grant to the v1 wildcard capability survived the upgrade")
		}
	}
	if after.Role != model.RoleGuest {
		t.Fatalf("agent role after upgrade = %q, want guest (the wildcard grant must not raise it)", after.Role)
	}
}
