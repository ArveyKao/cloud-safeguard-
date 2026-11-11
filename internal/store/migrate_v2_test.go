package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/capcatalog"
	"github.com/arveykao/cloud-safeguard/internal/model"
)

// v1Capability is a capability row as the v1 schema stored it (no access
// column).
type v1Capability struct {
	id             string
	name           string
	risk           model.RiskTier
	policyTemplate string
	params         []model.CapabilityParam
	enabled        bool
	builtin        bool
}

// v1Agent is an agent row as the v1 schema stored it (no role column).
type v1Agent struct {
	id     string
	name   string
	grants []string
}

// writeV1Database creates a database at the real v1 schema (migration 1's own
// statements, so the fixture cannot drift from the released schema) and fills
// it with v1 rows. It returns with the database closed, ready for Open to
// migrate it.
func writeV1Database(t *testing.T, dir string, caps []v1Capability, agents []v1Agent) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(dir, DBFileName)
	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("open v1 database: %v", err)
	}
	defer func() {
		if err := raw.Close(); err != nil {
			t.Fatalf("close v1 database: %v", err)
		}
	}()

	for _, stmt := range migrations[0].statements {
		if _, err := raw.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("v1 schema statement failed: %v\n%s", err, stmt)
		}
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES(?, ?)`, MetaSchemaVersion, "1"); err != nil {
		t.Fatalf("record v1 schema version: %v", err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES(?, ?)`, MetaInstanceID, "csg_v1fixture"); err != nil {
		t.Fatalf("record instance id: %v", err)
	}

	for _, c := range caps {
		paramsJSON, err := marshalJSON(c.params, "[]")
		if err != nil {
			t.Fatalf("marshal params for %s: %v", c.id, err)
		}
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO capabilities(id, name, description, provider_type, risk, policy_template,
				params_json, default_ttl_seconds, max_ttl_seconds, enabled, builtin, created_at, updated_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.id, c.name, "v1 row", string(model.ProviderAliyun), string(c.risk), c.policyTemplate,
			paramsJSON, 900, 1800, boolInt(c.enabled), boolInt(c.builtin),
			toMillis(testTime), toMillis(testTime),
		); err != nil {
			t.Fatalf("insert v1 capability %s: %v", c.id, err)
		}
	}
	for _, a := range agents {
		grantsJSON, err := marshalJSON(a.grants, "[]")
		if err != nil {
			t.Fatalf("marshal grants for %s: %v", a.id, err)
		}
		if _, err := raw.ExecContext(ctx,
			`INSERT INTO agents(id, name, description, status, grants_json, max_ttl_seconds,
				max_concurrent_leases, token_hash, token_prefix, last_seen_at, created_at, updated_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.id, a.name, "v1 row", string(model.AgentActive), grantsJSON, 1800, 3,
			strings.Repeat("f", 64)+a.id, "csg_agt_"+a.id, nil,
			toMillis(testTime), toMillis(testTime),
		); err != nil {
			t.Fatalf("insert v1 agent %s: %v", a.id, err)
		}
	}
}

// v1Fixture is the set of v1 rows used by the migration tests: the five v1
// builtins plus three custom capabilities that exercise step 2.
func v1Fixture() ([]v1Capability, []v1Agent) {
	caps := []v1Capability{
		{
			id: capcatalog.IDCloudRead, name: "Cloud read-only inventory", risk: model.RiskLow,
			policyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:Describe*","alidns:Describe*","oss:List*","sts:GetCallerIdentity"],"Resource":["*"]}]}`,
			enabled:        true, builtin: true,
		},
		{
			id: capcatalog.IDDNSManage, name: "Manage DNS records for one domain", risk: model.RiskMedium,
			policyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":["alidns:AddDomainRecord"],"Resource":["acs:alidns:*:*:domain/{{domain}}"]}]}`,
			params:         []model.CapabilityParam{{Name: "domain", Required: true, Pattern: capcatalog.DomainPattern}},
			enabled:        true, builtin: true,
		},
		{
			id: capcatalog.IDCertDNS01, name: "ACME DNS-01 challenge token for one domain", risk: model.RiskMedium,
			policyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":["alidns:AddDomainRecord"],"Resource":["acs:alidns:*:*:domain/{{domain}}"]}]}`,
			params:         []model.CapabilityParam{{Name: "domain", Required: true, Pattern: capcatalog.DomainPattern}},
			enabled:        true, builtin: true,
		},
		{
			id: capcatalog.IDECSOps, name: "Start/stop/restart one ECS instance", risk: model.RiskHigh,
			policyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:StopInstance"],"Resource":["acs:ecs:*:*:instance/{{instance_id}}"]}]}`,
			params:         []model.CapabilityParam{{Name: "instance_id", Required: true, Pattern: capcatalog.InstanceIDPattern}},
			enabled:        true, builtin: true,
		},
		{
			id: capcatalog.IDBreakGlass, name: "Emergency account-wide access (break-glass)", risk: model.RiskCritical,
			policyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			enabled:        true, builtin: true,
		},
		{
			// Renders a permitted policy at admin: stays enabled.
			id: "cap_custom_ok", name: "Custom bucket read", risk: model.RiskLow,
			policyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:List*"],"Resource":["acs:oss:*:*:{{bucket}}"]}]}`,
			params:         []model.CapabilityParam{{Name: "bucket", Required: true, Pattern: `^[a-z0-9-]+$`}},
			enabled:        true, builtin: false,
		},
		{
			// Allows RAM: step 2 must disable it.
			id: "cap_custom_ram", name: "Custom RAM reader", risk: model.RiskHigh,
			policyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ram:ListUsers"],"Resource":["*"]}]}`,
			enabled:        true, builtin: false,
		},
		{
			// Cannot be rendered at all: step 2 must disable it too.
			id: "cap_custom_broken", name: "Custom broken template", risk: model.RiskHigh,
			policyTemplate: `{"Version":"1","Statement":[`,
			enabled:        true, builtin: false,
		},
	}
	agents := []v1Agent{
		{id: "agt_admin", name: "claude-code", grants: []string{
			capcatalog.IDCloudRead, capcatalog.IDDNSManage, capcatalog.IDBreakGlass,
		}},
		{id: "agt_writer", name: "deployer", grants: []string{
			capcatalog.IDCloudRead, capcatalog.IDDNSManage, capcatalog.IDECSOps,
		}},
		{id: "agt_reader", name: "hermes-researcher", grants: []string{capcatalog.IDCloudRead}},
		{id: "agt_empty", name: "idle-bot", grants: nil},
		{id: "agt_bgonly", name: "firefighter", grants: []string{capcatalog.IDBreakGlass}},
		{id: "agt_custom", name: "ram-bot", grants: []string{"cap_custom_ram"}},
		{id: "agt_ghost", name: "stale-bot", grants: []string{"cap_deleted_long_ago"}},
	}
	return caps, agents
}

// TestMigrateV1DatabaseToSchema2 migrates a database created at the real v1
// schema and checks every step of CONTRACT §16.6.
func TestMigrateV1DatabaseToSchema2(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	caps, agents := v1Fixture()
	writeV1Database(t, dir, caps, agents)

	db, err := Open(ctx, dir)
	if err != nil {
		t.Fatalf("Open (migrate v1 -> v2): %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if version, err := db.GetMeta(ctx, MetaSchemaVersion); err != nil || version != strconv.Itoa(CurrentSchemaVersion) {
		t.Fatalf("schema_version after migration = %q, %v; want %d", version, err, CurrentSchemaVersion)
	}

	// ---- steps 1-3: capability access levels and disabling ----
	wantCaps := map[string]struct {
		access  model.AccessLevel
		enabled bool
	}{
		capcatalog.IDCloudRead:    {model.AccessRead, true},
		capcatalog.IDDNSManage:    {model.AccessWrite, true},
		capcatalog.IDCertDNS01:    {model.AccessWrite, true},
		capcatalog.IDECSOps:       {model.AccessWrite, true},
		capcatalog.IDAccountAdmin: {model.AccessAdmin, true},
		// Step 3: retired, kept, disabled.
		capcatalog.IDBreakGlass: {model.AccessAdmin, false},
		// Step 1: custom capabilities are classified admin.
		"cap_custom_ok": {model.AccessAdmin, true},
		// Step 2: these two cannot render a permitted policy.
		"cap_custom_ram":    {model.AccessAdmin, false},
		"cap_custom_broken": {model.AccessAdmin, false},
	}
	stored, err := db.ListCapabilities(ctx)
	if err != nil {
		t.Fatalf("ListCapabilities: %v", err)
	}
	if len(stored) != len(wantCaps) {
		ids := make([]string, 0, len(stored))
		for _, c := range stored {
			ids = append(ids, c.ID)
		}
		t.Fatalf("capabilities after migration = %v, want %d rows", ids, len(wantCaps))
	}
	for _, c := range stored {
		want, ok := wantCaps[c.ID]
		if !ok {
			t.Errorf("unexpected capability %s after migration", c.ID)
			continue
		}
		if c.Access != want.access {
			t.Errorf("%s: access = %q, want %q", c.ID, c.Access, want.access)
		}
		if c.Enabled != want.enabled {
			t.Errorf("%s: enabled = %v, want %v", c.ID, c.Enabled, want.enabled)
		}
	}

	// The replacement capability was seeded from the catalog, not invented.
	replacement, err := db.GetCapability(ctx, capcatalog.IDAccountAdmin)
	if err != nil {
		t.Fatalf("GetCapability(%s): %v", capcatalog.IDAccountAdmin, err)
	}
	spec, _ := capcatalog.Lookup(capcatalog.IDAccountAdmin)
	if !replacement.Builtin || replacement.PolicyTemplate != spec.PolicyTemplate ||
		replacement.Name != spec.Name || replacement.Risk != spec.Risk ||
		replacement.DefaultTTLSeconds != spec.DefaultTTLSeconds || replacement.MaxTTLSeconds != spec.MaxTTLSeconds {
		t.Fatalf("seeded %s = %+v, want the catalog spec", capcatalog.IDAccountAdmin, replacement)
	}

	// ---- step 4: grants and roles ----
	wantAgents := map[string]struct {
		role   model.AgentRole
		grants []string
	}{
		"agt_admin": {model.RoleAdministrator, []string{
			capcatalog.IDCloudRead, capcatalog.IDDNSManage, capcatalog.IDAccountAdmin,
		}},
		"agt_writer": {model.RoleMember, []string{
			capcatalog.IDCloudRead, capcatalog.IDDNSManage, capcatalog.IDECSOps,
		}},
		"agt_reader": {model.RoleGuest, []string{capcatalog.IDCloudRead}},
		"agt_empty":  {model.RoleGuest, nil},
		"agt_bgonly": {model.RoleAdministrator, []string{capcatalog.IDAccountAdmin}},
		// A grant to a custom capability the migration disabled for violating
		// the IAM prohibition is dropped, so it no longer raises the role.
		"agt_custom": {model.RoleGuest, nil},
		// An unknown capability cannot be leased, so it must not drive the role up.
		"agt_ghost": {model.RoleGuest, []string{"cap_deleted_long_ago"}},
	}
	storedAgents, err := db.ListAgents(ctx)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(storedAgents) != len(wantAgents) {
		t.Fatalf("agents after migration = %d, want %d", len(storedAgents), len(wantAgents))
	}
	for _, ag := range storedAgents {
		want, ok := wantAgents[ag.ID]
		if !ok {
			t.Errorf("unexpected agent %s after migration", ag.ID)
			continue
		}
		if ag.Role != want.role {
			t.Errorf("%s: role = %q, want %q", ag.ID, ag.Role, want.role)
		}
		if strings.Join(ag.Grants, ",") != strings.Join(want.grants, ",") {
			t.Errorf("%s: grants = %v, want %v", ag.ID, ag.Grants, want.grants)
		}
	}

	// ---- the migration report the server writes to the audit log ----
	report := db.MigrationReport()
	if report == nil {
		t.Fatal("MigrationReport() = nil after upgrading a v1 database")
	}
	if report.FromVersion != 1 || report.ToVersion != CurrentSchemaVersion {
		t.Errorf("report versions = %d→%d, want 1→%d", report.FromVersion, report.ToVersion, CurrentSchemaVersion)
	}
	if !strings.Contains(strings.Join(report.DisabledCapabilities, ","), "cap_custom_ram") {
		t.Errorf("report disabled capabilities = %v, want cap_custom_ram listed", report.DisabledCapabilities)
	}
	var customEntry *AgentMigration
	for i := range report.Agents {
		if report.Agents[i].AgentID == "agt_custom" {
			customEntry = &report.Agents[i]
		}
	}
	if customEntry == nil || strings.Join(customEntry.DroppedGrants, ",") != "cap_custom_ram" {
		t.Errorf("report entry for agt_custom = %+v, want dropped grant cap_custom_ram", customEntry)
	}

	// ---- "grants never widen" ----
	// Every migrated grant must trace back to a grant the agent already held,
	// with the retired capability mapped onto its replacement.
	before := make(map[string][]string, len(agents))
	for _, a := range agents {
		before[a.id] = a.grants
	}
	for _, ag := range storedAgents {
		allowed := make(map[string]bool, len(before[ag.ID]))
		for _, grant := range before[ag.ID] {
			if grant == capcatalog.IDBreakGlass {
				grant = capcatalog.IDAccountAdmin
			}
			allowed[grant] = true
		}
		for _, grant := range ag.Grants {
			if !allowed[grant] {
				t.Errorf("%s: migration widened grants with %s (had %v)", ag.ID, grant, before[ag.ID])
			}
		}
		if len(ag.Grants) > len(before[ag.ID]) {
			t.Errorf("%s: migration grew the grant set from %d to %d", ag.ID, len(before[ag.ID]), len(ag.Grants))
		}
		// And no agent ends up with a role above the lowest one its grants need.
		levels := make([]model.AccessLevel, 0, len(ag.Grants))
		for _, grant := range ag.Grants {
			c, err := db.GetCapability(ctx, grant)
			if err != nil {
				continue // unknown capability: cannot be leased, cannot raise the role
			}
			levels = append(levels, c.Access)
		}
		lowest, ok := model.LowestRolePermitting(levels)
		if !ok {
			t.Fatalf("%s: stored access levels %v are not all valid", ag.ID, levels)
		}
		if ag.Role != lowest {
			t.Errorf("%s: role = %q, want the lowest permitting role %q", ag.ID, ag.Role, lowest)
		}
	}
}

// TestMigrateV1IsIdempotent proves re-opening a migrated database changes
// nothing: the migration must not run twice.
func TestMigrateV1IsIdempotent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	caps, agents := v1Fixture()
	writeV1Database(t, dir, caps, agents)

	first, err := Open(ctx, dir)
	if err != nil {
		t.Fatalf("Open (first): %v", err)
	}
	beforeCaps := snapshotCapabilities(t, ctx, first)
	beforeAgents := snapshotAgents(t, ctx, first)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := Open(ctx, dir)
	if err != nil {
		t.Fatalf("Open (second): %v", err)
	}
	defer second.Close()
	if got := snapshotCapabilities(t, ctx, second); got != beforeCaps {
		t.Fatalf("capabilities changed on reopen:\n got %s\nwant %s", got, beforeCaps)
	}
	if got := snapshotAgents(t, ctx, second); got != beforeAgents {
		t.Fatalf("agents changed on reopen:\n got %s\nwant %s", got, beforeAgents)
	}
}

// TestMigrateWithoutRetiredCapabilityDoesNotSeedReplacement proves the
// replacement capability is only seeded for databases that actually carried the
// retired one; seeding is otherwise `csg init`'s job.
func TestMigrateWithoutRetiredCapabilityDoesNotSeedReplacement(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	writeV1Database(t,
		dir,
		[]v1Capability{{
			id: capcatalog.IDCloudRead, name: "Cloud read-only inventory", risk: model.RiskLow,
			policyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:Describe*"],"Resource":["*"]}]}`,
			enabled:        true, builtin: true,
		}},
		[]v1Agent{{id: "agt_reader", name: "reader", grants: []string{capcatalog.IDCloudRead}}},
	)

	db, err := Open(ctx, dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	stored, err := db.ListCapabilities(ctx)
	if err != nil {
		t.Fatalf("ListCapabilities: %v", err)
	}
	if len(stored) != 1 || stored[0].ID != capcatalog.IDCloudRead {
		ids := make([]string, 0, len(stored))
		for _, c := range stored {
			ids = append(ids, c.ID)
		}
		t.Fatalf("capabilities after migration = %v, want only %s", ids, capcatalog.IDCloudRead)
	}
}

// snapshotCapabilities renders the capability table as stable JSON.
func snapshotCapabilities(t *testing.T, ctx context.Context, db *DB) string {
	t.Helper()
	items, err := db.ListCapabilities(ctx)
	if err != nil {
		t.Fatalf("ListCapabilities: %v", err)
	}
	type row struct {
		ID      string            `json:"id"`
		Access  model.AccessLevel `json:"access"`
		Enabled bool              `json:"enabled"`
		Builtin bool              `json:"builtin"`
	}
	out := make([]row, 0, len(items))
	for _, c := range items {
		out = append(out, row{c.ID, c.Access, c.Enabled, c.Builtin})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal capability snapshot: %v", err)
	}
	return string(raw)
}

// snapshotAgents renders the agent table as stable JSON.
func snapshotAgents(t *testing.T, ctx context.Context, db *DB) string {
	t.Helper()
	items, err := db.ListAgents(ctx)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	type row struct {
		ID     string          `json:"id"`
		Role   model.AgentRole `json:"role"`
		Grants []string        `json:"grants"`
	}
	out := make([]row, 0, len(items))
	for _, a := range items {
		out = append(out, row{a.ID, a.Role, a.Grants})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal agent snapshot: %v", err)
	}
	return string(raw)
}
