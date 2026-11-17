package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Meta keys stored in the meta table. These are part of the bootstrap contract
// (docs/CONTRACT.md §11) and are read by the CLI/serve startup checks.
const (
	MetaSchemaVersion  = "schema_version"
	MetaInstanceID     = "instance_id"
	MetaBootstrapTime  = "bootstrap_time"
	MetaDemoMode       = "demo_mode"
	MetaPolicySettings = "policy_settings"
	// MetaVaultKeyCheck holds a known plaintext encrypted with the master
	// key, so a wrong key is detected even when nothing else is encrypted.
	MetaVaultKeyCheck = "vault_key_check"
)

// CurrentSchemaVersion is the schema version this binary writes and expects.
// It is exported because the bootstrap path records it in the meta table.
const CurrentSchemaVersion = 9

// migration is one ordered schema step. Migration index i moves the schema
// from version i to i+1.
type migration struct {
	// statements are DDL/DML statements executed one at a time.
	statements []string
	// transform is an optional data migration that needs Go logic. It runs in
	// the same transaction, after statements.
	transform func(ctx context.Context, tx *sql.Tx, report *MigrationReport) error
}

// migrations is the ordered list of schema migrations. Each runs inside a
// transaction, after which the schema_version meta key is bumped. Migrations
// are append-only: never edit a released one.
var migrations = []migration{
	{ // version 0 -> 1
		statements: []string{
			`CREATE TABLE IF NOT EXISTS meta (
				key   TEXT PRIMARY KEY,
				value TEXT NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS providers (
				id                    TEXT PRIMARY KEY,
				name                  TEXT NOT NULL,
				type                  TEXT NOT NULL,
				mode                  TEXT NOT NULL,
				region                TEXT NOT NULL,
				role_arn              TEXT NOT NULL DEFAULT '',
				access_key_id_masked  TEXT NOT NULL DEFAULT '',
				status                TEXT NOT NULL,
				last_tested_at        INTEGER,
				last_test_ok          INTEGER,
				encrypted_credential  TEXT NOT NULL DEFAULT '',
				created_at            INTEGER NOT NULL,
				updated_at            INTEGER NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS capabilities (
				id                  TEXT PRIMARY KEY,
				name                TEXT NOT NULL,
				description         TEXT NOT NULL DEFAULT '',
				provider_type       TEXT NOT NULL,
				risk                TEXT NOT NULL,
				policy_template     TEXT NOT NULL DEFAULT '',
				params_json         TEXT NOT NULL DEFAULT '[]',
				default_ttl_seconds INTEGER NOT NULL,
				max_ttl_seconds     INTEGER NOT NULL,
				enabled             INTEGER NOT NULL,
				builtin             INTEGER NOT NULL,
				created_at          INTEGER NOT NULL,
				updated_at          INTEGER NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS agents (
				id                    TEXT PRIMARY KEY,
				name                  TEXT NOT NULL,
				description           TEXT NOT NULL DEFAULT '',
				status                TEXT NOT NULL,
				grants_json           TEXT NOT NULL DEFAULT '[]',
				max_ttl_seconds       INTEGER NOT NULL,
				max_concurrent_leases INTEGER NOT NULL,
				token_hash            TEXT NOT NULL,
				token_prefix          TEXT NOT NULL DEFAULT '',
				last_seen_at          INTEGER,
				created_at            INTEGER NOT NULL,
				updated_at            INTEGER NOT NULL
			)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_token_hash ON agents(token_hash)`,
			`CREATE TABLE IF NOT EXISTS leases (
				id                     TEXT PRIMARY KEY,
				agent_id               TEXT NOT NULL,
				agent_name             TEXT NOT NULL DEFAULT '',
				capability_id          TEXT NOT NULL,
				capability_name        TEXT NOT NULL DEFAULT '',
				provider_id            TEXT NOT NULL DEFAULT '',
				provider_name          TEXT NOT NULL DEFAULT '',
				provider_mode          TEXT NOT NULL DEFAULT '',
				risk                   TEXT NOT NULL DEFAULT '',
				params_json            TEXT NOT NULL DEFAULT '{}',
				reason                 TEXT NOT NULL DEFAULT '',
				requested_ttl_seconds  INTEGER NOT NULL DEFAULT 0,
				effective_ttl_seconds  INTEGER NOT NULL DEFAULT 0,
				status                 TEXT NOT NULL,
				decision_json          TEXT NOT NULL DEFAULT '{}',
				break_glass            INTEGER NOT NULL DEFAULT 0,
				approved_by            TEXT NOT NULL DEFAULT '',
				approval_note          TEXT NOT NULL DEFAULT '',
				denied_reason          TEXT NOT NULL DEFAULT '',
				revoke_reason          TEXT NOT NULL DEFAULT '',
				failure_reason         TEXT NOT NULL DEFAULT '',
				session_name           TEXT NOT NULL DEFAULT '',
				credential_available   INTEGER NOT NULL DEFAULT 0,
				credential_fingerprint TEXT NOT NULL DEFAULT '',
				encrypted_credential   TEXT NOT NULL DEFAULT '',
				created_at             INTEGER NOT NULL,
				approved_at            INTEGER,
				issued_at              INTEGER,
				expires_at             INTEGER,
				revoked_at             INTEGER
			)`,
			`CREATE INDEX IF NOT EXISTS idx_leases_agent ON leases(agent_id, created_at)`,
			`CREATE INDEX IF NOT EXISTS idx_leases_status ON leases(status)`,
			`CREATE INDEX IF NOT EXISTS idx_leases_created ON leases(created_at)`,
			`CREATE TABLE IF NOT EXISTS audit (
				seq           INTEGER PRIMARY KEY,
				id            TEXT NOT NULL UNIQUE,
				time_ms       INTEGER NOT NULL,
				actor_type    TEXT NOT NULL,
				actor_id      TEXT NOT NULL,
				actor_name    TEXT NOT NULL,
				action        TEXT NOT NULL,
				status        TEXT NOT NULL,
				severity      TEXT NOT NULL,
				target_type   TEXT NOT NULL,
				target_id     TEXT NOT NULL,
				metadata_json TEXT NOT NULL DEFAULT '',
				prev_hash     TEXT NOT NULL,
				hash          TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_audit_time ON audit(time_ms)`,
			`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit(action)`,
			`CREATE INDEX IF NOT EXISTS idx_audit_severity ON audit(severity)`,
		},
	},
	{ // version 1 -> 2: agent roles and capability access levels (CONTRACT §16.6)
		statements: []string{
			`ALTER TABLE agents ADD COLUMN role TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE capabilities ADD COLUMN access TEXT NOT NULL DEFAULT ''`,
		},
		transform: migrateRolesAndAccess,
	},
	{ // version 2 -> 3: people, supervisors, role bindings, sessions (CONTRACT §17)
		statements: []string{
			`CREATE TABLE IF NOT EXISTS persons (
				id               TEXT PRIMARY KEY,
				username         TEXT NOT NULL UNIQUE,
				display_name     TEXT NOT NULL DEFAULT '',
				status           TEXT NOT NULL,
				supervisor       INTEGER NOT NULL DEFAULT 0,
				password_hash    TEXT NOT NULL DEFAULT '',
				totp_secret_enc  TEXT NOT NULL DEFAULT '',
				totp_last_step   INTEGER NOT NULL DEFAULT -1,
				setup_code_hash  TEXT NOT NULL DEFAULT '',
				setup_expires_at INTEGER,
				failed_logins    INTEGER NOT NULL DEFAULT 0,
				locked_until     INTEGER,
				last_login_at    INTEGER,
				created_at       INTEGER NOT NULL,
				updated_at       INTEGER NOT NULL
			)`,
			`CREATE UNIQUE INDEX IF NOT EXISTS idx_persons_setup ON persons(setup_code_hash) WHERE setup_code_hash <> ''`,
			`CREATE TABLE IF NOT EXISTS role_bindings (
				person_id   TEXT NOT NULL,
				provider_id TEXT NOT NULL,
				role        TEXT NOT NULL,
				created_by  TEXT NOT NULL DEFAULT '',
				created_at  INTEGER NOT NULL,
				updated_at  INTEGER NOT NULL,
				PRIMARY KEY (person_id, provider_id)
			)`,
			`CREATE INDEX IF NOT EXISTS idx_bindings_provider ON role_bindings(provider_id)`,
			`CREATE TABLE IF NOT EXISTS sessions (
				token_hash   TEXT PRIMARY KEY,
				person_id    TEXT NOT NULL,
				csrf_token   TEXT NOT NULL,
				created_at   INTEGER NOT NULL,
				last_seen_at INTEGER NOT NULL,
				expires_at   INTEGER NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS idx_sessions_person ON sessions(person_id)`,
		},
	},
	{ // version 3 -> 4: agent ownership and agent-first sign-in (CONTRACT §17.3)
		statements: []string{
			`ALTER TABLE agents ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''`,
			`CREATE INDEX IF NOT EXISTS idx_agents_owner ON agents(owner_id)`,
			`CREATE TABLE IF NOT EXISTS agent_signins (
				id               TEXT PRIMARY KEY,
				device_code_hash TEXT NOT NULL UNIQUE,
				user_code        TEXT NOT NULL UNIQUE,
				agent_name       TEXT NOT NULL,
				description      TEXT NOT NULL DEFAULT '',
				status           TEXT NOT NULL,
				person_id        TEXT NOT NULL DEFAULT '',
				agent_id         TEXT NOT NULL DEFAULT '',
				remote_addr      TEXT NOT NULL DEFAULT '',
				created_at       INTEGER NOT NULL,
				expires_at       INTEGER NOT NULL,
				decided_at       INTEGER
			)`,
			`CREATE INDEX IF NOT EXISTS idx_signins_status ON agent_signins(status, expires_at)`,
		},
	},
	{ // version 4 -> 5: cloud account IDs on providers (CONTRACT §17.2)
		statements: []string{
			`ALTER TABLE providers ADD COLUMN cloud_account_id TEXT NOT NULL DEFAULT ''`,
			`CREATE UNIQUE INDEX IF NOT EXISTS idx_providers_cloud_account
				ON providers(cloud_account_id) WHERE cloud_account_id <> ''`,
		},
		transform: migrateCloudAccountIDs,
	},
	{ // version 5 -> 6: approval modes (CONTRACT §17.5)
		statements: []string{
			`ALTER TABLE persons ADD COLUMN approval_mode TEXT NOT NULL DEFAULT 'read'`,
			`ALTER TABLE persons ADD COLUMN approval_mode_expires_at INTEGER`,
			`ALTER TABLE providers ADD COLUMN max_auto_level TEXT NOT NULL DEFAULT 'read'`,
		},
	},
	{ // version 6 -> 7: who issued each setup code (CONTRACT §17.3)
		statements: []string{
			`ALTER TABLE persons ADD COLUMN setup_issued_by TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE persons ADD COLUMN setup_issued_by_name TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE persons ADD COLUMN setup_issued_kind TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE persons ADD COLUMN setup_issued_at INTEGER`,
		},
	},
	{ // version 7 -> 8: no admin token, no agents without an owner (CONTRACT §17.7a)
		transform: removeAdminTokenAndOldAgentModel,
	},
	{ // version 8 -> 9: people on the command line (CONTRACT §17.9)
		// The session columns are added by the transform, only when missing.
		transform: addSessionKindColumns,
		statements: []string{
			`CREATE TABLE IF NOT EXISTS cli_signins (
				id               TEXT PRIMARY KEY,
				device_code_hash TEXT NOT NULL UNIQUE,
				user_code        TEXT NOT NULL UNIQUE,
				client_name      TEXT NOT NULL,
				status           TEXT NOT NULL,
				person_id        TEXT NOT NULL DEFAULT '',
				session_id       TEXT NOT NULL DEFAULT '',
				remote_addr      TEXT NOT NULL DEFAULT '',
				created_at       INTEGER NOT NULL,
				expires_at       INTEGER NOT NULL,
				decided_at       INTEGER
			)`,
			`CREATE INDEX IF NOT EXISTS idx_cli_signins_status ON cli_signins(status, expires_at)`,
		},
	},
}

// addSessionKindColumns adds the session columns of schema 9 that are not
// there yet, and their index.
func addSessionKindColumns(ctx context.Context, tx *sql.Tx, _ *MigrationReport) error {
	rows, err := tx.QueryContext(ctx, `SELECT name FROM pragma_table_info('sessions')`)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, col := range []struct{ name, ddl string }{
		{"kind", `ALTER TABLE sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'console'`},
		{"id", `ALTER TABLE sessions ADD COLUMN id TEXT NOT NULL DEFAULT ''`},
		{"client_name", `ALTER TABLE sessions ADD COLUMN client_name TEXT NOT NULL DEFAULT ''`},
		{"remote_addr", `ALTER TABLE sessions ADD COLUMN remote_addr TEXT NOT NULL DEFAULT ''`},
	} {
		if have[col.name] {
			continue
		}
		if _, err := tx.ExecContext(ctx, col.ddl); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS idx_sessions_person_kind ON sessions(person_id, kind)`)
	return err
}

// removeAdminTokenAndOldAgentModel deletes the admin token, revokes every
// agent that belongs to no person and clears the role and grants stored on
// every agent. Agents without an owner were created by the removed admin
// token or the v0.1 demo seed, and nothing can manage them any more. An
// agent's own role and grants mean nothing now (it inherits its owner's role),
// so they must not be shown as if they did. Leases of the removed model are
// revoked by the startup sweep, which records each one in the audit log.
func removeAdminTokenAndOldAgentModel(ctx context.Context, tx *sql.Tx, report *MigrationReport) error {
	res, err := tx.ExecContext(ctx, `DELETE FROM meta WHERE key IN ('admin_token_hash', 'admin_token_prefix')`)
	if err != nil {
		return err
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agents SET role = 'guest', grants_json = '[]'`); err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM agents WHERE owner_id = '' AND status <> ? ORDER BY id ASC`, string(model.AgentRevoked))
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	now := time.Now().UTC().UnixMilli()
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, `UPDATE agents SET status = ?, updated_at = ? WHERE id = ?`,
			string(model.AgentRevoked), now, id); err != nil {
			return err
		}
	}
	if report != nil {
		report.DeletedAdminToken = deleted > 0
		report.RevokedAgents = append(report.RevokedAgents, ids...)
	}
	return nil
}

// migrateCloudAccountIDs fills providers.cloud_account_id from each role
// ARN. When several providers point at the same cloud account, only the
// oldest gets the ID; the others keep "" and cannot serve access requests.
// A supervisor disables such a duplicate, or points it at a role in an
// account that is not connected yet, which gives it that account's ID.
func migrateCloudAccountIDs(ctx context.Context, tx *sql.Tx, _ *MigrationReport) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, type, role_arn FROM providers ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return err
	}
	type row struct{ id, typ, arn string }
	var all []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.typ, &r.arn); err != nil {
			rows.Close()
			return err
		}
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	taken := map[string]bool{}
	for _, r := range all {
		account := model.CloudAccountIDFromRoleARN(model.ProviderType(r.typ), r.arn)
		if account == "" || taken[account] {
			continue
		}
		taken[account] = true
		if _, err := tx.ExecContext(ctx, `UPDATE providers SET cloud_account_id = ? WHERE id = ?`, account, r.id); err != nil {
			return err
		}
	}
	return nil
}

// applyMigrations brings the database schema up to CurrentSchemaVersion. It is
// idempotent: running it on an up-to-date database is a no-op.
func (db *DB) applyMigrations(ctx context.Context) error {
	version, err := db.schemaVersion(ctx)
	if err != nil {
		return err
	}
	if version > CurrentSchemaVersion {
		return fmt.Errorf("store: database schema version %d is newer than supported version %d", version, CurrentSchemaVersion)
	}
	// A report an earlier upgrade left behind because it was never written
	// to the audit log (a fresh database has no meta table yet).
	var pending *MigrationReport
	if version > 0 {
		if pending, err = db.pendingMigrationReport(ctx); err != nil {
			return err
		}
	}
	var report *MigrationReport
	if version > 0 && version < CurrentSchemaVersion {
		// Only an upgrade of an existing database is reported; a fresh
		// database (version 0) has no rows to change.
		report = &MigrationReport{FromVersion: version, ToVersion: CurrentSchemaVersion}
	}
	for v := version; v < CurrentSchemaVersion; v++ {
		tx, err := db.sql.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin migration %d: %w", v+1, err)
		}
		// Another process may be upgrading the same database. Take the write
		// lock first, then read the version again: if the step was done
		// meanwhile, it is not done twice and not reported by this process.
		if v > 0 {
			var raw string
			if _, err := tx.ExecContext(ctx, `UPDATE meta SET value = value WHERE key = ?`, MetaSchemaVersion); err != nil {
				tx.Rollback()
				return fmt.Errorf("store: lock for migration %d: %w", v+1, err)
			}
			if err := tx.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, MetaSchemaVersion).Scan(&raw); err != nil {
				tx.Rollback()
				return fmt.Errorf("store: re-read schema version: %w", err)
			}
			if current, err := strconv.Atoi(raw); err != nil || current != v {
				tx.Rollback()
				if err != nil {
					return fmt.Errorf("store: corrupt schema version %q: %w", raw, err)
				}
				if current > CurrentSchemaVersion {
					return fmt.Errorf("store: database schema version %d is newer than supported version %d", current, CurrentSchemaVersion)
				}
				// Done by someone else: continue from where the database is.
				// What they did is in the report they kept.
				if pending, err = db.pendingMigrationReport(ctx); err != nil {
					return err
				}
				report = nil
				if current < CurrentSchemaVersion {
					report = &MigrationReport{FromVersion: current, ToVersion: CurrentSchemaVersion}
				}
				v = current - 1
				continue
			}
		}
		for _, stmt := range migrations[v].statements {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("store: migration %d: %w", v+1, err)
			}
		}
		if migrations[v].transform != nil {
			if err := migrations[v].transform(ctx, tx, report); err != nil {
				tx.Rollback()
				return fmt.Errorf("store: migration %d: %w", v+1, err)
			}
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO meta(key, value) VALUES(?, ?)
			 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			MetaSchemaVersion, strconv.Itoa(v+1),
		); err != nil {
			tx.Rollback()
			return fmt.Errorf("store: record schema version: %w", err)
		}
		// The report so far is stored in the same transaction as the step it
		// describes. It must outlive this process: the command that runs the
		// upgrade may stop, or be killed, before it can write the audit event.
		if report != nil {
			raw, err := json.Marshal(mergeMigrationReports(pending, report))
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("store: encode migration report: %w", err)
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO meta(key, value) VALUES(?, ?)
				 ON CONFLICT(key) DO UPDATE SET value = excluded.value`, metaPendingMigrationReport, string(raw)); err != nil {
				tx.Rollback()
				return fmt.Errorf("store: keep migration report: %w", err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %d: %w", v+1, err)
		}
	}
	db.migration = mergeMigrationReports(pending, report)
	return nil
}

// mergeMigrationReports is one report for an earlier upgrade that was never
// recorded (pending) followed by the one that just ran (report). Either may
// be nil.
func mergeMigrationReports(pending, report *MigrationReport) *MigrationReport {
	switch {
	case pending == nil && report == nil:
		return nil
	case pending == nil:
		merged := *report
		return &merged
	case report == nil:
		merged := *pending
		return &merged
	}
	merged := *report
	merged.FromVersion = pending.FromVersion
	merged.DisabledCapabilities = append(append([]string(nil), pending.DisabledCapabilities...), report.DisabledCapabilities...)
	merged.Agents = append(append([]AgentMigration(nil), pending.Agents...), report.Agents...)
	merged.RevokedAgents = append(append([]string(nil), pending.RevokedAgents...), report.RevokedAgents...)
	merged.DeletedAdminToken = pending.DeletedAdminToken || report.DeletedAdminToken
	return &merged
}

// metaPendingMigrationReport holds the report of an upgrade that has not
// been written to the audit log yet.
const metaPendingMigrationReport = "pending_migration_report"

// pendingMigrationReport reads a kept report; nil when there is none or the
// database is fresh.
func (db *DB) pendingMigrationReport(ctx context.Context) (*MigrationReport, error) {
	var raw string
	err := db.sql.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, metaPendingMigrationReport).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read migration report: %w", err)
	}
	var report MigrationReport
	if err := json.Unmarshal([]byte(raw), &report); err != nil {
		return nil, fmt.Errorf("store: corrupt migration report: %w", err)
	}
	return &report, nil
}

// schemaVersion reads the current schema version; 0 when the database is fresh.
func (db *DB) schemaVersion(ctx context.Context) (int, error) {
	var raw string
	err := db.sql.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, MetaSchemaVersion).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		// A fresh database has no meta table at all; treat any failure as
		// "version 0" and let the migration surface real errors.
		return 0, nil
	}
	if err != nil {
		// Table missing on a completely fresh file: SQLite reports "no such table".
		if strings.Contains(err.Error(), "no such table") {
			return 0, nil
		}
		return 0, fmt.Errorf("store: read schema version: %w", err)
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("store: corrupt schema version %q: %w", raw, err)
	}
	return v, nil
}

// ---- encoding helpers ----

// toMillis converts a time to UTC unix milliseconds (the storage format).
func toMillis(t time.Time) int64 { return t.UTC().UnixMilli() }

// fromMillis converts stored unix milliseconds to a UTC time.
func fromMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

// millisPtr converts an optional time to an optional unix-millisecond value.
func millisPtr(t *time.Time) *int64 {
	if t == nil {
		return nil
	}
	v := toMillis(*t)
	return &v
}

// timePtr converts an optional unix-millisecond value to an optional time.
func timePtr(ms *int64) *time.Time {
	if ms == nil {
		return nil
	}
	t := fromMillis(*ms)
	return &t
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func intBool(i int) bool { return i != 0 }

// boolPtrInt converts an optional bool to an optional 0/1 value.
func boolPtrInt(b *bool) *int64 {
	if b == nil {
		return nil
	}
	v := int64(0)
	if *b {
		v = 1
	}
	return &v
}

// intPtrBool converts an optional 0/1 value to an optional bool.
func intPtrBool(i *int64) *bool {
	if i == nil {
		return nil
	}
	v := *i != 0
	return &v
}

// marshalJSON encodes v, returning "[]" for nil slices and "{}" for nil maps so
// stored columns are always valid JSON.
func marshalJSON(v any, fallback string) (string, error) {
	if v == nil {
		return fallback, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	if string(b) == "null" {
		return fallback, nil
	}
	return string(b), nil
}

// mapErr maps common SQLite constraint errors onto the package error contract.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case strings.Contains(msg, "UNIQUE constraint failed"),
		strings.Contains(msg, "PRIMARY KEY constraint failed"):
		return ErrConflict
	default:
		return err
	}
}

// withTx runs fn inside a transaction, committing on success.
func (db *DB) withTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ---- meta ----

// GetMeta returns a meta value, or ErrNotFound when the key is unset.
func (db *DB) GetMeta(ctx context.Context, key string) (string, error) {
	var value string
	err := db.sql.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&value)
	if err != nil {
		return "", mapErr(err)
	}
	return value, nil
}

// SetMeta upserts a meta value.
func (db *DB) SetMeta(ctx context.Context, key, value string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES(?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		key, value)
	if err != nil {
		return mapErr(err)
	}
	return nil
}

// ---- policy settings ----

// GetPolicySettings returns the persisted guardrails, falling back to the
// shipped defaults when they were never stored.
func (db *DB) GetPolicySettings(ctx context.Context) (model.PolicySettings, error) {
	raw, err := db.GetMeta(ctx, MetaPolicySettings)
	if errors.Is(err, ErrNotFound) {
		return model.DefaultPolicySettings(), nil
	}
	if err != nil {
		return model.PolicySettings{}, err
	}
	var s model.PolicySettings
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return model.PolicySettings{}, fmt.Errorf("store: corrupt policy settings: %w", err)
	}
	return s, nil
}

// SetPolicySettings validates and persists the guardrails.
func (db *DB) SetPolicySettings(ctx context.Context, s model.PolicySettings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.SetMeta(ctx, MetaPolicySettings, string(raw))
}
