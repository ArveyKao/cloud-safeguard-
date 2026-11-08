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
	MetaSchemaVersion    = "schema_version"
	MetaInstanceID       = "instance_id"
	MetaAdminTokenHash   = "admin_token_hash"
	MetaAdminTokenPrefix = "admin_token_prefix"
	MetaBootstrapTime    = "bootstrap_time"
	MetaDemoMode         = "demo_mode"
	MetaPolicySettings   = "policy_settings"
)

// currentSchemaVersion is the schema version this binary writes and expects.
const currentSchemaVersion = 1

// migrations is the ordered list of schema migrations. Migration index i moves
// the schema from version i to i+1. Statements are executed one at a time
// inside a transaction, then the schema_version meta key is bumped.
var migrations = [][][]string{
	{ // version 0 -> 1
		{
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
}

// applyMigrations brings the database schema up to currentSchemaVersion. It is
// idempotent: running it on an up-to-date database is a no-op.
func (db *DB) applyMigrations(ctx context.Context) error {
	version, err := db.schemaVersion(ctx)
	if err != nil {
		return err
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("store: database schema version %d is newer than supported version %d", version, currentSchemaVersion)
	}
	for v := version; v < currentSchemaVersion; v++ {
		tx, err := db.sql.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("store: begin migration %d: %w", v+1, err)
		}
		for _, stmt := range migrations[v][0] {
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
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
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %d: %w", v+1, err)
		}
	}
	return nil
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
