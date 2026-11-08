// Package store is the persistence contract of the control plane.
//
// FROZEN CONTRACT: the interface below is consumed by the HTTP server, the CLI
// bootstrap and the mock cloud. The core-api owner implements it on SQLite
// (replace db_stub.go with db.go, migrations.go, ...) and may ADD methods but
// may not change or remove existing signatures. Other owners must not edit this
// package.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Common store errors.
var (
	// ErrNotFound is returned when a requested record does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned on a uniqueness or state conflict.
	ErrConflict = errors.New("store: conflict")
	// ErrNotImplemented is a placeholder error used before an implementation lands.
	ErrNotImplemented = errors.New("store: not implemented")
)

// LeaseFilter selects leases for ListLeases.
type LeaseFilter struct {
	Statuses     []model.LeaseStatus
	AgentID      string
	CapabilityID string
	// Limit defaults to 50 and is capped at 200 by the implementation.
	Limit  int
	Offset int
}

// AuditFilter selects audit events for ListAudit. Events are returned newest
// first (descending seq).
type AuditFilter struct {
	Action    string
	ActorType string
	ActorID   string
	Severity  string
	// Since is inclusive; the zero value means "no lower bound".
	Since  time.Time
	Limit  int
	Offset int
}

// Store is the complete persistence surface needed by the platform.
type Store interface {
	// ---- Meta / bootstrap ----
	GetMeta(ctx context.Context, key string) (string, error)
	SetMeta(ctx context.Context, key, value string) error

	// ---- Providers ----
	CreateProvider(ctx context.Context, p model.Provider, encryptedCredential string) error
	GetProvider(ctx context.Context, id string) (model.Provider, error)
	ListProviders(ctx context.Context) ([]model.Provider, error)
	UpdateProvider(ctx context.Context, p model.Provider) error
	// UpdateProviderCredential replaces the encrypted broker credential blob.
	UpdateProviderCredential(ctx context.Context, id, encryptedCredential string) error
	// GetProviderCredential returns the encrypted broker credential blob.
	GetProviderCredential(ctx context.Context, id string) (string, error)
	// CountProviderCredentials counts providers that hold a credential.
	CountProviderCredentials(ctx context.Context) (int, error)

	// ---- Capabilities ----
	CreateCapability(ctx context.Context, c model.Capability) error
	GetCapability(ctx context.Context, id string) (model.Capability, error)
	ListCapabilities(ctx context.Context) ([]model.Capability, error)
	UpdateCapability(ctx context.Context, c model.Capability) error

	// ---- Agents ----
	CreateAgent(ctx context.Context, a model.Agent, tokenHash string) error
	GetAgent(ctx context.Context, id string) (model.Agent, error)
	// GetAgentByTokenHash resolves a bearer token hash to an agent. It returns
	// ErrNotFound for unknown hashes.
	GetAgentByTokenHash(ctx context.Context, tokenHash string) (model.Agent, error)
	ListAgents(ctx context.Context) ([]model.Agent, error)
	UpdateAgent(ctx context.Context, a model.Agent) error
	UpdateAgentTokenHash(ctx context.Context, id, tokenHash string) error
	TouchAgentSeen(ctx context.Context, id string, at time.Time) error

	// ---- Leases ----
	CreateLease(ctx context.Context, l model.Lease) error
	GetLease(ctx context.Context, id string) (model.Lease, error)
	// ListLeases returns a page and the total number of matching records.
	ListLeases(ctx context.Context, f LeaseFilter) (items []model.Lease, total int, err error)
	UpdateLease(ctx context.Context, l model.Lease) error
	// SetLeaseCredential stores the encrypted credential blob for an active
	// lease together with its display fingerprint.
	SetLeaseCredential(ctx context.Context, leaseID, encryptedCredential, fingerprint string) error
	GetLeaseCredential(ctx context.Context, leaseID string) (string, error)
	// ClearLeaseCredential scrubs the stored credential blob (revoke/expire).
	ClearLeaseCredential(ctx context.Context, leaseID string) error
	// CountActiveLeases counts leases with status active for an agent.
	CountActiveLeases(ctx context.Context, agentID string) (int, error)
	// CountLeasesSince counts leases created at or after since for an agent.
	CountLeasesSince(ctx context.Context, agentID string, since time.Time) (int, error)
	// ListPendingLeases returns all pending leases (sweeper input).
	ListPendingLeases(ctx context.Context) ([]model.Lease, error)
	// ListActiveLeases returns all active leases (sweeper input).
	ListActiveLeases(ctx context.Context) ([]model.Lease, error)

	// ---- Audit ----
	// AppendAudit assigns Seq/ID/Time when zero, computes the hash chain and
	// persists the event, mutating ev in place.
	AppendAudit(ctx context.Context, ev *model.AuditEvent) error
	ListAudit(ctx context.Context, f AuditFilter) (items []model.AuditEvent, total int, err error)
	// VerifyAudit recomputes the hash chain and reports the first invalid event.
	VerifyAudit(ctx context.Context) (model.AuditVerifyResult, error)

	// ---- Policy ----
	GetPolicySettings(ctx context.Context) (model.PolicySettings, error)
	SetPolicySettings(ctx context.Context, s model.PolicySettings) error
}

// DB is the SQLite-backed Store implementation. Open is implemented by the
// core-api owner; the rest of the platform only depends on the Store interface.
type DB struct {
	sql  *sql.DB
	path string
	// appendMu serializes audit appends so seq allocation and hash chaining are
	// race-free across goroutines. VerifyAudit also takes it for a consistent
	// snapshot.
	appendMu sync.Mutex
}

// DBFileName is the SQLite database file inside the data directory.
const DBFileName = "csg.db"

// Open opens (and migrates) the control-plane database in dataDir.
//
// The database file is created with mode 0600 (best effort). Open is idempotent:
// opening an already-migrated database just applies no migrations.
func Open(ctx context.Context, dataDir string) (*DB, error) {
	if dataDir == "" {
		return nil, errors.New("store: data dir is required")
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create data dir: %w", err)
	}
	path := filepath.Join(dataDir, DBFileName)

	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=foreign_keys(ON)"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}
	// WAL allows concurrent readers with a single writer; a small pool plus the
	// busy timeout is plenty for a single-tenant control plane.
	sqlDB.SetMaxOpenConns(4)
	sqlDB.SetMaxIdleConns(4)
	sqlDB.SetConnMaxLifetime(0)

	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("store: ping database: %w", err)
	}
	// Best effort: the DB holds only ciphertext, but keep it owner-only anyway.
	_ = os.Chmod(path, 0o600)

	db := &DB{sql: sqlDB, path: path}
	if err := db.applyMigrations(ctx); err != nil {
		sqlDB.Close()
		return nil, err
	}
	return db, nil
}

// Path returns the database file path (used by tests and runtime diagnostics).
func (db *DB) Path() string {
	if db == nil {
		return ""
	}
	return db.path
}

// SQL returns the underlying *sql.DB. It is exposed for tests and diagnostics
// in the core-api package only; the rest of the platform depends on Store.
func (db *DB) SQL() *sql.DB {
	if db == nil {
		return nil
	}
	return db.sql
}

// Close releases the database.
func (db *DB) Close() error {
	if db == nil || db.sql == nil {
		return nil
	}
	err := db.sql.Close()
	db.sql = nil
	return err
}
