package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

const leaseColumns = `id, agent_id, agent_name, capability_id, capability_name,
	provider_id, provider_name, provider_mode, risk, params_json, reason,
	requested_ttl_seconds, effective_ttl_seconds, status, decision_json, break_glass,
	approved_by, approval_note, denied_reason, revoke_reason, failure_reason,
	session_name, credential_available, credential_fingerprint, created_at,
	approved_at, issued_at, expires_at, revoked_at`

// scanLease scans one lease row (credential blob excluded).
func scanLease(row rowScanner) (model.Lease, error) {
	var (
		l             model.Lease
		paramsJSON    string
		decisionJSON  string
		breakGlass    int
		credAvailable int
		createdAt     int64
		approvedAt    *int64
		issuedAt      *int64
		expiresAt     *int64
		revokedAt     *int64
	)
	err := row.Scan(
		&l.ID, &l.AgentID, &l.AgentName, &l.CapabilityID, &l.CapabilityName,
		&l.ProviderID, &l.ProviderName, &l.ProviderMode, &l.Risk, &paramsJSON, &l.Reason,
		&l.RequestedTTLSeconds, &l.EffectiveTTLSeconds, &l.Status, &decisionJSON, &breakGlass,
		&l.ApprovedBy, &l.ApprovalNote, &l.DeniedReason, &l.RevokeReason, &l.FailureReason,
		&l.SessionName, &credAvailable, &l.CredentialFingerprint, &createdAt,
		&approvedAt, &issuedAt, &expiresAt, &revokedAt,
	)
	if err != nil {
		return model.Lease{}, mapErr(err)
	}
	l.BreakGlass = intBool(breakGlass)
	l.CredentialAvailable = intBool(credAvailable)
	l.CreatedAt = fromMillis(createdAt)
	l.ApprovedAt = timePtr(approvedAt)
	l.IssuedAt = timePtr(issuedAt)
	l.ExpiresAt = timePtr(expiresAt)
	l.RevokedAt = timePtr(revokedAt)
	if paramsJSON != "" && paramsJSON != "null" {
		if err := json.Unmarshal([]byte(paramsJSON), &l.Params); err != nil {
			return model.Lease{}, fmt.Errorf("store: corrupt lease params for %s: %w", l.ID, err)
		}
	}
	if decisionJSON != "" && decisionJSON != "null" {
		if err := json.Unmarshal([]byte(decisionJSON), &l.Decision); err != nil {
			return model.Lease{}, fmt.Errorf("store: corrupt lease decision for %s: %w", l.ID, err)
		}
	}
	if l.Decision.Reasons == nil {
		l.Decision.Reasons = []model.DecisionReason{}
	}
	return l, nil
}

// CreateLease persists a new lease (all states, including denied ones).
func (db *DB) CreateLease(ctx context.Context, l model.Lease) error {
	paramsJSON, err := marshalJSON(l.Params, "{}")
	if err != nil {
		return err
	}
	decisionJSON, err := marshalJSON(l.Decision, "{}")
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO leases(`+leaseColumns+`, encrypted_credential)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')`,
		l.ID, l.AgentID, l.AgentName, l.CapabilityID, l.CapabilityName,
		l.ProviderID, l.ProviderName, string(l.ProviderMode), string(l.Risk), paramsJSON, l.Reason,
		l.RequestedTTLSeconds, l.EffectiveTTLSeconds, string(l.Status), decisionJSON, boolInt(l.BreakGlass),
		l.ApprovedBy, l.ApprovalNote, l.DeniedReason, l.RevokeReason, l.FailureReason,
		l.SessionName, boolInt(l.CredentialAvailable), l.CredentialFingerprint, toMillis(l.CreatedAt),
		millisPtr(l.ApprovedAt), millisPtr(l.IssuedAt), millisPtr(l.ExpiresAt), millisPtr(l.RevokedAt),
	)
	return mapErr(err)
}

// GetLease returns a lease by ID.
func (db *DB) GetLease(ctx context.Context, id string) (model.Lease, error) {
	row := db.sql.QueryRowContext(ctx, `SELECT `+leaseColumns+` FROM leases WHERE id = ?`, id)
	return scanLease(row)
}

// ListLeases returns a filtered page of leases (newest first) plus the total
// number of matching records.
func (db *DB) ListLeases(ctx context.Context, f LeaseFilter) ([]model.Lease, int, error) {
	limit, offset := pageParams(f.Limit, f.Offset)
	whereSQL, args := leaseWhere(f)

	var total int
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM leases`+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, mapErr(err)
	}

	query := `SELECT ` + leaseColumns + ` FROM leases` + whereSQL +
		` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`
	queryArgs := append(append([]any{}, args...), limit, offset)
	rows, err := db.sql.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, mapErr(err)
	}
	defer rows.Close()

	items := make([]model.Lease, 0, minInt(limit, total))
	for rows.Next() {
		l, err := scanLease(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, l)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mapErr(err)
	}
	return items, total, nil
}

// ListAllLeases returns every lease matching f (Limit and Offset are ignored)
// from one query, i.e. one consistent snapshot. Security sweeps use it: paging
// with LIMIT/OFFSET over a set that changes between pages can skip rows.
func (db *DB) ListAllLeases(ctx context.Context, f LeaseFilter) ([]model.Lease, error) {
	whereSQL, args := leaseWhere(f)
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+leaseColumns+` FROM leases`+whereSQL+` ORDER BY created_at DESC, id DESC`, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var items []model.Lease
	for rows.Next() {
		l, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, l)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return items, nil
}

// leaseWhere builds the WHERE clause and arguments for a lease filter.
func leaseWhere(f LeaseFilter) (string, []any) {
	var (
		where []string
		args  []any
	)
	if len(f.Statuses) > 0 {
		placeholders := make([]string, 0, len(f.Statuses))
		for _, s := range f.Statuses {
			placeholders = append(placeholders, "?")
			args = append(args, string(s))
		}
		where = append(where, "status IN ("+strings.Join(placeholders, ", ")+")")
	}
	if f.AgentID != "" {
		where = append(where, "agent_id = ?")
		args = append(args, f.AgentID)
	}
	if f.CapabilityID != "" {
		where = append(where, "capability_id = ?")
		args = append(args, f.CapabilityID)
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}
	return whereSQL, args
}

// UpdateLease persists all mutable lifecycle fields of a lease. The encrypted
// credential blob is managed separately by SetLeaseCredential /
// ClearLeaseCredential.
func (db *DB) UpdateLease(ctx context.Context, l model.Lease) error {
	return db.updateLease(ctx, l, "")
}

// UpdateLeaseIfStatus implements Store.UpdateLeaseIfStatus as a single
// compare-and-set UPDATE, so the status check and the write are atomic.
func (db *DB) UpdateLeaseIfStatus(ctx context.Context, l model.Lease, expected model.LeaseStatus) error {
	if expected == "" {
		return fmt.Errorf("store: UpdateLeaseIfStatus needs an expected status")
	}
	err := db.updateLease(ctx, l, expected)
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	// Zero rows: tell a missing lease apart from one that changed status.
	if _, gerr := db.GetLease(ctx, l.ID); gerr == nil {
		return ErrConflict
	}
	return ErrNotFound
}

// updateLease writes every mutable lease field. A non-empty expected status
// adds "AND status = expected" to the WHERE clause.
func (db *DB) updateLease(ctx context.Context, l model.Lease, expected model.LeaseStatus) error {
	paramsJSON, err := marshalJSON(l.Params, "{}")
	if err != nil {
		return err
	}
	decisionJSON, err := marshalJSON(l.Decision, "{}")
	if err != nil {
		return err
	}
	res, err := db.sql.ExecContext(ctx,
		`UPDATE leases SET agent_id = ?, agent_name = ?, capability_id = ?, capability_name = ?,
			provider_id = ?, provider_name = ?, provider_mode = ?, risk = ?, params_json = ?,
			reason = ?, requested_ttl_seconds = ?, effective_ttl_seconds = ?, status = ?,
			decision_json = ?, break_glass = ?, approved_by = ?, approval_note = ?,
			denied_reason = ?, revoke_reason = ?, failure_reason = ?, session_name = ?,
			credential_available = ?, credential_fingerprint = ?, approved_at = ?, issued_at = ?,
			expires_at = ?, revoked_at = ?
		 WHERE id = ? AND (? = '' OR status = ?)`,
		l.AgentID, l.AgentName, l.CapabilityID, l.CapabilityName,
		l.ProviderID, l.ProviderName, string(l.ProviderMode), string(l.Risk), paramsJSON,
		l.Reason, l.RequestedTTLSeconds, l.EffectiveTTLSeconds, string(l.Status),
		decisionJSON, boolInt(l.BreakGlass), l.ApprovedBy, l.ApprovalNote,
		l.DeniedReason, l.RevokeReason, l.FailureReason, l.SessionName,
		boolInt(l.CredentialAvailable), l.CredentialFingerprint,
		millisPtr(l.ApprovedAt), millisPtr(l.IssuedAt), millisPtr(l.ExpiresAt), millisPtr(l.RevokedAt),
		l.ID, string(expected), string(expected),
	)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// SetLeaseCredential stores the encrypted credential blob and its non-secret
// display fingerprint, marking the credential as available.
//
// It writes only while the lease is still pending, so a minting attempt that
// lost a race can never overwrite the credential of a lease another attempt
// already activated (or one that was revoked or expired). It returns
// ErrConflict when the lease exists but is no longer pending.
func (db *DB) SetLeaseCredential(ctx context.Context, leaseID, encryptedCredential, fingerprint string) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE leases SET encrypted_credential = ?, credential_fingerprint = ?,
			credential_available = 1
		 WHERE id = ? AND status = ?`,
		encryptedCredential, fingerprint, leaseID, string(model.LeasePending))
	if err != nil {
		return mapErr(err)
	}
	if err := affectedOrNotFound(res); !errors.Is(err, ErrNotFound) {
		return err
	}
	if _, gerr := db.GetLease(ctx, leaseID); gerr == nil {
		return ErrConflict
	}
	return ErrNotFound
}

// GetLeaseCredential returns the encrypted credential blob.
func (db *DB) GetLeaseCredential(ctx context.Context, leaseID string) (string, error) {
	var blob string
	err := db.sql.QueryRowContext(ctx,
		`SELECT encrypted_credential FROM leases WHERE id = ?`, leaseID).Scan(&blob)
	if err != nil {
		return "", mapErr(err)
	}
	if blob == "" {
		return "", ErrNotFound
	}
	return blob, nil
}

// ClearLeaseCredential scrubs the credential blob of a lease.
func (db *DB) ClearLeaseCredential(ctx context.Context, leaseID string) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE leases SET encrypted_credential = '', credential_fingerprint = '',
			credential_available = 0
		 WHERE id = ?`, leaseID)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// CountActiveLeases counts leases with status active for an agent.
func (db *DB) CountActiveLeases(ctx context.Context, agentID string) (int, error) {
	var n int
	err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM leases WHERE agent_id = ? AND status = ?`,
		agentID, string(model.LeaseActive)).Scan(&n)
	if err != nil {
		return 0, mapErr(err)
	}
	return n, nil
}

// CountLeasesSince counts leases created at or after since for an agent.
func (db *DB) CountLeasesSince(ctx context.Context, agentID string, since time.Time) (int, error) {
	var n int
	err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM leases WHERE agent_id = ? AND created_at >= ?`,
		agentID, toMillis(since)).Scan(&n)
	if err != nil {
		return 0, mapErr(err)
	}
	return n, nil
}

// ListPendingLeases returns every pending lease, oldest first (sweeper input).
func (db *DB) ListPendingLeases(ctx context.Context) ([]model.Lease, error) {
	return db.listLeasesByStatus(ctx, model.LeasePending)
}

// ListActiveLeases returns every active lease, oldest first (sweeper input).
func (db *DB) ListActiveLeases(ctx context.Context) ([]model.Lease, error) {
	return db.listLeasesByStatus(ctx, model.LeaseActive)
}

// listLeasesByStatus returns all leases in one status ordered by creation time.
func (db *DB) listLeasesByStatus(ctx context.Context, status model.LeaseStatus) ([]model.Lease, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+leaseColumns+` FROM leases WHERE status = ? ORDER BY created_at ASC, id ASC`,
		string(status))
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	out := make([]model.Lease, 0, 8)
	for rows.Next() {
		l, err := scanLease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

// CountLeasesByRisk counts leases in the given statuses grouped by risk tier.
// It backs the dashboard risk breakdown (not part of the frozen Store interface).
func (db *DB) CountLeasesByRisk(ctx context.Context, statuses []model.LeaseStatus) (model.RiskBreakdown, error) {
	var out model.RiskBreakdown
	if len(statuses) == 0 {
		return out, nil
	}
	placeholders := make([]string, 0, len(statuses))
	args := make([]any, 0, len(statuses))
	for _, s := range statuses {
		placeholders = append(placeholders, "?")
		args = append(args, string(s))
	}
	rows, err := db.sql.QueryContext(ctx,
		`SELECT risk, COUNT(*) FROM leases WHERE status IN (`+strings.Join(placeholders, ", ")+`) GROUP BY risk`,
		args...)
	if err != nil {
		return out, mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			risk string
			n    int
		)
		if err := rows.Scan(&risk, &n); err != nil {
			return out, mapErr(err)
		}
		switch model.RiskTier(risk) {
		case model.RiskLow:
			out.Low += n
		case model.RiskMedium:
			out.Medium += n
		case model.RiskHigh:
			out.High += n
		case model.RiskCritical:
			out.Critical += n
		}
	}
	if err := rows.Err(); err != nil {
		return out, mapErr(err)
	}
	return out, nil
}

// CountLeasesCreatedSinceByStatus counts leases with one status created since
// the given time (dashboard "denied in last 24h" counter). It is a concrete-DB
// extension, not part of the frozen Store interface.
func (db *DB) CountLeasesCreatedSinceByStatus(ctx context.Context, status model.LeaseStatus, since time.Time) (int, error) {
	var n int
	err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM leases WHERE status = ? AND created_at >= ?`,
		string(status), toMillis(since)).Scan(&n)
	if err != nil {
		return 0, mapErr(err)
	}
	return n, nil
}

// pageParams normalizes pagination: default limit 50, cap 200, offset >= 0.
func pageParams(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ensure sql import is used even if all statements above are in helpers.
var _ = sql.ErrNoRows
