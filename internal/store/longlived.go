package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Long-lived credentials (CONTRACT §17.14). The secret is never stored; the
// console link key is stored only as a hash.

const longLivedColumns = `id, link_hash, provider_id, owner_id, agent_id, agent_name, capability_id, resource_name, reason,
	status, cloud_user, cloud_policy, access_key_id, failure_reason, revoke_reason, created_at, expires_at, decided_at, revoked_at`

// LongLivedRow is a stored long-lived credential. The server turns it into
// the model view (account names, resource and permission).
type LongLivedRow struct {
	ID, LinkHash, ProviderID, OwnerID, AgentID, AgentName, CapabilityID, ResourceName, Reason string
	Status                                                                                    model.LongLivedStatus
	CloudUser, CloudPolicy, AccessKeyID, FailureReason, RevokeReason                          string
	CreatedAt, ExpiresAt                                                                      time.Time
	DecidedAt, RevokedAt                                                                      *time.Time
}

func scanLongLived(row rowScanner) (LongLivedRow, error) {
	var (
		r                  LongLivedRow
		created, expires   int64
		decided, revokedAt *int64
	)
	if err := row.Scan(&r.ID, &r.LinkHash, &r.ProviderID, &r.OwnerID, &r.AgentID, &r.AgentName, &r.CapabilityID, &r.ResourceName,
		&r.Reason, &r.Status, &r.CloudUser, &r.CloudPolicy, &r.AccessKeyID, &r.FailureReason, &r.RevokeReason,
		&created, &expires, &decided, &revokedAt); err != nil {
		return LongLivedRow{}, mapErr(err)
	}
	r.CreatedAt, r.ExpiresAt = fromMillis(created), fromMillis(expires)
	r.DecidedAt, r.RevokedAt = timePtr(decided), timePtr(revokedAt)
	return r, nil
}

// CreateLongLived stores a pending request unless the owner already has
// maxPending waiting (ErrConflict).
func (db *DB) CreateLongLived(ctx context.Context, r LongLivedRow, maxPending int) error {
	res, err := db.sql.ExecContext(ctx,
		`INSERT INTO long_lived_credentials(id, link_hash, provider_id, owner_id, agent_id, agent_name, capability_id,
			resource_name, reason, status, created_at, expires_at)
		 SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?
		 WHERE (SELECT COUNT(*) FROM long_lived_credentials WHERE owner_id = ? AND status = 'pending' AND expires_at > ?) < ?`,
		r.ID, r.LinkHash, r.ProviderID, r.OwnerID, r.AgentID, r.AgentName, r.CapabilityID, r.ResourceName, r.Reason,
		toMillis(r.CreatedAt), toMillis(r.ExpiresAt), r.OwnerID, toMillis(r.CreatedAt), maxPending)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

// GetLongLived returns one credential.
func (db *DB) GetLongLived(ctx context.Context, id string) (LongLivedRow, error) {
	return scanLongLived(db.sql.QueryRowContext(ctx, `SELECT `+longLivedColumns+` FROM long_lived_credentials WHERE id = ?`, id))
}

// GetLongLivedByLinkHash returns the credential a console link names.
func (db *DB) GetLongLivedByLinkHash(ctx context.Context, hash string) (LongLivedRow, error) {
	if hash == "" {
		return LongLivedRow{}, ErrNotFound
	}
	return scanLongLived(db.sql.QueryRowContext(ctx, `SELECT `+longLivedColumns+` FROM long_lived_credentials WHERE link_hash = ?`, hash))
}

// LongLivedFilter selects credentials; empty fields match everything.
type LongLivedFilter struct {
	OwnerID, ProviderID string
	Statuses            []model.LongLivedStatus
}

// ListLongLived returns credentials newest first (at most 500).
func (db *DB) ListLongLived(ctx context.Context, f LongLivedFilter) ([]LongLivedRow, error) {
	query := `SELECT ` + longLivedColumns + ` FROM long_lived_credentials WHERE (? = '' OR owner_id = ?) AND (? = '' OR provider_id = ?)`
	args := []any{f.OwnerID, f.OwnerID, f.ProviderID, f.ProviderID}
	if len(f.Statuses) > 0 {
		query += ` AND status IN (?` + repeatPlaceholders(len(f.Statuses)-1) + `)`
		for _, st := range f.Statuses {
			args = append(args, string(st))
		}
	}
	query += ` ORDER BY created_at DESC, id DESC LIMIT 500`
	rows, err := db.sql.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	var out []LongLivedRow
	for rows.Next() {
		r, err := scanLongLived(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, mapErr(rows.Err())
}

func repeatPlaceholders(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += ", ?"
	}
	return out
}

// moveLongLived is a compare-and-set of the status: from one of from to to,
// with extra column assignments. ErrConflict when the credential is in none
// of from (or, for pending, has expired).
func (db *DB) moveLongLived(ctx context.Context, id string, from []model.LongLivedStatus, to model.LongLivedStatus, now time.Time, set string, args ...any) error {
	query := `UPDATE long_lived_credentials SET status = ?` + set + ` WHERE id = ? AND status IN (?` + repeatPlaceholders(len(from)-1) + `)
		AND (status <> 'pending' OR expires_at > ?)`
	all := append([]any{string(to)}, args...)
	all = append(all, id)
	for _, st := range from {
		all = append(all, string(st))
	}
	all = append(all, toMillis(now))
	res, err := db.sql.ExecContext(ctx, query, all...)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

// ClaimLongLivedForCreate moves an unexpired pending request to creating;
// only one caller can win it.
func (db *DB) ClaimLongLivedForCreate(ctx context.Context, id string, now time.Time) error {
	return db.moveLongLived(ctx, id, []model.LongLivedStatus{model.LongLivedPending}, model.LongLivedCreating, now,
		`, decided_at = ?`, toMillis(now))
}

// SetLongLivedActive records what was created in the cloud.
func (db *DB) SetLongLivedActive(ctx context.Context, id, cloudUser, cloudPolicy, accessKeyID string, now time.Time) error {
	return db.moveLongLived(ctx, id, []model.LongLivedStatus{model.LongLivedCreating}, model.LongLivedActive, now,
		`, cloud_user = ?, cloud_policy = ?, access_key_id = ?`, cloudUser, cloudPolicy, accessKeyID)
}

// SetLongLivedFailed records a failed creation.
func (db *DB) SetLongLivedFailed(ctx context.Context, id, reason string, now time.Time) error {
	return db.moveLongLived(ctx, id, []model.LongLivedStatus{model.LongLivedCreating}, model.LongLivedFailed, now,
		`, failure_reason = ?`, reason)
}

// DenyLongLived declines a pending request.
func (db *DB) DenyLongLived(ctx context.Context, id string, now time.Time) error {
	return db.moveLongLived(ctx, id, []model.LongLivedStatus{model.LongLivedPending}, model.LongLivedDenied, now,
		`, decided_at = ?`, toMillis(now))
}

// ClaimLongLivedForRevoke moves an active (or earlier failed-to-revoke)
// credential to revoking; only one caller can win it.
func (db *DB) ClaimLongLivedForRevoke(ctx context.Context, id, reason string, now time.Time) error {
	return db.moveLongLived(ctx, id, []model.LongLivedStatus{model.LongLivedActive, model.LongLivedRevokeFailed},
		model.LongLivedRevoking, now, `, revoke_reason = ?`, reason)
}

// FinishLongLivedRevoke records the outcome of a deletion in the cloud.
func (db *DB) FinishLongLivedRevoke(ctx context.Context, id string, failure string, now time.Time) error {
	if failure != "" {
		return db.moveLongLived(ctx, id, []model.LongLivedStatus{model.LongLivedRevoking}, model.LongLivedRevokeFailed, now,
			`, failure_reason = ?`, failure)
	}
	return db.moveLongLived(ctx, id, []model.LongLivedStatus{model.LongLivedRevoking}, model.LongLivedRevoked, now,
		`, revoked_at = ?, failure_reason = ''`, toMillis(now))
}

// ExpireLongLivedRequests marks pending requests past their hour expired.
func (db *DB) ExpireLongLivedRequests(ctx context.Context, now time.Time) error {
	_, err := db.sql.ExecContext(ctx,
		`UPDATE long_lived_credentials SET status = 'expired' WHERE status = 'pending' AND expires_at <= ?`, toMillis(now))
	return mapErr(err)
}

// CountLiveLongLived counts the credentials of an account that exist, or may
// exist, in the cloud.
func (db *DB) CountLiveLongLived(ctx context.Context, providerID string) (int, error) {
	var n int
	err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM long_lived_credentials WHERE provider_id = ? AND status IN ('creating', 'active', 'revoking', 'revoke_failed')`,
		providerID).Scan(&n)
	return n, mapErr(err)
}

// SetPersonLongLived sets the person flag that allows creating long-lived
// credentials.
func (db *DB) SetPersonLongLived(ctx context.Context, id string, allowed bool, now time.Time) error {
	res, err := db.sql.ExecContext(ctx, `UPDATE persons SET long_lived = ?, updated_at = ? WHERE id = ?`, boolInt(allowed), toMillis(now), id)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// SetProviderUserAdmin stores (or, with empty values, clears) the encrypted
// second key of a cloud account. Clearing is refused while credentials of
// the account may exist in the cloud (ErrConflict).
func (db *DB) SetProviderUserAdmin(ctx context.Context, id, encrypted, masked string, now time.Time) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		if encrypted == "" {
			var n int
			if err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM long_lived_credentials WHERE provider_id = ? AND status IN ('creating', 'active', 'revoking', 'revoke_failed')`,
				id).Scan(&n); err != nil {
				return mapErr(err)
			}
			if n > 0 {
				return ErrConflict
			}
		}
		res, err := tx.ExecContext(ctx, `UPDATE providers SET user_admin_credential = ?, user_admin_key_masked = ?, updated_at = ? WHERE id = ?`,
			encrypted, masked, toMillis(now), id)
		if err != nil {
			return mapErr(err)
		}
		return affectedOrNotFound(res)
	})
}

// GetProviderUserAdmin returns the encrypted second key; ErrNotFound when the
// account has none.
func (db *DB) GetProviderUserAdmin(ctx context.Context, id string) (string, error) {
	var blob string
	err := db.sql.QueryRowContext(ctx, `SELECT user_admin_credential FROM providers WHERE id = ?`, id).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && blob == "") {
		return "", ErrNotFound
	}
	return blob, mapErr(err)
}
