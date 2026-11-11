package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// SignIn is one agent sign-in attempt (CONTRACT §17.3). Only the hash of
// the agent's device code is stored.
type SignIn struct {
	ID             string
	DeviceCodeHash string
	UserCode       string
	AgentName      string
	Description    string
	Status         model.SignInStatus
	// PersonID is the person who approved or denied.
	PersonID   string
	AgentID    string
	RemoteAddr string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	DecidedAt  *time.Time
}

const signInColumns = `id, device_code_hash, user_code, agent_name, description, status, person_id, agent_id, remote_addr, created_at, expires_at, decided_at`

func scanSignIn(row rowScanner) (SignIn, error) {
	var (
		s                SignIn
		created, expires int64
		decided          *int64
	)
	if err := row.Scan(&s.ID, &s.DeviceCodeHash, &s.UserCode, &s.AgentName, &s.Description, &s.Status, &s.PersonID,
		&s.AgentID, &s.RemoteAddr, &created, &expires, &decided); err != nil {
		return SignIn{}, mapErr(err)
	}
	s.CreatedAt, s.ExpiresAt, s.DecidedAt = fromMillis(created), fromMillis(expires), timePtr(decided)
	return s, nil
}

// ErrSignInLimit is returned when too many sign-ins are already waiting.
var ErrSignInLimit = errors.New("store: too many pending sign-ins")

// CreateSignIn stores a pending sign-in, unless too many are already
// waiting: at most maxTotal overall and maxPerAddr from one remote address.
// The limits are part of the INSERT, so parallel starts cannot exceed them.
// It returns ErrSignInLimit when a limit is reached and ErrConflict when a
// code collides with an existing sign-in.
func (db *DB) CreateSignIn(ctx context.Context, s SignIn, maxTotal, maxPerAddr int) error {
	res, err := db.sql.ExecContext(ctx,
		`INSERT INTO agent_signins(id, device_code_hash, user_code, agent_name, description, status, remote_addr, created_at, expires_at)
		 SELECT ?, ?, ?, ?, ?, 'pending', ?, ?, ?
		 WHERE (SELECT COUNT(*) FROM agent_signins WHERE status = 'pending' AND expires_at > ?) < ?
		   AND (SELECT COUNT(*) FROM agent_signins WHERE status = 'pending' AND expires_at > ? AND remote_addr = ?) < ?`,
		s.ID, s.DeviceCodeHash, s.UserCode, s.AgentName, s.Description, s.RemoteAddr, toMillis(s.CreatedAt), toMillis(s.ExpiresAt),
		toMillis(s.CreatedAt), maxTotal,
		toMillis(s.CreatedAt), s.RemoteAddr, maxPerAddr)
	if err != nil {
		return mapErr(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrSignInLimit
	}
	return nil
}

// GetSignInByUserCode returns a sign-in by the code shown to the person.
func (db *DB) GetSignInByUserCode(ctx context.Context, userCode string) (SignIn, error) {
	return scanSignIn(db.sql.QueryRowContext(ctx, `SELECT `+signInColumns+` FROM agent_signins WHERE user_code = ?`, userCode))
}

// GetSignInByDeviceCodeHash returns a sign-in by the agent's device code hash.
func (db *DB) GetSignInByDeviceCodeHash(ctx context.Context, hash string) (SignIn, error) {
	return scanSignIn(db.sql.QueryRowContext(ctx, `SELECT `+signInColumns+` FROM agent_signins WHERE device_code_hash = ?`, hash))
}

// DecideSignIn approves or denies a sign-in. It is a compare-and-set: it
// writes only while the sign-in is pending and unexpired and the deciding
// person is active. ErrConflict otherwise.
func (db *DB) DecideSignIn(ctx context.Context, signInID, personID string, decision model.SignInStatus, now time.Time) error {
	if decision != model.SignInApproved && decision != model.SignInDenied {
		return errors.New("store: decision must be approved or denied")
	}
	res, err := db.sql.ExecContext(ctx,
		`UPDATE agent_signins SET status = ?, person_id = ?, decided_at = ?
		 WHERE id = ? AND status = 'pending' AND expires_at > ?
		   AND EXISTS (SELECT 1 FROM persons WHERE id = ? AND status = 'active')`,
		string(decision), personID, toMillis(now), signInID, toMillis(now), personID)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

// CompleteSignIn finishes an approved sign-in in one transaction:
//
//  1. it marks the sign-in consumed, as a compare-and-set (still approved,
//     unexpired, approver still active), so a token is issued at most once;
//  2. it revokes the approver's earlier active agents with the same name;
//  3. it inserts agent with the approver as owner.
//
// It returns the stored agent and the IDs of the replaced agents, or
// ErrConflict when the sign-in cannot be completed (anymore).
func (db *DB) CompleteSignIn(ctx context.Context, signInID string, agent model.Agent, tokenHash string, now time.Time) (model.Agent, []string, error) {
	replaced := []string{}
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		var ownerID string
		err := tx.QueryRowContext(ctx,
			`UPDATE agent_signins SET status = 'consumed', agent_id = ?
			 WHERE id = ? AND status = 'approved' AND expires_at > ?
			   AND EXISTS (SELECT 1 FROM persons WHERE id = agent_signins.person_id AND status = 'active')
			 RETURNING person_id`,
			agent.ID, signInID, toMillis(now)).Scan(&ownerID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return mapErr(err)
		}
		if ownerID == "" {
			return ErrConflict
		}
		rows, err := tx.QueryContext(ctx,
			`UPDATE agents SET status = 'revoked', updated_at = ?
			 WHERE owner_id = ? AND name = ? AND status <> 'revoked' RETURNING id`,
			toMillis(now), ownerID, agent.Name)
		if err != nil {
			return mapErr(err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return mapErr(err)
			}
			replaced = append(replaced, id)
		}
		if err := rows.Close(); err != nil {
			return mapErr(err)
		}
		agent.OwnerID = ownerID
		return insertAgent(ctx, tx, agent, tokenHash)
	})
	if err != nil {
		return model.Agent{}, nil, err
	}
	return agent, replaced, nil
}

// DeleteOldSignIns removes sign-ins that expired before cutoff.
func (db *DB) DeleteOldSignIns(ctx context.Context, cutoff time.Time) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM agent_signins WHERE expires_at <= ?`, toMillis(cutoff))
	return mapErr(err)
}

// RevokeOwnerLeases revokes every pending and active lease of every agent a
// person owns, in one statement, and erases the stored credentials. It is
// for local recovery, which runs outside the server process; the server
// itself revokes through its own lease pipeline. It returns the lease IDs.
func (db *DB) RevokeOwnerLeases(ctx context.Context, personID, reason string, now time.Time) ([]string, error) {
	ids := []string{}
	if personID == "" {
		return ids, nil
	}
	rows, err := db.sql.QueryContext(ctx,
		`UPDATE leases SET status = 'revoked', revoke_reason = ?, revoked_at = ?,
			credential_available = 0, credential_fingerprint = '', encrypted_credential = ''
		 WHERE status IN ('pending', 'active')
		   AND agent_id IN (SELECT id FROM agents WHERE owner_id = ?)
		 RETURNING id`,
		reason, toMillis(now), personID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, mapErr(err)
		}
		ids = append(ids, id)
	}
	return ids, mapErr(rows.Err())
}
