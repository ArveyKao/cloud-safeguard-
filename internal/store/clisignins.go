package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// CLISignIn is one command-line sign-in of a person (CONTRACT §17.9). Only
// the hash of the client's device code is stored.
type CLISignIn struct {
	ID             string
	DeviceCodeHash string
	UserCode       string
	ClientName     string
	Status         model.SignInStatus
	// PersonID is the person who approved or denied.
	PersonID   string
	SessionID  string
	RemoteAddr string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	DecidedAt  *time.Time
}

const cliSignInColumns = `id, device_code_hash, user_code, client_name, status, person_id, session_id, remote_addr, created_at, expires_at, decided_at`

func scanCLISignIn(row rowScanner) (CLISignIn, error) {
	var (
		s                CLISignIn
		created, expires int64
		decided          *int64
	)
	if err := row.Scan(&s.ID, &s.DeviceCodeHash, &s.UserCode, &s.ClientName, &s.Status, &s.PersonID,
		&s.SessionID, &s.RemoteAddr, &created, &expires, &decided); err != nil {
		return CLISignIn{}, mapErr(err)
	}
	s.CreatedAt, s.ExpiresAt, s.DecidedAt = fromMillis(created), fromMillis(expires), timePtr(decided)
	return s, nil
}

// CreateCLISignIn stores a pending command-line sign-in, unless too many
// are already waiting (at most maxTotal overall, maxPerAddr from one
// address; checked in the INSERT). ErrSignInLimit when a limit is reached,
// ErrConflict when a code collides.
func (db *DB) CreateCLISignIn(ctx context.Context, s CLISignIn, maxTotal, maxPerAddr int) error {
	res, err := db.sql.ExecContext(ctx,
		`INSERT INTO cli_signins(id, device_code_hash, user_code, client_name, status, remote_addr, created_at, expires_at)
		 SELECT ?, ?, ?, ?, 'pending', ?, ?, ?
		 WHERE (SELECT COUNT(*) FROM cli_signins WHERE status = 'pending' AND expires_at > ?) < ?
		   AND (SELECT COUNT(*) FROM cli_signins WHERE status = 'pending' AND expires_at > ? AND remote_addr = ?) < ?`,
		s.ID, s.DeviceCodeHash, s.UserCode, s.ClientName, s.RemoteAddr, toMillis(s.CreatedAt), toMillis(s.ExpiresAt),
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

// GetCLISignInByUserCode returns a sign-in by the code shown to the person.
func (db *DB) GetCLISignInByUserCode(ctx context.Context, userCode string) (CLISignIn, error) {
	return scanCLISignIn(db.sql.QueryRowContext(ctx, `SELECT `+cliSignInColumns+` FROM cli_signins WHERE user_code = ?`, userCode))
}

// GetCLISignInByDeviceCodeHash returns a sign-in by the device code hash.
func (db *DB) GetCLISignInByDeviceCodeHash(ctx context.Context, hash string) (CLISignIn, error) {
	return scanCLISignIn(db.sql.QueryRowContext(ctx, `SELECT `+cliSignInColumns+` FROM cli_signins WHERE device_code_hash = ?`, hash))
}

// DecideCLISignIn approves or denies a pending, unexpired sign-in for an
// active person (compare-and-set; ErrConflict otherwise).
func (db *DB) DecideCLISignIn(ctx context.Context, signInID, personID string, decision model.SignInStatus, now time.Time) error {
	if decision != model.SignInApproved && decision != model.SignInDenied {
		return errors.New("store: decision must be approved or denied")
	}
	res, err := db.sql.ExecContext(ctx,
		`UPDATE cli_signins SET status = ?, person_id = ?, decided_at = ?
		 WHERE id = ? AND status = 'pending' AND expires_at > ?
		   AND EXISTS (SELECT 1 FROM persons WHERE id = ? AND status = 'active')`,
		string(decision), personID, toMillis(now), signInID, toMillis(now), personID)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

// CancelCLISignIn withdraws an approval that was not collected yet: only the
// person who approved it can, and only before the client picked up its
// session. ErrNotFound otherwise.
func (db *DB) CancelCLISignIn(ctx context.Context, userCode, personID string, now time.Time) (CLISignIn, error) {
	signIn, err := db.GetCLISignInByUserCode(ctx, userCode)
	if err != nil {
		return CLISignIn{}, err
	}
	res, err := db.sql.ExecContext(ctx,
		`UPDATE cli_signins SET status = 'denied', decided_at = ?
		 WHERE id = ? AND person_id = ? AND status = 'approved' AND expires_at > ?`,
		toMillis(now), signIn.ID, personID, toMillis(now))
	if err != nil {
		return CLISignIn{}, mapErr(err)
	}
	if err := affectedOrNotFound(res); err != nil {
		return CLISignIn{}, err
	}
	return signIn, nil
}

// CompleteCLISignIn finishes an approved sign-in in one transaction: it
// marks it consumed (still approved, unexpired, approver active), so a token
// is issued at most once, and creates the session for the approver. It
// returns the approver's ID, or ErrConflict.
func (db *DB) CompleteCLISignIn(ctx context.Context, signInID string, sess Session, now time.Time) (string, error) {
	var personID string
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx,
			`UPDATE cli_signins SET status = 'consumed', session_id = ?
			 WHERE id = ? AND status = 'approved' AND expires_at > ?
			   AND EXISTS (SELECT 1 FROM persons WHERE id = cli_signins.person_id AND status = 'active')
			 RETURNING person_id`, sess.ID, signInID, toMillis(now)).Scan(&personID)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && personID == "") {
			return ErrConflict
		}
		if err != nil {
			return mapErr(err)
		}
		sess.PersonID = personID
		sess.Kind = SessionCLI
		return insertSession(ctx, tx, sess)
	})
	return personID, err
}

// DeleteOldCLISignIns removes sign-ins that expired before cutoff.
func (db *DB) DeleteOldCLISignIns(ctx context.Context, cutoff time.Time) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM cli_signins WHERE expires_at <= ?`, toMillis(cutoff))
	return mapErr(err)
}
