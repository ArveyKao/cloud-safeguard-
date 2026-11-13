package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// ErrLastSupervisor is returned when a change would leave the platform with
// no active supervisor (CONTRACT §17.1).
var ErrLastSupervisor = errors.New("store: the last active supervisor cannot be removed")

// PersonAuth holds a person's authentication state. It never leaves the
// server process and is never serialized.
type PersonAuth struct {
	PasswordHash string
	// TOTPSecretEnc is the vault-encrypted TOTP secret.
	TOTPSecretEnc string
	// TOTPLastStep is the last accepted TOTP time step, -1 when none.
	TOTPLastStep   int64
	SetupCodeHash  string
	SetupExpiresAt *time.Time
	FailedLogins   int
	LockedUntil    *time.Time
}

// Session is a console session. Only the hash of the cookie value is stored.
type Session struct {
	TokenHash  string
	PersonID   string
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

const personColumns = `id, username, display_name, status, supervisor, last_login_at, created_at, updated_at,
	approval_mode, approval_mode_expires_at, setup_issued_by, setup_issued_by_name, setup_issued_kind, setup_issued_at`

func scanPerson(row rowScanner) (model.Person, error) {
	var (
		p                    model.Person
		supervisor           int
		lastLogin            *int64
		createdAt, updatedAt int64
		modeExpires          *int64
		issue                model.SetupIssue
		issuedAt             *int64
	)
	if err := row.Scan(&p.ID, &p.Username, &p.DisplayName, &p.Status, &supervisor, &lastLogin, &createdAt, &updatedAt,
		&p.ApprovalMode, &modeExpires, &issue.ByID, &issue.ByName, &issue.Kind, &issuedAt); err != nil {
		return model.Person{}, mapErr(err)
	}
	if issue.Kind != "" && issuedAt != nil {
		issue.At = fromMillis(*issuedAt)
		p.SetupIssued = &issue
	}
	p.ApprovalModeExpiresAt = timePtr(modeExpires)
	p.Supervisor = intBool(supervisor)
	p.LastLoginAt = timePtr(lastLogin)
	p.CreatedAt = fromMillis(createdAt)
	p.UpdatedAt = fromMillis(updatedAt)
	return p, nil
}

// CreatePerson stores a new pending person with the hash of a setup code.
// It returns ErrConflict when the username is taken.
// p.SetupIssued, when set, records who issued the setup code.
func (db *DB) CreatePerson(ctx context.Context, p model.Person, setupCodeHash string, setupExpiresAt time.Time) error {
	var issue model.SetupIssue
	var issuedAt *int64
	if p.SetupIssued != nil {
		issue = *p.SetupIssued
		issuedAt = millisPtr(&issue.At)
	}
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO persons(id, username, display_name, status, supervisor, setup_code_hash, setup_expires_at, created_at, updated_at,
			setup_issued_by, setup_issued_by_name, setup_issued_kind, setup_issued_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Username, p.DisplayName, string(model.PersonPending), boolInt(p.Supervisor),
		setupCodeHash, toMillis(setupExpiresAt), toMillis(p.CreatedAt), toMillis(p.UpdatedAt),
		issue.ByID, issue.ByName, issue.Kind, issuedAt)
	return mapErr(err)
}

// GetPerson returns a person by ID.
func (db *DB) GetPerson(ctx context.Context, id string) (model.Person, error) {
	return scanPerson(db.sql.QueryRowContext(ctx, `SELECT `+personColumns+` FROM persons WHERE id = ?`, id))
}

// GetPersonByUsername returns a person by exact (normalized) username.
func (db *DB) GetPersonByUsername(ctx context.Context, username string) (model.Person, error) {
	return scanPerson(db.sql.QueryRowContext(ctx, `SELECT `+personColumns+` FROM persons WHERE username = ?`, username))
}

// GetPersonBySetupCodeHash resolves a setup code hash to its person.
func (db *DB) GetPersonBySetupCodeHash(ctx context.Context, hash string) (model.Person, error) {
	if hash == "" {
		return model.Person{}, ErrNotFound
	}
	return scanPerson(db.sql.QueryRowContext(ctx, `SELECT `+personColumns+` FROM persons WHERE setup_code_hash = ?`, hash))
}

// ListPersons returns every person ordered by username.
func (db *DB) ListPersons(ctx context.Context) ([]model.Person, error) {
	rows, err := db.sql.QueryContext(ctx, `SELECT `+personColumns+` FROM persons ORDER BY username ASC`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []model.Person{}
	for rows.Next() {
		p, err := scanPerson(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, mapErr(rows.Err())
}

// CountActiveSupervisors counts active people with the supervisor flag.
func (db *DB) CountActiveSupervisors(ctx context.Context) (int, error) {
	var n int
	err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM persons WHERE supervisor = 1 AND status = ?`, string(model.PersonActive)).Scan(&n)
	return n, mapErr(err)
}

// GetPersonAuth returns the authentication state of a person.
func (db *DB) GetPersonAuth(ctx context.Context, id string) (PersonAuth, error) {
	var (
		a                    PersonAuth
		setupExpires, locked *int64
	)
	err := db.sql.QueryRowContext(ctx,
		`SELECT password_hash, totp_secret_enc, totp_last_step, setup_code_hash, setup_expires_at, failed_logins, locked_until
		 FROM persons WHERE id = ?`, id).
		Scan(&a.PasswordHash, &a.TOTPSecretEnc, &a.TOTPLastStep, &a.SetupCodeHash, &setupExpires, &a.FailedLogins, &locked)
	if err != nil {
		return PersonAuth{}, mapErr(err)
	}
	a.SetupExpiresAt = timePtr(setupExpires)
	a.LockedUntil = timePtr(locked)
	return a, nil
}

// UpdatePersonDisplayName changes the display name.
func (db *DB) UpdatePersonDisplayName(ctx context.Context, id, displayName string, now time.Time) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE persons SET display_name = ?, updated_at = ? WHERE id = ?`, displayName, toMillis(now), id)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// otherActiveSupervisor is a SQL condition that holds when an active
// supervisor other than the row being updated exists. Using it inside the
// UPDATE itself makes the last-supervisor guard atomic.
const otherActiveSupervisor = `EXISTS (SELECT 1 FROM persons o WHERE o.id <> persons.id AND o.supervisor = 1 AND o.status = 'active')`

// SetPersonAuthority sets a person's status (active or suspended) and
// supervisor flag in one atomic statement.
//
//   - ErrLastSupervisor: the change would leave no active supervisor.
//   - ErrConflict: status active was requested for a person who never
//     finished setup (only setup activates; use ResetPersonSetup instead).
//
// Any status other than active deletes the person's sessions.
func (db *DB) SetPersonAuthority(ctx context.Context, id string, status model.PersonStatus, supervisor bool, now time.Time) error {
	if status != model.PersonActive && status != model.PersonSuspended {
		return errors.New("store: status must be active or suspended")
	}
	return db.withTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`UPDATE persons SET status = ?, supervisor = ?, updated_at = ?
			 WHERE id = ?
			   AND (? <> 'active' OR (status <> 'pending' AND password_hash <> '' AND totp_secret_enc <> ''))
			   AND (NOT (supervisor = 1 AND status = 'active')
			        OR (? = 1 AND ? = 'active')
			        OR `+otherActiveSupervisor+`)`,
			string(status), boolInt(supervisor), toMillis(now),
			id,
			string(status),
			boolInt(supervisor), string(status))
		if err != nil {
			return mapErr(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return db.explainAuthorityRefusal(ctx, tx, id)
		}
		if status != model.PersonActive {
			if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE person_id = ?`, id); err != nil {
				return mapErr(err)
			}
		}
		return nil
	})
}

// explainAuthorityRefusal turns "no row updated" into a precise error.
func (db *DB) explainAuthorityRefusal(ctx context.Context, tx *sql.Tx, id string) error {
	var status string
	var supervisor int
	err := tx.QueryRowContext(ctx, `SELECT status, supervisor FROM persons WHERE id = ?`, id).Scan(&status, &supervisor)
	if err != nil {
		return mapErr(err)
	}
	if supervisor == 1 && status == string(model.PersonActive) {
		return ErrLastSupervisor
	}
	return ErrConflict
}

// ResetPersonSetup puts a person back into pending with a new setup code,
// erasing the password, TOTP secret, lockout state and all sessions. With
// guard set it refuses (ErrLastSupervisor) to reset the last active
// supervisor; local recovery passes guard=false.
// issue records who issued the new setup code.
func (db *DB) ResetPersonSetup(ctx context.Context, id, setupCodeHash string, setupExpiresAt, now time.Time, guard bool, issue model.SetupIssue) error {
	return db.withTx(ctx, func(tx *sql.Tx) error {
		cond := ""
		if guard {
			cond = ` AND (NOT (supervisor = 1 AND status = 'active') OR ` + otherActiveSupervisor + `)`
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE persons SET status = 'pending', password_hash = '', totp_secret_enc = '', totp_last_step = -1,
				approval_mode = 'read', approval_mode_expires_at = NULL,
				setup_code_hash = ?, setup_expires_at = ?, failed_logins = 0, locked_until = NULL, updated_at = ?,
				setup_issued_by = ?, setup_issued_by_name = ?, setup_issued_kind = ?, setup_issued_at = ?
			 WHERE id = ?`+cond,
			setupCodeHash, toMillis(setupExpiresAt), toMillis(now),
			issue.ByID, issue.ByName, issue.Kind, toMillis(now), id)
		if err != nil {
			return mapErr(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return db.explainAuthorityRefusal(ctx, tx, id)
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE person_id = ?`, id)
		return mapErr(err)
	})
}

// SetPendingSupervisorFlag sets the supervisor flag of a person who is still
// pending. It returns ErrConflict when the person is no longer pending (they
// finished setup in the meantime); the caller then goes through
// SetPersonAuthority, which carries the last-supervisor guard.
func (db *DB) SetPendingSupervisorFlag(ctx context.Context, id string, supervisor bool, now time.Time) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE persons SET supervisor = ?, updated_at = ? WHERE id = ? AND status = 'pending'`,
		boolInt(supervisor), toMillis(now), id)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

// SetSupervisorFlag sets the supervisor flag without the last-supervisor
// guard. It is for local recovery only; the API must never call it.
func (db *DB) SetSupervisorFlag(ctx context.Context, id string, supervisor bool, now time.Time) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE persons SET supervisor = ?, updated_at = ? WHERE id = ?`, boolInt(supervisor), toMillis(now), id)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// BeginPersonSetup stores the chosen password hash and a fresh encrypted
// TOTP secret. It only writes while the person is pending, the setup code
// hash still matches and the code has not expired; otherwise ErrConflict.
func (db *DB) BeginPersonSetup(ctx context.Context, id, setupCodeHash, passwordHash, totpSecretEnc string, now time.Time) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE persons SET password_hash = ?, totp_secret_enc = ?, totp_last_step = -1, updated_at = ?
		 WHERE id = ? AND status = 'pending' AND setup_code_hash = ? AND setup_code_hash <> '' AND setup_expires_at > ?`,
		passwordHash, totpSecretEnc, toMillis(now), id, setupCodeHash, toMillis(now))
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

// FinishPersonSetup activates a pending person and consumes the setup code in
// one compare-and-set. It returns ErrConflict when the code was already used,
// replaced or expired, or setup was never begun.
func (db *DB) FinishPersonSetup(ctx context.Context, id, setupCodeHash string, totpStep int64, now time.Time) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE persons SET status = 'active', setup_code_hash = '', setup_expires_at = NULL,
			totp_last_step = ?, failed_logins = 0, locked_until = NULL, updated_at = ?
		 WHERE id = ? AND status = 'pending' AND setup_code_hash = ? AND setup_code_hash <> ''
		   AND setup_expires_at > ? AND password_hash <> '' AND totp_secret_enc <> ''`,
		totpStep, toMillis(now), id, setupCodeHash, toMillis(now))
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

// RecordLoginFailure increments the failure counter and, once it reaches
// threshold, locks the account until now+lockFor and restarts the count.
func (db *DB) RecordLoginFailure(ctx context.Context, id string, now time.Time, threshold int, lockFor time.Duration) error {
	_, err := db.sql.ExecContext(ctx,
		`UPDATE persons SET
			locked_until  = CASE WHEN failed_logins + 1 >= ? THEN ? ELSE locked_until END,
			failed_logins = CASE WHEN failed_logins + 1 >= ? THEN 0 ELSE failed_logins + 1 END
		 WHERE id = ?`,
		threshold, toMillis(now.Add(lockFor)), threshold, id)
	return mapErr(err)
}

// AcceptLogin atomically consumes a TOTP step and records a successful
// login. It returns ErrConflict when that step (or a later one) was already
// used, or the person is no longer active: a replayed or concurrent login.
func (db *DB) AcceptLogin(ctx context.Context, id string, totpStep int64, now time.Time) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE persons SET totp_last_step = ?, failed_logins = 0, locked_until = NULL, last_login_at = ?
		 WHERE id = ? AND status = 'active' AND totp_last_step < ?`,
		totpStep, toMillis(now), id, totpStep)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

func affectedOrConflict(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return mapErr(err)
	}
	if n == 0 {
		return ErrConflict
	}
	return nil
}

// ---- sessions ----

// CreateSession stores a new session, but only while the person is active.
// The check is part of the INSERT, so a session can never be created after a
// suspend or reset has committed. It returns ErrConflict otherwise.
func (db *DB) CreateSession(ctx context.Context, s Session) error {
	res, err := db.sql.ExecContext(ctx,
		`INSERT INTO sessions(token_hash, person_id, csrf_token, created_at, last_seen_at, expires_at)
		 SELECT ?, ?, ?, ?, ?, ?
		 WHERE EXISTS (SELECT 1 FROM persons WHERE id = ? AND status = 'active')`,
		s.TokenHash, s.PersonID, s.CSRFToken, toMillis(s.CreatedAt), toMillis(s.LastSeenAt), toMillis(s.ExpiresAt),
		s.PersonID)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

// AnyTOTPSecret returns one stored encrypted TOTP secret with its person ID,
// or ErrNotFound. It is used to prove the vault key.
func (db *DB) AnyTOTPSecret(ctx context.Context) (personID, encrypted string, err error) {
	err = db.sql.QueryRowContext(ctx,
		`SELECT id, totp_secret_enc FROM persons WHERE totp_secret_enc <> '' ORDER BY id LIMIT 1`).Scan(&personID, &encrypted)
	return personID, encrypted, mapErr(err)
}

// GetSession returns a session by cookie hash.
func (db *DB) GetSession(ctx context.Context, tokenHash string) (Session, error) {
	var (
		s                         Session
		created, lastSeen, expiry int64
	)
	err := db.sql.QueryRowContext(ctx,
		`SELECT token_hash, person_id, csrf_token, created_at, last_seen_at, expires_at FROM sessions WHERE token_hash = ?`, tokenHash).
		Scan(&s.TokenHash, &s.PersonID, &s.CSRFToken, &created, &lastSeen, &expiry)
	if err != nil {
		return Session{}, mapErr(err)
	}
	s.CreatedAt, s.LastSeenAt, s.ExpiresAt = fromMillis(created), fromMillis(lastSeen), fromMillis(expiry)
	return s, nil
}

// TouchSession records activity on a session.
func (db *DB) TouchSession(ctx context.Context, tokenHash string, now time.Time) error {
	_, err := db.sql.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?`, toMillis(now), tokenHash)
	return mapErr(err)
}

// DeleteSession removes one session (logout).
func (db *DB) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return mapErr(err)
}

// DeletePersonSessions removes every session of a person.
func (db *DB) DeletePersonSessions(ctx context.Context, personID string) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM sessions WHERE person_id = ?`, personID)
	return mapErr(err)
}

// DeleteStaleSessions removes sessions past their absolute expiry or idle
// for longer than idle.
func (db *DB) DeleteStaleSessions(ctx context.Context, now time.Time, idle time.Duration) error {
	_, err := db.sql.ExecContext(ctx,
		`DELETE FROM sessions WHERE expires_at <= ? OR last_seen_at <= ?`, toMillis(now), toMillis(now.Add(-idle)))
	return mapErr(err)
}

// ---- role bindings ----

const bindingColumns = `person_id, provider_id, role, created_by, created_at, updated_at`

func scanBinding(row rowScanner) (model.RoleBinding, error) {
	var (
		b                model.RoleBinding
		created, updated int64
	)
	if err := row.Scan(&b.PersonID, &b.ProviderID, &b.Role, &b.CreatedBy, &created, &updated); err != nil {
		return model.RoleBinding{}, mapErr(err)
	}
	b.CreatedAt, b.UpdatedAt = fromMillis(created), fromMillis(updated)
	return b, nil
}

// PutBinding creates or replaces a person's role on a cloud account.
func (db *DB) PutBinding(ctx context.Context, b model.RoleBinding) error {
	if !b.Role.Valid() {
		return errors.New("store: invalid role")
	}
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO role_bindings(`+bindingColumns+`) VALUES(?, ?, ?, ?, ?, ?)
		 ON CONFLICT(person_id, provider_id) DO UPDATE SET role = excluded.role, updated_at = excluded.updated_at`,
		b.PersonID, b.ProviderID, string(b.Role), b.CreatedBy, toMillis(b.CreatedAt), toMillis(b.UpdatedAt))
	return mapErr(err)
}

// GetBinding returns a person's role binding on a cloud account, or
// ErrNotFound when the person has no access to it.
func (db *DB) GetBinding(ctx context.Context, personID, providerID string) (model.RoleBinding, error) {
	return scanBinding(db.sql.QueryRowContext(ctx,
		`SELECT `+bindingColumns+` FROM role_bindings WHERE person_id = ? AND provider_id = ?`, personID, providerID))
}

// DeleteBinding removes a binding; ErrNotFound when it does not exist.
func (db *DB) DeleteBinding(ctx context.Context, personID, providerID string) error {
	res, err := db.sql.ExecContext(ctx,
		`DELETE FROM role_bindings WHERE person_id = ? AND provider_id = ?`, personID, providerID)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// ListBindings returns bindings filtered by person and/or cloud account;
// empty filters match everything.
func (db *DB) ListBindings(ctx context.Context, personID, providerID string) ([]model.RoleBinding, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+bindingColumns+` FROM role_bindings
		 WHERE (? = '' OR person_id = ?) AND (? = '' OR provider_id = ?)
		 ORDER BY provider_id ASC, person_id ASC`,
		personID, personID, providerID, providerID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []model.RoleBinding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, mapErr(rows.Err())
}

// SetApprovalMode stores a person's approval mode. It only writes while the
// person is active (ErrConflict otherwise).
func (db *DB) SetApprovalMode(ctx context.Context, personID string, mode model.ApprovalMode, expiresAt *time.Time, now time.Time) error {
	if !mode.Valid() {
		return errors.New("store: invalid approval mode")
	}
	res, err := db.sql.ExecContext(ctx,
		`UPDATE persons SET approval_mode = ?, approval_mode_expires_at = ?, updated_at = ?
		 WHERE id = ? AND status = 'active'`,
		string(mode), millisPtr(expiresAt), toMillis(now), personID)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

// SetProviderMaxAutoLevel stores a cloud account's highest automatic level.
func (db *DB) SetProviderMaxAutoLevel(ctx context.Context, providerID string, level model.ApprovalMode, now time.Time) error {
	if !level.Valid() {
		return errors.New("store: invalid automatic level")
	}
	res, err := db.sql.ExecContext(ctx,
		`UPDATE providers SET max_auto_level = ?, updated_at = ? WHERE id = ?`, string(level), toMillis(now), providerID)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}
