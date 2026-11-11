package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// rowScanner is satisfied by *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// ================= Providers =================

const providerColumns = `id, name, type, mode, region, role_arn, access_key_id_masked,
	status, last_tested_at, last_test_ok, created_at, updated_at`

// scanProvider scans one provider row (credential blob excluded).
func scanProvider(row rowScanner) (model.Provider, error) {
	var (
		p            model.Provider
		lastTestedAt *int64
		lastTestOK   *int64
		createdAt    int64
		updatedAt    int64
	)
	err := row.Scan(
		&p.ID, &p.Name, &p.Type, &p.Mode, &p.Region, &p.RoleARN,
		&p.AccessKeyIDMasked, &p.Status, &lastTestedAt, &lastTestOK,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return model.Provider{}, mapErr(err)
	}
	p.LastTestedAt = timePtr(lastTestedAt)
	p.LastTestOK = intPtrBool(lastTestOK)
	p.CreatedAt = fromMillis(createdAt)
	p.UpdatedAt = fromMillis(updatedAt)
	return p, nil
}

// CreateProvider persists a provider and its encrypted broker credential.
func (db *DB) CreateProvider(ctx context.Context, p model.Provider, encryptedCredential string) error {
	_, err := db.sql.ExecContext(ctx,
		`INSERT INTO providers(`+providerColumns+`, encrypted_credential)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.Name, string(p.Type), string(p.Mode), p.Region, p.RoleARN,
		p.AccessKeyIDMasked, string(p.Status),
		millisPtr(p.LastTestedAt), boolPtrInt(p.LastTestOK),
		toMillis(p.CreatedAt), toMillis(p.UpdatedAt),
		encryptedCredential,
	)
	return mapErr(err)
}

// GetProvider returns a provider by ID without its credential blob.
func (db *DB) GetProvider(ctx context.Context, id string) (model.Provider, error) {
	row := db.sql.QueryRowContext(ctx, `SELECT `+providerColumns+` FROM providers WHERE id = ?`, id)
	return scanProvider(row)
}

// ListProviders returns all providers ordered by creation time (the provider
// selection rule in the lease flow relies on this order).
func (db *DB) ListProviders(ctx context.Context) ([]model.Provider, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+providerColumns+` FROM providers ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	out := make([]model.Provider, 0, 4)
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

// UpdateProvider updates the mutable provider fields (not the credential blob).
func (db *DB) UpdateProvider(ctx context.Context, p model.Provider) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE providers SET name = ?, region = ?, role_arn = ?, access_key_id_masked = ?,
			status = ?, last_tested_at = ?, last_test_ok = ?, updated_at = ?
		 WHERE id = ?`,
		p.Name, p.Region, p.RoleARN, p.AccessKeyIDMasked, string(p.Status),
		millisPtr(p.LastTestedAt), boolPtrInt(p.LastTestOK), toMillis(p.UpdatedAt), p.ID,
	)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// UpdateProviderCredential replaces the encrypted broker credential blob.
func (db *DB) UpdateProviderCredential(ctx context.Context, id, encryptedCredential string) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE providers SET encrypted_credential = ? WHERE id = ?`, encryptedCredential, id)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// GetProviderCredential returns the encrypted broker credential blob.
func (db *DB) GetProviderCredential(ctx context.Context, id string) (string, error) {
	var blob string
	err := db.sql.QueryRowContext(ctx, `SELECT encrypted_credential FROM providers WHERE id = ?`, id).Scan(&blob)
	if err != nil {
		return "", mapErr(err)
	}
	if blob == "" {
		return "", ErrNotFound
	}
	return blob, nil
}

// CountProviderCredentials counts providers that hold an encrypted credential.
func (db *DB) CountProviderCredentials(ctx context.Context) (int, error) {
	var n int
	err := db.sql.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM providers WHERE encrypted_credential <> ''`).Scan(&n)
	if err != nil {
		return 0, mapErr(err)
	}
	return n, nil
}

// ================= Capabilities =================

const capabilityColumns = `id, name, description, provider_type, risk, access, policy_template,
	params_json, default_ttl_seconds, max_ttl_seconds, enabled, builtin, created_at, updated_at`

// scanCapability scans one capability row.
func scanCapability(row rowScanner) (model.Capability, error) {
	var (
		c          model.Capability
		paramsJSON string
		enabled    int
		builtin    int
		createdAt  int64
		updatedAt  int64
	)
	err := row.Scan(
		&c.ID, &c.Name, &c.Description, &c.ProviderType, &c.Risk, &c.Access, &c.PolicyTemplate,
		&paramsJSON, &c.DefaultTTLSeconds, &c.MaxTTLSeconds, &enabled, &builtin,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return model.Capability{}, mapErr(err)
	}
	c.Enabled = intBool(enabled)
	c.Builtin = intBool(builtin)
	c.CreatedAt = fromMillis(createdAt)
	c.UpdatedAt = fromMillis(updatedAt)
	if paramsJSON != "" {
		if err := json.Unmarshal([]byte(paramsJSON), &c.Params); err != nil {
			return model.Capability{}, fmt.Errorf("store: corrupt capability params for %s: %w", c.ID, err)
		}
	}
	return c, nil
}

// CreateCapability persists a capability.
func (db *DB) CreateCapability(ctx context.Context, c model.Capability) error {
	paramsJSON, err := marshalJSON(c.Params, "[]")
	if err != nil {
		return err
	}
	_, err = db.sql.ExecContext(ctx,
		`INSERT INTO capabilities(`+capabilityColumns+`)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.Description, string(c.ProviderType), string(c.Risk), string(c.Access),
		c.PolicyTemplate, paramsJSON, c.DefaultTTLSeconds, c.MaxTTLSeconds,
		boolInt(c.Enabled), boolInt(c.Builtin),
		toMillis(c.CreatedAt), toMillis(c.UpdatedAt),
	)
	return mapErr(err)
}

// GetCapability returns a capability by ID.
func (db *DB) GetCapability(ctx context.Context, id string) (model.Capability, error) {
	row := db.sql.QueryRowContext(ctx, `SELECT `+capabilityColumns+` FROM capabilities WHERE id = ?`, id)
	return scanCapability(row)
}

// ListCapabilities returns all capabilities ordered by creation time.
func (db *DB) ListCapabilities(ctx context.Context) ([]model.Capability, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+capabilityColumns+` FROM capabilities ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	out := make([]model.Capability, 0, 8)
	for rows.Next() {
		c, err := scanCapability(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

// UpdateCapability updates all mutable capability fields.
func (db *DB) UpdateCapability(ctx context.Context, c model.Capability) error {
	paramsJSON, err := marshalJSON(c.Params, "[]")
	if err != nil {
		return err
	}
	res, err := db.sql.ExecContext(ctx,
		`UPDATE capabilities SET name = ?, description = ?, provider_type = ?, risk = ?,
			access = ?, policy_template = ?, params_json = ?, default_ttl_seconds = ?,
			max_ttl_seconds = ?, enabled = ?, builtin = ?, updated_at = ?
		 WHERE id = ?`,
		c.Name, c.Description, string(c.ProviderType), string(c.Risk), string(c.Access),
		c.PolicyTemplate, paramsJSON, c.DefaultTTLSeconds, c.MaxTTLSeconds,
		boolInt(c.Enabled), boolInt(c.Builtin),
		toMillis(c.UpdatedAt), c.ID,
	)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// ================= Agents =================

const agentColumns = `id, name, description, status, role, grants_json, max_ttl_seconds,
	max_concurrent_leases, token_prefix, last_seen_at, created_at, updated_at, owner_id`

// scanAgent scans one agent row (token hash excluded).
func scanAgent(row rowScanner) (model.Agent, error) {
	var (
		a          model.Agent
		grantsJSON string
		lastSeenAt *int64
		createdAt  int64
		updatedAt  int64
	)
	err := row.Scan(
		&a.ID, &a.Name, &a.Description, &a.Status, &a.Role, &grantsJSON, &a.MaxTTLSeconds,
		&a.MaxConcurrentLeases, &a.TokenPrefix, &lastSeenAt, &createdAt, &updatedAt, &a.OwnerID,
	)
	if err != nil {
		return model.Agent{}, mapErr(err)
	}
	a.LastSeenAt = timePtr(lastSeenAt)
	a.CreatedAt = fromMillis(createdAt)
	a.UpdatedAt = fromMillis(updatedAt)
	if grantsJSON != "" {
		if err := json.Unmarshal([]byte(grantsJSON), &a.Grants); err != nil {
			return model.Agent{}, fmt.Errorf("store: corrupt agent grants for %s: %w", a.ID, err)
		}
	}
	if a.Grants == nil {
		a.Grants = []string{}
	}
	return a, nil
}

// execer is satisfied by *sql.DB and *sql.Tx.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// CreateAgent persists an agent together with its bearer token hash.
func (db *DB) CreateAgent(ctx context.Context, a model.Agent, tokenHash string) error {
	return insertAgent(ctx, db.sql, a, tokenHash)
}

func insertAgent(ctx context.Context, x execer, a model.Agent, tokenHash string) error {
	grantsJSON, err := marshalJSON(a.Grants, "[]")
	if err != nil {
		return err
	}
	_, err = x.ExecContext(ctx,
		`INSERT INTO agents(id, name, description, status, role, grants_json, max_ttl_seconds,
			max_concurrent_leases, token_hash, token_prefix, last_seen_at, created_at, updated_at, owner_id)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.Name, a.Description, string(a.Status), string(a.Role), grantsJSON, a.MaxTTLSeconds,
		a.MaxConcurrentLeases, tokenHash, a.TokenPrefix, millisPtr(a.LastSeenAt),
		toMillis(a.CreatedAt), toMillis(a.UpdatedAt), a.OwnerID,
	)
	return mapErr(err)
}

// ListAgentsByOwner returns the agents owned by a person, oldest first.
func (db *DB) ListAgentsByOwner(ctx context.Context, ownerID string) ([]model.Agent, error) {
	if ownerID == "" {
		return []model.Agent{}, nil
	}
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+agentColumns+` FROM agents WHERE owner_id = ? ORDER BY created_at ASC, id ASC`, ownerID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []model.Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, mapErr(rows.Err())
}

// GetAgent returns an agent by ID.
func (db *DB) GetAgent(ctx context.Context, id string) (model.Agent, error) {
	row := db.sql.QueryRowContext(ctx, `SELECT `+agentColumns+` FROM agents WHERE id = ?`, id)
	return scanAgent(row)
}

// GetAgentByTokenHash resolves a bearer token hash to an agent.
func (db *DB) GetAgentByTokenHash(ctx context.Context, tokenHash string) (model.Agent, error) {
	row := db.sql.QueryRowContext(ctx, `SELECT `+agentColumns+` FROM agents WHERE token_hash = ?`, tokenHash)
	return scanAgent(row)
}

// ListAgents returns all agents ordered by creation time.
func (db *DB) ListAgents(ctx context.Context) ([]model.Agent, error) {
	rows, err := db.sql.QueryContext(ctx,
		`SELECT `+agentColumns+` FROM agents ORDER BY created_at ASC, id ASC`)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	out := make([]model.Agent, 0, 8)
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

// UpdateAgent updates the mutable agent fields (not the token hash).
func (db *DB) UpdateAgent(ctx context.Context, a model.Agent) error {
	grantsJSON, err := marshalJSON(a.Grants, "[]")
	if err != nil {
		return err
	}
	res, err := db.sql.ExecContext(ctx,
		`UPDATE agents SET name = ?, description = ?, status = ?, role = ?, grants_json = ?,
			max_ttl_seconds = ?, max_concurrent_leases = ?, token_prefix = ?,
			last_seen_at = ?, updated_at = ?
		 WHERE id = ?`,
		a.Name, a.Description, string(a.Status), string(a.Role), grantsJSON, a.MaxTTLSeconds,
		a.MaxConcurrentLeases, a.TokenPrefix, millisPtr(a.LastSeenAt), toMillis(a.UpdatedAt), a.ID,
	)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// UpdateAgentTokenHash replaces the stored bearer token hash.
func (db *DB) UpdateAgentTokenHash(ctx context.Context, id, tokenHash string) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE agents SET token_hash = ? WHERE id = ?`, tokenHash, id)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// TouchAgentSeen records the agent's last activity time.
func (db *DB) TouchAgentSeen(ctx context.Context, id string, at time.Time) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE agents SET last_seen_at = ? WHERE id = ?`, toMillis(at), id)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrNotFound(res)
}

// affectedOrNotFound converts an UPDATE with zero affected rows into ErrNotFound.
func affectedOrNotFound(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
