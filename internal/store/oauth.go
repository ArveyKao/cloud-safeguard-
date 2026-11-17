package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Remote MCP sign-in (CONTRACT §17.10): registered OAuth clients, the
// connection requests a person approves in the console, and the one-time
// links through which an MCP agent picks up a credential.

// OAuthClient is a dynamically registered public client. Registering grants
// nothing; it only names the client and fixes where codes may be sent.
type OAuthClient struct {
	ID           string
	ClientName   string
	RedirectURIs []string
	RemoteAddr   string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

const oauthClientColumns = `id, client_name, redirect_uris, remote_addr, created_at, last_used_at`

func scanOAuthClient(row rowScanner) (OAuthClient, error) {
	var (
		c       OAuthClient
		uris    string
		created int64
		used    *int64
	)
	if err := row.Scan(&c.ID, &c.ClientName, &uris, &c.RemoteAddr, &created, &used); err != nil {
		return OAuthClient{}, mapErr(err)
	}
	if err := json.Unmarshal([]byte(uris), &c.RedirectURIs); err != nil {
		return OAuthClient{}, errors.New("store: unreadable redirect URIs")
	}
	c.CreatedAt, c.LastUsedAt = fromMillis(created), timePtr(used)
	return c, nil
}

// ErrOAuthLimit is returned when too many unused registrations or open
// connection requests exist.
var ErrOAuthLimit = errors.New("store: too many open OAuth registrations or requests")

// CreateOAuthClient stores a registration unless too many clients that
// were never used were registered since `since`: at most maxTotal overall
// and maxPerAddr from one address. The limits are part of the INSERT.
func (db *DB) CreateOAuthClient(ctx context.Context, c OAuthClient, since time.Time, maxTotal, maxPerAddr int) error {
	uris, err := marshalJSON(c.RedirectURIs, "[]")
	if err != nil {
		return err
	}
	res, err := db.sql.ExecContext(ctx,
		`INSERT INTO oauth_clients(id, client_name, redirect_uris, remote_addr, created_at)
		 SELECT ?, ?, ?, ?, ?
		 WHERE (SELECT COUNT(*) FROM oauth_clients WHERE last_used_at IS NULL AND created_at > ?) < ?
		   AND (SELECT COUNT(*) FROM oauth_clients WHERE last_used_at IS NULL AND created_at > ? AND remote_addr = ?) < ?`,
		c.ID, c.ClientName, uris, c.RemoteAddr, toMillis(c.CreatedAt),
		toMillis(since), maxTotal, toMillis(since), c.RemoteAddr, maxPerAddr)
	if err != nil {
		return mapErr(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrOAuthLimit
	}
	return nil
}

// GetOAuthClient returns a registered client.
func (db *DB) GetOAuthClient(ctx context.Context, id string) (OAuthClient, error) {
	return scanOAuthClient(db.sql.QueryRowContext(ctx, `SELECT `+oauthClientColumns+` FROM oauth_clients WHERE id = ?`, id))
}

// DeleteUnusedOAuthClients removes registrations made before cutoff that
// never led to a connection, and registrations last used before usedCutoff
// that no kept request refers to. A client whose registration is gone
// registers again on its next sign-in; connected agents are not affected.
func (db *DB) DeleteUnusedOAuthClients(ctx context.Context, cutoff, usedCutoff time.Time) error {
	_, err := db.sql.ExecContext(ctx,
		`DELETE FROM oauth_clients
		 WHERE (last_used_at IS NULL AND created_at <= ?)
		    OR (last_used_at IS NOT NULL AND last_used_at <= ?
		        AND NOT EXISTS (SELECT 1 FROM oauth_requests WHERE client_id = oauth_clients.id))`,
		toMillis(cutoff), toMillis(usedCutoff))
	return mapErr(err)
}

// OAuthRequest is one authorization request, from the client's redirect to
// the console until its code is exchanged. Status is pending, approved,
// denied or consumed. Only the hash of the authorization code is stored.
type OAuthRequest struct {
	ID string
	// ConnectHash is the hash of the key in the console link; the key is an
	// approval secret while the request is pending.
	ConnectHash   string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	State         string
	Status        model.SignInStatus
	PersonID      string
	AgentName     string
	CodeHash      string
	AgentID       string
	RemoteAddr    string
	// Issuer is the authorization server's origin as the client saw it at
	// /oauth/authorize; the redirect after the decision carries it as iss.
	Issuer    string
	CreatedAt time.Time
	// ExpiresAt is when the request expires while pending, and when the
	// authorization code expires once approved.
	ExpiresAt time.Time
	DecidedAt *time.Time
}

const oauthRequestColumns = `id, connect_hash, client_id, redirect_uri, code_challenge, state, status, person_id, agent_name,
	code_hash, agent_id, remote_addr, issuer, created_at, expires_at, decided_at`

func scanOAuthRequest(row rowScanner) (OAuthRequest, error) {
	var (
		r                OAuthRequest
		created, expires int64
		decided          *int64
	)
	if err := row.Scan(&r.ID, &r.ConnectHash, &r.ClientID, &r.RedirectURI, &r.CodeChallenge, &r.State, &r.Status, &r.PersonID,
		&r.AgentName, &r.CodeHash, &r.AgentID, &r.RemoteAddr, &r.Issuer, &created, &expires, &decided); err != nil {
		return OAuthRequest{}, mapErr(err)
	}
	r.CreatedAt, r.ExpiresAt, r.DecidedAt = fromMillis(created), fromMillis(expires), timePtr(decided)
	return r, nil
}

// CreateOAuthRequest stores a pending request unless too many are already
// waiting (maxTotal overall, maxPerAddr from one address).
func (db *DB) CreateOAuthRequest(ctx context.Context, r OAuthRequest, maxTotal, maxPerAddr int) error {
	res, err := db.sql.ExecContext(ctx,
		`INSERT INTO oauth_requests(id, connect_hash, client_id, redirect_uri, code_challenge, state, status, remote_addr, issuer, created_at, expires_at)
		 SELECT ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?
		 WHERE (SELECT COUNT(*) FROM oauth_requests WHERE status = 'pending' AND expires_at > ?) < ?
		   AND (SELECT COUNT(*) FROM oauth_requests WHERE status = 'pending' AND expires_at > ? AND remote_addr = ?) < ?`,
		r.ID, r.ConnectHash, r.ClientID, r.RedirectURI, r.CodeChallenge, r.State, r.RemoteAddr, r.Issuer, toMillis(r.CreatedAt), toMillis(r.ExpiresAt),
		toMillis(r.CreatedAt), maxTotal, toMillis(r.CreatedAt), r.RemoteAddr, maxPerAddr)
	if err != nil {
		return mapErr(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrOAuthLimit
	}
	return nil
}

// GetOAuthRequest returns a request by ID.
func (db *DB) GetOAuthRequest(ctx context.Context, id string) (OAuthRequest, error) {
	return scanOAuthRequest(db.sql.QueryRowContext(ctx, `SELECT `+oauthRequestColumns+` FROM oauth_requests WHERE id = ?`, id))
}

// GetOAuthRequestByConnectHash returns a request by the hash of the key in
// its console link.
func (db *DB) GetOAuthRequestByConnectHash(ctx context.Context, hash string) (OAuthRequest, error) {
	return scanOAuthRequest(db.sql.QueryRowContext(ctx,
		`SELECT `+oauthRequestColumns+` FROM oauth_requests WHERE connect_hash = ?`, hash))
}

// GetOAuthRequestByCodeHash returns an approved request by the hash of its
// authorization code.
func (db *DB) GetOAuthRequestByCodeHash(ctx context.Context, hash string) (OAuthRequest, error) {
	if hash == "" {
		return OAuthRequest{}, ErrNotFound
	}
	return scanOAuthRequest(db.sql.QueryRowContext(ctx,
		`SELECT `+oauthRequestColumns+` FROM oauth_requests WHERE code_hash = ?`, hash))
}

// ApproveOAuthRequest records an approval with the agent name and the hash
// of the authorization code, which expires at codeExpires. DenyOAuthRequest
// records a denial. Both are compare-and-sets: they write only while the
// request is pending and unexpired and the person is active; ErrConflict
// otherwise.
func (db *DB) ApproveOAuthRequest(ctx context.Context, id, personID, agentName, codeHash string, codeExpires, now time.Time) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE oauth_requests SET status = 'approved', person_id = ?, agent_name = ?, code_hash = ?, expires_at = ?, decided_at = ?
		 WHERE id = ? AND status = 'pending' AND expires_at > ?
		   AND EXISTS (SELECT 1 FROM persons WHERE id = ? AND status = 'active')`,
		personID, agentName, codeHash, toMillis(codeExpires), toMillis(now), id, toMillis(now), personID)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

// DenyOAuthRequest: see ApproveOAuthRequest.
func (db *DB) DenyOAuthRequest(ctx context.Context, id, personID string, now time.Time) error {
	res, err := db.sql.ExecContext(ctx,
		`UPDATE oauth_requests SET status = 'denied', person_id = ?, decided_at = ?
		 WHERE id = ? AND status = 'pending' AND expires_at > ?
		   AND EXISTS (SELECT 1 FROM persons WHERE id = ? AND status = 'active')`,
		personID, toMillis(now), id, toMillis(now), personID)
	if err != nil {
		return mapErr(err)
	}
	return affectedOrConflict(res)
}

// BurnOAuthCode makes an approved request's code unusable, after an
// exchange attempt that failed its checks.
func (db *DB) BurnOAuthCode(ctx context.Context, id string) error {
	_, err := db.sql.ExecContext(ctx,
		`UPDATE oauth_requests SET status = 'denied', code_hash = '' WHERE id = ? AND status = 'approved'`, id)
	return mapErr(err)
}

// ConsumeOAuthCode exchanges an approved request's code for an agent, in
// one transaction:
//
//  1. it marks the request consumed, as a compare-and-set (still approved,
//     code unexpired, approver still active), so a code works at most once;
//  2. it revokes the approver's earlier agents with the same name;
//  3. it inserts agent with the approver as owner and agent name;
//  4. it records that the client was used.
//
// It returns the stored agent and the IDs of the replaced agents, or
// ErrConflict when the code cannot be exchanged (anymore).
func (db *DB) ConsumeOAuthCode(ctx context.Context, requestID string, agent model.Agent, tokenHash string, now time.Time) (model.Agent, []string, error) {
	var replaced []string
	err := db.withTx(ctx, func(tx *sql.Tx) error {
		var ownerID, name, clientID string
		err := tx.QueryRowContext(ctx,
			`UPDATE oauth_requests SET status = 'consumed', agent_id = ?, code_hash = ''
			 WHERE id = ? AND status = 'approved' AND expires_at > ?
			   AND EXISTS (SELECT 1 FROM persons WHERE id = oauth_requests.person_id AND status = 'active')
			 RETURNING person_id, agent_name, client_id`,
			agent.ID, requestID, toMillis(now)).Scan(&ownerID, &name, &clientID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return mapErr(err)
		}
		if ownerID == "" || name == "" {
			return ErrConflict
		}
		if _, err := tx.ExecContext(ctx, `UPDATE oauth_clients SET last_used_at = ? WHERE id = ?`, toMillis(now), clientID); err != nil {
			return mapErr(err)
		}
		agent.OwnerID, agent.Name = ownerID, name
		replaced, err = replaceOwnedAgent(ctx, tx, agent, tokenHash, now)
		return err
	})
	if err != nil {
		return model.Agent{}, nil, err
	}
	return agent, replaced, nil
}

// DeleteOldOAuthRequests removes requests that expired before cutoff.
func (db *DB) DeleteOldOAuthRequests(ctx context.Context, cutoff time.Time) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM oauth_requests WHERE expires_at <= ?`, toMillis(cutoff))
	return mapErr(err)
}

// CreateCredentialLink stores a one-time credential link (by the hash of
// its token) unless the agent already has maxOpen unused, unexpired links.
func (db *DB) CreateCredentialLink(ctx context.Context, tokenHash, leaseID, agentID string, now, expires time.Time, maxOpen int) error {
	res, err := db.sql.ExecContext(ctx,
		`INSERT INTO credential_links(token_hash, lease_id, agent_id, created_at, expires_at)
		 SELECT ?, ?, ?, ?, ?
		 WHERE (SELECT COUNT(*) FROM credential_links WHERE agent_id = ? AND used_at IS NULL AND expires_at > ?) < ?`,
		tokenHash, leaseID, agentID, toMillis(now), toMillis(expires), agentID, toMillis(now), maxOpen)
	if err != nil {
		return mapErr(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrOAuthLimit
	}
	return nil
}

// UseCredentialLink marks a link used, as a compare-and-set (unused and
// unexpired), and returns its lease and agent. ErrNotFound when the link
// is unknown, used or expired.
func (db *DB) UseCredentialLink(ctx context.Context, tokenHash string, now time.Time) (leaseID, agentID string, err error) {
	err = db.sql.QueryRowContext(ctx,
		`UPDATE credential_links SET used_at = ?
		 WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
		 RETURNING lease_id, agent_id`,
		toMillis(now), tokenHash, toMillis(now)).Scan(&leaseID, &agentID)
	return leaseID, agentID, mapErr(err)
}

// DeleteOldCredentialLinks removes links that expired before cutoff.
func (db *DB) DeleteOldCredentialLinks(ctx context.Context, cutoff time.Time) error {
	_, err := db.sql.ExecContext(ctx, `DELETE FROM credential_links WHERE expires_at <= ?`, toMillis(cutoff))
	return mapErr(err)
}
