package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

const (
	// auditChainTag prefixes the bytes hashed for every audit event.
	auditChainTag = "csg-audit-v1\n"
	// auditGenesisHash is the fixed prev_hash of the first event.
	auditGenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
	// auditIDPrefix is the identifier prefix for audit events.
	auditIDPrefix = "evt_"
)

// auditCanonical is the exact object form hashed by the audit chain
// (docs/CONTRACT.md §10). Field order is significant: encoding/json marshals
// struct fields in declaration order.
type auditCanonical struct {
	Seq        int64           `json:"seq"`
	Time       string          `json:"time"`
	ActorType  string          `json:"actor_type"`
	ActorID    string          `json:"actor_id"`
	ActorName  string          `json:"actor_name"`
	Action     string          `json:"action"`
	Status     string          `json:"status"`
	Severity   string          `json:"severity"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// canonicalAuditJSON renders the deterministic JSON object hashed for an event.
// Metadata is embedded as raw JSON so byte-identical storage round-trips do not
// depend on re-marshalling decisions.
func canonicalAuditJSON(ev model.AuditEvent, metadataJSON string) ([]byte, error) {
	c := auditCanonical{
		Seq:        ev.Seq,
		Time:       ev.Time.UTC().Format(time.RFC3339Nano),
		ActorType:  ev.ActorType,
		ActorID:    ev.ActorID,
		ActorName:  ev.ActorName,
		Action:     ev.Action,
		Status:     ev.Status,
		Severity:   ev.Severity,
		TargetType: ev.TargetType,
		TargetID:   ev.TargetID,
	}
	if metadataJSON != "" {
		c.Metadata = json.RawMessage(metadataJSON)
	}
	return json.Marshal(c)
}

// auditHash computes hex(SHA-256("csg-audit-v1\n" + prevHash + "\n" + canonical)).
func auditHash(prevHash string, canonical []byte) string {
	h := sha256.New()
	h.Write([]byte(auditChainTag))
	h.Write([]byte(prevHash))
	h.Write([]byte("\n"))
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

// newAuditID returns a random "evt_" identifier.
func newAuditID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("store: generate audit id: %w", err)
	}
	return auditIDPrefix + hex.EncodeToString(buf), nil
}

// AppendAudit assigns Seq/ID/Time when zero, computes the hash chain and
// persists the event, mutating ev in place.
func (db *DB) AppendAudit(ctx context.Context, ev *model.AuditEvent) error {
	if ev == nil {
		return errors.New("store: nil audit event")
	}
	db.appendMu.Lock()
	defer db.appendMu.Unlock()

	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin audit append: %w", err)
	}

	var (
		lastSeq  int64
		lastHash string
	)
	err = tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &lastHash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		lastSeq, lastHash = 0, auditGenesisHash
	case err != nil:
		tx.Rollback()
		return fmt.Errorf("store: read audit tail: %w", err)
	}

	ev.Seq = lastSeq + 1
	if ev.ID == "" {
		ev.ID, err = newAuditID()
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	// Storage granularity is unix milliseconds (SPEC §9); truncating before
	// hashing keeps VerifyAudit able to recompute the exact same canonical form
	// from persisted data.
	ev.Time = ev.Time.UTC().Truncate(time.Millisecond)
	ev.PrevHash = lastHash

	metadataJSON := ""
	if len(ev.Metadata) > 0 {
		raw, err := json.Marshal(ev.Metadata)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("store: marshal audit metadata: %w", err)
		}
		metadataJSON = string(raw)
	}
	canonical, err := canonicalAuditJSON(*ev, metadataJSON)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("store: canonicalize audit event: %w", err)
	}
	ev.Hash = auditHash(lastHash, canonical)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit(seq, id, time_ms, actor_type, actor_id, actor_name, action,
			status, severity, target_type, target_id, metadata_json, prev_hash, hash)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.Seq, ev.ID, toMillis(ev.Time), ev.ActorType, ev.ActorID, ev.ActorName,
		ev.Action, ev.Status, ev.Severity, ev.TargetType, ev.TargetID,
		metadataJSON, ev.PrevHash, ev.Hash,
	); err != nil {
		tx.Rollback()
		return fmt.Errorf("store: insert audit event: %w", mapErr(err))
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit audit event: %w", err)
	}
	return nil
}

// ListAudit returns a filtered page of audit events, newest first.
func (db *DB) ListAudit(ctx context.Context, f AuditFilter) ([]model.AuditEvent, int, error) {
	limit, offset := pageParams(f.Limit, f.Offset)

	var (
		where []string
		args  []any
	)
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	if f.ActorType != "" {
		where = append(where, "actor_type = ?")
		args = append(args, f.ActorType)
	}
	if f.ActorID != "" {
		where = append(where, "actor_id = ?")
		args = append(args, f.ActorID)
	}
	if f.Severity != "" {
		where = append(where, "severity = ?")
		args = append(args, f.Severity)
	}
	if !f.Since.IsZero() {
		where = append(where, "time_ms >= ?")
		args = append(args, toMillis(f.Since))
	}
	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit`+whereSQL, args...).Scan(&total); err != nil {
		return nil, 0, mapErr(err)
	}

	query := `SELECT seq, id, time_ms, actor_type, actor_id, actor_name, action, status,
		severity, target_type, target_id, metadata_json, prev_hash, hash
		FROM audit` + whereSQL + ` ORDER BY seq DESC LIMIT ? OFFSET ?`
	queryArgs := append(append([]any{}, args...), limit, offset)
	rows, err := db.sql.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, mapErr(err)
	}
	defer rows.Close()

	items := make([]model.AuditEvent, 0, minInt(limit, total))
	for rows.Next() {
		ev, err := scanAuditEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, mapErr(err)
	}
	return items, total, nil
}

// scanAuditEvent scans one audit row.
func scanAuditEvent(row rowScanner) (model.AuditEvent, error) {
	var (
		ev           model.AuditEvent
		timeMS       int64
		metadataJSON string
	)
	err := row.Scan(
		&ev.Seq, &ev.ID, &timeMS, &ev.ActorType, &ev.ActorID, &ev.ActorName,
		&ev.Action, &ev.Status, &ev.Severity, &ev.TargetType, &ev.TargetID,
		&metadataJSON, &ev.PrevHash, &ev.Hash,
	)
	if err != nil {
		return model.AuditEvent{}, mapErr(err)
	}
	ev.Time = fromMillis(timeMS)
	if metadataJSON != "" {
		if err := json.Unmarshal([]byte(metadataJSON), &ev.Metadata); err != nil {
			return model.AuditEvent{}, fmt.Errorf("store: corrupt audit metadata at seq %d: %w", ev.Seq, err)
		}
	}
	return ev, nil
}

// VerifyAudit recomputes the hash chain and reports the first invalid event.
func (db *DB) VerifyAudit(ctx context.Context) (model.AuditVerifyResult, error) {
	db.appendMu.Lock()
	defer db.appendMu.Unlock()

	rows, err := db.sql.QueryContext(ctx,
		`SELECT seq, id, time_ms, actor_type, actor_id, actor_name, action, status,
			severity, target_type, target_id, metadata_json, prev_hash, hash
		 FROM audit ORDER BY seq ASC`)
	if err != nil {
		return model.AuditVerifyResult{}, fmt.Errorf("store: read audit chain: %w", mapErr(err))
	}
	defer rows.Close()

	var (
		expectedSeq int64 = 1
		prevHash          = auditGenesisHash
		count       int64
	)
	for rows.Next() {
		var (
			ev           model.AuditEvent
			timeMS       int64
			metadataJSON string
		)
		if err := rows.Scan(
			&ev.Seq, &ev.ID, &timeMS, &ev.ActorType, &ev.ActorID, &ev.ActorName,
			&ev.Action, &ev.Status, &ev.Severity, &ev.TargetType, &ev.TargetID,
			&metadataJSON, &ev.PrevHash, &ev.Hash,
		); err != nil {
			return model.AuditVerifyResult{}, fmt.Errorf("store: scan audit chain: %w", mapErr(err))
		}
		count++

		if ev.Seq != expectedSeq {
			return model.AuditVerifyResult{
				OK:              false,
				Events:          count,
				FirstInvalidSeq: expectedSeq,
				Message:         fmt.Sprintf("audit chain discontinuity: expected seq %d, found %d", expectedSeq, ev.Seq),
			}, nil
		}
		ev.Time = fromMillis(timeMS)
		canonical, err := canonicalAuditJSON(ev, metadataJSON)
		if err != nil {
			return model.AuditVerifyResult{
				OK:              false,
				Events:          count,
				FirstInvalidSeq: ev.Seq,
				Message:         fmt.Sprintf("audit event %d cannot be canonicalized", ev.Seq),
			}, nil
		}
		if ev.PrevHash != prevHash {
			return model.AuditVerifyResult{
				OK:              false,
				Events:          count,
				FirstInvalidSeq: ev.Seq,
				Message:         fmt.Sprintf("audit chain broken at seq %d: prev_hash does not match previous event", ev.Seq),
			}, nil
		}
		wantHash := auditHash(prevHash, canonical)
		if ev.Hash != wantHash {
			return model.AuditVerifyResult{
				OK:              false,
				Events:          count,
				FirstInvalidSeq: ev.Seq,
				Message:         fmt.Sprintf("audit hash mismatch at seq %d: chain was modified", ev.Seq),
			}, nil
		}
		prevHash = ev.Hash
		expectedSeq = ev.Seq + 1
	}
	if err := rows.Err(); err != nil {
		return model.AuditVerifyResult{}, fmt.Errorf("store: iterate audit chain: %w", mapErr(err))
	}
	return model.AuditVerifyResult{
		OK:      true,
		Events:  count,
		Message: "audit chain verified",
	}, nil
}
