package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/capcatalog"
	"github.com/arveykao/cloud-safeguard/internal/model"
)

// migrateRolesAndAccess is the data half of schema migration 2 (CONTRACT
// §16.6). It runs inside the migration transaction, after the role/access
// columns exist, and performs four steps:
//
//  1. built-in capabilities get their catalog access level, custom ones admin;
//  2. custom capabilities whose template violates the IAM prohibition are
//     disabled (they could never mint a credential again anyway);
//  3. the retired break-glass capability is disabled but kept, because historic
//     leases reference it;
//  4. agents swap the retired grant for aliyun.account.admin and get the lowest
//     role that still permits every grant they hold. Grants never widen.
//
// On a fresh database there are no rows at all and the transform is a no-op:
// the catalog is seeded afterwards, by `csg init`.
func migrateRolesAndAccess(ctx context.Context, tx *sql.Tx, report *MigrationReport) error {
	if report == nil {
		report = &MigrationReport{} // fresh database: nothing is reported
	}
	accessByCapability, prohibited, err := migrateCapabilityAccess(ctx, tx, report)
	if err != nil {
		return err
	}
	return migrateAgentRoles(ctx, tx, accessByCapability, prohibited, report)
}

// capabilityRow is the subset of a capability needed by the migration.
type capabilityRow struct {
	id             string
	builtin        bool
	enabled        bool
	policyTemplate string
	paramsJSON     string
}

// migrateCapabilityAccess implements steps 1-3. It returns the resulting access
// level of every capability, keyed by ID, and the set of custom capabilities
// disabled because their template violates the IAM prohibition.
func migrateCapabilityAccess(ctx context.Context, tx *sql.Tx, report *MigrationReport) (map[string]model.AccessLevel, map[string]bool, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT id, builtin, enabled, policy_template, params_json FROM capabilities`)
	if err != nil {
		return nil, nil, fmt.Errorf("read capabilities: %w", err)
	}
	existing := make([]capabilityRow, 0, 8)
	for rows.Next() {
		var (
			row     capabilityRow
			builtin int
			enabled int
		)
		if err := rows.Scan(&row.id, &builtin, &enabled, &row.policyTemplate, &row.paramsJSON); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("scan capability: %w", err)
		}
		row.builtin = intBool(builtin)
		row.enabled = intBool(enabled)
		existing = append(existing, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, fmt.Errorf("read capabilities: %w", err)
	}
	rows.Close()

	access := make(map[string]model.AccessLevel, len(existing)+1)
	prohibited := make(map[string]bool)
	hadRetired := false
	for _, row := range existing {
		// Step 1: the catalog is authoritative for builtins; everything else is
		// treated as admin, the most restrictive classification there is.
		level := model.AccessAdmin
		if spec, ok := capcatalog.Lookup(row.id); ok && row.builtin {
			level = spec.Access
		}
		enabled := row.enabled

		// Step 2: a custom capability that cannot render a permitted policy is
		// disabled rather than left as a trap for the next lease request.
		if _, ok := capcatalog.Lookup(row.id); !ok {
			params, perr := decodeCapabilityParams(row.id, row.paramsJSON)
			if perr != nil {
				return nil, nil, perr
			}
			candidate := model.Capability{
				ID:             row.id,
				Access:         level,
				PolicyTemplate: row.policyTemplate,
				Params:         params,
			}
			// A v1 template that allows a bare "*" minted credentials without
			// the mandatory deny, so they could manage RAM. It is disabled like
			// a prohibited one, and its grants are dropped.
			broad, berr := capcatalog.TemplateAllowsEverything(candidate, capcatalog.SampleParams(candidate))
			if _, rerr := capcatalog.RenderSample(candidate); rerr != nil || berr != nil || broad {
				if enabled {
					report.DisabledCapabilities = append(report.DisabledCapabilities, row.id)
				}
				enabled = false
				prohibited[row.id] = true
			}
		}

		// Step 3: the retired break-glass capability stays, disabled.
		if row.id == capcatalog.IDBreakGlass {
			if enabled {
				report.DisabledCapabilities = append(report.DisabledCapabilities, row.id)
			}
			enabled = false
			hadRetired = true
		}

		if _, err := tx.ExecContext(ctx,
			`UPDATE capabilities SET access = ?, enabled = ? WHERE id = ?`,
			string(level), boolInt(enabled), row.id,
		); err != nil {
			return nil, nil, fmt.Errorf("update capability %s: %w", row.id, err)
		}
		access[row.id] = level
	}

	// Step 4 replaces the retired grant with aliyun.account.admin, so on a real
	// v1 database that capability must exist. Seed it from the catalog when the
	// database predates it: `csg serve` migrates but never re-seeds, so an
	// upgraded install would otherwise have agents granting a capability that
	// does not exist. A fresh database has no rows here at all and is seeded by
	// `csg init` instead, so nothing is inserted.
	_, haveReplacement := access[capcatalog.IDAccountAdmin]
	if hadRetired && !haveReplacement {
		spec, found := capcatalog.Lookup(capcatalog.IDAccountAdmin)
		if !found {
			return nil, nil, fmt.Errorf("catalog is missing %s", capcatalog.IDAccountAdmin)
		}
		if err := insertCatalogCapability(ctx, tx, spec); err != nil {
			return nil, nil, err
		}
		access[spec.ID] = spec.Access
	}
	return access, prohibited, nil
}

// insertCatalogCapability inserts one built-in capability during migration.
func insertCatalogCapability(ctx context.Context, tx *sql.Tx, c model.Capability) error {
	paramsJSON, err := marshalJSON(c.Params, "[]")
	if err != nil {
		return err
	}
	now := toMillis(time.Now().UTC())
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO capabilities(id, name, description, provider_type, risk, access,
			policy_template, params_json, default_ttl_seconds, max_ttl_seconds,
			enabled, builtin, created_at, updated_at)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.Name, c.Description, string(c.ProviderType), string(c.Risk), string(c.Access),
		c.PolicyTemplate, paramsJSON, c.DefaultTTLSeconds, c.MaxTTLSeconds,
		boolInt(true), boolInt(true), now, now,
	); err != nil {
		return fmt.Errorf("seed capability %s: %w", c.ID, err)
	}
	return nil
}

// migrateAgentRoles implements step 4.
//
// Grants to capabilities that step 2 disabled for violating the IAM prohibition
// are dropped: they can never be leased again, and keeping them would raise the
// agent's role ceiling for nothing.
func migrateAgentRoles(ctx context.Context, tx *sql.Tx, access map[string]model.AccessLevel, prohibited map[string]bool, report *MigrationReport) error {
	rows, err := tx.QueryContext(ctx, `SELECT id, grants_json FROM agents`)
	if err != nil {
		return fmt.Errorf("read agents: %w", err)
	}
	type agentRow struct {
		id         string
		grantsJSON string
	}
	existing := make([]agentRow, 0, 8)
	for rows.Next() {
		var row agentRow
		if err := rows.Scan(&row.id, &row.grantsJSON); err != nil {
			rows.Close()
			return fmt.Errorf("scan agent: %w", err)
		}
		existing = append(existing, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("read agents: %w", err)
	}
	rows.Close()

	for _, row := range existing {
		grants, err := decodeGrants(row.id, row.grantsJSON)
		if err != nil {
			return err
		}
		replacedRetired := false
		for _, g := range grants {
			if g == capcatalog.IDBreakGlass {
				replacedRetired = true
			}
		}
		grants = replaceRetiredGrant(grants)
		kept := make([]string, 0, len(grants))
		var dropped []string
		for _, g := range grants {
			if prohibited[g] {
				dropped = append(dropped, g)
				continue
			}
			kept = append(kept, g)
		}
		grants = kept

		levels := make([]model.AccessLevel, 0, len(grants))
		for _, grant := range grants {
			// An unknown capability cannot be leased, so it must not drive the
			// role up either.
			if level, ok := access[grant]; ok {
				levels = append(levels, level)
			}
		}
		role, ok := model.LowestRolePermitting(levels)
		if !ok {
			// Unreachable: every stored access level came from this migration.
			role = model.RoleAdministrator
		}
		encoded, err := marshalJSON(grants, "[]")
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE agents SET role = ?, grants_json = ? WHERE id = ?`,
			string(role), encoded, row.id,
		); err != nil {
			return fmt.Errorf("update agent %s: %w", row.id, err)
		}
		report.Agents = append(report.Agents, AgentMigration{
			AgentID:              row.id,
			Role:                 role,
			DroppedGrants:        dropped,
			ReplacedRetiredGrant: replacedRetired,
		})
	}
	return nil
}

// replaceRetiredGrant swaps the retired break-glass capability for its
// replacement, preserving order and never introducing a duplicate.
func replaceRetiredGrant(grants []string) []string {
	out := make([]string, 0, len(grants))
	seen := make(map[string]bool, len(grants))
	for _, grant := range grants {
		if grant == capcatalog.IDBreakGlass {
			grant = capcatalog.IDAccountAdmin
		}
		if seen[grant] {
			continue
		}
		seen[grant] = true
		out = append(out, grant)
	}
	return out
}

// decodeCapabilityParams decodes a stored params_json column.
func decodeCapabilityParams(id, raw string) ([]model.CapabilityParam, error) {
	if raw == "" || raw == "null" {
		return nil, nil
	}
	var params []model.CapabilityParam
	if err := json.Unmarshal([]byte(raw), &params); err != nil {
		return nil, fmt.Errorf("corrupt capability params for %s: %w", id, err)
	}
	return params, nil
}

// decodeGrants decodes a stored grants_json column.
func decodeGrants(id, raw string) ([]string, error) {
	if raw == "" || raw == "null" {
		return nil, nil
	}
	var grants []string
	if err := json.Unmarshal([]byte(raw), &grants); err != nil {
		return nil, fmt.Errorf("corrupt agent grants for %s: %w", id, err)
	}
	return grants, nil
}
