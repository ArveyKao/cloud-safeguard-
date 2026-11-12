package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/capcatalog"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/token"
	"github.com/arveykao/cloud-safeguard/internal/vaultcrypto"
)

// InitOptions configures first-run bootstrap.
type InitOptions struct {
	// DataDir is created if missing.
	DataDir string
	// Demo seeds the mock cloud provider, demo agents and built-in
	// capabilities, making the product immediately demoable.
	Demo bool
	// Force allows re-initializing an existing data directory (rotates the
	// admin token). Off by default: Init refuses to touch an existing install.
	Force bool
	// MasterKey optionally supplies the master key instead of generating one.
	MasterKey []byte
	// SupervisorUsername names the first supervisor (default "admin"). It is
	// only used when no person holds the supervisor flag yet.
	SupervisorUsername string
}

// InitAgent is one demo agent created by Init with its one-time token.
type InitAgent struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

// InitResult summarizes a bootstrap. AdminToken and agent Tokens are shown
// exactly once and are never retrievable again.
type InitResult struct {
	DataDir          string      `json:"data_dir"`
	AdminToken       string      `json:"admin_token"`
	AdminTokenPrefix string      `json:"admin_token_prefix"`
	ProviderIDs      []string    `json:"provider_ids"`
	CapabilityIDs    []string    `json:"capability_ids"`
	Agents           []InitAgent `json:"agents"`
	// Supervisor is the first supervisor with a one-time setup code, or nil
	// when a supervisor already existed (CONTRACT §17.1).
	Supervisor *model.PersonWithSetupCode `json:"supervisor,omitempty"`
}

// Demo seed constants (frozen by CONTRACT §11).
const (
	demoProviderName      = "demo-aliyun"
	demoProviderRegion    = "cn-hangzhou"
	demoProviderRoleARN   = "acs:ram::1234567890123456:role/csg-demo"
	demoBrokerAccessKeyID = "LTAI5tDemoMockBroker"
	demoAgentClaudeCode   = "claude-code"
	demoAgentHermes       = "hermes-researcher"
)

// Init bootstraps a new data directory: master key, database, admin token,
// built-in capabilities, and (with Demo) the mock provider plus demo agents.
func Init(ctx context.Context, opts InitOptions) (InitResult, error) {
	if opts.DataDir == "" {
		return InitResult{}, errors.New("server: data dir is required")
	}
	dir := opts.DataDir
	keyPath := filepath.Join(dir, "master.key")
	dbPath := filepath.Join(dir, store.DBFileName)

	keyPresent := fileExists(keyPath)
	dbPresent := fileExists(dbPath)
	if (keyPresent || dbPresent) && !opts.Force {
		return InitResult{}, fmt.Errorf(
			"data directory %q is already initialized; refusing to overwrite it (use --force to rotate the admin token)",
			dir)
	}
	// A database without a master key would be re-keyed with a fresh random key,
	// silently orphaning every encrypted credential. Refuse instead.
	if dbPresent && !keyPresent && len(opts.MasterKey) == 0 && strings.TrimSpace(os.Getenv("CSG_MASTER_KEY")) == "" {
		return InitResult{}, fmt.Errorf(
			"data directory %q contains a database but no master.key; refusing to initialize (restore master.key or set CSG_MASTER_KEY)",
			dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return InitResult{}, fmt.Errorf("server: create data dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700) // best effort 0700

	key, err := initMasterKey(opts, keyPath, keyPresent)
	if err != nil {
		return InitResult{}, err
	}
	if _, err := vault.New(key); err != nil {
		return InitResult{}, err
	}
	v, err := vault.New(key)
	if err != nil {
		return InitResult{}, err
	}

	db, err := store.Open(ctx, dir)
	if err != nil {
		return InitResult{}, err
	}
	defer db.Close()
	if err := ensureVaultKeyCheck(ctx, db, v); err != nil {
		return InitResult{}, err
	}
	// `csg init --force` on an older data dir performs the schema upgrade, so it
	// must record it too; a later `csg serve` would see no migration to report.
	if err := auditMigrationReport(ctx, db); err != nil {
		return InitResult{}, err
	}

	now := time.Now().UTC()
	// ---- meta ----
	instanceID, err := db.GetMeta(ctx, store.MetaInstanceID)
	if errors.Is(err, store.ErrNotFound) {
		instanceID, err = newID("csg_")
		if err != nil {
			return InitResult{}, err
		}
		if err := db.SetMeta(ctx, store.MetaInstanceID, instanceID); err != nil {
			return InitResult{}, err
		}
	} else if err != nil {
		return InitResult{}, err
	}
	// The admin token is generated exactly once per init run; --force rotates it.
	adminToken, adminHash, err := token.Generate(token.AdminPrefix)
	if err != nil {
		return InitResult{}, err
	}
	adminPrefix := token.DisplayPrefix(adminToken)
	for key, value := range map[string]string{
		store.MetaAdminTokenHash:   adminHash,
		store.MetaAdminTokenPrefix: adminPrefix,
		store.MetaBootstrapTime:    now.Format(time.RFC3339Nano),
		store.MetaDemoMode:         strconv.FormatBool(opts.Demo),
		store.MetaSchemaVersion:    strconv.Itoa(store.CurrentSchemaVersion),
	} {
		if err := db.SetMeta(ctx, key, value); err != nil {
			return InitResult{}, err
		}
	}

	// ---- built-in capabilities (missing only, never overwrite existing rows) ----
	capabilityIDs := make([]string, 0, 8)
	for _, capability := range capcatalog.Builtin() {
		capabilityIDs = append(capabilityIDs, capability.ID)
		if _, err := db.GetCapability(ctx, capability.ID); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return InitResult{}, err
		}
		capability.Builtin = true
		if capability.CreatedAt.IsZero() {
			capability.CreatedAt = now
		}
		if capability.UpdatedAt.IsZero() {
			capability.UpdatedAt = now
		}
		if err := db.CreateCapability(ctx, capability); err != nil {
			return InitResult{}, err
		}
	}

	// ---- default guardrails (only when never stored) ----
	if _, err := db.GetMeta(ctx, store.MetaPolicySettings); errors.Is(err, store.ErrNotFound) {
		if err := db.SetPolicySettings(ctx, model.DefaultPolicySettings()); err != nil {
			return InitResult{}, err
		}
	} else if err != nil {
		return InitResult{}, err
	}

	supervisor, err := bootstrapSupervisor(ctx, db, opts.SupervisorUsername, now)
	if err != nil {
		return InitResult{}, err
	}

	result := InitResult{
		Supervisor:       supervisor,
		DataDir:          dir,
		AdminToken:       adminToken,
		AdminTokenPrefix: adminPrefix,
		ProviderIDs:      []string{},
		CapabilityIDs:    capabilityIDs,
		Agents:           []InitAgent{},
	}

	if opts.Demo {
		providerID, err := seedDemoProvider(ctx, db, v, now)
		if err != nil {
			return InitResult{}, err
		}
		if providerID != "" {
			result.ProviderIDs = append(result.ProviderIDs, providerID)
		}
		agents, err := seedDemoAgents(ctx, db, capabilityIDs, now)
		if err != nil {
			return InitResult{}, err
		}
		result.Agents = agents
	}

	return result, nil
}

// initMasterKey resolves the master key for Init, reusing an existing key file
// so --force never orphans encrypted data.
func initMasterKey(opts InitOptions, keyPath string, keyPresent bool) ([]byte, error) {
	// An environment override must agree with an existing key file, otherwise a
	// later serve would decrypt with a different key than the data was written
	// with.
	if keyPresent && len(opts.MasterKey) == 0 {
		if raw := strings.TrimSpace(os.Getenv("CSG_MASTER_KEY")); raw != "" {
			envKey, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				return nil, fmt.Errorf("server: CSG_MASTER_KEY is not valid base64: %w", err)
			}
			existing, err := os.ReadFile(keyPath)
			if err != nil {
				return nil, fmt.Errorf("server: read existing master key: %w", err)
			}
			if !bytes.Equal(existing, envKey) {
				return nil, errors.New("server: CSG_MASTER_KEY does not match the existing data directory master key")
			}
		}
	}
	if len(opts.MasterKey) > 0 {
		if len(opts.MasterKey) != 32 {
			return nil, vault.ErrInvalidKey
		}
		key := append([]byte(nil), opts.MasterKey...)
		if keyPresent {
			existing, err := os.ReadFile(keyPath)
			if err != nil {
				return nil, fmt.Errorf("server: read existing master key: %w", err)
			}
			if !bytes.Equal(existing, key) {
				return nil, errors.New("server: supplied master key does not match the existing data directory master key")
			}
			return key, nil
		}
		if err := os.WriteFile(keyPath, key, 0o600); err != nil {
			return nil, fmt.Errorf("server: write master key: %w", err)
		}
		_ = os.Chmod(keyPath, 0o600)
		return key, nil
	}
	return vault.LoadOrCreateKey(filepath.Dir(keyPath))
}

// seedDemoProvider creates the demo-aliyun mock provider when missing. It
// returns the created provider ID ("" when the provider already existed).
func seedDemoProvider(ctx context.Context, db *store.DB, v *vault.Vault, now time.Time) (string, error) {
	providers, err := db.ListProviders(ctx)
	if err != nil {
		return "", err
	}
	for _, p := range providers {
		if p.Name == demoProviderName {
			return "", nil // data intact on --force
		}
	}
	id, err := newID("prv_")
	if err != nil {
		return "", err
	}
	placeholderSecret, err := randomBase64URL(24)
	if err != nil {
		return "", err
	}
	credentialJSON, err := json.Marshal(brokerCredential{
		AccessKeyID:     demoBrokerAccessKeyID,
		AccessKeySecret: placeholderSecret, // encoded placeholder: mock mode never uses it
	})
	if err != nil {
		return "", err
	}
	encrypted, err := v.Encrypt(credentialJSON, providerAAD(id))
	if err != nil {
		return "", err
	}
	provider := model.Provider{
		ID:                id,
		Name:              demoProviderName,
		Type:              model.ProviderAliyun,
		Mode:              model.ModeMock,
		Region:            demoProviderRegion,
		RoleARN:           demoProviderRoleARN,
		CloudAccountID:    model.CloudAccountIDFromRoleARN(model.ProviderAliyun, demoProviderRoleARN),
		AccessKeyIDMasked: maskAccessKeyID(demoBrokerAccessKeyID),
		Status:            model.ProviderActive,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := db.CreateProvider(ctx, provider, encrypted); err != nil {
		return "", err
	}
	return provider.ID, nil
}

// demoAgentSpec is one seeded demo agent definition (CONTRACT §11, §16.7).
type demoAgentSpec struct {
	name          string
	description   string
	role          model.AgentRole
	grants        []string
	maxTTLSeconds int
	maxConcurrent int
}

// seedDemoAgents creates the demo agents when missing and returns the one-time
// tokens of the agents it created. Existing agents are left untouched.
func seedDemoAgents(ctx context.Context, db *store.DB, capabilityIDs []string, now time.Time) ([]InitAgent, error) {
	// claude-code is an administrator and holds the whole catalog;
	// hermes-researcher is a guest, so it may only hold read capabilities
	// (CONTRACT §16.7). Never widen a guest's grants to make the seed
	// non-empty: an out-of-role grant would be rejected everywhere else.
	claudeGrants := append([]string(nil), capabilityIDs...)
	hermesGrants := make([]string, 0, 1)
	for _, id := range capabilityIDs {
		if id == capcatalog.IDCloudRead {
			hermesGrants = append(hermesGrants, id)
			break
		}
	}
	specs := []demoAgentSpec{
		{
			name:          demoAgentClaudeCode,
			description:   "Primary coding agent (Claude Code compatible)",
			role:          model.RoleAdministrator,
			grants:        claudeGrants,
			maxTTLSeconds: 3600,
			maxConcurrent: 3,
		},
		{
			name:          demoAgentHermes,
			description:   "Read-only research agent",
			role:          model.RoleGuest,
			grants:        hermesGrants,
			maxTTLSeconds: 900,
			maxConcurrent: 1,
		},
	}

	agents, err := db.ListAgents(ctx)
	if err != nil {
		return nil, err
	}
	existing := make(map[string]model.Agent, len(agents))
	for _, a := range agents {
		existing[a.Name] = a
	}

	created := make([]InitAgent, 0, len(specs))
	for _, spec := range specs {
		if _, ok := existing[spec.name]; ok {
			continue // data intact on --force; tokens are never re-recoverable
		}
		id, err := newID("agt_")
		if err != nil {
			return nil, err
		}
		plainToken, tokenHash, err := token.Generate(token.AgentPrefix)
		if err != nil {
			return nil, err
		}
		agent := model.Agent{
			ID:                  id,
			Name:                spec.name,
			Description:         spec.description,
			Status:              model.AgentActive,
			Role:                spec.role,
			Grants:              spec.grants,
			MaxTTLSeconds:       spec.maxTTLSeconds,
			MaxConcurrentLeases: spec.maxConcurrent,
			TokenPrefix:         token.DisplayPrefix(plainToken),
			CreatedAt:           now,
			UpdatedAt:           now,
		}
		if err := db.CreateAgent(ctx, agent, tokenHash); err != nil {
			return nil, err
		}
		created = append(created, InitAgent{ID: agent.ID, Name: agent.Name, Token: plainToken})
	}
	return created, nil
}

// fileExists reports whether path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false
		}
		return false
	}
	return !info.IsDir()
}

// auditMigrationReport appends one schema.migrated system audit event when
// store.Open upgraded an existing database. The report is converted to plain
// JSON values first, so the audit hash is computed over exactly what is stored.
func auditMigrationReport(ctx context.Context, db *store.DB) error {
	report := db.MigrationReport()
	if report == nil {
		return nil
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode migration report: %w", err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return fmt.Errorf("decode migration report: %w", err)
	}
	return db.AppendAudit(ctx, &model.AuditEvent{
		ActorType:  "system",
		ActorID:    "system",
		ActorName:  model.ProductName,
		Action:     "schema.migrated",
		Status:     "ok",
		Severity:   "warning",
		TargetType: "store",
		TargetID:   "schema",
		Metadata:   metadata,
	})
}

// DefaultSupervisorUsername is the first supervisor's username when Init is
// not given one.
const DefaultSupervisorUsername = "admin"

// bootstrapSupervisor creates the first supervisor (pending, with a setup
// code) when no person holds the supervisor flag. It returns nil otherwise.
func bootstrapSupervisor(ctx context.Context, db *store.DB, username string, now time.Time) (*model.PersonWithSetupCode, error) {
	people, err := db.ListPersons(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range people {
		if p.Supervisor {
			return nil, nil
		}
	}
	if strings.TrimSpace(username) == "" {
		username = DefaultSupervisorUsername
	}
	name, ok := normalizeUsername(username)
	if !ok {
		return nil, fmt.Errorf("server: invalid supervisor username %q", username)
	}
	created, err := newPersonWithSetupCode(ctx, db, name, "", true, now)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			return nil, fmt.Errorf("server: username %q exists but is not a supervisor; run `csg supervisor recover`", name)
		}
		return nil, err
	}
	ev := model.AuditEvent{
		ActorType: "system", ActorID: "system", ActorName: model.ProductName,
		Action: "person.supervisor_bootstrapped", Status: "ok", Severity: "critical",
		TargetType: "person", TargetID: created.Person.ID,
		Metadata: map[string]any{"username": name},
	}
	if err := db.AppendAudit(ctx, &ev); err != nil {
		return nil, err
	}
	return &created, nil
}

// RecoverOptions configures RecoverSupervisor.
type RecoverOptions struct {
	DataDir string
	// Username is the supervisor to restore; it is created when missing.
	Username string
	// MasterKey optionally overrides the master key loaded from DataDir.
	MasterKey []byte
}

// RecoverSupervisor restores console access for a locked-out supervisor
// (CONTRACT §17.1). It runs locally on the server host and needs the vault
// master key: it makes the named person a supervisor, erases their password,
// TOTP secret and sessions, and returns a new one-time setup code. The
// recovery is audited at critical severity.
func RecoverSupervisor(ctx context.Context, opts RecoverOptions) (model.PersonWithSetupCode, error) {
	var zero model.PersonWithSetupCode
	username, ok := normalizeUsername(opts.Username)
	if !ok {
		return zero, fmt.Errorf("server: invalid username %q", opts.Username)
	}
	if opts.DataDir == "" || !fileExists(filepath.Join(opts.DataDir, store.DBFileName)) {
		return zero, notInitializedErr(opts.DataDir)
	}
	// Holding the master key is the proof of authority for local recovery.
	key, err := loadMasterKeyForServe(Config{DataDir: opts.DataDir, MasterKey: opts.MasterKey})
	if err != nil {
		return zero, err
	}
	v, err := vault.New(key)
	if err != nil {
		return zero, err
	}
	db, err := store.Open(ctx, opts.DataDir)
	if err != nil {
		return zero, err
	}
	defer db.Close()
	if err := verifyVaultKey(ctx, db, v); err != nil {
		return zero, err
	}

	now := time.Now().UTC()
	var out model.PersonWithSetupCode
	revokedLeases := []string{}
	previousStatus := "(new)"
	person, err := db.GetPersonByUsername(ctx, username)
	if err == nil {
		previousStatus = string(person.Status)
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		if out, err = newPersonWithSetupCode(ctx, db, username, "", true, now); err != nil {
			return zero, err
		}
	case err != nil:
		return zero, err
	default:
		code, hash, err := authn.NewSecret(24)
		if err != nil {
			return zero, err
		}
		expires := now.Add(setupCodeTTL)
		if err := db.SetSupervisorFlag(ctx, person.ID, true, now); err != nil {
			return zero, err
		}
		if err := db.ResetPersonSetup(ctx, person.ID, hash, expires, now, false); err != nil {
			return zero, err
		}
		// The person is pending now: their agents' leases end with that
		// (§17.6). Recovery runs outside the server, so revoke in the store.
		if revokedLeases, err = db.RevokeOwnerLeases(ctx, person.ID, "agent's owner was reset by local recovery", now); err != nil {
			return zero, err
		}
		if person, err = db.GetPerson(ctx, person.ID); err != nil {
			return zero, err
		}
		out = model.PersonWithSetupCode{Person: person, SetupCode: code, SetupExpiresAt: expires}
	}
	ev := model.AuditEvent{
		ActorType: "system", ActorID: "system", ActorName: model.ProductName,
		Action: "person.supervisor_recovered", Status: "ok", Severity: "critical",
		TargetType: "person", TargetID: out.Person.ID,
		// A suspended person is reactivated by recovery; record what they were.
		Metadata: map[string]any{"username": username, "previous_status": previousStatus, "revoked_lease_ids": revokedLeases},
	}
	if err := db.AppendAudit(ctx, &ev); err != nil {
		return zero, err
	}
	return out, nil
}

// Vault key check: a known plaintext encrypted with the master key and kept
// in the meta table, so a wrong key is detected even when no provider
// credential or TOTP secret exists yet.
const (
	vaultKeyCheckPlaintext = "csg-vault-key-check-v1"
	vaultKeyCheckAAD       = "meta/vault-key-check"
)

var errWrongMasterKey = errors.New("server: the master key does not match this data directory")

// ensureVaultKeyCheck verifies the stored key check, or writes it when the
// data directory has none yet. Init and serve call it; both hold the key the
// directory was created with (or fail here).
func ensureVaultKeyCheck(ctx context.Context, db *store.DB, v *vault.Vault) error {
	err := verifyVaultKey(ctx, db, v)
	if err == nil || !errors.Is(err, errVaultKeyUnverifiable) {
		return err
	}
	blob, err := v.Encrypt([]byte(vaultKeyCheckPlaintext), vaultKeyCheckAAD)
	if err != nil {
		return err
	}
	return db.SetMeta(ctx, store.MetaVaultKeyCheck, blob)
}

// errVaultKeyUnverifiable means the data directory holds nothing encrypted
// to test a key against.
var errVaultKeyUnverifiable = errors.New("server: cannot verify the master key: this data directory has no key check yet; start `csg serve` once with the right key")

// verifyVaultKey proves that v holds the master key this data directory was
// encrypted with. It fails closed: errWrongMasterKey when a stored secret
// does not decrypt, errVaultKeyUnverifiable when there is nothing to test.
// A data directory from before the key check falls back to a stored provider
// credential or TOTP secret.
func verifyVaultKey(ctx context.Context, db *store.DB, v *vault.Vault) error {
	blob, err := db.GetMeta(ctx, store.MetaVaultKeyCheck)
	switch {
	case err == nil:
		plain, err := v.Decrypt(blob, vaultKeyCheckAAD)
		if err != nil || string(plain) != vaultKeyCheckPlaintext {
			return errWrongMasterKey
		}
		return nil
	case !errors.Is(err, store.ErrNotFound):
		return err
	}
	providers, err := db.ListProviders(ctx)
	if err != nil {
		return err
	}
	for _, p := range providers {
		blob, err := db.GetProviderCredential(ctx, p.ID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := v.Decrypt(blob, providerAAD(p.ID)); err != nil {
			return errWrongMasterKey
		}
		return nil
	}
	personID, enc, err := db.AnyTOTPSecret(ctx)
	switch {
	case err == nil:
		if _, err := v.Decrypt(enc, totpAAD(personID)); err != nil {
			return errWrongMasterKey
		}
		return nil
	case !errors.Is(err, store.ErrNotFound):
		return err
	}
	return errVaultKeyUnverifiable
}
