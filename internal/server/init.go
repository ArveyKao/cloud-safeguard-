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
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/vaultcrypto"
)

// InitOptions configures first-run bootstrap.
type InitOptions struct {
	// DataDir is created if missing.
	DataDir string
	// Demo seeds the mock cloud account, making the product immediately
	// demoable.
	Demo bool
	// MasterKey optionally supplies the master key instead of generating one.
	MasterKey []byte
	// SupervisorUsername names the first supervisor (default "admin"). It is
	// only used when no person holds the supervisor flag yet.
	SupervisorUsername string
}

// InitResult summarizes a bootstrap. The setup code is shown exactly once
// and is never retrievable again.
type InitResult struct {
	DataDir     string   `json:"data_dir"`
	ProviderIDs []string `json:"provider_ids"`
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
)

// Init bootstraps a new data directory: master key, database, default
// guardrails, the first supervisor's setup code and (with Demo) the mock
// cloud account. It never touches an existing install: upgrades happen when
// `csg serve` opens the database, and a locked-out supervisor is recovered
// with RecoverSupervisor.
func Init(ctx context.Context, opts InitOptions) (InitResult, error) {
	if opts.DataDir == "" {
		return InitResult{}, errors.New("server: data dir is required")
	}
	dir := opts.DataDir
	keyPath := filepath.Join(dir, "master.key")
	dbPath := filepath.Join(dir, store.DBFileName)

	keyPresent := fileExists(keyPath)
	dbPresent := fileExists(dbPath)
	if keyPresent || dbPresent {
		return InitResult{}, fmt.Errorf(
			"data directory %q is already initialized; refusing to touch it (`csg serve` upgrades it, and `csg supervisor recover` issues a new setup code)",
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
	for key, value := range map[string]string{
		store.MetaBootstrapTime: now.Format(time.RFC3339Nano),
		store.MetaDemoMode:      strconv.FormatBool(opts.Demo),
		store.MetaSchemaVersion: strconv.Itoa(store.CurrentSchemaVersion),
	} {
		if err := db.SetMeta(ctx, key, value); err != nil {
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

	result := InitResult{Supervisor: supervisor, DataDir: dir, ProviderIDs: []string{}}

	if opts.Demo {
		providerID, err := seedDemoProvider(ctx, db, v, now)
		if err != nil {
			return InitResult{}, err
		}
		if providerID != "" {
			result.ProviderIDs = append(result.ProviderIDs, providerID)
		}
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
		MaxAutoLevel:      model.ModeRead,
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
	created, err := newPersonWithSetupCode(ctx, db, name, "", true, now,
		model.SetupIssue{ByID: "system", ByName: "csg init", Kind: model.SetupBootstrap})
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
	recoveryIssue := model.SetupIssue{ByID: "system", ByName: "csg supervisor recover", Kind: model.SetupRecovered}
	previousStatus, previousMode := "(new)", model.ModeRead
	person, err := db.GetPersonByUsername(ctx, username)
	if err == nil {
		previousStatus = string(person.Status)
		previousMode = person.EffectiveApprovalMode(now)
	}
	switch {
	case errors.Is(err, store.ErrNotFound):
		if out, err = newPersonWithSetupCode(ctx, db, username, "", true, now, recoveryIssue); err != nil {
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
		if err := db.ResetPersonSetup(ctx, person.ID, hash, expires, now, false, recoveryIssue); err != nil {
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
		Metadata: map[string]any{"username": username, "previous_status": previousStatus, "revoked_lease_ids": revokedLeases,
			"previous_mode": string(previousMode), "mode": string(model.ModeRead)},
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
