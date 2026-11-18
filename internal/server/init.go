package server

import (
	"context"
	"crypto/subtle"
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
func Init(ctx context.Context, opts InitOptions) (result InitResult, err error) {
	if opts.DataDir == "" {
		return InitResult{}, errors.New("server: data dir is required")
	}
	// Everything that can be refused is refused before anything is written.
	supervisorName := opts.SupervisorUsername
	if strings.TrimSpace(supervisorName) == "" {
		supervisorName = DefaultSupervisorUsername
	}
	if _, ok := normalizeUsername(supervisorName); !ok {
		return InitResult{}, fmt.Errorf("server: invalid supervisor username %q", supervisorName)
	}
	if len(opts.MasterKey) > 0 && len(opts.MasterKey) != 32 {
		return InitResult{}, vault.ErrInvalidKey
	}
	if raw := strings.TrimSpace(os.Getenv("CSG_MASTER_KEY")); raw != "" && len(opts.MasterKey) == 0 {
		if key, err := base64.StdEncoding.DecodeString(raw); err != nil || len(key) != 32 {
			return InitResult{}, errors.New("server: CSG_MASTER_KEY must be 32 bytes, base64-encoded")
		}
	}
	dir := opts.DataDir
	keyPath := filepath.Join(dir, "master.key")
	dbPath := filepath.Join(dir, store.DBFileName)

	// Anything at these paths, a dangling symlink included, belongs to
	// someone else: Init then creates nothing, so its cleanup can only
	// remove files it made itself.
	keyPresent := pathExists(keyPath)
	dbFilePresent := pathExists(dbPath)
	// A -wal or -shm file without the database is what is left of one.
	dbPresent := dbFilePresent || pathExists(dbPath+"-wal") || pathExists(dbPath+"-shm")
	switch {
	case keyPresent && dbFilePresent:
		return InitResult{}, fmt.Errorf(
			"data directory %q is already initialized; refusing to touch it (`csg serve` upgrades it, and `csg supervisor recover` issues a new setup code)",
			dir)
	case keyPresent:
		return InitResult{}, fmt.Errorf(
			"data directory %q holds a master.key but no database: it is the remains of an interrupted setup or of a lost database; refusing to touch it. Restore %s, or remove master.key (and any %s-wal or -shm file) if nothing was ever stored with it, then run csg init again",
			dir, store.DBFileName, store.DBFileName)
	case dbPresent:
		return InitResult{}, fmt.Errorf(
			"data directory %q holds a database (or its -wal/-shm files) but no master.key; refusing to touch it. Restore master.key (or set CSG_MASTER_KEY); without the key the stored secrets cannot be read",
			dir)
	}
	// What Init may remove again if it fails: only paths that did not exist
	// before it started, and the directory only if Init made it.
	dirExisted := pathExists(dir)
	var mine []string
	for _, name := range []string{"master.key", store.DBFileName, store.DBFileName + "-wal", store.DBFileName + "-shm"} {
		if path := filepath.Join(dir, name); !pathExists(path) {
			mine = append(mine, path)
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return InitResult{}, fmt.Errorf("server: create data dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700) // best effort 0700

	// From here on Init creates files. If it fails, it removes what it
	// created, so a failed init never leaves a directory that looks
	// initialized but has no supervisor.
	var db *store.DB
	defer func() {
		if db != nil {
			db.Close()
		}
		if err != nil {
			for _, path := range mine {
				_ = os.Remove(path)
			}
			if !dirExisted {
				_ = os.Remove(dir) // only succeeds when it is empty
			}
		}
	}()

	key, err := initMasterKey(opts, keyPath)
	if err != nil {
		return InitResult{}, err
	}
	v, err := vault.New(key)
	if err != nil {
		return InitResult{}, err
	}

	db, err = store.Open(ctx, dir)
	if err != nil {
		return InitResult{}, err
	}
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

	if err := bootstrapHook(); err != nil {
		return InitResult{}, err
	}
	supervisor, err := bootstrapSupervisor(ctx, db, opts.SupervisorUsername, now)
	if err != nil {
		return InitResult{}, err
	}

	result = InitResult{Supervisor: supervisor, DataDir: dir, ProviderIDs: []string{}}

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

// initMasterKey writes the master key of a new data directory: the one
// supplied, or $CSG_MASTER_KEY, or a freshly generated one.
func initMasterKey(opts InitOptions, keyPath string) ([]byte, error) {
	if len(opts.MasterKey) > 0 {
		key := append([]byte(nil), opts.MasterKey...)
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
			return "", nil
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

// pathExists reports whether anything is at path, without following a
// symlink.
func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, fs.ErrNotExist)
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
	// The event and "the report is recorded" are one transaction; when
	// another process recorded it first, nothing is written here.
	_, err = db.RecordMigrationAudit(ctx, &model.AuditEvent{
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
	return err
}

// bootstrapHook runs just before the first supervisor is created; tests
// replace it to make Init fail after it has created files.
var bootstrapHook = func() error { return nil }

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
	// MasterKey optionally supplies the master key instead of DataDir's
	// master.key or $CSG_MASTER_KEY. It must be the key the data was
	// encrypted with.
	MasterKey []byte
	// TrustMasterKey accepts the supplied key for a directory that holds
	// nothing encrypted and no master.key, so nothing can verify the key. It
	// never overrides a key the data or a master.key proves wrong (see
	// checkVaultKey).
	TrustMasterKey bool
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
	// The key first: recovery is refused with a key that is not this
	// directory's (see checkVaultKey).
	if err := checkVaultKey(ctx, db, v, opts.DataDir, key, opts.TrustMasterKey); err != nil {
		return zero, err
	}
	// Recovery may be the first command to open an older database, which
	// upgrades it: record that.
	if err := auditMigrationReport(ctx, db); err != nil {
		return zero, err
	}

	now := time.Now().UTC()
	var out model.PersonWithSetupCode
	revokedLeases := []string{}
	recoveryIssue := model.SetupIssue{ByID: "system", ByName: "csg supervisor recover", Kind: model.SetupRecovered}
	previousStatus, previousModes := "(new)", map[string]string{}
	person, err := db.GetPersonByUsername(ctx, username)
	if err == nil {
		previousStatus = string(person.Status)
		if previousModes, err = raisedModes(ctx, db, person.ID, now); err != nil {
			return zero, err
		}
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
	// One lease.revoked event per credential, like every other revocation.
	for _, id := range revokedLeases {
		metadata := map[string]any{"actor": "system", "reason": "agent's owner was reset by local recovery",
			"caused_by": "csg supervisor recover", "owner_id": out.Person.ID}
		if lease, err := db.GetLease(ctx, id); err == nil {
			metadata["agent_id"], metadata["agent_name"] = lease.AgentID, lease.AgentName
		}
		if err := db.AppendAudit(ctx, &model.AuditEvent{
			ActorType: "system", ActorID: "system", ActorName: model.ProductName,
			Action: "lease.revoked", Status: "denied", Severity: "warning",
			TargetType: "lease", TargetID: id, Metadata: metadata,
		}); err != nil {
			return zero, err
		}
	}
	ev := model.AuditEvent{
		ActorType: "system", ActorID: "system", ActorName: model.ProductName,
		Action: "person.supervisor_recovered", Status: "ok", Severity: "critical",
		TargetType: "person", TargetID: out.Person.ID,
		// A suspended person is reactivated by recovery; record what they were.
		Metadata: map[string]any{"username": username, "previous_status": previousStatus, "revoked_lease_ids": revokedLeases,
			"previous_modes": previousModes, "mode": string(model.ModeRead)},
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

// checkVaultKey verifies key against the data directory. It never guesses.
//
//   - Something encrypted exists (the key check, a cloud account's stored
//     AccessKey or a TOTP secret): the key must decrypt it. A key supplied
//     from outside wins over a master.key file that differs.
//   - Nothing encrypted exists (an install from before the key check that
//     never stored a secret), and the directory has a master.key: that file
//     is the key. It is written into the key check; any other key is
//     refused.
//   - Nothing encrypted exists and there is no master.key: the key from the
//     environment cannot be told from a mistyped one, and a check written
//     with a wrong key would lock the right one out. It is refused unless
//     the operator says to trust it (trust), which is recorded in the audit
//     log.
func checkVaultKey(ctx context.Context, db *store.DB, v *vault.Vault, dataDir string, key []byte, trust bool) error {
	err := verifyVaultKey(ctx, db, v)
	if err == nil {
		// The data proved the key (a stored AccessKey or TOTP secret did,
		// when the directory is from before the key check). Write the check
		// if it is missing, so the key stays verifiable when that data goes.
		return writeVaultKeyCheckIfMissing(ctx, db, v)
	}
	if !errors.Is(err, errVaultKeyUnverifiable) {
		return err
	}
	stored, readErr := os.ReadFile(filepath.Join(dataDir, "master.key"))
	switch {
	case readErr == nil:
		if len(stored) != len(key) || subtle.ConstantTimeCompare(stored, key) != 1 {
			return fmt.Errorf("%w: nothing in it is encrypted yet, so its master.key is taken as the key, and the key supplied is a different one. "+
				"If the supplied key is the right one, remove the stale master.key and run this command once with --trust-master-key", errWrongMasterKey)
		}
		return writeVaultKeyCheckIfMissing(ctx, db, v)
	case !errors.Is(readErr, fs.ErrNotExist):
		return fmt.Errorf("server: read master key: %w", readErr)
	case !trust:
		return errVaultKeyUnverifiable
	}
	// Trusted by the operator: the key check and the record of that decision
	// are written together.
	blob, err := v.Encrypt([]byte(vaultKeyCheckPlaintext), vaultKeyCheckAAD)
	if err != nil {
		return err
	}
	return db.AppendAuditWithMeta(ctx, &model.AuditEvent{
		ActorType: "system", ActorID: "system", ActorName: model.ProductName,
		Action: "vault.master_key_trusted", Status: "ok", Severity: "critical",
		TargetType: "store", TargetID: "vault",
		Metadata: map[string]any{"reason": "no key check and no master.key; the operator chose to trust the supplied key"},
	}, store.MetaVaultKeyCheck, blob)
}

// writeVaultKeyCheckIfMissing stores the key check for a key that was just
// proved right, when the directory has none yet.
func writeVaultKeyCheckIfMissing(ctx context.Context, db *store.DB, v *vault.Vault) error {
	if _, err := db.GetMeta(ctx, store.MetaVaultKeyCheck); !errors.Is(err, store.ErrNotFound) {
		return err
	}
	blob, err := v.Encrypt([]byte(vaultKeyCheckPlaintext), vaultKeyCheckAAD)
	if err != nil {
		return err
	}
	return db.SetMeta(ctx, store.MetaVaultKeyCheck, blob)
}

// ensureVaultKeyCheck verifies the key, or writes the key check when the
// directory holds nothing to verify against. Only Init uses it, for a
// directory it has just created with this key; serve and recovery go
// through checkVaultKey, which does not take an unverifiable key on trust.
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
var errVaultKeyUnverifiable = errors.New("server: cannot verify the master key: this data directory has no key check, no master.key and nothing encrypted to test the key against. If the key in $CSG_MASTER_KEY is the right one, run this command once with --trust-master-key")

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
