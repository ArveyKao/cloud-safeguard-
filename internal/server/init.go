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

	"github.com/arveykao/cloud-safeguard/internal/capcatalog"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/token"
	"github.com/arveykao/cloud-safeguard/internal/vault"
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
		store.MetaSchemaVersion:    "1",
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

	result := InitResult{
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

// demoAgentSpec is one seeded demo agent definition (CONTRACT §11).
type demoAgentSpec struct {
	name          string
	description   string
	grants        []string
	maxTTLSeconds int
	maxConcurrent int
}

// seedDemoAgents creates the demo agents when missing and returns the one-time
// tokens of the agents it created. Existing agents are left untouched.
func seedDemoAgents(ctx context.Context, db *store.DB, capabilityIDs []string, now time.Time) ([]InitAgent, error) {
	claudeGrants := append([]string(nil), capabilityIDs...)
	hermesGrants := make([]string, 0, 1)
	readCapability := "aliyun.cloud.read"
	for _, id := range capabilityIDs {
		if id == readCapability {
			hermesGrants = append(hermesGrants, id)
			break
		}
	}
	if len(hermesGrants) == 0 && len(capabilityIDs) > 0 {
		// The catalog is the source of truth; fall back to its first capability.
		hermesGrants = append(hermesGrants, capabilityIDs[0])
	}
	specs := []demoAgentSpec{
		{
			name:          demoAgentClaudeCode,
			description:   "Primary coding agent (Claude Code compatible)",
			grants:        claudeGrants,
			maxTTLSeconds: 3600,
			maxConcurrent: 3,
		},
		{
			name:          demoAgentHermes,
			description:   "Read-only research agent",
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
