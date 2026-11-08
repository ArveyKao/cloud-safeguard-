package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/token"
)

// rawRequest performs an HTTP request against a handler (used by tests that
// build a Server directly rather than through testEnv).
func rawRequest(t *testing.T, handler http.Handler, method, path, bearer string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestInitForcePreservesDataAndRotatesAdminToken(t *testing.T) {
	dir := t.TempDir()
	first, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: true})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	keyBefore, err := os.ReadFile(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("read master.key: %v", err)
	}

	// Mutate data through a running server: audit event + a lease credential.
	srv, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := srv.db.AppendAudit(context.Background(), &model.AuditEvent{
		ActorType: "system", ActorID: "system", ActorName: model.ProductName,
		Action: "test.marker", Status: "ok", Severity: "info",
	}); err != nil {
		t.Fatalf("append marker audit event: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Force re-init rotates the admin token but keeps the data and key.
	second, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: true, Force: true})
	if err != nil {
		t.Fatalf("Init --force: %v", err)
	}
	if first.AdminToken == second.AdminToken {
		t.Fatal("--force did not rotate the admin token")
	}
	if len(second.Agents) != 0 {
		t.Fatalf("--force re-issued %d agent tokens, want 0 (data intact)", len(second.Agents))
	}
	if len(second.ProviderIDs) != 0 {
		t.Fatalf("--force re-created %d providers, want 0", len(second.ProviderIDs))
	}
	if len(second.CapabilityIDs) != 5 {
		t.Fatalf("--force capability ids = %v, want 5", second.CapabilityIDs)
	}
	keyAfter, err := os.ReadFile(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("read master.key after force: %v", err)
	}
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("--force replaced the master key and would orphan encrypted data")
	}

	// No duplicate seed rows; the pre-existing audit chain still verifies.
	db, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if caps, err := db.ListCapabilities(context.Background()); err != nil || len(caps) != 5 {
		t.Fatalf("capabilities after force = %d, %v", len(caps), err)
	}
	if providers, err := db.ListProviders(context.Background()); err != nil || len(providers) != 1 {
		t.Fatalf("providers after force = %d, %v", len(providers), err)
	}
	if agents, err := db.ListAgents(context.Background()); err != nil || len(agents) != 2 {
		t.Fatalf("agents after force = %d, %v", len(agents), err)
	}
	if result, err := db.VerifyAudit(context.Background()); err != nil || !result.OK || result.Events != 1 {
		t.Fatalf("audit chain after force = %+v, %v", result, err)
	}
	if hash, _ := db.GetMeta(context.Background(), store.MetaAdminTokenHash); hash != token.Hash(second.AdminToken) {
		t.Fatal("stored admin token hash was not rotated")
	}
	providers, _ := db.ListProviders(context.Background())
	db.Close()

	// The rotated admin token works; the old one is rejected.
	srv2, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New after force: %v", err)
	}
	defer srv2.Close()
	handler := srv2.Handler()
	rec := rawRequest(t, handler, http.MethodPost, "/api/v1/admin/login", second.AdminToken, nil)
	requireStatus(t, rec, http.StatusOK)
	rec = rawRequest(t, handler, http.MethodPost, "/api/v1/admin/login", first.AdminToken, nil)
	requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)

	// The preserved master key still decrypts the demo provider credential:
	// provider testing decrypts it, so ok=true proves decryption works.
	rec = rawRequest(t, handler, http.MethodPost, "/api/v1/admin/providers/"+providers[0].ID+"/test", second.AdminToken, nil)
	requireStatus(t, rec, http.StatusOK)
	tested := decodeEnvelope[providerTestResult](t, rec)
	if !tested.OK {
		t.Fatalf("provider credential no longer decrypts after force: %+v", tested)
	}

	// Force again without --demo: still allowed, data intact, demo flag updated.
	third, err := Init(context.Background(), InitOptions{DataDir: dir, Force: true})
	if err != nil {
		t.Fatalf("Init --force (non-demo): %v", err)
	}
	if third.AdminToken == second.AdminToken {
		t.Fatal("second --force did not rotate the admin token")
	}
	db3, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db3.Close()
	if agents, _ := db3.ListAgents(context.Background()); len(agents) != 2 {
		t.Fatalf("agents after second force = %d, want 2", len(agents))
	}
	if mode, _ := db3.GetMeta(context.Background(), store.MetaDemoMode); mode != "false" {
		t.Fatalf("demo_mode after non-demo force = %q, want false", mode)
	}
}

func TestInitNonDemoBootstrap(t *testing.T) {
	dir := t.TempDir()
	result, err := Init(context.Background(), InitOptions{DataDir: dir})
	if err != nil {
		t.Fatalf("Init non-demo: %v", err)
	}
	if len(result.Agents) != 0 || len(result.ProviderIDs) != 0 {
		t.Fatalf("non-demo init seeded agents/providers: %+v", result)
	}
	if len(result.CapabilityIDs) != 5 {
		t.Fatalf("capability IDs = %v, want 5 builtins", result.CapabilityIDs)
	}
	if !strings.HasPrefix(result.AdminToken, token.AdminPrefix) {
		t.Fatal("admin token missing expected prefix")
	}

	db, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	providers, _ := db.ListProviders(ctx)
	agents, _ := db.ListAgents(ctx)
	if len(providers) != 0 || len(agents) != 0 {
		t.Fatalf("non-demo seed rows = %d providers, %d agents", len(providers), len(agents))
	}
	if mode, _ := db.GetMeta(ctx, store.MetaDemoMode); mode != "false" {
		t.Fatalf("demo_mode = %q, want false", mode)
	}
	settings, err := db.GetPolicySettings(ctx)
	if err != nil || settings != model.DefaultPolicySettings() {
		t.Fatalf("policy settings = %+v, %v", settings, err)
	}

	// The server starts on a non-demo install.
	srv, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New non-demo: %v", err)
	}
	defer srv.Close()
	if rec := rawRequest(t, srv.Handler(), http.MethodPost, "/api/v1/admin/login", result.AdminToken, nil); rec.Code != http.StatusOK {
		t.Fatalf("admin login on non-demo install status = %d", rec.Code)
	}
}

func TestInitExplicitMasterKey(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x10 + i)
	}
	if _, err := Init(context.Background(), InitOptions{DataDir: dir, MasterKey: key}); err != nil {
		t.Fatalf("Init with master key: %v", err)
	}
	stored, err := os.ReadFile(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("read master.key: %v", err)
	}
	if !bytes.Equal(stored, key) {
		t.Fatal("explicit master key was not written to master.key")
	}
	info, err := os.Stat(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("stat master.key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("master.key mode = %o, want 0600", perm)
	}

	// The server loads the key file without any env override.
	srv, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New with key file: %v", err)
	}
	srv.Close()

	// Wrong-sized explicit key is rejected.
	other := t.TempDir()
	if _, err := Init(context.Background(), InitOptions{DataDir: other, MasterKey: make([]byte, 16)}); err == nil {
		t.Fatal("Init accepted a 16-byte master key")
	}

	// A different key on --force must not silently orphan the encrypted data.
	different := make([]byte, 32)
	if _, err := Init(context.Background(), InitOptions{DataDir: dir, Force: true, MasterKey: different}); err == nil {
		t.Fatal("Init --force accepted a different master key")
	} else if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatched key error = %v", err)
	}
	// The original key survived the refused force.
	after, _ := os.ReadFile(filepath.Join(dir, "master.key"))
	if !bytes.Equal(after, key) {
		t.Fatal("refused --force altered the master key")
	}
}

func TestInitCreatesDataDirPermissions(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "nested", "data")
	if _, err := Init(context.Background(), InitOptions{DataDir: dir}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat data dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("data dir mode = %o, want 0700", perm)
	}
}

func TestInitForceOnExistingUninitializedDir(t *testing.T) {
	dir := t.TempDir()
	// A stray file that is not part of an install does not block init.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write stray file: %v", err)
	}
	if _, err := Init(context.Background(), InitOptions{DataDir: dir}); err != nil {
		t.Fatalf("Init on dir with stray file: %v", err)
	}
	// A bare empty directory is initialized normally (Force is not required).
	dir2 := t.TempDir()
	if _, err := Init(context.Background(), InitOptions{DataDir: dir2, Force: true}); err != nil {
		t.Fatalf("Init --force on empty dir: %v", err)
	}
	db, err := store.Open(context.Background(), dir2)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer db.Close()
	caps, _ := db.ListCapabilities(context.Background())
	if len(caps) != 5 {
		t.Fatalf("capabilities = %d, want 5", len(caps))
	}
	_ = time.Now
}

func TestInitRefusesDatabaseWithoutMasterKey(t *testing.T) {
	dir := t.TempDir()
	// Simulate a damaged install: database present, master key lost.
	if err := os.WriteFile(filepath.Join(dir, store.DBFileName), []byte("not really sqlite"), 0o600); err != nil {
		t.Fatalf("write fake db: %v", err)
	}
	// Without --force it is "already initialized"; with --force it must refuse
	// rather than generate a fresh key and orphan the encrypted data.
	if _, err := Init(context.Background(), InitOptions{DataDir: dir, Force: true}); err == nil {
		t.Fatal("Init --force accepted a database without a master key")
	} else if !strings.Contains(err.Error(), "master.key") {
		t.Fatalf("error = %v, want a master.key hint", err)
	}
}

func TestInitRejectsMismatchedEnvironmentMasterKey(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(context.Background(), InitOptions{DataDir: dir}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	keyBefore, err := os.ReadFile(filepath.Join(dir, "master.key"))
	if err != nil {
		t.Fatalf("read master.key: %v", err)
	}
	different := make([]byte, 32)
	for i := range different {
		different[i] = 0xEE
	}
	t.Setenv("CSG_MASTER_KEY", base64.StdEncoding.EncodeToString(different))
	if _, err := Init(context.Background(), InitOptions{DataDir: dir, Force: true}); err == nil {
		t.Fatal("Init --force accepted a conflicting CSG_MASTER_KEY")
	} else if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("error = %v, want a mismatch error", err)
	}
	keyAfter, _ := os.ReadFile(filepath.Join(dir, "master.key"))
	if !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("refused --force altered the master key file")
	}
}
