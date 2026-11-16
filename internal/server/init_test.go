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

// Init never touches an existing install: not its data, not its master key,
// whatever options it is given. There is nothing to rotate any more.
func TestInitRefusesAnInitializedDirAndLeavesItIntact(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: true}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	snapshot := func() map[string][]byte {
		out := map[string][]byte{}
		for _, name := range []string{"master.key", store.DBFileName} {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read %s: %v", name, err)
			}
			out[name] = data
		}
		return out
	}
	before := snapshot()

	different := make([]byte, 32)
	for i := range different {
		different[i] = 0xEE
	}
	for name, opts := range map[string]InitOptions{
		"plain":            {DataDir: dir},
		"demo":             {DataDir: dir, Demo: true},
		"another key":      {DataDir: dir, MasterKey: different},
		"another username": {DataDir: dir, SupervisorUsername: "someone-else"},
	} {
		if _, err := Init(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "already initialized") {
			t.Fatalf("%s: Init on an initialized dir = %v, want a refusal", name, err)
		}
	}
	t.Setenv("CSG_MASTER_KEY", base64.StdEncoding.EncodeToString(different))
	if _, err := Init(context.Background(), InitOptions{DataDir: dir}); err == nil {
		t.Fatal("Init with a conflicting CSG_MASTER_KEY touched an initialized dir")
	}
	t.Setenv("CSG_MASTER_KEY", "")
	after := snapshot()
	for name := range before {
		if !bytes.Equal(before[name], after[name]) {
			t.Fatalf("a refused Init changed %s", name)
		}
	}

	// The install still works: the key decrypts the demo account's credential.
	env := &testEnv{t: t, dir: dir, clock: newFakeClock(time.Now()), logs: &bytes.Buffer{}}
	srv, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New after refused inits: %v", err)
	}
	defer srv.Close()
	env.srv = srv
	providers, err := srv.db.ListProviders(context.Background())
	if err != nil || len(providers) != 1 {
		t.Fatalf("providers = %d, %v", len(providers), err)
	}
	if ok, message := srv.testProvider(context.Background(), providers[0]); !ok {
		t.Fatalf("the demo account's credential no longer decrypts: %s", message)
	}
	people, err := srv.db.ListPersons(context.Background())
	if err != nil || len(people) != 1 {
		t.Fatalf("a refused Init added a person: %+v, %v", people, err)
	}
}

func TestInitNonDemoBootstrap(t *testing.T) {
	dir := t.TempDir()
	result, err := Init(context.Background(), InitOptions{DataDir: dir, SupervisorUsername: "root"})
	if err != nil {
		t.Fatalf("Init non-demo: %v", err)
	}
	if len(result.ProviderIDs) != 0 {
		t.Fatalf("non-demo init added a cloud account: %+v", result)
	}
	if result.Supervisor == nil || result.Supervisor.Person.Username != "root" || result.Supervisor.SetupCode == "" {
		t.Fatalf("first supervisor = %+v", result.Supervisor)
	}

	db, err := store.Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
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
	db.Close()

	// The server starts on a non-demo install, and the setup code works.
	srv, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatalf("New non-demo: %v", err)
	}
	defer srv.Close()
	rec := rawRequest(t, srv.Handler(), http.MethodPost, "/api/v1/auth/setup/begin", "",
		model.SetupBeginInput{SetupCode: result.Supervisor.SetupCode, Password: testPassword})
	requireStatus(t, rec, http.StatusOK)
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

func TestInitOnADirWithOtherFiles(t *testing.T) {
	dir := t.TempDir()
	// A stray file that is not part of an install does not block init.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write stray file: %v", err)
	}
	if _, err := Init(context.Background(), InitOptions{DataDir: dir}); err != nil {
		t.Fatalf("Init on dir with stray file: %v", err)
	}
}

// A damaged install (database present, master key lost, or the other way
// round) is never initialized over: a fresh key would orphan the encrypted
// data.
func TestInitRefusesAPartialInstall(t *testing.T) {
	for _, name := range []string{store.DBFileName, "master.key"} {
		dir := t.TempDir()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("left over from a damaged install"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Init(context.Background(), InitOptions{DataDir: dir}); err == nil {
			t.Fatalf("Init accepted a directory that already has %s", name)
		}
		if data, _ := os.ReadFile(path); string(data) != "left over from a damaged install" {
			t.Fatalf("a refused Init changed %s", name)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 {
			t.Fatalf("a refused Init left %d files next to %s", len(entries), name)
		}
	}
}
