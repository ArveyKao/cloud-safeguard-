package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/token"
)

// ---- regression tests for the independent review of commit a936962 ----

func (s *Server) listAuditFor(t *testing.T, action string) []model.AuditEvent {
	t.Helper()
	items, _, err := s.db.ListAudit(context.Background(), store.AuditFilter{Action: action, Limit: 100})
	if err != nil {
		t.Fatalf("ListAudit(%s): %v", action, err)
	}
	return items
}

// rawExec runs statements straight on a data directory's database.
func rawExec(t *testing.T, dir string, statements ...string) {
	t.Helper()
	raw, err := sql.Open("sqlite", filepath.Join(dir, store.DBFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, stmt := range statements {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

// An install from the version that had only the admin token has no person at
// all. After the upgrade deletes that token nobody could sign in, so the
// server must not start; `csg supervisor recover` creates the first
// supervisor, records the upgrade, and then it starts.
func TestUpgradeWithoutAnySupervisorDoesNotStartUntilRecovered(t *testing.T) {
	ctx := context.Background()
	for _, from := range []string{"1", "7"} {
		dir := t.TempDir()
		if _, err := Init(ctx, InitOptions{DataDir: dir, Demo: true}); err != nil {
			t.Fatal(err)
		}
		if from == "1" {
			downgradeToV1(t, dir)
		} else {
			rawExec(t, dir, `UPDATE meta SET value = '7' WHERE key = 'schema_version'`)
		}
		rawExec(t, dir, `DELETE FROM persons`, `DELETE FROM audit`,
			`INSERT INTO meta(key, value) VALUES('admin_token_hash', 'abc'), ('admin_token_prefix', 'csg_adm_abc')`)

		// From schema 7 the operator runs recovery straight away, so recovery
		// is the command that upgrades the database; from schema 1 the server
		// is started first (twice) and refuses.
		attempts := 2
		if from == "7" {
			attempts = 0
		}
		for attempt := 1; attempt <= attempts; attempt++ {
			srv, err := New(Config{DataDir: dir})
			if err == nil {
				srv.Close()
				t.Fatalf("from schema %s, attempt %d: the server started with no supervisor", from, attempt)
			}
			if !errors.Is(err, ErrNoSupervisor) || !strings.Contains(err.Error(), "csg supervisor recover --username") {
				t.Fatalf("from schema %s: error = %v, want ErrNoSupervisor with the recovery command", from, err)
			}
		}

		out, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: dir, Username: "root"})
		if err != nil || out.SetupCode == "" || !out.Person.Supervisor {
			t.Fatalf("from schema %s: recover = %+v, %v", from, out.Person, err)
		}
		srv, err := New(Config{DataDir: dir})
		if err != nil {
			t.Fatalf("from schema %s: New after recovery: %v", from, err)
		}
		// The upgrade is recorded exactly once, whichever command ran it.
		migrated := srv.listAuditFor(t, "schema.migrated")
		if len(migrated) != 1 || migrated[0].Metadata["deleted_admin_token"] != true {
			t.Fatalf("from schema %s: schema.migrated = %+v", from, migrated)
		}
		if res, err := srv.db.VerifyAudit(ctx); err != nil || !res.OK {
			t.Fatalf("audit chain = %+v, %v", res, err)
		}
		rec := rawRequest(t, srv.Handler(), http.MethodPost, "/api/v1/auth/setup/begin", "",
			model.SetupBeginInput{SetupCode: out.SetupCode, Password: testPassword})
		requireStatus(t, rec, http.StatusOK)
		srv.Close()
	}
}

// A failed init leaves nothing behind, and the three commands never point
// at each other for a half-made directory.
func TestInitFailsCleanlyAndExplainsPartialInstalls(t *testing.T) {
	ctx := context.Background()
	empty := func(dir string) bool {
		entries, err := os.ReadDir(dir)
		return err == nil && len(entries) == 0
	}

	// An invalid supervisor name is refused before anything is written.
	dir := t.TempDir()
	if _, err := Init(ctx, InitOptions{DataDir: dir, SupervisorUsername: "bad name"}); err == nil {
		t.Fatal("Init accepted an invalid supervisor username")
	}
	if !empty(dir) {
		t.Fatal("a refused Init left files behind")
	}
	if _, err := Init(ctx, InitOptions{DataDir: dir, MasterKey: make([]byte, 16)}); err == nil || !empty(dir) {
		t.Fatalf("Init with a 16-byte key: err %v, empty %v", err, empty(dir))
	}
	// The same directory can then be initialized normally.
	if _, err := Init(ctx, InitOptions{DataDir: dir, SupervisorUsername: "root"}); err != nil {
		t.Fatalf("Init after a refused one: %v", err)
	}

	// A failure after the key and the database exist removes both.
	old := bootstrapHook
	bootstrapHook = func() error { return errors.New("injected failure") }
	failed := t.TempDir()
	_, err := Init(ctx, InitOptions{DataDir: failed, Demo: true})
	bootstrapHook = old
	if err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("Init = %v, want the injected failure", err)
	}
	if !empty(failed) {
		entries, _ := os.ReadDir(failed)
		t.Fatalf("a failed Init left %d files behind", len(entries))
	}
	if _, err := New(Config{DataDir: failed}); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("New on a failed init = %v", err)
	}
	if _, err := Init(ctx, InitOptions{DataDir: failed}); err != nil {
		t.Fatalf("Init after a failed one: %v", err)
	}

	// Only a key, or only a database: init says what it is and how to repair
	// it, and does not call it "initialized".
	keyOnly := t.TempDir()
	if err := os.WriteFile(filepath.Join(keyOnly, "master.key"), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Init(ctx, InitOptions{DataDir: keyOnly})
	if err == nil || strings.Contains(err.Error(), "already initialized") || !strings.Contains(err.Error(), "remove master.key") {
		t.Fatalf("Init on a key-only directory = %v", err)
	}
	dbOnly := t.TempDir()
	if err := os.WriteFile(filepath.Join(dbOnly, store.DBFileName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Init(ctx, InitOptions{DataDir: dbOnly})
	if err == nil || strings.Contains(err.Error(), "already initialized") || !strings.Contains(err.Error(), "Restore master.key") {
		t.Fatalf("Init on a database-only directory = %v", err)
	}
}

// An agent without an owner is refused on every agent route, and a lease
// that is not an access request is never handed out, even when both are
// active in the database.
func TestOwnerlessAgentAndLegacyLeaseAreRefused(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	ctx := context.Background()
	plain, hash, err := token.Generate(token.AgentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	now := a.clock.Now()
	expires := now.Add(10 * time.Minute)
	orphan := model.Agent{ID: "agt_orphan", Name: "orphan", Status: model.AgentActive, Role: model.RoleAdministrator,
		Grants: []string{"aliyun.cloud.read"}, MaxTTLSeconds: 3600, MaxConcurrentLeases: 3,
		TokenPrefix: token.DisplayPrefix(plain), CreatedAt: now, UpdatedAt: now}
	if err := a.srv.db.CreateAgent(ctx, orphan, hash); err != nil {
		t.Fatal(err)
	}
	lease := model.Lease{ID: "lea_orphan", AgentID: orphan.ID, AgentName: orphan.Name, CapabilityID: "aliyun.cloud.read",
		ProviderID: a.providerID, Status: model.LeaseActive, RequestedTTLSeconds: 600, EffectiveTTLSeconds: 600,
		CreatedAt: now, IssuedAt: &now, ExpiresAt: &expires, CredentialAvailable: true}
	if err := a.srv.db.CreateLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	blob, err := a.srv.vault.Encrypt([]byte(`{"access_key_id":"LTAIorphan","access_key_secret":"orphan-secret"}`), leaseAAD(lease.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.srv.db.SQL().Exec(`UPDATE leases SET encrypted_credential = ?, credential_available = 1 WHERE id = ?`, blob, lease.ID); err != nil {
		t.Fatal(err)
	}
	if stored, err := a.srv.db.GetLeaseCredential(ctx, lease.ID); err != nil || stored == "" {
		t.Fatalf("precondition: no stored credential: %v", err)
	}

	for _, call := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/agent/me"},
		{http.MethodGet, "/api/v1/agent/accounts"},
		{http.MethodGet, "/api/v1/agent/leases"},
		{http.MethodGet, "/api/v1/agent/leases/" + lease.ID},
		{http.MethodPost, "/api/v1/agent/leases/" + lease.ID + "/credential"},
		{http.MethodPost, "/api/v1/agent/heartbeat"},
		{http.MethodPost, "/api/v1/agent/access-requests"},
	} {
		rec := a.do(call.method, call.path, plain, nil)
		requireErrorCode(t, rec, http.StatusForbidden, model.ErrCodeForbidden)
		if strings.Contains(rec.Body.String(), "orphan-secret") {
			t.Fatalf("%s %s returned the credential", call.method, call.path)
		}
	}

	// The same lease on an agent that has an owner: authenticated, and still
	// refused, because it is not an access request.
	if _, err := a.srv.db.SQL().Exec(`UPDATE leases SET agent_id = ?, agent_name = ? WHERE id = ?`, a.agent.ID, a.agent.Name, lease.ID); err != nil {
		t.Fatal(err)
	}
	rec := a.credential(lease.ID)
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "orphan-secret") {
		t.Fatalf("a lease that is not an access request was handed out: %d", rec.Code)
	}
}

// A provider an older upgrade left without a cloud account ID can be given
// one, with the roles set on it before removed; a duplicate of a connected
// account can only be disabled.
func TestProviderWithoutAccountIDCanBeRepaired(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	rec := a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts", newMockAccount("second", "6543210987654321"))
	requireStatus(t, rec, http.StatusCreated)
	second := decodeEnvelope[model.Provider](t, rec)
	account := "/api/v1/supervisor/accounts/" + second.ID
	requireStatus(t, a.sup.do(http.MethodPut, account+"/people/"+a.mei.person.ID, model.PutBindingInput{Role: model.RoleAdministrator}), http.StatusOK)
	// As the v5 upgrade leaves a duplicate.
	if _, err := a.srv.db.SQL().Exec(`UPDATE providers SET cloud_account_id = '', role_arn = 'not-a-role' WHERE id = ?`, second.ID); err != nil {
		t.Fatal(err)
	}

	patch := func(arn string) int {
		return a.sup.do(http.MethodPatch, account, model.UpdateProviderInput{RoleARN: &arn}).Code
	}
	if code := patch("acs:ram::6543210987654321:user/someone"); code != http.StatusBadRequest {
		t.Fatalf("a user ARN = %d", code)
	}
	// The account of the first provider is taken.
	if code := patch("acs:ram::" + demoAccountID + ":role/cloud-safeguard"); code != http.StatusConflict {
		t.Fatalf("an account that is already connected = %d", code)
	}
	if got, _ := a.srv.db.GetProvider(context.Background(), second.ID); got.CloudAccountID != "" {
		t.Fatalf("a refused repair set the account ID to %q", got.CloudAccountID)
	}
	if code := patch("acs:ram::7777777777777777:role/cloud-safeguard"); code != http.StatusOK {
		t.Fatalf("repair = %d", code)
	}
	got, _ := a.srv.db.GetProvider(context.Background(), second.ID)
	if got.CloudAccountID != "7777777777777777" || got.RoleARN != "acs:ram::7777777777777777:role/cloud-safeguard" {
		t.Fatalf("after the repair: %+v", got)
	}
	// The role given while it had no account does not carry over.
	if _, err := a.srv.db.GetBinding(context.Background(), a.mei.person.ID, second.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a role set before the repair survived it: %v", err)
	}
	in := accessInput("ecs", "read")
	in.CloudAccountID = "7777777777777777"
	requireStatus(t, a.requestRaw(a.token, in), http.StatusForbidden)
	ev := a.lastEvent("provider.updated")
	a.requireActor(ev, a.sup)
	// Once it has an account, the role ARN must stay in it.
	if code := patch("acs:ram::8888888888888888:role/cloud-safeguard"); code != http.StatusConflict {
		t.Fatalf("moving to another account = %d", code)
	}
}

// Writing a role always re-checks the person's agents, so a credential left
// behind by an interleaved or interrupted change is revoked by the next
// write of the same role.
func TestEveryRoleWriteRechecksThePersonsAgents(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	write := a.request(accessInput("ecs", "write"))
	requireStatus(t, a.approve(a.mei, write.ID), http.StatusOK)
	// The role was lowered without its sweep (what two changes at once, each
	// reading the other's "before", can leave behind).
	a.bindDirect(a.mei.person.ID, model.RoleGuest)
	if a.status(write.ID) != model.LeaseActive {
		t.Fatal("precondition: the credential should still be active")
	}
	// The supervisor writes guest: for this request nothing was lowered.
	a.bind(a.mei, model.RoleGuest)
	if got := a.status(write.ID); got != model.LeaseRevoked {
		t.Fatalf("credential above the role after a role write = %s", got)
	}
	// Raising a role revokes nothing.
	read := a.request(accessInput("ecs", "read"))
	a.bind(a.mei, model.RoleAdministrator)
	if got := a.status(read.ID); got != model.LeaseActive {
		t.Fatalf("raising the role changed a credential to %s", got)
	}
}

// A supervisor's Administrator role ends with the flag or with a
// suspension, for waiting requests as well as issued credentials, on every
// cloud account; a role given by name remains.
func TestSupervisorAuthorityEndsWithTheFlagOrSuspension(t *testing.T) {
	for _, how := range []string{"flag removed", "suspended", "reset"} {
		t.Run(how, func(t *testing.T) {
			a := newAccessEnv(t, "")
			rec := a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts", newMockAccount("second", "6543210987654321"))
			requireStatus(t, rec, http.StatusCreated)
			settings := model.DefaultPolicySettings()
			settings.MaxConcurrentLeasesPerAgent = 10
			requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/settings", settings), http.StatusOK)
			ana := a.addPerson(a.sup, "ana", true)
			a.bind(ana, model.RoleGuest) // by name, on the demo account only
			_, tok := a.signInAgent(ana, "ana-agent")
			ask := func(account, permission string) model.AccessRequest {
				in := model.AccessRequestInput{CloudAccountID: account, Resource: "ecs", Permission: permission, TTLSeconds: 600}
				if permission != "read" {
					in.Reason = "supervisor work"
				}
				rec := a.requestRaw(tok, in)
				requireStatus(t, rec, http.StatusCreated)
				return decodeEnvelope[model.AccessRequest](t, rec)
			}
			keptRead := ask(demoAccountID, "read")
			otherRead := ask("6543210987654321", "read")
			full := ask("6543210987654321", "full")
			requireStatus(t, a.approve(ana, full.ID), http.StatusOK)
			pending := ask(demoAccountID, "write")
			if keptRead.Status != model.LeaseActive || otherRead.Status != model.LeaseActive || a.status(full.ID) != model.LeaseActive || pending.Status != model.LeasePending {
				t.Fatalf("setup = %s/%s/%s/%s", keptRead.Status, otherRead.Status, a.status(full.ID), pending.Status)
			}

			path := "/api/v1/supervisor/people/" + ana.person.ID
			switch how {
			case "flag removed":
				no := false
				requireStatus(t, a.sup.do(http.MethodPatch, path, model.UpdatePersonInput{Supervisor: &no}), http.StatusOK)
			case "suspended":
				suspended := model.PersonSuspended
				requireStatus(t, a.sup.do(http.MethodPatch, path, model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
			case "reset":
				requireStatus(t, a.sup.do(http.MethodPost, path+"/reset", nil), http.StatusOK)
			}
			for name, id := range map[string]string{"read on the other account": otherRead.ID, "full": full.ID, "waiting write": pending.ID} {
				if got := a.status(id); got != model.LeaseRevoked {
					t.Errorf("%s after %s = %s, want revoked", name, how, got)
				}
			}
			wantKept := model.LeaseRevoked
			if how == "flag removed" {
				wantKept = model.LeaseActive // the guest role given by name still allows it
			}
			if got := a.status(keptRead.ID); got != wantKept {
				t.Errorf("read on the account with a role by name after %s = %s, want %s", how, got, wantKept)
			}
			// Nothing new beyond what is left.
			in := model.AccessRequestInput{CloudAccountID: "6543210987654321", Resource: "ecs", Permission: "read", TTLSeconds: 600}
			if code := a.requestRaw(tok, in).Code; code != http.StatusForbidden {
				t.Errorf("a new request on the other account after %s = %d", how, code)
			}
			if rec := a.do(http.MethodPost, "/api/v1/agent/leases/"+full.ID+"/credential", tok, nil); rec.Code == http.StatusOK {
				t.Errorf("the full credential was handed out after %s", how)
			}
		})
	}
}

// Expiry and startup revocations name the agent and its owner.
func TestSystemEventsNameTheAgentAndOwner(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	req := a.request(accessInput("ecs", "read"))
	a.clock.Advance(11 * time.Minute)
	a.srv.sweepOnce(context.Background())
	if a.status(req.ID) != model.LeaseExpired {
		t.Fatalf("status = %s", a.status(req.ID))
	}
	m := a.lastEvent("lease.expired").Metadata
	if m["agent_id"] != a.agent.ID || m["agent_name"] != a.agent.Name || m["owner_id"] != a.mei.person.ID {
		t.Fatalf("lease.expired metadata = %+v", m)
	}
}

// A path that matches no route is 404 for every method; under the
// authenticated prefixes the caller is authenticated first.
func TestUnknownPathsForEveryMethod(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, method := range methods {
		for _, path := range []string{"/api/v1/admin/login", "/api/v1/admin/agents/x", "/api/v1/nope", "/api", "/api/v2/agent/me"} {
			if code := a.do(method, path, "", nil).Code; code != http.StatusNotFound {
				t.Errorf("%s %s without credentials = %d, want 404", method, path, code)
			}
			if code := a.sup.do(method, path, nil).Code; code != http.StatusNotFound {
				t.Errorf("%s %s as a supervisor = %d, want 404", method, path, code)
			}
		}
		for _, path := range []string{"/api/v1/agent/nope", "/api/v1/me/nope", "/api/v1/supervisor/nope", "/api/v1/agent/capabilities"} {
			if code := a.do(method, path, "", nil).Code; code != http.StatusUnauthorized {
				t.Errorf("%s %s without credentials = %d, want 401", method, path, code)
			}
		}
		if code := a.do(method, "/api/v1/agent/nope", a.token, nil).Code; code != http.StatusNotFound {
			t.Errorf("%s /api/v1/agent/nope as an agent = %d, want 404", method, code)
		}
	}
	// Writes still need the CSRF token before the route is looked at.
	if code := a.testEnv.request(http.MethodPost, "/api/v1/supervisor/nope", a.sup.cookie, nil, nil).Code; code != http.StatusForbidden {
		t.Errorf("POST without the CSRF token = %d, want 403", code)
	}
}

// ---- regression tests for the second review round (commit dfb2b7a) ----

// A real v0.1 directory that never stored a secret: no key check (it did not
// exist yet), no cloud account, no person. Serve-first and recover-first must
// both end with a supervisor, exactly one upgrade record and a key check.
func TestEmptyV01InstallCanBeRecoveredEitherWay(t *testing.T) {
	ctx := context.Background()
	for _, order := range []string{"serve first", "recover first"} {
		t.Run(order, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := Init(ctx, InitOptions{DataDir: dir}); err != nil { // no --demo: no cloud account
				t.Fatal(err)
			}
			downgradeToV1(t, dir)
			rawExec(t, dir, `DELETE FROM persons`, `DELETE FROM audit`, `DELETE FROM meta WHERE key = 'vault_key_check'`,
				`INSERT INTO meta(key, value) VALUES('admin_token_hash', 'abc'), ('admin_token_prefix', 'csg_adm_abc')`)

			if order == "serve first" {
				for attempt := 1; attempt <= 2; attempt++ {
					if srv, err := New(Config{DataDir: dir}); !errors.Is(err, ErrNoSupervisor) {
						if srv != nil {
							srv.Close()
						}
						t.Fatalf("attempt %d: New = %v, want ErrNoSupervisor", attempt, err)
					}
				}
			}
			out, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: dir, Username: "root"})
			if err != nil || out.SetupCode == "" {
				t.Fatalf("recover: %v", err)
			}
			srv, err := New(Config{DataDir: dir})
			if err != nil {
				t.Fatalf("New after recovery: %v", err)
			}
			defer srv.Close()
			if migrated := srv.listAuditFor(t, "schema.migrated"); len(migrated) != 1 || migrated[0].Metadata["deleted_admin_token"] != true {
				t.Fatalf("schema.migrated = %+v", migrated)
			}
			if _, err := srv.db.GetMeta(ctx, store.MetaVaultKeyCheck); err != nil {
				t.Fatalf("no key check after recovery: %v", err)
			}
			if res, err := srv.db.VerifyAudit(ctx); err != nil || !res.OK {
				t.Fatalf("audit chain = %+v, %v", res, err)
			}
			// From now on a wrong key is refused.
			if _, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: dir, Username: "root", MasterKey: make([]byte, 32)}); !errors.Is(err, errWrongMasterKey) {
				t.Fatalf("wrong key after recovery: %v", err)
			}
		})
	}
}

// A 7 -> 8 upgrade that had no admin token says so.
func TestUpgradeRecordSaysWhenNoAdminTokenWasDeleted(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(context.Background(), InitOptions{DataDir: dir}); err != nil {
		t.Fatal(err)
	}
	rawExec(t, dir, `UPDATE meta SET value = '7' WHERE key = 'schema_version'`)
	srv, err := New(Config{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	migrated := srv.listAuditFor(t, "schema.migrated")
	if len(migrated) != 1 {
		t.Fatalf("schema.migrated events = %d", len(migrated))
	}
	if v, ok := migrated[0].Metadata["deleted_admin_token"]; !ok || v != false {
		t.Fatalf("deleted_admin_token = %v (present %v), want false", v, ok)
	}
}

// Init creates nothing when $CSG_MASTER_KEY is unusable, and never removes
// something that was there before it, a dangling symlink included.
func TestInitLeavesNoTraceAndRemovesOnlyItsOwnFiles(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	for _, bad := range []string{"not-base64!!", "c2hvcnQ="} {
		t.Setenv("CSG_MASTER_KEY", bad)
		dir := filepath.Join(parent, "new-"+bad[:3])
		if _, err := Init(ctx, InitOptions{DataDir: dir}); err == nil {
			t.Fatalf("Init accepted CSG_MASTER_KEY=%q", bad)
		}
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a refused Init created %s", dir)
		}
	}
	t.Setenv("CSG_MASTER_KEY", "")

	// A dangling master.key symlink is someone else's: Init refuses, and it
	// is still there afterwards.
	linked := t.TempDir()
	link := filepath.Join(linked, "master.key")
	if err := os.Symlink(filepath.Join(linked, "elsewhere", "key"), link); err != nil {
		t.Skip("symlinks are not available")
	}
	if _, err := Init(ctx, InitOptions{DataDir: linked}); err == nil {
		t.Fatal("Init ran over a dangling master.key symlink")
	}
	if _, err := os.Lstat(link); err != nil {
		t.Fatalf("Init removed a symlink it did not create: %v", err)
	}

	// A failure removes the directory Init made, and leaves a directory
	// that existed, with the files that were in it.
	old := bootstrapHook
	bootstrapHook = func() error { return errors.New("injected failure") }
	defer func() { bootstrapHook = old }()
	made := filepath.Join(parent, "made-by-init")
	if _, err := Init(ctx, InitOptions{DataDir: made}); err == nil {
		t.Fatal("the injected failure did not fail Init")
	}
	if _, err := os.Lstat(made); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed Init left the directory it created: %v", err)
	}
	existing := t.TempDir()
	notes := filepath.Join(existing, "notes.txt")
	if err := os.WriteFile(notes, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(ctx, InitOptions{DataDir: existing}); err == nil {
		t.Fatal("the injected failure did not fail Init")
	}
	entries, _ := os.ReadDir(existing)
	if data, err := os.ReadFile(notes); err != nil || string(data) != "mine" || len(entries) != 1 {
		t.Fatalf("a failed Init changed an existing directory: %d entries, %v", len(entries), err)
	}
}

// A connection test or a key rotation in flight writes only its own fields:
// it must not put back the status or role ARN it read before a supervisor
// changed them.
func TestTestAndRotateDoNotUndoAConcurrentEdit(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	account := "/api/v1/supervisor/accounts/" + a.providerID
	active := a.request(accessInput("ecs", "read"))

	// The account is disabled while its connection test is running.
	a.minter.onTest = func() {
		requireStatus(t, a.sup.do(http.MethodPatch, account, map[string]any{"status": "disabled", "name": "renamed"}), http.StatusOK)
	}
	rec := a.sup.do(http.MethodPost, account+"/test", nil)
	requireStatus(t, rec, http.StatusOK)
	a.minter.onTest = nil
	got, err := a.srv.db.GetProvider(context.Background(), a.providerID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != model.ProviderDisabled || got.Name != "renamed" {
		t.Fatalf("the test's write undid the edit: status %s, name %q", got.Status, got.Name)
	}
	if got.LastTestOK == nil || !*got.LastTestOK {
		t.Fatalf("the test result was not recorded: %+v", got.LastTestOK)
	}
	if a.status(active.ID) != model.LeaseRevoked {
		t.Fatalf("credential of a disabled account = %s", a.status(active.ID))
	}
	requireStatus(t, a.requestRaw(a.token, accessInput("ecs", "read")), http.StatusConflict)

	// A rotation keeps it disabled too, and returns the row as it is now.
	rec = a.sup.do(http.MethodPost, account+"/rotate", model.RotateProviderCredentialInput{AccessKeyID: "LTAI5tRotatedKeyId88", AccessKeySecret: "rotated-secret-value"})
	requireStatus(t, rec, http.StatusOK)
	if p := decodeEnvelope[model.Provider](t, rec); p.Status != model.ProviderDisabled || p.Name != "renamed" || p.AccessKeyIDMasked == got.AccessKeyIDMasked {
		t.Fatalf("after rotation: %+v", p)
	}
	if after, _ := a.srv.db.GetProvider(context.Background(), a.providerID); after.Status != model.ProviderDisabled || after.RoleARN != got.RoleARN {
		t.Fatalf("a rotation changed status or role ARN: %+v", after)
	}
}

// A refused repair changes nothing, roles included, and is recorded; a role
// cannot be given on a provider that has no cloud account yet.
func TestRefusedRepairKeepsRolesAndUnconnectedAccountTakesNoRoles(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	rec := a.sup.do(http.MethodPost, "/api/v1/supervisor/accounts", newMockAccount("second", "6543210987654321"))
	requireStatus(t, rec, http.StatusCreated)
	second := decodeEnvelope[model.Provider](t, rec)
	account := "/api/v1/supervisor/accounts/" + second.ID
	binding := account + "/people/" + a.mei.person.ID
	requireStatus(t, a.sup.do(http.MethodPut, binding, model.PutBindingInput{Role: model.RoleAdministrator}), http.StatusOK)
	if _, err := a.srv.db.SQL().Exec(`UPDATE providers SET cloud_account_id = '', role_arn = 'not-a-role' WHERE id = ?`, second.ID); err != nil {
		t.Fatal(err)
	}

	taken := "acs:ram::" + demoAccountID + ":role/cloud-safeguard"
	requireStatus(t, a.sup.do(http.MethodPatch, account, model.UpdateProviderInput{RoleARN: &taken}), http.StatusConflict)
	if b, err := a.srv.db.GetBinding(context.Background(), a.mei.person.ID, second.ID); err != nil || b.Role != model.RoleAdministrator {
		t.Fatalf("a refused repair removed or changed the role: %+v, %v", b, err)
	}
	if got, _ := a.srv.db.GetProvider(context.Background(), second.ID); got.CloudAccountID != "" || got.RoleARN != "not-a-role" {
		t.Fatalf("a refused repair changed the account: %+v", got)
	}
	refused := a.lastEvent("provider.update_refused")
	a.requireActor(refused, a.sup)
	if refused.TargetID != second.ID || refused.Metadata["cloud_account_id"] != demoAccountID {
		t.Fatalf("refusal event = %+v", refused)
	}

	// No new role while it is not connected, for anyone.
	requireErrorCode(t, a.sup.do(http.MethodPut, binding, model.PutBindingInput{Role: model.RoleGuest}), http.StatusConflict, model.ErrCodeConflict)
	jun := a.addPerson(a.sup, "jun", false)
	requireErrorCode(t, a.sup.do(http.MethodPut, account+"/people/"+jun.person.ID, model.PutBindingInput{Role: model.RoleGuest}), http.StatusConflict, model.ErrCodeConflict)
	if _, err := a.srv.db.GetBinding(context.Background(), jun.person.ID, second.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a role was written on an unconnected account: %v", err)
	}

	// The repair removes the old role and says whose it was.
	free := "acs:ram::7777777777777777:role/cloud-safeguard"
	requireStatus(t, a.sup.do(http.MethodPatch, account, model.UpdateProviderInput{RoleARN: &free}), http.StatusOK)
	ev := a.lastEvent("provider.updated")
	raw, _ := json.Marshal(ev.Metadata)
	for _, want := range []string{"removed_role_bindings", a.mei.person.ID, `"mei"`, "administrator", "7777777777777777"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("provider.updated does not record %s: %s", want, raw)
		}
	}
	// Connected now: roles can be given again.
	requireStatus(t, a.sup.do(http.MethodPut, binding, model.PutBindingInput{Role: model.RoleGuest}), http.StatusOK)
}

// Two approvals at once never put an agent above the limit on active
// credentials, including a limit that was lowered after the requests were made.
func TestParallelApprovalsRespectTheLimit(t *testing.T) {
	for round := 0; round < 5; round++ {
		a := newAccessEnv(t, model.RoleMember)
		settings := model.DefaultPolicySettings()
		settings.MaxConcurrentLeasesPerAgent = 5
		requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/settings", settings), http.StatusOK)
		a.request(accessInput("ecs", "read"))
		a.request(accessInput("oss", "read"))
		first := a.request(accessInput("ecs", "write"))
		second := a.request(accessInput("oss", "write"))
		settings.MaxConcurrentLeasesPerAgent = 3
		requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/settings", settings), http.StatusOK)

		codes := make(chan int, 2)
		start := make(chan struct{})
		for _, id := range []string{first.ID, second.ID} {
			go func() {
				<-start
				codes <- a.approve(a.mei, id).Code
			}()
		}
		close(start)
		x, y := <-codes, <-codes
		if !((x == http.StatusOK && y == http.StatusConflict) || (x == http.StatusConflict && y == http.StatusOK)) {
			t.Fatalf("round %d: approvals = %d, %d; want one 200 and one 409", round, x, y)
		}
		active, err := a.srv.db.CountActiveLeases(context.Background(), a.agent.ID)
		if err != nil || active != 3 {
			t.Fatalf("round %d: %d active credentials under a limit of 3 (%v)", round, active, err)
		}
		if n := a.minter.requestCount(); n != 3 {
			t.Fatalf("round %d: minted %d times, want 3", round, n)
		}
	}
}

// What an agent and its owner are shown as limits is what is enforced now.
func TestShownLimitsAreTheCurrentSettings(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	settings := model.DefaultPolicySettings()
	settings.MaxLeaseTTLSeconds, settings.MaxConcurrentLeasesPerAgent = 1800, 1
	requireStatus(t, a.sup.do(http.MethodPut, "/api/v1/supervisor/settings", settings), http.StatusOK)

	rec := a.do(http.MethodGet, "/api/v1/agent/me", a.token, nil)
	requireStatus(t, rec, http.StatusOK)
	me := decodeEnvelope[struct {
		Agent model.Agent `json:"agent"`
	}](t, rec).Agent
	if me.MaxTTLSeconds != 1800 || me.MaxConcurrentLeases != 1 {
		t.Fatalf("agent/me limits = %d s, %d; want 1800, 1", me.MaxTTLSeconds, me.MaxConcurrentLeases)
	}
	rec = a.mei.do(http.MethodGet, "/api/v1/me/agents", nil)
	requireStatus(t, rec, http.StatusOK)
	mine := decodeEnvelope[listData[model.Agent]](t, rec)
	if mine.Total != 1 || mine.Items[0].MaxTTLSeconds != 1800 || mine.Items[0].MaxConcurrentLeases != 1 {
		t.Fatalf("me/agents limits = %+v", mine.Items)
	}
	// And they are enforced.
	in := accessInput("ecs", "read")
	in.TTLSeconds = 1801
	requireStatus(t, a.requestRaw(a.token, in), http.StatusBadRequest)
}

// Revocations at startup and by local recovery name the agent and its owner,
// one event per credential.
func TestStartupAndRecoveryRevocationsNameAgentAndOwner(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	agent, _, lease := env.ownedAgentWithLease(mei, "mei-agent")
	if _, err := env.srv.db.SQL().Exec(`UPDATE persons SET status = 'suspended' WHERE id = ?`, mei.person.ID); err != nil {
		t.Fatal(err)
	}
	env.restart()
	var startup *model.AuditEvent
	for _, ev := range env.listAudit("lease.revoked") {
		if ev.TargetID == lease.ID {
			startup = &ev
		}
	}
	if startup == nil || startup.Metadata["agent_id"] != agent.ID || startup.Metadata["agent_name"] != agent.Name ||
		startup.Metadata["owner_id"] != mei.person.ID || startup.Metadata["caused_by"] != "startup check" {
		t.Fatalf("startup revocation = %+v", startup)
	}

	// Local recovery of a supervisor who has an agent with a credential.
	supAgent, _ := env.signInAgent(sup, "sup-agent")
	leases, err := env.srv.db.ListAllLeases(ctx, store.LeaseFilter{AgentID: supAgent.ID})
	if err != nil || len(leases) != 0 {
		t.Fatalf("precondition: %d leases, %v", len(leases), err)
	}
	now := env.clock.Now()
	expires := now.Add(10 * time.Minute)
	held := lease
	held.ID, held.AgentID, held.AgentName = "lea_sup_held", supAgent.ID, supAgent.Name
	held.Status, held.CreatedAt, held.IssuedAt, held.ExpiresAt = model.LeaseActive, now, &now, &expires
	held.RevokedAt, held.RevokeReason = nil, ""
	if err := env.srv.db.CreateLease(ctx, held); err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverSupervisor(ctx, RecoverOptions{DataDir: env.dir, Username: sup.person.Username}); err != nil {
		t.Fatal(err)
	}
	var recovered *model.AuditEvent
	for _, ev := range env.listAudit("lease.revoked") {
		if ev.TargetID == held.ID {
			recovered = &ev
		}
	}
	if recovered == nil || recovered.Metadata["agent_id"] != supAgent.ID || recovered.Metadata["owner_id"] != sup.person.ID ||
		recovered.Metadata["caused_by"] != "csg supervisor recover" || recovered.ActorType != "system" {
		t.Fatalf("recovery revocation = %+v", recovered)
	}
	if got := env.getLease(held.ID); got.Status != model.LeaseRevoked {
		t.Fatalf("credential after recovery = %s", got.Status)
	}
	env.verifyAudit()
}
