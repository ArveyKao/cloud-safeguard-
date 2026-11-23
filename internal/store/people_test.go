package store

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

var peopleNow = time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)

// newPerson inserts a pending person whose setup code hash is "code-"+id.
func newPerson(t *testing.T, db *DB, id string, supervisor bool) {
	t.Helper()
	p := model.Person{ID: id, Username: id, Supervisor: supervisor, CreatedAt: peopleNow, UpdatedAt: peopleNow}
	if err := db.CreatePerson(context.Background(), p, "code-"+id, peopleNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// activate runs setup for a person created by newPerson.
func activate(t *testing.T, db *DB, id string) {
	t.Helper()
	ctx := context.Background()
	if err := db.BeginPersonSetup(ctx, id, "code-"+id, "hash", "enc", peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.FinishPersonSetup(ctx, id, "code-"+id, 100, peopleNow); err != nil {
		t.Fatal(err)
	}
}

func TestPersonSetupIsCompareAndSet(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "mei", false)

	if err := db.CreatePerson(ctx, model.Person{ID: "other", Username: "mei"}, "x", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate username: %v", err)
	}
	// Wrong code, expired code and finishing before begin are all refused.
	if err := db.BeginPersonSetup(ctx, "mei", "wrong", "hash", "enc", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong code: %v", err)
	}
	if err := db.BeginPersonSetup(ctx, "mei", "code-mei", "hash", "enc", peopleNow.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired code at begin: %v", err)
	}
	if err := db.FinishPersonSetup(ctx, "mei", "code-mei", 1, peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("finish before begin: %v", err)
	}
	if err := db.BeginPersonSetup(ctx, "mei", "code-mei", "hash", "enc", peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.FinishPersonSetup(ctx, "mei", "code-mei", 1, peopleNow.Add(time.Hour)); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired code at finish: %v", err)
	}
	if err := db.FinishPersonSetup(ctx, "mei", "wrong", 1, peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong code at finish: %v", err)
	}
	if err := db.FinishPersonSetup(ctx, "mei", "code-mei", 7, peopleNow); err != nil {
		t.Fatal(err)
	}
	// The code is consumed: neither step works again.
	if err := db.FinishPersonSetup(ctx, "mei", "code-mei", 8, peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("second finish: %v", err)
	}
	if err := db.BeginPersonSetup(ctx, "mei", "code-mei", "hash2", "enc2", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("begin after finish: %v", err)
	}
	if _, err := db.GetPersonBySetupCodeHash(ctx, "code-mei"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("consumed code still resolves: %v", err)
	}
	if _, err := db.GetPersonBySetupCodeHash(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty hash resolved a person: %v", err)
	}
	auth, err := db.GetPersonAuth(ctx, "mei")
	if err != nil || auth.TOTPLastStep != 7 || auth.PasswordHash != "hash" || auth.SetupCodeHash != "" {
		t.Fatalf("auth after setup = %+v, %v", auth, err)
	}
}

func TestAcceptLoginConsumesStepAndNeedsActive(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "root", true)
	activate(t, db, "root")
	newPerson(t, db, "mei", false)
	activate(t, db, "mei") // last step 100

	for _, step := range []int64{100, 99} {
		if err := db.AcceptLogin(ctx, "mei", step, peopleNow); !errors.Is(err, ErrConflict) {
			t.Fatalf("step %d accepted: %v", step, err)
		}
	}
	if err := db.AcceptLogin(ctx, "mei", 101, peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPersonAuthority(ctx, "mei", model.PersonSuspended, false, peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.AcceptLogin(ctx, "mei", 102, peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("suspended person logged in: %v", err)
	}
	// A suspended person's setup cannot be resumed either.
	if err := db.BeginPersonSetup(ctx, "mei", "", "h", "e", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("begin with empty code: %v", err)
	}
}

func TestLoginFailureLock(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "mei", false)
	activate(t, db, "mei")
	for i := 0; i < 2; i++ {
		if err := db.RecordLoginFailure(ctx, "mei", peopleNow, 3, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if auth, _ := db.GetPersonAuth(ctx, "mei"); auth.LockedUntil != nil || auth.FailedLogins != 2 {
		t.Fatalf("locked too early: %+v", auth)
	}
	_ = db.RecordLoginFailure(ctx, "mei", peopleNow, 3, time.Minute)
	auth, _ := db.GetPersonAuth(ctx, "mei")
	if auth.LockedUntil == nil || !auth.LockedUntil.Equal(peopleNow.Add(time.Minute)) || auth.FailedLogins != 0 {
		t.Fatalf("not locked at threshold: %+v", auth)
	}
	if err := db.AcceptLogin(ctx, "mei", 200, peopleNow); err != nil {
		t.Fatal(err)
	}
	if auth, _ := db.GetPersonAuth(ctx, "mei"); auth.LockedUntil != nil {
		t.Fatal("success did not clear the lock")
	}
}

func TestAuthorityChangesAndSessions(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "root", true)
	activate(t, db, "root")
	newPerson(t, db, "mei", false)
	activate(t, db, "mei")
	session := func(person, hash string) {
		t.Helper()
		err := db.CreateSession(ctx, Session{TokenHash: hash, PersonID: person, CSRFToken: "c",
			CreatedAt: peopleNow, LastSeenAt: peopleNow, ExpiresAt: peopleNow.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
	}
	alive := func(hash string) bool { _, err := db.GetSession(ctx, hash); return err == nil }
	session("mei", "s1")
	session("mei", "s2")
	session("root", "r1")

	// The only active supervisor cannot be suspended, demoted or reset.
	if err := db.SetPersonAuthority(ctx, "root", model.PersonSuspended, true, peopleNow); !errors.Is(err, ErrLastSupervisor) {
		t.Fatalf("suspend last supervisor: %v", err)
	}
	if err := db.SetPersonAuthority(ctx, "root", model.PersonActive, false, peopleNow); !errors.Is(err, ErrLastSupervisor) {
		t.Fatalf("demote last supervisor: %v", err)
	}
	if err := db.ResetPersonSetup(ctx, "root", "new", peopleNow.Add(time.Hour), peopleNow, true, testIssue); !errors.Is(err, ErrLastSupervisor) {
		t.Fatalf("reset last supervisor: %v", err)
	}
	if !alive("r1") {
		t.Fatal("a refused change deleted sessions")
	}
	if err := db.SetPersonAuthority(ctx, "root", model.PersonPending, true, peopleNow); err == nil {
		t.Fatal("pending accepted as a target status")
	}
	if err := db.SetPersonAuthority(ctx, "nobody", model.PersonSuspended, false, peopleNow); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown person: %v", err)
	}

	// Suspending ends every session of that person only.
	if err := db.SetPersonAuthority(ctx, "mei", model.PersonSuspended, false, peopleNow); err != nil {
		t.Fatal(err)
	}
	if alive("s1") || alive("s2") || !alive("r1") {
		t.Fatal("suspend did not end exactly that person's sessions")
	}
	// With a second active supervisor the first can step down.
	if err := db.SetPersonAuthority(ctx, "mei", model.PersonActive, true, peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPersonAuthority(ctx, "root", model.PersonActive, false, peopleNow); err != nil {
		t.Fatal(err)
	}
	if n, _ := db.CountActiveSupervisors(ctx); n != 1 {
		t.Fatalf("active supervisors = %d", n)
	}

	// Reset without the guard (local recovery) clears credentials and sessions.
	session("mei", "s3")
	if err := db.ResetPersonSetup(ctx, "mei", "recovery", peopleNow.Add(time.Hour), peopleNow, false, testIssue); err != nil {
		t.Fatal(err)
	}
	auth, _ := db.GetPersonAuth(ctx, "mei")
	p, _ := db.GetPerson(ctx, "mei")
	if alive("s3") || auth.PasswordHash != "" || auth.TOTPSecretEnc != "" || auth.TOTPLastStep != -1 || p.Status != model.PersonPending {
		t.Fatalf("reset left state behind: %+v %+v", auth, p)
	}
	// A pending person cannot be switched to active.
	if err := db.SetPersonAuthority(ctx, "mei", model.PersonActive, true, peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("activate pending: %v", err)
	}
}

func TestStaleSessionsAreDeleted(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	mk := func(hash string, lastSeen, expires time.Time) {
		if err := db.CreateSession(ctx, Session{TokenHash: hash, PersonID: "p", CSRFToken: "c",
			CreatedAt: lastSeen, LastSeenAt: lastSeen, ExpiresAt: expires}); err != nil {
			t.Fatal(err)
		}
	}
	newPerson(t, db, "p", false)
	activate(t, db, "p")
	mk("fresh", peopleNow, peopleNow.Add(time.Hour))
	mk("idle", peopleNow.Add(-31*time.Minute), peopleNow.Add(time.Hour))
	mk("expired", peopleNow, peopleNow)
	if err := db.DeleteStaleSessions(ctx, peopleNow, 30*time.Minute); err != nil {
		t.Fatal(err)
	}
	for hash, want := range map[string]bool{"fresh": true, "idle": false, "expired": false} {
		if _, err := db.GetSession(ctx, hash); (err == nil) != want {
			t.Errorf("session %s alive=%v, want %v", hash, err == nil, want)
		}
	}
}

func TestBindings(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	put := func(person, provider string, role model.Role) error {
		return db.PutBinding(ctx, model.RoleBinding{PersonID: person, ProviderID: provider, Role: role, CreatedBy: "root", CreatedAt: peopleNow, UpdatedAt: peopleNow})
	}
	if err := put("mei", "prod", "owner"); err == nil {
		t.Fatal("invalid role stored")
	}
	for _, b := range [][3]string{{"mei", "prod", "member"}, {"mei", "stage", "administrator"}, {"jun", "prod", "guest"}, {"mei", "prod", "guest"}} {
		if err := put(b[0], b[1], model.Role(b[2])); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := db.GetBinding(ctx, "mei", "prod"); err != nil || b.Role != model.RoleGuest {
		t.Fatalf("upsert: %+v, %v", b, err)
	}
	if _, err := db.GetBinding(ctx, "jun", "stage"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing binding: %v", err)
	}
	for _, c := range []struct {
		person, provider string
		want             int
	}{{"", "", 3}, {"mei", "", 2}, {"", "prod", 2}, {"jun", "stage", 0}} {
		if got, err := db.ListBindings(ctx, c.person, c.provider); err != nil || len(got) != c.want {
			t.Errorf("ListBindings(%q,%q) = %d, %v; want %d", c.person, c.provider, len(got), err, c.want)
		}
	}
	if err := db.DeleteBinding(ctx, "mei", "prod"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteBinding(ctx, "mei", "prod"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

func TestSessionNeedsAnActivePerson(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "root", true)
	activate(t, db, "root")
	newPerson(t, db, "pending", false)
	newPerson(t, db, "mei", false)
	activate(t, db, "mei")
	create := func(person string) error {
		return db.CreateSession(ctx, Session{TokenHash: "h-" + person, PersonID: person, CSRFToken: "c",
			CreatedAt: peopleNow, LastSeenAt: peopleNow, ExpiresAt: peopleNow.Add(time.Hour)})
	}
	if err := create("mei"); err != nil {
		t.Fatal(err)
	}
	for _, person := range []string{"pending", "nobody"} {
		if err := create(person); !errors.Is(err, ErrConflict) {
			t.Errorf("session for %s: %v", person, err)
		}
	}
	// After a suspend or reset has committed, no session can be created:
	// a login that verified just before cannot finish around it.
	if err := db.SetPersonAuthority(ctx, "mei", model.PersonSuspended, false, peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession(ctx, Session{TokenHash: "late", PersonID: "mei", CSRFToken: "c",
		CreatedAt: peopleNow, LastSeenAt: peopleNow, ExpiresAt: peopleNow.Add(time.Hour)}); !errors.Is(err, ErrConflict) {
		t.Fatalf("session after suspend: %v", err)
	}
	if err := db.ResetPersonSetup(ctx, "root", "again", peopleNow.Add(time.Hour), peopleNow, false, testIssue); err != nil {
		t.Fatal(err)
	}
	if err := create("root"); !errors.Is(err, ErrConflict) {
		t.Fatalf("session after reset: %v", err)
	}
}

func TestPendingSupervisorFlagOnlyWhilePending(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "mei", true)
	if err := db.SetPendingSupervisorFlag(ctx, "mei", false, peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPendingSupervisorFlag(ctx, "mei", true, peopleNow); err != nil {
		t.Fatal(err)
	}
	activate(t, db, "mei") // now the only active supervisor
	// A stale "still pending" decision must not demote an active supervisor.
	if err := db.SetPendingSupervisorFlag(ctx, "mei", false, peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("flag changed on an active person: %v", err)
	}
	if n, _ := db.CountActiveSupervisors(ctx); n != 1 {
		t.Fatalf("active supervisors = %d", n)
	}
}

// The schema-5 migration gives each cloud account to its oldest provider.
func TestCloudAccountIDMigration(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	db, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`ALTER TABLE persons DROP COLUMN setup_issued_by`,
		`ALTER TABLE persons DROP COLUMN setup_issued_by_name`,
		`ALTER TABLE persons DROP COLUMN setup_issued_kind`,
		`ALTER TABLE persons DROP COLUMN setup_issued_at`,
		`ALTER TABLE persons DROP COLUMN approval_mode`,
		`ALTER TABLE persons DROP COLUMN approval_mode_expires_at`,
		`ALTER TABLE providers DROP COLUMN max_auto_level`,
		`DROP INDEX idx_providers_cloud_account`,
		`ALTER TABLE providers DROP COLUMN cloud_account_id`,
		`INSERT INTO providers(id, name, type, mode, region, role_arn, status, created_at, updated_at) VALUES
			('p1', 'first',  'aliyun', 'sts',  'r', 'acs:ram::1111111111111111:role/a', 'active', 1, 1),
			('p2', 'second', 'aliyun', 'sts',  'r', 'acs:ram::1111111111111111:role/b', 'active', 2, 2),
			('p3', 'third',  'aliyun', 'sts',  'r', 'acs:ram::2222222222222222:role/c', 'active', 3, 3),
			('p4', 'no-arn', 'aliyun', 'mock', 'r', '',                                 'active', 4, 4)`,
		`UPDATE meta SET value = '4' WHERE key = 'schema_version'`,
	} {
		if _, err := db.SQL().Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	db.Close()

	db, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	want := map[string]string{"p1": "1111111111111111", "p2": "", "p3": "2222222222222222", "p4": ""}
	for id, account := range want {
		p, err := db.GetProvider(ctx, id)
		if err != nil || p.CloudAccountID != account {
			t.Errorf("%s: account %q, %v; want %q", id, p.CloudAccountID, err, account)
		}
	}
	if p, err := db.GetProviderByCloudAccountID(ctx, "1111111111111111"); err != nil || p.ID != "p1" {
		t.Fatalf("lookup = %+v, %v", p, err)
	}
	if _, err := db.GetProviderByCloudAccountID(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty account resolved: %v", err)
	}
	// The account stays unique afterwards.
	dup := model.Provider{ID: "p5", Name: "dup", Type: model.ProviderAliyun, Mode: model.ModeSTS, Status: model.ProviderActive,
		CloudAccountID: "2222222222222222", CreatedAt: peopleNow, UpdatedAt: peopleNow}
	if err := db.CreateProvider(ctx, dup, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate cloud account: %v", err)
	}
}

func addTestProvider(t *testing.T, db *DB, id string) {
	t.Helper()
	p := model.Provider{ID: id, Name: id, Type: model.ProviderAliyun, Mode: model.ModeMock, Status: model.ProviderActive,
		CreatedAt: peopleNow, UpdatedAt: peopleNow}
	if err := db.CreateProvider(context.Background(), p, ""); err != nil {
		t.Fatal(err)
	}
}

func bindTest(t *testing.T, db *DB, person, provider string) {
	t.Helper()
	if err := db.PutBinding(context.Background(), model.RoleBinding{PersonID: person, ProviderID: provider, Role: model.RoleMember,
		CreatedAt: peopleNow, UpdatedAt: peopleNow}); err != nil {
		t.Fatal(err)
	}
}

func TestAccountModeGuards(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "root", true)
	activate(t, db, "root")
	newPerson(t, db, "mei", false)
	addTestProvider(t, db, "p1")
	addTestProvider(t, db, "p2")
	mode := func(person, provider string) model.ApprovalMode {
		t.Helper()
		m, err := db.GetAccountMode(ctx, person, provider)
		if err != nil {
			t.Fatal(err)
		}
		return m.Effective(peopleNow)
	}
	// Only an active person with a role on the account.
	bindTest(t, db, "mei", "p1")
	if err := db.SetAccountMode(ctx, "mei", "p1", model.ModeFull, nil, peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("pending person: %v", err)
	}
	activate(t, db, "mei")
	if err := db.SetAccountMode(ctx, "mei", "p2", model.ModeFull, nil, peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("no role on the account: %v", err)
	}
	if err := db.SetAccountMode(ctx, "mei", "p1", "everything", nil, peopleNow); err == nil {
		t.Fatal("unknown mode stored")
	}
	until := peopleNow.Add(time.Hour)
	if err := db.SetAccountMode(ctx, "mei", "p1", model.ModeFull, &until, peopleNow); err != nil {
		t.Fatal(err)
	}
	if mode("mei", "p1") != model.ModeFull || mode("mei", "p2") != model.ModeRead {
		t.Fatal("modes are per account")
	}
	if m, _ := db.GetAccountMode(ctx, "mei", "p1"); m.Effective(until) != model.ModeRead {
		t.Fatal("an expired mode is still in effect")
	}
	// A supervisor has a role everywhere.
	if err := db.SetAccountMode(ctx, "root", "p2", model.ModeWrite, nil, peopleNow); err != nil {
		t.Fatal(err)
	}
	if all, err := db.ListAccountModes(ctx, "root"); err != nil || len(all) != 1 || all["p2"].Mode != model.ModeWrite {
		t.Fatalf("list %v %v", all, err)
	}
	// Setting read removes the row.
	if err := db.SetAccountMode(ctx, "root", "p2", model.ModeRead, nil, peopleNow); err != nil {
		t.Fatal(err)
	}
	if all, _ := db.ListAccountModes(ctx, "root"); len(all) != 0 {
		t.Fatalf("read kept a row: %v", all)
	}
	// Losing the role ends the mode there.
	if err := db.DeleteBinding(ctx, "mei", "p1"); err != nil {
		t.Fatal(err)
	}
	if mode("mei", "p1") != model.ModeRead {
		t.Fatal("mode survived the removal of the binding")
	}
	// Losing the supervisor flag ends modes on accounts without a binding.
	newPerson(t, db, "sup2", true)
	activate(t, db, "sup2")
	bindTest(t, db, "sup2", "p1")
	for _, prov := range []string{"p1", "p2"} {
		if err := db.SetAccountMode(ctx, "sup2", prov, model.ModeWrite, nil, peopleNow); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.SetPersonAuthority(ctx, "sup2", model.PersonActive, false, peopleNow); err != nil {
		t.Fatal(err)
	}
	if mode("sup2", "p1") != model.ModeWrite || mode("sup2", "p2") != model.ModeRead {
		t.Fatal("supervisor flag removal kept or dropped the wrong modes")
	}
	// A reset puts every mode back to read.
	if err := db.ResetPersonSetup(ctx, "sup2", "again", peopleNow.Add(time.Hour), peopleNow, false, testIssue); err != nil {
		t.Fatal(err)
	}
	if mode("sup2", "p1") != model.ModeRead {
		t.Fatal("mode survived a reset")
	}
}

// Schema 11 turns the single mode into a mode per account, lowered to each
// account's former level; nothing becomes more automatic.
func TestAccountModeMigration(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	db, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	// The migration drops modes expired by the real clock, so "future" must be
	// after both the wall clock and peopleNow.
	future, past := time.Now().Add(240*time.Hour).UnixMilli(), int64(1)
	for _, stmt := range []string{
		`DROP TABLE account_modes`,
		`ALTER TABLE leases DROP COLUMN refresh_until`,
		`ALTER TABLE leases DROP COLUMN refresh_count`,
		`INSERT INTO persons(id, username, status, supervisor, created_at, updated_at, approval_mode) VALUES
			('mei', 'mei', 'active', 0, 1, 1, 'full'), ('old', 'old', 'active', 0, 1, 1, 'full'),
			('sus', 'sus', 'suspended', 0, 1, 1, 'full'), ('sup', 'sup', 'active', 1, 1, 1, 'write')`,
		`UPDATE persons SET approval_mode_expires_at = ` + strconv.FormatInt(past, 10) + ` WHERE id = 'old'`,
		`UPDATE persons SET approval_mode_expires_at = ` + strconv.FormatInt(future, 10) + ` WHERE id = 'sup'`,
		`INSERT INTO providers(id, name, type, mode, region, role_arn, status, created_at, updated_at, cloud_account_id, max_auto_level) VALUES
			('pw', 'w', 'aliyun', 'mock', 'r', '', 'active', 1, 1, '', 'write'),
			('pf', 'f', 'aliyun', 'mock', 'r', '', 'active', 1, 1, '', 'full'),
			('pr', 'r', 'aliyun', 'mock', 'r', '', 'active', 1, 1, '', 'read'),
			('pn', 'n', 'aliyun', 'mock', 'r', '', 'active', 1, 1, '', 'full')`,
		`INSERT INTO role_bindings(person_id, provider_id, role, created_by, created_at, updated_at) VALUES
			('mei', 'pw', 'member', 'x', 1, 1), ('mei', 'pf', 'member', 'x', 1, 1), ('mei', 'pr', 'member', 'x', 1, 1),
			('old', 'pf', 'member', 'x', 1, 1), ('sus', 'pf', 'member', 'x', 1, 1)`,
		`UPDATE meta SET value = '10' WHERE key = 'schema_version'`,
	} {
		if _, err := db.SQL().Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	db.Close()
	db, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	want := map[[2]string]model.ApprovalMode{
		{"mei", "pw"}: model.ModeWrite, {"mei", "pf"}: model.ModeFull, {"mei", "pr"}: model.ModeRead, {"mei", "pn"}: model.ModeRead,
		{"old", "pf"}: model.ModeRead, {"sus", "pf"}: model.ModeRead,
		{"sup", "pw"}: model.ModeWrite, {"sup", "pf"}: model.ModeWrite, {"sup", "pr"}: model.ModeRead,
	}
	for k, w := range want {
		m, err := db.GetAccountMode(ctx, k[0], k[1])
		if err != nil || m.Effective(peopleNow) != w {
			t.Errorf("%v: got %q, want %q (%v)", k, m.Effective(peopleNow), w, err)
		}
	}
	if m, _ := db.GetAccountMode(ctx, "sup", "pf"); m.ExpiresAt == nil || m.ExpiresAt.UnixMilli() != future {
		t.Errorf("expiry not carried over: %+v", m)
	}
}

var testIssue = model.SetupIssue{ByID: "root", ByName: "root", Kind: model.SetupReset}

// Accounts set up before the issuer was recorded have none; a reset records it.
func TestSetupIssueStorage(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "root", true)
	activate(t, db, "root")
	if p, _ := db.GetPerson(ctx, "root"); p.SetupIssued != nil {
		t.Fatalf("issuer without one being recorded: %+v", p.SetupIssued)
	}
	at := peopleNow.Add(time.Minute)
	p := model.Person{ID: "jun", Username: "jun", CreatedAt: at, UpdatedAt: at,
		SetupIssued: &model.SetupIssue{ByID: "root", ByName: "root", Kind: model.SetupCreated, At: at}}
	if err := db.CreatePerson(ctx, p, "code-jun", at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ := db.GetPerson(ctx, "jun")
	if got.SetupIssued == nil || *got.SetupIssued != *p.SetupIssued {
		t.Fatalf("stored issuer = %+v", got.SetupIssued)
	}
	if err := db.ResetPersonSetup(ctx, "jun", "again", at.Add(time.Hour), at, false,
		model.SetupIssue{ByID: "system", ByName: "csg supervisor recover", Kind: model.SetupRecovered}); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetPerson(ctx, "jun")
	if got.SetupIssued == nil || got.SetupIssued.Kind != model.SetupRecovered || got.SetupIssued.ByID != "system" || !got.SetupIssued.At.Equal(at) {
		t.Fatalf("issuer after reset = %+v", got.SetupIssued)
	}
}
