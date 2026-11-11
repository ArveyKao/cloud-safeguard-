package store

import (
	"context"
	"errors"
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
	if err := db.ResetPersonSetup(ctx, "root", "new", peopleNow.Add(time.Hour), peopleNow, true); !errors.Is(err, ErrLastSupervisor) {
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
	if err := db.ResetPersonSetup(ctx, "mei", "recovery", peopleNow.Add(time.Hour), peopleNow, false); err != nil {
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
	if err := db.ResetPersonSetup(ctx, "root", "again", peopleNow.Add(time.Hour), peopleNow, false); err != nil {
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
