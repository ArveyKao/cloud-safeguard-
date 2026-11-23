package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

func newSignIn(t *testing.T, db *DB, id string) SignIn {
	t.Helper()
	s := SignIn{ID: id, DeviceCodeHash: "dev-" + id, UserCode: "U" + id, AgentName: "bot", RemoteAddr: "10.0.0.1",
		CreatedAt: peopleNow, ExpiresAt: peopleNow.Add(10 * time.Minute)}
	if err := db.CreateSignIn(context.Background(), s, 100, 100); err != nil {
		t.Fatal(err)
	}
	return s
}

func signInTestAgent(id string) model.Agent {
	return model.Agent{ID: id, Name: "bot", Status: model.AgentActive, Role: model.RoleGuest, Grants: []string{},
		MaxTTLSeconds: 900, MaxConcurrentLeases: 1, CreatedAt: peopleNow, UpdatedAt: peopleNow}
}

func TestDecideSignInIsCompareAndSet(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "root", true)
	activate(t, db, "root")
	newPerson(t, db, "mei", false)
	activate(t, db, "mei")
	newPerson(t, db, "pending", false)

	s := newSignIn(t, db, "a")
	if err := db.DecideSignIn(ctx, "a", "mei", model.SignInPending, peopleNow); err == nil {
		t.Fatal("pending accepted as a decision")
	}
	// Only an active person can decide.
	for _, who := range []string{"pending", "nobody"} {
		if err := db.DecideSignIn(ctx, "a", who, model.SignInApproved, peopleNow); !errors.Is(err, ErrConflict) {
			t.Fatalf("decision by %s: %v", who, err)
		}
	}
	// Not after expiry.
	if err := db.DecideSignIn(ctx, "a", "mei", model.SignInApproved, s.ExpiresAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("approval at expiry: %v", err)
	}
	if err := db.DecideSignIn(ctx, "a", "mei", model.SignInDenied, peopleNow); err != nil {
		t.Fatal(err)
	}
	// A decision is final: a denial cannot be turned into an approval, and
	// nobody else can take the sign-in over.
	for _, who := range []string{"mei", "root"} {
		if err := db.DecideSignIn(ctx, "a", who, model.SignInApproved, peopleNow); !errors.Is(err, ErrConflict) {
			t.Fatalf("re-decision by %s: %v", who, err)
		}
	}
	if _, _, err := db.CompleteSignIn(ctx, "a", signInTestAgent("agt_1"), "h1", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("denied sign-in completed: %v", err)
	}
}

func TestCompleteSignInIssuesOnceToAnActiveOwner(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "root", true)
	activate(t, db, "root")
	newPerson(t, db, "mei", false)
	activate(t, db, "mei")

	// Pending and expired sign-ins cannot be completed.
	newSignIn(t, db, "p")
	if _, _, err := db.CompleteSignIn(ctx, "p", signInTestAgent("agt_p"), "hp", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("pending sign-in completed: %v", err)
	}
	e := newSignIn(t, db, "e")
	if err := db.DecideSignIn(ctx, "e", "mei", model.SignInApproved, peopleNow); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.CompleteSignIn(ctx, "e", signInTestAgent("agt_e"), "he", e.ExpiresAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired sign-in completed: %v", err)
	}

	ag, replaced, err := db.CompleteSignIn(ctx, "e", signInTestAgent("agt_1"), "h1", peopleNow)
	if err != nil || ag.OwnerID != "mei" || len(replaced) != 0 {
		t.Fatalf("complete: %+v %v %v", ag, replaced, err)
	}
	if _, _, err := db.CompleteSignIn(ctx, "e", signInTestAgent("agt_2"), "h2", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("second completion: %v", err)
	}
	if _, err := db.GetAgent(ctx, "agt_2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a refused completion left an agent behind: %v", err)
	}
	if got, err := db.GetAgentByTokenHash(ctx, "h1"); err != nil || got.ID != "agt_1" || got.OwnerID != "mei" {
		t.Fatalf("stored agent: %+v, %v", got, err)
	}

	// The approver was suspended before pickup: no agent.
	newSignIn(t, db, "s")
	if err := db.DecideSignIn(ctx, "s", "mei", model.SignInApproved, peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPersonAuthority(ctx, "mei", model.PersonSuspended, false, peopleNow); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.CompleteSignIn(ctx, "s", signInTestAgent("agt_3"), "h3", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("completion for a suspended owner: %v", err)
	}
}

func TestSignInLimitsAndCleanup(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	mk := func(id, addr string, total, perAddr int) error {
		return db.CreateSignIn(ctx, SignIn{ID: id, DeviceCodeHash: "d" + id, UserCode: "U" + id, AgentName: "bot",
			RemoteAddr: addr, CreatedAt: peopleNow, ExpiresAt: peopleNow.Add(time.Minute)}, total, perAddr)
	}
	if err := mk("1", "a", 3, 2); err != nil {
		t.Fatal(err)
	}
	if err := mk("2", "a", 3, 2); err != nil {
		t.Fatal(err)
	}
	if err := mk("3", "a", 3, 2); !errors.Is(err, ErrSignInLimit) {
		t.Fatalf("per-address limit: %v", err)
	}
	if err := mk("3", "b", 3, 2); err != nil {
		t.Fatal(err)
	}
	if err := mk("4", "c", 3, 2); !errors.Is(err, ErrSignInLimit) {
		t.Fatalf("total limit: %v", err)
	}
	// Colliding codes are a conflict, not a limit.
	if err := db.CreateSignIn(ctx, SignIn{ID: "9", DeviceCodeHash: "d9", UserCode: "U1", AgentName: "bot",
		RemoteAddr: "z", CreatedAt: peopleNow, ExpiresAt: peopleNow.Add(time.Minute)}, 100, 100); !errors.Is(err, ErrConflict) {
		t.Fatalf("user code collision: %v", err)
	}
	if err := db.DeleteOldSignIns(ctx, peopleNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetSignInByUserCode(ctx, "U1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired sign-in kept: %v", err)
	}
}
