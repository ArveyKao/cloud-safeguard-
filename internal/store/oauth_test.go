package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

func newOAuthRequest(t *testing.T, db *DB, id string) OAuthRequest {
	t.Helper()
	r := OAuthRequest{ID: id, ConnectHash: "ch-" + id, ClientID: "mcc_1", RedirectURI: "https://app.example/cb",
		CodeChallenge: "challenge", State: "s", RemoteAddr: "10.0.0.1", Issuer: "https://csg.example", CreatedAt: peopleNow, ExpiresAt: peopleNow.Add(10 * time.Minute)}
	if err := db.CreateOAuthRequest(context.Background(), r, 100, 100); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestOAuthClientRegistrationLimits(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	since := peopleNow.Add(-24 * time.Hour)
	add := func(id, addr string) error {
		return db.CreateOAuthClient(ctx, OAuthClient{ID: id, ClientName: "x", RedirectURIs: []string{"https://a.example/cb"},
			RemoteAddr: addr, CreatedAt: peopleNow}, since, 3, 2)
	}
	for _, c := range [][2]string{{"c1", "a"}, {"c2", "a"}} {
		if err := add(c[0], c[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := add("c3", "a"); !errors.Is(err, ErrOAuthLimit) {
		t.Fatalf("third from one address: %v", err)
	}
	if err := add("c3", "b"); err != nil {
		t.Fatal(err)
	}
	if err := add("c4", "c"); !errors.Is(err, ErrOAuthLimit) {
		t.Fatalf("over the total: %v", err)
	}
	got, err := db.GetOAuthClient(ctx, "c1")
	if err != nil || len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://a.example/cb" || got.LastUsedAt != nil {
		t.Fatalf("client %+v %v", got, err)
	}
	// Unused registrations go after the window; used ones stay.
	if _, err := db.sql.ExecContext(ctx, `UPDATE oauth_clients SET last_used_at = 1 WHERE id = 'c2'`); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteUnusedOAuthClients(ctx, peopleNow, time.UnixMilli(0)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetOAuthClient(ctx, "c1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unused client kept: %v", err)
	}
	if _, err := db.GetOAuthClient(ctx, "c2"); err != nil {
		t.Fatalf("used client removed: %v", err)
	}
	// A used client goes once it has been idle past the retention, unless a
	// kept request still refers to it.
	if err := add("c5", "d"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE oauth_clients SET last_used_at = 1 WHERE id = 'c5'`); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateOAuthRequest(ctx, OAuthRequest{ID: "r1", ConnectHash: "ch", ClientID: "c5", RedirectURI: "https://a.example/cb",
		CodeChallenge: "c", CreatedAt: peopleNow, ExpiresAt: peopleNow.Add(time.Minute)}, 10, 10); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteUnusedOAuthClients(ctx, peopleNow, time.UnixMilli(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetOAuthClient(ctx, "c2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("idle used client kept: %v", err)
	}
	if _, err := db.GetOAuthClient(ctx, "c5"); err != nil {
		t.Fatalf("client with a kept request removed: %v", err)
	}
}

func TestOAuthCodeIsExchangedOnce(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "mei", false)
	activate(t, db, "mei")
	newPerson(t, db, "pending", false)
	if err := db.CreateOAuthClient(ctx, OAuthClient{ID: "mcc_1", ClientName: "x", RedirectURIs: []string{"https://app.example/cb"},
		CreatedAt: peopleNow}, peopleNow.Add(-time.Hour), 10, 10); err != nil {
		t.Fatal(err)
	}
	r := newOAuthRequest(t, db, "r1")
	if got, err := db.GetOAuthRequestByConnectHash(ctx, "ch-r1"); err != nil || got.ID != "r1" || got.Status != model.SignInPending || got.Issuer != "https://csg.example" {
		t.Fatalf("by connect hash: %+v %v", got, err)
	}
	// Not consumable before approval; not approvable by an inactive person
	// or after expiry.
	if _, _, err := db.ConsumeOAuthCode(ctx, "r1", signInTestAgent("agt_1"), "h1", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("consume before approval: %v", err)
	}
	codeExpires := peopleNow.Add(time.Minute)
	if err := db.ApproveOAuthRequest(ctx, "r1", "pending", "tool", "code-hash", codeExpires, peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("approval by a pending person: %v", err)
	}
	if err := db.ApproveOAuthRequest(ctx, "r1", "mei", "tool", "code-hash", codeExpires, r.ExpiresAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("approval at expiry: %v", err)
	}
	if err := db.ApproveOAuthRequest(ctx, "r1", "mei", "tool", "code-hash", codeExpires, peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.DenyOAuthRequest(ctx, "r1", "mei", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("a decision changed: %v", err)
	}
	// The code expires with the approval's own, short lifetime.
	if _, _, err := db.ConsumeOAuthCode(ctx, "r1", signInTestAgent("agt_1"), "h1", codeExpires); !errors.Is(err, ErrConflict) {
		t.Fatalf("consume at code expiry: %v", err)
	}
	agent, replaced, err := db.ConsumeOAuthCode(ctx, "r1", signInTestAgent("agt_1"), "h1", peopleNow)
	if err != nil || agent.OwnerID != "mei" || agent.Name != "tool" || len(replaced) != 0 {
		t.Fatalf("consume: %+v %v %v", agent, replaced, err)
	}
	if _, _, err := db.ConsumeOAuthCode(ctx, "r1", signInTestAgent("agt_2"), "h2", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("second exchange: %v", err)
	}
	if got, _ := db.GetOAuthRequest(ctx, "r1"); got.Status != model.SignInConsumed || got.CodeHash != "" || got.AgentID != "agt_1" {
		t.Fatalf("after exchange: %+v", got)
	}
	if c, _ := db.GetOAuthClient(ctx, "mcc_1"); c.LastUsedAt == nil {
		t.Fatal("client not marked used")
	}
	// A second connection with the same name replaces the first agent.
	newOAuthRequest(t, db, "r2")
	if err := db.ApproveOAuthRequest(ctx, "r2", "mei", "tool", "code-hash-2", codeExpires, peopleNow); err != nil {
		t.Fatal(err)
	}
	if _, replaced, err := db.ConsumeOAuthCode(ctx, "r2", signInTestAgent("agt_3"), "h3", peopleNow); err != nil || len(replaced) != 1 || replaced[0] != "agt_1" {
		t.Fatalf("replace: %v %v", replaced, err)
	}
	// A burned code is dead.
	newOAuthRequest(t, db, "r3")
	if err := db.ApproveOAuthRequest(ctx, "r3", "mei", "other", "code-hash-3", codeExpires, peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.BurnOAuthCode(ctx, "r3"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetOAuthRequestByCodeHash(ctx, "code-hash-3"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("burned code still found: %v", err)
	}
	if _, _, err := db.ConsumeOAuthCode(ctx, "r3", signInTestAgent("agt_4"), "h4", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("burned code exchanged: %v", err)
	}
}

func TestSuspendingEndsMCPApprovals(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	newPerson(t, db, "root", true)
	activate(t, db, "root")
	newPerson(t, db, "mei", false)
	activate(t, db, "mei")
	newOAuthRequest(t, db, "r1")
	if err := db.ApproveOAuthRequest(ctx, "r1", "mei", "tool", "code-hash", peopleNow.Add(time.Minute), peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPersonAuthority(ctx, "mei", model.PersonSuspended, false, peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.SetPersonAuthority(ctx, "mei", model.PersonActive, false, peopleNow); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.ConsumeOAuthCode(ctx, "r1", signInTestAgent("agt_1"), "h1", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("an approval survived a suspension: %v", err)
	}
	// The exchange itself checks the approver, whatever path changed them.
	newOAuthRequest(t, db, "r2")
	if err := db.ApproveOAuthRequest(ctx, "r2", "mei", "tool", "code-hash-2", peopleNow.Add(time.Minute), peopleNow); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE persons SET status = 'suspended' WHERE id = 'mei'`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.ConsumeOAuthCode(ctx, "r2", signInTestAgent("agt_2"), "h2", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("exchanged for a suspended approver: %v", err)
	}
}

func TestCredentialLinkWorksOnce(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	expires := peopleNow.Add(time.Minute)
	if err := db.CreateCredentialLink(ctx, "l1", "lea_1", "agt_1", peopleNow, expires, 2); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateCredentialLink(ctx, "l2", "lea_1", "agt_1", peopleNow, expires, 2); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateCredentialLink(ctx, "l3", "lea_1", "agt_1", peopleNow, expires, 2); !errors.Is(err, ErrOAuthLimit) {
		t.Fatalf("over the open-link limit: %v", err)
	}
	if err := db.CreateCredentialLink(ctx, "l3", "lea_2", "agt_2", peopleNow, expires, 2); err != nil {
		t.Fatalf("another agent's limit is its own: %v", err)
	}
	lease, agent, err := db.UseCredentialLink(ctx, "l1", peopleNow)
	if err != nil || lease != "lea_1" || agent != "agt_1" {
		t.Fatalf("use: %s %s %v", lease, agent, err)
	}
	if _, _, err := db.UseCredentialLink(ctx, "l1", peopleNow); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second use: %v", err)
	}
	if _, _, err := db.UseCredentialLink(ctx, "l2", expires); !errors.Is(err, ErrNotFound) {
		t.Fatalf("use at expiry: %v", err)
	}
	if _, _, err := db.UseCredentialLink(ctx, "nope", peopleNow); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown link: %v", err)
	}
	if err := db.DeleteOldCredentialLinks(ctx, expires); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM credential_links`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d links left: %v", n, err)
	}
}
