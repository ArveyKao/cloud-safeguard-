package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

func TestLongLivedTransitions(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	addTestProvider(t, db, "p1")
	row := LongLivedRow{ID: "llc_1", LinkHash: "h1", ProviderID: "p1", OwnerID: "mei", CapabilityID: "aliyun.access.ecs.read",
		ResourceName: "*", Reason: "r", CreatedAt: peopleNow, ExpiresAt: peopleNow.Add(time.Hour)}
	if err := db.CreateLongLived(ctx, row, 1); err != nil {
		t.Fatal(err)
	}
	second := row
	second.ID, second.LinkHash = "llc_2", "h2"
	if err := db.CreateLongLived(ctx, second, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("over the pending limit: %v", err)
	}
	if got, err := db.GetLongLivedByLinkHash(ctx, "h1"); err != nil || got.ID != "llc_1" || got.Status != model.LongLivedPending {
		t.Fatalf("by hash %+v %v", got, err)
	}
	if _, err := db.GetLongLivedByLinkHash(ctx, ""); !errors.Is(err, ErrNotFound) {
		t.Fatal("an empty hash matched")
	}
	// Not after expiry; once only.
	if err := db.ClaimLongLivedForCreate(ctx, "llc_1", row.ExpiresAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("claimed at expiry: %v", err)
	}
	if err := db.ClaimLongLivedForCreate(ctx, "llc_1", peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.ClaimLongLivedForCreate(ctx, "llc_1", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatal("claimed twice")
	}
	if err := db.SetLongLivedActive(ctx, "llc_1", "csg-1", "csg-1", "LTAI1", peopleNow); err != nil {
		t.Fatal(err)
	}
	// The second key cannot be cleared while the credential exists.
	if err := db.SetProviderUserAdmin(ctx, "p1", "enc", "LTAI****", peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.SetProviderUserAdmin(ctx, "p1", "", "", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("cleared with a live credential: %v", err)
	}
	if n, _ := db.CountLiveLongLived(ctx, "p1"); n != 1 {
		t.Fatalf("live %d", n)
	}
	// Revoke: claimed once; a failure can be retried; then cleared.
	if err := db.ClaimLongLivedForRevoke(ctx, "llc_1", "test", peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.ClaimLongLivedForRevoke(ctx, "llc_1", "test", peopleNow); !errors.Is(err, ErrConflict) {
		t.Fatal("revoke claimed twice")
	}
	if err := db.FinishLongLivedRevoke(ctx, "llc_1", "Throttling", peopleNow); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetLongLived(ctx, "llc_1"); got.Status != model.LongLivedRevokeFailed || got.FailureReason != "Throttling" {
		t.Fatalf("after failure %+v", got)
	}
	if err := db.ClaimLongLivedForRevoke(ctx, "llc_1", "retry", peopleNow); err != nil {
		t.Fatal(err)
	}
	if err := db.FinishLongLivedRevoke(ctx, "llc_1", "", peopleNow); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetLongLived(ctx, "llc_1"); got.Status != model.LongLivedRevoked || got.RevokedAt == nil {
		t.Fatalf("after revoke %+v", got)
	}
	if err := db.SetProviderUserAdmin(ctx, "p1", "", "", peopleNow); err != nil {
		t.Fatalf("clear after revoke: %v", err)
	}
	// Pending requests expire.
	third := row
	third.ID, third.LinkHash = "llc_3", "h3"
	if err := db.CreateLongLived(ctx, third, 5); err != nil {
		t.Fatal(err)
	}
	if err := db.ExpireLongLivedRequests(ctx, third.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if got, _ := db.GetLongLived(ctx, "llc_3"); got.Status != model.LongLivedExpired {
		t.Fatalf("expiry %s", got.Status)
	}
	// The person flag.
	newPerson(t, db, "mei", false)
	if err := db.SetPersonLongLived(ctx, "mei", true, peopleNow); err != nil {
		t.Fatal(err)
	}
	if p, _ := db.GetPerson(ctx, "mei"); !p.LongLived {
		t.Fatal("flag not stored")
	}
}
