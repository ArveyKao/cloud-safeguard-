package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

func TestListenAndServeAndGracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(context.Background(), InitOptions{DataDir: dir}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	srv, err := New(Config{Addr: "127.0.0.1:0", DataDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()
	srv.logWriter = log.New(io.Discard, "", 0)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ListenAndServe(ctx) }()

	// Wait for the socket to be bound and learn the effective address.
	deadline := time.Now().Add(5 * time.Second)
	var baseURL string
	for time.Now().Before(deadline) {
		addr := srv.Addr()
		if addr != "" && addr != "127.0.0.1:0" {
			baseURL = "http://" + addr
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if baseURL == "" {
		t.Fatalf("server did not bind (Addr = %q)", srv.Addr())
	}

	// /healthz over a real TCP socket, without auth.
	resp, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d", resp.StatusCode)
	}
	var health model.Health
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	if health.Status != "ok" || health.Version != model.Version {
		t.Fatalf("health = %+v", health)
	}

	// The dashboard is served over the same socket.
	rootResp, err := http.Get(baseURL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer rootResp.Body.Close()
	if rootResp.StatusCode != http.StatusOK {
		t.Fatalf("GET / status = %d", rootResp.StatusCode)
	}
	if ct := rootResp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("GET / Content-Type = %q", ct)
	}

	// Wrong HTTP method on health is rejected by the mux.
	methodResp, err := http.Post(baseURL+"/healthz", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST /healthz: %v", err)
	}
	methodResp.Body.Close()
	if methodResp.StatusCode == http.StatusOK {
		t.Fatal("POST /healthz unexpectedly succeeded")
	}

	// Cancel the context: ListenAndServe must shut down gracefully and return nil.
	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("ListenAndServe returned %v, want nil after graceful shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ListenAndServe did not shut down within 10s")
	}
}

func TestListenAndServeReportsBindErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(context.Background(), InitOptions{DataDir: dir}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	srv, err := New(Config{Addr: "invalid-address:not-a-port", DataDir: dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.Close()
	srv.logWriter = log.New(io.Discard, "", 0)
	if err := srv.ListenAndServe(context.Background()); err == nil {
		t.Fatal("ListenAndServe accepted an invalid listen address")
	}
}

func TestInitResultAdminTokenPrefixIsNonSecret(t *testing.T) {
	dir := t.TempDir()
	result, err := Init(context.Background(), InitOptions{DataDir: dir})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	// The stored/displayed prefix must be a short hint, not the token.
	if result.AdminTokenPrefix == result.AdminToken {
		t.Fatal("admin token prefix equals the full admin token")
	}
	if len(result.AdminTokenPrefix) > 16 {
		t.Fatalf("admin token prefix length = %d, want a short hint", len(result.AdminTokenPrefix))
	}
	if _, err := Init(context.Background(), InitOptions{DataDir: dir}); err == nil {
		t.Fatal("re-init without --force succeeded")
	}
}
