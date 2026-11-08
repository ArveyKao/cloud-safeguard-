// Package server implements the Cloud Safeguard control plane: the REST API
// consumed by the agent CLI and the web console, the embedded dashboard, and
// the background lease sweeper.
//
// FROZEN CONTRACT: Config, Server, New, Handler, ListenAndServe, Addr, Close,
// InitOptions, InitResult, InitAgent and Init are consumed by the CLI. The
// core-api owner implements this package; replace server_stub.go and add files.
// Other owners must not edit it.
package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/mockcloud"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/vaultcrypto"
)

// ErrNotImplemented is a placeholder used until the implementation lands.
//
// Deprecated: kept for signature compatibility with the frozen base commit.
var ErrNotImplemented = errors.New("server: not implemented")

// ErrNotInitialized is returned by New when the data directory has not been
// bootstrapped with `csg init`.
var ErrNotInitialized = errors.New("server: data directory is not initialized")

// DefaultAddr is the loopback listen address used when Config.Addr is empty.
const DefaultAddr = "127.0.0.1:8787"

// maxRequestBody is the maximum accepted HTTP request body size (1 MiB).
const maxRequestBody = 1 << 20

// sweepInterval is how often the background sweeper expires leases.
// It is a package variable so tests can shorten it.
var sweepInterval = 10 * time.Second

// Config configures the control plane.
type Config struct {
	// Addr is the listen address, e.g. "127.0.0.1:8787".
	Addr string
	// DataDir holds the SQLite database, master.key and runtime files.
	DataDir string
	// MasterKey optionally overrides the master key loaded from DataDir.
	MasterKey []byte
	// Version overrides the reported version (default model.Version).
	Version string
	// MinterFactory optionally overrides provider minters (tests inject fakes).
	// When nil the server uses provider.New(provider.Mode).
	MinterFactory func(p model.Provider) (provider.Minter, error)
	// Now optionally overrides the clock (tests use a fixed clock).
	Now func() time.Time
}

// Server is a running control-plane instance.
type Server struct {
	cfg        Config
	db         *store.DB
	vault      *vault.Vault
	key        []byte
	signingKey []byte

	version       string
	now           func() time.Time
	minterFactory func(model.Provider) (provider.Minter, error)

	handler   http.Handler
	mockCloud http.Handler
	startedAt time.Time

	// lifecycleMu guards the live listener/HTTP server/effective address so
	// Addr() can be called while ListenAndServe is binding (and during Close).
	lifecycleMu  sync.Mutex
	httpServer   *http.Server
	listener     net.Listener
	returnedAddr string

	sweepCancel context.CancelFunc
	sweepDone   chan struct{}
	closeOnce   sync.Once
	closeErr    error

	// logWriter receives access log lines; tests redirect it.
	logWriter *log.Logger
}

// defaultMinterFactory resolves the real provider minters.
func defaultMinterFactory(p model.Provider) (provider.Minter, error) {
	return provider.New(p.Mode)
}

// New opens the store, loads the vault and builds the HTTP handler. It does not
// bind a socket.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	version := cfg.Version
	if version == "" {
		version = model.Version
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	factory := cfg.MinterFactory
	if factory == nil {
		factory = defaultMinterFactory
	}
	if cfg.DataDir == "" {
		return nil, notInitializedErr("")
	}

	// Refuse to auto-create a data directory: serve must run on an install that
	// `csg init` bootstrapped. LoadOrCreateKey would otherwise silently create a
	// new master key on a typo'd path.
	if _, err := os.Stat(cfg.DataDir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, notInitializedErr(cfg.DataDir)
		}
		return nil, fmt.Errorf("server: stat data dir: %w", err)
	}

	key, err := loadMasterKeyForServe(cfg)
	if err != nil {
		return nil, err
	}
	v, err := vault.New(key)
	if err != nil {
		return nil, err
	}

	dbPath := filepath.Join(cfg.DataDir, store.DBFileName)
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, notInitializedErr(cfg.DataDir)
		}
		return nil, fmt.Errorf("server: stat database: %w", err)
	}

	db, err := store.Open(context.Background(), cfg.DataDir)
	if err != nil {
		return nil, err
	}
	// An initialized install always carries both the schema version and the
	// admin token hash; anything else means `csg init` never ran (or the data
	// dir is damaged).
	if _, err := db.GetMeta(context.Background(), store.MetaSchemaVersion); err != nil {
		db.Close()
		if errors.Is(err, store.ErrNotFound) {
			return nil, notInitializedErr(cfg.DataDir)
		}
		return nil, fmt.Errorf("server: read schema version: %w", err)
	}
	if _, err := db.GetMeta(context.Background(), store.MetaAdminTokenHash); err != nil {
		db.Close()
		if errors.Is(err, store.ErrNotFound) {
			return nil, notInitializedErr(cfg.DataDir)
		}
		return nil, fmt.Errorf("server: read admin token: %w", err)
	}

	s := &Server{
		cfg:           cfg,
		db:            db,
		vault:         v,
		key:           append([]byte(nil), key...),
		signingKey:    vault.DeriveKey(key, "mock-sts"),
		version:       version,
		now:           now,
		minterFactory: factory,
		startedAt:     now().UTC(),
		logWriter:     log.New(os.Stderr, "", log.LstdFlags),
	}
	s.mockCloud = mockcloud.NewHandler(mockcloud.Deps{Store: db, SigningKey: s.signingKey})
	s.handler = s.buildHandler()
	s.startSweeper()
	return s, nil
}

// notInitializedErr builds the clear bootstrap error required by CONTRACT §11.
func notInitializedErr(dataDir string) error {
	if dataDir == "" {
		return fmt.Errorf("%w: configure a data directory and run `csg init`", ErrNotInitialized)
	}
	return fmt.Errorf("%w: %q; run `csg init --data-dir %s`", ErrNotInitialized, dataDir, dataDir)
}

// loadMasterKeyForServe loads the master key without creating one.
func loadMasterKeyForServe(cfg Config) ([]byte, error) {
	if len(cfg.MasterKey) > 0 {
		if len(cfg.MasterKey) != 32 {
			return nil, vault.ErrInvalidKey
		}
		return append([]byte(nil), cfg.MasterKey...), nil
	}
	if os.Getenv("CSG_MASTER_KEY") == "" {
		keyPath := filepath.Join(cfg.DataDir, "master.key")
		if _, err := os.Stat(keyPath); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil, notInitializedErr(cfg.DataDir)
			}
			return nil, fmt.Errorf("server: stat master key: %w", err)
		}
	}
	key, err := vault.LoadOrCreateKey(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, vault.ErrInvalidKey
	}
	return key, nil
}

// Handler returns the fully routed HTTP handler (API, mock cloud, dashboard).
func (s *Server) Handler() http.Handler { return s.handler }

// ListenAndServe binds Config.Addr and serves until ctx is cancelled, then
// shuts down gracefully. Addr() reports the effective address after binding.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("server: listen on %s: %w", s.cfg.Addr, err)
	}
	httpServer := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	s.lifecycleMu.Lock()
	s.listener = ln
	s.returnedAddr = ln.Addr().String()
	s.httpServer = httpServer
	effectiveAddr := s.returnedAddr
	s.lifecycleMu.Unlock()

	url := "http://" + effectiveAddr
	s.logWriter.Printf("%s %s listening: console %s  api %s/api/v1  mock-cloud %s/mock-cloud/",
		model.ProductName, s.version, url, url, url)

	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.Serve(ln) }()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			// Force-close so we never leak the listener/goroutines.
			_ = httpServer.Close()
		}
		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server: serve: %w", err)
		}
		return nil
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("server: serve: %w", err)
		}
		return nil
	}
}

// Addr reports the bound listen address ("127.0.0.1:8787"), or the configured
// address before binding.
func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	if s.returnedAddr != "" {
		return s.returnedAddr
	}
	return s.cfg.Addr
}

// Close releases the store and stops background workers.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.sweepCancel != nil {
			s.sweepCancel()
			<-s.sweepDone
		}
		s.lifecycleMu.Lock()
		httpServer := s.httpServer
		s.lifecycleMu.Unlock()
		if httpServer != nil {
			s.closeErr = httpServer.Close()
		}
		if s.db != nil {
			if err := s.db.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		}
	})
	return s.closeErr
}

// startSweeper launches the background lease sweeper (every sweepInterval).
func (s *Server) startSweeper() {
	ctx, cancel := context.WithCancel(context.Background())
	s.sweepCancel = cancel
	s.sweepDone = make(chan struct{})
	go func() {
		defer close(s.sweepDone)
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sweepOnce(ctx)
			}
		}
	}()
}

// nowUTC returns the current server time in UTC.
func (s *Server) nowUTC() time.Time { return s.now().UTC() }
