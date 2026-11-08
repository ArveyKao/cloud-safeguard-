package server

import (
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/web"
)

// handleHealth implements GET /healthz (returns model.Health directly).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(model.Health{
		Status:  "ok",
		Version: s.version,
		Name:    model.ProductName,
		Time:    s.nowUTC(),
	})
}

// handleUnknownAPI is the JSON 404 fallback for unknown API paths.
func (s *Server) handleUnknownAPI(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "endpoint not found")
}

// handleMockCloud mounts the mock cloud only when a mock provider exists.
// Revoking a mock provider therefore disables the demo cloud surface.
func (s *Server) handleMockCloud(w http.ResponseWriter, r *http.Request) {
	providers, err := s.db.ListProviders(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	hasMock := false
	for _, p := range providers {
		if p.Mode == model.ModeMock {
			hasMock = true
			break
		}
	}
	if !hasMock {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound,
			"mock cloud is not enabled: no mock provider is configured")
		return
	}
	s.mockCloud.ServeHTTP(w, r)
}

// handleStatic serves the embedded dashboard with SPA fallback: unknown
// non-API GET paths return index.html so client-side routes work.
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeError(w, http.StatusMethodNotAllowed, model.ErrCodeInvalidRequest, "method not allowed")
		return
	}
	// API paths must never fall back to the SPA shell.
	if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/healthz" {
		s.handleUnknownAPI(w, r)
		return
	}

	fsys := web.FS()
	fileServer := http.FileServer(http.FS(fsys))

	rel := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if rel == "" {
		rel = "index.html"
	}
	if info, err := fs.Stat(fsys, rel); err == nil && !info.IsDir() {
		if rel == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		fileServer.ServeHTTP(w, r)
		return
	}
	s.serveIndexHTML(w, r, fsys)
}

// serveIndexHTML serves the SPA shell for client-side routes.
func (s *Server) serveIndexHTML(w http.ResponseWriter, r *http.Request, fsys fs.FS) {
	f, err := fsys.Open("index.html")
	if err != nil {
		s.logf("dashboard asset missing: %v", err)
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "dashboard not found")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, model.ErrCodeInternal, "dashboard unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}
