package server

import (
	"net/http"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// agentMeResponse is the payload of GET /api/v1/agent/me.
type agentMeResponse struct {
	Agent        model.Agent `json:"agent"`
	ActiveLeases int         `json:"active_leases"`
	ServerTime   time.Time   `json:"server_time"`
}

// handleAgentMe implements GET /api/v1/agent/me.
func (s *Server) handleAgentMe(w http.ResponseWriter, r *http.Request) {
	ag, ok := agentFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "agent token required")
		return
	}
	active, err := s.db.CountActiveLeases(r.Context(), ag.ID)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, agentMeResponse{
		Agent:        ag,
		ActiveLeases: active,
		ServerTime:   s.nowUTC(),
	})
}

// handleAgentCapabilities implements GET /api/v1/agent/capabilities. Only
// enabled capabilities granted to the authenticated agent are returned.
func (s *Server) handleAgentCapabilities(w http.ResponseWriter, r *http.Request) {
	ag, ok := agentFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "agent token required")
		return
	}
	granted := make(map[string]bool, len(ag.Grants))
	for _, id := range ag.Grants {
		granted[id] = true
	}
	all, err := s.db.ListCapabilities(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	items := make([]model.Capability, 0, len(all))
	for _, c := range all {
		if c.Enabled && granted[c.ID] {
			items = append(items, c)
		}
	}
	writeList(s, w, http.StatusOK, items, len(items))
}

// heartbeatResponse is the payload of POST /api/v1/agent/heartbeat.
type heartbeatResponse struct {
	OK         bool      `json:"ok"`
	ServerTime time.Time `json:"server_time"`
}

// handleAgentHeartbeat implements POST /api/v1/agent/heartbeat.
func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	ag, ok := agentFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "agent token required")
		return
	}
	now := s.nowUTC()
	// Touch explicitly: the auth middleware only refreshes once per 60 s.
	if err := s.db.TouchAgentSeen(r.Context(), ag.ID, now); err != nil {
		// A vanished agent cannot authenticate, so this only logs a race.
		s.logf("heartbeat: touch agent %s: %v", ag.ID, err)
	}
	s.writeData(w, http.StatusOK, heartbeatResponse{OK: true, ServerTime: now})
}
