package server

import (
	"context"
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
	if ag, err = s.withLiveLimits(r.Context(), ag); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, agentMeResponse{
		Agent:        ag,
		ActiveLeases: active,
		ServerTime:   s.nowUTC(),
	})
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

// withLiveLimits replaces the limits stored on an agent, which are a record
// of the settings when it signed in, with the supervisor's current settings:
// those are what is enforced, so those are what is shown.
func (s *Server) withLiveLimits(ctx context.Context, ag model.Agent) (model.Agent, error) {
	settings, err := s.db.GetPolicySettings(ctx)
	if err != nil {
		return ag, err
	}
	ag.MaxTTLSeconds = settings.MaxLeaseTTLSeconds
	ag.MaxConcurrentLeases = settings.MaxConcurrentLeasesPerAgent
	return ag, nil
}
