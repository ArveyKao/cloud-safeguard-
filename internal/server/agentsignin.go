package server

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/token"
)

// Agent-first sign-in (CONTRACT §17.3 item 2).
//
//  1. The agent starts a sign-in and gets a secret device code plus a short
//     user code, which it shows to its human.
//  2. A signed-in person looks the user code up and approves or denies it.
//  3. The agent polls with the device code; on approval it receives its
//     token exactly once, already bound to the approver as owner.
//
// The token is generated at pickup and never stored in plaintext.
const (
	signInTTL          = 10 * time.Minute
	signInPollInterval = 5 // seconds, advisory
	// maxOpenSignIns bounds unauthenticated sign-in starts.
	maxOpenSignIns        = 100
	maxOpenSignInsPerAddr = 10
	// signInRetention keeps finished sign-ins briefly so a late poll gets a
	// clear answer; the audit log keeps the history.
	signInRetention = time.Hour

	// userCodeAlphabet avoids look-alike characters (0/O, 1/I/L, U/V).
	userCodeAlphabet = "ABCDEFGHJKMNPQRSTWXYZ23456789"
	userCodeLength   = 7

	signInNotFoundMessage = "no pending sign-in with this code"
)

var agentNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$`)

// newUserCode returns a random user code without modulo bias.
func newUserCode() (string, error) {
	const n = len(userCodeAlphabet)
	// Bytes at or above limit are discarded so every character is equally
	// likely. limit is an int: for an alphabet that divides 256 it is 256
	// and must not wrap to 0.
	limit := 256 - 256%n
	out := make([]byte, 0, userCodeLength)
	buf := make([]byte, 16)
	for len(out) < userCodeLength {
		if _, err := rand.Read(buf); err != nil {
			return "", errors.New("cannot read system randomness")
		}
		for _, b := range buf {
			if int(b) < limit && len(out) < userCodeLength {
				out = append(out, userCodeAlphabet[int(b)%n])
			}
		}
	}
	return string(out), nil
}

// formatUserCode renders "K7Q4XPM" as "K7Q-4XPM".
func formatUserCode(code string) string {
	if len(code) != userCodeLength {
		return code
	}
	return code[:3] + "-" + code[3:]
}

// normalizeUserCode accepts what a person types: any case, with or without
// the dash or spaces.
func normalizeUserCode(raw string) (string, bool) {
	code := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(raw)))
	if len(code) != userCodeLength {
		return "", false
	}
	for _, c := range code {
		if !strings.ContainsRune(userCodeAlphabet, c) {
			return "", false
		}
	}
	return code, true
}

// signInState is the status of a sign-in as seen now (expiry applied).
func signInState(s store.SignIn, now time.Time) model.SignInStatus {
	if s.Status == model.SignInConsumed || !now.Before(s.ExpiresAt) {
		return model.SignInExpired
	}
	return s.Status
}

// handleAgentSignInStart begins a sign-in. It needs no authentication.
func (s *Server) handleAgentSignInStart(w http.ResponseWriter, r *http.Request) {
	var in model.AgentSignInStartInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	name := strings.TrimSpace(in.AgentName)
	if !agentNamePattern.MatchString(name) {
		s.badRequest(w, "agent_name must be 2-64 characters: letters, digits, dot, dash or underscore, starting with a letter or digit")
		return
	}
	description, ok := cleanDisplayName(in.Description)
	if !ok {
		s.badRequest(w, "description must be at most 100 characters without control characters")
		return
	}
	ctx := r.Context()
	now := s.nowUTC()
	id, err := newID("sgn_")
	if err != nil {
		s.internalError(w, "generate id", err)
		return
	}
	deviceCode, deviceHash, err := authn.NewSecret(32)
	if err != nil {
		s.internalError(w, "generate device code", err)
		return
	}
	signIn := store.SignIn{
		ID: id, DeviceCodeHash: deviceHash, AgentName: name, Description: description,
		RemoteAddr: s.clientAddr(r), CreatedAt: now, ExpiresAt: now.Add(signInTTL),
	}
	for attempt := 0; ; attempt++ {
		if signIn.UserCode, err = newUserCode(); err != nil {
			s.internalError(w, "generate user code", err)
			return
		}
		err = s.db.CreateSignIn(ctx, signIn, maxOpenSignIns, maxOpenSignInsPerAddr)
		if err == nil {
			break
		}
		if errors.Is(err, store.ErrSignInLimit) {
			s.writeError(w, http.StatusTooManyRequests, model.ErrCodeRateLimited, "too many sign-ins are waiting; try again in a few minutes")
			return
		}
		if !errors.Is(err, store.ErrConflict) || attempt >= 4 {
			s.internalError(w, "create sign-in", err)
			return
		}
	}
	s.systemAudit(ctx, "agent_signin.started", "ok", "info", "agent_signin", id, map[string]any{
		"agent_name": name, "remote_addr": signIn.RemoteAddr,
	})
	s.writeData(w, http.StatusCreated, model.AgentSignInStart{
		DeviceCode:      deviceCode,
		UserCode:        formatUserCode(signIn.UserCode),
		VerificationURL: s.expectedOrigin(r) + "/?signin=" + formatUserCode(signIn.UserCode),
		ExpiresAt:       signIn.ExpiresAt,
		IntervalSeconds: signInPollInterval,
	})
}

// handleAgentSignInToken is the agent's poll. On approval it creates the
// agent and returns the token exactly once.
func (s *Server) handleAgentSignInToken(w http.ResponseWriter, r *http.Request) {
	var in model.AgentSignInTokenInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	ctx := r.Context()
	code := strings.TrimSpace(in.DeviceCode)
	if code == "" || len(code) > 128 {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "unknown device code")
		return
	}
	signIn, err := s.db.GetSignInByDeviceCodeHash(ctx, authn.HashSecret(code))
	if err != nil {
		s.storeErrorResponse(w, err, "unknown device code")
		return
	}
	now := s.nowUTC()
	state := signInState(signIn, now)
	if state != model.SignInApproved {
		s.writeData(w, http.StatusOK, model.AgentSignInResult{Status: state})
		return
	}

	settings, err := s.db.GetPolicySettings(ctx)
	if err != nil {
		s.internalError(w, "read policy settings", err)
		return
	}
	agentID, err := newID("agt_")
	if err != nil {
		s.internalError(w, "generate id", err)
		return
	}
	plainToken, tokenHash, err := token.Generate(token.AgentPrefix)
	if err != nil {
		s.internalError(w, "generate token", err)
		return
	}
	// An owned agent has no role or grants of its own: what it may do comes
	// from its owner's role on each cloud account (§17.2). Guest with no
	// grants means the §16 request path gives it nothing.
	agent := model.Agent{
		ID: agentID, Name: signIn.AgentName, Description: signIn.Description,
		Status: model.AgentActive, Role: model.RoleGuest, Grants: []string{},
		MaxTTLSeconds:       settings.MaxLeaseTTLSeconds,
		MaxConcurrentLeases: settings.MaxConcurrentLeasesPerAgent,
		TokenPrefix:         token.DisplayPrefix(plainToken),
		CreatedAt:           now, UpdatedAt: now,
	}
	agent, replaced, err := s.db.CompleteSignIn(ctx, signIn.ID, agent, tokenHash, now)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Collected by a parallel poll, expired just now, or the approver
			// is no longer active.
			s.writeData(w, http.StatusOK, model.AgentSignInResult{Status: model.SignInExpired})
			return
		}
		s.internalError(w, "complete sign-in", err)
		return
	}
	// A new sign-in under the same name replaces the owner's earlier agent:
	// its token is dead (status revoked) and its leases go with it.
	for _, oldID := range replaced {
		cause := map[string]any{"caused_by": "agent sign-in", "owner_id": agent.OwnerID, "replaced_by_agent_id": agent.ID}
		if _, err := s.revalidateLeasesAs(ctx, store.LeaseFilter{AgentID: oldID}, "agent replaced by a new sign-in", cause); err != nil {
			s.logf("revoke leases of replaced agent %s: %v", oldID, err)
		}
	}
	s.agentAudit(ctx, agent, "agent_signin.completed", "ok", "info", "agent", agent.ID, map[string]any{
		"owner_id": agent.OwnerID, "signin_id": signIn.ID, "replaced_agent_ids": replaced,
		"remote_addr": s.clientAddr(r),
	})
	s.writeData(w, http.StatusOK, model.AgentSignInResult{Status: model.SignInApproved, Agent: &agent, Token: plainToken})
}

// pendingSignIn loads the pending sign-in named in the path for a person.
func (s *Server) pendingSignIn(w http.ResponseWriter, r *http.Request) (store.SignIn, bool) {
	code, ok := normalizeUserCode(r.PathValue("code"))
	if !ok {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, signInNotFoundMessage)
		return store.SignIn{}, false
	}
	signIn, err := s.db.GetSignInByUserCode(r.Context(), code)
	if err != nil || signInState(signIn, s.nowUTC()) != model.SignInPending {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internalError(w, "read sign-in", err)
			return store.SignIn{}, false
		}
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, signInNotFoundMessage)
		return store.SignIn{}, false
	}
	return signIn, true
}

func signInView(signIn store.SignIn, status model.SignInStatus) model.AgentSignIn {
	return model.AgentSignIn{
		UserCode: formatUserCode(signIn.UserCode), AgentName: signIn.AgentName, Description: signIn.Description,
		Status: status, RemoteAddr: signIn.RemoteAddr, CreatedAt: signIn.CreatedAt, ExpiresAt: signIn.ExpiresAt,
	}
}

// handleGetSignIn shows a pending sign-in to a signed-in person.
func (s *Server) handleGetSignIn(w http.ResponseWriter, r *http.Request) {
	signIn, ok := s.pendingSignIn(w, r)
	if !ok {
		return
	}
	s.writeData(w, http.StatusOK, signInView(signIn, model.SignInPending))
}

func (s *Server) handleApproveSignIn(w http.ResponseWriter, r *http.Request) {
	s.decideSignIn(w, r, model.SignInApproved)
}

func (s *Server) handleDenySignIn(w http.ResponseWriter, r *http.Request) {
	s.decideSignIn(w, r, model.SignInDenied)
}

// decideSignIn records the signed-in person's decision. The approver becomes
// the agent's owner.
func (s *Server) decideSignIn(w http.ResponseWriter, r *http.Request, decision model.SignInStatus) {
	signIn, ok := s.pendingSignIn(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	if err := s.db.DecideSignIn(ctx, signIn.ID, actor.person.ID, decision, s.nowUTC()); err != nil {
		if errors.Is(err, store.ErrConflict) { // decided or expired in the meantime
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, signInNotFoundMessage)
			return
		}
		s.internalError(w, "decide sign-in", err)
		return
	}
	action, severity := "agent_signin.approved", "warning"
	if decision == model.SignInDenied {
		action, severity = "agent_signin.denied", "info"
	}
	s.personAudit(ctx, actor.person, action, "ok", severity, "agent_signin", signIn.ID, map[string]any{
		"agent_name": signIn.AgentName, "started_from": signIn.RemoteAddr,
	})
	s.writeData(w, http.StatusOK, signInView(signIn, decision))
}

// handleListMyAgents lists the signed-in person's agents.
func (s *Server) handleListMyAgents(w http.ResponseWriter, r *http.Request) {
	actor, _ := sessionFromContext(r.Context())
	agents, err := s.db.ListAgentsByOwner(r.Context(), actor.person.ID)
	if err != nil {
		s.internalError(w, "list agents", err)
		return
	}
	writeList(s, w, http.StatusOK, agents, len(agents))
}

// handleRevokeMyAgent permanently revokes one of the person's own agents and
// its leases.
func (s *Server) handleRevokeMyAgent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	agent, err := s.db.GetAgent(ctx, r.PathValue("id"))
	if err != nil || agent.OwnerID != actor.person.ID {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internalError(w, "read agent", err)
			return
		}
		// Someone else's agent looks the same as a missing one.
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "agent not found")
		return
	}
	agent.Status = model.AgentRevoked
	agent.UpdatedAt = s.nowUTC()
	if err := s.db.UpdateAgent(ctx, agent); err != nil {
		s.storeErrorResponse(w, err, "agent not found")
		return
	}
	revoked, err := s.revalidateLeasesAs(ctx, store.LeaseFilter{AgentID: agent.ID}, "agent revoked by its owner", map[string]any{
		"caused_by": "person:" + actor.person.ID, "caused_by_username": actor.person.Username, "owner_id": agent.OwnerID,
	})
	if err != nil {
		s.internalError(w, "revoke leases", err)
		return
	}
	s.personAudit(ctx, actor.person, "agent.revoked", "ok", "warning", "agent", agent.ID, map[string]any{
		"agent_name": agent.Name, "revoked_lease_ids": revoked,
	})
	s.writeData(w, http.StatusOK, agent)
}

// agentOwnerProblem reports why an owned agent may not act: its owner is
// missing or not active (§17.1). Agents without an owner (created before
// people existed) are not affected.
func (s *Server) agentOwnerProblem(ctx context.Context, ag model.Agent) (string, error) {
	if ag.OwnerID == "" {
		return "", nil
	}
	owner, err := s.db.GetPerson(ctx, ag.OwnerID)
	if errors.Is(err, store.ErrNotFound) {
		return "agent's owner no longer exists", nil
	}
	if err != nil {
		return "", err
	}
	if owner.Status != model.PersonActive {
		return "agent's owner is " + string(owner.Status), nil
	}
	return "", nil
}

// revokeOwnedAgentLeases re-checks every lease of every agent the person
// owns and revokes those no longer authorized.
func (s *Server) revokeOwnedAgentLeases(ctx context.Context, personID, reason string, cause map[string]any) ([]string, error) {
	agents, err := s.db.ListAgentsByOwner(ctx, personID)
	if err != nil {
		return nil, err
	}
	var revoked []string
	for _, ag := range agents {
		ids, err := s.revalidateLeasesAs(ctx, store.LeaseFilter{AgentID: ag.ID}, reason, cause)
		if err != nil {
			return revoked, err
		}
		revoked = append(revoked, ids...)
	}
	return revoked, nil
}
