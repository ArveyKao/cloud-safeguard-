package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// People on the command line (CONTRACT §17.9). A person signs in to csg by
// approving a short code in the console; the result is a session of kind
// "cli", sent as a bearer token. Because agents often run on the same machine
// and could read it, such a session is guarded: approving stays console-only,
// and anything that raises access needs a fresh authenticator code.

const (
	// cliTokenPrefix starts every command-line session token.
	cliTokenPrefix = "csg_ses_"
	// authenticatorCodeHeader carries the fresh authenticator code a
	// command-line session sends with a change that raises access.
	authenticatorCodeHeader = "X-CSG-Authenticator-Code"
	// cliClientNameMax bounds the name a client gives itself.
	cliClientNameMax = 64
)

// handlePersonSignInStart begins a command-line sign-in. Anyone may start
// one; it does nothing until a signed-in person approves its code.
func (s *Server) handlePersonSignInStart(w http.ResponseWriter, r *http.Request) {
	var in model.PersonSignInStartInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	name := strings.TrimSpace(in.ClientName)
	if name == "" {
		name = "csg"
	}
	if !agentNamePattern.MatchString(name) || len(name) > cliClientNameMax {
		s.badRequest(w, "client_name must be 2-64 characters: letters, digits, dot, dash or underscore, starting with a letter or digit")
		return
	}
	ctx := r.Context()
	now := s.nowUTC()
	id, err := newID("cls_")
	if err != nil {
		s.internalError(w, "generate id", err)
		return
	}
	deviceCode, deviceHash, err := authn.NewSecret(32)
	if err != nil {
		s.internalError(w, "generate device code", err)
		return
	}
	signIn := store.CLISignIn{
		ID: id, DeviceCodeHash: deviceHash, ClientName: name,
		RemoteAddr: s.clientAddr(r), CreatedAt: now, ExpiresAt: now.Add(signInTTL),
	}
	for attempt := 0; ; attempt++ {
		if signIn.UserCode, err = newUserCode(); err != nil {
			s.internalError(w, "generate user code", err)
			return
		}
		err = s.db.CreateCLISignIn(ctx, signIn, maxOpenSignIns, maxOpenSignInsPerAddr)
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
	s.systemAudit(ctx, "cli_signin.started", "ok", "info", "cli_signin", id, map[string]any{
		"client_name": name, "remote_addr": signIn.RemoteAddr,
	})
	s.writeData(w, http.StatusCreated, model.AgentSignInStart{
		DeviceCode:      deviceCode,
		UserCode:        formatUserCode(signIn.UserCode),
		VerificationURL: s.expectedOrigin(r) + "/?cli-signin=" + formatUserCode(signIn.UserCode),
		ExpiresAt:       signIn.ExpiresAt,
		IntervalSeconds: signInPollInterval,
	})
}

// handlePersonSignInToken is the client's poll. On approval it creates the
// session and returns its token exactly once.
func (s *Server) handlePersonSignInToken(w http.ResponseWriter, r *http.Request) {
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
	signIn, err := s.db.GetCLISignInByDeviceCodeHash(ctx, authn.HashSecret(code))
	if err != nil {
		s.storeErrorResponse(w, err, "unknown device code")
		return
	}
	now := s.nowUTC()
	if state := cliSignInState(signIn, now); state != model.SignInApproved {
		s.writeData(w, http.StatusOK, model.PersonSignInResult{Status: state})
		return
	}
	secret, _, err := authn.NewSecret(32)
	if err != nil {
		s.internalError(w, "generate token", err)
		return
	}
	plain := cliTokenPrefix + secret
	sessionID, err := newID("ses_")
	if err != nil {
		s.internalError(w, "generate id", err)
		return
	}
	sess := store.Session{
		TokenHash: authn.HashSecret(plain), ID: sessionID, Kind: store.SessionCLI,
		ClientName: signIn.ClientName, RemoteAddr: s.clientAddr(r),
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(sessionMaxLifetime),
	}
	personID, err := s.db.CompleteCLISignIn(ctx, signIn.ID, sess, now)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			// Collected by a parallel poll, expired just now, or the
			// approver is no longer active.
			s.writeData(w, http.StatusOK, model.PersonSignInResult{Status: model.SignInExpired})
			return
		}
		s.internalError(w, "complete sign-in", err)
		return
	}
	person, err := s.db.GetPerson(ctx, personID)
	if err != nil {
		s.internalError(w, "read person", err)
		return
	}
	s.personAudit(ctx, person, "cli_signin.completed", "ok", "warning", "session", sessionID, map[string]any{
		"signin_id": signIn.ID, "client_name": signIn.ClientName, "remote_addr": sess.RemoteAddr,
	})
	view := person.AsOf(now)
	s.writeData(w, http.StatusOK, model.PersonSignInResult{
		Status: model.SignInApproved, Token: plain, Person: &view, ExpiresAt: &sess.ExpiresAt,
	})
}

func cliSignInState(signIn store.CLISignIn, now time.Time) model.SignInStatus {
	return signInState(store.SignIn{Status: signIn.Status, ExpiresAt: signIn.ExpiresAt}, now)
}

// pendingCLISignIn loads the pending command-line sign-in named in the path.
func (s *Server) pendingCLISignIn(w http.ResponseWriter, r *http.Request) (store.CLISignIn, bool) {
	code, ok := normalizeUserCode(r.PathValue("code"))
	if !ok {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, signInNotFoundMessage)
		return store.CLISignIn{}, false
	}
	signIn, err := s.db.GetCLISignInByUserCode(r.Context(), code)
	if err != nil || cliSignInState(signIn, s.nowUTC()) != model.SignInPending {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internalError(w, "read sign-in", err)
			return store.CLISignIn{}, false
		}
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, signInNotFoundMessage)
		return store.CLISignIn{}, false
	}
	return signIn, true
}

// handleGetCLISignIn shows a pending command-line sign-in to whoever is
// about to decide it, and an approved one that was not collected yet to the
// person who approved it (so it can still be withdrawn after a reload).
func (s *Server) handleGetCLISignIn(w http.ResponseWriter, r *http.Request) {
	view := func(signIn store.CLISignIn, status model.SignInStatus) model.CLISignIn {
		return model.CLISignIn{
			UserCode: formatUserCode(signIn.UserCode), ClientName: signIn.ClientName, Status: status,
			RemoteAddr: signIn.RemoteAddr, CreatedAt: signIn.CreatedAt, ExpiresAt: signIn.ExpiresAt,
		}
	}
	if code, ok := normalizeUserCode(r.PathValue("code")); ok {
		actor, _ := sessionFromContext(r.Context())
		signIn, err := s.db.GetCLISignInByUserCode(r.Context(), code)
		if err == nil && signIn.Status == model.SignInApproved && signIn.PersonID == actor.person.ID &&
			cliSignInState(signIn, s.nowUTC()) == model.SignInApproved {
			s.writeData(w, http.StatusOK, view(signIn, model.SignInApproved))
			return
		}
	}
	signIn, ok := s.pendingCLISignIn(w, r)
	if !ok {
		return
	}
	s.writeData(w, http.StatusOK, view(signIn, model.SignInPending))
}

func (s *Server) handleApproveCLISignIn(w http.ResponseWriter, r *http.Request) {
	s.decideCLISignIn(w, r, model.SignInApproved)
}

func (s *Server) handleDenyCLISignIn(w http.ResponseWriter, r *http.Request) {
	s.decideCLISignIn(w, r, model.SignInDenied)
}

// handleCancelCLISignIn withdraws the person's own approval before csg has
// collected the session: an approval given by mistake can still be undone.
func (s *Server) handleCancelCLISignIn(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	code, ok := normalizeUserCode(r.PathValue("code"))
	if !ok {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "no approved sign-in with this code is waiting")
		return
	}
	signIn, err := s.db.CancelCLISignIn(ctx, code, actor.person.ID, s.nowUTC())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound,
				"no approved sign-in with this code is waiting: it was collected already (end it in Settings) or it expired")
			return
		}
		s.internalError(w, "cancel sign-in", err)
		return
	}
	s.personAudit(ctx, actor.person, "cli_signin.cancelled", "ok", "warning", "cli_signin", signIn.ID, map[string]any{
		"client_name": signIn.ClientName, "remote_addr": signIn.RemoteAddr,
	})
	s.writeData(w, http.StatusOK, map[string]string{"status": string(model.SignInDenied)})
}

// decideCLISignIn records the signed-in person's decision. On approval the
// client gets a session of that person.
func (s *Server) decideCLISignIn(w http.ResponseWriter, r *http.Request, decision model.SignInStatus) {
	signIn, ok := s.pendingCLISignIn(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	if err := s.db.DecideCLISignIn(ctx, signIn.ID, actor.person.ID, decision, s.nowUTC()); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, signInNotFoundMessage)
			return
		}
		s.internalError(w, "decide sign-in", err)
		return
	}
	action, severity := "cli_signin.approved", "warning"
	if decision == model.SignInDenied {
		action, severity = "cli_signin.denied", "info"
	}
	s.personAudit(ctx, actor.person, action, "ok", severity, "cli_signin", signIn.ID, map[string]any{
		"client_name": signIn.ClientName, "remote_addr": signIn.RemoteAddr,
	})
	s.writeData(w, http.StatusOK, map[string]string{"status": string(decision)})
}

// handleListCLISessions lists the signed-in person's live command-line
// sessions.
func (s *Server) handleListCLISessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	sessions, err := s.db.ListCLISessions(ctx, actor.person.ID)
	if err != nil {
		s.internalError(w, "list sessions", err)
		return
	}
	now := s.nowUTC()
	out := make([]model.CLISession, 0, len(sessions))
	for _, sess := range sessions {
		if !now.Before(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) >= sessionIdleTimeout {
			continue
		}
		out = append(out, model.CLISession{
			ID: sess.ID, ClientName: sess.ClientName, RemoteAddr: sess.RemoteAddr,
			CreatedAt: sess.CreatedAt, LastSeenAt: sess.LastSeenAt, ExpiresAt: sess.ExpiresAt,
			Current: sess.TokenHash == actor.session.TokenHash,
		})
	}
	writeList(s, w, http.StatusOK, out, len(out))
}

// handleRevokeCLISession ends one of the signed-in person's command-line
// sessions. Someone else's looks the same as a missing one.
func (s *Server) handleRevokeCLISession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	id := r.PathValue("id")
	if err := s.db.DeleteCLISession(ctx, actor.person.ID, id); err != nil {
		s.storeErrorResponse(w, err, "session not found")
		return
	}
	s.personAudit(ctx, actor.person, "cli_session.revoked", "ok", "warning", "session", id, nil)
	s.writeData(w, http.StatusOK, map[string]bool{"ok": true})
}

// consoleOnly refuses a command-line session. It guards the decisions an
// agent on the same machine must never be able to take with a session it
// read from disk (CONTRACT §17.9).
func (s *Server) consoleOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sc, ok := sessionFromContext(r.Context()); ok && sc.session.IsCLI() {
			s.personAudit(r.Context(), sc.person, "auth.console_only_refused", "denied", "warning", "session", sc.session.ID,
				map[string]any{"method": r.Method, "path": logPath(r.URL.Path)})
			s.writeError(w, http.StatusForbidden, model.ErrCodeConsoleOnly,
				"this can only be done in the console, never from the command line")
			return
		}
		next(w, r)
	}
}

// stepUp makes a change that raises access wait for a fresh authenticator
// code when the request comes from a command-line session. It returns false
// after writing the response. Console sessions pass unchanged. Callers run
// it before taking any per-person lock (it takes the actor's).
func (s *Server) stepUp(w http.ResponseWriter, r *http.Request) bool {
	ctx := r.Context()
	sc, ok := sessionFromContext(ctx)
	if !ok || !sc.session.IsCLI() {
		return true
	}
	code := strings.TrimSpace(r.Header.Get(authenticatorCodeHeader))
	if code == "" {
		s.writeError(w, http.StatusForbidden, model.ErrCodeAuthenticatorCodeRequired,
			"this change raises access: repeat it with a fresh code from your authenticator app")
		return false
	}
	refuse := func(reason string, count bool) bool {
		if count {
			if err := s.db.RecordLoginFailure(ctx, sc.person.ID, s.nowUTC(), loginFailureThreshold, loginLockDuration); err != nil {
				s.logf("record step-up failure: %v", err)
			}
		}
		s.personAudit(ctx, sc.person, "auth.step_up_failed", "denied", "warning", "session", sc.session.ID, map[string]any{
			"reason": reason, "method": r.Method, "path": logPath(r.URL.Path),
		})
		s.writeError(w, http.StatusForbidden, model.ErrCodeAuthenticatorCodeInvalid, "the authenticator code was not accepted")
		return false
	}
	unlock, err := s.lockPerson(ctx, sc.person.ID)
	if err != nil {
		s.internalError(w, "lock person", err)
		return false
	}
	defer unlock()
	auth, err := s.db.GetPersonAuth(ctx, sc.person.ID)
	if err != nil {
		s.internalError(w, "read person auth", err)
		return false
	}
	now := s.nowUTC()
	if auth.LockedUntil != nil && now.Before(*auth.LockedUntil) {
		return refuse("temporarily locked after failed codes", false)
	}
	if auth.TOTPSecretEnc == "" {
		return refuse("no authenticator enrolled", false)
	}
	secret, err := s.vault.Decrypt(auth.TOTPSecretEnc, totpAAD(sc.person.ID))
	if err != nil {
		s.internalError(w, "decrypt TOTP secret", err)
		return false
	}
	step, result, err := authn.CheckTOTP(string(secret), code, now, auth.TOTPLastStep)
	if err != nil {
		s.internalError(w, "verify TOTP", err)
		return false
	}
	switch result {
	case authn.TOTPWrong:
		return refuse("wrong code", true)
	case authn.TOTPReused:
		return refuse("code already used", false)
	}
	if err := s.db.ConsumeTOTPStep(ctx, sc.person.ID, step); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return refuse("code already used or person no longer active", false)
		}
		s.internalError(w, "consume TOTP step", err)
		return false
	}
	s.personAudit(ctx, sc.person, "auth.step_up", "ok", "info", "session", sc.session.ID, map[string]any{
		"method": r.Method, "path": logPath(r.URL.Path),
	})
	return true
}

// isCLIRequest reports whether the request comes from a command-line
// session.
func isCLIRequest(r *http.Request) bool {
	sc, ok := sessionFromContext(r.Context())
	return ok && sc.session.IsCLI()
}
