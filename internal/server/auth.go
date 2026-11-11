package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// Human authentication (CONTRACT §17.3).
const (
	sessionCookieName = "csg_session"
	csrfHeader        = "X-CSRF-Token"
	// sessionIdleTimeout ends a session after this long without a request.
	sessionIdleTimeout = 30 * time.Minute
	// sessionMaxLifetime ends a session regardless of activity.
	sessionMaxLifetime = 12 * time.Hour
	// setupCodeTTL is how long a setup code stays usable.
	setupCodeTTL = 72 * time.Hour
	// After loginFailureThreshold consecutive failures the account refuses
	// logins for loginLockDuration.
	loginFailureThreshold = 5
	loginLockDuration     = 15 * time.Minute
	// maxConcurrentHashes bounds simultaneous Argon2id computations (each
	// uses tens of MiB) so a login flood cannot exhaust memory.
	maxConcurrentHashes = 4

	loginFailedMessage = "invalid username, password or code"
	setupFailedMessage = "setup code is invalid, already used or expired"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,31}$`)

// normalizeUsername lowercases and validates a username.
func normalizeUsername(raw string) (string, bool) {
	u := strings.ToLower(strings.TrimSpace(raw))
	return u, usernamePattern.MatchString(u)
}

type personContextKey struct{}

// sessionContext is the authenticated person and session of a request.
type sessionContext struct {
	person  model.Person
	session store.Session
}

func sessionFromContext(ctx context.Context) (sessionContext, bool) {
	sc, ok := ctx.Value(personContextKey{}).(sessionContext)
	return sc, ok
}

func totpAAD(personID string) string { return "person-totp:" + personID }

// hashPassword runs Argon2id under the concurrency limit.
func (s *Server) hashPassword(ctx context.Context, password string) (string, error) {
	if err := s.acquireHashSlot(ctx); err != nil {
		return "", err
	}
	defer s.releaseHashSlot()
	return authn.HashPassword(password, s.pwParams)
}

// verifyPassword runs Argon2id verification under the concurrency limit. An
// empty stored hash is checked against a dummy hash so unknown and
// not-yet-set-up accounts take the same time as real ones; it never matches.
func (s *Server) verifyPassword(ctx context.Context, encoded, password string) bool {
	if err := s.acquireHashSlot(ctx); err != nil {
		return false
	}
	defer s.releaseHashSlot()
	if encoded == "" {
		_, _ = authn.VerifyPassword(s.dummyHash, password)
		return false
	}
	ok, err := authn.VerifyPassword(encoded, password)
	return err == nil && ok
}

func (s *Server) acquireHashSlot(ctx context.Context) error {
	select {
	case s.hashSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Server) releaseHashSlot() { <-s.hashSlots }

// sameOrigin rejects cross-site browser requests. Browsers send Origin on
// every cross-origin and every state-changing request; a request without it
// comes from a non-browser client, which cannot carry a victim's cookie.
func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

// requireSameOrigin guards the unauthenticated auth endpoints (login CSRF).
func (s *Server) requireSameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sameOrigin(r) {
			s.writeError(w, http.StatusForbidden, model.ErrCodeForbidden, "cross-site request refused")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireSession authenticates the console session cookie. State-changing
// requests must also be same-origin and carry the session's CSRF token.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc, ok := s.loadSession(r)
		if !ok {
			s.clearSessionCookie(w, r)
			s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, "sign in required")
			return
		}
		if !isSafeMethod(r.Method) {
			if !sameOrigin(r) || !authn.Equal(r.Header.Get(csrfHeader), sc.session.CSRFToken) {
				s.personAudit(r.Context(), sc.person, "auth.csrf_rejected", "denied", "warning", "person", sc.person.ID,
					map[string]any{"remote_addr": remoteHost(r)})
				s.writeError(w, http.StatusForbidden, model.ErrCodeForbidden, "missing or invalid CSRF token")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), personContextKey{}, sc)))
	})
}

// requireSupervisor allows only supervisors (after requireSession).
func (s *Server) requireSupervisor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc, ok := sessionFromContext(r.Context())
		if !ok || !sc.person.Supervisor {
			s.writeError(w, http.StatusForbidden, model.ErrCodeForbidden, "supervisor access required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// loadSession resolves the session cookie to a live session of an active
// person. Stale sessions are deleted.
func (s *Server) loadSession(r *http.Request) (sessionContext, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" || len(cookie.Value) > 128 {
		return sessionContext{}, false
	}
	ctx := r.Context()
	hash := authn.HashSecret(cookie.Value)
	sess, err := s.db.GetSession(ctx, hash)
	if err != nil {
		return sessionContext{}, false
	}
	now := s.nowUTC()
	if !now.Before(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) >= sessionIdleTimeout {
		_ = s.db.DeleteSession(ctx, hash)
		return sessionContext{}, false
	}
	person, err := s.db.GetPerson(ctx, sess.PersonID)
	if err != nil || person.Status != model.PersonActive {
		_ = s.db.DeleteSession(ctx, hash)
		return sessionContext{}, false
	}
	if now.Sub(sess.LastSeenAt) >= time.Minute {
		if err := s.db.TouchSession(ctx, hash, now); err == nil {
			sess.LastSeenAt = now
		}
	}
	return sessionContext{person: person, session: sess}, true
}

func (s *Server) secureCookie(r *http.Request) bool { return s.cfg.SecureCookies || r.TLS != nil }

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookie(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// startSession creates a session for person, sets the cookie and returns the
// session description.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, person model.Person) (model.SessionInfo, error) {
	ctx := r.Context()
	plain, hash, err := authn.NewSecret(32)
	if err != nil {
		return model.SessionInfo{}, err
	}
	csrf, _, err := authn.NewSecret(32)
	if err != nil {
		return model.SessionInfo{}, err
	}
	now := s.nowUTC()
	sess := store.Session{
		TokenHash: hash, PersonID: person.ID, CSRFToken: csrf,
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(sessionMaxLifetime),
	}
	if err := s.db.CreateSession(ctx, sess); err != nil {
		return model.SessionInfo{}, err
	}
	s.setSessionCookie(w, r, plain, sess.ExpiresAt)
	return s.sessionInfo(ctx, person, sess)
}

func (s *Server) sessionInfo(ctx context.Context, person model.Person, sess store.Session) (model.SessionInfo, error) {
	bindings, err := s.db.ListBindings(ctx, person.ID, "")
	if err != nil {
		return model.SessionInfo{}, err
	}
	return model.SessionInfo{Person: person, Bindings: bindings, CSRFToken: sess.CSRFToken, ExpiresAt: sess.ExpiresAt}, nil
}

// ================= handlers =================

// handleSetupBegin: the person proves a setup code and chooses a password;
// the server returns a fresh TOTP secret. It may be repeated while pending
// (each call replaces the password and the secret).
func (s *Server) handleSetupBegin(w http.ResponseWriter, r *http.Request) {
	var in model.SetupBeginInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	ctx := r.Context()
	person, codeHash, ok := s.pendingPersonForSetupCode(ctx, r, in.SetupCode)
	if !ok {
		s.badRequest(w, setupFailedMessage)
		return
	}
	if err := authn.ValidatePassword(in.Password); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	passwordHash, err := s.hashPassword(ctx, in.Password)
	if err != nil {
		s.internalError(w, "hash password", err)
		return
	}
	secret, err := authn.NewTOTPSecret()
	if err != nil {
		s.internalError(w, "generate TOTP secret", err)
		return
	}
	secretEnc, err := s.vault.Encrypt([]byte(secret), totpAAD(person.ID))
	if err != nil {
		s.internalError(w, "encrypt TOTP secret", err)
		return
	}
	if err := s.db.BeginPersonSetup(ctx, person.ID, codeHash, passwordHash, secretEnc, s.nowUTC()); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.badRequest(w, setupFailedMessage)
			return
		}
		s.internalError(w, "begin setup", err)
		return
	}
	s.personAudit(ctx, person, "person.setup_started", "ok", "info", "person", person.ID,
		map[string]any{"remote_addr": remoteHost(r)})
	s.writeData(w, http.StatusOK, model.SetupBeginResult{
		Username:   person.Username,
		TOTPSecret: secret,
		OTPAuthURL: authn.OTPAuthURL(model.ProductName, person.Username, secret),
	})
}

// handleSetupFinish: the person proves the authenticator works. The account
// becomes active, the setup code is consumed and a session starts.
func (s *Server) handleSetupFinish(w http.ResponseWriter, r *http.Request) {
	var in model.SetupFinishInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	ctx := r.Context()
	person, codeHash, ok := s.pendingPersonForSetupCode(ctx, r, in.SetupCode)
	if !ok {
		s.badRequest(w, setupFailedMessage)
		return
	}
	auth, err := s.db.GetPersonAuth(ctx, person.ID)
	if err != nil || auth.PasswordHash == "" || auth.TOTPSecretEnc == "" {
		s.badRequest(w, "choose a password first")
		return
	}
	secret, err := s.vault.Decrypt(auth.TOTPSecretEnc, totpAAD(person.ID))
	if err != nil {
		s.internalError(w, "decrypt TOTP secret", err)
		return
	}
	now := s.nowUTC()
	step, ok, err := authn.VerifyTOTP(string(secret), in.TOTPCode, now, -1)
	if err != nil {
		s.internalError(w, "verify TOTP", err)
		return
	}
	if !ok {
		s.badRequest(w, "the code does not match; check the authenticator app and try again")
		return
	}
	if err := s.db.FinishPersonSetup(ctx, person.ID, codeHash, step, now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.badRequest(w, setupFailedMessage)
			return
		}
		s.internalError(w, "finish setup", err)
		return
	}
	person, err = s.db.GetPerson(ctx, person.ID)
	if err != nil {
		s.internalError(w, "reload person", err)
		return
	}
	s.personAudit(ctx, person, "person.setup_completed", "ok", "info", "person", person.ID,
		map[string]any{"remote_addr": remoteHost(r)})
	info, err := s.startSession(w, r, person)
	if err != nil {
		s.internalError(w, "start session", err)
		return
	}
	s.writeData(w, http.StatusOK, info)
}

// pendingPersonForSetupCode resolves a setup code to a pending person whose
// code has not expired. Failures are audited without the code.
func (s *Server) pendingPersonForSetupCode(ctx context.Context, r *http.Request, code string) (model.Person, string, bool) {
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 128 {
		return model.Person{}, "", false
	}
	hash := authn.HashSecret(code)
	person, err := s.db.GetPersonBySetupCodeHash(ctx, hash)
	if err != nil {
		s.systemAudit(ctx, "auth.setup_failed", "denied", "warning", "person", "", map[string]any{
			"remote_addr": remoteHost(r), "reason": "unknown setup code",
		})
		return model.Person{}, "", false
	}
	auth, err := s.db.GetPersonAuth(ctx, person.ID)
	if err != nil || person.Status != model.PersonPending ||
		auth.SetupExpiresAt == nil || !s.nowUTC().Before(*auth.SetupExpiresAt) {
		s.systemAudit(ctx, "auth.setup_failed", "denied", "warning", "person", person.ID, map[string]any{
			"remote_addr": remoteHost(r), "reason": "setup code expired or person not pending",
		})
		return model.Person{}, "", false
	}
	return person, hash, true
}

// handleLogin signs a person in with username, password and TOTP code. Every
// failure returns the same response, whatever the cause.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in model.PersonLoginInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	ctx := r.Context()
	fail := func(personID, reason string) {
		if personID != "" {
			if err := s.db.RecordLoginFailure(ctx, personID, s.nowUTC(), loginFailureThreshold, loginLockDuration); err != nil {
				s.logf("record login failure: %v", err)
			}
		}
		s.systemAudit(ctx, "auth.login_failed", "denied", "warning", "person", personID, map[string]any{
			"remote_addr": remoteHost(r), "reason": reason,
		})
		s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, loginFailedMessage)
	}

	username, valid := normalizeUsername(in.Username)
	var (
		person model.Person
		auth   store.PersonAuth
		found  bool
	)
	if valid {
		if p, err := s.db.GetPersonByUsername(ctx, username); err == nil {
			if a, err := s.db.GetPersonAuth(ctx, p.ID); err == nil {
				person, auth, found = p, a, true
			}
		}
	}
	if !found {
		s.verifyPassword(ctx, "", in.Password) // equalize timing
		fail("", "unknown username")
		return
	}
	now := s.nowUTC()
	locked := auth.LockedUntil != nil && now.Before(*auth.LockedUntil)
	usable := person.Status == model.PersonActive && auth.PasswordHash != "" && auth.TOTPSecretEnc != ""
	if locked || !usable {
		s.verifyPassword(ctx, "", in.Password) // equalize timing; never matches
		if locked {
			// Do not extend the lock: a locked account ignores attempts.
			s.systemAudit(ctx, "auth.login_failed", "denied", "warning", "person", person.ID, map[string]any{
				"remote_addr": remoteHost(r), "reason": "account temporarily locked",
			})
			s.writeError(w, http.StatusUnauthorized, model.ErrCodeUnauthorized, loginFailedMessage)
			return
		}
		fail(person.ID, "person is "+string(person.Status))
		return
	}
	if !s.verifyPassword(ctx, auth.PasswordHash, in.Password) {
		fail(person.ID, "wrong password")
		return
	}
	secret, err := s.vault.Decrypt(auth.TOTPSecretEnc, totpAAD(person.ID))
	if err != nil {
		s.internalError(w, "decrypt TOTP secret", err)
		return
	}
	step, ok, err := authn.VerifyTOTP(string(secret), in.TOTPCode, now, auth.TOTPLastStep)
	if err != nil {
		s.internalError(w, "verify TOTP", err)
		return
	}
	if !ok {
		fail(person.ID, "wrong or reused code")
		return
	}
	// Consume the TOTP step atomically: of two logins with the same code,
	// only one succeeds.
	if err := s.db.AcceptLogin(ctx, person.ID, step, now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			fail(person.ID, "wrong or reused code")
			return
		}
		s.internalError(w, "accept login", err)
		return
	}
	person, err = s.db.GetPerson(ctx, person.ID)
	if err != nil {
		s.internalError(w, "reload person", err)
		return
	}
	info, err := s.startSession(w, r, person)
	if err != nil {
		s.internalError(w, "start session", err)
		return
	}
	s.personAudit(ctx, person, "auth.login", "ok", "info", "person", person.ID,
		map[string]any{"remote_addr": remoteHost(r)})
	s.writeData(w, http.StatusOK, info)
}

// handleLogout ends the current session.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sc, _ := sessionFromContext(r.Context())
	if err := s.db.DeleteSession(r.Context(), sc.session.TokenHash); err != nil {
		s.internalError(w, "delete session", err)
		return
	}
	s.clearSessionCookie(w, r)
	s.personAudit(r.Context(), sc.person, "auth.logout", "ok", "info", "person", sc.person.ID, nil)
	s.writeData(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAuthMe describes the signed-in person.
func (s *Server) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	sc, _ := sessionFromContext(r.Context())
	info, err := s.sessionInfo(r.Context(), sc.person, sc.session)
	if err != nil {
		s.internalError(w, "load session info", err)
		return
	}
	s.writeData(w, http.StatusOK, info)
}

// internalError logs err (never to the client) and writes a 500.
func (s *Server) internalError(w http.ResponseWriter, what string, err error) {
	s.logf("%s: %v", what, err)
	s.writeError(w, http.StatusInternalServerError, model.ErrCodeInternal, "internal error")
}

// personAudit appends an audit event attributed to a person.
func (s *Server) personAudit(ctx context.Context, p model.Person, action, status, severity, targetType, targetID string, metadata map[string]any) {
	s.appendAudit(ctx, model.AuditEvent{
		ActorType:  "person",
		ActorID:    p.ID,
		ActorName:  p.Username,
		Action:     action,
		Status:     status,
		Severity:   severity,
		TargetType: targetType,
		TargetID:   targetID,
		Metadata:   metadata,
	})
}
