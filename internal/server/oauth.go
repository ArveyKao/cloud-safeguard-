package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/token"
)

// OAuth sign-in for remote MCP (CONTRACT §17.10). The server is both the
// authorization server and the protected resource; the person approves in
// the console, and the access token is the token of a new agent owned by
// that person.
const (
	oauthRequestTTL = 10 * time.Minute
	oauthCodeTTL    = 60 * time.Second
	// Unused registrations within oauthClientWindow are bounded; older ones
	// are deleted.
	oauthClientWindow = 24 * time.Hour
	// A registration that led to a connection is kept until it has not
	// been used for oauthClientRetention.
	oauthClientRetention     = 90 * 24 * time.Hour
	maxUnusedOAuthClients    = 500
	maxUnusedOAuthClientAddr = 20
	maxOpenOAuthRequests     = 100
	maxOpenOAuthRequestsAddr = 10
	maxRedirectURIs          = 10
	maxRedirectURILength     = 2000
	maxOAuthStateLength      = 1000
	oauthFormLimit           = 64 << 10

	mcpConnectionNotFound = "no pending connection with this link"
)

var (
	pkceRE          = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	privateSchemeRE = regexp.MustCompile(`^[a-z][a-z0-9+.-]{1,63}$`)
	connectKeyRE    = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)
	clientIDRE      = regexp.MustCompile(`^mcc_[0-9a-f]{32}$`)
)

// Schemes a redirect URI may never use: they are not native-app private
// schemes and would run or show content in the browser.
var forbiddenRedirectSchemes = map[string]bool{
	"javascript": true, "data": true, "file": true, "vbscript": true, "about": true, "blob": true,
	"ftp": true, "ws": true, "wss": true, "mailto": true, "tel": true, "chrome": true, "view-source": true,
}

func (s *Server) mcpResourceURL(r *http.Request) string { return s.expectedOrigin(r) + "/mcp" }

func (s *Server) protectedResourceMetadataURL(r *http.Request) string {
	return s.expectedOrigin(r) + "/.well-known/oauth-protected-resource"
}

// writeOAuthJSON writes a bare JSON document (OAuth endpoints do not use
// the API envelope).
func (s *Server) writeOAuthJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.logf("write oauth response: %v", err)
	}
}

func (s *Server) oauthError(w http.ResponseWriter, status int, code, description string) {
	s.writeOAuthJSON(w, status, map[string]string{"error": code, "error_description": description})
}

// handleProtectedResourceMetadata is RFC 9728 metadata for /mcp.
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	s.writeOAuthJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.mcpResourceURL(r),
		"authorization_servers":    []string{s.expectedOrigin(r)},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"mcp"},
		"resource_name":            "Cloud Safeguard",
	})
}

// handleAuthorizationServerMetadata is RFC 8414 metadata.
func (s *Server) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	origin := s.expectedOrigin(r)
	s.writeOAuthJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         origin,
		"authorization_endpoint":                         origin + "/oauth/authorize",
		"token_endpoint":                                 origin + "/oauth/token",
		"registration_endpoint":                          origin + "/oauth/register",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none"},
		"scopes_supported":                               []string{"mcp"},
		"authorization_response_iss_parameter_supported": true,
	})
}

// validRedirectURI accepts https URLs, http URLs on the loopback interface,
// and private-use schemes of native apps (RFC 8252). Never a fragment or
// user info.
func validRedirectURI(raw string) bool {
	if raw == "" || len(raw) > maxRedirectURILength || strings.ContainsAny(raw, " \t\r\n#") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" {
		return false
	}
	switch scheme := strings.ToLower(u.Scheme); {
	case scheme == "https":
		host := u.Hostname()
		return u.Opaque == "" && host != "" && strings.Trim(host, ".") != "" && validURIPort(u.Port(), u.Host)
	case scheme == "http":
		return u.Opaque == "" && isLoopbackHost(u.Hostname()) && validURIPort(u.Port(), u.Host)
	default:
		return u.Scheme == scheme && privateSchemeRE.MatchString(scheme) && !forbiddenRedirectSchemes[scheme]
	}
}

// validURIPort accepts no port, or a port from 1 to 65535 written without
// leading zeros. host is the URI's host:port, to refuse an empty port ("h:").
func validURIPort(port, host string) bool {
	if port == "" {
		return !strings.HasSuffix(host, ":")
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535 && strconv.Itoa(n) == port
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// redirectURIMatches compares a requested redirect URI with a registered
// one: exactly, except that the port of a loopback http URI may differ
// (RFC 8252 §7.3), since native apps listen on a port chosen at run time.
func redirectURIMatches(registered, requested string) bool {
	if registered == requested {
		return true
	}
	a, err1 := url.Parse(registered)
	b, err2 := url.Parse(requested)
	if err1 != nil || err2 != nil || a.Scheme != "http" || b.Scheme != "http" || !isLoopbackHost(a.Hostname()) {
		return false
	}
	return a.Hostname() == b.Hostname() && a.EscapedPath() == b.EscapedPath() && a.RawQuery == b.RawQuery &&
		b.User == nil && b.Fragment == ""
}

// handleOAuthRegister is dynamic client registration (RFC 7591), for
// public clients only. Registering grants nothing.
func (s *Server) handleOAuthRegister(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ClientName              string   `json:"client_name"`
		RedirectURIs            []string `json:"redirect_uris"`
		GrantTypes              []string `json:"grant_types"`
		ResponseTypes           []string `json:"response_types"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	// Requiring JSON makes a browser send a preflight, which is never
	// granted, so another website cannot register clients from a visitor's
	// address.
	if !isJSONRequest(r) {
		s.oauthError(w, http.StatusUnsupportedMediaType, "invalid_client_metadata", "Content-Type must be application/json")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, oauthFormLimit+1))
	if err != nil || len(body) > oauthFormLimit || json.Unmarshal(body, &in) != nil {
		s.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the body must be a JSON object of at most 64 KiB")
		return
	}
	name, ok := cleanDisplayName(in.ClientName)
	if !ok {
		s.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "client_name must be at most 100 characters without control characters")
		return
	}
	if name == "" {
		name = "MCP client"
	}
	if len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > maxRedirectURIs {
		s.oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "give 1 to 10 redirect_uris")
		return
	}
	for _, u := range in.RedirectURIs {
		if !validRedirectURI(u) {
			s.oauthError(w, http.StatusBadRequest, "invalid_redirect_uri",
				"each redirect URI must be https, http on localhost, or a private app scheme, without a fragment")
			return
		}
	}
	if len(in.GrantTypes) > 0 && !containsString(in.GrantTypes, "authorization_code") {
		s.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "only the authorization_code grant is supported")
		return
	}
	if len(in.ResponseTypes) > 0 && !containsString(in.ResponseTypes, "code") {
		s.oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "only the code response type is supported")
		return
	}
	id, err := newID("mcc_")
	if err != nil {
		s.internalError(w, "generate id", err)
		return
	}
	now := s.nowUTC()
	client := store.OAuthClient{ID: id, ClientName: name, RedirectURIs: in.RedirectURIs, RemoteAddr: s.clientAddr(r), CreatedAt: now}
	if err := s.db.CreateOAuthClient(r.Context(), client, now.Add(-oauthClientWindow), maxUnusedOAuthClients, maxUnusedOAuthClientAddr); err != nil {
		if errors.Is(err, store.ErrOAuthLimit) {
			s.oauthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many registrations; try again later")
			return
		}
		s.internalError(w, "register oauth client", err)
		return
	}
	s.writeOAuthJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"client_id_issued_at":        now.Unix(),
		"client_name":                name,
		"redirect_uris":              in.RedirectURIs,
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// oauthPageError answers an authorization request that cannot be sent back
// to the client, because the client or redirect URI is not trusted.
func (s *Server) oauthPageError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "Cloud Safeguard cannot continue this sign-in: "+message+"\n")
}

// oauthRedirect builds the redirect back to the client with params, state
// and the issuer (RFC 9207).
func oauthRedirect(issuer, redirectURI, state string, params map[string]string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return ""
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", issuer)
	u.RawQuery = q.Encode()
	return u.String()
}

// handleOAuthAuthorize checks an authorization request, keeps it, and sends
// the browser to the console, where the person decides.
func (s *Server) handleOAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID, redirectURI, state := q.Get("client_id"), q.Get("redirect_uri"), q.Get("state")
	if !clientIDRE.MatchString(clientID) {
		s.oauthPageError(w, http.StatusBadRequest, "unknown client")
		return
	}
	client, err := s.db.GetOAuthClient(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.oauthPageError(w, http.StatusBadRequest, "unknown client")
			return
		}
		s.internalError(w, "read oauth client", err)
		return
	}
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}
	// The requested URI must itself be valid: a loopback port may differ
	// from the registered one, but stays a real port, and the length stays
	// bounded.
	matched := false
	for _, registered := range client.RedirectURIs {
		if validRedirectURI(redirectURI) && redirectURIMatches(registered, redirectURI) {
			matched = true
			break
		}
	}
	if !matched {
		s.oauthPageError(w, http.StatusBadRequest, "the redirect URI is not one this client registered")
		return
	}
	// From here on, errors go back to the client.
	issuer := s.expectedOrigin(r)
	fail := func(code, description string) {
		http.Redirect(w, r, oauthRedirect(issuer, redirectURI, state, map[string]string{"error": code, "error_description": description}), http.StatusFound)
	}
	if len(state) > maxOAuthStateLength {
		state = "" // not echoed back
		fail("invalid_request", "state is too long")
		return
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	if q.Get("code_challenge_method") != "S256" || !pkceRE.MatchString(q.Get("code_challenge")) {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}
	if res := q.Get("resource"); res != "" && strings.TrimSuffix(res, "/") != s.mcpResourceURL(r) {
		fail("invalid_target", "the resource must be "+s.mcpResourceURL(r))
		return
	}
	id, err := newID("mcr_")
	if err != nil {
		s.internalError(w, "generate id", err)
		return
	}
	// The console link carries a separate key, stored only as a hash: it is
	// an approval secret while pending, and the id goes to the audit log.
	connectKey, connectHash, err := authn.NewSecret(24)
	if err != nil {
		s.internalError(w, "generate connect key", err)
		return
	}
	now := s.nowUTC()
	req := store.OAuthRequest{
		ID: id, ConnectHash: connectHash, ClientID: client.ID, RedirectURI: redirectURI, CodeChallenge: q.Get("code_challenge"), State: state,
		RemoteAddr: s.clientAddr(r), Issuer: issuer, CreatedAt: now, ExpiresAt: now.Add(oauthRequestTTL),
	}
	if err := s.db.CreateOAuthRequest(r.Context(), req, maxOpenOAuthRequests, maxOpenOAuthRequestsAddr); err != nil {
		if errors.Is(err, store.ErrOAuthLimit) {
			fail("temporarily_unavailable", "too many sign-ins are waiting; try again in a few minutes")
			return
		}
		s.internalError(w, "create oauth request", err)
		return
	}
	s.systemAudit(r.Context(), "mcp_signin.started", "ok", "info", "mcp_signin", id, map[string]any{
		"client_id": client.ID, "client_name": client.ClientName, "redirect_host": redirectHost(redirectURI),
		"remote_addr": req.RemoteAddr,
	})
	http.Redirect(w, r, "/?mcp-connect="+connectKey, http.StatusFound)
}

// requestIssuer is the issuer the client saw when it started the request,
// so the redirect after the decision carries the same iss whatever host
// name the console was opened at.
func (s *Server) requestIssuer(r *http.Request, req store.OAuthRequest) string {
	if req.Issuer != "" {
		return req.Issuer
	}
	return s.expectedOrigin(r)
}

// redirectHost is what the person is shown about where the sign-in goes:
// the host of an http(s) URI, or a private-use URI without its query, since
// its scheme alone says little.
func redirectHost(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		return u.Host
	}
	u.RawQuery, u.ForceQuery, u.Fragment = "", false, ""
	return u.String()
}

// mcpConnection is what the console shows about a pending request.
type mcpConnection struct {
	ClientName   string    `json:"client_name"`
	RedirectURI  string    `json:"redirect_uri"`
	RedirectHost string    `json:"redirect_host"`
	Local        bool      `json:"local"`
	AgentName    string    `json:"suggested_agent_name"`
	RemoteAddr   string    `json:"remote_addr"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// suggestAgentName turns a client name into a valid agent name.
func suggestAgentName(clientName string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(clientName) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_' || r == '.':
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "-") {
				b.WriteByte('-')
			}
		}
		if b.Len() >= 40 {
			break
		}
	}
	name := strings.Trim(b.String(), "-")
	if !agentNamePattern.MatchString(name) {
		name = "mcp-client"
	}
	return name
}

// pendingMCPConnection loads the pending request named in the path.
func (s *Server) pendingMCPConnection(w http.ResponseWriter, r *http.Request) (store.OAuthRequest, store.OAuthClient, bool) {
	key := r.PathValue("key")
	notFound := func() { s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, mcpConnectionNotFound) }
	if !connectKeyRE.MatchString(key) {
		notFound()
		return store.OAuthRequest{}, store.OAuthClient{}, false
	}
	req, err := s.db.GetOAuthRequestByConnectHash(r.Context(), authn.HashSecret(key))
	if err == nil && (req.Status != model.SignInPending || !s.nowUTC().Before(req.ExpiresAt)) {
		err = store.ErrNotFound
	}
	var client store.OAuthClient
	if err == nil {
		client, err = s.db.GetOAuthClient(r.Context(), req.ClientID)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			notFound()
		} else {
			s.internalError(w, "read mcp connection", err)
		}
		return store.OAuthRequest{}, store.OAuthClient{}, false
	}
	return req, client, true
}

func mcpConnectionView(req store.OAuthRequest, client store.OAuthClient) mcpConnection {
	host := redirectHost(req.RedirectURI)
	u, _ := url.Parse(req.RedirectURI)
	local := u != nil && u.Scheme == "http" && isLoopbackHost(u.Hostname())
	return mcpConnection{
		ClientName: client.ClientName, RedirectURI: req.RedirectURI, RedirectHost: host, Local: local,
		AgentName: suggestAgentName(client.ClientName), RemoteAddr: req.RemoteAddr,
		CreatedAt: req.CreatedAt, ExpiresAt: req.ExpiresAt,
	}
}

// handleGetMCPConnection shows a pending connection to a signed-in person.
func (s *Server) handleGetMCPConnection(w http.ResponseWriter, r *http.Request) {
	req, client, ok := s.pendingMCPConnection(w, r)
	if !ok {
		return
	}
	s.writeData(w, http.StatusOK, mcpConnectionView(req, client))
}

// handleApproveMCPConnection approves a connection: the client gets a
// one-time code for a new agent owned by the person, named as they chose.
func (s *Server) handleApproveMCPConnection(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AgentName string `json:"agent_name"`
	}
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	name := strings.TrimSpace(in.AgentName)
	if !agentNamePattern.MatchString(name) {
		s.badRequest(w, "agent_name must be 2-64 characters: letters, digits, dot, dash or underscore, starting with a letter or digit")
		return
	}
	req, client, ok := s.pendingMCPConnection(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	code, codeHash, err := authn.NewSecret(32)
	if err != nil {
		s.internalError(w, "generate code", err)
		return
	}
	now := s.nowUTC()
	if err := s.db.ApproveOAuthRequest(ctx, req.ID, actor.person.ID, name, codeHash, now.Add(oauthCodeTTL), now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, mcpConnectionNotFound)
			return
		}
		s.internalError(w, "approve mcp connection", err)
		return
	}
	s.personAudit(ctx, actor.person, "mcp_signin.approved", "ok", "warning", "mcp_signin", req.ID, map[string]any{
		"agent_name": name, "client_id": client.ID, "client_name": client.ClientName,
		"redirect_host": redirectHost(req.RedirectURI), "started_from": req.RemoteAddr,
	})
	s.writeData(w, http.StatusOK, map[string]string{
		"redirect_url": oauthRedirect(s.requestIssuer(r, req), req.RedirectURI, req.State, map[string]string{"code": code}),
	})
}

// handleDenyMCPConnection denies a connection and sends the client an
// access_denied error.
func (s *Server) handleDenyMCPConnection(w http.ResponseWriter, r *http.Request) {
	req, client, ok := s.pendingMCPConnection(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	if err := s.db.DenyOAuthRequest(ctx, req.ID, actor.person.ID, s.nowUTC()); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, mcpConnectionNotFound)
			return
		}
		s.internalError(w, "deny mcp connection", err)
		return
	}
	s.personAudit(ctx, actor.person, "mcp_signin.denied", "ok", "info", "mcp_signin", req.ID, map[string]any{
		"client_id": client.ID, "client_name": client.ClientName, "redirect_host": redirectHost(req.RedirectURI),
	})
	s.writeData(w, http.StatusOK, map[string]string{
		"redirect_url": oauthRedirect(s.requestIssuer(r, req), req.RedirectURI, req.State, map[string]string{
			"error": "access_denied", "error_description": "the person denied the connection",
		}),
	})
}

// pkceS256 is BASE64URL(SHA256(verifier)).
func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// handleOAuthToken exchanges an authorization code for an agent token.
func (s *Server) handleOAuthToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, oauthFormLimit)
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		s.oauthError(w, http.StatusBadRequest, "invalid_request", "the body must be application/x-www-form-urlencoded")
		return
	}
	if err := r.ParseForm(); err != nil {
		s.oauthError(w, http.StatusBadRequest, "invalid_request", "unreadable form")
		return
	}
	form := r.PostForm
	if form.Get("grant_type") != "authorization_code" {
		s.oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	code := form.Get("code")
	if code == "" || len(code) > 128 {
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired code")
		return
	}
	ctx := r.Context()
	req, err := s.db.GetOAuthRequestByCodeHash(ctx, authn.HashSecret(code))
	now := s.nowUTC()
	if err != nil || req.Status != model.SignInApproved || !now.Before(req.ExpiresAt) {
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internalError(w, "read oauth code", err)
			return
		}
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired code")
		return
	}
	// A code presented with the wrong client, redirect URI or verifier is
	// burned: whoever holds it is not the client it was issued to.
	problem := ""
	switch {
	case form.Get("client_id") != req.ClientID:
		problem = "the code was issued to another client"
	case form.Get("redirect_uri") != "" && form.Get("redirect_uri") != req.RedirectURI:
		problem = "redirect_uri does not match the authorization request"
	case !pkceRE.MatchString(form.Get("code_verifier")) || !authn.Equal(pkceS256(form.Get("code_verifier")), req.CodeChallenge):
		problem = "code_verifier does not match"
	case form.Get("resource") != "" && strings.TrimSuffix(form.Get("resource"), "/") != s.mcpResourceURL(r):
		problem = "the resource must be " + s.mcpResourceURL(r)
	}
	if problem != "" {
		if err := s.db.BurnOAuthCode(ctx, req.ID); err != nil {
			s.logf("burn oauth code %s: %v", req.ID, err)
		}
		s.systemAudit(ctx, "mcp_signin.exchange_refused", "denied", "warning", "mcp_signin", req.ID, map[string]any{
			"reason": problem, "remote_addr": s.clientAddr(r),
		})
		s.oauthError(w, http.StatusBadRequest, "invalid_grant", problem)
		return
	}
	client, err := s.db.GetOAuthClient(ctx, req.ClientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.oauthError(w, http.StatusBadRequest, "invalid_client", "unknown client")
			return
		}
		s.internalError(w, "read oauth client", err)
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
	description, _ := cleanDisplayName(truncateRunes("MCP: "+client.ClientName, maxDisplayNameLength))
	agent := model.Agent{
		ID: agentID, Description: description,
		Status: model.AgentActive, Role: model.RoleGuest, Grants: []string{},
		MaxTTLSeconds:       settings.MaxLeaseTTLSeconds,
		MaxConcurrentLeases: settings.MaxConcurrentLeasesPerAgent,
		TokenPrefix:         token.DisplayPrefix(plainToken),
		CreatedAt:           now, UpdatedAt: now,
	}
	agent, replaced, err := s.db.ConsumeOAuthCode(ctx, req.ID, agent, tokenHash, now)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired code")
			return
		}
		s.internalError(w, "exchange oauth code", err)
		return
	}
	for _, oldID := range replaced {
		cause := map[string]any{"caused_by": "mcp sign-in", "owner_id": agent.OwnerID, "replaced_by_agent_id": agent.ID}
		if _, err := s.revalidateLeasesAs(ctx, store.LeaseFilter{AgentID: oldID}, "agent replaced by a new sign-in", cause); err != nil {
			s.logf("revoke leases of replaced agent %s: %v", oldID, err)
		}
	}
	s.agentAudit(ctx, agent, "mcp_signin.completed", "ok", "info", "agent", agent.ID, map[string]any{
		"owner_id": agent.OwnerID, "mcp_signin_id": req.ID, "client_id": client.ID, "client_name": client.ClientName,
		"replaced_agent_ids": replaced, "remote_addr": s.clientAddr(r),
	})
	w.Header().Set("Pragma", "no-cache")
	s.writeOAuthJSON(w, http.StatusOK, map[string]any{
		"access_token": plainToken,
		"token_type":   "Bearer",
		"scope":        "mcp",
	})
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
