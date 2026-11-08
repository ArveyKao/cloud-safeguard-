package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/token"
)

const (
	// apiPrefix is the control-plane REST prefix.
	apiPrefix = "/api/v1"
	// clientTimeout bounds one HTTP round trip to the control plane.
	clientTimeout = 30 * time.Second
	// maxResponseBytes bounds how much of a control-plane response we buffer.
	maxResponseBytes = 16 << 20
)

// HTTPDoer is the subset of *http.Client the CLI needs (injectable for tests).
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// httpClient returns the injected client or a sensible default.
func (a *App) httpClient() HTTPDoer {
	if a.HTTPClient != nil {
		return a.HTTPClient
	}
	return &http.Client{Timeout: clientTimeout}
}

// fileConfig is the on-disk CLI configuration (~/.config/cloud-safeguard/config.json).
type fileConfig struct {
	Server string `json:"server"`
	Token  string `json:"token"`
	Kind   string `json:"kind"`
}

// configPath returns the CLI config file path.
func (a *App) configPath() (string, error) {
	home, err := a.HomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot locate home directory: %v", err)
	}
	return filepath.Join(home, ".config", "cloud-safeguard", "config.json"), nil
}

// loadFileConfig reads the saved CLI config. Missing/unreadable files are not an
// error: the CLI works from flags and environment variables alone.
func (a *App) loadFileConfig() fileConfig {
	var cfg fileConfig
	path, err := a.configPath()
	if err != nil {
		return cfg
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg
	}
	_ = json.Unmarshal(data, &cfg)
	return cfg
}

// saveFileConfig writes the CLI config with 0600 permissions.
func (a *App) saveFileConfig(cfg fileConfig) (string, error) {
	path, err := a.configPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("cannot create config directory: %v", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("cannot encode config: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("cannot write config: %v", err)
	}
	// Best effort: an existing file keeps its old mode through os.WriteFile.
	_ = os.Chmod(path, 0o600)
	return path, nil
}

// clientFlags are the per-command connection flags.
type clientFlags struct {
	server string
	token  string
}

// addClientFlags registers --server/--token on fs.
func (a *App) addClientFlags(fs *flagSet) *clientFlags {
	cf := &clientFlags{}
	fs.StringVar(&cf.server, "server", "", "control plane URL (default: $CSG_SERVER or saved config)")
	fs.StringVar(&cf.token, "token", "", "bearer token (default: $CSG_TOKEN or saved config)")
	return cf
}

// resolvedConfig is the effective connection configuration after applying the
// frozen precedence: flags > environment > config file.
type resolvedConfig struct {
	Server string
	Token  string
	Kind   string
}

// resolveConfig applies flags > CSG_SERVER/CSG_TOKEN > ~/.config file.
func (a *App) resolveConfig(cf *clientFlags) (*resolvedConfig, error) {
	fileCfg := a.loadFileConfig()

	server := fileCfg.Server
	if env := strings.TrimSpace(a.Getenv("CSG_SERVER")); env != "" {
		server = env
	}
	if cf != nil && strings.TrimSpace(cf.server) != "" {
		server = cf.server
	}

	tokenValue := fileCfg.Token
	if env := strings.TrimSpace(a.Getenv("CSG_TOKEN")); env != "" {
		tokenValue = env
	}
	if cf != nil && strings.TrimSpace(cf.token) != "" {
		tokenValue = cf.token
	}

	server = normalizeServer(server)
	tokenValue = strings.TrimSpace(tokenValue)

	if server == "" {
		return nil, usagef("server URL not configured: pass --server, set CSG_SERVER, or run csg login")
	}
	if err := validateServerURL(server); err != nil {
		return nil, usagef("%v", err)
	}
	if tokenValue == "" {
		return nil, authf("no token configured: pass --token, set CSG_TOKEN, or run csg login")
	}
	return &resolvedConfig{Server: server, Token: tokenValue, Kind: token.Kind(tokenValue)}, nil
}

// resolveServer resolves only the server URL (used by `csg mock request`, which
// authenticates with a mock STS token instead of a CLI token).
func (a *App) resolveServer(cf *clientFlags) (string, error) {
	fileCfg := a.loadFileConfig()
	server := fileCfg.Server
	if env := strings.TrimSpace(a.Getenv("CSG_SERVER")); env != "" {
		server = env
	}
	if cf != nil && strings.TrimSpace(cf.server) != "" {
		server = cf.server
	}
	server = normalizeServer(server)
	if server == "" {
		return "", usagef("server URL not configured: pass --server, set CSG_SERVER, or run csg login")
	}
	if err := validateServerURL(server); err != nil {
		return "", usagef("%v", err)
	}
	return server, nil
}

// normalizeServer trims whitespace and trailing slashes.
func normalizeServer(server string) string {
	return strings.TrimRight(strings.TrimSpace(server), "/")
}

// validateServerURL checks that the server URL is an absolute http(s) URL.
func validateServerURL(server string) error {
	u, err := url.Parse(server)
	if err != nil {
		return fmt.Errorf("invalid server URL %q: %v", server, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid server URL %q: scheme must be http or https", server)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid server URL %q: missing host", server)
	}
	return nil
}

// tokenKindLabel describes a token kind for error messages.
func tokenKindLabel(kind string) string {
	switch kind {
	case "admin":
		return "an admin token"
	case "agent":
		return "an agent token"
	default:
		return "not a csg token (expected a csg_adm_ or csg_agt_ prefix)"
	}
}

// apiClient is the typed client of the control plane.
type apiClient struct {
	baseURL string
	token   string
	http    HTTPDoer
}

// newAPIClient builds a client from a resolved config.
func (a *App) newAPIClient(cfg *resolvedConfig) *apiClient {
	return &apiClient{baseURL: cfg.Server, token: cfg.Token, http: a.httpClient()}
}

// adminClient resolves config and requires an admin token (exit 3 otherwise).
func (a *App) adminClient(cf *clientFlags) (*apiClient, error) {
	cfg, err := a.resolveConfig(cf)
	if err != nil {
		return nil, err
	}
	if cfg.Kind != "admin" {
		return nil, authf("admin token required (configured token is %s)", tokenKindLabel(cfg.Kind))
	}
	return a.newAPIClient(cfg), nil
}

// agentClient resolves config and requires an agent token (exit 3 otherwise).
func (a *App) agentClient(cf *clientFlags) (*apiClient, error) {
	cfg, err := a.resolveConfig(cf)
	if err != nil {
		return nil, err
	}
	if cfg.Kind != "agent" {
		return nil, authf("agent token required (configured token is %s; use csg login with an agent token)", tokenKindLabel(cfg.Kind))
	}
	return a.newAPIClient(cfg), nil
}

// apiError is a non-2xx control-plane response.
type apiError struct {
	Status  int
	Code    string
	Message string
}

// Error implements error.
func (e *apiError) Error() string { return e.Message }

// do performs one API request. For success responses it unwraps the
// {"data": ...} envelope into out (when out is non-nil).
func (c *apiClient) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("cannot encode request: %v", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("cannot build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach control plane at %s: %v", c.baseURL, unwrapHTTPError(err))
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("cannot read control plane response: %v", err)
	}

	if resp.StatusCode >= 400 {
		var errBody model.ErrorBody
		if err := json.Unmarshal(data, &errBody); err == nil && errBody.Error.Message != "" {
			return &apiError{Status: resp.StatusCode, Code: errBody.Error.Code, Message: errBody.Error.Message}
		}
		return &apiError{
			Status:  resp.StatusCode,
			Message: fmt.Sprintf("control plane returned HTTP %d", resp.StatusCode),
		}
	}

	if out == nil {
		return nil
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("invalid response from control plane: %v", err)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return fmt.Errorf("response from control plane is missing the data envelope")
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("cannot decode response data: %v", err)
	}
	return nil
}

// get performs a GET request.
func (c *apiClient) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// post performs a POST request.
func (c *apiClient) post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

// patch performs a PATCH request.
func (c *apiClient) patch(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPatch, path, body, out)
}

// put performs a PUT request.
func (c *apiClient) put(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPut, path, body, out)
}

// unwrapHTTPError strips the request URL from transport errors for cleaner
// messages (the token is in a header, but the URL noise helps nobody).
func unwrapHTTPError(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return uerr.Err
	}
	return err
}

// pathEscape escapes one path segment.
func pathEscape(segment string) string {
	return url.PathEscape(segment)
}
