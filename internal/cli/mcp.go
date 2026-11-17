package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/mcp"
	"github.com/arveykao/cloud-safeguard/internal/model"
)

// `csg mcp` is a Model Context Protocol server on stdio (CONTRACT §17.7). It
// is a thin client of the agent API: it holds the agent token from csg login
// and nothing else.
//
// Credentials never enter the model's context: get_credential writes them to
// a file only the user can read and returns its path, so the secret does not
// end up in a transcript, a log or a model provider's request.

// leaseIDRE matches a request (lease) id.
var leaseIDRE = mcp.LeaseIDRE

// cliBackend calls the agent API over HTTP for the MCP tools.
type cliBackend struct{ client *apiClient }

func (b cliBackend) Call(ctx context.Context, method, path string, in, out any) error {
	return mcpErr(b.client.do(ctx, method, path, in, out))
}

// mcpServer is the stdio MCP server: the shared tools, with the credential
// handed over in a file only the user can read.
func (a *App) mcpServer(client *apiClient) *mcp.Server {
	return &mcp.Server{
		Backend:  cliBackend{client},
		Versions: []string{"2025-06-18", "2025-03-26", "2024-11-05"},
		CredentialDescription: "Prepare the credential of an active request. The secret is written to a file only the user can read and is NOT returned here; " +
			"run `source <path>` in the shell that runs the cloud command (aliyun CLI, SDKs, terraform).",
		RevokeDescription: "End an access request early and delete its credential file. Do this as soon as the task is done.",
		PrepareCredential: func(ctx context.Context, id string) (map[string]any, error) {
			var envelope model.CredentialEnvelope
			if err := client.post(ctx, apiPrefix+"/agent/leases/"+pathEscape(id)+"/credential", nil, &envelope); err != nil {
				return nil, mcpErr(err)
			}
			a.sweepCredentialFiles(time.Now())
			path, err := a.writeCredentialFile(id, &envelope, client.baseURL)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"request_id": id,
				"file":       path,
				"expires_at": envelope.Credential.ExpiresAt.UTC().Format(time.RFC3339),
				"use":        "source " + shellQuote(path) + "  # in the shell that runs the cloud command",
				"note":       "The credential is in the file, readable only by this user; it is not shown here. Revoke it when done.",
			}, nil
		},
		AfterRevoke: func(id string) map[string]any {
			return map[string]any{"credential_file_deleted": a.removeCredentialFile(id)}
		},
	}
}

// runMCP implements `csg mcp`.
func (a *App) runMCP(args []string) error {
	fs := a.newFlagSet("mcp", `Usage: csg mcp

Runs the Cloud Safeguard MCP server on stdin/stdout for Claude, Cursor and
other MCP clients. Sign the agent in first with csg login. Example client
configuration:

  "cloud-safeguard": { "command": "csg", "args": ["mcp"] }

Tools: list_accounts, request_access, check_status, get_credential, revoke.
Credentials are written to ~/.config/cloud-safeguard/credentials/ (mode 0600)
and never returned to the model.
`)
	cf := a.addClientFlags(fs)
	positionals, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(positionals) != 0 {
		return usagef("mcp takes no arguments")
	}
	client, err := a.agentClient(cf)
	if err != nil {
		return err
	}
	if a.Stdin == nil {
		return usagef("mcp needs stdin")
	}
	a.sweepCredentialFiles(time.Now())
	server := a.mcpServer(client)
	reader := bufio.NewReaderSize(a.Stdin, 64*1024)
	enc := json.NewEncoder(a.Stdout)
	for {
		line, tooLong, err := readMCPLine(reader, mcp.MaxMessage)
		if tooLong {
			// One oversized message is refused; the session goes on.
			if err := enc.Encode(mcp.ErrorResponse(-32600, "message too large")); err != nil {
				return err
			}
		} else if trimmed := strings.TrimSpace(string(line)); trimmed != "" {
			if out := server.HandleMessage(context.Background(), []byte(trimmed)); out != nil {
				if err := enc.Encode(out); err != nil {
					return err
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// readMCPLine reads one newline-terminated line. A line longer than max is
// read to its end and discarded, and tooLong is set.
func readMCPLine(r *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
	for {
		chunk, isPrefix, err := r.ReadLine()
		if !tooLong {
			if len(line)+len(chunk) > max {
				tooLong, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if err != nil || !isPrefix {
			return line, tooLong, err
		}
	}
}

// mcpErr turns an API error into a message for the model.
func mcpErr(err error) error {
	var ae *apiError
	if errors.As(err, &ae) {
		return fmt.Errorf("%s", ae.Message)
	}
	return err
}

// credentialPath is ~/.config/cloud-safeguard/credentials/<request id>.env.
func (a *App) credentialPath(id string) (string, error) {
	if !leaseIDRE.MatchString(id) {
		return "", fmt.Errorf("invalid request id")
	}
	cfg, err := a.configPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfg), "credentials", id+".env"), nil
}

// writeCredentialFile writes export lines to a 0600 file in a 0700 directory.
func (a *App) writeCredentialFile(id string, envelope *model.CredentialEnvelope, server string) (string, error) {
	path, err := a.credentialPath(id)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("cannot create the credentials directory: %v", err)
	}
	_ = os.Chmod(filepath.Dir(path), 0o700)
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s\n", credentialFileHeader, envelope.Credential.ExpiresAt.UTC().Format(time.RFC3339))
	for _, kv := range safeCredentialEnv(envelope) {
		fmt.Fprintf(&b, "export %s=%s\n", kv.Name, shellQuote(kv.Value))
	}
	fmt.Fprintf(&b, "export CSG_LEASE_ID=%s\nexport CSG_SERVER=%s\n", shellQuote(id), shellQuote(server))
	// Create with 0600 from the start; replace an older file atomically.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("cannot write the credential file: %v", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.WriteString(b.String()); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", fmt.Errorf("cannot write the credential file: %v", err)
	}
	return path, nil
}

func (a *App) removeCredentialFile(id string) bool {
	path, err := a.credentialPath(id)
	if err != nil {
		return false
	}
	return os.Remove(path) == nil
}

// shellQuote single-quotes a value for POSIX shells.
func shellQuote(s string) string { return "'" + shellSingleQuote(s) + "'" }

// credentialFileHeader starts the first line of every credential file; the
// expiry follows it.
const credentialFileHeader = "# Cloud Safeguard credential, valid until "

// sweepCredentialFiles deletes credential files whose credential has expired,
// so secrets do not pile up on disk. Files it cannot read are left alone.
func (a *App) sweepCredentialFiles(now time.Time) {
	cfg, err := a.configPath()
	if err != nil {
		return
	}
	dir := filepath.Join(filepath.Dir(cfg), "credentials")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".env")
		if !e.Type().IsRegular() || !leaseIDRE.MatchString(id) || id+".env" != e.Name() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		first, _ := bufio.NewReader(io.LimitReader(f, 256)).ReadString('\n')
		f.Close()
		stamp, ok := strings.CutPrefix(strings.TrimSpace(first), strings.TrimSpace(credentialFileHeader))
		if !ok {
			continue
		}
		expires, err := time.Parse(time.RFC3339, strings.TrimSpace(stamp))
		if err == nil && !now.Before(expires) {
			_ = os.Remove(path)
		}
	}
}
