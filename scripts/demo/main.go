// Command demo drives the Cloud Safeguard end-to-end demo (scenarios S1-S13)
// against a running control plane in mock mode. scripts/demo.sh builds csg,
// bootstraps a throwaway data directory, starts the server and runs this.
//
// People act through the same HTTP API the console uses (setup, sign-in with
// an authenticator code, approvals); the agent acts through the real csg
// binary. No secret is printed: setup codes, passwords, tokens and
// credentials stay in memory, and S13 checks that none of them reached the
// server log or this program's own output.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
)

const demoAccount = "1234567890123456"

// person is one console session.
type person struct {
	name   string
	id     string
	client *http.Client
	csrf   string
}

type demo struct {
	server  string
	csg     string
	home    string
	logPath string
	// secrets are values that must never appear in the server log or in
	// anything this program prints.
	secrets map[string]string
	printed bytes.Buffer

	sup, mei *person
	// supSecret is the supervisor's TOTP secret, for codes on the command line.
	supSecret string
	// tokens of the credentials issued along the way.
	writeLease, writeToken string
}

func main() {
	d := &demo{secrets: map[string]string{}}
	flag.StringVar(&d.server, "server", "", "control plane URL")
	flag.StringVar(&d.csg, "csg", "", "path of the csg binary")
	flag.StringVar(&d.home, "home", "", "empty directory used as the agent's home")
	flag.StringVar(&d.logPath, "server-log", "", "path of the server log")
	flag.Parse()
	setupCode := os.Getenv("CSG_DEMO_SETUP_CODE")
	if d.server == "" || d.csg == "" || d.home == "" || d.logPath == "" || setupCode == "" {
		fmt.Fprintln(os.Stderr, "demo: --server, --csg, --home, --server-log and $CSG_DEMO_SETUP_CODE are required")
		os.Exit(2)
	}
	d.secrets["the supervisor's setup code"] = setupCode

	scenarios := []struct {
		name string
		run  func() error
	}{
		{"S1 supervisor sets up, adds a person and gives her a role", func() error { return d.s1(setupCode) }},
		{"S2 agent signs in with a short code; no token is copied", d.s2},
		{"S3 read access is issued at once and works", d.s3},
		{"S4 least privilege: a read credential cannot write", d.s4},
		{"S5 a guest's agent cannot get write access", d.s5},
		{"S6 write waits for the owner; only the owner approves", d.s6},
		{"S7 lowering the role revokes the credential at once", d.s7},
		{"S8 a supervisor can stop anything; the admin token is gone", d.s8},
		{"S9 a supervisor on the command line: raising access needs a code, approving stays in the console", d.s9person},
		{"S10 an MCP client connects by URL: the owner approves in the console, the credential reaches a shell through a one-time link", d.s10remote},
		{"S11 approval mode per account, and a credential refreshed under the same request", d.s11modeRefresh},
		{"S12 an AWS account: read on one S3 bucket lists and reads it, never writes, never reaches IAM", d.s12aws},
		{"S13 audit chain verifies and no secret leaked", d.s9},
	}
	failed := 0
	for _, s := range scenarios {
		if err := s.run(); err != nil {
			failed++
			d.say("FAIL  %s\n      %v\n", s.name, err)
			continue
		}
		d.say("PASS  %s\n", s.name)
	}
	d.say("\ndemo summary: %d passed, %d failed\n", len(scenarios)-failed, failed)
	if failed != 0 {
		os.Exit(1)
	}
}

// say prints and remembers what was printed, for the leak check in S13.
func (d *demo) say(format string, args ...any) {
	text := fmt.Sprintf(format, args...)
	d.printed.WriteString(text)
	fmt.Print(text)
}

// ---- people ----

// call sends a request in p's console session and decodes the data envelope.
func (d *demo) call(p *person, method, path string, body, out any) (int, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return 0, err
		}
	}
	req, err := http.NewRequest(method, d.server+path, &buf)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.csrf != "" {
		req.Header.Set("X-CSRF-Token", p.csrf)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if out != nil && resp.StatusCode < 300 {
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: not a data envelope", method, path)
		}
		if err := json.Unmarshal(env.Data, out); err != nil {
			return resp.StatusCode, fmt.Errorf("%s %s: %v", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// must is call with an expected status.
func (d *demo) must(p *person, method, path string, body, out any, want int) error {
	got, err := d.call(p, method, path, body, out)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s %s as %s = %d, want %d", method, path, p.name, got, want)
	}
	return nil
}

// setUp completes a person's setup: a password and an authenticator app.
func (d *demo) setUp(name, setupCode string) (*person, error) {
	jar, _ := cookiejar.New(nil)
	p := &person{name: name, client: &http.Client{Jar: jar, Timeout: 30 * time.Second}}
	random := make([]byte, 18)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	password := "demo " + hex.EncodeToString(random)
	d.secrets[name+"'s password"] = password
	var begin model.SetupBeginResult
	if err := d.must(p, http.MethodPost, "/api/v1/auth/setup/begin", model.SetupBeginInput{SetupCode: setupCode, Password: password}, &begin, http.StatusOK); err != nil {
		return nil, err
	}
	d.secrets[name+"'s authenticator secret"] = begin.TOTPSecret
	if name == "the supervisor" {
		d.supSecret = begin.TOTPSecret
	}
	code, err := authn.TOTPCode(begin.TOTPSecret, authn.TOTPStep(time.Now()))
	if err != nil {
		return nil, err
	}
	var info model.SessionInfo
	if err := d.must(p, http.MethodPost, "/api/v1/auth/setup/finish", model.SetupFinishInput{SetupCode: setupCode, TOTPCode: code}, &info, http.StatusOK); err != nil {
		return nil, err
	}
	p.csrf, p.id = info.CSRFToken, info.Person.ID
	if u, err := url.Parse(d.server); err == nil {
		for _, c := range jar.Cookies(u) {
			d.secrets[name+"'s session cookie"] = c.Value
		}
	}
	return p, nil
}

// bind sets mei's role on the demo cloud account.
func (d *demo) bind(role model.Role) error {
	var accounts struct {
		Items []model.Provider `json:"items"`
	}
	if err := d.must(d.sup, http.MethodGet, "/api/v1/supervisor/accounts", nil, &accounts, http.StatusOK); err != nil {
		return err
	}
	for _, acct := range accounts.Items {
		if acct.CloudAccountID == demoAccount {
			return d.must(d.sup, http.MethodPut, "/api/v1/supervisor/accounts/"+acct.ID+"/people/"+d.mei.id,
				model.PutBindingInput{Role: role}, nil, http.StatusOK)
		}
	}
	return errors.New("the demo cloud account is missing")
}

// ---- the agent ----

// agent runs csg as the agent and returns stdout, stderr and the exit code.
func (d *demo) agent(extraEnv []string, args ...string) (string, string, int) {
	cmd := exec.Command(d.csg, args...)
	cmd.Env = append([]string{"HOME=" + d.home, "PATH=" + os.Getenv("PATH")}, extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return "", err.Error(), -1
		}
		code = exit.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}

// request asks for access and returns the request as the server reports it.
func (d *demo) request(permission string, extra ...string) (model.AccessRequest, int, error) {
	args := append([]string{"access", "request", "--account", demoAccount, "--resource", "ecs",
		"--permission", permission, "--ttl", "10m", "--json"}, extra...)
	stdout, stderr, code := d.agent(nil, args...)
	var out model.AccessRequest
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		return out, code, fmt.Errorf("csg access request (%s) exit %d: %s", permission, code, firstLine(stderr))
	}
	return out, code, nil
}

// credentialToken fetches a request's credential and returns its security
// token, which is remembered as a secret and never printed.
func (d *demo) credentialToken(requestID string) (string, error) {
	stdout, stderr, code := d.agent(nil, "credential", "--lease", requestID, "--json")
	if code != 0 {
		return "", fmt.Errorf("csg credential exit %d: %s", code, firstLine(stderr))
	}
	var envelope model.CredentialEnvelope
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil || envelope.Credential.SecurityToken == "" {
		return "", errors.New("csg credential returned no security token")
	}
	d.secrets["security token of "+requestID] = envelope.Credential.SecurityToken
	d.secrets["access key secret of "+requestID] = envelope.Credential.AccessKeySecret
	return envelope.Credential.SecurityToken, nil
}

// mock calls the mock cloud with a credential's security token.
func (d *demo) mock(token string, args ...string) (string, int) {
	stdout, stderr, code := d.agent([]string{"CSG_SERVER=" + d.server, "ALIBABA_CLOUD_SECURITY_TOKEN=" + token},
		append([]string{"mock", "request"}, args...)...)
	return stdout + stderr, code
}

func (d *demo) status(requestID string) (model.LeaseStatus, error) {
	stdout, stderr, _ := d.agent(nil, "access", "status", requestID, "--json")
	var out model.AccessRequest
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		return "", fmt.Errorf("csg access status: %s", firstLine(stderr))
	}
	return out.Status, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// ---- scenarios ----

func (d *demo) s1(setupCode string) error {
	sup, err := d.setUp("the supervisor", setupCode)
	if err != nil {
		return err
	}
	d.sup = sup
	// The setup code works once.
	if got, _ := d.call(&person{name: "anyone", client: http.DefaultClient}, http.MethodPost, "/api/v1/auth/setup/begin",
		model.SetupBeginInput{SetupCode: setupCode, Password: "another long passphrase"}, nil); got == http.StatusOK {
		return errors.New("the setup code worked a second time")
	}
	var created model.PersonWithSetupCode
	if err := d.must(sup, http.MethodPost, "/api/v1/supervisor/people", model.CreatePersonInput{Username: "mei"}, &created, http.StatusCreated); err != nil {
		return err
	}
	d.secrets["mei's setup code"] = created.SetupCode
	if d.mei, err = d.setUp("mei", created.SetupCode); err != nil {
		return err
	}
	// mei is not a supervisor.
	if err := d.must(d.mei, http.MethodGet, "/api/v1/supervisor/people", nil, nil, http.StatusForbidden); err != nil {
		return err
	}
	return d.bind(model.RoleGuest)
}

func (d *demo) s2() error {
	cmd := exec.Command(d.csg, "login", "--server", d.server, "--name", "demo-agent")
	cmd.Env = []string{"HOME=" + d.home, "PATH=" + os.Getenv("PATH")}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var shown bytes.Buffer
	approved := false
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		line := scanner.Text()
		shown.WriteString(line + "\n")
		if code, ok := strings.CutPrefix(strings.TrimSpace(line), "code: "); ok && !approved {
			d.secrets["the agent's sign-in code"] = code
			// The person checks the code in the console and approves.
			var pending model.AgentSignIn
			if err := d.must(d.mei, http.MethodGet, "/api/v1/me/signins/"+code, nil, &pending, http.StatusOK); err != nil {
				_ = cmd.Process.Kill()
				return err
			}
			if pending.AgentName != "demo-agent" {
				_ = cmd.Process.Kill()
				return fmt.Errorf("the console shows agent %q for this code", pending.AgentName)
			}
			if err := d.must(d.mei, http.MethodPost, "/api/v1/me/signins/"+code+"/approve", nil, nil, http.StatusOK); err != nil {
				_ = cmd.Process.Kill()
				return err
			}
			approved = true
		}
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("csg login: %v: %s", err, firstLine(shown.String()))
	}
	if !approved {
		return errors.New("csg login showed no code")
	}
	raw, err := os.ReadFile(filepath.Join(d.home, ".config", "cloud-safeguard", "config.json"))
	if err != nil {
		return err
	}
	var cfg struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || !strings.HasPrefix(cfg.Token, "csg_agt_") {
		return errors.New("csg login saved no agent token")
	}
	d.secrets["the agent's token"] = cfg.Token
	if strings.Contains(stdout.String()+shown.String(), cfg.Token) {
		return errors.New("csg login printed the agent token")
	}
	if info, err := os.Stat(filepath.Join(d.home, ".config", "cloud-safeguard", "config.json")); err != nil || info.Mode().Perm() != 0o600 {
		return errors.New("the saved token is readable by others")
	}
	out, errOut, code := d.agent(nil, "accounts")
	if code != 0 || !strings.Contains(out, demoAccount) || !strings.Contains(out, "guest") {
		return fmt.Errorf("csg accounts exit %d: %s", code, firstLine(out+errOut))
	}
	return nil
}

func (d *demo) s3() error {
	// csg exec asks for read access, runs the command with the credential
	// and gives the credential back when the command ends.
	out, errOut, code := d.agent(nil, "exec", "--account", demoAccount, "--resource", "ecs", "--permission", "read", "--ttl", "10m",
		"--", d.csg, "mock", "request", "GET", "/v1/ecs/instances")
	if code != 0 {
		return fmt.Errorf("csg exec exit %d: %s", code, firstLine(errOut))
	}
	if !strings.Contains(out, "i-2ze0demo001") {
		return errors.New("the mock cloud did not list the demo instance")
	}
	var mine struct {
		Items []model.Lease `json:"items"`
	}
	listed, _, _ := d.agent(nil, "leases", "mine", "--json")
	if err := json.Unmarshal([]byte(listed), &mine); err != nil || len(mine.Items) != 1 {
		return errors.New("csg leases mine does not show the request")
	}
	if mine.Items[0].Status != model.LeaseRevoked {
		return fmt.Errorf("the credential is %s after the command ended, want revoked", mine.Items[0].Status)
	}
	return nil
}

func (d *demo) s4() error {
	read, _, err := d.request("read")
	if err != nil {
		return err
	}
	if read.Status != model.LeaseActive {
		return fmt.Errorf("read request is %s, want active at once", read.Status)
	}
	token, err := d.credentialToken(read.ID)
	if err != nil {
		return err
	}
	if out, code := d.mock(token, "GET", "/v1/ecs/instances"); code != 0 {
		return fmt.Errorf("read with a read credential failed: %s", firstLine(out))
	}
	out, code := d.mock(token, "POST", "/v1/ecs/instances/i-2ze0demo001/restart")
	if code == 0 || !strings.Contains(out, "Forbidden.RAM") {
		return errors.New("a read credential restarted an instance")
	}
	if _, errOut, code := d.agent(nil, "revoke", "--lease", read.ID); code != 0 {
		return fmt.Errorf("csg revoke exit %d: %s", code, firstLine(errOut))
	}
	if out, code := d.mock(token, "GET", "/v1/ecs/instances"); code == 0 || !strings.Contains(out, "InvalidSecurityToken") {
		return errors.New("a credential the agent gave back still works")
	}
	return nil
}

func (d *demo) s5() error {
	write, code, err := d.request("write", "--reason", "restart after a config change")
	if err != nil {
		return err
	}
	if write.Status != model.LeaseDenied || code == 0 {
		return fmt.Errorf("a guest's write request is %s (exit %d), want denied", write.Status, code)
	}
	if _, _, code := d.agent(nil, "credential", "--lease", write.ID); code == 0 {
		return errors.New("a denied request handed out a credential")
	}
	return nil
}

func (d *demo) s6() error {
	if err := d.bind(model.RoleMember); err != nil {
		return err
	}
	// A reason is required for anything above read.
	if _, _, code := d.agent(nil, "access", "request", "--account", demoAccount, "--resource", "ecs", "--permission", "write", "--ttl", "10m"); code == 0 {
		return errors.New("a write request without a reason was accepted")
	}
	write, _, err := d.request("write", "--name", "i-2ze0demo001", "--reason", "restart after a config change")
	if err != nil {
		return err
	}
	if write.Status != model.LeasePending {
		return fmt.Errorf("a member's write request is %s, want pending", write.Status)
	}
	if _, _, code := d.agent(nil, "credential", "--lease", write.ID); code == 0 {
		return errors.New("a waiting request handed out a credential")
	}
	// It is in the owner's inbox; a supervisor cannot approve it.
	var inbox struct {
		Items []model.AccessRequest `json:"items"`
	}
	if err := d.must(d.mei, http.MethodGet, "/api/v1/me/requests?status=pending", nil, &inbox, http.StatusOK); err != nil {
		return err
	}
	found := false
	for _, item := range inbox.Items {
		found = found || item.ID == write.ID
	}
	if !found {
		return errors.New("the request is not in the owner's inbox")
	}
	for _, path := range []string{"/api/v1/me/requests/" + write.ID + "/approve", "/api/v1/supervisor/leases/" + write.ID + "/approve"} {
		if err := d.must(d.sup, http.MethodPost, path, nil, nil, http.StatusNotFound); err != nil {
			return err
		}
	}
	if err := d.must(d.mei, http.MethodPost, "/api/v1/me/requests/"+write.ID+"/approve", nil, nil, http.StatusOK); err != nil {
		return err
	}
	if st, err := d.status(write.ID); err != nil || st != model.LeaseActive {
		return fmt.Errorf("the approved request is %s (%v), want active", st, err)
	}
	token, err := d.credentialToken(write.ID)
	if err != nil {
		return err
	}
	d.writeLease, d.writeToken = write.ID, token
	if out, code := d.mock(token, "POST", "/v1/ecs/instances/i-2ze0demo001/restart"); code != 0 {
		return fmt.Errorf("the approved credential cannot restart the named instance: %s", firstLine(out))
	}
	// Scoped to one instance and to ECS: nothing else.
	if out, code := d.mock(token, "POST", "/v1/ecs/instances/i-2ze0demo002/restart"); code == 0 || !strings.Contains(out, "Forbidden.RAM") {
		return errors.New("the credential restarted an instance it was not asked for")
	}
	if out, code := d.mock(token, "POST", "/v1/dns/zones/arveykao.com/records", `{"RR":"demo","Type":"A","Value":"192.0.2.1"}`); code == 0 || !strings.Contains(out, "Forbidden.RAM") {
		return errors.New("an ECS credential changed DNS")
	}
	// Full access is above a member's role.
	full, _, err := d.request("full", "--reason", "rebuild the instance")
	if err != nil {
		return err
	}
	if full.Status != model.LeaseDenied {
		return fmt.Errorf("a member's full request is %s, want denied", full.Status)
	}
	return nil
}

func (d *demo) s7() error {
	if d.writeToken == "" {
		return errors.New("S6 issued no write credential")
	}
	if err := d.bind(model.RoleGuest); err != nil {
		return err
	}
	if st, err := d.status(d.writeLease); err != nil || st != model.LeaseRevoked {
		return fmt.Errorf("the write credential is %s (%v) after the role was lowered, want revoked", st, err)
	}
	if out, code := d.mock(d.writeToken, "POST", "/v1/ecs/instances/i-2ze0demo001/restart"); code == 0 || !strings.Contains(out, "InvalidSecurityToken") {
		return errors.New("the credential still works after the role was lowered")
	}
	return nil
}

func (d *demo) s8() error {
	read, _, err := d.request("read")
	if err != nil {
		return err
	}
	token, err := d.credentialToken(read.ID)
	if err != nil {
		return err
	}
	if err := d.must(d.sup, http.MethodPost, "/api/v1/supervisor/leases/"+read.ID+"/revoke",
		model.RevokeLeaseInput{Reason: "demo: emergency stop"}, nil, http.StatusOK); err != nil {
		return err
	}
	if out, code := d.mock(token, "GET", "/v1/ecs/instances"); code == 0 || !strings.Contains(out, "InvalidSecurityToken") {
		return errors.New("a credential a supervisor stopped still works")
	}
	// A supervisor is Administrator on every cloud account without a role.
	var mine struct {
		Items []model.PersonAccount `json:"items"`
	}
	if err := d.must(d.sup, http.MethodGet, "/api/v1/me/accounts", nil, &mine, http.StatusOK); err != nil {
		return err
	}
	if len(mine.Items) != 1 || mine.Items[0].Role != model.RoleAdministrator {
		return errors.New("the supervisor is not Administrator on the demo account")
	}
	// The admin token and its API no longer exist.
	nobody := &person{name: "nobody", client: &http.Client{Timeout: 30 * time.Second}}
	for _, path := range []string{"/api/v1/admin/login", "/api/v1/admin/agents", "/api/v1/admin/providers"} {
		for _, p := range []*person{nobody, d.sup} {
			if err := d.must(p, http.MethodGet, path, nil, nil, http.StatusNotFound); err != nil {
				return err
			}
		}
	}
	if _, errOut, code := d.agent(nil, "providers", "list"); code != 2 || !strings.Contains(errOut, "unknown command") {
		return errors.New("csg still has the admin commands")
	}
	return nil
}

func (d *demo) s9() error {
	var verify model.AuditVerifyResult
	if err := d.must(d.sup, http.MethodGet, "/api/v1/supervisor/audit/verify", nil, &verify, http.StatusOK); err != nil {
		return err
	}
	if !verify.OK || verify.Events == 0 {
		return fmt.Errorf("the audit chain does not verify: %s", verify.Message)
	}
	var events struct {
		Items []model.AuditEvent `json:"items"`
	}
	if err := d.must(d.sup, http.MethodGet, "/api/v1/supervisor/audit?limit=200", nil, &events, http.StatusOK); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, ev := range events.Items {
		seen[ev.Action] = true
	}
	for _, action := range []string{"person.created", "agent_signin.approved", "lease.requested", "lease.auto_approved",
		"lease.approved", "lease.denied", "lease.revoked", "lease.credential_fetched", "binding.set",
		"mcp_signin.approved", "mcp_signin.completed", "lease.credential_link_created"} {
		if !seen[action] {
			return fmt.Errorf("the audit log has no %s event", action)
		}
	}
	// mei cannot read the audit log.
	if err := d.must(d.mei, http.MethodGet, "/api/v1/supervisor/audit", nil, nil, http.StatusForbidden); err != nil {
		return err
	}
	log, err := os.ReadFile(d.logPath)
	if err != nil {
		return err
	}
	auditJSON, _ := json.Marshal(events)
	if len(d.secrets) < 8 {
		return fmt.Errorf("only %d secrets were collected; the leak check would prove little", len(d.secrets))
	}
	for name, value := range d.secrets {
		if value == "" {
			return fmt.Errorf("no value collected for %s", name)
		}
		for where, haystack := range map[string][]byte{"the server log": log, "the audit log": auditJSON, "the demo's own output": d.printed.Bytes()} {
			if bytes.Contains(haystack, []byte(value)) {
				return fmt.Errorf("%s appears in %s", name, where)
			}
		}
	}
	return nil
}

func (d *demo) s9person() error {
	// csg person login: the supervisor approves the code in the console.
	cmd := exec.Command(d.csg, "person", "login", "--server", d.server, "--name", "demo-laptop")
	cmd.Env = []string{"HOME=" + d.home, "PATH=" + os.Getenv("PATH")}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var shown bytes.Buffer
	approved := false
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		line := scanner.Text()
		shown.WriteString(line + "\n")
		if code, ok := strings.CutPrefix(strings.TrimSpace(line), "code: "); ok && !approved {
			d.secrets["the command-line sign-in code"] = code
			var pending model.CLISignIn
			if err := d.must(d.sup, http.MethodGet, "/api/v1/me/cli-signins/"+code, nil, &pending, http.StatusOK); err != nil {
				_ = cmd.Process.Kill()
				return err
			}
			if pending.ClientName != "demo-laptop" {
				_ = cmd.Process.Kill()
				return fmt.Errorf("the console shows client %q for this code", pending.ClientName)
			}
			if err := d.must(d.sup, http.MethodPost, "/api/v1/me/cli-signins/"+code+"/approve", nil, nil, http.StatusOK); err != nil {
				_ = cmd.Process.Kill()
				return err
			}
			approved = true
		}
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("csg person login: %v: %s", err, firstLine(shown.String()))
	}
	raw, err := os.ReadFile(filepath.Join(d.home, ".config", "cloud-safeguard", "person.json"))
	if err != nil {
		return err
	}
	var saved struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil || !strings.HasPrefix(saved.Token, "csg_ses_") {
		return errors.New("csg person login saved no session")
	}
	d.secrets["the supervisor's command-line session"] = saved.Token
	if strings.Contains(stdout.String()+shown.String(), saved.Token) {
		return errors.New("csg person login printed the session token")
	}

	// Reading works.
	out, errOut, code := d.agent(nil, "supervisor", "people")
	if code != 0 || !strings.Contains(out, "mei") {
		return fmt.Errorf("csg supervisor people exit %d: %s", code, firstLine(errOut))
	}
	// Raising access without a code is refused, nothing changes.
	if _, errOut, code := d.agent(nil, "supervisor", "roles", "set", demoAccount, "mei", "member"); code != 3 || !strings.Contains(errOut, "--code") {
		return fmt.Errorf("a role was raised without a code (exit %d): %s", code, firstLine(errOut))
	}
	// With a fresh code it works.
	next, err := authn.TOTPCode(d.supSecret, authn.TOTPStep(time.Now())+1)
	if err != nil {
		return err
	}
	if _, errOut, code := d.agent(nil, "supervisor", "roles", "set", demoAccount, "mei", "member", "--code", next); code != 0 {
		return fmt.Errorf("raising a role with a code: exit %d: %s", code, firstLine(errOut))
	}
	// Lowering needs none.
	if _, errOut, code := d.agent(nil, "supervisor", "roles", "set", demoAccount, "mei", "guest"); code != 0 {
		return fmt.Errorf("lowering a role: exit %d: %s", code, firstLine(errOut))
	}
	// Approving an agent's request is never possible from the command line,
	// even for the request's owner with a code (the session is the
	// supervisor's here; the server refuses it as console-only).
	write, _, err := d.request("write", "--reason", "demo: try to approve from the command line")
	if err != nil {
		return err
	}
	{
		req, _ := http.NewRequest(http.MethodPost, d.server+"/api/v1/me/requests/"+write.ID+"/approve", strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer "+saved.Token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			return fmt.Errorf("approving from a command-line session answered %d, want 403", resp.StatusCode)
		}
	}
	if _, errOut, code := d.agent(nil, "supervisor", "accounts", "add"); code != 2 || !strings.Contains(errOut, "console") {
		return errors.New("csg offers to add a cloud account")
	}
	// Sign out.
	if _, errOut, code := d.agent(nil, "person", "logout"); code != 0 {
		return fmt.Errorf("csg person logout: %s", firstLine(errOut))
	}
	if _, _, code := d.agent(nil, "person", "whoami"); code != 3 {
		return errors.New("the session still works after logout")
	}
	return nil
}

// s10remote is a remote MCP client that knows only the server's URL: it
// discovers the sign-in, registers, mei approves in the console, and the
// credential reaches a shell through a one-time link.
func (d *demo) s11modeRefresh() error {
	// The earlier scenarios used up this minute's requests: the supervisor
	// raises the limit for the scenario and puts it back after.
	var settings model.PolicySettings
	if err := d.must(d.sup, http.MethodGet, "/api/v1/supervisor/settings", nil, &settings, http.StatusOK); err != nil {
		return err
	}
	raised := settings
	raised.LeasesPerMinutePerAgent = 60
	if err := d.must(d.sup, http.MethodPut, "/api/v1/supervisor/settings", raised, nil, http.StatusOK); err != nil {
		return err
	}
	defer func() { _ = d.must(d.sup, http.MethodPut, "/api/v1/supervisor/settings", settings, nil, http.StatusOK) }()
	if err := d.bind(model.RoleMember); err != nil {
		return err
	}
	var mine struct {
		Items []model.PersonAccount `json:"items"`
	}
	if err := d.must(d.mei, http.MethodGet, "/api/v1/me/accounts", nil, &mine, http.StatusOK); err != nil {
		return err
	}
	var providerID string
	for _, a := range mine.Items {
		if a.CloudAccountID == demoAccount {
			providerID = a.ProviderID
		}
	}
	if providerID == "" {
		return errors.New("the demo account is not among mei's accounts")
	}
	// Write mode on this account: write is issued at once, no approval.
	if err := d.must(d.mei, http.MethodPut, "/api/v1/me/accounts/"+providerID+"/mode",
		model.SetApprovalModeInput{Mode: model.ModeWrite}, nil, http.StatusOK); err != nil {
		return err
	}
	write, _, err := d.request("write", "--reason", "restart after a config change", "--max-lifetime", "1h")
	if err != nil {
		return err
	}
	if write.Status != model.LeaseActive || write.RefreshUntil == nil {
		return fmt.Errorf("write in write mode is %s (%s), want active at once", write.Status, write.DeniedReason)
	}
	first, err := d.credentialToken(write.ID)
	if err != nil {
		return err
	}
	// A new key under the same request; it works, and so does the old one
	// until its own expiry.
	stdout, stderr, code := d.agent(nil, "access", "refresh", write.ID, "--json")
	var refreshed model.AccessRequest
	if code != 0 || json.Unmarshal([]byte(stdout), &refreshed) != nil || refreshed.RefreshCount != 1 {
		return fmt.Errorf("csg access refresh exit %d: %s", code, firstLine(stderr))
	}
	second, err := d.credentialToken(write.ID)
	if err != nil {
		return err
	}
	if second == first {
		return errors.New("the refresh handed out the same key")
	}
	if out, code := d.mock(second, "POST", "/v1/ecs/instances/i-2ze0demo001/restart"); code != 0 {
		return fmt.Errorf("the refreshed key cannot restart: %s", firstLine(out))
	}
	// At most once a minute.
	if _, _, code := d.agent(nil, "access", "refresh", write.ID); code == 0 {
		return errors.New("a second refresh within a minute was accepted")
	}
	if _, errOut, code := d.agent(nil, "revoke", "--lease", write.ID); code != 0 {
		return fmt.Errorf("csg revoke exit %d: %s", code, firstLine(errOut))
	}
	if _, _, code := d.agent(nil, "access", "refresh", write.ID); code == 0 {
		return errors.New("a revoked request was refreshed")
	}
	// Back to read, and the role back to guest, as before this scenario.
	if err := d.must(d.mei, http.MethodPut, "/api/v1/me/accounts/"+providerID+"/mode",
		model.SetApprovalModeInput{Mode: model.ModeRead}, nil, http.StatusOK); err != nil {
		return err
	}
	return d.bind(model.RoleGuest)
}

func (d *demo) s12aws() error {
	var settings model.PolicySettings
	if err := d.must(d.sup, http.MethodGet, "/api/v1/supervisor/settings", nil, &settings, http.StatusOK); err != nil {
		return err
	}
	raised := settings
	raised.LeasesPerMinutePerAgent = 60
	if err := d.must(d.sup, http.MethodPut, "/api/v1/supervisor/settings", raised, nil, http.StatusOK); err != nil {
		return err
	}
	defer func() { _ = d.must(d.sup, http.MethodPut, "/api/v1/supervisor/settings", settings, nil, http.StatusOK) }()

	const awsAccount = "123456789012"
	var prov model.Provider
	if err := d.must(d.sup, http.MethodPost, "/api/v1/supervisor/accounts", model.CreateProviderInput{
		Name: "demo-aws", Type: model.ProviderAWS, Mode: model.ModeMock, Region: "us-east-1",
		RoleARN: "arn:aws:iam::" + awsAccount + ":role/cloud-safeguard"}, &prov, http.StatusCreated); err != nil {
		return err
	}
	if err := d.must(d.sup, http.MethodPut, "/api/v1/supervisor/accounts/"+prov.ID+"/people/"+d.mei.id,
		model.PutBindingInput{Role: model.RoleMember}, nil, http.StatusOK); err != nil {
		return err
	}
	stdout, stderr, code := d.agent(nil, "access", "request", "--account", awsAccount, "--resource", "s3", "--name", "claudecode",
		"--permission", "read", "--ttl", "10m", "--json")
	var read model.AccessRequest
	if code != 0 || json.Unmarshal([]byte(stdout), &read) != nil || read.Status != model.LeaseActive {
		return fmt.Errorf("s3 read request exit %d: %s", code, firstLine(stderr))
	}
	// The credential comes as the AWS variables.
	exports, _, code := d.agent(nil, "credential", "--lease", read.ID, "--export")
	if code != 0 || !strings.Contains(exports, "export AWS_ACCESS_KEY_ID=") || !strings.Contains(exports, "export AWS_SESSION_TOKEN=") ||
		strings.Contains(exports, "ALIBABA_CLOUD") {
		return errors.New("the AWS credential did not come as AWS_ variables")
	}
	token, err := d.credentialToken(read.ID)
	if err != nil {
		return err
	}
	s3 := func(args ...string) (string, int) {
		out, errOut, code := d.agent([]string{"CSG_SERVER=" + d.server, "AWS_SESSION_TOKEN=" + token}, append([]string{"mock", "request"}, args...)...)
		return out + errOut, code
	}
	if out, code := s3("GET", "/v1/s3/buckets/claudecode/objects"); code != 0 || !strings.Contains(out, "notes/plan.txt") {
		return fmt.Errorf("listing claudecode failed: %s", firstLine(out))
	}
	if out, code := s3("GET", "/v1/s3/buckets/claudecode/objects/README.md"); code != 0 {
		return fmt.Errorf("reading an object failed: %s", firstLine(out))
	}
	for _, c := range [][]string{
		{"PUT", "/v1/s3/buckets/claudecode/objects/new.txt", `{"Body":"x"}`},
		{"GET", "/v1/s3/buckets/other-team-bucket/objects"},
		{"GET", "/v1/iam/users"},
	} {
		if out, code := s3(c...); code == 0 || !strings.Contains(out, "Forbidden") {
			return fmt.Errorf("a read key on claudecode was allowed %s %s", c[0], c[1])
		}
	}
	if _, errOut, code := d.agent(nil, "revoke", "--lease", read.ID); code != 0 {
		return fmt.Errorf("csg revoke exit %d: %s", code, firstLine(errOut))
	}
	if out, code := s3("GET", "/v1/s3/buckets/claudecode/objects"); code == 0 || !strings.Contains(out, "InvalidSecurityToken") {
		return errors.New("a revoked AWS key still works")
	}
	d.say("      an AWS account (mock): read on bucket claudecode listed and read it; writing, another bucket and IAM were refused\n")
	return nil
}

func (d *demo) s10remote() error {
	plain := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	send := func(method, target, contentType, token string, body []byte) (*http.Response, []byte, error) {
		req, err := http.NewRequest(method, target, bytes.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := plain.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp, raw, nil
	}
	// Discovery from the URL alone.
	resp, _, err := send(http.MethodPost, d.server+"/mcp", "application/json", "", []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		return err
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(challenge, "/.well-known/oauth-protected-resource") {
		return fmt.Errorf("/mcp without a token answered %d %q", resp.StatusCode, challenge)
	}
	var meta struct {
		Authorize string `json:"authorization_endpoint"`
		Token     string `json:"token_endpoint"`
		Register  string `json:"registration_endpoint"`
	}
	_, raw, err := send(http.MethodGet, d.server+"/.well-known/oauth-authorization-server", "", "", nil)
	if err != nil || json.Unmarshal(raw, &meta) != nil || meta.Register == "" {
		return fmt.Errorf("no authorization server metadata: %v", err)
	}
	redirect := "http://127.0.0.1:53682/callback"
	body, _ := json.Marshal(map[string]any{"client_name": "Demo MCP App", "redirect_uris": []string{redirect}})
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if _, raw, err = send(http.MethodPost, meta.Register, "application/json", "", body); err != nil || json.Unmarshal(raw, &reg) != nil || reg.ClientID == "" {
		return fmt.Errorf("registration failed: %v", err)
	}
	verifierBytes := make([]byte, 32)
	_, _ = rand.Read(verifierBytes)
	verifier := hex.EncodeToString(verifierBytes)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {redirect}, "state": {"demo-state"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	resp, _, err = send(http.MethodGet, meta.Authorize+"?"+q.Encode(), "", "", nil)
	if err != nil {
		return err
	}
	connID, ok := strings.CutPrefix(resp.Header.Get("Location"), "/?mcp-connect=")
	if resp.StatusCode != http.StatusFound || !ok {
		return fmt.Errorf("authorize answered %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	d.secrets["the MCP connection id"] = connID

	// mei sees where the sign-in goes and approves.
	var view struct {
		ClientName   string `json:"client_name"`
		RedirectHost string `json:"redirect_host"`
	}
	if err := d.must(d.mei, http.MethodGet, "/api/v1/me/mcp-connections/"+connID, nil, &view, http.StatusOK); err != nil {
		return err
	}
	if view.ClientName != "Demo MCP App" || view.RedirectHost != "127.0.0.1:53682" {
		return fmt.Errorf("the console shows %+v", view)
	}
	var approved struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := d.must(d.mei, http.MethodPost, "/api/v1/me/mcp-connections/"+connID+"/approve", map[string]string{"agent_name": "demo-mcp-app"}, &approved, http.StatusOK); err != nil {
		return err
	}
	back, err := url.Parse(approved.RedirectURL)
	if err != nil || back.Query().Get("state") != "demo-state" || back.Query().Get("code") == "" {
		return fmt.Errorf("unexpected redirect back to the app")
	}
	code := back.Query().Get("code")
	d.secrets["the MCP authorization code"] = code
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {reg.ClientID}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if _, raw, err = send(http.MethodPost, meta.Token, "application/x-www-form-urlencoded", "", []byte(form.Encode())); err != nil || json.Unmarshal(raw, &tok) != nil || tok.AccessToken == "" {
		return fmt.Errorf("token exchange failed: %v", err)
	}
	d.secrets["the MCP agent token"] = tok.AccessToken
	if resp, _, _ := send(http.MethodPost, meta.Token, "application/x-www-form-urlencoded", "", []byte(form.Encode())); resp == nil || resp.StatusCode != http.StatusBadRequest {
		return errors.New("an authorization code worked twice")
	}

	// The tools over HTTP.
	tool := func(name string, args map[string]any) (string, error) {
		msg, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
		resp, raw, err := send(http.MethodPost, d.server+"/mcp", "application/json", tok.AccessToken, msg)
		if err != nil {
			return "", err
		}
		var out struct {
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
				IsError bool `json:"isError"`
			} `json:"result"`
		}
		if resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &out) != nil || len(out.Result.Content) != 1 {
			return "", fmt.Errorf("%s answered %d", name, resp.StatusCode)
		}
		if out.Result.IsError {
			return "", fmt.Errorf("%s: %s", name, out.Result.Content[0].Text)
		}
		return out.Result.Content[0].Text, nil
	}
	text, err := tool("request_access", map[string]any{"cloud_account_id": demoAccount, "resource": "ecs", "permission": "read", "ttl_seconds": 300})
	if err != nil {
		return err
	}
	var req struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if json.Unmarshal([]byte(text), &req) != nil || req.Status != "active" {
		return fmt.Errorf("read access was not issued at once: %s", firstLine(text))
	}
	if text, err = tool("get_credential", map[string]any{"request_id": req.ID}); err != nil {
		return err
	}
	var cred struct {
		Run string `json:"run"`
	}
	if json.Unmarshal([]byte(text), &cred) != nil || !strings.HasPrefix(cred.Run, `eval "$(curl -fsS -X POST '`) {
		return fmt.Errorf("get_credential gave no one-time link")
	}
	if i := strings.Index(cred.Run, "/credential-links/"); i >= 0 {
		d.secrets["the one-time credential link"] = strings.TrimSuffix(cred.Run[i+len("/credential-links/"):], `')"`)
	}
	// The link sets the credential in a shell; the shell reports only
	// which variables are set.
	check := `; for v in ALIBABA_CLOUD_ACCESS_KEY_ID ALIBABA_CLOUD_ACCESS_KEY_SECRET CSG_LEASE_ID; do [ -n "${!v}" ] && printf '%s ' "$v"; done`
	out, err := exec.Command("bash", "-c", cred.Run+check).Output()
	if err != nil || strings.TrimSpace(string(out)) != "ALIBABA_CLOUD_ACCESS_KEY_ID ALIBABA_CLOUD_ACCESS_KEY_SECRET CSG_LEASE_ID" {
		return fmt.Errorf("the link did not set the credential in the shell (%v): %q", err, out)
	}
	if out, _ := exec.Command("bash", "-c", cred.Run+check).Output(); strings.TrimSpace(string(out)) != "" {
		return errors.New("a one-time link worked twice")
	}
	if _, err := tool("revoke", map[string]any{"request_id": req.ID}); err != nil {
		return err
	}
	d.say("      an MCP app connected by URL as mei's agent demo-mcp-app; the credential went to a shell, not the model\n")
	return nil
}
