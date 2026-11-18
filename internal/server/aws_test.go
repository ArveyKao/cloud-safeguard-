package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
)

// AWS (CONTRACT §17.13), end to end with the real mock minter and the mock
// cloud's S3: read lists and reads one bucket only, never writes, never IAM.
func TestAWSMockAccountEndToEnd(t *testing.T) {
	dir := t.TempDir()
	initRes, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: true})
	if err != nil {
		t.Fatal(err)
	}
	clock := newFakeClock(time.Now())
	srv, err := New(Config{DataDir: dir, Now: clock.Now,
		PasswordParams: &authn.Params{MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	handler := srv.Handler()
	env := &testEnv{t: t, srv: srv, dir: dir, clock: clock, logs: &bytes.Buffer{}, supervisor: initRes.Supervisor,
		providerID: initRes.ProviderIDs[0]}
	sup := env.supervisorClient()

	// The account: an AWS role ARN gives the 12-digit account ID; an
	// Alibaba ARN on an AWS account is refused.
	bad := model.CreateProviderInput{Name: "aws", Type: model.ProviderAWS, Mode: model.ModeMock, Region: "eu-west-1",
		RoleARN: "acs:ram::1234567890123456:role/csg"}
	if rec := sup.do(http.MethodPost, supAccounts, bad); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "arn:aws:iam::") {
		t.Fatalf("an Alibaba ARN on an AWS account: %d %s", rec.Code, rec.Body)
	}
	in := bad
	in.RoleARN = "arn:aws:iam::123456789012:role/cloud-safeguard"
	rec := sup.do(http.MethodPost, supAccounts, in)
	requireStatus(t, rec, http.StatusCreated)
	prov := decodeEnvelope[model.Provider](t, rec)
	if prov.CloudAccountID != "123456789012" || prov.Type != model.ProviderAWS || !strings.HasPrefix(prov.AccessKeyIDMasked, "AKIA") {
		t.Fatalf("account %+v", prov)
	}

	mei := env.addPerson(sup, "mei", false)
	requireStatus(t, sup.do(http.MethodPut, supAccounts+"/"+prov.ID+"/people/"+mei.person.ID,
		model.PutBindingInput{Role: model.RoleMember}), http.StatusOK)
	_, agentToken := env.signInAgent(mei, "claude-code")

	// The agent sees the account and its resource types.
	rec = rawRequest(t, handler, http.MethodGet, "/api/v1/agent/accounts", agentToken, nil)
	var found bool
	for _, a := range decodeEnvelope[listData[model.AgentAccount]](t, rec).Items {
		if a.CloudAccountID == "123456789012" && a.ProviderType == model.ProviderAWS && strings.Join(a.Resources, ",") == "s3" {
			found = true
		}
	}
	if !found {
		t.Fatalf("accounts %s", rec.Body)
	}
	// Alibaba resource types do not exist on AWS.
	requireStatus(t, rawRequest(t, handler, http.MethodPost, "/api/v1/agent/access-requests", agentToken, model.AccessRequestInput{
		CloudAccountID: "123456789012", Resource: "oss", Permission: "read", TTLSeconds: 600}), http.StatusBadRequest)

	createRec := rawRequest(t, handler, http.MethodPost, "/api/v1/agent/access-requests", agentToken, model.AccessRequestInput{
		CloudAccountID: "123456789012", Resource: "s3", Permission: "read", ResourceName: "claudecode", TTLSeconds: 600})
	requireStatus(t, createRec, http.StatusCreated)
	req := decodeEnvelope[model.AccessRequest](t, createRec)
	if req.Status != model.LeaseActive {
		t.Fatalf("request %+v", req)
	}
	credRec := rawRequest(t, handler, http.MethodPost, "/api/v1/agent/leases/"+req.ID+"/credential", agentToken, nil)
	requireStatus(t, credRec, http.StatusOK)
	envelope := decodeEnvelope[model.CredentialEnvelope](t, credRec)
	env2 := map[string]string{}
	for _, kv := range envelope.Env {
		env2[kv.Name] = kv.Value
	}
	if env2["AWS_ACCESS_KEY_ID"] == "" || env2["AWS_SECRET_ACCESS_KEY"] == "" || env2["AWS_SESSION_TOKEN"] == "" ||
		env2["AWS_REGION"] != "eu-west-1" || env2["ALIBABA_CLOUD_ACCESS_KEY_ID"] != "" || env2["CSG_LEASE_ID"] != req.ID {
		t.Fatalf("environment names %v", keys(env2))
	}
	token := env2["AWS_SESSION_TOKEN"]

	call := func(method, path string, body any) int {
		t.Helper()
		return rawRequest(t, handler, method, "/mock-cloud"+path, token, body).Code
	}
	if c := call(http.MethodGet, "/v1/s3/buckets/claudecode/objects", nil); c != http.StatusOK {
		t.Fatalf("list the bucket: %d", c)
	}
	if c := call(http.MethodGet, "/v1/s3/buckets/claudecode/objects/notes/plan.txt", nil); c != http.StatusOK {
		t.Fatalf("read an object: %d", c)
	}
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPut, "/v1/s3/buckets/claudecode/objects/new.txt", map[string]string{"Body": "x"}},
		{http.MethodDelete, "/v1/s3/buckets/claudecode/objects/README.md", nil},
		{http.MethodGet, "/v1/s3/buckets/other-team-bucket/objects", nil},
		{http.MethodGet, "/v1/s3/buckets/other-team-bucket/objects/secret.txt", nil},
		{http.MethodGet, "/v1/iam/users", nil},
	} {
		if got := call(c.method, c.path, c.body); got != http.StatusForbidden {
			t.Errorf("%s %s with a read key on claudecode: %d", c.method, c.path, got)
		}
	}

	// Write: objects in the bucket change; still no IAM.
	writeRec := rawRequest(t, handler, http.MethodPost, "/api/v1/agent/access-requests", agentToken, model.AccessRequestInput{
		CloudAccountID: "123456789012", Resource: "s3", Permission: "write", ResourceName: "claudecode", TTLSeconds: 600,
		Reason: "upload the build report"})
	requireStatus(t, writeRec, http.StatusCreated)
	write := decodeEnvelope[model.AccessRequest](t, writeRec)
	requireStatus(t, mei.do(http.MethodPost, "/api/v1/me/requests/"+write.ID+"/approve", nil), http.StatusOK)
	credRec = rawRequest(t, handler, http.MethodPost, "/api/v1/agent/leases/"+write.ID+"/credential", agentToken, nil)
	requireStatus(t, credRec, http.StatusOK)
	token = decodeEnvelope[model.CredentialEnvelope](t, credRec).Credential.SecurityToken
	if c := call(http.MethodPut, "/v1/s3/buckets/claudecode/objects/report.txt", map[string]string{"Body": "ok"}); c != http.StatusOK {
		t.Fatalf("write with a write key: %d", c)
	}
	if c := call(http.MethodGet, "/v1/iam/users", nil); c != http.StatusForbidden {
		t.Fatalf("IAM with a write key: %d", c)
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The policy minted for an AWS request: the AWS language, the bucket's ARNs
// and the AWS deny.
func TestAWSRequestPolicy(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	rec := a.sup.do(http.MethodPost, supAccounts, model.CreateProviderInput{Name: "aws", Type: model.ProviderAWS, Mode: model.ModeMock,
		Region: "us-east-1", RoleARN: "arn:aws:iam::123456789012:role/cloud-safeguard"})
	requireStatus(t, rec, http.StatusCreated)
	prov := decodeEnvelope[model.Provider](t, rec)
	requireStatus(t, a.sup.do(http.MethodPut, supAccounts+"/"+prov.ID+"/people/"+a.mei.person.ID,
		model.PutBindingInput{Role: model.RoleGuest}), http.StatusOK)
	req := a.request(model.AccessRequestInput{CloudAccountID: "123456789012", Resource: "s3", Permission: "read",
		ResourceName: "claudecode", TTLSeconds: 900})
	if req.Status != model.LeaseActive {
		t.Fatalf("request %+v", req)
	}
	policy := string(a.minter.lastRequest(t).PolicyJSON)
	for _, want := range []string{`"Version":"2012-10-17"`, `"arn:aws:s3:::claudecode"`, `"arn:aws:s3:::claudecode/*"`, `"s3:Get*"`, `"iam:*"`, `"sts:AssumeRole*"`} {
		if !strings.Contains(policy, want) {
			t.Errorf("policy lacks %s: %s", want, policy)
		}
	}
	if strings.Contains(policy, "PutObject") || strings.Contains(policy, "ram:") {
		t.Errorf("policy: %s", policy)
	}
	// A bucket name that is not one: refused before anything is minted.
	requireStatus(t, a.requestRaw(a.token, model.AccessRequestInput{CloudAccountID: "123456789012", Resource: "s3",
		Permission: "read", ResourceName: "Bad_Bucket", TTLSeconds: 900}), http.StatusBadRequest)
}

// A connection test that passes with a warning says so, and the audit
// records it.
func TestConnectionTestWarning(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	a.minter.setFailure(&provider.TestWarning{Message: "the role allows IAM"})
	rec := a.sup.do(http.MethodPost, supAccounts+"/"+a.providerID+"/test", nil)
	requireStatus(t, rec, http.StatusOK)
	out := decodeEnvelope[providerTestResult](t, rec)
	if !out.OK || out.Warning != "the role allows IAM" {
		t.Fatalf("result %+v", out)
	}
	if ev := a.lastEvent("provider.tested"); ev.Severity != "warning" || ev.Metadata["warning"] != "the role allows IAM" {
		t.Fatalf("audit %+v", ev)
	}
	a.minter.setFailure(errors.New("AccessDenied: no"))
	out = decodeEnvelope[providerTestResult](t, a.sup.do(http.MethodPost, supAccounts+"/"+a.providerID+"/test", nil))
	if out.OK || out.Warning != "" {
		t.Fatalf("failed test %+v", out)
	}
}
