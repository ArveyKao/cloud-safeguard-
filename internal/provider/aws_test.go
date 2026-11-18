package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// The Signature Version 4 example from the AWS documentation (IAM ListUsers,
// 2015-08-30 12:36:00 UTC, example keys).
func TestAWSSignatureMatchesTheDocumentedExample(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	signAWS(req, "iam.amazonaws.com", "", awsSigner{accessKeyID: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
		"us-east-1", "iam", time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, " +
		"Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("authorization\n got %s\nwant %s", got, want)
	}
}

// fakeAWS answers STS and IAM like AWS, checks the signature's shape and
// records the forms it received.
type fakeAWS struct {
	mu        sync.Mutex
	forms     []url.Values
	headers   []http.Header
	assumeErr string // an error code AssumeRole answers with
	iamAllows string // the one IAM action the role allows, if any
	iamBroken bool   // IAM answers with a server error
}

func (f *fakeAWS) serve(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		f.mu.Lock()
		f.forms = append(f.forms, form)
		f.headers = append(f.headers, r.Header.Clone())
		f.mu.Unlock()
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=") || !strings.Contains(auth, "SignedHeaders=content-type;host;x-amz-date") &&
			!strings.Contains(auth, "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token") {
			http.Error(w, "<ErrorResponse><Error><Code>IncompleteSignature</Code></Error></ErrorResponse>", http.StatusForbidden)
			return
		}
		switch form.Get("Action") {
		case "GetCallerIdentity":
			fmt.Fprint(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		case "AssumeRole":
			if f.assumeErr != "" {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>User is not authorized to perform: sts:AssumeRole</Message></Error></ErrorResponse>`, f.assumeErr)
				return
			}
			exp := time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339)
			fmt.Fprintf(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIATEMP%d</AccessKeyId>`+
				`<SecretAccessKey>temp-secret</SecretAccessKey><SessionToken>temp-token</SessionToken><Expiration>%s</Expiration>`+
				`</Credentials></AssumeRoleResult></AssumeRoleResponse>`, len(f.forms), exp)
		case "GetAccountSummary", "ListUsers", "ListRoles", "ListPolicies":
			if r.Header.Get("X-Amz-Security-Token") != "temp-token" {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>`)
				return
			}
			if f.iamBroken {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if f.iamAllows != form.Get("Action") {
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>not authorized</Message></Error></ErrorResponse>`)
				return
			}
			fmt.Fprint(w, `<GetAccountSummaryResponse/>`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	oldSTS, oldIAM := awsSTSEndpoint, awsIAMEndpoint
	awsSTSEndpoint = func(string) string { return srv.URL + "/" }
	awsIAMEndpoint = srv.URL + "/"
	t.Cleanup(func() { awsSTSEndpoint, awsIAMEndpoint = oldSTS, oldIAM })
	return srv
}

func awsRequest() MintRequest {
	return MintRequest{
		LeaseID: "lea_1",
		Provider: model.Provider{ID: "prv_1", Type: model.ProviderAWS, Mode: model.ModeSTS, Region: "eu-west-1",
			RoleARN: "arn:aws:iam::123456789012:role/cloud-safeguard"},
		BrokerAccessKeyID: "AKIABROKERKEY", BrokerAccessKeySecret: "broker-secret-value",
		PolicyJSON:      []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:Get*"],"Resource":["arn:aws:s3:::claudecode/*"]}]}`),
		SessionName:     "csg-agt_1-lea_1",
		DurationSeconds: 900,
	}
}

func TestAWSMintAssumesTheRoleWithTheSessionPolicy(t *testing.T) {
	f := &fakeAWS{}
	f.serve(t)
	cred, err := awsMinter{}.Mint(context.Background(), awsRequest())
	if err != nil {
		t.Fatal(err)
	}
	if cred.AccessKeyID == "" || cred.AccessKeySecret != "temp-secret" || cred.SecurityToken != "temp-token" || cred.ExpiresAt.IsZero() {
		t.Fatalf("credential %+v", cred)
	}
	form := f.forms[0]
	if form.Get("RoleArn") != "arn:aws:iam::123456789012:role/cloud-safeguard" || form.Get("DurationSeconds") != "900" ||
		form.Get("RoleSessionName") != "csg-agt_1-lea_1" || !strings.Contains(form.Get("Policy"), "arn:aws:s3:::claudecode/*") ||
		form.Get("Version") != "2011-06-15" {
		t.Fatalf("form %v", form)
	}
	if strings.Contains(f.headers[0].Get("Authorization"), "broker-secret-value") {
		t.Fatal("the secret was sent")
	}
	if !strings.Contains(f.headers[0].Get("Authorization"), "/eu-west-1/sts/aws4_request") {
		t.Fatalf("signed for the wrong region or service: %s", f.headers[0].Get("Authorization"))
	}
}

func TestAWSMintRefusals(t *testing.T) {
	f := &fakeAWS{}
	f.serve(t)
	for name, mutate := range map[string]func(*MintRequest){
		"no role":        func(r *MintRequest) { r.Provider.RoleARN = "" },
		"no key":         func(r *MintRequest) { r.BrokerAccessKeySecret = "" },
		"too short":      func(r *MintRequest) { r.DurationSeconds = 899 },
		"too long":       func(r *MintRequest) { r.DurationSeconds = 43201 },
		"invalid policy": func(r *MintRequest) { r.PolicyJSON = []byte("{") },
		"policy too long": func(r *MintRequest) {
			r.PolicyJSON = []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"` + strings.Repeat("a", 2100) + `"}]}`)
		},
	} {
		req := awsRequest()
		mutate(&req)
		if _, err := (awsMinter{}).Mint(context.Background(), req); err == nil {
			t.Errorf("%s: minted", name)
		}
	}
	if len(f.forms) != 0 {
		t.Fatalf("%d calls for refused requests", len(f.forms))
	}
	// An AWS error carries the code and message, never a key.
	f.assumeErr = "AccessDenied"
	_, err := awsMinter{}.Mint(context.Background(), awsRequest())
	if err == nil || !strings.HasPrefix(err.Error(), "AccessDenied:") || strings.Contains(err.Error(), "AKIABROKERKEY") {
		t.Fatalf("error %v", err)
	}
}

func TestAWSConnectionTest(t *testing.T) {
	f := &fakeAWS{}
	f.serve(t)
	if err := (awsMinter{}).Test(context.Background(), awsRequest()); err != nil {
		t.Fatalf("test: %v", err)
	}
	actions := []string{}
	for _, form := range f.forms {
		actions = append(actions, form.Get("Action"))
	}
	if strings.Join(actions, ",") != "GetCallerIdentity,AssumeRole,AssumeRole,GetAccountSummary,ListUsers,ListRoles,ListPolicies" {
		t.Fatalf("calls %v", actions)
	}
	if !strings.Contains(f.forms[1].Get("Policy"), "sts:GetCallerIdentity") || !strings.Contains(f.forms[2].Get("Policy"), "iam:ListUsers") ||
		strings.Contains(f.forms[2].Get("Policy"), "iam:*") {
		t.Fatal("probe policies are not the narrow ones")
	}
	// A role that allows any of the IAM reads: passed, with a warning that
	// names it.
	var warning *TestWarning
	for _, action := range []string{"GetAccountSummary", "ListRoles"} {
		f.iamAllows = action
		if err := (awsMinter{}).Test(context.Background(), awsRequest()); !errors.As(err, &warning) || !strings.Contains(warning.Message, "iam:"+action+" succeeded") {
			t.Fatalf("%s warning: %v", action, err)
		}
	}
	// When IAM cannot answer, the test passes and says the check could not run.
	f.iamAllows, f.iamBroken = "", true
	if err := (awsMinter{}).Test(context.Background(), awsRequest()); !errors.As(err, &warning) || !strings.Contains(warning.Message, "could not be checked") {
		t.Fatalf("broken IAM: %v", err)
	}
	f.iamBroken = false
	// A region that is not a region name is refused before any call.
	calls := len(f.forms)
	bad := awsRequest()
	bad.Provider.Region = "evil.com/x"
	if err := (awsMinter{}).Test(context.Background(), bad); err == nil || errors.As(err, &warning) {
		t.Fatalf("bad region test: %v", err)
	}
	if _, err := (awsMinter{}).Mint(context.Background(), bad); err == nil || len(f.forms) != calls {
		t.Fatalf("bad region mint: %v, %d calls", err, len(f.forms)-calls)
	}
	// A key that cannot assume the role fails.
	f.assumeErr = "AccessDenied"
	if err := (awsMinter{}).Test(context.Background(), awsRequest()); err == nil || errors.As(err, &warning) {
		t.Fatalf("assume failure: %v", err)
	}
}

func TestNewForChoosesTheCloud(t *testing.T) {
	if m, err := NewFor(model.ProviderAWS, model.ModeSTS); err != nil || fmt.Sprintf("%T", m) != "provider.awsMinter" {
		t.Fatalf("%T %v", m, err)
	}
	if m, err := NewFor(model.ProviderAliyun, model.ModeSTS); err != nil || fmt.Sprintf("%T", m) != "provider.stsMinter" {
		t.Fatalf("%T %v", m, err)
	}
	if m, err := NewFor(model.ProviderAWS, model.ModeMock); err != nil || fmt.Sprintf("%T", m) != "provider.mockMinter" {
		t.Fatalf("%T %v", m, err)
	}
	if _, err := NewFor("gcp", model.ModeSTS); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("gcp: %v", err)
	}
}

// A signed POST with a session token, recomputed independently: it covers
// the form body and the
// X-Amz-Security-Token header the documented GET example does not. The
// expected value was computed with Python hashlib and hmac, not this code.
func TestAWSSignatureOfAPostWithASessionToken(t *testing.T) {
	body := "Action=GetAccountSummary&Version=2010-05-08"
	req, _ := http.NewRequest(http.MethodPost, "https://iam.amazonaws.com/", strings.NewReader(body))
	req.Header.Set("Content-Type", awsContentType)
	signAWS(req, "iam.amazonaws.com", body, awsSigner{accessKeyID: "ASIAEXAMPLE", secretAccessKey: "secret-example", sessionToken: "token-example"},
		"us-east-1", "iam", time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC))
	got := req.Header.Get("Authorization")
	want := "AWS4-HMAC-SHA256 Credential=ASIAEXAMPLE/20261117/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token, Signature=" + expectedPostSignature
	if got != want {
		t.Fatalf("authorization\n got %s\nwant %s", got, want)
	}
}

const expectedPostSignature = "b82e31dbf569c423fceb1be7b2549f8da3e384dae1c7bf0c41b1c66bad144b99"
