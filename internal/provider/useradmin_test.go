package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// fakeCloudUsers answers IAM (form POST) or RAM (query GET) user calls, and
// can fail one action.
type fakeCloudUsers struct {
	mu     sync.Mutex
	calls  []url.Values
	failOn string
	goneOn string   // answers "already gone" for this action
	keys   []string // access keys ListAccessKeys answers
	aliyun bool
}

func (f *fakeCloudUsers) actions() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, c := range f.calls {
		out = append(out, c.Get("Action"))
	}
	return strings.Join(out, ",")
}

func (f *fakeCloudUsers) serve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			values, _ = url.ParseQuery(string(body))
		}
		f.mu.Lock()
		f.calls = append(f.calls, values)
		f.mu.Unlock()
		action := values.Get("Action")
		fail := func(code string) {
			if f.aliyun {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, `{"Code":"%s","Message":"refused"}`, code)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `<ErrorResponse><Error><Code>%s</Code><Message>refused</Message></Error></ErrorResponse>`, code)
		}
		switch {
		case f.failOn != "" && strings.Contains(","+f.failOn+",", ","+action+","):
			fail("AccessDenied")
		case action == f.goneOn && f.aliyun:
			fail("EntityNotExist.User")
		case action == f.goneOn:
			fail("NoSuchEntity")
		case action == "ListAccessKeys" && f.aliyun:
			items := []string{}
			for _, k := range f.keys {
				items = append(items, `{"AccessKeyId":"`+k+`"}`)
			}
			fmt.Fprintf(w, `{"AccessKeys":{"AccessKey":[%s]}}`, strings.Join(items, ","))
		case action == "ListAccessKeys":
			items := ""
			for _, k := range f.keys {
				items += "<member><AccessKeyId>" + k + "</AccessKeyId></member>"
			}
			fmt.Fprintf(w, `<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata>%s</AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>`, items)
		case action == "CreateAccessKey" && f.aliyun:
			fmt.Fprint(w, `{"AccessKey":{"AccessKeyId":"LTAILONGLIVED1","AccessKeySecret":"long-lived-secret"}}`)
		case action == "CreateAccessKey":
			fmt.Fprint(w, `<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>AKIALONGLIVED1</AccessKeyId>`+
				`<SecretAccessKey>long-lived-secret</SecretAccessKey></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`)
		case f.aliyun:
			fmt.Fprint(w, `{"RequestId":"x"}`)
		default:
			fmt.Fprint(w, `<Response/>`)
		}
	}))
	t.Cleanup(srv.Close)
	oldIAM, oldRAM := awsIAMEndpoint, ramEndpoint
	awsIAMEndpoint, ramEndpoint = srv.URL+"/", srv.URL+"/"
	t.Cleanup(func() { awsIAMEndpoint, ramEndpoint = oldIAM, oldRAM })
}

func userRequest(t model.ProviderType) UserRequest {
	return UserRequest{
		Provider:         model.Provider{ID: "prv_1", Type: t, Mode: model.ModeSTS, Region: "us-east-1", CloudAccountID: "123456789012"},
		AdminAccessKeyID: "AKIAADMIN", AdminAccessKeySecret: "admin-secret",
		CredentialID: "llc_0123456789abcdef",
		PolicyJSON:   []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::claudecode/*"]}]}`),
	}
}

func TestAWSUserAdminCreatesWithBoundaryAndCleansUp(t *testing.T) {
	f := &fakeCloudUsers{}
	f.serve(t)
	created, err := awsUserAdmin{}.CreateUser(context.Background(), userRequest(model.ProviderAWS))
	if err != nil {
		t.Fatal(err)
	}
	if created.UserName != "csg-0123456789abcdef" || created.PolicyName != created.UserName ||
		created.AccessKeyID != "AKIALONGLIVED1" || created.AccessKeySecret != "long-lived-secret" {
		t.Fatalf("created %+v", created)
	}
	if f.actions() != "CreateUser,PutUserPolicy,CreateAccessKey" {
		t.Fatalf("calls %s", f.actions())
	}
	first := f.calls[0]
	if first.Get("Path") != "/csg/" || first.Get("PermissionsBoundary") != "arn:aws:iam::123456789012:policy/cloud-safeguard-boundary" {
		t.Fatalf("create user %v", first)
	}
	if !strings.Contains(f.calls[1].Get("PolicyDocument"), "arn:aws:s3:::claudecode/*") {
		t.Fatalf("policy %v", f.calls[1])
	}

	// A failure part-way deletes what was made (listing the keys, so one
	// whose answer was lost goes too), and reports the step.
	f2 := &fakeCloudUsers{failOn: "CreateAccessKey", keys: []string{"AKIALOST"}}
	f2.serve(t)
	_, err = awsUserAdmin{}.CreateUser(context.Background(), userRequest(model.ProviderAWS))
	if err == nil || !strings.Contains(err.Error(), "create access key: AccessDenied") || strings.Contains(err.Error(), "admin-secret") {
		t.Fatalf("error %v", err)
	}
	if f2.actions() != "CreateUser,PutUserPolicy,CreateAccessKey,ListAccessKeys,DeleteAccessKey,DeleteUserPolicy,DeleteUser" ||
		f2.calls[4].Get("AccessKeyId") != "AKIALOST" || errors.Is(err, ErrCleanupFailed) {
		t.Fatalf("cleanup calls %s %v", f2.actions(), err)
	}

	// The cleanup fails too: the caller is told the user may still exist.
	f3 := &fakeCloudUsers{failOn: "CreateAccessKey,DeleteUser"}
	f3.serve(t)
	_, err = awsUserAdmin{}.CreateUser(context.Background(), userRequest(model.ProviderAWS))
	if !errors.Is(err, ErrCleanupFailed) || !strings.Contains(err.Error(), "create access key") {
		t.Fatalf("cleanup failure %v", err)
	}

	// A refused CreateUser made nothing: no cleanup calls.
	f4 := &fakeCloudUsers{failOn: "CreateUser"}
	f4.serve(t)
	if _, err := (awsUserAdmin{}).CreateUser(context.Background(), userRequest(model.ProviderAWS)); err == nil || f4.actions() != "CreateUser" {
		t.Fatalf("refused create %v %s", err, f4.actions())
	}
}

func TestAWSUserAdminDeletes(t *testing.T) {
	f := &fakeCloudUsers{goneOn: "DeleteUserPolicy", keys: []string{"AKIA1", "AKIA2"}}
	f.serve(t)
	req := userRequest(model.ProviderAWS)
	req.UserName, req.PolicyName, req.AccessKeyID = "csg-1", "csg-1", "AKIA1"
	if err := (awsUserAdmin{}).DeleteUser(context.Background(), req); err != nil {
		t.Fatalf("an already deleted policy is not an error: %v", err)
	}
	if f.actions() != "ListAccessKeys,DeleteAccessKey,DeleteAccessKey,DeleteUserPolicy,DeleteUser" || f.calls[2].Get("AccessKeyId") != "AKIA2" {
		t.Fatalf("calls %s", f.actions())
	}
	f2 := &fakeCloudUsers{failOn: "DeleteAccessKey", keys: []string{"AKIA1"}}
	f2.serve(t)
	if err := (awsUserAdmin{}).DeleteUser(context.Background(), req); err == nil || f2.actions() != "ListAccessKeys,DeleteAccessKey" {
		t.Fatalf("a failed key deletion must stop and report: %v %s", err, f2.actions())
	}
	// No user: nothing else to delete.
	f3 := &fakeCloudUsers{goneOn: "ListAccessKeys"}
	f3.serve(t)
	if err := (awsUserAdmin{}).DeleteUser(context.Background(), req); err != nil || f3.actions() != "ListAccessKeys" {
		t.Fatalf("gone user %v %s", err, f3.actions())
	}
	// Without recorded names the credential ID gives them; never a non-csg user.
	f4 := &fakeCloudUsers{}
	f4.serve(t)
	bare := userRequest(model.ProviderAWS)
	if err := (awsUserAdmin{}).DeleteUser(context.Background(), bare); err != nil || f4.calls[0].Get("UserName") != "csg-0123456789abcdef" {
		t.Fatalf("by id %v %v", err, f4.calls)
	}
	bare.UserName = "admin"
	if err := (awsUserAdmin{}).DeleteUser(context.Background(), bare); err == nil {
		t.Fatal("deleted a non-csg user")
	}
}

func TestRefuseManagedIdentity(t *testing.T) {
	for arn, refused := range map[string]bool{
		"arn:aws:iam::123456789012:user/csg-admin":       true,
		"arn:aws:iam::123456789012:user/csg/anything":    true,
		"arn:aws:iam::123456789012:user/ops/CSG-x":       true,
		"arn:aws:iam::123456789012:user/csg-useradmin-x": true,
		"acs:ram::1234567890123456:user/csg-admin":       true,
		"arn:aws:iam::123456789012:user/csg-safeguard":   true,
		"arn:aws:iam::123456789012:user/safeguard-admin": false,
		"acs:ram::1234567890123456:user/safeguard":       false,
		"arn:aws:iam::123456789012:root":                 false,
	} {
		if got := refuseManagedIdentity(arn) != nil; got != refused {
			t.Errorf("%s: refused %v", arn, got)
		}
	}
}

func TestAliyunUserAdmin(t *testing.T) {
	f := &fakeCloudUsers{aliyun: true}
	f.serve(t)
	req := userRequest(model.ProviderAliyun)
	req.PolicyJSON = []byte(`{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:GetObject"],"Resource":["acs:oss:*:*:b/*"]}]}`)
	created, err := aliyunUserAdmin{}.CreateUser(context.Background(), req)
	if err != nil || created.AccessKeyID != "LTAILONGLIVED1" || created.AccessKeySecret != "long-lived-secret" {
		t.Fatalf("created %+v %v", created, err)
	}
	if f.actions() != "CreateUser,CreatePolicy,AttachPolicyToUser,CreateAccessKey" {
		t.Fatalf("calls %s", f.actions())
	}
	if f.calls[2].Get("PolicyType") != "Custom" || f.calls[0].Get("Signature") == "" || f.calls[0].Get("Version") != "2015-05-01" {
		t.Fatalf("calls %v", f.calls)
	}
	// Attach fails: policy and user are deleted, no detach is needed.
	f2 := &fakeCloudUsers{aliyun: true, failOn: "AttachPolicyToUser"}
	f2.serve(t)
	if _, err := (aliyunUserAdmin{}).CreateUser(context.Background(), req); err == nil ||
		f2.actions() != "CreateUser,CreatePolicy,AttachPolicyToUser,ListAccessKeys,DetachPolicyFromUser,DeletePolicy,DeleteUser" {
		t.Fatalf("cleanup %v %s", err, f2.actions())
	}
	f3 := &fakeCloudUsers{aliyun: true, goneOn: "DeleteAccessKey", keys: []string{"LTAI1"}}
	f3.serve(t)
	req.UserName, req.PolicyName, req.AccessKeyID = "csg-1", "csg-1", "LTAI1"
	if err := (aliyunUserAdmin{}).DeleteUser(context.Background(), req); err != nil ||
		f3.actions() != "ListAccessKeys,DeleteAccessKey,DetachPolicyFromUser,DeletePolicy,DeleteUser" || f3.calls[1].Get("UserAccessKeyId") != "LTAI1" {
		t.Fatalf("delete %v %s", err, f3.actions())
	}
}

func TestMockUserAdminSecretNamesTheCredential(t *testing.T) {
	key := make([]byte, 32)
	req := userRequest(model.ProviderAWS)
	req.SigningKey = key
	created, err := mockUserAdmin{}.CreateUser(context.Background(), req)
	if err != nil || !strings.HasPrefix(created.AccessKeyID, "AKIA") {
		t.Fatalf("%+v %v", created, err)
	}
	payload, err := VerifyMockToken(created.AccessKeySecret, key)
	if err != nil || payload.LeaseID != req.CredentialID || !strings.Contains(string(payload.Policy), "claudecode") {
		t.Fatalf("payload %+v %v", payload, err)
	}
	if _, err := NewUserAdmin(model.ProviderAWS, model.ModeSTS); err != nil {
		t.Fatal(err)
	}
	if _, err := NewUserAdmin("gcp", model.ModeSTS); err == nil {
		t.Fatal("gcp user admin")
	}
}

func TestUserAdminRefusesWithoutAKey(t *testing.T) {
	req := userRequest(model.ProviderAWS)
	req.AdminAccessKeySecret = ""
	for name, admin := range map[string]UserAdmin{"aws": awsUserAdmin{}, "aliyun": aliyunUserAdmin{}} {
		if _, err := admin.CreateUser(context.Background(), req); err == nil {
			t.Errorf("%s created without a key", name)
		}
	}
}

// The console's setup matches what the provider calls: the boundary name,
// and every action the user admin uses is in the policy it shows.
func TestConsoleUserAdminPolicyMatches(t *testing.T) {
	raw, err := os.ReadFile("../../web/src/app/rolePolicy.ts")
	if err != nil {
		t.Fatal(err)
	}
	ts := string(raw)
	if !strings.Contains(ts, "AWS_BOUNDARY_POLICY_NAME = '"+AWSBoundaryPolicyName+"'") {
		t.Error("the console's boundary policy name differs")
	}
	for _, action := range []string{"CreateUser", "PutUserPolicy", "ListAccessKeys", "CreateAccessKey", "DeleteAccessKey", "DeleteUserPolicy", "DeleteUser"} {
		if !strings.Contains(ts, "'iam:"+action+"'") {
			t.Errorf("the AWS user-admin policy lacks iam:%s", action)
		}
	}
	for _, action := range []string{"CreateUser", "CreatePolicy", "AttachPolicyToUser", "ListAccessKeys", "CreateAccessKey", "DeleteAccessKey", "DetachPolicyFromUser", "DeletePolicy", "DeleteUser"} {
		if !strings.Contains(ts, "'ram:"+action+"'") {
			t.Errorf("the RAM user-admin policy lacks ram:%s", action)
		}
	}
}

// The connection test refuses a key of a user Cloud Safeguard manages.
func TestUserAdminTestRefusesManagedIdentity(t *testing.T) {
	arn := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			fmt.Fprintf(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>%s</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>`, arn)
			return
		}
		fmt.Fprintf(w, `{"Arn":"%s","RequestId":"x"}`, arn)
	}))
	t.Cleanup(srv.Close)
	oldAWS, oldSTS := awsSTSEndpoint, stsEndpoint
	awsSTSEndpoint, stsEndpoint = func(string) string { return srv.URL + "/" }, srv.URL+"/"
	t.Cleanup(func() { awsSTSEndpoint, stsEndpoint = oldAWS, oldSTS })
	for _, c := range []struct {
		admin UserAdmin
		typ   model.ProviderType
		bad   string
		good  string
	}{
		{awsUserAdmin{}, model.ProviderAWS, "arn:aws:iam::123456789012:user/csg/csg-admin", "arn:aws:iam::123456789012:user/safeguard-admin"},
		{aliyunUserAdmin{}, model.ProviderAliyun, "acs:ram::1234567890123456:user/csg-admin", "acs:ram::1234567890123456:user/safeguard-admin"},
	} {
		arn = c.bad
		if err := c.admin.Test(context.Background(), userRequest(c.typ)); err == nil {
			t.Errorf("%s: a managed user's key passed", c.typ)
		}
		arn = c.good
		if err := c.admin.Test(context.Background(), userRequest(c.typ)); err != nil {
			t.Errorf("%s: %v", c.typ, err)
		}
	}
}
