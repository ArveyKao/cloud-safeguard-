package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// testEncode is an independent RFC 3986 encoder used by the tests to recompute
// signatures without calling the package's percentEncode.
func testEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		isUnreserved := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~'
		if isUnreserved {
			b.WriteByte(c)
		} else {
			b.WriteString(fmt.Sprintf("%%%02X", c))
		}
	}
	return b.String()
}

// testCanonicalQuery independently builds the canonical query string.
func testCanonicalQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, testEncode(k)+"="+testEncode(params[k]))
	}
	return strings.Join(parts, "&")
}

// testSignature independently computes base64(HMAC-SHA1(secret+"&", stringToSign)).
func testSignature(secret, stringToSignValue string) string {
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSignValue))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// testStringToSign independently builds the RPC v1 string to sign.
func testStringToSign(method, canonical string) string {
	return method + "&" + testEncode("/") + "&" + testEncode(canonical)
}

// fixedSignatureParams is the known vector used to pin the signature algorithm.
// The golden constants below were computed independently (Python urllib.parse
// quote + hmac/sha1/base64/openssl) from these exact params.
func fixedSignatureParams() map[string]string {
	return map[string]string{
		"AccessKeyId":      "LTAI5tTestBrokerKey",
		"Action":           "AssumeRole",
		"DurationSeconds":  "900",
		"Format":           "JSON",
		"Policy":           `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:Describe*"],"Resource":["*"]}]}`,
		"RoleArn":          "acs:ram::1234567890123456:role/csg-demo",
		"RoleSessionName":  "csg-agt_demo-lea_demo",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   "0123456789abcdef",
		"SignatureVersion": "1.0",
		"Timestamp":        "2026-11-08T00:00:00Z",
		"Version":          "2015-04-01",
	}
}

const (
	goldenCanonicalQuery = "AccessKeyId=LTAI5tTestBrokerKey&Action=AssumeRole&DurationSeconds=900&Format=JSON&Policy=%7B%22Version%22%3A%221%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%5B%22ecs%3ADescribe%2A%22%5D%2C%22Resource%22%3A%5B%22%2A%22%5D%7D%5D%7D&RoleArn=acs%3Aram%3A%3A1234567890123456%3Arole%2Fcsg-demo&RoleSessionName=csg-agt_demo-lea_demo&SignatureMethod=HMAC-SHA1&SignatureNonce=0123456789abcdef&SignatureVersion=1.0&Timestamp=2026-11-08T00%3A00%3A00Z&Version=2015-04-01"
	goldenStringToSign   = "GET&%2F&AccessKeyId%3DLTAI5tTestBrokerKey%26Action%3DAssumeRole%26DurationSeconds%3D900%26Format%3DJSON%26Policy%3D%257B%2522Version%2522%253A%25221%2522%252C%2522Statement%2522%253A%255B%257B%2522Effect%2522%253A%2522Allow%2522%252C%2522Action%2522%253A%255B%2522ecs%253ADescribe%252A%2522%255D%252C%2522Resource%2522%253A%255B%2522%252A%2522%255D%257D%255D%257D%26RoleArn%3Dacs%253Aram%253A%253A1234567890123456%253Arole%252Fcsg-demo%26RoleSessionName%3Dcsg-agt_demo-lea_demo%26SignatureMethod%3DHMAC-SHA1%26SignatureNonce%3D0123456789abcdef%26SignatureVersion%3D1.0%26Timestamp%3D2026-11-08T00%253A00%253A00Z%26Version%3D2015-04-01"
	goldenSignature      = "pw0KpdajNV1Ls+BVyMUqMHOi1cg="
)

func TestPercentEncode(t *testing.T) {
	tests := []struct{ in, want string }{
		{"abcXYZ012-_.~", "abcXYZ012-_.~"},
		{"a b", "a%20b"},
		{"/", "%2F"},
		{"*", "%2A"},
		{`{"Version":"1"}`, "%7B%22Version%22%3A%221%22%7D"},
		{"acs:ram::123:role/demo", "acs%3Aram%3A%3A123%3Arole%2Fdemo"},
		{"中文", "%E4%B8%AD%E6%96%87"},
		{"a+b&c=d", "a%2Bb%26c%3Dd"},
	}
	for _, tc := range tests {
		if got := percentEncode(tc.in); got != tc.want {
			t.Errorf("percentEncode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalQuerySortsAndEncodes(t *testing.T) {
	params := map[string]string{"b": "2", "a": "1", "c": "x y", "d": "/"}
	want := "a=1&b=2&c=x%20y&d=%2F"
	if got := canonicalQuery(params); got != want {
		t.Fatalf("canonicalQuery() = %q, want %q", got, want)
	}
}

func TestStringToSignShape(t *testing.T) {
	got := stringToSign("GET", "a=1&b=2")
	if !strings.HasPrefix(got, "GET&%2F&") {
		t.Fatalf("stringToSign must start with GET&%%2F&, got %q", got)
	}
}

func TestSignatureKnownVector(t *testing.T) {
	params := fixedSignatureParams()

	// 1) The package's canonical query must match the independently encoded
	//    canonical query.
	if got := canonicalQuery(params); got != goldenCanonicalQuery {
		t.Fatalf("canonicalQuery mismatch\n got: %s\nwant: %s", got, goldenCanonicalQuery)
	}
	// 2) The package's stringToSign must match the independently built one.
	if got := stringToSign("GET", canonicalQuery(params)); got != goldenStringToSign {
		t.Fatalf("stringToSign mismatch\n got: %s\nwant: %s", got, goldenStringToSign)
	}

	// 3) The signature must match both the hard-coded golden vector and the
	//    HMAC computed independently in the test.
	wantIndependent := testSignature("test-broker-secret", testStringToSign("GET", testCanonicalQuery(params)))
	if wantIndependent != goldenSignature {
		t.Fatalf("test's independent HMAC disagrees with the golden vector: %s vs %s", wantIndependent, goldenSignature)
	}
	got := rpcSignature("test-broker-secret", goldenStringToSign)
	if got != goldenSignature {
		t.Fatalf("rpcSignature() = %q, want golden %q", got, goldenSignature)
	}

	// 4) signedQuery wires it together with a percent-encoded signature.
	signed := signedQuery(params, "test-broker-secret")
	wantPrefix := goldenCanonicalQuery + "&Signature="
	if !strings.HasPrefix(signed, wantPrefix) {
		t.Fatalf("signedQuery() = %.120q..., want prefix %.120q...", signed, wantPrefix)
	}
	if gotSig := strings.TrimPrefix(signed, wantPrefix); gotSig != testEncode(goldenSignature) {
		t.Fatalf("signedQuery signature = %q, want %q", gotSig, testEncode(goldenSignature))
	}

	// 5) The signed query must parse back to exactly the original params plus
	//    the signature.
	values, err := url.ParseQuery(signed)
	if err != nil {
		t.Fatalf("signedQuery is not a valid query string: %v", err)
	}
	for k, v := range params {
		if got := values.Get(k); got != v {
			t.Fatalf("roundtrip param %s = %q, want %q", k, got, v)
		}
	}
	if values.Get("Signature") != goldenSignature {
		t.Fatalf("roundtrip Signature = %q, want %q", values.Get("Signature"), goldenSignature)
	}
}

func TestAssumeRoleAgainstFakeSTS(t *testing.T) {
	oldEndpoint, oldClient := stsEndpoint, stsHTTPClient
	defer func() { stsEndpoint, stsHTTPClient = oldEndpoint, oldClient }()

	const (
		brokerAKID   = "LTAI5tBrokerTestKey"
		brokerSecret = "broker-secret-do-not-log"
	)
	policy := []byte(`{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:Describe*"],"Resource":["*"]}]}`)

	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("STS request method = %s, want GET", r.Method)
		}
		gotQuery = r.URL.Query()

		// Recompute the signature from the request the same way an STS server
		// would: build the canonical query without Signature, then HMAC-SHA1.
		unsigned := make(map[string]string)
		for k, vs := range gotQuery {
			if k == "Signature" {
				continue
			}
			if len(vs) != 1 {
				t.Errorf("param %s has %d values", k, len(vs))
			}
			unsigned[k] = vs[0]
		}
		wantSig := testSignature(brokerSecret, testStringToSign("GET", testCanonicalQuery(unsigned)))
		if got := gotQuery.Get("Signature"); got != wantSig {
			t.Errorf("request signature = %q, want %q", got, wantSig)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"AccessKeyId":"STS.LTAI5tMinted","AccessKeySecret":"minted-secret","SecurityToken":"minted-token","Expiration":"2026-11-08T01:00:00Z","RequestId":"req-123"}`)
	}))
	defer srv.Close()
	stsEndpoint = srv.URL + "/"
	stsHTTPClient = srv.Client()

	minter, err := New(model.ModeSTS)
	if err != nil {
		t.Fatalf("New(sts) error = %v", err)
	}
	cred, err := minter.Mint(context.Background(), MintRequest{
		LeaseID: "lea_test01",
		Provider: model.Provider{
			ID:      "prv_test",
			RoleARN: "acs:ram::1234567890123456:role/csg-demo",
			Region:  "cn-hangzhou",
		},
		BrokerAccessKeyID:     brokerAKID,
		BrokerAccessKeySecret: brokerSecret,
		PolicyJSON:            policy,
		SessionName:           "csg-agt_123-lea_test01",
		DurationSeconds:       900,
	})
	if err != nil {
		t.Fatalf("Mint() error = %v", err)
	}

	// Request shape assertions.
	expected := map[string]string{
		"AccessKeyId":      brokerAKID,
		"Action":           "AssumeRole",
		"DurationSeconds":  "900",
		"Format":           "JSON",
		"Policy":           string(policy),
		"RoleArn":          "acs:ram::1234567890123456:role/csg-demo",
		"RoleSessionName":  "csg-agt_123-lea_test01",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"Version":          "2015-04-01",
	}
	for k, want := range expected {
		if got := gotQuery.Get(k); got != want {
			t.Errorf("STS request param %s = %q, want %q", k, got, want)
		}
	}
	if nonce := gotQuery.Get("SignatureNonce"); !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(nonce) {
		t.Errorf("SignatureNonce = %q, want 16 lowercase hex chars", nonce)
	}
	if ts := gotQuery.Get("Timestamp"); ts == "" {
		t.Error("Timestamp param missing")
	} else if _, err := time.Parse(stsTimestampLayout, ts); err != nil {
		t.Errorf("Timestamp = %q, not in %s format: %v", ts, stsTimestampLayout, err)
	}
	if _, ok := gotQuery["Signature"]; !ok {
		t.Error("Signature param missing")
	}

	// Response parsing assertions.
	if cred.ProviderID != "prv_test" || cred.ProviderMode != model.ModeSTS || cred.LeaseID != "lea_test01" {
		t.Errorf("credential metadata = %+v", cred)
	}
	if cred.AccessKeyID != "STS.LTAI5tMinted" || cred.AccessKeySecret != "minted-secret" || cred.SecurityToken != "minted-token" {
		t.Errorf("credential fields not parsed from STS response: %+v", cred)
	}
	wantExpiry := time.Date(2026, 11, 8, 1, 0, 0, 0, time.UTC)
	if !cred.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("credential ExpiresAt = %v, want %v", cred.ExpiresAt, wantExpiry)
	}
}

func TestAssumeRolePolicyIsCompacted(t *testing.T) {
	oldEndpoint := stsEndpoint
	defer func() { stsEndpoint = oldEndpoint }()

	var gotPolicy string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPolicy = r.URL.Query().Get("Policy")
		fmt.Fprint(w, `{"AccessKeyId":"a","AccessKeySecret":"b","SecurityToken":"c","Expiration":"2026-11-08T01:00:00Z"}`)
	}))
	defer srv.Close()
	stsEndpoint = srv.URL + "/"

	minter, _ := New(model.ModeSTS)
	spaced := []byte("{\n  \"Version\": \"1\",\n  \"Statement\": []\n}")
	if _, err := minter.Mint(context.Background(), MintRequest{
		LeaseID:               "lea_x",
		Provider:              model.Provider{ID: "prv", RoleARN: "acs:ram::1:role/r"},
		BrokerAccessKeyID:     "ak",
		BrokerAccessKeySecret: "sk",
		PolicyJSON:            spaced,
		DurationSeconds:       900,
	}); err != nil {
		t.Fatalf("Mint() error = %v", err)
	}
	if gotPolicy != `{"Version":"1","Statement":[]}` {
		t.Fatalf("Policy param = %q, want compact JSON", gotPolicy)
	}
}

func TestAssumeRoleErrorMapping(t *testing.T) {
	oldEndpoint := stsEndpoint
	defer func() { stsEndpoint = oldEndpoint }()

	const brokerSecret = "super-secret-broker-value"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"Code":"InvalidAccessKeyId.NotFound","Message":"Specified Access Key is not found.","RequestId":"req-err"}`)
	}))
	defer srv.Close()
	stsEndpoint = srv.URL + "/"

	minter, _ := New(model.ModeSTS)
	_, err := minter.Mint(context.Background(), MintRequest{
		LeaseID:               "lea_x",
		Provider:              model.Provider{ID: "prv", RoleARN: "acs:ram::1:role/r"},
		BrokerAccessKeyID:     "LTAI5tLeakyKeyId",
		BrokerAccessKeySecret: brokerSecret,
		PolicyJSON:            []byte(`{"Version":"1"}`),
		DurationSeconds:       900,
	})
	if err == nil {
		t.Fatal("Mint() = nil error, want mapped provider error")
	}
	if err.Error() != "InvalidAccessKeyId.NotFound: Specified Access Key is not found." {
		t.Fatalf("Mint() error = %q, want '<Code>: <Message>'", err.Error())
	}
	if strings.Contains(err.Error(), brokerSecret) || strings.Contains(err.Error(), "LTAI5tLeakyKeyId") {
		t.Fatalf("provider error leaks broker credentials: %q", err.Error())
	}
}

func TestAssumeRoleTransportErrorIsSanitized(t *testing.T) {
	oldEndpoint := stsEndpoint
	defer func() { stsEndpoint = oldEndpoint }()
	// Port 1 is not listening: the dial fails without any provider response.
	stsEndpoint = "http://127.0.0.1:1/"

	minter, _ := New(model.ModeSTS)
	_, err := minter.Mint(context.Background(), MintRequest{
		LeaseID:               "lea_x",
		Provider:              model.Provider{ID: "prv", RoleARN: "acs:ram::1:role/r"},
		BrokerAccessKeyID:     "LTAI5tLeakyKeyId",
		BrokerAccessKeySecret: "super-secret-broker-value",
		PolicyJSON:            []byte(`{"Version":"1"}`),
		DurationSeconds:       900,
	})
	if err == nil {
		t.Fatal("Mint() = nil error, want transport error")
	}
	if !strings.Contains(err.Error(), "RequestFailed") {
		t.Fatalf("transport error = %q, want RequestFailed prefix", err.Error())
	}
	if strings.Contains(err.Error(), "LTAI5tLeakyKeyId") || strings.Contains(err.Error(), "super-secret-broker-value") || strings.Contains(err.Error(), "AccessKeyId=") {
		t.Fatalf("transport error leaks request details: %q", err.Error())
	}
}

func TestAssumeRoleValidation(t *testing.T) {
	minter, _ := New(model.ModeSTS)
	goodPolicy := []byte(`{"Version":"1","Statement":[]}`)
	base := MintRequest{
		LeaseID:               "lea_x",
		Provider:              model.Provider{ID: "prv", RoleARN: "acs:ram::1:role/r"},
		BrokerAccessKeyID:     "ak",
		BrokerAccessKeySecret: "sk",
		PolicyJSON:            goodPolicy,
		DurationSeconds:       900,
	}

	tests := []struct {
		name    string
		mutate  func(*MintRequest)
		wantErr string
	}{
		{"missing role arn", func(r *MintRequest) { r.Provider.RoleARN = "" }, "role ARN is required"},
		{"missing broker ak id", func(r *MintRequest) { r.BrokerAccessKeyID = "" }, "broker access key is not configured"},
		{"missing broker secret", func(r *MintRequest) { r.BrokerAccessKeySecret = "" }, "broker access key is not configured"},
		{"duration too short", func(r *MintRequest) { r.DurationSeconds = 899 }, "outside allowed range"},
		{"duration too long", func(r *MintRequest) { r.DurationSeconds = 3601 }, "outside allowed range"},
		{"duration zero", func(r *MintRequest) { r.DurationSeconds = 0 }, "outside allowed range"},
		{"invalid policy", func(r *MintRequest) { r.PolicyJSON = []byte(`{invalid`) }, "not valid JSON"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			tc.mutate(&req)
			_, err := minter.Mint(context.Background(), req)
			if err == nil {
				t.Fatalf("Mint() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Mint() error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestSTSContextCancelled(t *testing.T) {
	minter, _ := New(model.ModeSTS)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := minter.Mint(ctx, MintRequest{
		LeaseID:               "lea_x",
		Provider:              model.Provider{ID: "prv", RoleARN: "acs:ram::1:role/r"},
		BrokerAccessKeyID:     "ak",
		BrokerAccessKeySecret: "sk",
		PolicyJSON:            []byte(`{"Version":"1"}`),
		DurationSeconds:       900,
	})
	if err == nil {
		t.Fatal("Mint() with cancelled context = nil error")
	}
}

func TestGetCallerIdentityAgainstFakeSTS(t *testing.T) {
	oldEndpoint := stsEndpoint
	defer func() { stsEndpoint = oldEndpoint }()

	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		fmt.Fprint(w, `{"AccountId":"1234567890123456","Arn":"acs:ram::1234567890123456:user/csg","RequestId":"req"}`)
	}))
	defer srv.Close()
	stsEndpoint = srv.URL + "/"

	minter, _ := New(model.ModeSTS)
	err := minter.Test(context.Background(), MintRequest{
		Provider:              model.Provider{ID: "prv", RoleARN: "acs:ram::1:role/r"},
		BrokerAccessKeyID:     "LTAI5tBroker",
		BrokerAccessKeySecret: "secret",
	})
	if err != nil {
		t.Fatalf("Test() error = %v", err)
	}
	if got := gotQuery.Get("Action"); got != "GetCallerIdentity" {
		t.Errorf("Action = %q, want GetCallerIdentity", got)
	}
	if got := gotQuery.Get("Version"); got != "2015-04-01" {
		t.Errorf("Version = %q, want 2015-04-01", got)
	}
	if got := gotQuery.Get("AccessKeyId"); got != "LTAI5tBroker" {
		t.Errorf("AccessKeyId = %q", got)
	}
	if got := gotQuery.Get("Signature"); got == "" {
		t.Error("Signature missing from GetCallerIdentity request")
	}
	for _, unwanted := range []string{"Policy", "RoleArn", "DurationSeconds", "RoleSessionName"} {
		if got := gotQuery.Get(unwanted); got != "" {
			t.Errorf("%s = %q, want absent for GetCallerIdentity", unwanted, got)
		}
	}

	// A provider error must be returned as a sanitized error.
	srvErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"Code":"InvalidAccessKeyId.NotFound","Message":"not found","RequestId":"r"}`)
	}))
	defer srvErr.Close()
	stsEndpoint = srvErr.URL + "/"
	err = minter.Test(context.Background(), MintRequest{
		BrokerAccessKeyID:     "LTAI5tBroker",
		BrokerAccessKeySecret: "secret",
	})
	if err == nil || !strings.Contains(err.Error(), "InvalidAccessKeyId.NotFound") {
		t.Fatalf("Test() error = %v, want provider error code", err)
	}
}

func TestSTSTestRequiresBrokerCredentials(t *testing.T) {
	minter, _ := New(model.ModeSTS)
	if err := minter.Test(context.Background(), MintRequest{}); err == nil {
		t.Fatal("Test() with no broker credentials = nil error")
	}
}

func TestSanitizeSessionName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"csg-agt_abc123-lea_def456", "csg-agt_abc123-lea_def456"},
		{"csg/agent:lease 01", "csgagentlease01"},
		{"!", "csg"},
		{"", "csg"},
		{"a", "csg"},
		{"ab", "ab"},
		{"名字", "csg"},
		{strings.Repeat("x", 100), strings.Repeat("x", 64)},
		{"csg-中文-agt", "csg--agt"},
	}
	for _, tc := range tests {
		if got := SanitizeSessionName(tc.in); got != tc.want {
			t.Errorf("SanitizeSessionName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNewMinterModes(t *testing.T) {
	for _, mode := range []model.ProviderMode{model.ModeSTS, model.ModeMock} {
		minter, err := New(mode)
		if err != nil {
			t.Fatalf("New(%q) error = %v", mode, err)
		}
		if minter == nil {
			t.Fatalf("New(%q) = nil minter", mode)
		}
	}
	if _, err := New(model.ProviderMode("bogus")); err == nil {
		t.Fatal("New(bogus) = nil error")
	}
}

func TestCompactJSON(t *testing.T) {
	in := []byte("{\n  \"Version\":\"1\",\n  \"Statement\": [ ]\n}")
	want := `{"Version":"1","Statement":[]}`
	if got := compactJSON(in); got != want {
		t.Fatalf("compactJSON() = %q, want %q", got, want)
	}
	if got := compactJSON([]byte(`{"a":1}`)); got != `{"a":1}` {
		t.Fatalf("compactJSON(compact) = %q", got)
	}
}

// TestSTSErrorResponseIgnoresNonJSONBody makes sure an HTML/plain body does not
// leak into the error and the status is still reported.
func TestSTSErrorResponseIgnoresNonJSONBody(t *testing.T) {
	err := stsResponseError(http.StatusBadGateway, []byte("<html>bad gateway secret-token</html>"))
	if err == nil {
		t.Fatal("stsResponseError() = nil")
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatalf("error leaked raw body: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("error = %q, want status code", err.Error())
	}
}

// TestAssumeRoleUnparseableResponse covers a malformed 200 body.
func TestAssumeRoleUnparseableResponse(t *testing.T) {
	oldEndpoint := stsEndpoint
	defer func() { stsEndpoint = oldEndpoint }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `not-json`)
	}))
	defer srv.Close()
	stsEndpoint = srv.URL + "/"

	minter, _ := New(model.ModeSTS)
	_, err := minter.Mint(context.Background(), MintRequest{
		LeaseID:               "lea_x",
		Provider:              model.Provider{ID: "prv", RoleARN: "acs:ram::1:role/r"},
		BrokerAccessKeyID:     "ak",
		BrokerAccessKeySecret: "sk",
		PolicyJSON:            []byte(`{"Version":"1"}`),
		DurationSeconds:       900,
	})
	if err == nil || !strings.Contains(err.Error(), "InvalidResponse") {
		t.Fatalf("Mint() error = %v, want InvalidResponse", err)
	}
	if !json.Valid([]byte(`{"Version":"1"}`)) {
		t.Fatal("test bug")
	}
}
