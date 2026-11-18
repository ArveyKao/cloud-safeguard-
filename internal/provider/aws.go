package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// AWS STS AssumeRole with a session policy (CONTRACT §17.13), signed with
// Signature Version 4. The broker access key can only assume one role; every
// credential is that role cut down to the request's session policy.
const (
	// AWSMinDuration / AWSMaxDuration bound an AssumeRole session. The role's
	// own maximum session duration may be lower; AWS then refuses.
	AWSMinDuration = 900
	AWSMaxDuration = 43200
	// AWSMaxPolicyLength bounds the compact session policy. AWS packs and
	// limits it further; a policy this short always fits.
	AWSMaxPolicyLength = 2048
	// AWSDefaultRegion is used when a provider has no region.
	AWSDefaultRegion = "us-east-1"

	awsSTSVersion   = "2011-06-15"
	awsIAMVersion   = "2010-05-08"
	awsTimeLayout   = "20060102T150405Z"
	awsDateLayout   = "20060102"
	awsAlgorithm    = "AWS4-HMAC-SHA256"
	awsContentType  = "application/x-www-form-urlencoded; charset=utf-8"
	awsIAMSignature = "us-east-1" // IAM is a global service signed for us-east-1
)

var (
	// awsSTSEndpoint is the regional STS endpoint; tests replace it.
	awsSTSEndpoint = func(region string) string { return "https://sts." + region + ".amazonaws.com/" }
	// awsIAMEndpoint is the global IAM endpoint; tests replace it.
	awsIAMEndpoint = "https://iam.amazonaws.com/"
	// awsHTTPClient performs the provider calls; no retries.
	awsHTTPClient = &http.Client{Timeout: stsRequestTimeout}
	// awsNow is the signing clock; tests replace it.
	awsNow = func() time.Time { return time.Now().UTC() }
)

// TestWarning is returned by a connection test that passed but found
// something a supervisor should fix. The server reports the test as passed
// and shows the message.
type TestWarning struct{ Message string }

func (w *TestWarning) Error() string { return w.Message }

// awsMinter mints AWS credentials with STS AssumeRole.
type awsMinter struct{}

type awsCredentials struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type awsAssumeRoleResponse struct {
	Result struct {
		Credentials awsCredentials `xml:"Credentials"`
	} `xml:"AssumeRoleResult"`
}

type awsErrorResponse struct {
	Error struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	} `xml:"Error"`
}

// awsSigner is the key that signs one call: the broker key, or a temporary
// credential with its session token.
type awsSigner struct {
	accessKeyID, secretAccessKey, sessionToken string
}

func region(p model.Provider) string {
	if p.Region == "" {
		return AWSDefaultRegion
	}
	return p.Region
}

// Mint implements Minter for AWS.
func (awsMinter) Mint(ctx context.Context, req MintRequest) (model.Credential, error) {
	if err := ctx.Err(); err != nil {
		return model.Credential{}, err
	}
	if req.Provider.RoleARN == "" {
		return model.Credential{}, fmt.Errorf("provider aws: role ARN is required")
	}
	if req.BrokerAccessKeyID == "" || req.BrokerAccessKeySecret == "" {
		return model.Credential{}, fmt.Errorf("provider aws: broker access key is not configured")
	}
	if req.DurationSeconds < AWSMinDuration || req.DurationSeconds > AWSMaxDuration {
		return model.Credential{}, fmt.Errorf("provider aws: duration %ds outside allowed range %d-%ds",
			req.DurationSeconds, AWSMinDuration, AWSMaxDuration)
	}
	if !json.Valid(req.PolicyJSON) {
		return model.Credential{}, fmt.Errorf("provider aws: policy is not valid JSON")
	}
	policy := compactJSON(req.PolicyJSON)
	if len(policy) > AWSMaxPolicyLength {
		return model.Credential{}, fmt.Errorf("provider aws: the policy is %d characters; the limit is %d", len(policy), AWSMaxPolicyLength)
	}
	signer := awsSigner{accessKeyID: req.BrokerAccessKeyID, secretAccessKey: req.BrokerAccessKeySecret}
	creds, err := assumeAWSRole(ctx, signer, req.Provider, SanitizeSessionName(req.SessionName), req.DurationSeconds, policy)
	if err != nil {
		return model.Credential{}, err
	}
	expiresAt, err := time.Parse(time.RFC3339, creds.Expiration)
	if err != nil {
		return model.Credential{}, fmt.Errorf("InvalidResponse: STS returned an invalid Expiration timestamp")
	}
	return model.Credential{
		ProviderID:      req.Provider.ID,
		ProviderMode:    model.ModeSTS,
		LeaseID:         req.LeaseID,
		AccessKeyID:     creds.AccessKeyID,
		AccessKeySecret: creds.SecretAccessKey,
		SecurityToken:   creds.SessionToken,
		ExpiresAt:       expiresAt.UTC(),
	}, nil
}

func assumeAWSRole(ctx context.Context, signer awsSigner, p model.Provider, session string, duration int, policy string) (awsCredentials, error) {
	form := url.Values{
		"Action":          {"AssumeRole"},
		"Version":         {awsSTSVersion},
		"RoleArn":         {p.RoleARN},
		"RoleSessionName": {session},
		"DurationSeconds": {strconv.Itoa(duration)},
		"Policy":          {policy},
	}
	body, err := callAWS(ctx, signer, awsSTSEndpoint(region(p)), region(p), "sts", form)
	if err != nil {
		return awsCredentials{}, err
	}
	var resp awsAssumeRoleResponse
	if err := xml.Unmarshal(body, &resp); err != nil {
		return awsCredentials{}, fmt.Errorf("InvalidResponse: STS returned an unparseable AssumeRole response")
	}
	c := resp.Result.Credentials
	if c.AccessKeyID == "" || c.SecretAccessKey == "" || c.SessionToken == "" || c.Expiration == "" {
		return awsCredentials{}, fmt.Errorf("InvalidResponse: STS AssumeRole response is missing credential fields")
	}
	return c, nil
}

// awsConnectionTestPolicy lets the test's credential only ask who it is.
const awsConnectionTestPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}`

// awsIAMProbePolicy lets the probe credential read one harmless IAM summary.
// If that call succeeds, the role itself allows IAM, which it should not.
const awsIAMProbePolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:GetAccountSummary","Resource":"*"}]}`

// Test implements Minter for AWS: the broker key is valid
// (GetCallerIdentity), it can assume the role, and the role does not allow
// IAM (a warning, not a failure).
func (awsMinter) Test(ctx context.Context, req MintRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.BrokerAccessKeyID == "" || req.BrokerAccessKeySecret == "" {
		return fmt.Errorf("provider aws: broker access key is not configured")
	}
	if req.Provider.RoleARN == "" {
		return fmt.Errorf("provider aws: role ARN is required")
	}
	broker := awsSigner{accessKeyID: req.BrokerAccessKeyID, secretAccessKey: req.BrokerAccessKeySecret}
	identity := url.Values{"Action": {"GetCallerIdentity"}, "Version": {awsSTSVersion}}
	if _, err := callAWS(ctx, broker, awsSTSEndpoint(region(req.Provider)), region(req.Provider), "sts", identity); err != nil {
		return err
	}
	if _, err := assumeAWSRole(ctx, broker, req.Provider, "csg-connection-test", AWSMinDuration, awsConnectionTestPolicy); err != nil {
		return fmt.Errorf("the access key is valid, but it cannot assume the role: %w", err)
	}
	probe, err := assumeAWSRole(ctx, broker, req.Provider, "csg-iam-check", AWSMinDuration, awsIAMProbePolicy)
	if err != nil {
		return nil // the role can be assumed; the check itself could not run
	}
	signer := awsSigner{accessKeyID: probe.AccessKeyID, secretAccessKey: probe.SecretAccessKey, sessionToken: probe.SessionToken}
	summary := url.Values{"Action": {"GetAccountSummary"}, "Version": {awsIAMVersion}}
	if _, err := callAWS(ctx, signer, awsIAMEndpoint, awsIAMSignature, "iam", summary); err == nil {
		return &TestWarning{Message: "the connection works, but the role " + req.Provider.RoleARN +
			" allows IAM (iam:GetAccountSummary succeeded): remove IAM from the role's permissions"}
	}
	return nil
}

// callAWS performs one signed POST of a form to an AWS query API and returns
// the body of a 200 response. Errors carry only the AWS error code and
// message or a transport reason, never a key or the signature.
func callAWS(ctx context.Context, signer awsSigner, endpoint, signingRegion, service string, form url.Values) ([]byte, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("RequestFailed: bad endpoint")
	}
	body := form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("RequestFailed: cannot build the request")
	}
	req.Header.Set("Content-Type", awsContentType)
	req.Header.Set("Accept", "application/xml")
	signAWS(req, u.Host, body, signer, signingRegion, service, awsNow())
	resp, err := awsHTTPClient.Do(req)
	if err != nil {
		return nil, sanitizeSTSRequestError(err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, stsMaxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("RequestFailed: cannot read the response")
	}
	if resp.StatusCode != http.StatusOK {
		var e awsErrorResponse
		if xml.Unmarshal(raw, &e) == nil && e.Error.Code != "" {
			msg := e.Error.Message
			if msg == "" {
				msg = "request failed"
			}
			return nil, fmt.Errorf("%s: %s", e.Error.Code, msg)
		}
		return nil, fmt.Errorf("RequestFailed: %s returned HTTP %d", strings.ToUpper(service), resp.StatusCode)
	}
	return raw, nil
}

// signAWS adds the Signature Version 4 headers to a request whose body is
// body. The query string, if any, is signed as it is.
func signAWS(req *http.Request, host, body string, signer awsSigner, signingRegion, service string, now time.Time) {
	amzDate := now.UTC().Format(awsTimeLayout)
	date := now.UTC().Format(awsDateLayout)
	req.Host = host
	req.Header.Set("X-Amz-Date", amzDate)
	if signer.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", signer.sessionToken)
	}
	headers := map[string]string{"host": host, "x-amz-date": amzDate}
	for _, name := range []string{"Content-Type", "X-Amz-Security-Token"} {
		if v := req.Header.Get(name); v != "" {
			headers[strings.ToLower(name)] = strings.TrimSpace(v)
		}
	}
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		canonicalHeaders.WriteString(name + ":" + headers[name] + "\n")
	}
	signedHeaders := strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{
		req.Method, path, awsCanonicalQuery(req.URL.Query()), canonicalHeaders.String(), signedHeaders, sha256Hex(body),
	}, "\n")
	scope := date + "/" + signingRegion + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{awsAlgorithm, amzDate, scope, sha256Hex(canonical)}, "\n")
	key := hmacSHA256([]byte("AWS4"+signer.secretAccessKey), date)
	key = hmacSHA256(key, signingRegion)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))
	req.Header.Set("Authorization", awsAlgorithm+" Credential="+signer.accessKeyID+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+signature)
}

// awsCanonicalQuery sorts and RFC 3986-encodes query parameters.
func awsCanonicalQuery(q url.Values) string {
	pairs := make([]string, 0, len(q))
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, percentEncode(k)+"="+percentEncode(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// ErrUnsupportedProvider is returned for a provider type without a minter.
var ErrUnsupportedProvider = errors.New("provider: unsupported provider type")
