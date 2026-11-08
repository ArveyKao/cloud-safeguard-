package provider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Alibaba Cloud RPC signature v1 / STS AssumeRole constants.
const (
	// STSMinDuration / STSMaxDuration bound STS role session lifetimes.
	STSMinDuration = 900
	STSMaxDuration = 3600
	// stsAPIVersion is the STS API version for AssumeRole/GetCallerIdentity.
	stsAPIVersion = "2015-04-01"
	// stsActionAssumeRole / stsActionGetCallerIdentity are the RPC actions used.
	stsActionAssumeRole        = "AssumeRole"
	stsActionGetCallerIdentity = "GetCallerIdentity"
	// stsSignatureMethod / stsSignatureVersion are fixed by RPC signature v1.
	stsSignatureMethod  = "HMAC-SHA1"
	stsSignatureVersion = "1.0"
	// stsTimestampLayout is the UTC timestamp format expected by STS.
	stsTimestampLayout = "2006-01-02T15:04:05Z"
	// stsDefaultEndpoint is the public Alibaba Cloud STS endpoint. Tests
	// override it with an httptest server.
	stsDefaultEndpoint = "https://sts.aliyuncs.com/"
	// stsRequestTimeout bounds one provider call; the contract forbids retries.
	stsRequestTimeout = 10 * time.Second
	// stsMaxResponseBytes bounds how much of a provider response we read.
	stsMaxResponseBytes = 1 << 20
)

var (
	// stsEndpoint is a variable so tests can point at an httptest STS server.
	stsEndpoint = stsDefaultEndpoint
	// stsHTTPClient performs the single provider call.
	stsHTTPClient = &http.Client{Timeout: stsRequestTimeout}
)

// stsMinter mints real Alibaba Cloud STS credentials by calling AssumeRole with
// the broker AccessKey and a per-lease inline policy.
type stsMinter struct{}

// assumeRoleResponse is the JSON body of a successful AssumeRole call.
type assumeRoleResponse struct {
	AccessKeyID     string `json:"AccessKeyId"`
	AccessKeySecret string `json:"AccessKeySecret"`
	SecurityToken   string `json:"SecurityToken"`
	Expiration      string `json:"Expiration"`
	RequestID       string `json:"RequestId"`
}

// stsErrorResponse is the Aliyun-shaped error body of a failed STS call.
type stsErrorResponse struct {
	Code      string `json:"Code"`
	Message   string `json:"Message"`
	RequestID string `json:"RequestId"`
}

// Mint implements Minter for the aliyun sts provider.
func (stsMinter) Mint(ctx context.Context, req MintRequest) (model.Credential, error) {
	if err := ctx.Err(); err != nil {
		return model.Credential{}, err
	}
	if req.Provider.RoleARN == "" {
		return model.Credential{}, fmt.Errorf("provider sts: role ARN is required")
	}
	if req.BrokerAccessKeyID == "" || req.BrokerAccessKeySecret == "" {
		return model.Credential{}, fmt.Errorf("provider sts: broker access key is not configured")
	}
	if req.DurationSeconds < STSMinDuration || req.DurationSeconds > STSMaxDuration {
		return model.Credential{}, fmt.Errorf(
			"provider sts: duration %ds outside allowed range %d-%ds",
			req.DurationSeconds, STSMinDuration, STSMaxDuration)
	}
	if !json.Valid(req.PolicyJSON) {
		return model.Credential{}, fmt.Errorf("provider sts: policy is not valid JSON")
	}

	now := time.Now().UTC()
	params := map[string]string{
		"AccessKeyId":      req.BrokerAccessKeyID,
		"Action":           stsActionAssumeRole,
		"DurationSeconds":  strconv.Itoa(req.DurationSeconds),
		"Format":           "JSON",
		"Policy":           compactJSON(req.PolicyJSON),
		"RoleArn":          req.Provider.RoleARN,
		"RoleSessionName":  SanitizeSessionName(req.SessionName),
		"SignatureMethod":  stsSignatureMethod,
		"SignatureNonce":   newSignatureNonce(),
		"SignatureVersion": stsSignatureVersion,
		"Timestamp":        now.Format(stsTimestampLayout),
		"Version":          stsAPIVersion,
	}

	body, err := callSTS(ctx, req.BrokerAccessKeySecret, params)
	if err != nil {
		return model.Credential{}, err
	}

	var resp assumeRoleResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return model.Credential{}, fmt.Errorf("InvalidResponse: STS returned an unparseable AssumeRole response")
	}
	if resp.AccessKeyID == "" || resp.AccessKeySecret == "" || resp.SecurityToken == "" || resp.Expiration == "" {
		return model.Credential{}, fmt.Errorf("InvalidResponse: STS AssumeRole response is missing credential fields")
	}
	expiresAt, err := time.Parse(time.RFC3339, resp.Expiration)
	if err != nil {
		return model.Credential{}, fmt.Errorf("InvalidResponse: STS returned an invalid Expiration timestamp")
	}

	return model.Credential{
		ProviderID:      req.Provider.ID,
		ProviderMode:    model.ModeSTS,
		LeaseID:         req.LeaseID,
		AccessKeyID:     resp.AccessKeyID,
		AccessKeySecret: resp.AccessKeySecret,
		SecurityToken:   resp.SecurityToken,
		ExpiresAt:       expiresAt.UTC(),
	}, nil
}

// Test implements Minter for the aliyun sts provider by making a signed,
// read-only GetCallerIdentity call with the broker credentials.
func (stsMinter) Test(ctx context.Context, req MintRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.BrokerAccessKeyID == "" || req.BrokerAccessKeySecret == "" {
		return fmt.Errorf("provider sts: broker access key is not configured")
	}
	params := map[string]string{
		"AccessKeyId":      req.BrokerAccessKeyID,
		"Action":           stsActionGetCallerIdentity,
		"Format":           "JSON",
		"SignatureMethod":  stsSignatureMethod,
		"SignatureNonce":   newSignatureNonce(),
		"SignatureVersion": stsSignatureVersion,
		"Timestamp":        time.Now().UTC().Format(stsTimestampLayout),
		"Version":          stsAPIVersion,
	}
	if _, err := callSTS(ctx, req.BrokerAccessKeySecret, params); err != nil {
		return err
	}
	return nil
}

// callSTS signs the params and performs the single STS RPC call. It returns the
// raw body of a 200 response. Errors are sanitized: they contain only provider
// error codes/messages or a transport reason, never the broker AccessKey or the
// signed request URL (which embeds the AccessKey ID).
func callSTS(ctx context.Context, accessKeySecret string, params map[string]string) ([]byte, error) {
	requestURL := stsEndpoint + "?" + signedQuery(params, accessKeySecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("RequestFailed: cannot build STS request")
	}
	req.Header.Set("Accept", "application/json")

	resp, err := stsHTTPClient.Do(req)
	if err != nil {
		return nil, sanitizeSTSRequestError(err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, stsMaxResponseBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("RequestFailed: cannot read STS response")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, stsResponseError(resp.StatusCode, body)
	}
	return body, nil
}

// stsResponseError maps a non-200 STS response to a sanitized error of the form
// "<Code>: <Message>". It never includes the response body verbatim (which could
// echo request details) beyond the structured error fields.
func stsResponseError(status int, body []byte) error {
	var e stsErrorResponse
	if err := json.Unmarshal(body, &e); err == nil && e.Code != "" {
		msg := e.Message
		if msg == "" {
			msg = "request failed"
		}
		return fmt.Errorf("%s: %s", e.Code, msg)
	}
	return fmt.Errorf("RequestFailed: STS returned HTTP %d", status)
}

// sanitizeSTSRequestError strips the request URL from transport errors so the
// broker AccessKey ID embedded in the query string can never leak into logs.
func sanitizeSTSRequestError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("RequestTimeout: STS request timed out")
	}
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("RequestCanceled: STS request canceled")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("RequestTimeout: STS request timed out")
	}
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return fmt.Errorf("RequestFailed: %s", uerr.Err.Error())
	}
	return fmt.Errorf("RequestFailed: %s", err.Error())
}

// signedQuery builds the canonical query, the RPC v1 stringToSign, signs it and
// returns "<canonicalQuery>&Signature=<percent-encoded signature>".
func signedQuery(params map[string]string, accessKeySecret string) string {
	canonical := canonicalQuery(params)
	sts := stringToSign("GET", canonical)
	signature := rpcSignature(accessKeySecret, sts)
	return canonical + "&Signature=" + percentEncode(signature)
}

// stringToSign builds "GET&<encoded / >&<encoded canonicalQuery>".
func stringToSign(method, canonicalQuery string) string {
	return method + "&" + percentEncode("/") + "&" + percentEncode(canonicalQuery)
}

// rpcSignature computes base64(HMAC-SHA1(accessKeySecret+"&", stringToSign)).
func rpcSignature(accessKeySecret, stringToSignValue string) string {
	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	mac.Write([]byte(stringToSignValue))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// canonicalQuery percent-encodes and sorts the params and joins them as
// "k=v" pairs with "&".
func canonicalQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, percentEncode(k)+"="+percentEncode(params[k]))
	}
	return strings.Join(pairs, "&")
}

// percentEncode implements RFC 3986 percent-encoding as required by Alibaba
// Cloud RPC signature v1: unreserved characters A-Za-z0-9-_.~ stay as-is; every
// other byte (including UTF-8 continuation bytes and space) becomes %XX
// uppercase. Space therefore becomes %20, never '+'.
func percentEncode(s string) string {
	const hexChars = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexChars[c>>4])
			b.WriteByte(hexChars[c&0x0F])
		}
	}
	return b.String()
}

// newSignatureNonce returns 16 random lowercase hex characters.
func newSignatureNonce() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// The OS CSPRNG failing is unrecoverable; fall back to a time-derived
		// nonce so the request still fails loudly at the provider rather than
		// panicking in the control plane.
		return fmt.Sprintf("%016x", uint64(time.Now().UnixNano()))
	}
	return hex.EncodeToString(buf)
}

// compactJSON returns the compact form of already-valid JSON. It is used for
// the inline Policy parameter so signatures are stable and minimal.
func compactJSON(in []byte) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, in); err != nil {
		return string(in)
	}
	return buf.String()
}
