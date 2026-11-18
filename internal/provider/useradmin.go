package provider

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Long-lived credentials (CONTRACT §17.14): a cloud user with a policy and
// an access key, created and deleted with an account's second key, which may
// manage only csg users and policies. The broker key is never used here.

// UserRequest is one create, delete or test call.
type UserRequest struct {
	Provider model.Provider
	// AdminAccessKeyID / AdminAccessKeySecret are the decrypted second key;
	// used only inside the call, never logged or returned.
	AdminAccessKeyID, AdminAccessKeySecret string
	// CredentialID names the credential; the cloud user and policy are
	// named after it.
	CredentialID string
	// PolicyJSON is the rendered policy (a §17.4 template plus the IAM deny).
	PolicyJSON []byte
	// UserName, PolicyName and AccessKeyID identify what to delete.
	UserName, PolicyName, AccessKeyID string
	// SigningKey is used by the mock only.
	SigningKey []byte
}

// UserCreated is what a successful create made. The secret is returned to
// the caller once and never stored.
type UserCreated struct {
	UserName, PolicyName, AccessKeyID, AccessKeySecret string
}

// UserAdmin creates and deletes long-lived cloud users.
type UserAdmin interface {
	// CreateUser creates the user, its policy and an access key. On
	// failure, whatever it created is deleted again.
	CreateUser(ctx context.Context, req UserRequest) (UserCreated, error)
	// DeleteUser deletes the access key, the policy and the user; parts that
	// are already gone are not an error.
	DeleteUser(ctx context.Context, req UserRequest) error
	// Test checks that the second key can sign a harmless call.
	Test(ctx context.Context, req UserRequest) error
}

// NewUserAdmin returns the UserAdmin for a provider type and mode.
func NewUserAdmin(t model.ProviderType, mode model.ProviderMode) (UserAdmin, error) {
	if mode == model.ModeMock {
		return mockUserAdmin{}, nil
	}
	switch t {
	case model.ProviderAWS:
		return awsUserAdmin{}, nil
	case model.ProviderAliyun:
		return aliyunUserAdmin{}, nil
	}
	return nil, fmt.Errorf("%w %q", ErrUnsupportedProvider, t)
}

// CloudUserName is the cloud user (and policy) name of a credential.
func CloudUserName(credentialID string) string {
	return "csg-" + strings.TrimPrefix(credentialID, "llc_")
}

// AWSBoundaryPolicyName is the permissions boundary every AWS csg user gets.
const AWSBoundaryPolicyName = "cloud-safeguard-boundary"

func checkUserRequest(req UserRequest, needPolicy bool) error {
	if req.AdminAccessKeyID == "" || req.AdminAccessKeySecret == "" {
		return fmt.Errorf("the account's key for long-lived credentials is not configured")
	}
	if req.CredentialID == "" {
		return fmt.Errorf("credential id is required")
	}
	if needPolicy && (!json.Valid(req.PolicyJSON) || len(compactJSON(req.PolicyJSON)) > AWSMaxPolicyLength) {
		return fmt.Errorf("the policy is not valid JSON or longer than %d characters", AWSMaxPolicyLength)
	}
	return nil
}

// ---- mock ----

// mockUserAdmin creates nothing: the secret is a signed mock token naming the
// credential, which the mock cloud accepts while the credential is active.
type mockUserAdmin struct{}

func (mockUserAdmin) CreateUser(_ context.Context, req UserRequest) (UserCreated, error) {
	if len(req.SigningKey) != 32 || req.CredentialID == "" || !json.Valid(req.PolicyJSON) {
		return UserCreated{}, fmt.Errorf("provider mock: invalid long-lived request")
	}
	payload := MockTokenPayload{
		V: MockTokenVersion, LeaseID: req.CredentialID, ProviderID: req.Provider.ID, AccountID: MockAccountID,
		Region: req.Provider.Region, ExpiresAt: time.Now().UTC().AddDate(100, 0, 0).Format(time.RFC3339Nano),
		SessionName: CloudUserName(req.CredentialID), Policy: append(json.RawMessage(nil), req.PolicyJSON...),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return UserCreated{}, err
	}
	secret, err := mintMockToken(req.SigningKey, body)
	if err != nil {
		return UserCreated{}, err
	}
	id, err := randomAccessKeyID()
	if err != nil {
		return UserCreated{}, err
	}
	if req.Provider.Type == model.ProviderAWS {
		id = "AKIA" + strings.TrimPrefix(id, "LTAI")
	}
	name := CloudUserName(req.CredentialID)
	return UserCreated{UserName: name, PolicyName: name, AccessKeyID: id, AccessKeySecret: secret}, nil
}

func (mockUserAdmin) DeleteUser(context.Context, UserRequest) error { return nil }

func (mockUserAdmin) Test(_ context.Context, req UserRequest) error {
	if req.AdminAccessKeyID == "" {
		return fmt.Errorf("the account's key for long-lived credentials is not configured")
	}
	return nil
}

// ---- AWS IAM ----

type awsUserAdmin struct{}

type awsCreateAccessKeyResponse struct {
	Result struct {
		AccessKey struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
		} `xml:"AccessKey"`
	} `xml:"CreateAccessKeyResult"`
}

func (awsUserAdmin) iam(ctx context.Context, req UserRequest, action string, params map[string]string) ([]byte, error) {
	form := url.Values{"Action": {action}, "Version": {awsIAMVersion}}
	for k, v := range params {
		form.Set(k, v)
	}
	signer := awsSigner{accessKeyID: req.AdminAccessKeyID, secretAccessKey: req.AdminAccessKeySecret}
	return callAWS(ctx, signer, awsIAMEndpoint, awsIAMSignature, "iam", form)
}

func (a awsUserAdmin) CreateUser(ctx context.Context, req UserRequest) (UserCreated, error) {
	if err := checkUserRequest(req, true); err != nil {
		return UserCreated{}, err
	}
	if req.Provider.CloudAccountID == "" {
		return UserCreated{}, fmt.Errorf("the account has no account ID")
	}
	name := CloudUserName(req.CredentialID)
	boundary := "arn:aws:iam::" + req.Provider.CloudAccountID + ":policy/" + AWSBoundaryPolicyName
	if _, err := a.iam(ctx, req, "CreateUser", map[string]string{"UserName": name, "Path": "/csg/", "PermissionsBoundary": boundary}); err != nil {
		return UserCreated{}, fmt.Errorf("create user: %w", err)
	}
	created := UserCreated{UserName: name}
	undo := func(cause error) (UserCreated, error) {
		cleanup := req
		cleanup.UserName, cleanup.PolicyName = created.UserName, created.PolicyName
		_ = a.DeleteUser(ctx, cleanup)
		return UserCreated{}, cause
	}
	if _, err := a.iam(ctx, req, "PutUserPolicy", map[string]string{"UserName": name, "PolicyName": name, "PolicyDocument": compactJSON(req.PolicyJSON)}); err != nil {
		return undo(fmt.Errorf("put user policy: %w", err))
	}
	created.PolicyName = name
	body, err := a.iam(ctx, req, "CreateAccessKey", map[string]string{"UserName": name})
	if err != nil {
		return undo(fmt.Errorf("create access key: %w", err))
	}
	var resp awsCreateAccessKeyResponse
	if err := xml.Unmarshal(body, &resp); err != nil || resp.Result.AccessKey.AccessKeyID == "" || resp.Result.AccessKey.SecretAccessKey == "" {
		return undo(fmt.Errorf("InvalidResponse: IAM returned no access key"))
	}
	created.AccessKeyID, created.AccessKeySecret = resp.Result.AccessKey.AccessKeyID, resp.Result.AccessKey.SecretAccessKey
	return created, nil
}

func (a awsUserAdmin) DeleteUser(ctx context.Context, req UserRequest) error {
	if err := checkUserRequest(req, false); err != nil {
		return err
	}
	gone := func(err error) bool { return err == nil || strings.HasPrefix(err.Error(), "NoSuchEntity") }
	if req.AccessKeyID != "" {
		if _, err := a.iam(ctx, req, "DeleteAccessKey", map[string]string{"UserName": req.UserName, "AccessKeyId": req.AccessKeyID}); !gone(err) {
			return fmt.Errorf("delete access key: %w", err)
		}
	}
	if req.PolicyName != "" {
		if _, err := a.iam(ctx, req, "DeleteUserPolicy", map[string]string{"UserName": req.UserName, "PolicyName": req.PolicyName}); !gone(err) {
			return fmt.Errorf("delete user policy: %w", err)
		}
	}
	if req.UserName != "" {
		if _, err := a.iam(ctx, req, "DeleteUser", map[string]string{"UserName": req.UserName}); !gone(err) {
			return fmt.Errorf("delete user: %w", err)
		}
	}
	return nil
}

func (awsUserAdmin) Test(ctx context.Context, req UserRequest) error {
	if req.AdminAccessKeyID == "" || req.AdminAccessKeySecret == "" {
		return fmt.Errorf("the account's key for long-lived credentials is not configured")
	}
	if !model.ValidRegion(model.ProviderAWS, region(req.Provider)) {
		return errBadRegion
	}
	signer := awsSigner{accessKeyID: req.AdminAccessKeyID, secretAccessKey: req.AdminAccessKeySecret}
	_, err := callAWS(ctx, signer, awsSTSEndpoint(region(req.Provider)), region(req.Provider), "sts",
		url.Values{"Action": {"GetCallerIdentity"}, "Version": {awsSTSVersion}})
	return err
}

// ---- Alibaba Cloud RAM ----

var ramEndpoint = "https://ram.aliyuncs.com/"

const ramAPIVersion = "2015-05-01"

type aliyunUserAdmin struct{}

func (aliyunUserAdmin) ram(ctx context.Context, req UserRequest, action string, params map[string]string) ([]byte, error) {
	all := map[string]string{
		"AccessKeyId":      req.AdminAccessKeyID,
		"Action":           action,
		"Format":           "JSON",
		"SignatureMethod":  stsSignatureMethod,
		"SignatureNonce":   newSignatureNonce(),
		"SignatureVersion": stsSignatureVersion,
		"Timestamp":        time.Now().UTC().Format(stsTimestampLayout),
		"Version":          ramAPIVersion,
	}
	for k, v := range params {
		all[k] = v
	}
	return callAliyunRPC(ctx, ramEndpoint, req.AdminAccessKeySecret, all)
}

func (a aliyunUserAdmin) CreateUser(ctx context.Context, req UserRequest) (UserCreated, error) {
	if err := checkUserRequest(req, true); err != nil {
		return UserCreated{}, err
	}
	name := CloudUserName(req.CredentialID)
	if _, err := a.ram(ctx, req, "CreateUser", map[string]string{"UserName": name}); err != nil {
		return UserCreated{}, fmt.Errorf("create user: %w", err)
	}
	created := UserCreated{UserName: name}
	attached := false
	undo := func(cause error) (UserCreated, error) {
		cleanup := req
		cleanup.UserName, cleanup.PolicyName = created.UserName, created.PolicyName
		if !attached {
			// Not attached: delete the policy and user without a detach.
			if created.PolicyName != "" {
				_, _ = a.ram(ctx, req, "DeletePolicy", map[string]string{"PolicyName": created.PolicyName})
			}
			_, _ = a.ram(ctx, req, "DeleteUser", map[string]string{"UserName": created.UserName})
			return UserCreated{}, cause
		}
		_ = a.DeleteUser(ctx, cleanup)
		return UserCreated{}, cause
	}
	if _, err := a.ram(ctx, req, "CreatePolicy", map[string]string{"PolicyName": name, "PolicyDocument": compactJSON(req.PolicyJSON),
		"Description": "Cloud Safeguard long-lived credential " + req.CredentialID}); err != nil {
		return undo(fmt.Errorf("create policy: %w", err))
	}
	created.PolicyName = name
	if _, err := a.ram(ctx, req, "AttachPolicyToUser", map[string]string{"PolicyType": "Custom", "PolicyName": name, "UserName": name}); err != nil {
		return undo(fmt.Errorf("attach policy: %w", err))
	}
	attached = true
	body, err := a.ram(ctx, req, "CreateAccessKey", map[string]string{"UserName": name})
	if err != nil {
		return undo(fmt.Errorf("create access key: %w", err))
	}
	var resp struct {
		AccessKey struct {
			AccessKeyID     string `json:"AccessKeyId"`
			AccessKeySecret string `json:"AccessKeySecret"`
		} `json:"AccessKey"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.AccessKey.AccessKeyID == "" || resp.AccessKey.AccessKeySecret == "" {
		return undo(fmt.Errorf("InvalidResponse: RAM returned no access key"))
	}
	created.AccessKeyID, created.AccessKeySecret = resp.AccessKey.AccessKeyID, resp.AccessKey.AccessKeySecret
	return created, nil
}

func (a aliyunUserAdmin) DeleteUser(ctx context.Context, req UserRequest) error {
	if err := checkUserRequest(req, false); err != nil {
		return err
	}
	gone := func(err error) bool { return err == nil || strings.HasPrefix(err.Error(), "EntityNotExist") }
	if req.AccessKeyID != "" {
		if _, err := a.ram(ctx, req, "DeleteAccessKey", map[string]string{"UserName": req.UserName, "UserAccessKeyId": req.AccessKeyID}); !gone(err) {
			return fmt.Errorf("delete access key: %w", err)
		}
	}
	if req.PolicyName != "" {
		if _, err := a.ram(ctx, req, "DetachPolicyFromUser", map[string]string{"PolicyType": "Custom", "PolicyName": req.PolicyName, "UserName": req.UserName}); !gone(err) {
			return fmt.Errorf("detach policy: %w", err)
		}
		if _, err := a.ram(ctx, req, "DeletePolicy", map[string]string{"PolicyName": req.PolicyName}); !gone(err) {
			return fmt.Errorf("delete policy: %w", err)
		}
	}
	if req.UserName != "" {
		if _, err := a.ram(ctx, req, "DeleteUser", map[string]string{"UserName": req.UserName}); !gone(err) {
			return fmt.Errorf("delete user: %w", err)
		}
	}
	return nil
}

func (aliyunUserAdmin) Test(ctx context.Context, req UserRequest) error {
	if req.AdminAccessKeyID == "" || req.AdminAccessKeySecret == "" {
		return fmt.Errorf("the account's key for long-lived credentials is not configured")
	}
	_, err := callSTS(ctx, req.AdminAccessKeySecret, map[string]string{
		"AccessKeyId": req.AdminAccessKeyID, "Action": stsActionGetCallerIdentity, "Format": "JSON",
		"SignatureMethod": stsSignatureMethod, "SignatureNonce": newSignatureNonce(), "SignatureVersion": stsSignatureVersion,
		"Timestamp": time.Now().UTC().Format(stsTimestampLayout), "Version": stsAPIVersion,
	})
	return err
}
