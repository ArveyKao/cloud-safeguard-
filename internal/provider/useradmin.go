package provider

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
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

// ErrCleanupFailed marks a failed create whose cleanup failed too: the cloud
// user, policy or key may still exist.
var ErrCleanupFailed = errors.New("cleanup failed")

// CleanupError is a failed create whose cleanup also failed.
type CleanupError struct{ Cause, Cleanup error }

func (e *CleanupError) Error() string {
	return e.Cause.Error() + "; deleting what was made also failed: " + e.Cleanup.Error()
}
func (e *CleanupError) Is(target error) bool { return target == ErrCleanupFailed }
func (e *CleanupError) Unwrap() error        { return e.Cause }

// cleanUp deletes whatever a failed create made and returns the cause, or a
// CleanupError when the deletion failed too.
func cleanUp(ctx context.Context, admin UserAdmin, req UserRequest, cause error) error {
	req.UserName, req.PolicyName, req.AccessKeyID = "", "", ""
	if err := admin.DeleteUser(ctx, req); err != nil {
		return &CleanupError{Cause: cause, Cleanup: err}
	}
	return cause
}

// mayHaveHappened reports whether a failed call may still have taken effect
// in the cloud (the request or the answer was lost).
func mayHaveHappened(err error) bool {
	return strings.HasPrefix(err.Error(), "RequestFailed") || strings.HasPrefix(err.Error(), "InvalidResponse")
}

// purgeNames returns the user and policy to delete: the recorded names, or
// the ones the credential ID gives. Only csg- users are ever deleted.
func purgeNames(req UserRequest) (user, policy string, err error) {
	if err := checkUserRequest(req, false); err != nil {
		return "", "", err
	}
	user, policy = req.UserName, req.PolicyName
	if user == "" {
		user = CloudUserName(req.CredentialID)
	}
	if policy == "" {
		policy = user
	}
	if !strings.HasPrefix(user, "csg-") || !strings.HasPrefix(policy, "csg-") {
		return "", "", fmt.Errorf("only csg- users and policies are deleted")
	}
	return user, policy, nil
}

// refuseManagedIdentity refuses a second key that belongs to a user Cloud
// Safeguard itself manages (path /csg/ or a csg- name): the key could then
// change its own policies.
func refuseManagedIdentity(arn string) error {
	i := strings.Index(arn, ":user/")
	if i < 0 {
		return nil
	}
	rest := arn[i+len(":user/"):]
	name := rest[strings.LastIndex(rest, "/")+1:]
	if strings.HasPrefix(rest, "csg/") || strings.HasPrefix(strings.ToLower(name), "csg-") {
		return fmt.Errorf("this key belongs to a user Cloud Safeguard manages (path /csg/ or a name starting with csg-); use a separate user")
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
	undo := func(cause error) (UserCreated, error) { return UserCreated{}, cleanUp(ctx, a, req, cause) }
	boundary := "arn:aws:iam::" + req.Provider.CloudAccountID + ":policy/" + AWSBoundaryPolicyName
	if _, err := a.iam(ctx, req, "CreateUser", map[string]string{"UserName": name, "Path": "/csg/", "PermissionsBoundary": boundary}); err != nil {
		if mayHaveHappened(err) {
			return undo(fmt.Errorf("create user: %w", err))
		}
		return UserCreated{}, fmt.Errorf("create user: %w", err)
	}
	if _, err := a.iam(ctx, req, "PutUserPolicy", map[string]string{"UserName": name, "PolicyName": name, "PolicyDocument": compactJSON(req.PolicyJSON)}); err != nil {
		return undo(fmt.Errorf("put user policy: %w", err))
	}
	body, err := a.iam(ctx, req, "CreateAccessKey", map[string]string{"UserName": name})
	if err != nil {
		return undo(fmt.Errorf("create access key: %w", err))
	}
	var resp awsCreateAccessKeyResponse
	if err := xml.Unmarshal(body, &resp); err != nil || resp.Result.AccessKey.AccessKeyID == "" || resp.Result.AccessKey.SecretAccessKey == "" {
		return undo(fmt.Errorf("InvalidResponse: IAM returned no access key"))
	}
	return UserCreated{UserName: name, PolicyName: name,
		AccessKeyID: resp.Result.AccessKey.AccessKeyID, AccessKeySecret: resp.Result.AccessKey.SecretAccessKey}, nil
}

// DeleteUser lists the user's access keys and deletes every one (so a key
// whose ID was never recorded is deleted too), then the policy and the user.
func (a awsUserAdmin) DeleteUser(ctx context.Context, req UserRequest) error {
	user, policy, err := purgeNames(req)
	if err != nil {
		return err
	}
	gone := func(err error) bool { return err == nil || strings.HasPrefix(err.Error(), "NoSuchEntity") }
	body, err := a.iam(ctx, req, "ListAccessKeys", map[string]string{"UserName": user})
	if err != nil {
		if gone(err) {
			return nil // no user: no key and no inline policy either
		}
		return fmt.Errorf("list access keys: %w", err)
	}
	var list struct {
		Keys []string `xml:"ListAccessKeysResult>AccessKeyMetadata>member>AccessKeyId"`
	}
	if err := xml.Unmarshal(body, &list); err != nil {
		return fmt.Errorf("InvalidResponse: IAM returned an unreadable key list")
	}
	for _, id := range list.Keys {
		if _, err := a.iam(ctx, req, "DeleteAccessKey", map[string]string{"UserName": user, "AccessKeyId": id}); !gone(err) {
			return fmt.Errorf("delete access key: %w", err)
		}
	}
	if _, err := a.iam(ctx, req, "DeleteUserPolicy", map[string]string{"UserName": user, "PolicyName": policy}); !gone(err) {
		return fmt.Errorf("delete user policy: %w", err)
	}
	if _, err := a.iam(ctx, req, "DeleteUser", map[string]string{"UserName": user}); !gone(err) {
		return fmt.Errorf("delete user: %w", err)
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
	body, err := callAWS(ctx, signer, awsSTSEndpoint(region(req.Provider)), region(req.Provider), "sts",
		url.Values{"Action": {"GetCallerIdentity"}, "Version": {awsSTSVersion}})
	if err != nil {
		return err
	}
	var who struct {
		Arn string `xml:"GetCallerIdentityResult>Arn"`
	}
	_ = xml.Unmarshal(body, &who)
	return refuseManagedIdentity(who.Arn)
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
	undo := func(cause error) (UserCreated, error) { return UserCreated{}, cleanUp(ctx, a, req, cause) }
	if _, err := a.ram(ctx, req, "CreateUser", map[string]string{"UserName": name}); err != nil {
		if mayHaveHappened(err) {
			return undo(fmt.Errorf("create user: %w", err))
		}
		return UserCreated{}, fmt.Errorf("create user: %w", err)
	}
	if _, err := a.ram(ctx, req, "CreatePolicy", map[string]string{"PolicyName": name, "PolicyDocument": compactJSON(req.PolicyJSON),
		"Description": "Cloud Safeguard long-lived credential " + req.CredentialID}); err != nil {
		return undo(fmt.Errorf("create policy: %w", err))
	}
	if _, err := a.ram(ctx, req, "AttachPolicyToUser", map[string]string{"PolicyType": "Custom", "PolicyName": name, "UserName": name}); err != nil {
		return undo(fmt.Errorf("attach policy: %w", err))
	}
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
	return UserCreated{UserName: name, PolicyName: name,
		AccessKeyID: resp.AccessKey.AccessKeyID, AccessKeySecret: resp.AccessKey.AccessKeySecret}, nil
}

// DeleteUser lists the user's access keys and deletes every one, then
// detaches and deletes the policy and deletes the user. Parts already gone
// (EntityNotExist.*) are skipped, so it also cleans up a half-made user.
func (a aliyunUserAdmin) DeleteUser(ctx context.Context, req UserRequest) error {
	user, policy, err := purgeNames(req)
	if err != nil {
		return err
	}
	gone := func(err error) bool { return err == nil || strings.HasPrefix(err.Error(), "EntityNotExist") }
	body, err := a.ram(ctx, req, "ListAccessKeys", map[string]string{"UserName": user})
	if !gone(err) {
		return fmt.Errorf("list access keys: %w", err)
	}
	if err == nil {
		var list struct {
			AccessKeys struct {
				AccessKey []struct {
					AccessKeyID string `json:"AccessKeyId"`
				} `json:"AccessKey"`
			} `json:"AccessKeys"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return fmt.Errorf("InvalidResponse: RAM returned an unreadable key list")
		}
		for _, k := range list.AccessKeys.AccessKey {
			if _, err := a.ram(ctx, req, "DeleteAccessKey", map[string]string{"UserName": user, "UserAccessKeyId": k.AccessKeyID}); !gone(err) {
				return fmt.Errorf("delete access key: %w", err)
			}
		}
	}
	if _, err := a.ram(ctx, req, "DetachPolicyFromUser", map[string]string{"PolicyType": "Custom", "PolicyName": policy, "UserName": user}); !gone(err) {
		return fmt.Errorf("detach policy: %w", err)
	}
	if _, err := a.ram(ctx, req, "DeletePolicy", map[string]string{"PolicyName": policy}); !gone(err) {
		return fmt.Errorf("delete policy: %w", err)
	}
	if _, err := a.ram(ctx, req, "DeleteUser", map[string]string{"UserName": user}); !gone(err) {
		return fmt.Errorf("delete user: %w", err)
	}
	return nil
}

func (aliyunUserAdmin) Test(ctx context.Context, req UserRequest) error {
	if req.AdminAccessKeyID == "" || req.AdminAccessKeySecret == "" {
		return fmt.Errorf("the account's key for long-lived credentials is not configured")
	}
	body, err := callSTS(ctx, req.AdminAccessKeySecret, map[string]string{
		"AccessKeyId": req.AdminAccessKeyID, "Action": stsActionGetCallerIdentity, "Format": "JSON",
		"SignatureMethod": stsSignatureMethod, "SignatureNonce": newSignatureNonce(), "SignatureVersion": stsSignatureVersion,
		"Timestamp": time.Now().UTC().Format(stsTimestampLayout), "Version": stsAPIVersion,
	})
	if err != nil {
		return err
	}
	var who struct {
		Arn string `json:"Arn"`
	}
	_ = json.Unmarshal(body, &who)
	return refuseManagedIdentity(who.Arn)
}
