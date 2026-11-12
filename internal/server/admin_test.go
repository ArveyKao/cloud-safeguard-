package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

func TestAdminLogin(t *testing.T) {
	env := newTestEnv(t, true)
	rec := env.admin(http.MethodPost, "/api/v1/admin/login", nil)
	requireStatus(t, rec, http.StatusOK)
	result := decodeEnvelope[model.LoginResult](t, rec)
	if !result.OK || result.Role != "admin" || result.Version != model.Version {
		t.Fatalf("login result = %+v", result)
	}
	if !env.hasAction("auth.admin_login") {
		t.Fatal("missing auth.admin_login audit event")
	}
}

func TestProviderAdminCRUD(t *testing.T) {
	env := newTestEnv(t, true)

	// List: the demo provider is present with a masked AccessKey only.
	rec := env.admin(http.MethodGet, "/api/v1/admin/providers", nil)
	requireStatus(t, rec, http.StatusOK)
	providers := decodeEnvelope[model.ListResponse[model.Provider]](t, rec)
	if providers.Total != 1 || len(providers.Items) != 1 {
		t.Fatalf("providers = %+v, want the demo provider", providers)
	}
	demo := providers.Items[0]
	if demo.Name != "demo-aliyun" || demo.Mode != model.ModeMock || demo.AccessKeyIDMasked != "LTAI****oker" {
		t.Fatalf("demo provider = %+v", demo)
	}

	// Create a mock provider without AccessKey values: placeholders are generated.
	createRec := env.admin(http.MethodPost, "/api/v1/admin/providers", model.CreateProviderInput{
		Name:   "second-mock",
		Type:   model.ProviderAliyun,
		Mode:   model.ModeMock,
		Region: "cn-beijing",
	})
	requireStatus(t, createRec, http.StatusCreated)
	created := decodeEnvelope[model.Provider](t, createRec)
	if !strings.HasPrefix(created.ID, "prv_") || created.Status != model.ProviderActive {
		t.Fatalf("created provider = %+v", created)
	}
	if created.AccessKeyIDMasked == "" || !strings.Contains(created.AccessKeyIDMasked, "****") {
		t.Fatalf("masked AccessKey = %q", created.AccessKeyIDMasked)
	}
	if rec := env.admin(http.MethodGet, "/api/v1/admin/providers/"+created.ID, nil); rec.Code != http.StatusOK {
		t.Fatalf("GET provider status = %d", rec.Code)
	}
	if !env.hasAction("provider.created") {
		t.Fatal("missing provider.created audit event")
	}

	// Create an sts provider with explicit credentials.
	stsRec := env.admin(http.MethodPost, "/api/v1/admin/providers", model.CreateProviderInput{
		Name:            "real-sts",
		Type:            model.ProviderAliyun,
		Mode:            model.ModeSTS,
		Region:          "cn-hangzhou",
		RoleARN:         "acs:ram::6543210987654321:role/csg",
		AccessKeyID:     "LTAIbrokerAKID0001",
		AccessKeySecret: "broker-secret-0001",
	})
	requireStatus(t, stsRec, http.StatusCreated)
	sts := decodeEnvelope[model.Provider](t, stsRec)
	if sts.AccessKeyIDMasked != "LTAI****0001" {
		t.Fatalf("sts masked AccessKey = %q", sts.AccessKeyIDMasked)
	}

	// PATCH updates fields.
	name := "renamed-provider"
	region := "cn-shanghai"
	disabled := model.ProviderDisabled
	patchRec := env.admin(http.MethodPatch, "/api/v1/admin/providers/"+created.ID, model.UpdateProviderInput{
		Name:   &name,
		Region: &region,
		Status: &disabled,
	})
	requireStatus(t, patchRec, http.StatusOK)
	patched := decodeEnvelope[model.Provider](t, patchRec)
	if patched.Name != name || patched.Region != region || patched.Status != model.ProviderDisabled {
		t.Fatalf("patched provider = %+v", patched)
	}
	if !env.hasAction("provider.updated") {
		t.Fatal("missing provider.updated audit event")
	}

	// Rotate the sts credential; the masked form changes.
	rotateRec := env.admin(http.MethodPost, "/api/v1/admin/providers/"+sts.ID+"/rotate", model.RotateProviderCredentialInput{
		AccessKeyID:     "LTAIrotatedAKID9999",
		AccessKeySecret: "rotated-secret-9999",
	})
	requireStatus(t, rotateRec, http.StatusOK)
	rotated := decodeEnvelope[model.Provider](t, rotateRec)
	if rotated.AccessKeyIDMasked != "LTAI****9999" {
		t.Fatalf("rotated masked AccessKey = %q", rotated.AccessKeyIDMasked)
	}
	if !env.hasAction("provider.credential_rotated") {
		t.Fatal("missing provider.credential_rotated audit event")
	}

	// Test endpoint persists last_tested_at/last_test_ok.
	testRec := env.admin(http.MethodPost, "/api/v1/admin/providers/"+sts.ID+"/test", nil)
	requireStatus(t, testRec, http.StatusOK)
	testResult := decodeEnvelope[providerTestResult](t, testRec)
	if !testResult.OK || testResult.Message == "" {
		t.Fatalf("provider test result = %+v", testResult)
	}
	if !testResult.TestedAt.Equal(fixedTestTime) {
		t.Fatalf("tested_at = %v, want %v", testResult.TestedAt, fixedTestTime)
	}
	rec = env.admin(http.MethodGet, "/api/v1/admin/providers/"+sts.ID, nil)
	requireStatus(t, rec, http.StatusOK)
	testedProvider := decodeEnvelope[model.Provider](t, rec)
	if testedProvider.LastTestOK == nil || !*testedProvider.LastTestOK || testedProvider.LastTestedAt == nil {
		t.Fatalf("provider test state not persisted: %+v", testedProvider)
	}
	if !env.hasAction("provider.tested") {
		t.Fatal("missing provider.tested audit event")
	}

	// Unknown provider IDs are 404.
	if rec := env.admin(http.MethodGet, "/api/v1/admin/providers/prv_missing", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("GET missing provider status = %d, want 404", rec.Code)
	}
	env.verifyAudit()
}

func TestProviderValidation(t *testing.T) {
	env := newTestEnv(t, true)
	tests := []struct {
		name string
		body model.CreateProviderInput
	}{
		{"invalid type", model.CreateProviderInput{Type: "aws", Mode: model.ModeMock, Region: "us-east-1"}},
		{"invalid mode", model.CreateProviderInput{Type: model.ProviderAliyun, Mode: "fake", Region: "cn-hangzhou"}},
		{"missing region", model.CreateProviderInput{Type: model.ProviderAliyun, Mode: model.ModeMock}},
		{"sts missing credentials", model.CreateProviderInput{Type: model.ProviderAliyun, Mode: model.ModeSTS, Region: "cn-hangzhou"}},
		{"sts missing role", model.CreateProviderInput{
			Type: model.ProviderAliyun, Mode: model.ModeSTS, Region: "cn-hangzhou",
			AccessKeyID: "LTAIx", AccessKeySecret: "secret",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := env.admin(http.MethodPost, "/api/v1/admin/providers", tt.body)
			requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
		})
	}

	// Unknown provider credential rotation is 404.
	rec := env.admin(http.MethodPost, "/api/v1/admin/providers/prv_missing/rotate", model.RotateProviderCredentialInput{
		AccessKeyID: "LTAIx", AccessKeySecret: "y",
	})
	requireErrorCode(t, rec, http.StatusNotFound, model.ErrCodeNotFound)

	// Rotating with empty credentials is a 400.
	rec = env.admin(http.MethodPost, "/api/v1/admin/providers/"+env.providerID+"/rotate", model.RotateProviderCredentialInput{})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
}

func TestDisabledProviderBlocksLeases(t *testing.T) {
	env := newTestEnv(t, true)
	disabled := model.ProviderDisabled
	rec := env.admin(http.MethodPatch, "/api/v1/admin/providers/"+env.providerID, model.UpdateProviderInput{Status: &disabled})
	requireStatus(t, rec, http.StatusOK)

	lease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "provider disabled",
	})
	if lease.Status != model.LeaseDenied {
		t.Fatalf("lease status = %q, want denied", lease.Status)
	}
	requireRuleOutcome(t, lease.Decision, "provider_active", "deny")

	// Approval of an existing pending lease is blocked while the provider is disabled.
	active := model.ProviderActive
	rec = env.admin(http.MethodPatch, "/api/v1/admin/providers/"+env.providerID, model.UpdateProviderInput{Status: &active})
	requireStatus(t, rec, http.StatusOK)
	pending, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "will be blocked",
	})
	rec = env.admin(http.MethodPatch, "/api/v1/admin/providers/"+env.providerID, model.UpdateProviderInput{Status: &disabled})
	requireStatus(t, rec, http.StatusOK)
	approveRec := env.admin(http.MethodPost, "/api/v1/admin/leases/"+pending.ID+"/approve", model.ApproveLeaseInput{})
	requireErrorCode(t, approveRec, http.StatusConflict, model.ErrCodeConflict)
}

func TestProviderRotationDoesNotAffectExistingLeases(t *testing.T) {
	env := newTestEnv(t, true)
	lease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "before rotation",
	})
	if lease.Status != model.LeaseActive {
		t.Fatalf("lease status = %q", lease.Status)
	}

	rec := env.admin(http.MethodPost, "/api/v1/admin/providers/"+env.providerID+"/rotate", model.RotateProviderCredentialInput{
		AccessKeyID:     "LTAInewBrokerAKID42",
		AccessKeySecret: "new-broker-secret-42",
	})
	requireStatus(t, rec, http.StatusOK)

	// The existing lease credential is unaffected.
	if _, fetchRec := env.fetchCredential("claude-code", lease.ID); fetchRec.Code != http.StatusOK {
		t.Fatalf("credential fetch after rotation status = %d, want 200", fetchRec.Code)
	}

	// New leases mint with the rotated broker credential.
	fresh, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.cloud.read",
		Reason:       "after rotation",
	})
	if fresh.Status != model.LeaseActive {
		t.Fatalf("post-rotation lease status = %q", fresh.Status)
	}
	if got := env.minter.lastRequest(t).BrokerAccessKeyID; got != "LTAInewBrokerAKID42" {
		t.Fatalf("new lease minted with broker AKID %q, want rotated one", got)
	}
}

func TestCapabilityAdminCRUD(t *testing.T) {
	env := newTestEnv(t, true)

	rec := env.admin(http.MethodGet, "/api/v1/admin/capabilities", nil)
	requireStatus(t, rec, http.StatusOK)
	builtins := decodeEnvelope[model.ListResponse[model.Capability]](t, rec)
	if builtins.Total != 5 {
		t.Fatalf("builtin capabilities = %d, want 5", builtins.Total)
	}

	// Create a valid custom capability.
	custom := model.Capability{
		Name:              "Custom bucket read",
		Description:       "Read one OSS bucket",
		ProviderType:      model.ProviderAliyun,
		Risk:              model.RiskLow,
		PolicyTemplate:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:List*"],"Resource":["acs:oss:*:*:{{bucket}}"]}]}`,
		Params:            []model.CapabilityParam{{Name: "bucket", Required: true, Pattern: `^[a-z0-9-]+$`}},
		DefaultTTLSeconds: 300,
		MaxTTLSeconds:     600,
	}
	createRec := env.admin(http.MethodPost, "/api/v1/admin/capabilities", custom)
	requireStatus(t, createRec, http.StatusCreated)
	created := decodeEnvelope[model.Capability](t, createRec)
	if !strings.HasPrefix(created.ID, "cap_") || created.Builtin || !created.Enabled {
		t.Fatalf("created capability = %+v", created)
	}
	if !env.hasAction("capability.created") {
		t.Fatal("missing capability.created audit event")
	}

	// A custom capability with no declared access level is classified admin,
	// the most restrictive classification (CONTRACT §16.6 step 1).
	if created.Access != model.AccessAdmin {
		t.Fatalf("created capability access = %q, want admin", created.Access)
	}

	// Grant it to claude-code (an administrator) and lease it.
	grants := append([]string{"aliyun.cloud.read", "aliyun.dns.manage", "aliyun.cert.dns01", "aliyun.ecs.instance.ops", "aliyun.account.admin"}, created.ID)
	grantRec := env.admin(http.MethodPatch, "/api/v1/admin/agents/"+env.agentIDs["claude-code"], model.UpdateAgentInput{Grants: &grants})
	requireStatus(t, grantRec, http.StatusOK)
	lease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: created.ID,
		Params:       map[string]string{"bucket": "demo-bucket"},
		Reason:       "inspect bucket",
	})
	// Admin-level access is never auto-approved, even when a custom capability
	// declares low risk (CONTRACT §16.4 admin_requires_approval).
	if lease.Status != model.LeasePending {
		t.Fatalf("custom admin-capability lease status = %q, want pending (reasons %v)", lease.Status, lease.Decision.Reasons)
	}
	approveRec := env.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", model.ApproveLeaseInput{Note: "ok"})
	requireStatus(t, approveRec, http.StatusOK)
	if got := env.getLease(lease.ID); got.Status != model.LeaseActive {
		t.Fatalf("approved custom-capability lease status = %q, want active", got.Status)
	}
	if policy := string(env.minter.lastRequest(t).PolicyJSON); !strings.Contains(policy, "acs:oss:*:*:demo-bucket") {
		t.Fatalf("custom policy not rendered with params: %s", policy)
	}

	// Disable it: new leases are denied, and approval of pending leases is blocked.
	disabled := false
	disableRec := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/"+created.ID, map[string]any{"enabled": disabled})
	requireStatus(t, disableRec, http.StatusOK)
	deniedLease, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: created.ID,
		Params:       map[string]string{"bucket": "demo-bucket"},
		Reason:       "capability disabled",
	})
	if deniedLease.Status != model.LeaseDenied {
		t.Fatalf("disabled-capability lease status = %q, want denied", deniedLease.Status)
	}
	requireRuleOutcome(t, deniedLease.Decision, "capability_enabled", "deny")

	// Builtin risk/policy/params are immutable.
	risk := model.RiskCritical
	builtinPatch := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/aliyun.cloud.read", map[string]any{"risk": risk})
	requireErrorCode(t, builtinPatch, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	// So is the access level: raising it would re-open the capability to roles
	// that must not hold it (CONTRACT §16.3).
	accessPatch := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/aliyun.cloud.read",
		map[string]any{"access": model.AccessAdmin})
	requireErrorCode(t, accessPatch, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	// Builtin TTLs and enabled toggles are allowed.
	ttlUpdate := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/aliyun.cloud.read", map[string]any{"default_ttl_seconds": 300})
	requireStatus(t, ttlUpdate, http.StatusOK)
	if got := decodeEnvelope[model.Capability](t, ttlUpdate).DefaultTTLSeconds; got != 300 {
		t.Fatalf("default TTL after patch = %d, want 300", got)
	}
	if !env.hasAction("capability.updated") {
		t.Fatal("missing capability.updated audit event")
	}
	// Unknown capability is 404.
	if rec := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/cap_missing", map[string]any{"enabled": false}); rec.Code != http.StatusNotFound {
		t.Fatalf("patch missing capability status = %d, want 404", rec.Code)
	}
	env.verifyAudit()
}

func TestCapabilityValidation(t *testing.T) {
	env := newTestEnv(t, true)
	valid := model.Capability{
		Name:              "Valid",
		ProviderType:      model.ProviderAliyun,
		Risk:              model.RiskLow,
		PolicyTemplate:    `{"Version":"1","Statement":[]}`,
		DefaultTTLSeconds: 300,
		MaxTTLSeconds:     600,
	}
	tests := []struct {
		name   string
		mutate func(*model.Capability)
	}{
		{"missing name", func(c *model.Capability) { c.Name = "" }},
		{"invalid risk", func(c *model.Capability) { c.Risk = "extreme" }},
		{"invalid provider type", func(c *model.Capability) { c.ProviderType = "aws" }},
		{"zero default ttl", func(c *model.Capability) { c.DefaultTTLSeconds = 0 }},
		{"default over max", func(c *model.Capability) { c.DefaultTTLSeconds, c.MaxTTLSeconds = 900, 600 }},
		{"max over global", func(c *model.Capability) { c.MaxTTLSeconds = 4000 }},
		{"invalid policy json", func(c *model.Capability) { c.PolicyTemplate = `{not json` }},
		{"undeclared placeholder", func(c *model.Capability) {
			c.PolicyTemplate = `{"Resource":["{{nope}}"]}`
		}},
		{"invalid access level", func(c *model.Capability) { c.Access = "root" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capability := valid
			tt.mutate(&capability)
			rec := env.admin(http.MethodPost, "/api/v1/admin/capabilities", capability)
			requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
		})
	}
}

// TestCapabilityTemplateIAMProhibition covers CONTRACT §16.3 at the admin API:
// a template that violates the IAM prohibition is a 400 naming the offending
// action, is audited as capability.rejected, and never reaches the catalog.
func TestCapabilityTemplateIAMProhibition(t *testing.T) {
	env := newTestEnv(t, true)

	tests := []struct {
		name          string
		access        model.AccessLevel
		template      string
		wantInMessage string
	}{
		{
			name:          "ram wildcard",
			access:        model.AccessAdmin,
			template:      `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ram:*"],"Resource":["*"]}]}`,
			wantInMessage: "ram:*",
		},
		{
			name:          "ram create user",
			access:        model.AccessWrite,
			template:      `{"Version":"1","Statement":[{"Effect":"Allow","Action":"RAM:CreateUser","Resource":"*"}]}`,
			wantInMessage: "RAM:CreateUser",
		},
		{
			name:          "role chaining",
			access:        model.AccessWrite,
			template:      `{"Version":"1","Statement":[{"Effect":"Allow","Action":["sts:AssumeRole"],"Resource":["*"]}]}`,
			wantInMessage: "sts:AssumeRole",
		},
		{
			name:          "wildcard service",
			access:        model.AccessAdmin,
			template:      `{"Version":"1","Statement":[{"Effect":"Allow","Action":["r*:*"],"Resource":["*"]}]}`,
			wantInMessage: "r*:*",
		},
		{
			name:          "not action",
			access:        model.AccessAdmin,
			template:      `{"Version":"1","Statement":[{"Effect":"Allow","NotAction":["ram:*"],"Resource":["*"]}]}`,
			wantInMessage: "NotAction",
		},
		{
			name:          "write action on a read capability",
			access:        model.AccessRead,
			template:      `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:StopInstance"],"Resource":["*"]}]}`,
			wantInMessage: "ecs:StopInstance",
		},
		{
			name:          "bare wildcard below admin",
			access:        model.AccessWrite,
			template:      `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			wantInMessage: `"*"`,
		},
	}

	before := len(env.listAudit("capability.rejected"))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := env.admin(http.MethodPost, "/api/v1/admin/capabilities", model.Capability{
				Name:              "Prohibited " + tt.name,
				ProviderType:      model.ProviderAliyun,
				Risk:              model.RiskHigh,
				Access:            tt.access,
				PolicyTemplate:    tt.template,
				DefaultTTLSeconds: 300,
				MaxTTLSeconds:     600,
			})
			requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
			if msg := decodeError(t, rec).Error.Message; !strings.Contains(msg, tt.wantInMessage) {
				t.Fatalf("error message = %q, want it to name %q", msg, tt.wantInMessage)
			}
		})
	}

	rejected := env.listAudit("capability.rejected")
	if len(rejected)-before != len(tests) {
		t.Fatalf("capability.rejected events = %d, want %d", len(rejected)-before, len(tests))
	}
	for _, ev := range rejected {
		if ev.Severity != "warning" || ev.Status != "denied" {
			t.Fatalf("capability.rejected severity/status = %q/%q, want warning/denied", ev.Severity, ev.Status)
		}
	}

	// Nothing was added to the catalog.
	listRec := env.admin(http.MethodGet, "/api/v1/admin/capabilities", nil)
	requireStatus(t, listRec, http.StatusOK)
	if total := decodeEnvelope[model.ListResponse[model.Capability]](t, listRec).Total; total != 5 {
		t.Fatalf("capabilities = %d, want the 5 builtins only", total)
	}

	// A PATCH that would introduce a prohibited template is refused the same way.
	okRec := env.admin(http.MethodPost, "/api/v1/admin/capabilities", model.Capability{
		Name:              "Bucket read",
		ProviderType:      model.ProviderAliyun,
		Risk:              model.RiskLow,
		Access:            model.AccessRead,
		PolicyTemplate:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:List*"],"Resource":["*"]}]}`,
		DefaultTTLSeconds: 300,
		MaxTTLSeconds:     600,
	})
	requireStatus(t, okRec, http.StatusCreated)
	custom := decodeEnvelope[model.Capability](t, okRec)
	patchRec := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/"+custom.ID, map[string]any{
		"policy_template": `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ram:ListUsers"],"Resource":["*"]}]}`,
	})
	requireErrorCode(t, patchRec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	stored, err := env.srv.db.GetCapability(context.Background(), custom.ID)
	if err != nil {
		t.Fatalf("GetCapability: %v", err)
	}
	if strings.Contains(stored.PolicyTemplate, "ram:") {
		t.Fatalf("refused PATCH still persisted the prohibited template: %s", stored.PolicyTemplate)
	}
	env.verifyAudit()
}

// TestCapabilityAccessRaiseRejectsOutOfRoleAgents covers CONTRACT §16.3: a
// PATCH that raises a custom capability's access must return 400 naming every
// granted agent whose role would not permit the new level, and must not persist
// the raise. Lowering access, or raising when every holder can use the new
// level, still succeeds.
func TestCapabilityAccessRaiseRejectsOutOfRoleAgents(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t, true)

	createRec := env.admin(http.MethodPost, "/api/v1/admin/capabilities", model.Capability{
		Name:              "Scoped OSS read",
		ProviderType:      model.ProviderAliyun,
		Risk:              model.RiskLow,
		Access:            model.AccessRead,
		PolicyTemplate:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:List*"],"Resource":["*"]}]}`,
		DefaultTTLSeconds: 300,
		MaxTTLSeconds:     600,
	})
	requireStatus(t, createRec, http.StatusCreated)
	custom := decodeEnvelope[model.Capability](t, createRec)

	// Grant the read capability to hermes (guest). Raising it to write would
	// leave that grant outside the guest role.
	hermesID := env.agentIDs["hermes-researcher"]
	hermes, err := env.srv.db.GetAgent(ctx, hermesID)
	if err != nil {
		t.Fatalf("GetAgent: %v", err)
	}
	grants := append(append([]string{}, hermes.Grants...), custom.ID)
	grantRec := env.admin(http.MethodPatch, "/api/v1/admin/agents/"+hermesID, model.UpdateAgentInput{Grants: &grants})
	requireStatus(t, grantRec, http.StatusOK)

	raiseRec := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/"+custom.ID, map[string]any{
		"access": model.AccessWrite,
	})
	requireErrorCode(t, raiseRec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	msg := decodeError(t, raiseRec).Error.Message
	if !strings.Contains(msg, "hermes-researcher") {
		t.Fatalf("error message = %q, want it to name hermes-researcher", msg)
	}
	if !strings.Contains(msg, string(model.RoleGuest)) {
		t.Fatalf("error message = %q, want it to name the guest role", msg)
	}
	stored, err := env.srv.db.GetCapability(ctx, custom.ID)
	if err != nil {
		t.Fatalf("GetCapability: %v", err)
	}
	if stored.Access != model.AccessRead {
		t.Fatalf("refused raise persisted access = %q, want read", stored.Access)
	}

	// After removing the guest grant, the same raise succeeds.
	without := hermes.Grants
	ungrantRec := env.admin(http.MethodPatch, "/api/v1/admin/agents/"+hermesID, model.UpdateAgentInput{Grants: &without})
	requireStatus(t, ungrantRec, http.StatusOK)
	okRaise := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/"+custom.ID, map[string]any{
		"access": model.AccessWrite,
	})
	requireStatus(t, okRaise, http.StatusOK)
	if got := decodeEnvelope[model.Capability](t, okRaise).Access; got != model.AccessWrite {
		t.Fatalf("access after raise = %q, want write", got)
	}

	// Lowering access is always allowed (it cannot leave grants outside a role).
	lowerRec := env.admin(http.MethodPatch, "/api/v1/admin/capabilities/"+custom.ID, map[string]any{
		"access": model.AccessRead,
	})
	requireStatus(t, lowerRec, http.StatusOK)
	if got := decodeEnvelope[model.Capability](t, lowerRec).Access; got != model.AccessRead {
		t.Fatalf("access after lower = %q, want read", got)
	}
	env.verifyAudit()
}

func TestAgentAdminCRUD(t *testing.T) {
	env := newTestEnv(t, true)

	rec := env.admin(http.MethodGet, "/api/v1/admin/agents", nil)
	requireStatus(t, rec, http.StatusOK)
	agents := decodeEnvelope[model.ListResponse[model.Agent]](t, rec)
	if agents.Total != 2 {
		t.Fatalf("seeded agents = %d, want 2", agents.Total)
	}

	// Validation.
	rec = env.admin(http.MethodPost, "/api/v1/admin/agents", model.CreateAgentInput{Name: ""})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	rec = env.admin(http.MethodPost, "/api/v1/admin/agents", model.CreateAgentInput{
		Name:   "bad-grants",
		Grants: []string{"cap_missing"},
	})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// Create. The role bounds the grants, so ci-bot needs member to hold the
	// write capability it is granted below (CONTRACT §16.1).
	createRec := env.admin(http.MethodPost, "/api/v1/admin/agents", model.CreateAgentInput{
		Name:                "ci-bot",
		Description:         "CI helper",
		Role:                model.RoleMember,
		Grants:              []string{"aliyun.cloud.read"},
		MaxTTLSeconds:       600,
		MaxConcurrentLeases: 2,
	})
	requireStatus(t, createRec, http.StatusCreated)
	created := decodeEnvelope[model.AgentWithToken](t, createRec)
	if created.Agent.Name != "ci-bot" || created.Token == "" {
		t.Fatalf("created agent = %+v", created.Agent)
	}
	if created.Agent.Role != model.RoleMember {
		t.Fatalf("created agent role = %q, want member", created.Agent.Role)
	}
	if !strings.HasPrefix(created.Token, "csg_agt_") || created.Agent.TokenPrefix == "" {
		t.Fatalf("agent token/prefix = %q / %q", created.Token, created.Agent.TokenPrefix)
	}
	if created.Agent.MaxTTLSeconds != 600 || created.Agent.MaxConcurrentLeases != 2 {
		t.Fatalf("created agent limits = %+v", created.Agent)
	}

	// The new token authenticates.
	rec = env.do(http.MethodGet, "/api/v1/agent/me", created.Token, nil)
	requireStatus(t, rec, http.StatusOK)

	// The raw token is never returned by list/get.
	listRec := env.admin(http.MethodGet, "/api/v1/admin/agents", nil)
	if structContains(t, listRec.Body.String(), created.Token) {
		t.Fatal("agent list response contains a plaintext agent token")
	}
	getRec := env.admin(http.MethodGet, "/api/v1/admin/agents/"+created.Agent.ID, nil)
	if structContains(t, getRec.Body.String(), created.Token) {
		t.Fatal("agent get response contains a plaintext agent token")
	}
	if !env.hasAction("agent.created") {
		t.Fatal("missing agent.created audit event")
	}

	// PATCH grants and description.
	grants := []string{"aliyun.cloud.read", "aliyun.dns.manage"}
	desc := "CI helper with DNS"
	patchRec := env.admin(http.MethodPatch, "/api/v1/admin/agents/"+created.Agent.ID, model.UpdateAgentInput{
		Grants:      &grants,
		Description: &desc,
	})
	requireStatus(t, patchRec, http.StatusOK)
	patched := decodeEnvelope[model.Agent](t, patchRec)
	if len(patched.Grants) != 2 || patched.Description != desc {
		t.Fatalf("patched agent = %+v", patched)
	}
	// Unknown grant on PATCH is a 400.
	badGrants := []string{"cap_missing"}
	rec = env.admin(http.MethodPatch, "/api/v1/admin/agents/"+created.Agent.ID, model.UpdateAgentInput{Grants: &badGrants})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	// Invalid limits on PATCH are 400.
	zero := 0
	rec = env.admin(http.MethodPatch, "/api/v1/admin/agents/"+created.Agent.ID, model.UpdateAgentInput{MaxTTLSeconds: &zero})
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// Suspend/activate.
	rec = env.admin(http.MethodPost, "/api/v1/admin/agents/"+created.Agent.ID+"/suspend", nil)
	requireStatus(t, rec, http.StatusOK)
	rec = env.do(http.MethodGet, "/api/v1/agent/me", created.Token, nil)
	requireErrorCode(t, rec, http.StatusForbidden, model.ErrCodeForbidden)
	rec = env.admin(http.MethodPost, "/api/v1/admin/agents/"+created.Agent.ID+"/activate", nil)
	requireStatus(t, rec, http.StatusOK)
	rec = env.do(http.MethodGet, "/api/v1/agent/me", created.Token, nil)
	requireStatus(t, rec, http.StatusOK)

	// Unknown agent is 404.
	if rec := env.admin(http.MethodGet, "/api/v1/admin/agents/agt_missing", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("GET missing agent status = %d, want 404", rec.Code)
	}
	env.verifyAudit()
}

func TestTokenRotationInvalidatesOldToken(t *testing.T) {
	env := newTestEnv(t, true)
	agentID := env.agentIDs["claude-code"]
	oldToken := env.agentTokens["claude-code"]

	rec := env.admin(http.MethodPost, "/api/v1/admin/agents/"+agentID+"/token/rotate", nil)
	requireStatus(t, rec, http.StatusOK)
	rotated := decodeEnvelope[model.AgentWithToken](t, rec)
	if rotated.Token == "" || rotated.Token == oldToken {
		t.Fatal("token rotation did not return a fresh token")
	}

	// Old token is invalid immediately; the new one works.
	rec = env.do(http.MethodGet, "/api/v1/agent/me", oldToken, nil)
	requireErrorCode(t, rec, http.StatusUnauthorized, model.ErrCodeUnauthorized)
	rec = env.do(http.MethodGet, "/api/v1/agent/me", rotated.Token, nil)
	requireStatus(t, rec, http.StatusOK)

	if !env.hasAction("agent.token_rotated") {
		t.Fatal("missing agent.token_rotated audit event")
	}
	var warning bool
	for _, ev := range env.listAudit("agent.token_rotated") {
		if ev.Severity == "warning" {
			warning = true
		}
	}
	if !warning {
		t.Fatal("agent.token_rotated was not audited at warning severity")
	}
}

func TestOverviewShape(t *testing.T) {
	env := newTestEnv(t, true)

	// Empty-but-seeded overview.
	rec := env.admin(http.MethodGet, "/api/v1/admin/overview", nil)
	requireStatus(t, rec, http.StatusOK)
	overview := decodeEnvelope[model.Overview](t, rec)
	if overview.Counts.Agents != 2 || overview.Counts.ActiveAgents != 2 {
		t.Fatalf("agent counts = %+v", overview.Counts)
	}
	if overview.Counts.Capabilities != 5 || overview.Counts.Providers != 1 {
		t.Fatalf("catalog counts = %+v", overview.Counts)
	}
	if overview.Counts.ActiveLeases != 0 || overview.Counts.PendingLeases != 0 {
		t.Fatalf("lease counts = %+v", overview.Counts)
	}
	if !overview.Vault.Configured || overview.Vault.KeyFingerprint == "" || overview.Vault.SecretsStored != 1 {
		t.Fatalf("vault status = %+v", overview.Vault)
	}
	if len(overview.Vault.KeyFingerprint) != 16 {
		t.Fatalf("key fingerprint length = %d, want 16", len(overview.Vault.KeyFingerprint))
	}
	if overview.Version != model.Version {
		t.Fatalf("version = %q", overview.Version)
	}
	if !overview.ServerTime.Equal(fixedTestTime) {
		t.Fatalf("server_time = %v, want fixed clock", overview.ServerTime)
	}
	if overview.Policy.AutoApproveMaxRisk != model.RiskLow {
		t.Fatalf("policy = %+v", overview.Policy)
	}
	if len(overview.Providers) != 1 || overview.Providers[0].Name != "demo-aliyun" {
		t.Fatalf("overview providers = %+v", overview.Providers)
	}

	// Create one active (low risk) and one pending (medium risk) lease.
	active, _ := env.createLease("claude-code", model.CreateLeaseInput{CapabilityID: "aliyun.cloud.read", Reason: "active"})
	if active.Status != model.LeaseActive {
		t.Fatalf("seed active lease status = %q", active.Status)
	}
	pending, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "pending",
	})
	if pending.Status != model.LeasePending {
		t.Fatalf("seed pending lease status = %q", pending.Status)
	}

	rec = env.admin(http.MethodGet, "/api/v1/admin/overview", nil)
	requireStatus(t, rec, http.StatusOK)
	overview = decodeEnvelope[model.Overview](t, rec)
	if overview.Counts.ActiveLeases != 1 || overview.Counts.PendingLeases != 1 {
		t.Fatalf("lease counts after create = %+v", overview.Counts)
	}
	if overview.RiskBreakdown.Low != 1 || overview.RiskBreakdown.Medium != 1 {
		t.Fatalf("risk breakdown = %+v", overview.RiskBreakdown)
	}
	if len(overview.PendingLeases) != 1 || overview.PendingLeases[0].ID != pending.ID {
		t.Fatalf("overview pending leases = %+v", overview.PendingLeases)
	}
	if len(overview.ActiveLeases) != 1 || overview.ActiveLeases[0].ID != active.ID {
		t.Fatalf("overview active leases = %+v", overview.ActiveLeases)
	}
	if overview.Counts.Events24h < 2 {
		t.Fatalf("events_24h = %d, want >= 2", overview.Counts.Events24h)
	}
	if len(overview.RecentEvents) == 0 {
		t.Fatal("overview recent_events is empty")
	}
	if overview.UptimeSeconds < 0 {
		t.Fatalf("uptime_seconds = %d", overview.UptimeSeconds)
	}
}

func TestPolicyUpdateEffect(t *testing.T) {
	env := newTestEnv(t, true)

	// Default policy: medium-risk dns.manage requires approval.
	first, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "before policy change",
	})
	if first.Status != model.LeasePending {
		t.Fatalf("default dns lease status = %q, want pending", first.Status)
	}

	// Raise the auto-approve risk ceiling to medium.
	current := decodeEnvelope[model.PolicySettings](t, env.admin(http.MethodGet, "/api/v1/admin/policy", nil))
	current.AutoApproveMaxRisk = model.RiskMedium
	putRec := env.admin(http.MethodPut, "/api/v1/admin/policy", current)
	requireStatus(t, putRec, http.StatusOK)
	updated := decodeEnvelope[model.PolicySettings](t, putRec)
	if updated.AutoApproveMaxRisk != model.RiskMedium {
		t.Fatalf("updated policy = %+v", updated)
	}
	if !env.hasAction("policy.updated") {
		t.Fatal("missing policy.updated audit event")
	}
	var warning bool
	for _, ev := range env.listAudit("policy.updated") {
		if ev.Severity == "warning" {
			warning = true
		}
	}
	if !warning {
		t.Fatal("policy.updated was not audited at warning severity")
	}

	// The same request is now auto-approved.
	second, _ := env.createLease("claude-code", model.CreateLeaseInput{
		CapabilityID: "aliyun.dns.manage",
		Params:       map[string]string{"domain": "arveykao.com"},
		Reason:       "after policy change",
	})
	if second.Status != model.LeaseActive || second.Decision.Outcome != model.OutcomeAutoApprove {
		t.Fatalf("post-policy lease = %+v (status %q outcome %q)", second, second.Status, second.Decision.Outcome)
	}

	// Invalid policy settings are rejected and do not change stored state.
	bad := current
	bad.AutoApproveMaxRisk = "extreme"
	rec := env.admin(http.MethodPut, "/api/v1/admin/policy", bad)
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	bad = current
	bad.MaxLeaseTTLSeconds = bad.AutoApproveMaxTTLSeconds - 1
	rec = env.admin(http.MethodPut, "/api/v1/admin/policy", bad)
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	bad = current
	bad.PendingTimeoutSeconds = 0
	rec = env.admin(http.MethodPut, "/api/v1/admin/policy", bad)
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)
	after := decodeEnvelope[model.PolicySettings](t, env.admin(http.MethodGet, "/api/v1/admin/policy", nil))
	if after != updated {
		t.Fatalf("policy changed after invalid updates: %+v", after)
	}
	env.verifyAudit()
}

func TestAdminAuditListAndVerify(t *testing.T) {
	env := newTestEnv(t, true)

	// Generate a few events.
	env.admin(http.MethodPost, "/api/v1/admin/login", nil)
	lease, _ := env.createLease("claude-code", model.CreateLeaseInput{CapabilityID: "aliyun.cloud.read", Reason: "audit test"})
	if lease.Status != model.LeaseActive {
		t.Fatalf("lease status = %q", lease.Status)
	}

	// List newest first, filtered by action.
	rec := env.admin(http.MethodGet, "/api/v1/admin/audit?limit=200", nil)
	requireStatus(t, rec, http.StatusOK)
	all := decodeEnvelope[model.ListResponse[model.AuditEvent]](t, rec)
	if all.Total == 0 || len(all.Items) == 0 {
		t.Fatal("audit list is empty")
	}
	for i := 1; i < len(all.Items); i++ {
		if all.Items[i-1].Seq <= all.Items[i].Seq {
			t.Fatalf("audit list is not newest-first: %d then %d", all.Items[i-1].Seq, all.Items[i].Seq)
		}
	}

	rec = env.admin(http.MethodGet, "/api/v1/admin/audit?action=lease.requested", nil)
	requireStatus(t, rec, http.StatusOK)
	requested := decodeEnvelope[model.ListResponse[model.AuditEvent]](t, rec)
	if requested.Total != 1 || requested.Items[0].Action != "lease.requested" {
		t.Fatalf("filtered audit = %+v", requested)
	}

	// Filter by severity + since + pagination.
	rec = env.admin(http.MethodGet, "/api/v1/admin/audit?severity=warning&since="+fixedTestTime.Add(-time.Hour).Format(time.RFC3339), nil)
	requireStatus(t, rec, http.StatusOK)
	_ = decodeEnvelope[model.ListResponse[model.AuditEvent]](t, rec)
	rec = env.admin(http.MethodGet, "/api/v1/admin/audit?limit=1", nil)
	requireStatus(t, rec, http.StatusOK)
	page := decodeEnvelope[model.ListResponse[model.AuditEvent]](t, rec)
	if page.Total < 2 || len(page.Items) != 1 {
		t.Fatalf("audit pagination total=%d len=%d", page.Total, len(page.Items))
	}

	// Invalid since is a 400.
	rec = env.admin(http.MethodGet, "/api/v1/admin/audit?since=not-a-time", nil)
	requireErrorCode(t, rec, http.StatusBadRequest, model.ErrCodeInvalidRequest)

	// Verify endpoint is OK on a clean chain.
	result := env.verifyAudit()
	if result.Events == 0 {
		t.Fatal("verify reported zero events")
	}

	// Mutating a row makes verification fail at the right seq.
	tamperedSeq := all.Items[len(all.Items)/2].Seq
	if _, err := env.srv.db.SQL().ExecContext(context.Background(),
		`UPDATE audit SET severity = 'critical' WHERE seq = ?`, tamperedSeq); err != nil {
		t.Fatalf("tamper audit row: %v", err)
	}
	rec = env.admin(http.MethodGet, "/api/v1/admin/audit/verify", nil)
	requireStatus(t, rec, http.StatusOK)
	failed := decodeEnvelope[model.AuditVerifyResult](t, rec)
	if failed.OK {
		t.Fatal("verify endpoint did not detect tampering")
	}
	if failed.FirstInvalidSeq != tamperedSeq {
		t.Fatalf("first_invalid_seq = %d, want %d", failed.FirstInvalidSeq, tamperedSeq)
	}
	if !strings.Contains(failed.Message, "mismatch") {
		t.Fatalf("verify message = %q", failed.Message)
	}
}

func TestAuditSurvivesRestart(t *testing.T) {
	env := newTestEnv(t, true)
	if rec := env.admin(http.MethodPost, "/api/v1/admin/login", nil); rec.Code != http.StatusOK {
		t.Fatal("login failed")
	}
	// Closing and reopening the store must keep the chain verifiable.
	if err := env.srv.db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	db, err := store.Open(context.Background(), env.dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer db.Close()
	result, err := db.VerifyAudit(context.Background())
	if err != nil || !result.OK || result.Events == 0 {
		t.Fatalf("audit verify after reopen = %+v, %v", result, err)
	}
}
