package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/capcatalog"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
	"github.com/arveykao/cloud-safeguard/internal/token"
	"github.com/arveykao/cloud-safeguard/internal/vault"
)

// ================= login / overview =================

// handleAdminLogin implements POST /api/v1/admin/login.
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	s.adminAudit(r.Context(), "auth.admin_login", "ok", "info", "admin", "admin", map[string]any{
		"remote_addr": remoteHost(r),
	})
	s.writeData(w, http.StatusOK, model.LoginResult{
		OK:      true,
		Role:    "admin",
		Version: s.version,
	})
}

// handleAdminOverview implements GET /api/v1/admin/overview.
func (s *Server) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := s.nowUTC()

	agents, err := s.db.ListAgents(ctx)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	providers, err := s.db.ListProviders(ctx)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	capabilities, err := s.db.ListCapabilities(ctx)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	pending, err := s.db.ListPendingLeases(ctx)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	active, err := s.db.ListActiveLeases(ctx)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	policySettings, err := s.db.GetPolicySettings(ctx)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	_, events24h, err := s.db.ListAudit(ctx, store.AuditFilter{Since: now.Add(-24 * time.Hour), Limit: 1})
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	denied24h, err := s.db.CountLeasesCreatedSinceByStatus(ctx, model.LeaseDenied, now.Add(-24*time.Hour))
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	risk, err := s.db.CountLeasesByRisk(ctx, []model.LeaseStatus{model.LeaseActive, model.LeasePending})
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	secretsStored, err := s.db.CountProviderCredentials(ctx)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	recent, _, err := s.db.ListAudit(ctx, store.AuditFilter{Limit: 20})
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}

	activeAgents := 0
	for _, a := range agents {
		if a.Status == model.AgentActive {
			activeAgents++
		}
	}

	overview := model.Overview{
		Counts: model.OverviewCounts{
			Agents:          len(agents),
			ActiveAgents:    activeAgents,
			Capabilities:    len(capabilities),
			Providers:       len(providers),
			ActiveLeases:    len(active),
			PendingLeases:   len(pending),
			Events24h:       events24h,
			DeniedLeases24h: denied24h,
		},
		RiskBreakdown: risk,
		Policy:        policySettings,
		Vault: model.VaultStatus{
			Configured:     true,
			KeyFingerprint: vault.KeyFingerprint(s.key),
			SecretsStored:  secretsStored,
		},
		PendingLeases: trimLeases(pending, 20),
		ActiveLeases:  trimLeases(active, 20),
		RecentEvents:  recent,
		Providers:     providers,
		Version:       s.version,
		UptimeSeconds: int64(now.Sub(s.startedAt).Seconds()),
		ServerTime:    now,
	}
	s.writeData(w, http.StatusOK, overview)
}

// trimLeases caps a lease list at n items (dashboard previews are bounded).
func trimLeases(leases []model.Lease, n int) []model.Lease {
	if len(leases) > n {
		return leases[:n]
	}
	if leases == nil {
		return []model.Lease{}
	}
	return leases
}

// ================= providers =================

// handleAdminListProviders implements GET /api/v1/admin/providers.
func (s *Server) handleAdminListProviders(w http.ResponseWriter, r *http.Request) {
	items, err := s.db.ListProviders(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	writeList(s, w, http.StatusOK, items, len(items))
}

// handleAdminCreateProvider implements POST /api/v1/admin/providers.
func (s *Server) handleAdminCreateProvider(w http.ResponseWriter, r *http.Request) {
	var in model.CreateProviderInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Region = strings.TrimSpace(in.Region)
	in.RoleARN = strings.TrimSpace(in.RoleARN)
	if in.Type == "" {
		in.Type = model.ProviderAliyun // single supported vendor; CLI may omit it
	}
	if !in.Type.Valid() {
		s.badRequest(w, "type must be aliyun")
		return
	}
	if !in.Mode.Valid() {
		s.badRequest(w, "mode must be one of sts, mock")
		return
	}
	if in.Region == "" {
		s.badRequest(w, "region is required")
		return
	}
	switch in.Mode {
	case model.ModeSTS:
		if strings.TrimSpace(in.AccessKeyID) == "" || strings.TrimSpace(in.AccessKeySecret) == "" || in.RoleARN == "" {
			s.badRequest(w, "sts providers require access_key_id, access_key_secret and role_arn")
			return
		}
	case model.ModeMock:
		// Missing AccessKey values are replaced with generated placeholders.
		if strings.TrimSpace(in.AccessKeyID) == "" {
			suffix, err := randomHexUpper(4)
			if err != nil {
				s.writeHandlerError(w, err)
				return
			}
			in.AccessKeyID = "LTAI5tMock" + suffix
		}
		if in.AccessKeySecret == "" {
			placeholder, err := randomBase64URL(24)
			if err != nil {
				s.writeHandlerError(w, err)
				return
			}
			in.AccessKeySecret = placeholder
		}
	}

	now := s.nowUTC()
	id, err := newID("prv_")
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	name := in.Name
	if name == "" {
		name = "provider-" + strings.TrimPrefix(id, "prv_")[:8]
	}
	credentialJSON, err := json.Marshal(brokerCredential{
		AccessKeyID:     in.AccessKeyID,
		AccessKeySecret: in.AccessKeySecret,
	})
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	encrypted, err := s.vault.Encrypt(credentialJSON, providerAAD(id))
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	prov := model.Provider{
		ID:                id,
		Name:              name,
		Type:              in.Type,
		Mode:              in.Mode,
		Region:            in.Region,
		RoleARN:           in.RoleARN,
		AccessKeyIDMasked: maskAccessKeyID(in.AccessKeyID),
		Status:            model.ProviderActive,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.db.CreateProvider(r.Context(), prov, encrypted); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "provider.created", "ok", "info", "provider", prov.ID, map[string]any{
		"provider_id":          prov.ID,
		"name":                 prov.Name,
		"mode":                 string(prov.Mode),
		"access_key_id_masked": prov.AccessKeyIDMasked,
	})
	s.writeData(w, http.StatusCreated, prov)
}

// handleAdminGetProvider implements GET /api/v1/admin/providers/{id}.
func (s *Server) handleAdminGetProvider(w http.ResponseWriter, r *http.Request) {
	prov, err := s.db.GetProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "provider not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, prov)
}

// handleAdminUpdateProvider implements PATCH /api/v1/admin/providers/{id}.
func (s *Server) handleAdminUpdateProvider(w http.ResponseWriter, r *http.Request) {
	var in model.UpdateProviderInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	prov, err := s.db.GetProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "provider not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	changed := make([]string, 0, 4)
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			s.badRequest(w, "name must not be empty")
			return
		}
		if prov.Name != name {
			prov.Name = name
			changed = append(changed, "name")
		}
	}
	if in.Region != nil {
		region := strings.TrimSpace(*in.Region)
		if region == "" {
			s.badRequest(w, "region must not be empty")
			return
		}
		if prov.Region != region {
			prov.Region = region
			changed = append(changed, "region")
		}
	}
	if in.RoleARN != nil && prov.RoleARN != *in.RoleARN {
		prov.RoleARN = *in.RoleARN
		changed = append(changed, "role_arn")
	}
	if in.Status != nil {
		if *in.Status != model.ProviderActive && *in.Status != model.ProviderDisabled {
			s.badRequest(w, "status must be active or disabled")
			return
		}
		if prov.Status != *in.Status {
			prov.Status = *in.Status
			changed = append(changed, "status")
		}
	}
	prov.UpdatedAt = s.nowUTC()
	if err := s.db.UpdateProvider(r.Context(), prov); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "provider.updated", "ok", "info", "provider", prov.ID, map[string]any{
		"changed_fields": changed,
	})
	s.writeData(w, http.StatusOK, prov)
}

// handleAdminRotateProvider implements POST /api/v1/admin/providers/{id}/rotate.
func (s *Server) handleAdminRotateProvider(w http.ResponseWriter, r *http.Request) {
	var in model.RotateProviderCredentialInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	if strings.TrimSpace(in.AccessKeyID) == "" || in.AccessKeySecret == "" {
		s.badRequest(w, "access_key_id and access_key_secret are required")
		return
	}
	prov, err := s.db.GetProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "provider not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	credentialJSON, err := json.Marshal(brokerCredential{
		AccessKeyID:     in.AccessKeyID,
		AccessKeySecret: in.AccessKeySecret,
	})
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	encrypted, err := s.vault.Encrypt(credentialJSON, providerAAD(prov.ID))
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if err := s.db.UpdateProviderCredential(r.Context(), prov.ID, encrypted); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	oldMasked := prov.AccessKeyIDMasked
	prov.AccessKeyIDMasked = maskAccessKeyID(in.AccessKeyID)
	prov.UpdatedAt = s.nowUTC()
	if err := s.db.UpdateProvider(r.Context(), prov); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "provider.credential_rotated", "ok", "warning", "provider", prov.ID, map[string]any{
		"provider_id":        prov.ID,
		"old_masked_ak":      oldMasked,
		"new_masked_ak":      prov.AccessKeyIDMasked,
		"access_key_id_mask": prov.AccessKeyIDMasked,
	})
	s.writeData(w, http.StatusOK, prov)
}

// providerTestResult is the success payload of POST /admin/providers/{id}/test.
type providerTestResult struct {
	OK       bool      `json:"ok"`
	Message  string    `json:"message"`
	TestedAt time.Time `json:"tested_at"`
}

// handleAdminTestProvider implements POST /api/v1/admin/providers/{id}/test.
func (s *Server) handleAdminTestProvider(w http.ResponseWriter, r *http.Request) {
	prov, err := s.db.GetProvider(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "provider not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	ok, message := s.testProvider(r.Context(), prov)
	now := s.nowUTC()
	prov.LastTestedAt = &now
	prov.LastTestOK = &ok
	prov.UpdatedAt = now
	if err := s.db.UpdateProvider(r.Context(), prov); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "provider.tested", "ok", "info", "provider", prov.ID, map[string]any{
		"ok":      ok,
		"message": message,
	})
	s.writeData(w, http.StatusOK, providerTestResult{OK: ok, Message: message, TestedAt: now})
}

// testProvider decrypts the broker credential and runs the provider's Test.
func (s *Server) testProvider(ctx context.Context, prov model.Provider) (bool, string) {
	encCred, err := s.db.GetProviderCredential(ctx, prov.ID)
	if err != nil {
		return false, "provider has no stored credential"
	}
	plain, err := s.vault.Decrypt(encCred, providerAAD(prov.ID))
	if err != nil {
		return false, "provider credential cannot be decrypted"
	}
	var broker brokerCredential
	if err := json.Unmarshal(plain, &broker); err != nil {
		return false, "provider credential is malformed"
	}
	minter, err := s.minterFactory(prov)
	if err != nil {
		return false, sanitizeMessage(err.Error())
	}
	err = minter.Test(ctx, provider.MintRequest{
		Provider:              prov,
		BrokerAccessKeyID:     broker.AccessKeyID,
		BrokerAccessKeySecret: broker.AccessKeySecret,
		PolicyJSON:            []byte(`{"Version":"1","Statement":[]}`),
		SessionName:           "csg-provider-test",
		SigningKey:            s.signingKey,
	})
	if err != nil {
		return false, sanitizeMessage(err.Error())
	}
	return true, "provider configuration is valid"
}

// ================= capabilities =================

// handleAdminListCapabilities implements GET /api/v1/admin/capabilities.
func (s *Server) handleAdminListCapabilities(w http.ResponseWriter, r *http.Request) {
	items, err := s.db.ListCapabilities(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	writeList(s, w, http.StatusOK, items, len(items))
}

// handleAdminCreateCapability implements POST /api/v1/admin/capabilities.
func (s *Server) handleAdminCreateCapability(w http.ResponseWriter, r *http.Request) {
	var in model.Capability
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	settings, err := s.db.GetPolicySettings(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		s.badRequest(w, "name is required")
		return
	}
	if in.ProviderType == "" {
		in.ProviderType = model.ProviderAliyun
	}
	if !in.ProviderType.Valid() {
		s.badRequest(w, "provider_type must be aliyun")
		return
	}
	if err := validateCapabilityDefinition(in, settings); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	now := s.nowUTC()
	id, err := newID("cap_")
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	in.ID = id
	in.Builtin = false
	in.Enabled = true // creation implies enabled; use PATCH to disable
	in.CreatedAt = now
	in.UpdatedAt = now
	if in.Params == nil {
		in.Params = []model.CapabilityParam{}
	}
	if err := s.db.CreateCapability(r.Context(), in); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "capability.created", "ok", "info", "capability", in.ID, map[string]any{
		"capability_id": in.ID,
		"risk":          string(in.Risk),
		"builtin":       false,
	})
	s.writeData(w, http.StatusCreated, in)
}

// capabilityPatch is the partial-update body for PATCH /admin/capabilities/{id}.
type capabilityPatch struct {
	Enabled           *bool                    `json:"enabled,omitempty"`
	Description       *string                  `json:"description,omitempty"`
	DefaultTTLSeconds *int                     `json:"default_ttl_seconds,omitempty"`
	MaxTTLSeconds     *int                     `json:"max_ttl_seconds,omitempty"`
	Risk              *model.RiskTier          `json:"risk,omitempty"`
	PolicyTemplate    *string                  `json:"policy_template,omitempty"`
	Params            *[]model.CapabilityParam `json:"params,omitempty"`
}

// handleAdminUpdateCapability implements PATCH /api/v1/admin/capabilities/{id}.
func (s *Server) handleAdminUpdateCapability(w http.ResponseWriter, r *http.Request) {
	var in capabilityPatch
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	capability, err := s.db.GetCapability(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "capability not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	if capability.Builtin && (in.Risk != nil || in.PolicyTemplate != nil || in.Params != nil) {
		s.badRequest(w, "risk, policy_template and params of builtin capabilities cannot be modified")
		return
	}
	changed := make([]string, 0, 4)
	if in.Description != nil && capability.Description != *in.Description {
		capability.Description = *in.Description
		changed = append(changed, "description")
	}
	if in.Enabled != nil && capability.Enabled != *in.Enabled {
		capability.Enabled = *in.Enabled
		changed = append(changed, "enabled")
	}
	if in.DefaultTTLSeconds != nil {
		capability.DefaultTTLSeconds = *in.DefaultTTLSeconds
		changed = append(changed, "default_ttl_seconds")
	}
	if in.MaxTTLSeconds != nil {
		capability.MaxTTLSeconds = *in.MaxTTLSeconds
		changed = append(changed, "max_ttl_seconds")
	}
	if in.Risk != nil {
		capability.Risk = *in.Risk
		changed = append(changed, "risk")
	}
	if in.PolicyTemplate != nil {
		capability.PolicyTemplate = *in.PolicyTemplate
		changed = append(changed, "policy_template")
	}
	if in.Params != nil {
		capability.Params = *in.Params
		changed = append(changed, "params")
	}
	settings, err := s.db.GetPolicySettings(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if err := validateCapabilityDefinition(capability, settings); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	capability.UpdatedAt = s.nowUTC()
	if err := s.db.UpdateCapability(r.Context(), capability); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "capability.updated", "ok", "info", "capability", capability.ID, map[string]any{
		"changed_fields": changed,
	})
	s.writeData(w, http.StatusOK, capability)
}

// validateCapabilityDefinition enforces CONTRACT §4 capability validation.
func validateCapabilityDefinition(c model.Capability, settings model.PolicySettings) error {
	if !c.ProviderType.Valid() {
		return fmt.Errorf("provider_type must be aliyun")
	}
	if !c.Risk.Valid() {
		return fmt.Errorf("risk %q is not a valid risk tier", c.Risk)
	}
	if c.DefaultTTLSeconds <= 0 {
		return fmt.Errorf("default_ttl_seconds must be positive")
	}
	if c.DefaultTTLSeconds > c.MaxTTLSeconds {
		return fmt.Errorf("default_ttl_seconds must not exceed max_ttl_seconds")
	}
	if c.MaxTTLSeconds > settings.MaxLeaseTTLSeconds {
		return fmt.Errorf("max_ttl_seconds must not exceed the global maximum %d", settings.MaxLeaseTTLSeconds)
	}
	if _, err := renderSamplePolicy(c); err != nil {
		return err
	}
	return nil
}

// sampleParamValue returns a safe sample value for a declared parameter.
func sampleParamValue(p model.CapabilityParam) string {
	candidates := []string{"sample"}
	switch p.Name {
	case "domain":
		candidates = append(candidates, "example.com")
	case "instance_id":
		candidates = append(candidates, "i-sample123")
	}
	for _, candidate := range candidates {
		if p.Pattern == "" {
			return candidate
		}
		if re, err := regexp.Compile(p.Pattern); err == nil && re.MatchString(candidate) {
			return candidate
		}
	}
	return candidates[0]
}

// renderSamplePolicy renders the policy template with sample params and
// requires the result to be valid JSON.
func renderSamplePolicy(c model.Capability) ([]byte, error) {
	samples := make(map[string]string, len(c.Params))
	for _, p := range c.Params {
		samples[p.Name] = sampleParamValue(p)
	}
	rendered, err := capcatalog.RenderPolicy(c, samples)
	if err != nil {
		return nil, fmt.Errorf("policy_template is not valid: %v", err)
	}
	if !json.Valid(rendered) {
		return nil, fmt.Errorf("policy_template does not render to valid JSON")
	}
	return rendered, nil
}

// ================= agents =================

// handleAdminListAgents implements GET /api/v1/admin/agents.
func (s *Server) handleAdminListAgents(w http.ResponseWriter, r *http.Request) {
	items, err := s.db.ListAgents(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	writeList(s, w, http.StatusOK, items, len(items))
}

// validateGrants checks that every granted capability exists and dedupes IDs.
func (s *Server) validateGrants(ctx context.Context, grants []string) ([]string, error) {
	out := make([]string, 0, len(grants))
	seen := make(map[string]bool, len(grants))
	for _, grant := range grants {
		grant = strings.TrimSpace(grant)
		if grant == "" {
			return nil, errBadRequestAPI("granted capability ids must not be empty")
		}
		if seen[grant] {
			continue
		}
		if _, err := s.db.GetCapability(ctx, grant); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, errBadRequestAPI("unknown capability " + grant)
			}
			return nil, err
		}
		seen[grant] = true
		out = append(out, grant)
	}
	return out, nil
}

// handleAdminCreateAgent implements POST /api/v1/admin/agents.
func (s *Server) handleAdminCreateAgent(w http.ResponseWriter, r *http.Request) {
	var in model.CreateAgentInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		s.badRequest(w, "name is required")
		return
	}
	settings, err := s.db.GetPolicySettings(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	grants, err := s.validateGrants(r.Context(), in.Grants)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	maxTTL := in.MaxTTLSeconds
	if maxTTL == 0 {
		maxTTL = settings.MaxLeaseTTLSeconds
	}
	if maxTTL < 0 {
		s.badRequest(w, "max_ttl_seconds must be positive")
		return
	}
	maxConcurrent := in.MaxConcurrentLeases
	if maxConcurrent == 0 {
		maxConcurrent = settings.MaxConcurrentLeasesPerAgent
	}
	if maxConcurrent < 0 {
		s.badRequest(w, "max_concurrent_leases must be positive")
		return
	}
	now := s.nowUTC()
	id, err := newID("agt_")
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	plainToken, tokenHash, err := token.Generate(token.AgentPrefix)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	ag := model.Agent{
		ID:                  id,
		Name:                in.Name,
		Description:         in.Description,
		Status:              model.AgentActive,
		Grants:              grants,
		MaxTTLSeconds:       maxTTL,
		MaxConcurrentLeases: maxConcurrent,
		TokenPrefix:         token.DisplayPrefix(plainToken),
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.db.CreateAgent(r.Context(), ag, tokenHash); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "agent.created", "ok", "info", "agent", ag.ID, map[string]any{
		"agent_id": ag.ID,
		"grants":   grants,
	})
	s.writeData(w, http.StatusCreated, model.AgentWithToken{Agent: ag, Token: plainToken})
}

// handleAdminGetAgent implements GET /api/v1/admin/agents/{id}.
func (s *Server) handleAdminGetAgent(w http.ResponseWriter, r *http.Request) {
	ag, err := s.db.GetAgent(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "agent not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, ag)
}

// handleAdminUpdateAgent implements PATCH /api/v1/admin/agents/{id}.
func (s *Server) handleAdminUpdateAgent(w http.ResponseWriter, r *http.Request) {
	var in model.UpdateAgentInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	ag, err := s.db.GetAgent(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "agent not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	changed := make([]string, 0, 6)
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		if name == "" {
			s.badRequest(w, "name must not be empty")
			return
		}
		if ag.Name != name {
			ag.Name = name
			changed = append(changed, "name")
		}
	}
	if in.Description != nil && ag.Description != *in.Description {
		ag.Description = *in.Description
		changed = append(changed, "description")
	}
	if in.Grants != nil {
		grants, err := s.validateGrants(r.Context(), *in.Grants)
		if err != nil {
			s.writeHandlerError(w, err)
			return
		}
		ag.Grants = grants
		changed = append(changed, "grants")
	}
	if in.MaxTTLSeconds != nil {
		if *in.MaxTTLSeconds <= 0 {
			s.badRequest(w, "max_ttl_seconds must be positive")
			return
		}
		ag.MaxTTLSeconds = *in.MaxTTLSeconds
		changed = append(changed, "max_ttl_seconds")
	}
	if in.MaxConcurrentLeases != nil {
		if *in.MaxConcurrentLeases <= 0 {
			s.badRequest(w, "max_concurrent_leases must be positive")
			return
		}
		ag.MaxConcurrentLeases = *in.MaxConcurrentLeases
		changed = append(changed, "max_concurrent_leases")
	}
	if in.Status != nil {
		if *in.Status != model.AgentActive && *in.Status != model.AgentSuspended && *in.Status != model.AgentRevoked {
			s.badRequest(w, "status must be active, suspended or revoked")
			return
		}
		if ag.Status != *in.Status {
			ag.Status = *in.Status
			changed = append(changed, "status")
		}
	}
	ag.UpdatedAt = s.nowUTC()
	if err := s.db.UpdateAgent(r.Context(), ag); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "agent.updated", "ok", "info", "agent", ag.ID, map[string]any{
		"changed_fields": changed,
	})
	s.writeData(w, http.StatusOK, ag)
}

// handleAdminSuspendAgent implements POST /api/v1/admin/agents/{id}/suspend.
func (s *Server) handleAdminSuspendAgent(w http.ResponseWriter, r *http.Request) {
	s.setAgentStatus(w, r, model.AgentSuspended, "agent.suspended")
}

// handleAdminActivateAgent implements POST /api/v1/admin/agents/{id}/activate.
func (s *Server) handleAdminActivateAgent(w http.ResponseWriter, r *http.Request) {
	s.setAgentStatus(w, r, model.AgentActive, "agent.activated")
}

// setAgentStatus updates an agent's lifecycle status and audits it.
func (s *Server) setAgentStatus(w http.ResponseWriter, r *http.Request, status model.AgentStatus, action string) {
	ag, err := s.db.GetAgent(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "agent not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	ag.Status = status
	ag.UpdatedAt = s.nowUTC()
	if err := s.db.UpdateAgent(r.Context(), ag); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), action, "ok", "info", "agent", ag.ID, map[string]any{
		"agent_id": ag.ID,
		"status":   string(status),
	})
	s.writeData(w, http.StatusOK, ag)
}

// handleAdminRotateAgentToken implements POST /api/v1/admin/agents/{id}/token/rotate.
func (s *Server) handleAdminRotateAgentToken(w http.ResponseWriter, r *http.Request) {
	ag, err := s.db.GetAgent(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "agent not found")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	plainToken, tokenHash, err := token.Generate(token.AgentPrefix)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	ag.TokenPrefix = token.DisplayPrefix(plainToken)
	ag.UpdatedAt = s.nowUTC()
	if err := s.db.UpdateAgent(r.Context(), ag); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if err := s.db.UpdateAgentTokenHash(r.Context(), ag.ID, tokenHash); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "agent.token_rotated", "ok", "warning", "agent", ag.ID, map[string]any{
		"agent_id":     ag.ID,
		"token_prefix": ag.TokenPrefix,
	})
	s.writeData(w, http.StatusOK, model.AgentWithToken{Agent: ag, Token: plainToken})
}

// ================= audit =================

// handleAdminListAudit implements GET /api/v1/admin/audit.
func (s *Server) handleAdminListAudit(w http.ResponseWriter, r *http.Request) {
	since, err := timeQuery(r, "since")
	if err != nil {
		s.badRequest(w, err.Error())
		return
	}
	limit, offset, err := limitOffset(r)
	if err != nil {
		s.badRequest(w, err.Error())
		return
	}
	items, total, err := s.db.ListAudit(r.Context(), store.AuditFilter{
		Action:    r.URL.Query().Get("action"),
		ActorType: r.URL.Query().Get("actor_type"),
		ActorID:   r.URL.Query().Get("actor_id"),
		Severity:  r.URL.Query().Get("severity"),
		Since:     since,
		Limit:     limit,
		Offset:    offset,
	})
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	writeList(s, w, http.StatusOK, items, total)
}

// handleAdminVerifyAudit implements GET /api/v1/admin/audit/verify.
func (s *Server) handleAdminVerifyAudit(w http.ResponseWriter, r *http.Request) {
	result, err := s.db.VerifyAudit(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, result)
}

// ================= policy =================

// handleAdminGetPolicy implements GET /api/v1/admin/policy.
func (s *Server) handleAdminGetPolicy(w http.ResponseWriter, r *http.Request) {
	settings, err := s.db.GetPolicySettings(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, settings)
}

// handleAdminPutPolicy implements PUT /api/v1/admin/policy.
func (s *Server) handleAdminPutPolicy(w http.ResponseWriter, r *http.Request) {
	var in model.PolicySettings
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	if err := in.Validate(); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	before, err := s.db.GetPolicySettings(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if err := s.db.SetPolicySettings(r.Context(), in); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.adminAudit(r.Context(), "policy.updated", "ok", "warning", "policy", "policy", map[string]any{
		"before": before,
		"after":  in,
	})
	s.writeData(w, http.StatusOK, in)
}

// ================= helpers =================

// randomHexUpper returns n random bytes as uppercase hex (2n chars).
func randomHexUpper(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return strings.ToUpper(hex.EncodeToString(buf)), nil
}

// randomBase64URL returns n random bytes in raw URL-safe base64.
func randomBase64URL(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
