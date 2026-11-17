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
	"strings"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// ================= cloud accounts =================

// handleListAccounts implements GET /api/v1/supervisor/accounts.
func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	items, err := s.db.ListProviders(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	writeList(s, w, http.StatusOK, items, len(items))
}

// handleCreateAccount implements POST /api/v1/supervisor/accounts.
func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
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

	// Roles and requests are bound to the cloud account the role lives in; an
	// account without one could never issue anything.
	if model.CloudAccountIDFromRoleARN(in.Type, in.RoleARN) == "" {
		s.badRequest(w, "role_arn must be a RAM role ARN such as acs:ram::1234567890123456:role/cloud-safeguard")
		return
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
		CloudAccountID:    model.CloudAccountIDFromRoleARN(in.Type, in.RoleARN),
		MaxAutoLevel:      model.ModeRead,
		AccessKeyIDMasked: maskAccessKeyID(in.AccessKeyID),
		Status:            model.ProviderActive,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.db.CreateProvider(r.Context(), prov, encrypted); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict,
				"cloud account "+prov.CloudAccountID+" is already connected")
			return
		}
		s.writeHandlerError(w, err)
		return
	}
	s.actorAudit(r.Context(), "provider.created", "ok", "info", "provider", prov.ID, map[string]any{
		"provider_id":          prov.ID,
		"name":                 prov.Name,
		"mode":                 string(prov.Mode),
		"access_key_id_masked": prov.AccessKeyIDMasked,
	})
	s.writeData(w, http.StatusCreated, prov)
}

// handleGetAccount implements GET /api/v1/supervisor/accounts/{id}.
func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
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

// handleUpdateAccount implements PATCH /api/v1/supervisor/accounts/{id}.
func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	var in model.UpdateProviderInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	// Only disabling or renaming lowers nothing else; any other change of a
	// cloud account (its role, its region, enabling it) may raise access.
	if in.RoleARN != nil || in.Region != nil || (in.Status != nil && *in.Status != model.ProviderDisabled) {
		if !s.stepUp(w, r) {
			return
		}
	}
	// One edit of cloud accounts at a time (single process per data dir):
	// the account is read, checked and written under this lock, so two edits
	// cannot each write a row based on what the other has since changed.
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()
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
	values := map[string]any{}
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
			values["region"] = map[string]string{"from": prov.Region, "to": region}
			prov.Region = region
			changed = append(changed, "region")
		}
	}
	if in.RoleARN != nil && prov.RoleARN != *in.RoleARN {
		// People's roles are bound to this provider. Pointing it at a role in
		// another cloud account would silently move those roles there.
		account := model.CloudAccountIDFromRoleARN(prov.Type, *in.RoleARN)
		switch {
		case account == "":
			s.badRequest(w, "role_arn must be a RAM role ARN such as acs:ram::1234567890123456:role/cloud-safeguard")
			return
		case prov.CloudAccountID == "":
			// Left without a cloud account by an upgrade (its role ARN was
			// not a role, or another provider already had the account). It
			// cannot issue anything until it gets one; the unique index
			// refuses an account that is already connected.
			removed, err := s.db.AdoptProviderCloudAccountID(r.Context(), prov.ID, *in.RoleARN, account, s.nowUTC())
			if err != nil {
				if errors.Is(err, store.ErrConflict) {
					s.actorAudit(r.Context(), "provider.update_refused", "denied", "warning", "provider", prov.ID, map[string]any{
						"reason": "cloud account already connected", "cloud_account_id": account,
					})
					s.writeError(w, http.StatusConflict, model.ErrCodeConflict,
						"cloud account "+account+" is already connected; nothing was changed. Disable this duplicate instead")
					return
				}
				s.writeHandlerError(w, err)
				return
			}
			// Roles given on it while it had no account did nothing, and the
			// store removed them with the adoption: say whose.
			gone := make([]map[string]string, 0, len(removed))
			for _, b := range removed {
				entry := map[string]string{"person_id": b.PersonID, "role": string(b.Role)}
				if person, err := s.db.GetPerson(r.Context(), b.PersonID); err == nil {
					entry["username"] = person.Username
				}
				gone = append(gone, entry)
			}
			values["removed_role_bindings"] = gone
			prov.CloudAccountID = account
			values["cloud_account_id"] = map[string]string{"from": "", "to": account}
			changed = append(changed, "cloud_account_id")
		case account != prov.CloudAccountID:
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict,
				"role_arn must stay in the same cloud account; connect the other account as a new provider")
			return
		}
		values["role_arn"] = map[string]string{"from": prov.RoleARN, "to": *in.RoleARN}
		prov.RoleARN = *in.RoleARN
		changed = append(changed, "role_arn")
	}
	if in.Status != nil {
		if *in.Status != model.ProviderActive && *in.Status != model.ProviderDisabled {
			s.badRequest(w, "status must be active or disabled")
			return
		}
		if prov.Status != *in.Status {
			values["status"] = map[string]string{"from": string(prov.Status), "to": string(*in.Status)}
			prov.Status = *in.Status
			changed = append(changed, "status")
		}
	}
	prov.UpdatedAt = s.nowUTC()
	if err := s.db.UpdateProvider(r.Context(), prov); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if s.hookAfterAuthorityWrite != nil {
		s.hookAfterAuthorityWrite("provider")
	}
	// Disabling a cloud account stops it: its pending and active leases are
	// revoked (the re-check fails on "provider is not active").
	revoked := []string{}
	if prov.Status != model.ProviderActive {
		ids, err := s.revalidateLeases(r.Context(), store.LeaseFilter{}, "provider "+prov.ID+" disabled")
		if err != nil {
			s.writeHandlerError(w, err)
			return
		}
		revoked = ids
	}
	// Repointing the role or switching an account on or off changes what
	// credentials can do: record it as a warning.
	severity := "info"
	if values["role_arn"] != nil || values["status"] != nil {
		severity = "warning"
	}
	s.actorAudit(r.Context(), "provider.updated", "ok", severity, "provider", prov.ID, map[string]any{
		"changed_fields":    changed,
		"changes":           values,
		"revoked_lease_ids": revoked,
	})
	s.writeData(w, http.StatusOK, prov)
}

// handleRotateAccount implements POST /api/v1/supervisor/accounts/{id}/rotate.
func (s *Server) handleRotateAccount(w http.ResponseWriter, r *http.Request) {
	var in model.RotateProviderCredentialInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	if strings.TrimSpace(in.AccessKeyID) == "" || in.AccessKeySecret == "" {
		s.badRequest(w, "access_key_id and access_key_secret are required")
		return
	}
	// A new AccessKey decides what every credential of the account can do.
	if !s.stepUp(w, r) {
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
	// Only the credential and its masked ID are written: a rotation must
	// never put back a status or role ARN that changed since the read above.
	oldMasked := prov.AccessKeyIDMasked
	now := s.nowUTC()
	if err := s.db.RotateProviderCredential(r.Context(), prov.ID, encrypted, maskAccessKeyID(in.AccessKeyID), now); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if prov, err = s.db.GetProvider(r.Context(), prov.ID); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.actorAudit(r.Context(), "provider.credential_rotated", "ok", "warning", "provider", prov.ID, map[string]any{
		"provider_id":        prov.ID,
		"old_masked_ak":      oldMasked,
		"new_masked_ak":      prov.AccessKeyIDMasked,
		"access_key_id_mask": prov.AccessKeyIDMasked,
	})
	s.writeData(w, http.StatusOK, prov)
}

// providerTestResult is the success payload of POST /supervisor/accounts/{id}/test.
type providerTestResult struct {
	OK       bool      `json:"ok"`
	Message  string    `json:"message"`
	TestedAt time.Time `json:"tested_at"`
}

// handleTestAccount implements POST /api/v1/supervisor/accounts/{id}/test.
func (s *Server) handleTestAccount(w http.ResponseWriter, r *http.Request) {
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
	// The test can take seconds. Only its result is written: writing the row
	// read before it would undo a disable that happened meanwhile.
	if err := s.db.SetProviderTestResult(r.Context(), prov.ID, now, ok); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.actorAudit(r.Context(), "provider.tested", "ok", "info", "provider", prov.ID, map[string]any{
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

// ================= audit =================

// handleListAudit implements GET /api/v1/supervisor/audit.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
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

// handleVerifyAudit implements GET /api/v1/supervisor/audit/verify.
func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	result, err := s.db.VerifyAudit(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, result)
}

// ================= policy =================

// handleGetSettings implements GET /api/v1/supervisor/settings.
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.db.GetPolicySettings(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, settings)
}

// handlePutSettings implements PUT /api/v1/supervisor/settings.
func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
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
	// Lowering every limit lowers access; anything else may raise it.
	if !(in.MaxLeaseTTLSeconds <= before.MaxLeaseTTLSeconds && in.PendingTimeoutSeconds <= before.PendingTimeoutSeconds &&
		in.MaxConcurrentLeasesPerAgent <= before.MaxConcurrentLeasesPerAgent && in.LeasesPerMinutePerAgent <= before.LeasesPerMinutePerAgent) {
		if !s.stepUp(w, r) {
			return
		}
	}
	before, err = s.db.GetPolicySettings(r.Context())
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if err := s.db.SetPolicySettings(r.Context(), in); err != nil {
		s.writeHandlerError(w, err)
		return
	}
	// A lower global TTL ceiling applies to pending and active leases too.
	revoked, err := s.revalidateLeases(r.Context(), store.LeaseFilter{}, "policy settings changed")
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.actorAudit(r.Context(), "policy.updated", "ok", "warning", "policy", "policy", map[string]any{
		"before":            before,
		"after":             in,
		"revoked_lease_ids": revoked,
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
