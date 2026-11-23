package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/capcatalog"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// Long-lived credentials (CONTRACT §17.14).

const (
	// longLivedLinkTTL is how long a request's console link works.
	longLivedLinkTTL = time.Hour
	// maxPendingLongLived bounds the requests one person has waiting.
	maxPendingLongLived = 10
	// longLivedLinkPrefix is the console path a link opens.
	longLivedLinkPrefix = "/?long-lived="
)

var (
	longLivedKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)
	longLivedIDRE  = regexp.MustCompile(`^llc_[0-9a-f]{32}$`)
)

func defaultUserAdminFactory(p model.Provider) (provider.UserAdmin, error) {
	return provider.NewUserAdmin(p.Type, p.Mode)
}

// longLivedTarget is a checked request: the account, the template and the
// resource name.
type longLivedTarget struct {
	prov     model.Provider
	template capcatalog.AccessTemplate
	name     string
}

// parseLongLived checks the fields of a request (§17.4 rules, plus a reason).
func (s *Server) parseLongLived(ctx context.Context, ownerID string, in model.LongLivedRequestInput) (longLivedTarget, error) {
	accountID := strings.TrimSpace(in.CloudAccountID)
	resource := strings.TrimSpace(in.Resource)
	permission := capcatalog.Permission(strings.TrimSpace(in.Permission))
	if accountID == "" || resource == "" {
		return longLivedTarget{}, errBadRequestAPI("cloud_account_id and resource are required")
	}
	if !permission.Valid() {
		return longLivedTarget{}, errBadRequestAPI("permission must be read, write or full")
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" || !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > maxReasonLength {
		return longLivedTarget{}, errBadRequestAPI(fmt.Sprintf("reason is required, at most %d characters; it is shown to the person who confirms", maxReasonLength))
	}
	// An unknown account and one without a role look the same, and both
	// are answered before the resource is looked at: no probing.
	noRole := &httpError{status: http.StatusForbidden, code: model.ErrCodeForbidden,
		message: "no role on cloud account " + sanitizeMessage(accountID)}
	prov, err := s.db.GetProviderByCloudAccountID(ctx, accountID)
	if errors.Is(err, store.ErrNotFound) {
		return longLivedTarget{}, noRole
	}
	if err != nil {
		return longLivedTarget{}, err
	}
	if _, err := s.personRole(ctx, ownerID, prov.ID); errors.Is(err, store.ErrNotFound) {
		return longLivedTarget{}, noRole
	} else if err != nil {
		return longLivedTarget{}, err
	}
	template, ok := capcatalog.LookupAccessTemplate(prov.Type, resource, permission)
	if !ok {
		return longLivedTarget{}, errBadRequestAPI("unknown resource " + sanitizeMessage(resource) +
			"; available: " + strings.Join(capcatalog.AccessResources(prov.Type), ", "))
	}
	name := strings.TrimSpace(in.ResourceName)
	if name == "" {
		name = capcatalog.AllResources
	} else if name == capcatalog.AllResources || len(name) > maxResourceNameLength {
		return longLivedTarget{}, errBadRequestAPI("resource_name must be one resource; leave it out for all")
	}
	if err := capcatalog.ValidateParams(template.Capability, map[string]string{capcatalog.ResourceNameParam: name}); err != nil {
		return longLivedTarget{}, errBadRequestAPI("resource_name must be " + capcatalog.ResourceNameHint(prov.Type, resource))
	}
	return longLivedTarget{prov: prov, template: template, name: name}, nil
}

// longLivedProblem is why a person may not hold this credential now, or "".
// It is the single check for asking, creating and keeping one.
func (s *Server) longLivedProblem(ctx context.Context, personID, providerID, capabilityID, resourceName string) (string, error) {
	person, err := s.db.GetPerson(ctx, personID)
	if errors.Is(err, store.ErrNotFound) {
		return "the owner no longer exists", nil
	}
	if err != nil {
		return "", err
	}
	if !person.MayCreateLongLived() {
		return "the owner may not hold long-lived credentials (a supervisor allows it)", nil
	}
	prov, err := s.db.GetProvider(ctx, providerID)
	if errors.Is(err, store.ErrNotFound) {
		return "the cloud account no longer exists", nil
	}
	if err != nil {
		return "", err
	}
	if prov.Status != model.ProviderActive {
		return "the cloud account is disabled", nil
	}
	template, ok := capcatalog.AccessTemplateByID(capabilityID)
	if !ok {
		return "unknown access template", nil
	}
	role, err := s.personRole(ctx, personID, providerID)
	if errors.Is(err, store.ErrNotFound) {
		return "the owner has no role on this cloud account", nil
	}
	if err != nil {
		return "", err
	}
	if !role.Permits(template.Capability.Access) {
		return fmt.Sprintf("the owner's role %s does not permit %s access", role, template.Permission), nil
	}
	if violation := policyViolation(template.Capability, map[string]string{capcatalog.ResourceNameParam: resourceName}); violation != "" {
		return violation, nil
	}
	return "", nil
}

// createLongLivedRequest stores a pending request and returns its link.
func (s *Server) createLongLivedRequest(ctx context.Context, r *http.Request, owner model.Person, agent *model.Agent, in model.LongLivedRequestInput) (model.LongLivedRequestResult, error) {
	target, err := s.parseLongLived(ctx, owner.ID, in)
	if err != nil {
		return model.LongLivedRequestResult{}, err
	}
	if problem, err := s.longLivedProblem(ctx, owner.ID, target.prov.ID, target.template.Capability.ID, target.name); err != nil {
		return model.LongLivedRequestResult{}, err
	} else if problem != "" {
		return model.LongLivedRequestResult{}, &httpError{status: http.StatusForbidden, code: model.ErrCodeForbidden, message: problem}
	}
	if _, err := s.db.GetProviderUserAdmin(ctx, target.prov.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return model.LongLivedRequestResult{}, errConflictAPI("long-lived credentials are not enabled on this cloud account; a supervisor enables them")
		}
		return model.LongLivedRequestResult{}, err
	}
	id, err := newID("llc_")
	if err != nil {
		return model.LongLivedRequestResult{}, err
	}
	key, hash, err := authn.NewSecret(24)
	if err != nil {
		return model.LongLivedRequestResult{}, err
	}
	now := s.nowUTC()
	row := store.LongLivedRow{
		ID: id, LinkHash: hash, ProviderID: target.prov.ID, OwnerID: owner.ID, CapabilityID: target.template.Capability.ID,
		ResourceName: target.name, Reason: sanitizeMessage(strings.TrimSpace(in.Reason)), CreatedAt: now, ExpiresAt: now.Add(longLivedLinkTTL),
	}
	if agent != nil {
		row.AgentID, row.AgentName = agent.ID, agent.Name
	}
	if err := s.db.CreateLongLived(ctx, row, maxPendingLongLived); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return model.LongLivedRequestResult{}, &httpError{status: http.StatusTooManyRequests, code: model.ErrCodeRateLimited,
				message: fmt.Sprintf("%d long-lived requests are already waiting; confirm or decline them first", maxPendingLongLived)}
		}
		return model.LongLivedRequestResult{}, err
	}
	metadata := map[string]any{"cloud_account_id": target.prov.CloudAccountID, "capability": row.CapabilityID,
		"resource_name": row.ResourceName, "owner_id": owner.ID}
	if agent != nil {
		s.agentAudit(ctx, *agent, "long_lived.requested", "ok", "warning", "long_lived", id, metadata)
	} else {
		s.personAudit(ctx, owner, "long_lived.requested", "ok", "warning", "long_lived", id, metadata)
	}
	return model.LongLivedRequestResult{ID: id, Status: model.LongLivedPending,
		Link: s.expectedOrigin(r) + longLivedLinkPrefix + key, ExpiresAt: row.ExpiresAt}, nil
}

func (s *Server) handleMyLongLivedRequest(w http.ResponseWriter, r *http.Request) {
	actor, _ := sessionFromContext(r.Context())
	var in model.LongLivedRequestInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	out, err := s.createLongLivedRequest(r.Context(), r, actor.person, nil, in)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusCreated, out)
}

func (s *Server) handleAgentLongLivedRequest(w http.ResponseWriter, r *http.Request) {
	ag, _ := agentFromContext(r.Context())
	var in model.LongLivedRequestInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	if ag.OwnerID == "" {
		s.writeError(w, http.StatusForbidden, model.ErrCodeForbidden, "this agent has no owner")
		return
	}
	owner, err := s.db.GetPerson(r.Context(), ag.OwnerID)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	out, err := s.createLongLivedRequest(r.Context(), r, owner, &ag, in)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusCreated, out)
}

// longLivedView renders a stored credential for the API.
func (s *Server) longLivedView(ctx context.Context, row store.LongLivedRow, now time.Time) model.LongLivedCredential {
	v := model.LongLivedCredential{
		ID: row.ID, ProviderID: row.ProviderID, OwnerID: row.OwnerID, AgentID: row.AgentID, AgentName: row.AgentName,
		CapabilityID: row.CapabilityID, Reason: row.Reason, Status: row.Status, CloudUser: row.CloudUser,
		CloudPolicy: row.CloudPolicy, AccessKeyID: row.AccessKeyID, FailureReason: row.FailureReason,
		RevokeReason: row.RevokeReason, CreatedAt: row.CreatedAt, DecidedAt: row.DecidedAt,
		RevokedAt: row.RevokedAt,
	}
	if v.Status == model.LongLivedPending && !now.Before(row.ExpiresAt) {
		v.Status = model.LongLivedExpired
	}
	if v.Status == model.LongLivedPending || v.Status == model.LongLivedExpired {
		expires := row.ExpiresAt
		v.ExpiresAt = &expires
	}
	if row.ResourceName != capcatalog.AllResources {
		v.ResourceName = row.ResourceName
	}
	if t, ok := capcatalog.AccessTemplateByID(row.CapabilityID); ok {
		v.Resource, v.Permission = t.Resource, string(t.Permission)
	}
	if prov, err := s.db.GetProvider(ctx, row.ProviderID); err == nil {
		v.CloudAccountID, v.CloudAccountName, v.ProviderType = prov.CloudAccountID, prov.Name, prov.Type
	}
	if p, err := s.db.GetPerson(ctx, row.OwnerID); err == nil {
		v.OwnerName = p.Username
	}
	return v
}

// pendingLongLived resolves a console link for the signed-in person: to
// anyone but the owner, or once decided or expired, it does not exist.
func (s *Server) pendingLongLived(w http.ResponseWriter, r *http.Request) (store.LongLivedRow, model.Person, bool) {
	actor, _ := sessionFromContext(r.Context())
	notFound := func() (store.LongLivedRow, model.Person, bool) {
		s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "this request is unknown, already decided or expired")
		return store.LongLivedRow{}, model.Person{}, false
	}
	key := r.PathValue("key")
	if !longLivedKeyRE.MatchString(key) {
		return notFound()
	}
	row, err := s.db.GetLongLivedByLinkHash(r.Context(), authn.HashSecret(key))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.writeHandlerError(w, err)
			return store.LongLivedRow{}, model.Person{}, false
		}
		return notFound()
	}
	if row.OwnerID != actor.person.ID || row.Status != model.LongLivedPending || !s.nowUTC().Before(row.ExpiresAt) {
		return notFound()
	}
	return row, actor.person, true
}

func (s *Server) handleGetLongLivedRequest(w http.ResponseWriter, r *http.Request) {
	row, _, ok := s.pendingLongLived(w, r)
	if !ok {
		return
	}
	s.writeData(w, http.StatusOK, s.longLivedView(r.Context(), row, s.nowUTC()))
}

func (s *Server) handleDenyLongLivedRequest(w http.ResponseWriter, r *http.Request) {
	row, person, ok := s.pendingLongLived(w, r)
	if !ok {
		return
	}
	if err := s.db.DenyLongLived(r.Context(), row.ID, s.nowUTC()); err != nil {
		s.storeErrorResponse(w, err, "this request is unknown, already decided or expired")
		return
	}
	s.personAudit(r.Context(), person, "long_lived.denied", "denied", "info", "long_lived", row.ID, map[string]any{"capability": row.CapabilityID})
	updated, err := s.db.GetLongLived(r.Context(), row.ID)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, s.longLivedView(r.Context(), updated, s.nowUTC()))
}

// userAdminFor decrypts an account's second key and returns its user admin.
func (s *Server) userAdminFor(ctx context.Context, prov model.Provider) (provider.UserAdmin, brokerCredential, error) {
	enc, err := s.db.GetProviderUserAdmin(ctx, prov.ID)
	if err != nil {
		return nil, brokerCredential{}, errors.New("long-lived credentials are not enabled on this cloud account")
	}
	plain, err := s.vault.Decrypt(enc, userAdminAAD(prov.ID))
	if err != nil {
		return nil, brokerCredential{}, errors.New("the account's key for long-lived credentials cannot be decrypted")
	}
	var key brokerCredential
	if err := json.Unmarshal(plain, &key); err != nil {
		return nil, brokerCredential{}, errors.New("the account's key for long-lived credentials is malformed")
	}
	admin, err := s.userAdminFactory(prov)
	if err != nil {
		return nil, brokerCredential{}, err
	}
	return admin, key, nil
}

func userAdminAAD(providerID string) string { return "provider/" + providerID + "/user-admin" }

// handleCreateLongLived confirms a request: the cloud user, policy and key
// are created, and the secret is answered once.
func (s *Server) handleCreateLongLived(w http.ResponseWriter, r *http.Request) {
	row, person, ok := s.pendingLongLived(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	now := s.nowUTC()
	if err := s.db.ClaimLongLivedForCreate(ctx, row.ID, now); err != nil {
		s.storeErrorResponse(w, err, "this request is unknown, already decided or expired")
		return
	}
	fail := func(status int, reason string) {
		if err := s.db.SetLongLivedFailed(ctx, row.ID, sanitizeMessage(reason), s.nowUTC()); err != nil {
			s.logf("long-lived %s: record failure: %v", row.ID, err)
		}
		s.personAudit(ctx, person, "long_lived.create_failed", "failed", "warning", "long_lived", row.ID,
			map[string]any{"reason": sanitizeMessage(reason)})
		s.writeError(w, status, model.ErrCodeConflict, sanitizeMessage(reason))
	}
	// Everything again, now.
	if problem, err := s.longLivedProblem(ctx, row.OwnerID, row.ProviderID, row.CapabilityID, row.ResourceName); err != nil {
		fail(http.StatusInternalServerError, "internal error")
		return
	} else if problem != "" {
		fail(http.StatusConflict, problem)
		return
	}
	prov, err := s.db.GetProvider(ctx, row.ProviderID)
	if err != nil {
		fail(http.StatusConflict, "the cloud account no longer exists")
		return
	}
	template, _ := capcatalog.AccessTemplateByID(row.CapabilityID)
	policyJSON, err := capcatalog.RenderPolicy(template.Capability, map[string]string{capcatalog.ResourceNameParam: row.ResourceName})
	if err != nil {
		fail(http.StatusConflict, "the policy cannot be rendered: "+err.Error())
		return
	}
	admin, key, err := s.userAdminFor(ctx, prov)
	if err != nil {
		fail(http.StatusConflict, err.Error())
		return
	}
	created, err := admin.CreateUser(ctx, provider.UserRequest{
		Provider: prov, AdminAccessKeyID: key.AccessKeyID, AdminAccessKeySecret: key.AccessKeySecret,
		CredentialID: row.ID, PolicyJSON: policyJSON, SigningKey: s.signingKey,
	})
	if errors.Is(err, provider.ErrCleanupFailed) {
		// Something may be left in the cloud: never show it as gone.
		reason := sanitizeMessage("the cloud did not create the credential, and deleting what was made failed: " + err.Error())
		s.needsDeletion(ctx, row.ID, reason)
		s.personAudit(ctx, person, "long_lived.create_failed", "failed", "critical", "long_lived", row.ID,
			map[string]any{"reason": reason, "cloud_user": provider.CloudUserName(row.ID), "cleanup_failed": true})
		s.writeError(w, http.StatusBadGateway, model.ErrCodeConflict, reason+" A supervisor can retry the deletion.")
		return
	}
	if err != nil {
		fail(http.StatusBadGateway, "the cloud did not create the credential: "+err.Error())
		return
	}
	if err := s.db.SetLongLivedActive(ctx, row.ID, created.UserName, created.PolicyName, created.AccessKeyID, s.nowUTC()); err != nil {
		// Not recorded: delete what was created rather than leave a key
		// nobody tracks; if that fails too, keep it named for a retry.
		if derr := admin.DeleteUser(ctx, provider.UserRequest{Provider: prov, AdminAccessKeyID: key.AccessKeyID, AdminAccessKeySecret: key.AccessKeySecret,
			CredentialID: row.ID, UserName: created.UserName, PolicyName: created.PolicyName}); derr != nil {
			s.needsDeletion(ctx, row.ID, "recording the credential failed, and deleting it failed: "+derr.Error())
		} else if ferr := s.db.SetLongLivedFailed(ctx, row.ID, "recording the credential failed; it was deleted", s.nowUTC()); ferr != nil {
			s.logf("long-lived %s: record failure: %v", row.ID, ferr)
		}
		s.writeHandlerError(w, err)
		return
	}
	// The right may have gone while the cloud calls ran (an automatic
	// deletion skips a credential that is still being created): check again
	// and delete it before the secret is shown.
	if problem, err := s.longLivedProblem(ctx, row.OwnerID, row.ProviderID, row.CapabilityID, row.ResourceName); err != nil || problem != "" {
		if err != nil {
			problem = "the permission could not be checked again"
		}
		if active, gerr := s.db.GetLongLived(ctx, row.ID); gerr == nil {
			if _, rerr := s.revokeLongLived(ctx, active, "automatic: "+problem, nil, map[string]any{"cause": "changed_while_creating"}); rerr != nil {
				s.logf("revoke long-lived %s: %v", row.ID, rerr)
			}
		}
		s.writeError(w, http.StatusConflict, model.ErrCodeConflict, sanitizeMessage(problem+"; the credential was deleted again"))
		return
	}
	s.personAudit(ctx, person, "long_lived.created", "ok", "critical", "long_lived", row.ID, map[string]any{
		"cloud_account_id": prov.CloudAccountID, "capability": row.CapabilityID, "resource_name": row.ResourceName,
		"cloud_user": created.UserName, "access_key_id": maskAccessKeyID(created.AccessKeyID), "agent_id": row.AgentID,
	})
	updated, err := s.db.GetLongLived(ctx, row.ID)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	env := []model.EnvVar{
		{Name: "ALIBABA_CLOUD_ACCESS_KEY_ID", Value: created.AccessKeyID},
		{Name: "ALIBABA_CLOUD_ACCESS_KEY_SECRET", Value: created.AccessKeySecret},
	}
	if prov.Type == model.ProviderAWS {
		env = []model.EnvVar{
			{Name: "AWS_ACCESS_KEY_ID", Value: created.AccessKeyID},
			{Name: "AWS_SECRET_ACCESS_KEY", Value: created.AccessKeySecret},
		}
	}
	s.writeData(w, http.StatusOK, model.LongLivedSecret{
		Credential: s.longLivedView(ctx, updated, s.nowUTC()), AccessKeyID: created.AccessKeyID,
		AccessKeySecret: created.AccessKeySecret, Env: env,
	})
}

// needsDeletion marks a credential that may exist in the cloud as
// revoke_failed, named after its ID, so its deletion can be retried.
func (s *Server) needsDeletion(ctx context.Context, id, reason string) {
	name := provider.CloudUserName(id)
	if err := s.db.SetLongLivedNeedsDeletion(ctx, id, name, name, sanitizeMessage(reason), s.nowUTC()); err != nil {
		s.logf("long-lived %s: mark for deletion: %v", id, err)
	}
}

// interruptedLongLived marks credentials left creating or revoking by a
// crash as revoke_failed and returns them; recoverLongLived deletes them.
// Run once at startup, before anything can be creating in this process.
func (s *Server) interruptedLongLived(ctx context.Context) ([]string, error) {
	rows, err := s.db.ListLongLived(ctx, store.LongLivedFilter{
		Statuses: []model.LongLivedStatus{model.LongLivedCreating, model.LongLivedRevoking}})
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(rows))
	for _, row := range rows {
		s.needsDeletion(ctx, row.ID, "interrupted while "+map[model.LongLivedStatus]string{
			model.LongLivedCreating: "creating", model.LongLivedRevoking: "deleting"}[row.Status]+"; deleted to be sure")
		ids = append(ids, row.ID)
	}
	return ids, nil
}

// recoverLongLived deletes the interrupted credentials, then deletes every
// credential whose owner lost the right while the server was down.
func (s *Server) recoverLongLived(ctx context.Context, interrupted []string) {
	cause := map[string]any{"cause": "startup_check", "caused_by": "startup check"}
	for _, id := range interrupted {
		row, err := s.db.GetLongLived(ctx, id)
		if err != nil || row.Status != model.LongLivedRevokeFailed {
			continue
		}
		if _, err := s.revokeLongLived(ctx, row, "automatic: interrupted", nil, cause); err != nil {
			s.logf("revoke long-lived %s: %v", id, err)
		}
	}
	s.revokeLongLivedNoLongerAllowed(ctx, "", "", cause)
}

// revokeLongLived deletes a credential in the cloud and records the outcome.
// cause is merged into the audit event.
func (s *Server) revokeLongLived(ctx context.Context, row store.LongLivedRow, reason string, actor *model.Person, cause map[string]any) (store.LongLivedRow, error) {
	now := s.nowUTC()
	if err := s.db.ClaimLongLivedForRevoke(ctx, row.ID, sanitizeMessage(reason), now); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return store.LongLivedRow{}, errConflictAPI("this credential is not active")
		}
		return store.LongLivedRow{}, err
	}
	failure := ""
	prov, err := s.db.GetProvider(ctx, row.ProviderID)
	if err != nil {
		failure = "the cloud account cannot be read"
	} else if admin, key, err := s.userAdminFor(ctx, prov); err != nil {
		failure = err.Error()
	} else if err := admin.DeleteUser(ctx, provider.UserRequest{Provider: prov, AdminAccessKeyID: key.AccessKeyID,
		AdminAccessKeySecret: key.AccessKeySecret, CredentialID: row.ID, UserName: row.CloudUser,
		PolicyName: row.CloudPolicy, AccessKeyID: row.AccessKeyID}); err != nil {
		failure = "the cloud did not delete it: " + err.Error()
	}
	if err := s.db.FinishLongLivedRevoke(ctx, row.ID, sanitizeMessage(failure), s.nowUTC()); err != nil {
		return store.LongLivedRow{}, err
	}
	metadata := map[string]any{"reason": sanitizeMessage(reason), "cloud_user": row.CloudUser, "owner_id": row.OwnerID,
		"access_key_id": maskAccessKeyID(row.AccessKeyID)}
	for k, v := range cause {
		metadata[k] = v
	}
	action, status := "long_lived.revoked", "ok"
	if failure != "" {
		action, status = "long_lived.revoke_failed", "failed"
		metadata["failure"] = sanitizeMessage(failure)
	}
	if actor != nil {
		s.personAudit(ctx, *actor, action, status, "critical", "long_lived", row.ID, metadata)
	} else {
		s.systemAudit(ctx, action, status, "critical", "long_lived", row.ID, metadata)
	}
	return s.db.GetLongLived(ctx, row.ID)
}

// revokeLongLivedNoLongerAllowed deletes the credentials of a person (on one
// account, or all when providerID is empty) that they may no longer hold.
func (s *Server) revokeLongLivedNoLongerAllowed(ctx context.Context, personID, providerID string, cause map[string]any) []string {
	return s.revokeLongLivedIn(ctx, personID, providerID, cause, model.LongLivedActive, model.LongLivedRevokeFailed)
}

// revokeLongLivedIn is revokeLongLivedNoLongerAllowed over the given statuses.
func (s *Server) revokeLongLivedIn(ctx context.Context, personID, providerID string, cause map[string]any, statuses ...model.LongLivedStatus) []string {
	rows, err := s.db.ListLongLived(ctx, store.LongLivedFilter{OwnerID: personID, ProviderID: providerID, Statuses: statuses})
	if err != nil {
		s.logf("list long-lived credentials of %s: %v", personID, err)
		return nil
	}
	var revoked []string
	for _, row := range rows {
		problem, err := s.longLivedProblem(ctx, row.OwnerID, row.ProviderID, row.CapabilityID, row.ResourceName)
		if err != nil {
			s.logf("long-lived %s: check the owner's right: %v", row.ID, err)
			continue
		}
		if problem == "" {
			continue
		}
		if _, err := s.revokeLongLived(ctx, row, "automatic: "+problem, nil, cause); err != nil {
			s.logf("revoke long-lived %s: %v", row.ID, err)
			continue
		}
		revoked = append(revoked, row.ID)
	}
	return revoked
}

// revokeLongLivedOfAccount deletes every credential of a disabled account.
func (s *Server) revokeLongLivedOfAccount(ctx context.Context, providerID string, cause map[string]any) {
	rows, err := s.db.ListLongLived(ctx, store.LongLivedFilter{ProviderID: providerID,
		Statuses: []model.LongLivedStatus{model.LongLivedActive, model.LongLivedRevokeFailed}})
	if err != nil {
		s.logf("list long-lived credentials of %s: %v", providerID, err)
		return
	}
	for _, row := range rows {
		if _, err := s.revokeLongLived(ctx, row, "automatic: the cloud account was disabled", nil, cause); err != nil {
			s.logf("revoke long-lived %s: %v", row.ID, err)
		}
	}
}

func (s *Server) listLongLived(w http.ResponseWriter, r *http.Request, f store.LongLivedFilter) {
	rows, err := s.db.ListLongLived(r.Context(), f)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	now := s.nowUTC()
	out := make([]model.LongLivedCredential, 0, len(rows))
	for _, row := range rows {
		out = append(out, s.longLivedView(r.Context(), row, now))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	writeList(s, w, http.StatusOK, out, len(out))
}

func (s *Server) handleListMyLongLived(w http.ResponseWriter, r *http.Request) {
	actor, _ := sessionFromContext(r.Context())
	s.listLongLived(w, r, store.LongLivedFilter{OwnerID: actor.person.ID})
}

func (s *Server) handleListAllLongLived(w http.ResponseWriter, r *http.Request) {
	s.listLongLived(w, r, store.LongLivedFilter{})
}

// handleRevokeLongLived revokes as the owner (mine=true) or as a supervisor.
func (s *Server) handleRevokeLongLived(mine bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		actor, _ := sessionFromContext(r.Context())
		id := r.PathValue("id")
		row, err := s.db.GetLongLived(r.Context(), id)
		if !longLivedIDRE.MatchString(id) || errors.Is(err, store.ErrNotFound) || (err == nil && mine && row.OwnerID != actor.person.ID) {
			s.writeError(w, http.StatusNotFound, model.ErrCodeNotFound, "credential not found")
			return
		}
		if err != nil {
			s.writeHandlerError(w, err)
			return
		}
		reason := "revoked by its owner"
		if !mine {
			reason = "revoked by a supervisor"
		}
		updated, err := s.revokeLongLived(r.Context(), row, reason, &actor.person, map[string]any{"caused_by": "person:" + actor.person.ID})
		if err != nil {
			s.writeHandlerError(w, err)
			return
		}
		s.writeData(w, http.StatusOK, s.longLivedView(r.Context(), updated, s.nowUTC()))
	}
}

// handleSetUserAdmin enables long-lived credentials on an account: the second
// key is tested, then stored encrypted.
func (s *Server) handleSetUserAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in model.SetUserAdminKeyInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, "invalid request body: "+err.Error())
		return
	}
	prov, err := s.db.GetProvider(ctx, r.PathValue("provider"))
	if err != nil {
		s.storeErrorResponse(w, err, "cloud account not found")
		return
	}
	keyID, secret := strings.TrimSpace(in.AccessKeyID), in.AccessKeySecret
	if prov.Mode == model.ModeMock && keyID == "" {
		suffix, err := randomHexUpper(4)
		if err != nil {
			s.writeHandlerError(w, err)
			return
		}
		keyID, secret = "LTAI5tMockAdmin"+suffix, "mock-placeholder"
	}
	if keyID == "" || secret == "" || len(keyID) > 128 || len(secret) > 256 {
		s.badRequest(w, "access_key_id and access_key_secret are required")
		return
	}
	admin, err := s.userAdminFactory(prov)
	if err != nil {
		s.badRequest(w, sanitizeMessage(err.Error()))
		return
	}
	if err := admin.Test(ctx, provider.UserRequest{Provider: prov, AdminAccessKeyID: keyID, AdminAccessKeySecret: secret}); err != nil {
		s.badRequest(w, "the key was not accepted: "+sanitizeMessage(err.Error()))
		return
	}
	plain, err := json.Marshal(brokerCredential{AccessKeyID: keyID, AccessKeySecret: secret})
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	enc, err := s.vault.Encrypt(plain, userAdminAAD(prov.ID))
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if err := s.db.SetProviderUserAdmin(ctx, prov.ID, enc, maskAccessKeyID(keyID), s.nowUTC()); err != nil {
		s.storeErrorResponse(w, err, "cloud account not found")
		return
	}
	s.actorAudit(ctx, "provider.long_lived_enabled", "ok", "critical", "provider", prov.ID, map[string]any{
		"cloud_account_id": prov.CloudAccountID, "access_key_id": maskAccessKeyID(keyID),
	})
	updated, err := s.db.GetProvider(ctx, prov.ID)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, updated)
}

func (s *Server) handleClearUserAdmin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	prov, err := s.db.GetProvider(ctx, r.PathValue("provider"))
	if err != nil {
		s.storeErrorResponse(w, err, "cloud account not found")
		return
	}
	if err := s.db.SetProviderUserAdmin(ctx, prov.ID, "", "", s.nowUTC()); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "revoke this account's long-lived credentials first")
			return
		}
		s.storeErrorResponse(w, err, "cloud account not found")
		return
	}
	s.actorAudit(ctx, "provider.long_lived_disabled", "ok", "critical", "provider", prov.ID, map[string]any{"cloud_account_id": prov.CloudAccountID})
	updated, err := s.db.GetProvider(ctx, prov.ID)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.writeData(w, http.StatusOK, updated)
}
