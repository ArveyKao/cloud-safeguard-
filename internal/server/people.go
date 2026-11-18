package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

// Supervisor API (CONTRACT §17.1, §17.2): people and role bindings.

const maxDisplayNameLength = 100

func cleanDisplayName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxDisplayNameLength {
		return "", false
	}
	for _, r := range name {
		// Control and format characters (bidi overrides, zero-width
		// characters) could make a name render as something else.
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "", false
		}
	}
	return name, true
}

// raisedModes is a person's approval modes above read that are in effect at
// now, by cloud account ID (or provider ID when the account has none), for
// the audit of a reset.
func raisedModes(ctx context.Context, db *store.DB, personID string, now time.Time) (map[string]string, error) {
	modes, err := db.ListAccountModes(ctx, personID)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for providerID, m := range modes {
		mode := m.Effective(now)
		if mode == model.ModeRead {
			continue
		}
		key := providerID
		if prov, err := db.GetProvider(ctx, providerID); err == nil && prov.CloudAccountID != "" {
			key = prov.CloudAccountID
		}
		out[key] = string(mode)
	}
	return out, nil
}

// removedModes compares a person's raised modes now with those before a
// change and returns the ones that are gone or lower, for the audit.
func removedModes(ctx context.Context, db *store.DB, personID string, now time.Time, before map[string]string) (map[string]string, error) {
	after, err := raisedModes(ctx, db, personID, now)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for account, mode := range before {
		if after[account] != mode {
			out[account] = mode
		}
	}
	return out, nil
}

// newPersonWithSetupCode creates a pending person and returns the one-time
// setup code. It is shared by the supervisor API, bootstrap and recovery.
func newPersonWithSetupCode(ctx context.Context, db *store.DB, username, displayName string, supervisor bool, now time.Time, issue model.SetupIssue) (model.PersonWithSetupCode, error) {
	id, err := newID("per_")
	if err != nil {
		return model.PersonWithSetupCode{}, err
	}
	code, hash, err := authn.NewSecret(24)
	if err != nil {
		return model.PersonWithSetupCode{}, err
	}
	person := model.Person{
		ID: id, Username: username, DisplayName: displayName, Status: model.PersonPending,
		Supervisor: supervisor, CreatedAt: now, UpdatedAt: now,
	}
	issue.At = now
	person.SetupIssued = &issue
	expires := now.Add(setupCodeTTL)
	if err := db.CreatePerson(ctx, person, hash, expires); err != nil {
		return model.PersonWithSetupCode{}, err
	}
	return model.PersonWithSetupCode{Person: person, SetupCode: code, SetupExpiresAt: expires}, nil
}

func (s *Server) handleListPeople(w http.ResponseWriter, r *http.Request) {
	people, err := s.db.ListPersons(r.Context())
	if err != nil {
		s.internalError(w, "list people", err)
		return
	}
	writeList(s, w, http.StatusOK, people, len(people))
}

func (s *Server) handleCreatePerson(w http.ResponseWriter, r *http.Request) {
	var in model.CreatePersonInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	username, ok := normalizeUsername(in.Username)
	if !ok {
		s.badRequest(w, "username must be 2-32 characters: lowercase letters, digits, dot, dash or underscore, starting with a letter or digit")
		return
	}
	displayName, ok := cleanDisplayName(in.DisplayName)
	if !ok {
		s.badRequest(w, "display_name must be at most 100 characters without control characters")
		return
	}
	// A new person gets a setup code: whoever holds it holds the account.
	if !s.stepUp(w, r) {
		return
	}
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	created, err := newPersonWithSetupCode(ctx, s.db, username, displayName, in.Supervisor, s.nowUTC(),
		model.SetupIssue{ByID: actor.person.ID, ByName: actor.person.Username, Kind: model.SetupCreated})
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "username is already taken")
			return
		}
		s.internalError(w, "create person", err)
		return
	}
	severity := "info"
	if in.Supervisor {
		severity = "critical"
	}
	s.personAudit(ctx, actor.person, "person.created", "ok", severity, "person", created.Person.ID, map[string]any{
		"username": username, "supervisor": in.Supervisor,
	})
	s.writeData(w, http.StatusCreated, created)
}

func (s *Server) handleUpdatePerson(w http.ResponseWriter, r *http.Request) {
	var in model.UpdatePersonInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	// Making a supervisor or activating a person raises access.
	if (in.Supervisor != nil && *in.Supervisor) || (in.Status != nil && *in.Status == model.PersonActive) {
		if !s.stepUp(w, r) {
			return
		}
	}
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	id := r.PathValue("id")
	// Authority changes and sign-in for one person never interleave.
	unlock, err := s.lockPerson(ctx, id)
	if err != nil {
		s.internalError(w, "lock person", err)
		return
	}
	defer unlock()
	person, err := s.db.GetPerson(ctx, id)
	if err != nil {
		s.storeErrorResponse(w, err, "person not found")
		return
	}
	now := s.nowUTC()
	if in.DisplayName != nil {
		name, ok := cleanDisplayName(*in.DisplayName)
		if !ok {
			s.badRequest(w, "display_name must be at most 100 characters without control characters")
			return
		}
		if err := s.db.UpdatePersonDisplayName(ctx, id, name, now); err != nil {
			s.storeErrorResponse(w, err, "person not found")
			return
		}
	}
	if in.Status != nil || in.Supervisor != nil {
		modesBefore, err := raisedModes(ctx, s.db, id, now)
		if err != nil {
			s.writeHandlerError(w, err)
			return
		}
		status, supervisor := person.Status, person.Supervisor
		if in.Status != nil {
			if *in.Status != model.PersonActive && *in.Status != model.PersonSuspended {
				s.badRequest(w, "status must be active or suspended")
				return
			}
			status = *in.Status
		}
		if in.Supervisor != nil {
			supervisor = *in.Supervisor
		}
		if status == model.PersonPending {
			// Only the flag of a pending person can change here. The write
			// itself requires the person to still be pending, so it can
			// never demote someone who finished setup in the meantime.
			if err := s.db.SetPendingSupervisorFlag(ctx, id, supervisor, now); err != nil {
				if errors.Is(err, store.ErrConflict) {
					s.writeError(w, http.StatusConflict, model.ErrCodeConflict, "this person just finished setup; try again")
					return
				}
				s.storeErrorResponse(w, err, "person not found")
				return
			}
		} else if err := s.db.SetPersonAuthority(ctx, id, status, supervisor, now); err != nil {
			switch {
			case errors.Is(err, store.ErrLastSupervisor):
				s.writeError(w, http.StatusConflict, model.ErrCodeConflict,
					"this is the last active supervisor; make another person a supervisor first")
			case errors.Is(err, store.ErrConflict):
				s.writeError(w, http.StatusConflict, model.ErrCodeConflict,
					"this person has not finished setup; reset their setup code instead")
			default:
				s.storeErrorResponse(w, err, "person not found")
			}
			return
		}
		removed, err := removedModes(ctx, s.db, id, now, modesBefore)
		if err != nil {
			s.logf("person %s: read modes after change: %v", id, err)
		}
		if supervisor != person.Supervisor {
			metadata := map[string]any{"username": person.Username, "supervisor": supervisor}
			if len(removed) > 0 && status == person.Status {
				metadata["removed_modes"] = removed
			}
			s.personAudit(ctx, actor.person, "person.supervisor_changed", "ok", "critical", "person", id, metadata)
			if !supervisor && status == person.Status {
				// A former supervisor keeps only their role bindings.
				s.afterBindingReduced(ctx, actor.person, id, "")
			}
		}
		if status != person.Status {
			metadata := map[string]any{"username": person.Username, "from": string(person.Status), "to": string(status)}
			if len(removed) > 0 {
				metadata["removed_modes"] = removed
			}
			s.personAudit(ctx, actor.person, "person.status_changed", "ok", "warning", "person", id, metadata)
			s.afterPersonAuthorityChange(ctx, actor.person, id)
		}
	}
	updated, err := s.db.GetPerson(ctx, id)
	if err != nil {
		s.storeErrorResponse(w, err, "person not found")
		return
	}
	s.writeData(w, http.StatusOK, updated)
}

// handleResetPerson issues a new setup code, erasing the person's password,
// TOTP secret and sessions. The person becomes pending, whatever their status
// was; this is also how a suspended person who never finished setup is
// brought back.
func (s *Server) handleResetPerson(w http.ResponseWriter, r *http.Request) {
	// A reset issues a new setup code: whoever holds it holds the account.
	if !s.stepUp(w, r) {
		return
	}
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	id := r.PathValue("id")
	unlock, err := s.lockPerson(ctx, id)
	if err != nil {
		s.internalError(w, "lock person", err)
		return
	}
	defer unlock()
	person, err := s.db.GetPerson(ctx, id)
	if err != nil {
		s.storeErrorResponse(w, err, "person not found")
		return
	}
	code, hash, err := authn.NewSecret(24)
	if err != nil {
		s.internalError(w, "generate setup code", err)
		return
	}
	now := s.nowUTC()
	expires := now.Add(setupCodeTTL)
	previousModes, err := raisedModes(ctx, s.db, id, now)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	if err := s.db.ResetPersonSetup(ctx, id, hash, expires, now, true,
		model.SetupIssue{ByID: actor.person.ID, ByName: actor.person.Username, Kind: model.SetupReset}); err != nil {
		if errors.Is(err, store.ErrLastSupervisor) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict,
				"this is the last active supervisor; make another person a supervisor first")
			return
		}
		s.storeErrorResponse(w, err, "person not found")
		return
	}
	s.personAudit(ctx, actor.person, "person.setup_reset", "ok", "warning", "person", id, map[string]any{
		"username":       person.Username,
		"previous_modes": previousModes, "mode": string(model.ModeRead),
	})
	s.afterPersonAuthorityChange(ctx, actor.person, id)
	person, err = s.db.GetPerson(ctx, id)
	if err != nil {
		s.storeErrorResponse(w, err, "person not found")
		return
	}
	s.writeData(w, http.StatusOK, model.PersonWithSetupCode{Person: person, SetupCode: code, SetupExpiresAt: expires})
}

func (s *Server) handleListBindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	bindings, err := s.db.ListBindings(r.Context(), q.Get("person_id"), q.Get("provider_id"))
	if err != nil {
		s.internalError(w, "list bindings", err)
		return
	}
	writeList(s, w, http.StatusOK, bindings, len(bindings))
}

func (s *Server) handlePutBinding(w http.ResponseWriter, r *http.Request) {
	var in model.PutBindingInput
	if err := s.decodeJSON(w, r, &in); err != nil {
		s.badRequest(w, err.Error())
		return
	}
	if !in.Role.Valid() {
		s.badRequest(w, "role must be guest, member or administrator")
		return
	}
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	provider, person, ok := s.bindingTargets(w, r)
	if !ok {
		return
	}
	// Read, decide and write as one step (see bindingsMu).
	s.bindingsMu.Lock()
	defer s.bindingsMu.Unlock()
	previous := ""
	if old, err := s.db.GetBinding(ctx, person.ID, provider.ID); err == nil {
		previous = string(old.Role)
	} else if !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, "read binding", err)
		return
	}
	// A role above the one the person has now raises access. No role at all
	// counts as below guest, but giving guest (read) is allowed as is.
	raises := in.Role.Rank() > model.Role(previous).Rank()
	if previous == "" {
		raises = in.Role != model.RoleGuest
	}
	if raises && !s.stepUp(w, r) {
		return
	}
	now := s.nowUTC()
	binding := model.RoleBinding{
		PersonID: person.ID, ProviderID: provider.ID, Role: in.Role,
		CreatedBy: actor.person.ID, CreatedAt: now, UpdatedAt: now,
	}
	// A provider without a cloud account ID is not connected to anything: a
	// role on it would do nothing now and would be removed when it gets an
	// account. Checked and written under the accounts lock, so a role can
	// never slip in while the account is being given its ID.
	s.accountsMu.Lock()
	current, err := s.db.GetProvider(ctx, provider.ID)
	if err == nil && current.CloudAccountID == "" {
		s.accountsMu.Unlock()
		s.writeError(w, http.StatusConflict, model.ErrCodeConflict,
			"this cloud account is not connected yet (it has no cloud account ID); set its role ARN first")
		return
	}
	if err == nil {
		err = s.db.PutBinding(ctx, binding)
	}
	s.accountsMu.Unlock()
	if err != nil {
		s.internalError(w, "put binding", err)
		return
	}
	severity := "info"
	if person.ID == actor.person.ID {
		severity = "warning" // a supervisor giving themself cloud access
	}
	s.personAudit(ctx, actor.person, "binding.set", "ok", severity, "provider", provider.ID, map[string]any{
		"person_id": person.ID, "username": person.Username, "role": string(in.Role), "previous_role": previous,
		"self": person.ID == actor.person.ID,
	})
	// Always re-check the person's agents after a role is written, not only
	// when this request saw a higher role before: two changes at once can
	// each read the other's "before", and the one that lowers the role would
	// then skip the sweep. The re-check revokes nothing the new role allows.
	s.afterBindingReduced(ctx, actor.person, person.ID, provider.ID)
	stored, err := s.db.GetBinding(ctx, person.ID, provider.ID)
	if err != nil {
		s.internalError(w, "reload binding", err)
		return
	}
	s.writeData(w, http.StatusOK, stored)
}

func (s *Server) handleDeleteBinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	provider, person, ok := s.bindingTargets(w, r)
	if !ok {
		return
	}
	now := s.nowUTC()
	modesBefore, err := raisedModes(ctx, s.db, person.ID, now)
	if err != nil {
		s.writeHandlerError(w, err)
		return
	}
	s.bindingsMu.Lock()
	err = s.db.DeleteBinding(ctx, person.ID, provider.ID)
	s.bindingsMu.Unlock()
	if err != nil {
		s.storeErrorResponse(w, err, "this person has no role on this cloud account")
		return
	}
	metadata := map[string]any{"person_id": person.ID, "username": person.Username}
	if removed, err := removedModes(ctx, s.db, person.ID, now, modesBefore); err == nil && len(removed) > 0 {
		metadata["removed_modes"] = removed
	}
	s.personAudit(ctx, actor.person, "binding.removed", "ok", "warning", "provider", provider.ID, metadata)
	s.afterBindingReduced(ctx, actor.person, person.ID, provider.ID)
	s.writeData(w, http.StatusOK, map[string]bool{"ok": true})
}

// bindingTargets loads the cloud account and person named in the path.
func (s *Server) bindingTargets(w http.ResponseWriter, r *http.Request) (model.Provider, model.Person, bool) {
	provider, err := s.db.GetProvider(r.Context(), r.PathValue("provider"))
	if err != nil {
		s.storeErrorResponse(w, err, "cloud account not found")
		return model.Provider{}, model.Person{}, false
	}
	person, err := s.db.GetPerson(r.Context(), r.PathValue("person"))
	if err != nil {
		s.storeErrorResponse(w, err, "person not found")
		return model.Provider{}, model.Person{}, false
	}
	return provider, person, true
}

// afterPersonAuthorityChange runs after a person was suspended, reactivated
// or reset. Sessions are already gone (store). While the person is not
// active their agents cannot authenticate, and this revokes those agents'
// pending and active leases at once (§17.6). After a reactivation the
// re-check finds nothing to revoke.
func (s *Server) afterPersonAuthorityChange(ctx context.Context, actor model.Person, personID string) {
	if s.hookAfterAuthorityWrite != nil {
		s.hookAfterAuthorityWrite("person")
	}
	revoked, err := s.revokeOwnedAgentLeases(ctx, personID, "agent's owner is no longer active", map[string]any{
		"caused_by": "person:" + actor.ID, "caused_by_username": actor.Username, "owner_id": personID,
	})
	if err != nil {
		s.logf("revoke leases of agents owned by %s: %v", personID, err)
	}
	if len(revoked) > 0 {
		s.systemAudit(ctx, "person.agent_leases_revoked", "ok", "warning", "person", personID,
			map[string]any{"revoked_lease_ids": revoked})
	}
}

// afterBindingReduced runs after a binding was lowered or removed. It
// re-checks every pending and active lease of the person's agents and
// revokes those the new role no longer permits (§17.6). Leases on other
// cloud accounts pass the re-check and are left alone.
func (s *Server) afterBindingReduced(ctx context.Context, actor model.Person, personID, providerID string) {
	if s.hookAfterAuthorityWrite != nil {
		s.hookAfterAuthorityWrite("binding")
	}
	revoked, err := s.revokeOwnedAgentLeases(ctx, personID, "owner's role on the cloud account was lowered or removed", map[string]any{
		"cause": "binding_reduced", "owner_id": personID, "provider_id": providerID,
		"caused_by": "person:" + actor.ID, "caused_by_username": actor.Username,
	})
	if err != nil {
		s.logf("revoke leases after binding change for %s on %s: %v", personID, providerID, err)
	}
	if len(revoked) > 0 {
		s.systemAudit(ctx, "binding.agent_leases_revoked", "ok", "warning", "provider", providerID,
			map[string]any{"person_id": personID, "revoked_lease_ids": revoked,
				"caused_by": "person:" + actor.ID, "caused_by_username": actor.Username})
	}
}
