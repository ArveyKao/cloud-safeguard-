package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
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
		if r < 0x20 || r == 0x7f {
			return "", false
		}
	}
	return name, true
}

// newPersonWithSetupCode creates a pending person and returns the one-time
// setup code. It is shared by the supervisor API, bootstrap and recovery.
func newPersonWithSetupCode(ctx context.Context, db *store.DB, username, displayName string, supervisor bool, now time.Time) (model.PersonWithSetupCode, error) {
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
	ctx := r.Context()
	actor, _ := sessionFromContext(ctx)
	created, err := newPersonWithSetupCode(ctx, s.db, username, displayName, in.Supervisor, s.nowUTC())
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
		if supervisor != person.Supervisor {
			s.personAudit(ctx, actor.person, "person.supervisor_changed", "ok", "critical", "person", id,
				map[string]any{"username": person.Username, "supervisor": supervisor})
		}
		if status != person.Status {
			s.personAudit(ctx, actor.person, "person.status_changed", "ok", "warning", "person", id,
				map[string]any{"username": person.Username, "from": string(person.Status), "to": string(status)})
			s.afterPersonAuthorityChange(ctx, id)
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
	if err := s.db.ResetPersonSetup(ctx, id, hash, expires, now, true); err != nil {
		if errors.Is(err, store.ErrLastSupervisor) {
			s.writeError(w, http.StatusConflict, model.ErrCodeConflict,
				"this is the last active supervisor; make another person a supervisor first")
			return
		}
		s.storeErrorResponse(w, err, "person not found")
		return
	}
	s.personAudit(ctx, actor.person, "person.setup_reset", "ok", "warning", "person", id,
		map[string]any{"username": person.Username})
	s.afterPersonAuthorityChange(ctx, id)
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
	previous := ""
	if old, err := s.db.GetBinding(ctx, person.ID, provider.ID); err == nil {
		previous = string(old.Role)
	} else if !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, "read binding", err)
		return
	}
	now := s.nowUTC()
	binding := model.RoleBinding{
		PersonID: person.ID, ProviderID: provider.ID, Role: in.Role,
		CreatedBy: actor.person.ID, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.db.PutBinding(ctx, binding); err != nil {
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
	if previous != "" && model.Role(previous).Rank() > in.Role.Rank() {
		s.afterBindingReduced(ctx, person.ID, provider.ID)
	}
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
	if err := s.db.DeleteBinding(ctx, person.ID, provider.ID); err != nil {
		s.storeErrorResponse(w, err, "this person has no role on this cloud account")
		return
	}
	s.personAudit(ctx, actor.person, "binding.removed", "ok", "warning", "provider", provider.ID, map[string]any{
		"person_id": person.ID, "username": person.Username,
	})
	s.afterBindingReduced(ctx, person.ID, provider.ID)
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

// afterPersonAuthorityChange runs after a person was suspended or reset.
// Sessions are already gone (store). Agent ownership arrives with the agent
// sign-in work; from then on this also revokes the person's agents' leases.
func (s *Server) afterPersonAuthorityChange(ctx context.Context, personID string) {
	if s.hookAfterAuthorityWrite != nil {
		s.hookAfterAuthorityWrite("person")
	}
}

// afterBindingReduced runs after a binding was lowered or removed. It will
// revoke the leases the person's agents no longer qualify for (§17.6).
func (s *Server) afterBindingReduced(ctx context.Context, personID, providerID string) {
	if s.hookAfterAuthorityWrite != nil {
		s.hookAfterAuthorityWrite("binding")
	}
}
