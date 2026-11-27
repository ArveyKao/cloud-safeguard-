package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/authn"
	"github.com/arveykao/cloud-safeguard/internal/model"
)

// QA lifecycle coverage for QA_BRIEF A (second half). Already covered elsewhere
// (reference only — do not duplicate):
//
//	Long-lived: longlived_test.go (TestLongLivedFlow, TestLongLivedAgentRequestGivesOnlyALink,
//	  TestLongLivedIsDeletedWhenTheOwnerLosesTheRight, …)
//	Refresh API: refresh_test.go; CLI refresh rate limit in TestE2EAgentSignInAccessAndExec;
//	  remote MCP refresh in TestRemoteMCPFlow
//	Fetch after expired/revoked/denied: TestReadRequestIsIssuedAtOnceAndExpires,
//	  TestOwnerDeniesAndRevokes, …
//	Remote MCP adversarial: mcpremote_test.go

// newRealMockAccessEnv is like newAccessEnv but uses the real mock STS minter
// (no MinterFactory override). The fake clock starts at time.Now() so mock-cloud
// token deadlines match wall-clock validation.
func newRealMockAccessEnv(t *testing.T, role model.Role) *accessEnv {
	t.Helper()
	dir := t.TempDir()
	initRes, err := Init(context.Background(), InitOptions{DataDir: dir, Demo: true})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	clock := newFakeClock(time.Now())
	srv, err := New(Config{
		DataDir: dir,
		Now:     clock.Now,
		PasswordParams: &authn.Params{
			MemoryKiB: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32,
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Logf("server Close: %v", err)
		}
	})
	env := &testEnv{
		t: t, srv: srv, dir: dir, clock: clock, logs: &bytes.Buffer{},
		supervisor: initRes.Supervisor, providerID: initRes.ProviderIDs[0],
	}
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	a := &accessEnv{testEnv: env, sup: sup, mei: mei}
	if role != "" {
		a.bind(mei, role)
	}
	a.agent, a.token = env.signInAgent(mei, "mei-agent")
	return a
}

func requireForbiddenRAM(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("%s: status %d, want 403", what, rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Forbidden.RAM") {
		t.Fatalf("%s: missing Forbidden.RAM error code (status %d)", what, rec.Code)
	}
}

// securityTokenOK reports a mock STS token without printing it.
func securityTokenOK(token string) bool {
	return strings.HasPrefix(token, "cgk1.")
}

// TestQALeastPrivilegeAndRAMRefuse: each permission level on ecs gets a real
// mock credential; in-scope mock-cloud calls succeed; out-of-scope and RAM are
// Forbidden.RAM. Named-resource write refuses other instances.
func TestQALeastPrivilegeAndRAMRefuse(t *testing.T) {
	a := newRealMockAccessEnv(t, model.RoleAdministrator)
	requireCode(t, a.setMode(a.mei, model.ModeFull, 0), http.StatusOK)
	h := a.srv.Handler()

	for _, level := range []string{"read", "write", "full"} {
		t.Run(level, func(t *testing.T) {
			req := a.request(accessInput("ecs", level))
			if req.Status != model.LeaseActive {
				t.Fatalf("request status = %s, want active", req.Status)
			}
			credRec := a.credential(req.ID)
			if credRec.Code != http.StatusOK {
				t.Fatalf("credential: status %d, want 200", credRec.Code)
			}
			token := decodeEnvelope[model.CredentialEnvelope](t, credRec).Credential.SecurityToken
			if !securityTokenOK(token) {
				t.Fatalf("security token missing cgk1. prefix (len=%d)", len(token))
			}

			list := rawRequest(t, h, http.MethodGet, "/mock-cloud/v1/ecs/instances", token, nil)
			if list.Code != http.StatusOK {
				t.Fatalf("list instances: status %d", list.Code)
			}

			restart := rawRequest(t, h, http.MethodPost, "/mock-cloud/v1/ecs/instances/i-2ze0demo001/restart", token, nil)
			if level == "read" {
				requireForbiddenRAM(t, restart, "read restart")
			} else if restart.Code != http.StatusOK {
				t.Fatalf("%s restart: status %d", level, restart.Code)
			}

			ram := rawRequest(t, h, http.MethodGet, "/mock-cloud/v1/ram/users", token, nil)
			requireForbiddenRAM(t, ram, level+" RAM")
			// Give the credential back: an agent may hold at most 3 at a time.
			requireStatus(t, a.do(http.MethodPost, "/api/v1/agent/leases/"+req.ID+"/revoke", a.token, nil), http.StatusOK)
		})
	}

	t.Run("named-resource", func(t *testing.T) {
		in := accessInput("ecs", "write")
		in.ResourceName = "i-2ze0demo001"
		req := a.request(in)
		if req.Status != model.LeaseActive {
			t.Fatalf("named write status = %s", req.Status)
		}
		credRec := a.credential(req.ID)
		if credRec.Code != http.StatusOK {
			t.Fatalf("credential: status %d, want 200", credRec.Code)
		}
		token := decodeEnvelope[model.CredentialEnvelope](t, credRec).Credential.SecurityToken
		ok := rawRequest(t, h, http.MethodPost, "/mock-cloud/v1/ecs/instances/i-2ze0demo001/restart", token, nil)
		if ok.Code != http.StatusOK {
			t.Fatalf("named instance restart: status %d", ok.Code)
		}
		other := rawRequest(t, h, http.MethodPost, "/mock-cloud/v1/ecs/instances/i-2ze0demo002/restart", token, nil)
		requireForbiddenRAM(t, other, "other instance restart")
		// Listing works on the whole type, so a one-instance credential can
		// find its instance (owner's decision, 2026-11-23); it still changes
		// nothing else.
		if list := rawRequest(t, h, http.MethodGet, "/mock-cloud/v1/ecs/instances", token, nil); list.Code != http.StatusOK {
			t.Fatalf("named credential lists instances: status %d", list.Code)
		}
		if own := rawRequest(t, h, http.MethodGet, "/mock-cloud/v1/ecs/instances/i-2ze0demo001", token, nil); own.Code != http.StatusOK {
			t.Fatalf("named credential reads its instance: status %d", own.Code)
		}
		stop := rawRequest(t, h, http.MethodPost, "/mock-cloud/v1/ecs/instances/i-2ze0demo002/stop", token, nil)
		requireForbiddenRAM(t, stop, "other instance stop")
		ram := rawRequest(t, h, http.MethodGet, "/mock-cloud/v1/ram/users", token, nil)
		requireForbiddenRAM(t, ram, "named-resource RAM")
	})
}

// TestQARevocationMatrix: each control-plane trigger leaves fetch, refresh and
// the OLD mock-cloud token refused. Fresh env per subtest; real mock minter.
func TestQARevocationMatrix(t *testing.T) {
	type setup struct {
		a     *accessEnv
		reqID string
		token string // old SecurityToken from before the trigger
	}

	// activeLease prepares a working read lease (or write for "lower role") and
	// advances two minutes so a refresh would succeed if nothing revoked it.
	activeLease := func(t *testing.T, role model.Role, permission string) setup {
		t.Helper()
		a := newRealMockAccessEnv(t, role)
		req := a.request(accessInput("ecs", permission))
		if permission != "read" && req.Status == model.LeasePending {
			requireStatus(t, a.approve(a.mei, req.ID), http.StatusOK)
		} else if req.Status != model.LeaseActive {
			t.Fatalf("request status = %s", req.Status)
		}
		credRec := a.credential(req.ID)
		if credRec.Code != http.StatusOK {
			t.Fatalf("credential before trigger: status %d", credRec.Code)
		}
		cred := decodeEnvelope[model.CredentialEnvelope](t, credRec)
		if !securityTokenOK(cred.Credential.SecurityToken) {
			t.Fatalf("security token missing cgk1. prefix (len=%d)", len(cred.Credential.SecurityToken))
		}
		cloud := rawRequest(t, a.srv.Handler(), http.MethodGet, "/mock-cloud/v1/ecs/instances", cred.Credential.SecurityToken, nil)
		if cloud.Code != http.StatusOK {
			t.Fatalf("mock cloud before trigger: status %d", cloud.Code)
		}
		a.clock.Advance(2 * time.Minute)
		return setup{a: a, reqID: req.ID, token: cred.Credential.SecurityToken}
	}

	// assertLeaseRefused: agent still authenticates; credential/refresh are
	// 409 with the lease-not-active / conflict codes; mock cloud is 401.
	assertLeaseRefused := func(t *testing.T, s setup) {
		t.Helper()
		requireErrorCode(t, s.a.credential(s.reqID), http.StatusConflict, model.ErrCodeLeaseNotActive)
		requireErrorCode(t, s.a.refresh(s.a.token, s.reqID), http.StatusConflict, model.ErrCodeConflict)
		cloud := rawRequest(t, s.a.srv.Handler(), http.MethodGet, "/mock-cloud/v1/ecs/instances", s.token, nil)
		if cloud.Code != http.StatusUnauthorized {
			t.Fatalf("old mock-cloud token: status %d, want 401", cloud.Code)
		}
		if s.a.status(s.reqID) != model.LeaseRevoked {
			t.Fatalf("lease status = %s, want revoked", s.a.status(s.reqID))
		}
	}

	// assertAuthRefused: the agent can no longer authenticate (owner
	// suspended/reset or agent revoked), so fetch/refresh are 403.
	assertAuthRefused := func(t *testing.T, s setup) {
		t.Helper()
		requireErrorCode(t, s.a.credential(s.reqID), http.StatusForbidden, model.ErrCodeForbidden)
		requireErrorCode(t, s.a.refresh(s.a.token, s.reqID), http.StatusForbidden, model.ErrCodeForbidden)
		cloud := rawRequest(t, s.a.srv.Handler(), http.MethodGet, "/mock-cloud/v1/ecs/instances", s.token, nil)
		if cloud.Code != http.StatusUnauthorized {
			t.Fatalf("old mock-cloud token: status %d, want 401", cloud.Code)
		}
		if s.a.status(s.reqID) != model.LeaseRevoked {
			t.Fatalf("lease status = %s, want revoked", s.a.status(s.reqID))
		}
	}

	assertSystemRevoke := func(t *testing.T, a *accessEnv, reqID, cause string) {
		t.Helper()
		var found *model.AuditEvent
		for _, ev := range a.listAudit("lease.revoked") {
			if ev.TargetID == reqID {
				e := ev
				found = &e
				break
			}
		}
		if found == nil {
			t.Fatal("missing lease.revoked audit event for the request")
		}
		if found.ActorType != "system" {
			t.Fatalf("lease.revoked ActorType = %q, want system", found.ActorType)
		}
		wantBy := "person:" + a.sup.person.ID
		if found.Metadata["caused_by"] != wantBy {
			t.Fatalf("lease.revoked caused_by = %v, want %s", found.Metadata["caused_by"], wantBy)
		}
		if cause != "" && found.Metadata["cause"] != cause {
			t.Fatalf("lease.revoked cause = %v, want %s", found.Metadata["cause"], cause)
		}
	}

	t.Run("refresh baseline without revoke", func(t *testing.T) {
		s := activeLease(t, model.RoleGuest, "read")
		requireStatus(t, s.a.refresh(s.a.token, s.reqID), http.StatusOK)
	})

	t.Run("lower role", func(t *testing.T) {
		s := activeLease(t, model.RoleMember, "write")
		s.a.bind(s.a.mei, model.RoleGuest)
		assertLeaseRefused(t, s)
		assertSystemRevoke(t, s.a, s.reqID, "binding_reduced")
	})

	t.Run("remove role", func(t *testing.T) {
		s := activeLease(t, model.RoleGuest, "read")
		s.a.unbind(s.a.mei)
		assertLeaseRefused(t, s)
		assertSystemRevoke(t, s.a, s.reqID, "binding_reduced")
	})

	t.Run("suspend person", func(t *testing.T) {
		s := activeLease(t, model.RoleGuest, "read")
		suspended := model.PersonSuspended
		requireStatus(t, s.a.sup.do(http.MethodPatch, "/api/v1/supervisor/people/"+s.a.mei.person.ID,
			model.UpdatePersonInput{Status: &suspended}), http.StatusOK)
		assertAuthRefused(t, s)
		assertSystemRevoke(t, s.a, s.reqID, "")
		person, err := s.a.srv.db.GetPerson(context.Background(), s.a.mei.person.ID)
		if err != nil || person.Status != model.PersonSuspended {
			t.Fatalf("person status after suspend: %v %s", err, person.Status)
		}
	})

	t.Run("reset person", func(t *testing.T) {
		s := activeLease(t, model.RoleGuest, "read")
		requireStatus(t, s.a.sup.do(http.MethodPost, "/api/v1/supervisor/people/"+s.a.mei.person.ID+"/reset", nil), http.StatusOK)
		assertAuthRefused(t, s)
		assertSystemRevoke(t, s.a, s.reqID, "")
		person, err := s.a.srv.db.GetPerson(context.Background(), s.a.mei.person.ID)
		if err != nil || person.Status != model.PersonPending {
			t.Fatalf("person status after reset: %v %s", err, person.Status)
		}
	})

	t.Run("revoke agent", func(t *testing.T) {
		s := activeLease(t, model.RoleGuest, "read")
		requireStatus(t, s.a.mei.do(http.MethodPost, "/api/v1/me/agents/"+s.a.agent.ID+"/revoke", nil), http.StatusOK)
		assertAuthRefused(t, s)
		ag, err := s.a.srv.db.GetAgent(context.Background(), s.a.agent.ID)
		if err != nil || ag.Status != model.AgentRevoked {
			t.Fatalf("agent status after revoke: %v %s", err, ag.Status)
		}
	})

	t.Run("disable cloud account", func(t *testing.T) {
		s := activeLease(t, model.RoleGuest, "read")
		disabled := model.ProviderDisabled
		requireStatus(t, s.a.sup.do(http.MethodPatch, "/api/v1/supervisor/accounts/"+s.a.providerID,
			model.UpdateProviderInput{Status: &disabled}), http.StatusOK)
		assertLeaseRefused(t, s)
	})

	t.Run("owner revokes request", func(t *testing.T) {
		s := activeLease(t, model.RoleGuest, "read")
		requireStatus(t, s.a.mei.do(http.MethodPost, "/api/v1/me/requests/"+s.reqID+"/revoke", nil), http.StatusOK)
		assertLeaseRefused(t, s)
		ev := s.a.lastEvent("lease.revoked")
		if ev.TargetID != s.reqID {
			t.Fatalf("lease.revoked target = %s, want %s", ev.TargetID, s.reqID)
		}
		if ev.ActorType != "person" || ev.ActorID != s.a.mei.person.ID {
			t.Fatalf("owner revoke actor = %s %s, want person %s", ev.ActorType, ev.ActorID, s.a.mei.person.ID)
		}
		if ev.Metadata["cause"] != "owner_revoked" || ev.Metadata["caused_by"] != "person:"+s.a.mei.person.ID {
			t.Fatalf("owner revoke metadata cause/caused_by = %v / %v", ev.Metadata["cause"], ev.Metadata["caused_by"])
		}
	})
}

// TestQACredentialUnfetchableAfterTerminal consolidates API-only fetch refusal
// after expired / revoked / denied (fake minter OK — maps QA_BRIEF bullet).
func TestQACredentialUnfetchableAfterTerminal(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		a := newAccessEnv(t, model.RoleGuest)
		req := a.request(accessInput("ecs", "read"))
		if rec := a.credential(req.ID); rec.Code != http.StatusOK {
			t.Fatalf("credential before expiry: status %d", rec.Code)
		}
		a.clock.Advance(601 * time.Second)
		a.srv.sweepOnce(context.Background())
		requireErrorCode(t, a.credential(req.ID), http.StatusConflict, model.ErrCodeLeaseNotActive)
		if a.status(req.ID) != model.LeaseExpired {
			t.Fatalf("lease status = %s, want expired", a.status(req.ID))
		}
	})
	t.Run("revoked", func(t *testing.T) {
		a := newAccessEnv(t, model.RoleMember)
		req := a.request(accessInput("ecs", "write"))
		requireStatus(t, a.approve(a.mei, req.ID), http.StatusOK)
		if rec := a.credential(req.ID); rec.Code != http.StatusOK {
			t.Fatalf("credential before revoke: status %d", rec.Code)
		}
		requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/requests/"+req.ID+"/revoke", nil), http.StatusOK)
		requireErrorCode(t, a.credential(req.ID), http.StatusConflict, model.ErrCodeLeaseNotActive)
		if a.status(req.ID) != model.LeaseRevoked {
			t.Fatalf("lease status = %s, want revoked", a.status(req.ID))
		}
		ev := a.lastEvent("lease.revoked")
		if ev.ActorType != "person" || ev.ActorID != a.mei.person.ID {
			t.Fatalf("owner revoke actor = %s %s, want person %s", ev.ActorType, ev.ActorID, a.mei.person.ID)
		}
		if ev.Metadata["cause"] != "owner_revoked" {
			t.Fatalf("owner revoke cause = %v, want owner_revoked", ev.Metadata["cause"])
		}
	})
	t.Run("denied", func(t *testing.T) {
		a := newAccessEnv(t, model.RoleMember)
		req := a.request(accessInput("ecs", "write"))
		requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/requests/"+req.ID+"/deny",
			model.DenyRequestInput{Reason: "qa terminal"}), http.StatusOK)
		requireErrorCode(t, a.credential(req.ID), http.StatusConflict, model.ErrCodeLeaseNotActive)
		if a.status(req.ID) != model.LeaseDenied {
			t.Fatalf("lease status = %s, want denied", a.status(req.ID))
		}
	})
}
