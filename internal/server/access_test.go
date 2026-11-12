package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/arveykao/cloud-safeguard/internal/capcatalog"
	"github.com/arveykao/cloud-safeguard/internal/model"
	"github.com/arveykao/cloud-safeguard/internal/provider"
	"github.com/arveykao/cloud-safeguard/internal/store"
)

const demoAccountID = "1234567890123456"

// accessEnv is a demo environment with a supervisor and one person ("mei")
// who owns an agent and holds the given role on the demo cloud account.
type accessEnv struct {
	*testEnv
	sup   *personClient
	mei   *personClient
	agent model.Agent
	token string
}

func newAccessEnv(t *testing.T, role model.Role) *accessEnv {
	t.Helper()
	env := newTestEnv(t, true)
	sup := env.supervisorClient()
	mei := env.addPerson(sup, "mei", false)
	a := &accessEnv{testEnv: env, sup: sup, mei: mei}
	if role != "" {
		a.bind(mei, role)
	}
	a.agent, a.token = env.signInAgent(mei, "mei-agent")
	return a
}

func (a *accessEnv) bind(p *personClient, role model.Role) {
	a.t.Helper()
	rec := a.sup.do(http.MethodPut, "/api/v1/supervisor/accounts/"+a.providerID+"/people/"+p.person.ID, model.PutBindingInput{Role: role})
	requireStatus(a.t, rec, http.StatusOK)
}

func (a *accessEnv) unbind(p *personClient) {
	a.t.Helper()
	requireStatus(a.t, a.sup.do(http.MethodDelete, "/api/v1/supervisor/accounts/"+a.providerID+"/people/"+p.person.ID, nil), http.StatusOK)
}

func accessInput(resource, permission string) model.AccessRequestInput {
	in := model.AccessRequestInput{CloudAccountID: demoAccountID, Resource: resource, Permission: permission, TTLSeconds: 600}
	if permission != "read" {
		in.Reason = "restart after the nginx config change"
	}
	return in
}

func (a *accessEnv) requestRaw(token string, in any) *httptest.ResponseRecorder {
	a.t.Helper()
	return a.do(http.MethodPost, "/api/v1/agent/access-requests", token, in)
}

func (a *accessEnv) request(in model.AccessRequestInput) model.AccessRequest {
	a.t.Helper()
	rec := a.requestRaw(a.token, in)
	requireStatus(a.t, rec, http.StatusCreated)
	return decodeEnvelope[model.AccessRequest](a.t, rec)
}

func (a *accessEnv) status(id string) model.LeaseStatus {
	a.t.Helper()
	lease, err := a.srv.db.GetLease(context.Background(), id)
	if err != nil {
		a.t.Fatal(err)
	}
	return lease.Status
}

func (a *accessEnv) credential(id string) *httptest.ResponseRecorder {
	return a.do(http.MethodPost, "/api/v1/agent/leases/"+id+"/credential", a.token, nil)
}

func (a *accessEnv) approve(p *personClient, id string) *httptest.ResponseRecorder {
	return p.do(http.MethodPost, "/api/v1/me/requests/"+id+"/approve", nil)
}

func (a *accessEnv) leaseCount() int {
	a.t.Helper()
	leases, err := a.srv.db.ListAllLeases(context.Background(), store.LeaseFilter{})
	if err != nil {
		a.t.Fatal(err)
	}
	return len(leases)
}

func TestReadRequestIsIssuedAtOnceAndExpires(t *testing.T) {
	a := newAccessEnv(t, model.RoleGuest)
	req := a.request(accessInput("ecs", "read"))
	if req.Status != model.LeaseActive || req.Permission != "read" || req.Resource != "ecs" ||
		req.CloudAccountID != demoAccountID || req.OwnerID != a.mei.person.ID || req.ResourceName != "" ||
		req.ExpiresAt == nil || !req.ExpiresAt.Equal(a.clock.Now().Add(600*time.Second)) {
		t.Fatalf("unexpected request: %+v", req)
	}
	mint := a.minter.lastRequest(t)
	policy := string(mint.PolicyJSON)
	if mint.DurationSeconds != 600 || !strings.Contains(policy, `"ecs:Describe*"`) || !strings.Contains(policy, `"ram:*"`) ||
		strings.Contains(policy, "StartInstance") || !strings.Contains(policy, "instance/*") {
		t.Fatalf("minted with ttl %d and policy %s", mint.DurationSeconds, policy)
	}
	requireStatus(t, a.credential(req.ID), http.StatusOK)

	// The deadline: issue time + validity period.
	a.clock.Advance(599 * time.Second)
	a.srv.sweepOnce(context.Background())
	requireStatus(t, a.credential(req.ID), http.StatusOK)
	a.clock.Advance(2 * time.Second)
	if rec := a.credential(req.ID); rec.Code == http.StatusOK {
		t.Fatal("credential handed out after its deadline")
	}
	a.srv.sweepOnce(context.Background())
	if got := a.status(req.ID); got != model.LeaseExpired {
		t.Fatalf("status after deadline = %s", got)
	}
	if _, err := a.srv.db.GetLeaseCredential(context.Background(), req.ID); err == nil {
		t.Fatal("stored credential not erased at the deadline")
	}

	// The agent can read its own request, and the event names the owner.
	rec := a.do(http.MethodGet, "/api/v1/agent/access-requests/"+req.ID, a.token, nil)
	requireStatus(t, rec, http.StatusOK)
	events := a.listAudit("lease.requested")
	if len(events) == 0 || events[0].Metadata["owner_id"] != a.mei.person.ID {
		t.Fatalf("request event does not name the owner: %+v", events)
	}
}

func TestRequestAboveOwnersRoleIsDeniedAtOnce(t *testing.T) {
	for _, tc := range []struct {
		role       model.Role
		permission string
	}{{model.RoleGuest, "write"}, {model.RoleGuest, "full"}, {model.RoleMember, "full"}} {
		t.Run(string(tc.role)+" asks "+tc.permission, func(t *testing.T) {
			a := newAccessEnv(t, tc.role)
			req := a.request(accessInput("ecs", tc.permission))
			if req.Status != model.LeaseDenied || !strings.Contains(req.DeniedReason, "does not permit") {
				t.Fatalf("request = %+v", req)
			}
			if a.minter.requestCount() != 0 {
				t.Fatal("a credential was minted")
			}
			// It never reaches approval.
			rec := a.mei.do(http.MethodGet, "/api/v1/me/requests?status=pending", nil)
			if list := decodeEnvelope[listData[model.AccessRequest]](t, rec); list.Total != 0 {
				t.Fatalf("denied request is waiting for approval: %+v", list)
			}
			requireStatus(t, a.approve(a.mei, req.ID), http.StatusConflict)
			if a.minter.requestCount() != 0 || a.status(req.ID) != model.LeaseDenied {
				t.Fatal("a denied request was approved")
			}
		})
	}
}

func TestWriteAndFullWaitForTheOwner(t *testing.T) {
	for _, tc := range []struct {
		role       model.Role
		permission string
		action     string
	}{{model.RoleMember, "write", "ecs:StartInstance"}, {model.RoleAdministrator, "write", "ecs:StartInstance"},
		{model.RoleAdministrator, "full", "ecs:DeleteInstance"}} {
		t.Run(string(tc.role)+" asks "+tc.permission, func(t *testing.T) {
			a := newAccessEnv(t, tc.role)
			jun := a.addPerson(a.sup, "jun", false)
			a.bind(jun, model.RoleAdministrator)
			a.bind(a.sup, model.RoleAdministrator)

			in := accessInput("ecs", tc.permission)
			in.ResourceName = "i-2ze0demo001"
			req := a.request(in)
			if req.Status != model.LeasePending || a.minter.requestCount() != 0 {
				t.Fatalf("request = %+v, mints = %d", req, a.minter.requestCount())
			}
			requireErrorCode(t, a.credential(req.ID), http.StatusConflict, model.ErrCodeLeaseNotActive)

			rec := a.mei.do(http.MethodGet, "/api/v1/me/requests?status=pending", nil)
			list := decodeEnvelope[listData[model.AccessRequest]](t, rec)
			if list.Total != 1 || list.Items[0].ID != req.ID || list.Items[0].ResourceName != "i-2ze0demo001" ||
				list.Items[0].Reason != in.Reason || list.Items[0].TTLSeconds != 600 {
				t.Fatalf("owner's inbox = %+v", list)
			}

			// Nobody but the owner approves: not another administrator of
			// the account, not a supervisor, not the operator token.
			for name, rec := range map[string]*httptest.ResponseRecorder{
				"other administrator": a.approve(jun, req.ID),
				"supervisor":          a.approve(a.sup, req.ID),
				"other person deny":   jun.do(http.MethodPost, "/api/v1/me/requests/"+req.ID+"/deny", nil),
				"other person revoke": jun.do(http.MethodPost, "/api/v1/me/requests/"+req.ID+"/revoke", nil),
			} {
				if rec.Code != http.StatusNotFound {
					t.Errorf("%s: status %d", name, rec.Code)
				}
			}
			requireStatus(t, a.admin(http.MethodPost, "/api/v1/admin/leases/"+req.ID+"/approve", nil), http.StatusConflict)
			if rec := jun.do(http.MethodGet, "/api/v1/me/requests", nil); decodeEnvelope[listData[model.AccessRequest]](t, rec).Total != 0 {
				t.Error("another person sees the request")
			}
			if a.status(req.ID) != model.LeasePending || a.minter.requestCount() != 0 {
				t.Fatal("someone other than the owner approved or changed the request")
			}

			rec = a.approve(a.mei, req.ID)
			requireStatus(t, rec, http.StatusOK)
			approved := decodeEnvelope[model.AccessRequest](t, rec)
			if approved.Status != model.LeaseActive || approved.ApprovedBy != "owner:"+a.mei.person.ID ||
				approved.ExpiresAt == nil || !approved.ExpiresAt.Equal(a.clock.Now().Add(600*time.Second)) {
				t.Fatalf("approved = %+v", approved)
			}
			policy := string(a.minter.lastRequest(t).PolicyJSON)
			if !strings.Contains(policy, `"`+tc.action+`"`) || !strings.Contains(policy, "instance/i-2ze0demo001") ||
				strings.Contains(policy, "instance/*") || !strings.Contains(policy, `"ram:*"`) {
				t.Fatalf("policy = %s", policy)
			}
			if tc.permission == "write" && strings.Contains(policy, "DeleteInstance") {
				t.Fatalf("write policy allows deleting: %s", policy)
			}
			requireStatus(t, a.credential(req.ID), http.StatusOK)
			requireStatus(t, a.approve(a.mei, req.ID), http.StatusConflict) // only once
			if a.minter.requestCount() != 1 {
				t.Fatalf("minted %d times", a.minter.requestCount())
			}
			events := a.listAudit("lease.approved")
			if len(events) != 1 || events[0].ActorType != "person" || events[0].ActorID != a.mei.person.ID ||
				events[0].Metadata["agent_id"] != a.agent.ID {
				t.Fatalf("approval audit = %+v", events)
			}
			a.verifyAudit()
		})
	}
}

func TestAccessRequestValidation(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	before := a.leaseCount()
	bad := map[string]func(*model.AccessRequestInput){
		"no account":           func(in *model.AccessRequestInput) { in.CloudAccountID = "" },
		"no resource":          func(in *model.AccessRequestInput) { in.Resource = "" },
		"unknown resource":     func(in *model.AccessRequestInput) { in.Resource = "ram" },
		"no permission":        func(in *model.AccessRequestInput) { in.Permission = "" },
		"admin permission":     func(in *model.AccessRequestInput) { in.Permission = "admin" },
		"action as resource":   func(in *model.AccessRequestInput) { in.Resource = "ecs:*" },
		"no validity period":   func(in *model.AccessRequestInput) { in.TTLSeconds = 0 },
		"negative period":      func(in *model.AccessRequestInput) { in.TTLSeconds = -5 },
		"below the minimum":    func(in *model.AccessRequestInput) { in.TTLSeconds = provider.MockMinDuration - 1 },
		"above the maximum":    func(in *model.AccessRequestInput) { in.TTLSeconds = 3601 },
		"write with no reason": func(in *model.AccessRequestInput) { in.Reason = "  " },
		"bad resource name":    func(in *model.AccessRequestInput) { in.ResourceName = `i-1","Action":"*` },
		"wildcard name":        func(in *model.AccessRequestInput) { in.ResourceName = "*" },
		"partial wildcard":     func(in *model.AccessRequestInput) { in.ResourceName = "i-*" },
		"long reason":          func(in *model.AccessRequestInput) { in.Reason = strings.Repeat("x", 501) },
	}
	for name, mutate := range bad {
		in := accessInput("ecs", "write")
		mutate(&in)
		if rec := a.requestRaw(a.token, in); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d (%s)", name, rec.Code, rec.Body.String())
		}
	}
	// A read needs no reason; a missing ttl_seconds field is refused.
	rec := a.requestRaw(a.token, map[string]any{"cloud_account_id": demoAccountID, "resource": "ecs", "permission": "read"})
	requireStatus(t, rec, http.StatusBadRequest)
	if a.leaseCount() != before || a.minter.requestCount() != 0 {
		t.Fatal("a malformed request left a record or minted")
	}

	// An unknown account and one the owner has no role on look the same.
	a.unbind(a.mei)
	unbound := a.requestRaw(a.token, accessInput("ecs", "read"))
	in := accessInput("ecs", "read")
	in.CloudAccountID = "9999999999999999"
	unknown := a.requestRaw(a.token, in)
	requireErrorCode(t, unbound, http.StatusForbidden, model.ErrCodeForbidden)
	requireErrorCode(t, unknown, http.StatusForbidden, model.ErrCodeForbidden)
	if strings.Replace(unknown.Body.String(), "9999999999999999", demoAccountID, 1) != unbound.Body.String() {
		t.Fatalf("responses differ:\n%s\n%s", unbound.Body.String(), unknown.Body.String())
	}

	// Agents without an owner cannot use access requests, and the old
	// capability request cannot name an access template.
	requireStatus(t, a.requestRaw(a.agentTokens[demoAgentClaudeCode], accessInput("ecs", "read")), http.StatusForbidden)
	requireStatus(t, a.do(http.MethodPost, "/api/v1/agent/leases", a.agentTokens[demoAgentClaudeCode],
		model.CreateLeaseInput{CapabilityID: "aliyun.access.ecs.full", Params: map[string]string{"resource_name": "*"}}), http.StatusNotFound)
	requireStatus(t, a.requestRaw("", accessInput("ecs", "read")), http.StatusUnauthorized)
	if a.leaseCount() != before {
		t.Fatal("a refused request left a record")
	}
}

func TestLoweringOrRemovingARoleRevokesAtOnce(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	read := a.request(accessInput("ecs", "read"))
	write := a.request(accessInput("dns", "write"))
	requireStatus(t, a.approve(a.mei, write.ID), http.StatusOK)
	pending := a.request(accessInput("ecs", "write"))
	if a.status(read.ID) != model.LeaseActive || a.status(write.ID) != model.LeaseActive || a.status(pending.ID) != model.LeasePending {
		t.Fatal("setup failed")
	}

	// member -> guest: write access goes, read stays.
	a.bind(a.mei, model.RoleGuest)
	if a.status(write.ID) != model.LeaseRevoked || a.status(pending.ID) != model.LeaseRevoked || a.status(read.ID) != model.LeaseActive {
		t.Fatalf("after lowering: read=%s write=%s pending=%s", a.status(read.ID), a.status(write.ID), a.status(pending.ID))
	}
	if rec := a.credential(write.ID); rec.Code == http.StatusOK {
		t.Fatal("write credential still handed out")
	}
	requireStatus(t, a.credential(read.ID), http.StatusOK)
	requireStatus(t, a.approve(a.mei, pending.ID), http.StatusConflict)
	if events := a.listAudit("binding.agent_leases_revoked"); len(events) != 1 {
		t.Fatalf("revocation not audited: %+v", events)
	}

	// Raising a role revokes nothing.
	a.bind(a.mei, model.RoleAdministrator)
	if a.status(read.ID) != model.LeaseActive {
		t.Fatal("raising a role revoked a lease")
	}

	// Removing the binding ends everything on that account.
	a.unbind(a.mei)
	if a.status(read.ID) != model.LeaseRevoked {
		t.Fatalf("after removal: read=%s", a.status(read.ID))
	}
	if rec := a.credential(read.ID); rec.Code == http.StatusOK {
		t.Fatal("credential handed out after the role was removed")
	}
}

// The owner's role is read again at approval and at every credential fetch,
// even if no revocation sweep ran (here the binding changes behind the
// API's back).
func TestRoleIsRecheckedAtApprovalAndFetch(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	ctx := context.Background()
	setRole := func(role model.Role) {
		t.Helper()
		now := a.clock.Now()
		if err := a.srv.db.PutBinding(ctx, model.RoleBinding{PersonID: a.mei.person.ID, ProviderID: a.providerID, Role: role, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	read := a.request(accessInput("ecs", "read"))
	pending := a.request(accessInput("ecs", "write"))

	setRole(model.RoleGuest)
	requireStatus(t, a.approve(a.mei, pending.ID), http.StatusConflict)
	if a.minter.requestCount() != 1 || a.status(pending.ID) == model.LeaseActive {
		t.Fatal("approval minted after the role was lowered")
	}
	requireStatus(t, a.credential(read.ID), http.StatusOK)

	if err := a.srv.db.DeleteBinding(ctx, a.mei.person.ID, a.providerID); err != nil {
		t.Fatal(err)
	}
	if rec := a.credential(read.ID); rec.Code == http.StatusOK {
		t.Fatal("credential handed out with no role on the account")
	}
}

// A role lowered while the credential is being minted: the lease must not
// become active.
func TestRoleLoweredDuringIssuance(t *testing.T) {
	for _, auto := range []bool{true, false} {
		a := newAccessEnv(t, model.RoleMember)
		lower := func(provider.MintRequest) {
			now := a.clock.Now()
			role := model.RoleGuest
			if auto { // a read survives guest; remove the role entirely
				if err := a.srv.db.DeleteBinding(context.Background(), a.mei.person.ID, a.providerID); err != nil {
					t.Error(err)
				}
				return
			}
			if err := a.srv.db.PutBinding(context.Background(), model.RoleBinding{PersonID: a.mei.person.ID, ProviderID: a.providerID, Role: role, CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Error(err)
			}
		}
		var id string
		if auto {
			a.minter.onMint = lower
			rec := a.requestRaw(a.token, accessInput("ecs", "read"))
			requireStatus(t, rec, http.StatusConflict)
			leases, _ := a.srv.db.ListAllLeases(context.Background(), store.LeaseFilter{AgentID: a.agent.ID})
			id = leases[0].ID
		} else {
			req := a.request(accessInput("ecs", "write"))
			id = req.ID
			a.minter.onMint = lower
			requireStatus(t, a.approve(a.mei, id), http.StatusConflict)
		}
		if a.minter.requestCount() != 1 {
			t.Fatalf("auto=%v: mint was not reached", auto)
		}
		if got := a.status(id); got == model.LeaseActive || got == model.LeasePending {
			t.Fatalf("auto=%v: status %s after the role was lowered mid-issuance", auto, got)
		}
		if _, err := a.srv.db.GetLeaseCredential(context.Background(), id); err == nil {
			t.Fatalf("auto=%v: a credential stayed stored", auto)
		}
	}
}

func TestOwnerDeniesAndRevokes(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	first := a.request(accessInput("ecs", "write"))
	rec := a.mei.do(http.MethodPost, "/api/v1/me/requests/"+first.ID+"/deny", model.DenyRequestInput{Reason: "not now"})
	requireStatus(t, rec, http.StatusOK)
	if got := decodeEnvelope[model.AccessRequest](t, rec); got.Status != model.LeaseDenied || got.DeniedReason != "not now" {
		t.Fatalf("denied = %+v", got)
	}
	requireStatus(t, a.approve(a.mei, first.ID), http.StatusConflict)
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/requests/"+first.ID+"/deny", nil), http.StatusConflict)
	if a.minter.requestCount() != 0 {
		t.Fatal("a denied request minted")
	}

	second := a.request(accessInput("ecs", "write"))
	requireStatus(t, a.approve(a.mei, second.ID), http.StatusOK)
	requireStatus(t, a.credential(second.ID), http.StatusOK)
	requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/requests/"+second.ID+"/revoke", nil), http.StatusOK)
	if rec := a.credential(second.ID); rec.Code == http.StatusOK || a.status(second.ID) != model.LeaseRevoked {
		t.Fatal("credential usable after the owner revoked it")
	}

	// A pending request expires if nobody decides.
	third := a.request(accessInput("ecs", "write"))
	a.clock.Advance(time.Duration(model.DefaultPolicySettings().PendingTimeoutSeconds+1) * time.Second)
	requireStatus(t, a.approve(a.mei, third.ID), http.StatusConflict)
	if a.status(third.ID) != model.LeaseExpired {
		t.Fatalf("stale request status = %s", a.status(third.ID))
	}

	// Session-only routes: an agent token is not a session, and writes need
	// the CSRF token.
	fourth := a.request(accessInput("ecs", "write"))
	requireStatus(t, a.do(http.MethodPost, "/api/v1/me/requests/"+fourth.ID+"/approve", a.token, nil), http.StatusUnauthorized)
	requireStatus(t, a.request2(a.mei, fourth.ID), http.StatusForbidden)
	if a.status(fourth.ID) != model.LeasePending {
		t.Fatal("request approved without a valid session and CSRF token")
	}
}

// request2 posts an approval with the session cookie but no CSRF token.
func (a *accessEnv) request2(p *personClient, id string) *httptest.ResponseRecorder {
	return a.testEnv.request(http.MethodPost, "/api/v1/me/requests/"+id+"/approve", p.cookie, nil, nil)
}

func TestAgentAccountsAndReservedIDs(t *testing.T) {
	a := newAccessEnv(t, model.RoleMember)
	rec := a.do(http.MethodGet, "/api/v1/agent/accounts", a.token, nil)
	requireStatus(t, rec, http.StatusOK)
	list := decodeEnvelope[listData[model.AgentAccount]](t, rec)
	if list.Total != 1 || list.Items[0].CloudAccountID != demoAccountID || list.Items[0].Role != model.RoleMember ||
		list.Items[0].HighestPermission != "write" || strings.Join(list.Items[0].Resources, ",") != "dns,ecs,oss" {
		t.Fatalf("accounts = %+v", list)
	}
	rec = a.do(http.MethodGet, "/api/v1/agent/accounts", a.agentTokens[demoAgentHermes], nil)
	if decodeEnvelope[listData[model.AgentAccount]](t, rec).Total != 0 {
		t.Fatal("an agent without an owner sees accounts")
	}

	// The operator cannot define a capability under a reserved ID.
	tpl, _ := capcatalog.LookupAccessTemplate(model.ProviderAliyun, "ecs", capcatalog.PermissionRead)
	forged := tpl.Capability
	forged.PolicyTemplate = `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:DeleteInstance"],"Resource":["*"]}]}`
	requireStatus(t, a.admin(http.MethodPost, "/api/v1/admin/capabilities", forged), http.StatusBadRequest)
	if _, err := a.srv.db.GetCapability(context.Background(), forged.ID); err == nil {
		t.Fatal("a capability with a reserved ID was stored")
	}
}

func TestCloudAccountIsFixedPerProvider(t *testing.T) {
	a := newAccessEnv(t, "")
	other := "acs:ram::6543210987654321:role/elsewhere"
	rec := a.admin(http.MethodPatch, "/api/v1/admin/providers/"+a.providerID, model.UpdateProviderInput{RoleARN: &other})
	requireStatus(t, rec, http.StatusConflict)
	same := "acs:ram::" + demoAccountID + ":role/another-role"
	requireStatus(t, a.admin(http.MethodPatch, "/api/v1/admin/providers/"+a.providerID, model.UpdateProviderInput{RoleARN: &same}), http.StatusOK)

	dup := model.CreateProviderInput{Name: "dup", Type: model.ProviderAliyun, Mode: model.ModeMock, Region: "cn-hangzhou",
		RoleARN: "acs:ram::" + demoAccountID + ":role/dup", AccessKeyID: "LTAI5tDupDupDupDup", AccessKeySecret: "placeholder-secret-value"}
	requireStatus(t, a.admin(http.MethodPost, "/api/v1/admin/providers", dup), http.StatusConflict)
	for arn, want := range map[string]string{
		"acs:ram::1234567890123456:role/x": "1234567890123456", "acs:ram::12:role/x": "", "arn:aws:iam::1:role/x": "",
		"acs:ram::1234567890123456:user/x": "", "": "", "acs:ram::1234567890123456:role/": "",
	} {
		if got := model.CloudAccountIDFromRoleARN(model.ProviderAliyun, arn); got != want {
			t.Errorf("account of %q = %q, want %q", arn, got, want)
		}
	}
}

// A person approves only access requests. A capability lease of the older
// kind held by their agent (granted by the operator) stays with the operator.
func TestOwnerCannotApproveOperatorLeases(t *testing.T) {
	a := newAccessEnv(t, model.RoleAdministrator)
	role, grants := model.RoleMember, []string{capcatalog.IDDNSManage}
	requireStatus(t, a.admin(http.MethodPatch, "/api/v1/admin/agents/"+a.agent.ID,
		model.UpdateAgentInput{Role: &role, Grants: &grants}), http.StatusOK)
	rec := a.do(http.MethodPost, "/api/v1/agent/leases", a.token, model.CreateLeaseInput{
		CapabilityID: capcatalog.IDDNSManage, Params: map[string]string{"domain": "example.com"}, Reason: "dns change",
	})
	requireStatus(t, rec, http.StatusCreated)
	lease := decodeEnvelope[model.Lease](t, rec)
	if lease.Status != model.LeasePending {
		t.Fatalf("lease status = %s", lease.Status)
	}
	for _, action := range []string{"approve", "deny", "revoke"} {
		requireStatus(t, a.mei.do(http.MethodPost, "/api/v1/me/requests/"+lease.ID+"/"+action, nil), http.StatusNotFound)
	}
	if a.status(lease.ID) != model.LeasePending || a.minter.requestCount() != 0 {
		t.Fatal("the owner decided an operator lease")
	}
	if rec := a.mei.do(http.MethodGet, "/api/v1/me/requests", nil); decodeEnvelope[listData[model.AccessRequest]](t, rec).Total != 0 {
		t.Fatal("an operator lease is listed as an access request")
	}
	requireStatus(t, a.admin(http.MethodPost, "/api/v1/admin/leases/"+lease.ID+"/approve", nil), http.StatusOK)
}
