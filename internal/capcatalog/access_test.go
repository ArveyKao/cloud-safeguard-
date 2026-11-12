package capcatalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

func TestClassifyAction(t *testing.T) {
	for action, want := range map[string]Permission{
		"ecs:DescribeInstances":     PermissionRead,
		"ecs:Describe*":             PermissionRead,
		"oss:List*":                 PermissionRead,
		"oss:GetObject":             PermissionRead,
		"alidns:QueryThing":         PermissionRead,
		"sts:GetCallerIdentity":     PermissionRead,
		"ecs:StartInstance":         PermissionWrite,
		"alidns:AddDomainRecord":    PermissionWrite,
		"alidns:DeleteDomainRecord": PermissionWrite, // an item inside a domain
		"oss:PutObject":             PermissionWrite,
		"oss:DeleteObject":          PermissionWrite,
		"ecs:RunInstances":          PermissionFull,
		"ecs:DeleteInstance":        PermissionFull,
		"alidns:AddDomain":          PermissionFull,
		"alidns:DeleteDomain":       PermissionFull,
		"oss:DeleteBucket":          PermissionFull,
		// Fail towards full: unknown, wildcard and odd actions.
		"ecs:SomethingNew":      PermissionFull,
		"ecs:*":                 PermissionFull,
		"ecs:Start*":            PermissionFull,
		"ecs:Delete*":           PermissionFull,
		"*":                     PermissionFull,
		"ecs:Describe*Instance": PermissionFull,
		"ecs:describeInstances": PermissionFull,
		"":                      PermissionFull,
	} {
		if got := classifyAction(action); got != want {
			t.Errorf("classifyAction(%q) = %s, want %s", action, got, want)
		}
	}
}

// templateActions returns the Allow actions of a rendered template.
func templateActions(t *testing.T, raw []byte) []string {
	t.Helper()
	var doc struct {
		Statement []struct {
			Effect string
			Action json.RawMessage
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, st := range doc.Statement {
		if st.Effect != "Allow" {
			continue
		}
		var actions []string
		if err := json.Unmarshal(st.Action, &actions); err != nil {
			t.Fatal(err)
		}
		out = append(out, actions...)
	}
	return out
}

func TestEveryAccessTemplateRendersWithinItsLevel(t *testing.T) {
	if len(accessTemplates) != len(resourceSpecs)*3 {
		t.Fatalf("%d templates for %d resource types", len(accessTemplates), len(resourceSpecs))
	}
	for id, tpl := range accessTemplates {
		for _, name := range []string{AllResources, SampleParams(tpl.Capability)[ResourceNameParam]} {
			raw, err := RenderPolicy(tpl.Capability, map[string]string{ResourceNameParam: name})
			if err != nil {
				t.Errorf("%s with %q: %v", id, name, err)
				continue
			}
			if !strings.Contains(string(raw), `"ram:*"`) {
				t.Errorf("%s: no IAM deny statement", id)
			}
			for _, action := range templateActions(t, raw) {
				if need := classifyAction(action); need.Rank() > tpl.Permission.Rank() {
					t.Errorf("%s allows %s, which needs %s", id, action, need)
				}
			}
		}
		if tpl.Capability.Access != tpl.Permission.Access() {
			t.Errorf("%s: access %s for permission %s", id, tpl.Capability.Access, tpl.Permission)
		}
	}
	// Each level adds something, and never drops what the lower level had.
	for _, spec := range resourceSpecs {
		prev := 0
		for _, p := range Permissions() {
			tpl, ok := LookupAccessTemplate(spec.provider, spec.resource, p)
			if !ok {
				t.Fatalf("no template for %s %s", spec.resource, p)
			}
			raw, _ := RenderPolicy(tpl.Capability, map[string]string{ResourceNameParam: AllResources})
			n := len(templateActions(t, raw))
			if n <= prev {
				t.Errorf("%s %s has %d actions, lower level had %d", spec.resource, p, n, prev)
			}
			prev = n
		}
	}
}

func TestRolePermissionLadder(t *testing.T) {
	want := map[model.Role]Permission{
		model.RoleGuest: PermissionRead, model.RoleMember: PermissionWrite, model.RoleAdministrator: PermissionFull,
	}
	for role, highest := range want {
		for _, p := range Permissions() {
			if got := role.Permits(p.Access()); got != (p.Rank() <= highest.Rank()) {
				t.Errorf("%s permits %s = %v", role, p, got)
			}
		}
	}
	if Permission("admin").Valid() || Permission("").Access() != "" {
		t.Error("unknown permission accepted")
	}
}

func TestResourceNameValidation(t *testing.T) {
	tpl, _ := LookupAccessTemplate(model.ProviderAliyun, "dns", PermissionWrite)
	for name, ok := range map[string]bool{
		"*": true, "example.com": true, "a.b.example.com": true,
		"": false, "**": false, "*.example.com": false, "example.com/*": false,
		`x","Action":"*`: false, "EXAMPLE.com": false,
	} {
		err := ValidateParams(tpl.Capability, map[string]string{ResourceNameParam: name})
		if (err == nil) != ok {
			t.Errorf("resource name %q: err=%v, want ok=%v", name, err, ok)
		}
	}
}

// A capability that borrows a reserved ID, or a template edited above its
// level, never renders.
func TestAccessTemplateIDsAreReserved(t *testing.T) {
	tpl, _ := LookupAccessTemplate(model.ProviderAliyun, "ecs", PermissionWrite)
	params := map[string]string{ResourceNameParam: AllResources}

	forged := tpl.Capability
	forged.PolicyTemplate = strings.Replace(forged.PolicyTemplate, `"ecs:StartInstance"`, `"ecs:DeleteInstance"`, 1)
	if _, err := RenderPolicy(forged, params); err == nil {
		t.Error("an edited access template rendered")
	}
	raised := tpl.Capability
	raised.Access = model.AccessAdmin
	if _, err := RenderPolicy(raised, params); err == nil {
		t.Error("an access template with a raised access level rendered")
	}
	unknown := tpl.Capability
	unknown.ID = "aliyun.access.ecs.everything"
	if _, err := RenderPolicy(unknown, params); err == nil {
		t.Error("an unknown reserved ID rendered")
	}
	if !IsAccessTemplateID(tpl.Capability.ID) || IsAccessTemplateID(IDDNSManage) || IsAccessTemplateID(IDECSOps) {
		t.Error("reserved ID detection is wrong")
	}
	for _, c := range Builtin() {
		if IsAccessTemplateID(c.ID) {
			t.Errorf("built-in capability %s uses a reserved ID", c.ID)
		}
	}

	// The level check itself: a write template that allows a full action, or
	// an action of another service, is refused.
	for _, action := range []string{"ecs:DeleteInstance", "ecs:*", "oss:PutObject"} {
		doc := `{"Version":"1","Statement":[{"Effect":"Allow","Action":["` + action + `"],"Resource":["*"]}]}`
		if err := CheckAccessTemplateLevel(tpl, []byte(doc)); err == nil {
			t.Errorf("level check accepted %s in an ecs write template", action)
		}
	}
}

// The exact actions of every template, written out independently of the
// classification code. Changing a template means changing this list, which
// is the point: a reviewer sees the action that was added.
func TestAccessTemplateActionsAreExactlyAsReviewed(t *testing.T) {
	want := map[string][]string{
		"aliyun.access.ecs.read":  {"ecs:Describe*"},
		"aliyun.access.ecs.write": {"ecs:Describe*", "ecs:StartInstance", "ecs:StopInstance", "ecs:RebootInstance"},
		"aliyun.access.ecs.full": {"ecs:Describe*", "ecs:StartInstance", "ecs:StopInstance", "ecs:RebootInstance",
			"ecs:RunInstances", "ecs:CreateInstance", "ecs:DeleteInstance"},
		"aliyun.access.dns.read": {"alidns:Describe*"},
		"aliyun.access.dns.write": {"alidns:Describe*", "alidns:AddDomainRecord", "alidns:UpdateDomainRecord",
			"alidns:DeleteDomainRecord", "alidns:SetDomainRecordStatus"},
		"aliyun.access.dns.full": {"alidns:Describe*", "alidns:AddDomainRecord", "alidns:UpdateDomainRecord",
			"alidns:DeleteDomainRecord", "alidns:SetDomainRecordStatus", "alidns:AddDomain", "alidns:DeleteDomain"},
		"aliyun.access.oss.read":  {"oss:Get*", "oss:List*"},
		"aliyun.access.oss.write": {"oss:Get*", "oss:List*", "oss:PutObject", "oss:DeleteObject", "oss:AbortMultipartUpload"},
		"aliyun.access.oss.full": {"oss:Get*", "oss:List*", "oss:PutObject", "oss:DeleteObject", "oss:AbortMultipartUpload",
			"oss:PutBucket", "oss:DeleteBucket"},
	}
	if len(want) != len(accessTemplates) {
		t.Fatalf("%d templates reviewed, %d defined", len(want), len(accessTemplates))
	}
	for id, actions := range want {
		tpl, ok := AccessTemplateByID(id)
		if !ok {
			t.Errorf("no template %s", id)
			continue
		}
		raw, err := RenderPolicy(tpl.Capability, map[string]string{ResourceNameParam: AllResources})
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		if got := strings.Join(templateActions(t, raw), " "); got != strings.Join(actions, " ") {
			t.Errorf("%s allows\n  %s\nreviewed\n  %s", id, got, strings.Join(actions, " "))
		}
	}
	// Never in any template: it can set an instance's login password.
	for id, tpl := range accessTemplates {
		if strings.Contains(tpl.Capability.PolicyTemplate, "ModifyInstanceAttribute") {
			t.Errorf("%s allows ecs:ModifyInstanceAttribute", id)
		}
	}
}

// A stored row that borrows a reserved ID and the exact template text, but
// loosens the parameter rule, does not render.
func TestReservedIDWithLooserParamsIsRefused(t *testing.T) {
	tpl, _ := LookupAccessTemplate(model.ProviderAliyun, "ecs", PermissionRead)
	loose := tpl.Capability
	loose.Params = []model.CapabilityParam{{Name: ResourceNameParam, Required: true, Pattern: ".*"}}
	if _, err := RenderPolicy(loose, map[string]string{ResourceNameParam: "*/*"}); err == nil {
		t.Error("a reserved ID with a looser parameter pattern rendered")
	}
	noParams := tpl.Capability
	noParams.Params = nil
	if _, err := RenderPolicy(noParams, nil); err == nil {
		t.Error("a reserved ID without parameters rendered")
	}
	for name, ok := range map[string]bool{"i-" + strings.Repeat("a", 62): true, "i-" + strings.Repeat("a", 63): false} {
		err := ValidateParams(tpl.Capability, map[string]string{ResourceNameParam: name})
		if (err == nil) != ok {
			t.Errorf("instance id of %d characters: %v", len(name), err)
		}
	}
}
