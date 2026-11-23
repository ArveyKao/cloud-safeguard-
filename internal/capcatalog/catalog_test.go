package capcatalog

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// expectedPolicyTemplates are the exact compact policy templates from
// docs/CONTRACT.md §7. They are acceptance-relevant: the demo and the mock
// cloud rely on their IAM actions and resources.
var expectedPolicyTemplates = map[string]string{
	IDCloudRead:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:Describe*","alidns:Describe*","oss:List*","sts:GetCallerIdentity"],"Resource":["*"]}]}`,
	IDDNSManage:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":["alidns:DescribeDomainRecords","alidns:AddDomainRecord","alidns:UpdateDomainRecord","alidns:DeleteDomainRecord","alidns:SetDomainRecordStatus"],"Resource":["acs:alidns:*:*:domain/{{domain}}"]}]}`,
	IDCertDNS01:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":["alidns:DescribeDomainRecords","alidns:AddDomainRecord","alidns:DeleteDomainRecord"],"Resource":["acs:alidns:*:*:domain/{{domain}}"]}]}`,
	IDECSOps:       `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:StartInstance","ecs:StopInstance","ecs:RebootInstance","ecs:DescribeInstances"],"Resource":["acs:ecs:*:*:instance/{{instance_id}}"]}]}`,
	IDAccountAdmin: `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
}

func TestBuiltinCatalogIsExact(t *testing.T) {
	caps := Builtin()
	if len(caps) != 5 {
		t.Fatalf("Builtin() returned %d capabilities, want 5", len(caps))
	}

	want := map[string]struct {
		risk       model.RiskTier
		access     model.AccessLevel
		defaultTTL int
		maxTTL     int
		paramNames []string
	}{
		IDCloudRead:    {model.RiskLow, model.AccessRead, 900, 1800, nil},
		IDDNSManage:    {model.RiskMedium, model.AccessWrite, 900, 1800, []string{"domain"}},
		IDCertDNS01:    {model.RiskMedium, model.AccessWrite, 600, 1200, []string{"domain"}},
		IDECSOps:       {model.RiskHigh, model.AccessWrite, 900, 1800, []string{"instance_id"}},
		IDAccountAdmin: {model.RiskCritical, model.AccessAdmin, 900, 1800, nil},
	}

	seen := make(map[string]bool, len(caps))
	for _, c := range caps {
		if seen[c.ID] {
			t.Fatalf("duplicate capability ID %q", c.ID)
		}
		seen[c.ID] = true

		spec, ok := want[c.ID]
		if !ok {
			t.Fatalf("unexpected capability ID %q", c.ID)
		}
		if c.Name == "" {
			t.Errorf("%s: empty name", c.ID)
		}
		if c.Description == "" {
			t.Errorf("%s: empty description", c.ID)
		}
		if c.ProviderType != model.ProviderAliyun {
			t.Errorf("%s: provider type = %q, want aliyun", c.ID, c.ProviderType)
		}
		if c.Risk != spec.risk {
			t.Errorf("%s: risk = %q, want %q", c.ID, c.Risk, spec.risk)
		}
		if c.Access != spec.access {
			t.Errorf("%s: access = %q, want %q", c.ID, c.Access, spec.access)
		}
		if !c.Enabled || !c.Builtin {
			t.Errorf("%s: enabled=%v builtin=%v, want both true", c.ID, c.Enabled, c.Builtin)
		}
		if c.DefaultTTLSeconds != spec.defaultTTL {
			t.Errorf("%s: default ttl = %d, want %d", c.ID, c.DefaultTTLSeconds, spec.defaultTTL)
		}
		if c.MaxTTLSeconds != spec.maxTTL {
			t.Errorf("%s: max ttl = %d, want %d", c.ID, c.MaxTTLSeconds, spec.maxTTL)
		}
		if c.MaxTTLSeconds <= c.DefaultTTLSeconds {
			t.Errorf("%s: max ttl %d must exceed default %d", c.ID, c.MaxTTLSeconds, c.DefaultTTLSeconds)
		}

		var gotNames []string
		for _, p := range c.Params {
			gotNames = append(gotNames, p.Name)
			if p.Description == "" {
				t.Errorf("%s param %s: empty description", c.ID, p.Name)
			}
			if !p.Required {
				t.Errorf("%s param %s: should be required", c.ID, p.Name)
			}
			if p.Pattern == "" {
				t.Errorf("%s param %s: missing pattern", c.ID, p.Name)
			}
		}
		if !reflect.DeepEqual(gotNames, spec.paramNames) {
			t.Errorf("%s: params = %v, want %v", c.ID, gotNames, spec.paramNames)
		}

		if c.PolicyTemplate != expectedPolicyTemplates[c.ID] {
			t.Errorf("%s: policy template mismatch\n got: %s\nwant: %s", c.ID, c.PolicyTemplate, expectedPolicyTemplates[c.ID])
		}
		if !json.Valid([]byte(c.PolicyTemplate)) {
			t.Errorf("%s: policy template is not valid JSON: %s", c.ID, c.PolicyTemplate)
		}
	}

	for id := range want {
		if !seen[id] {
			t.Errorf("missing built-in capability %q", id)
		}
	}
}

func TestBuiltinReturnsDefensiveCopy(t *testing.T) {
	first := Builtin()
	first[0].Name = "mutated"
	first[0].Enabled = false
	if len(first) > 0 && len(Builtin()[0].Params) > 0 {
		first[0].Params[0].Name = "mutated"
	}
	first[1].Params[0].Pattern = "mutated"

	second := Builtin()
	if second[0].Name == "mutated" || !second[0].Enabled {
		t.Fatalf("Builtin() leaked mutations of a previous return value")
	}
	if second[1].Params[0].Pattern == "mutated" {
		t.Fatalf("Builtin() leaked mutation of a nested params slice")
	}
}

func TestLookup(t *testing.T) {
	for id := range expectedPolicyTemplates {
		got, ok := Lookup(id)
		if !ok {
			t.Fatalf("Lookup(%q) = not found", id)
		}
		if got.ID != id {
			t.Fatalf("Lookup(%q).ID = %q", id, got.ID)
		}
	}
	if _, ok := Lookup("does.not.exist"); ok {
		t.Fatalf("Lookup of unknown ID returned ok")
	}
	// The retired break-glass capability is no longer part of the catalog
	// (CONTRACT §16.2); only the stored row of an upgraded install keeps it.
	if _, ok := Lookup(IDBreakGlass); ok {
		t.Fatalf("Lookup(%q) still returns a seeded capability", IDBreakGlass)
	}
}

func TestValidateParams(t *testing.T) {
	read, _ := Lookup(IDCloudRead)
	dns, _ := Lookup(IDDNSManage)
	ecs, _ := Lookup(IDECSOps)

	custom := model.Capability{
		ID: "cap_custom",
		Params: []model.CapabilityParam{
			{Name: "required", Required: true, Pattern: `^[a-z]+$`},
			{Name: "optional", Required: false, Pattern: `^[0-9]+$`},
			{Name: "free"},
		},
	}

	tests := []struct {
		name    string
		cap     model.Capability
		params  map[string]string
		wantErr string // substring; empty means no error
	}{
		{"no params for paramless cap", read, nil, ""},
		{"empty map for paramless cap", read, map[string]string{}, ""},
		{"unknown param", read, map[string]string{"foo": "bar"}, "unknown parameter"},
		{"missing required domain", dns, nil, "missing required parameter"},
		{"empty required domain", dns, map[string]string{"domain": ""}, "missing required parameter"},
		{"whitespace required domain", dns, map[string]string{"domain": "  "}, "missing required parameter"},
		{"valid domain", dns, map[string]string{"domain": "arveykao.com"}, ""},
		{"valid subdomain", dns, map[string]string{"domain": "a.b-c.example.org"}, ""},
		{"invalid domain uppercase", dns, map[string]string{"domain": "Arveykao.com"}, "invalid value"},
		{"invalid domain empty label", dns, map[string]string{"domain": "a..b"}, "invalid value"},
		{"invalid domain leading dash", dns, map[string]string{"domain": "-bad.com"}, "invalid value"},
		{"injection attempt via domain", dns, map[string]string{"domain": `evil.com"]}]},{"Effect":"Allow"`}, "invalid value"},
		{"valid instance id", ecs, map[string]string{"instance_id": "i-2ze0demo001"}, ""},
		{"invalid instance id", ecs, map[string]string{"instance_id": "i-abc; rm -rf /"}, "invalid value"},
		{"unknown param on parameterized cap", dns, map[string]string{"domain": "a.com", "x": "y"}, "unknown parameter"},
		{"custom required missing", custom, map[string]string{"optional": "12"}, "missing required parameter"},
		{"custom required ok", custom, map[string]string{"required": "abc"}, ""},
		{"custom optional pattern violation", custom, map[string]string{"required": "abc", "optional": "x"}, "invalid value"},
		{"custom optional present ok", custom, map[string]string{"required": "abc", "optional": "12"}, ""},
		{"custom optional absent ok", custom, map[string]string{"required": "abc", "free": "anything"}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateParams(tc.cap, tc.params)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateParams() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateParams() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateParams() error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateParamsRejectsInvalidPattern(t *testing.T) {
	cap := model.Capability{
		ID:     "cap_broken",
		Params: []model.CapabilityParam{{Name: "x", Pattern: `(`}},
	}
	err := ValidateParams(cap, map[string]string{"x": "value"})
	if err == nil || !strings.Contains(err.Error(), "invalid pattern") {
		t.Fatalf("ValidateParams() error = %v, want invalid pattern error", err)
	}
}

func TestRenderPolicyAllBuiltins(t *testing.T) {
	samples := map[string]map[string]string{
		IDCloudRead:    nil,
		IDDNSManage:    {"domain": "arveykao.com"},
		IDCertDNS01:    {"domain": "example.org"},
		IDECSOps:       {"instance_id": "i-2ze0demo001"},
		IDAccountAdmin: nil,
	}

	for _, cap := range Builtin() {
		params := samples[cap.ID]
		if err := ValidateParams(cap, params); err != nil {
			t.Fatalf("%s: sample params invalid: %v", cap.ID, err)
		}
		out, err := RenderPolicy(cap, params)
		if err != nil {
			t.Fatalf("%s: RenderPolicy() error = %v", cap.ID, err)
		}
		if !json.Valid(out) {
			t.Fatalf("%s: rendered policy is not valid JSON: %s", cap.ID, out)
		}
		if strings.Contains(string(out), "{{") {
			t.Fatalf("%s: rendered policy still contains a placeholder: %s", cap.ID, out)
		}
		if strings.ContainsAny(string(out), "\n\t") {
			t.Fatalf("%s: rendered policy is not compact: %q", cap.ID, out)
		}

		// Rendered policy must be structurally a valid IAM policy.
		var doc struct {
			Version   string `json:"Version"`
			Statement []struct {
				Effect   string          `json:"Effect"`
				Action   json.RawMessage `json:"Action"`
				Resource json.RawMessage `json:"Resource"`
			} `json:"Statement"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("%s: cannot unmarshal rendered policy: %v", cap.ID, err)
		}
		if doc.Version != "1" {
			t.Fatalf("%s: rendered Version = %q, want 1", cap.ID, doc.Version)
		}
		if len(doc.Statement) == 0 {
			t.Fatalf("%s: rendered policy has no statements", cap.ID)
		}
	}
}

func TestRenderPolicySubstitutesCorrectResource(t *testing.T) {
	dns, _ := Lookup(IDDNSManage)
	out, err := RenderPolicy(dns, map[string]string{"domain": "arveykao.com"})
	if err != nil {
		t.Fatalf("RenderPolicy() error = %v", err)
	}
	if !strings.Contains(string(out), `"acs:alidns:*:*:domain/arveykao.com"`) {
		t.Fatalf("rendered policy does not scope to the requested domain: %s", out)
	}

	ecs, _ := Lookup(IDECSOps)
	out, err = RenderPolicy(ecs, map[string]string{"instance_id": "i-2ze0demo003"})
	if err != nil {
		t.Fatalf("RenderPolicy() error = %v", err)
	}
	if !strings.Contains(string(out), `"acs:ecs:*:*:instance/i-2ze0demo003"`) {
		t.Fatalf("rendered policy does not scope to the requested instance: %s", out)
	}
}

func TestRenderPolicyErrors(t *testing.T) {
	// The base template allows a bare "*", so it is only renderable at admin
	// access (CONTRACT §16.3 rule 2).
	base := model.Capability{
		ID:             "cap_test",
		Access:         model.AccessAdmin,
		PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":["{{res}}"]}]}`,
		Params:         []model.CapabilityParam{{Name: "res"}},
	}

	tests := []struct {
		name    string
		cap     model.Capability
		params  map[string]string
		wantErr string
	}{
		{"empty template", model.Capability{ID: "cap_empty", Access: model.AccessAdmin}, nil, "empty policy template"},
		{"missing value", base, nil, "missing value"},
		{"empty value", base, map[string]string{"res": ""}, "missing value"},
		{"undeclared placeholder", base, map[string]string{"res": "*", "other": "x"}, ""}, // extra params are harmless
		{
			"template references undeclared param",
			model.Capability{ID: "cap_u", Access: model.AccessAdmin, PolicyTemplate: `{"x":"{{nope}}"}`},
			map[string]string{"nope": "v"},
			"undeclared parameter",
		},
		{
			"malformed placeholder",
			model.Capability{ID: "cap_m", Access: model.AccessAdmin, PolicyTemplate: `{"x":"{{ res }}"}`},
			map[string]string{"res": "v"},
			"unresolved placeholder",
		},
		{
			"invalid JSON template",
			model.Capability{ID: "cap_bad", Access: model.AccessAdmin, PolicyTemplate: `not json`},
			nil,
			"valid JSON",
		},
		{
			"unquoted placeholder yields invalid JSON",
			model.Capability{
				ID: "cap_raw", Access: model.AccessAdmin, PolicyTemplate: `{"x":{{v}}}`,
				Params: []model.CapabilityParam{{Name: "v"}},
			},
			map[string]string{"v": "abc"},
			"valid JSON",
		},
		{
			"invalid access level fails closed",
			model.Capability{
				ID: "cap_noaccess", PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:DescribeInstances"],"Resource":"*"}]}`,
			},
			nil,
			"not valid",
		},
		{
			"read template that allows a write action is rejected",
			model.Capability{
				ID: "cap_read_write", Access: model.AccessRead,
				PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:StopInstance"],"Resource":"*"}]}`,
			},
			nil,
			"ecs:StopInstance",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := RenderPolicy(tc.cap, tc.params)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("RenderPolicy() error = %v, want nil", err)
				}
				if !json.Valid(out) {
					t.Fatalf("RenderPolicy() = invalid JSON: %s", out)
				}
				return
			}
			if err == nil {
				t.Fatalf("RenderPolicy() = %s, want error containing %q", out, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("RenderPolicy() error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestRenderPolicyEscapesInjectedStructures(t *testing.T) {
	cap := model.Capability{
		ID:             "cap_inject",
		Access:         model.AccessAdmin,
		PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":["{{res}}"]}]}`,
		Params:         []model.CapabilityParam{{Name: "res"}},
	}
	attack := `*"]}]},{"Effect":"Allow","Action":"*","Resource":["*`

	out, err := RenderPolicy(cap, map[string]string{"res": attack})
	if err != nil {
		t.Fatalf("RenderPolicy() error = %v", err)
	}
	if !json.Valid(out) {
		t.Fatalf("injected value broke JSON validity: %s", out)
	}

	// Resource may be a string ("*") or an array; the mandatory Deny uses the
	// string form, so the decode type must accept both.
	var doc struct {
		Statement []struct {
			Effect   string          `json:"Effect"`
			Resource json.RawMessage `json:"Resource"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal rendered policy: %v", err)
	}
	// One Allow statement from the template plus the mandatory deny (§16.3).
	if len(doc.Statement) != 2 {
		t.Fatalf("injection changed the statement count: got %d, want 2", len(doc.Statement))
	}
	resources, err := jsonStringList(doc.Statement[0].Resource)
	if err != nil {
		t.Fatalf("decode Allow Resource: %v", err)
	}
	if len(resources) != 1 || resources[0] != attack {
		t.Fatalf("injected value was not preserved as a literal string: %+v", resources)
	}
	if doc.Statement[1].Effect != "Deny" {
		t.Fatalf("second statement = %+v, want the mandatory deny", doc.Statement[1])
	}
	if _, err := jsonStringList(doc.Statement[1].Resource); err != nil {
		t.Fatalf("decode Deny Resource: %v", err)
	}
	if strings.Contains(string(out), `},{"Effect":"Allow"`) {
		t.Fatalf("injection escaped its string literal: %s", out)
	}
}

func TestRenderPolicyNoParamsForStaticTemplate(t *testing.T) {
	admin, ok := Lookup(IDAccountAdmin)
	if !ok {
		t.Fatalf("Lookup(%q) = not found", IDAccountAdmin)
	}
	out, err := RenderPolicy(admin, nil)
	if err != nil {
		t.Fatalf("RenderPolicy() error = %v", err)
	}
	want := `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},` + DenyStatement + `]}`
	if string(out) != want {
		t.Fatalf("RenderPolicy() = %s, want %s", out, want)
	}
}

// A template without statements is rejected even though the appended deny
// statement would make the final document non-empty (QA finding).
func TestRenderPolicyRejectsEmptyStatementList(t *testing.T) {
	for _, tmpl := range []string{
		`{"Version":"1","Statement":[]}`,
		`{"Version":"1","Statement":null}`,
	} {
		c := model.Capability{ID: "cap_empty", Access: model.AccessRead, PolicyTemplate: tmpl}
		if out, err := RenderPolicy(c, nil); err == nil {
			t.Errorf("%s rendered to %s", tmpl, out)
		}
	}
}
