// Package capcatalog ships the built-in least-privilege capability catalog and
// renders parameterized IAM policy templates into concrete policy documents.
//
// FROZEN CONTRACT: Builtin, Lookup, RenderPolicy and ValidateParams are
// consumed by the HTTP server (demo seeding, lease minting) and the CLI.
package capcatalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Built-in capability IDs. They are part of the demo/acceptance contract and
// must never change between releases within v0.1.
const (
	IDCloudRead    = "aliyun.cloud.read"
	IDDNSManage    = "aliyun.dns.manage"
	IDCertDNS01    = "aliyun.cert.dns01"
	IDECSOps       = "aliyun.ecs.instance.ops"
	IDAccountAdmin = "aliyun.account.admin"

	// IDBreakGlass is retired (CONTRACT §16.2): it is no longer seeded and is
	// replaced by IDAccountAdmin. The ID is kept because historic leases
	// reference it, the schema-2 migration disables the row instead of deleting
	// it, and every startup revokes leases that still point at it.
	IDBreakGlass = "aliyun.iam.break_glass"
)

// Parameter patterns of the built-in capabilities (RE2). They are exported so
// the server can render sample params for validation and the docs stay in
// sync with the catalog.
const (
	// DomainPattern matches a lower-case DNS name with at least two labels.
	DomainPattern = `^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`
	// InstanceIDPattern matches an ECS instance ID such as i-2ze0demo001.
	InstanceIDPattern = `^i-[A-Za-z0-9]+$`
)

// placeholderRE matches {{param}} placeholders inside a policy template.
var placeholderRE = regexp.MustCompile(`\{\{([A-Za-z_][A-Za-z0-9_]*)\}\}`)

// literalPlaceholderRE matches any remaining {{...}} construct after
// substitution; it is used to reject malformed templates instead of silently
// shipping an unrendered placeholder.
var literalPlaceholderRE = regexp.MustCompile(`\{\{[^{}]*\}\}`)

// builtinSpecs is the frozen catalog from docs/CONTRACT.md §7. CreatedAt /
// UpdatedAt and Enabled are filled in by Builtin / the server seed path.
var builtinSpecs = []model.Capability{
	{
		ID:           IDCloudRead,
		Name:         "Cloud read-only inventory",
		Description:  "Read-only inventory across ECS, DNS, OSS and the caller identity; use for discovery, inspection and safe diagnostics.",
		ProviderType: model.ProviderAliyun,
		Risk:         model.RiskLow,
		Access:       model.AccessRead,
		PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow",` +
			`"Action":["ecs:Describe*","alidns:Describe*","oss:List*","sts:GetCallerIdentity"],` +
			`"Resource":["*"]}]}`,
		DefaultTTLSeconds: 900,
		MaxTTLSeconds:     1800,
		Enabled:           true,
		Builtin:           true,
	},
	{
		ID:           IDDNSManage,
		Name:         "Manage DNS records for one domain",
		Description:  "Create, update, enable/disable and delete DNS records for a single domain; use for approved DNS changes.",
		ProviderType: model.ProviderAliyun,
		Risk:         model.RiskMedium,
		Access:       model.AccessWrite,
		PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow",` +
			`"Action":["alidns:DescribeDomainRecords","alidns:AddDomainRecord","alidns:UpdateDomainRecord","alidns:DeleteDomainRecord","alidns:SetDomainRecordStatus"],` +
			`"Resource":["acs:alidns:*:*:domain/{{domain}}"]}]}`,
		Params: []model.CapabilityParam{
			{
				Name:        "domain",
				Description: "Domain name to manage (e.g. example.com)",
				Required:    true,
				Pattern:     DomainPattern,
			},
		},
		DefaultTTLSeconds: 900,
		MaxTTLSeconds:     1800,
		Enabled:           true,
		Builtin:           true,
	},
	{
		ID:           IDCertDNS01,
		Name:         "ACME DNS-01 challenge token for one domain",
		Description:  "Publish and clean up ACME DNS-01 challenge records for a single domain; use for certificate issuance and renewal.",
		ProviderType: model.ProviderAliyun,
		Risk:         model.RiskMedium,
		Access:       model.AccessWrite,
		PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow",` +
			`"Action":["alidns:DescribeDomainRecords","alidns:AddDomainRecord","alidns:DeleteDomainRecord"],` +
			`"Resource":["acs:alidns:*:*:domain/{{domain}}"]}]}`,
		Params: []model.CapabilityParam{
			{
				Name:        "domain",
				Description: "Domain name the certificate is issued for (e.g. example.com)",
				Required:    true,
				Pattern:     DomainPattern,
			},
		},
		DefaultTTLSeconds: 600,
		MaxTTLSeconds:     1200,
		Enabled:           true,
		Builtin:           true,
	},
	{
		ID:           IDECSOps,
		Name:         "Start/stop/restart one ECS instance",
		Description:  "Start, stop or reboot a single ECS instance; use for runbook-driven instance maintenance.",
		ProviderType: model.ProviderAliyun,
		Risk:         model.RiskHigh,
		Access:       model.AccessWrite,
		PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow",` +
			`"Action":["ecs:StartInstance","ecs:StopInstance","ecs:RebootInstance","ecs:DescribeInstances"],` +
			`"Resource":["acs:ecs:*:*:instance/{{instance_id}}"]}]}`,
		Params: []model.CapabilityParam{
			{
				Name:        "instance_id",
				Description: "ECS instance ID to operate on (e.g. i-2ze0demo001)",
				Required:    true,
				Pattern:     InstanceIDPattern,
			},
		},
		DefaultTTLSeconds: 900,
		MaxTTLSeconds:     1800,
		Enabled:           true,
		Builtin:           true,
	},
	{
		ID:           IDAccountAdmin,
		Name:         "Emergency account-wide access, IAM excluded",
		Description:  "Emergency account-wide access for incident response, with RAM/IAM and sts:AssumeRole always denied; requires break_glass=true and explicit human approval, and every action is audited at critical severity.",
		ProviderType: model.ProviderAliyun,
		Risk:         model.RiskCritical,
		Access:       model.AccessAdmin,
		PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow",` +
			`"Action":"*","Resource":"*"}]}`,
		DefaultTTLSeconds: 900,
		MaxTTLSeconds:     1800,
		Enabled:           true,
		Builtin:           true,
	},
}

// Builtin returns the capability catalog shipped with Cloud Safeguard. IDs are
// stable and documented in docs/CONTRACT.md. The returned slice is a defensive
// copy: callers may mutate it (the server stamps timestamps on seed) without
// corrupting the catalog.
func Builtin() []model.Capability {
	out := make([]model.Capability, 0, len(builtinSpecs))
	for _, spec := range builtinSpecs {
		spec.Params = append([]model.CapabilityParam(nil), spec.Params...)
		out = append(out, spec)
	}
	return out
}

// Lookup returns a built-in capability by ID.
func Lookup(id string) (model.Capability, bool) {
	for _, spec := range builtinSpecs {
		if spec.ID == id {
			spec.Params = append([]model.CapabilityParam(nil), spec.Params...)
			return spec, true
		}
	}
	return model.Capability{}, false
}

// ValidateParams checks that required params are present and non-empty, that
// every supplied param is declared by the capability, and that each value
// matches its declared RE2 pattern. Unknown params are rejected. Errors are
// safe to return to agents: they never echo secret material (params are
// non-secret by design) and are bounded in length.
func ValidateParams(cap model.Capability, params map[string]string) error {
	declared := make(map[string]model.CapabilityParam, len(cap.Params))
	for _, p := range cap.Params {
		if p.Name == "" {
			return fmt.Errorf("capability %s declares a parameter with an empty name", cap.ID)
		}
		if _, dup := declared[p.Name]; dup {
			return fmt.Errorf("capability %s declares parameter %q twice", cap.ID, p.Name)
		}
		declared[p.Name] = p
	}

	for name := range params {
		if _, ok := declared[name]; !ok {
			return fmt.Errorf("unknown parameter %q for capability %s", name, cap.ID)
		}
	}

	// Check required params in declaration order so the error is deterministic.
	for _, p := range cap.Params {
		value, present := params[p.Name]
		if !present || strings.TrimSpace(value) == "" {
			if p.Required {
				return fmt.Errorf("missing required parameter %q for capability %s", p.Name, cap.ID)
			}
			continue
		}
		if p.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return fmt.Errorf("capability %s parameter %q has invalid pattern: %v", cap.ID, p.Name, err)
		}
		if !re.MatchString(value) {
			return fmt.Errorf("invalid value for parameter %q: must match %s", p.Name, p.Pattern)
		}
	}
	return nil
}

// RenderPolicy substitutes {{param}} placeholders in the capability's policy
// template, appends the mandatory IAM deny statement (CONTRACT §16.3),
// validates the result with CheckPolicy and returns the compact document. Only
// declared placeholders are substituted; values are JSON-string-escaped before
// insertion so a hostile parameter can never alter the structure of the
// rendered policy document.
//
// It fails closed: when the rendered document violates the IAM prohibition the
// error is returned and no document is produced, so no credential can be
// minted from it.
func RenderPolicy(cap model.Capability, params map[string]string) ([]byte, error) {
	rendered, err := renderTemplate(cap, params)
	if err != nil {
		return nil, err
	}
	// Check the template's own document before re-encoding it: appending the
	// deny statement rebuilds the top level and would silently drop duplicate
	// top-level keys instead of rejecting them.
	if err := RejectDuplicateKeys(rendered); err != nil {
		return nil, fmt.Errorf("policy template of capability %s: %v", cap.ID, err)
	}
	// The template itself must be a valid policy with at least one
	// statement: once the deny statement is appended, an empty or null
	// Statement would no longer look empty (CONTRACT §16.3 rule 0).
	if err := CheckPolicy(cap.Access, rendered); err != nil {
		return nil, err
	}
	withDeny, err := appendDenyStatement(rendered)
	if err != nil {
		return nil, fmt.Errorf("policy template of capability %s cannot carry the mandatory deny statement: %v", cap.ID, err)
	}
	if err := CheckPolicy(cap.Access, withDeny); err != nil {
		return nil, err
	}
	return withDeny, nil
}

// renderTemplate performs the placeholder substitution half of RenderPolicy.
func renderTemplate(cap model.Capability, params map[string]string) ([]byte, error) {
	template := strings.TrimSpace(cap.PolicyTemplate)
	if template == "" {
		return nil, fmt.Errorf("capability %s has an empty policy template", cap.ID)
	}

	declared := make(map[string]bool, len(cap.Params))
	for _, p := range cap.Params {
		declared[p.Name] = true
	}

	// Validate every placeholder before substituting so a partial render is
	// never returned.
	for _, match := range placeholderRE.FindAllStringSubmatch(template, -1) {
		name := match[1]
		if !declared[name] {
			return nil, fmt.Errorf("policy template of capability %s references undeclared parameter %q", cap.ID, name)
		}
		value, ok := params[name]
		if !ok || value == "" {
			return nil, fmt.Errorf("missing value for parameter %q", name)
		}
	}

	rendered := placeholderRE.ReplaceAllStringFunc(template, func(token string) string {
		name := placeholderRE.FindStringSubmatch(token)[1]
		value, ok := params[name]
		if !ok || value == "" {
			// Unreachable: validated above.
			return token
		}
		return jsonEscape(value)
	})

	if leftover := literalPlaceholderRE.FindString(rendered); leftover != "" {
		return nil, fmt.Errorf("policy template of capability %s contains unresolved placeholder %q", cap.ID, leftover)
	}
	if !json.Valid([]byte(rendered)) {
		return nil, fmt.Errorf("policy template of capability %s does not render to valid JSON", cap.ID)
	}

	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(rendered)); err != nil {
		return nil, fmt.Errorf("policy template of capability %s does not render to valid JSON: %v", cap.ID, err)
	}
	return compact.Bytes(), nil
}

// SampleParams returns a safe, pattern-conforming value for every declared
// parameter of a capability. It exists so a capability's policy template can be
// rendered (and therefore IAM-checked) without a real lease request: the admin
// API uses it on create/update and the schema-2 migration uses it to decide
// which custom capabilities must be disabled.
func SampleParams(cap model.Capability) map[string]string {
	samples := make(map[string]string, len(cap.Params))
	for _, p := range cap.Params {
		samples[p.Name] = sampleParamValue(p)
	}
	return samples
}

// RenderSample renders a capability's policy template with SampleParams. A
// non-nil error means the capability cannot mint a credential at all: either
// the template is malformed or it violates the IAM prohibition.
func RenderSample(cap model.Capability) ([]byte, error) {
	return RenderPolicy(cap, SampleParams(cap))
}

// sampleParamValue returns a safe sample value for one declared parameter,
// preferring a realistic value that satisfies the declared pattern.
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

// jsonEscape returns s escaped as the contents of a JSON string (without the
// surrounding quotes). It uses the same escaping rules encoding/json applies,
// with HTML escaping disabled so ARN-like values stay readable.
func jsonEscape(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		// Encoding a Go string cannot fail.
		return ""
	}
	b := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(b) >= 2 {
		b = b[1 : len(b)-1]
	}
	return string(b)
}
