package capcatalog

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// Access templates (CONTRACT §17.4).
//
// An agent asks for a (resource type, permission) pair on a cloud account;
// it never submits IAM actions. Each pair maps to exactly one vetted policy
// template defined here in code. The templates are not stored in the
// database and cannot be edited through any API.
//
// Permission levels:
//
//	read   Describe*/List*/Get*/Query* only.
//	write  read, plus changing an existing resource: its settings and state,
//	       and adding, changing or removing items inside it (a DNS record in
//	       a domain, an object in a bucket).
//	full   write, plus creating a new resource and deleting an existing one.
//
// Every action a template allows is classified by classifyAction. An action
// that is not explicitly listed as write (and is not a read verb) counts as
// full, so forgetting to classify something can only make it harder to get.

// Permission is the level of an access request.
type Permission string

const (
	PermissionRead  Permission = "read"
	PermissionWrite Permission = "write"
	PermissionFull  Permission = "full"
)

// Rank orders permissions: read=1, write=2, full=3; unknown=0.
func (p Permission) Rank() int {
	switch p {
	case PermissionRead:
		return 1
	case PermissionWrite:
		return 2
	case PermissionFull:
		return 3
	}
	return 0
}

// Valid reports whether p is a known permission.
func (p Permission) Valid() bool { return p.Rank() > 0 }

// Access maps a permission onto the capability access level used by the
// role check and the IAM guard: read->read, write->write, full->admin.
// guest/member/administrator permit read/write/admin (model.AgentRole.Permits),
// which is exactly guest=read, member=write, administrator=full.
func (p Permission) Access() model.AccessLevel {
	switch p {
	case PermissionRead:
		return model.AccessRead
	case PermissionWrite:
		return model.AccessWrite
	case PermissionFull:
		return model.AccessAdmin
	}
	return ""
}

// Permissions returns the permissions in ascending order.
func Permissions() []Permission {
	return []Permission{PermissionRead, PermissionWrite, PermissionFull}
}

// ResourceNameParam is the single parameter of every access template. The
// server sets it to the requested resource name, or to "*" for all resources
// of that type in the account.
const ResourceNameParam = "resource_name"

// AllResources is the resource_name value meaning "every resource of this
// type".
const AllResources = "*"

// resourceSpec describes one resource type of one cloud.
type resourceSpec struct {
	provider model.ProviderType
	resource string
	// title is used in capability names, e.g. "ECS instances".
	title string
	// service is the IAM service prefix of the resource's actions.
	service string
	// resources are the policy Resource entries; {{resource_name}} is
	// substituted.
	resources []string
	// namePattern validates a specific resource name (RE2, anchored).
	namePattern string
	// nameHint describes the name for error messages.
	nameHint string
	// read are the read-level actions.
	read []string
	// write are the additional actions of the write level: changes to an
	// existing resource and to items inside it.
	write []string
	// full are the additional actions of the full level: creating and
	// deleting the resource itself.
	full []string
}

var resourceSpecs = []resourceSpec{
	{
		provider:    model.ProviderAliyun,
		resource:    "ecs",
		title:       "ECS instances",
		service:     "ecs",
		resources:   []string{"acs:ecs:*:*:instance/{{resource_name}}"},
		namePattern: `^i-[A-Za-z0-9]+$`,
		nameHint:    "an ECS instance ID such as i-2ze0demo001",
		read:        []string{"ecs:Describe*"},
		write:       []string{"ecs:StartInstance", "ecs:StopInstance", "ecs:RebootInstance", "ecs:ModifyInstanceAttribute"},
		full:        []string{"ecs:RunInstances", "ecs:CreateInstance", "ecs:DeleteInstance"},
	},
	{
		provider:    model.ProviderAliyun,
		resource:    "dns",
		title:       "DNS domains",
		service:     "alidns",
		resources:   []string{"acs:alidns:*:*:domain/{{resource_name}}"},
		namePattern: DomainPattern,
		nameHint:    "a domain name such as example.com",
		read:        []string{"alidns:Describe*"},
		write: []string{
			"alidns:AddDomainRecord", "alidns:UpdateDomainRecord", "alidns:DeleteDomainRecord",
			"alidns:SetDomainRecordStatus",
		},
		full: []string{"alidns:AddDomain", "alidns:DeleteDomain"},
	},
	{
		provider:    model.ProviderAliyun,
		resource:    "oss",
		title:       "OSS buckets",
		service:     "oss",
		resources:   []string{"acs:oss:*:*:{{resource_name}}", "acs:oss:*:*:{{resource_name}}/*"},
		namePattern: `^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`,
		nameHint:    "a bucket name",
		read:        []string{"oss:Get*", "oss:List*"},
		write:       []string{"oss:PutObject", "oss:DeleteObject", "oss:AbortMultipartUpload"},
		full:        []string{"oss:PutBucket", "oss:DeleteBucket"},
	},
}

// writeActions is the classification table: every action that counts as
// "write". Read verbs are recognised by name; everything else is full.
var writeActions = func() map[string]bool {
	out := map[string]bool{}
	for _, spec := range resourceSpecs {
		for _, action := range spec.write {
			out[action] = true
		}
	}
	return out
}()

var readActionRE = regexp.MustCompile(`^[A-Za-z0-9]+:(Describe|List|Get|Query)[A-Za-z0-9]*\*?$`)

// classifyAction returns the permission level an IAM action needs. It fails
// towards full: wildcards outside a read verb, unknown actions and anything
// malformed are full.
func classifyAction(action string) Permission {
	if action == "sts:GetCallerIdentity" || readActionRE.MatchString(action) {
		return PermissionRead
	}
	if strings.ContainsAny(action, "*?") {
		return PermissionFull
	}
	if writeActions[action] {
		return PermissionWrite
	}
	return PermissionFull
}

// accessTemplateIDPrefix marks capability IDs reserved for access templates.
func accessTemplateID(provider model.ProviderType, resource string, p Permission) string {
	return string(provider) + ".access." + resource + "." + string(p)
}

// IsAccessTemplateID reports whether id is reserved for an access template.
// Stored capabilities may never use such an ID.
func IsAccessTemplateID(id string) bool {
	parts := strings.Split(id, ".")
	return len(parts) == 4 && parts[1] == "access"
}

// AccessTemplate describes one (resource, permission) pair.
type AccessTemplate struct {
	Resource   string
	Permission Permission
	// Capability is the vetted policy template in capability form, so the
	// lease pipeline (rendering, IAM guard, minting) handles it unchanged.
	Capability model.Capability
}

var accessTemplates = buildAccessTemplates()

func buildAccessTemplates() map[string]AccessTemplate {
	out := map[string]AccessTemplate{}
	for _, spec := range resourceSpecs {
		for _, p := range Permissions() {
			actions := append([]string(nil), spec.read...)
			if p.Rank() >= PermissionWrite.Rank() {
				actions = append(actions, spec.write...)
			}
			if p.Rank() >= PermissionFull.Rank() {
				actions = append(actions, spec.full...)
			}
			doc := map[string]any{
				"Version": "1",
				"Statement": []any{map[string]any{
					"Effect": "Allow", "Action": actions, "Resource": spec.resources,
				}},
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				panic(err)
			}
			risk := map[Permission]model.RiskTier{
				PermissionRead: model.RiskLow, PermissionWrite: model.RiskMedium, PermissionFull: model.RiskHigh,
			}[p]
			id := accessTemplateID(spec.provider, spec.resource, p)
			out[id] = AccessTemplate{
				Resource:   spec.resource,
				Permission: p,
				Capability: model.Capability{
					ID:             id,
					Name:           fmt.Sprintf("%s: %s", spec.title, p),
					Description:    fmt.Sprintf("%s access to %s (CONTRACT §17.4).", p, spec.title),
					ProviderType:   spec.provider,
					Risk:           risk,
					Access:         p.Access(),
					PolicyTemplate: string(raw),
					Params: []model.CapabilityParam{{
						Name:        ResourceNameParam,
						Description: "One resource (" + spec.nameHint + ") or * for all",
						Required:    true,
						Pattern:     `^(\*|` + strings.TrimSuffix(strings.TrimPrefix(spec.namePattern, "^"), "$") + `)$`,
					}},
					DefaultTTLSeconds: 900,
					MaxTTLSeconds:     3600,
					Enabled:           true,
					Builtin:           true,
				},
			}
		}
	}
	return out
}

// LookupAccessTemplate returns the template for a provider type, resource
// type and permission.
func LookupAccessTemplate(provider model.ProviderType, resource string, p Permission) (AccessTemplate, bool) {
	t, ok := accessTemplates[accessTemplateID(provider, resource, p)]
	return t, ok
}

// AccessTemplateByID returns the template with the given capability ID.
func AccessTemplateByID(id string) (AccessTemplate, bool) {
	t, ok := accessTemplates[id]
	return t, ok
}

// AccessResources lists the resource types available for a provider type.
func AccessResources(provider model.ProviderType) []string {
	seen := map[string]bool{}
	var out []string
	for _, spec := range resourceSpecs {
		if spec.provider == provider && !seen[spec.resource] {
			seen[spec.resource] = true
			out = append(out, spec.resource)
		}
	}
	sort.Strings(out)
	return out
}

// ResourceNameHint describes a valid resource name for error messages.
func ResourceNameHint(provider model.ProviderType, resource string) string {
	for _, spec := range resourceSpecs {
		if spec.provider == provider && spec.resource == resource {
			return spec.nameHint
		}
	}
	return ""
}

// CheckAccessTemplateLevel verifies that a rendered policy of an access
// template allows nothing above the template's permission level and nothing
// outside its resource type's service. RenderPolicy calls it for every access
// template, so a template that drifts above its level can never mint.
func CheckAccessTemplateLevel(t AccessTemplate, policy []byte) error {
	var doc struct {
		Statement []struct {
			Effect string          `json:"Effect"`
			Action json.RawMessage `json:"Action"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal(policy, &doc); err != nil {
		return fmt.Errorf("access template %s: %v", t.Capability.ID, err)
	}
	service := ""
	for _, spec := range resourceSpecs {
		if accessTemplateID(spec.provider, spec.resource, t.Permission) == t.Capability.ID {
			service = spec.service
		}
	}
	if service == "" {
		return fmt.Errorf("access template %s: unknown resource type", t.Capability.ID)
	}
	for _, st := range doc.Statement {
		if st.Effect != "Allow" {
			continue
		}
		var actions []string
		if err := json.Unmarshal(st.Action, &actions); err != nil {
			var single string
			if err := json.Unmarshal(st.Action, &single); err != nil {
				return fmt.Errorf("access template %s: malformed Action", t.Capability.ID)
			}
			actions = []string{single}
		}
		for _, action := range actions {
			if !strings.HasPrefix(action, service+":") {
				return fmt.Errorf("access template %s allows %q outside service %q", t.Capability.ID, action, service)
			}
			if need := classifyAction(action); need.Rank() > t.Permission.Rank() {
				return fmt.Errorf("access template %s (%s) allows %q, which needs %s",
					t.Capability.ID, t.Permission, action, need)
			}
		}
	}
	return nil
}
