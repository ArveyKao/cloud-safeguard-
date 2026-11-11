package capcatalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// allowDoc builds a one-statement Allow document whose Action field is the raw
// JSON given, so both the string and the array form can be exercised.
func allowDoc(rawAction string) string {
	return `{"Version":"1","Statement":[{"Effect":"Allow","Action":` + rawAction + `,"Resource":"*"}]}`
}

// TestCheckPolicy is the CONTRACT §16.8 table: every rule of §16.3, at every
// access level that changes the answer.
func TestCheckPolicy(t *testing.T) {
	tests := []struct {
		name   string
		access model.AccessLevel
		doc    string
		// wantErr is a substring of the expected error; "" means "accepted".
		wantErr string
	}{
		// ---- rule 1: NotAction / NotResource / unparseable ----
		{
			name:    "NotAction is rejected",
			access:  model.AccessAdmin,
			doc:     `{"Version":"1","Statement":[{"Effect":"Allow","NotAction":["ram:*"],"Resource":"*"}]}`,
			wantErr: "NotAction",
		},
		{
			name:    "NotAction on a Deny statement is rejected too",
			access:  model.AccessAdmin,
			doc:     `{"Version":"1","Statement":[{"Effect":"Deny","NotAction":"ram:CreateUser","Resource":"*"}]}`,
			wantErr: "NotAction",
		},
		{
			name:    "NotResource is rejected",
			access:  model.AccessAdmin,
			doc:     `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","NotResource":["acs:ram:*"]}]}`,
			wantErr: "NotResource",
		},
		{
			name:    "unparseable document is rejected",
			access:  model.AccessAdmin,
			doc:     `{"Version":"1","Statement":[`,
			wantErr: "cannot be checked",
		},
		{
			name:    "Statement of the wrong shape is rejected",
			access:  model.AccessAdmin,
			doc:     `{"Version":"1","Statement":"ecs:DescribeInstances"}`,
			wantErr: "cannot be checked",
		},
		{
			name:    "invalid access level fails closed",
			access:  model.AccessLevel("root"),
			doc:     allowDoc(`"ecs:DescribeInstances"`),
			wantErr: "not valid",
		},

		// ---- rule 2: RAM, wildcard services, bare "*" ----
		{
			name:    "RAM:CreateUser is rejected case-insensitively at admin",
			access:  model.AccessAdmin,
			doc:     allowDoc(`"RAM:CreateUser"`),
			wantErr: "RAM",
		},
		{
			name:    "ram:* is rejected at admin",
			access:  model.AccessAdmin,
			doc:     allowDoc(`"ram:*"`),
			wantErr: "RAM",
		},
		{
			name:    "ram:ListUsers is rejected at read",
			access:  model.AccessRead,
			doc:     allowDoc(`"ram:ListUsers"`),
			wantErr: "RAM",
		},
		{
			name:    "r*:* is rejected: wildcard service",
			access:  model.AccessAdmin,
			doc:     allowDoc(`"r*:*"`),
			wantErr: "wildcard service",
		},
		{
			name:    "*:* is rejected: wildcard service",
			access:  model.AccessAdmin,
			doc:     allowDoc(`"*:*"`),
			wantErr: "wildcard service",
		},
		{
			name:    "ec?:DescribeInstances is rejected: wildcard service",
			access:  model.AccessAdmin,
			doc:     allowDoc(`"ec?:DescribeInstances"`),
			wantErr: "wildcard service",
		},
		{
			name:   "bare * is the one exception, and only at admin",
			access: model.AccessAdmin,
			doc:    allowDoc(`"*"`),
		},
		{
			name:    "bare * is rejected at write",
			access:  model.AccessWrite,
			doc:     allowDoc(`"*"`),
			wantErr: "only allowed on an admin capability",
		},
		{
			name:    "bare * is rejected at read",
			access:  model.AccessRead,
			doc:     allowDoc(`"*"`),
			wantErr: "only allowed on an admin capability",
		},
		{
			name:    "an action without a service part is rejected",
			access:  model.AccessAdmin,
			doc:     allowDoc(`"DescribeInstances"`),
			wantErr: "service:Action",
		},

		// ---- rule 3: STS ----
		{
			name:    "sts:Assume* is rejected",
			access:  model.AccessAdmin,
			doc:     allowDoc(`"sts:Assume*"`),
			wantErr: "sts:GetCallerIdentity is the only permitted STS action",
		},
		{
			name:    "sts:AssumeRole is rejected",
			access:  model.AccessAdmin,
			doc:     allowDoc(`"sts:AssumeRole"`),
			wantErr: "sts:GetCallerIdentity is the only permitted STS action",
		},
		{
			name:    "STS:AssumeRole is rejected case-insensitively",
			access:  model.AccessWrite,
			doc:     allowDoc(`"STS:AssumeRole"`),
			wantErr: "sts:GetCallerIdentity is the only permitted STS action",
		},
		{
			name:   "sts:GetCallerIdentity is allowed at read",
			access: model.AccessRead,
			doc:    allowDoc(`"sts:GetCallerIdentity"`),
		},
		{
			name:   "sts:getcalleridentity is allowed case-insensitively",
			access: model.AccessWrite,
			doc:    allowDoc(`"sts:getcalleridentity"`),
		},

		// ---- rule 4: read ----
		{
			name:   "read allows the four verbs with a trailing wildcard",
			access: model.AccessRead,
			doc:    allowDoc(`["ecs:Describe*","oss:List*","ecs:Get*","rds:Query*"]`),
		},
		{
			name:   "read allows an exact verb-prefixed action",
			access: model.AccessRead,
			doc:    allowDoc(`["alidns:DescribeDomainRecords","ecs:DescribeInstances"]`),
		},
		{
			name:   "read allows literal characters before the trailing wildcard",
			access: model.AccessRead,
			doc:    allowDoc(`"ecs:DescribeInstance*"`),
		},
		{
			name:    "ecs:D* is rejected as read: the full verb must come first",
			access:  model.AccessRead,
			doc:     allowDoc(`"ecs:D*"`),
			wantErr: "ecs:D*",
		},
		{
			name:    "ecs:Describ* is rejected as read: truncated verb",
			access:  model.AccessRead,
			doc:     allowDoc(`"ecs:Describ*"`),
			wantErr: "ecs:Describ*",
		},
		{
			name:    "ecs:Describe? is rejected as read: no single-character wildcard",
			access:  model.AccessRead,
			doc:     allowDoc(`"ecs:Describe?"`),
			wantErr: "single-character wildcards",
		},
		{
			name:    "ecs:* is rejected as read",
			access:  model.AccessRead,
			doc:     allowDoc(`"ecs:*"`),
			wantErr: "must name a",
		},
		{
			name:    "ecs:StopInstance is rejected as read: not a read verb",
			access:  model.AccessRead,
			doc:     allowDoc(`"ecs:StopInstance"`),
			wantErr: "must start with one of",
		},
		{
			name:    "ecs:Describe*Instances is rejected as read: wildcard must be last",
			access:  model.AccessRead,
			doc:     allowDoc(`"ecs:Describe*Instances"`),
			wantErr: "only one trailing",
		},

		// ---- rule 5: write ----
		{
			name:   "write allows service:*",
			access: model.AccessWrite,
			doc:    allowDoc(`"alidns:*"`),
		},
		{
			name:   "write allows a named write action",
			access: model.AccessWrite,
			doc:    allowDoc(`["alidns:AddDomainRecord","ecs:StopInstance"]`),
		},
		{
			name:   "admin allows service:*",
			access: model.AccessAdmin,
			doc:    allowDoc(`"ecs:*"`),
		},

		// ---- Deny statements are never restricted ----
		{
			name:   "the mandatory deny statement passes at every access level",
			access: model.AccessRead,
			doc:    `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:Describe*"],"Resource":"*"},` + DenyStatement + `]}`,
		},
		{
			name:   "a deny may name ram and sts:AssumeRole",
			access: model.AccessWrite,
			doc:    `{"Version":"1","Statement":[{"Effect":"Deny","Action":["ram:*","sts:AssumeRole"],"Resource":"*"}]}`,
		},

		// ---- shapes: single statement object, string and array Action ----
		{
			name:   "a single statement object is accepted",
			access: model.AccessRead,
			doc:    `{"Version":"1","Statement":{"Effect":"Allow","Action":"ecs:DescribeInstances","Resource":"*"}}`,
		},
		{
			name:    "a single statement object is checked",
			access:  model.AccessRead,
			doc:     `{"Version":"1","Statement":{"Effect":"Allow","Action":"ram:ListUsers","Resource":"*"}}`,
			wantErr: "RAM",
		},
		{
			name:    "every element of an array Action is checked",
			access:  model.AccessAdmin,
			doc:     allowDoc(`["ecs:DescribeInstances","ram:CreateUser"]`),
			wantErr: "ram:CreateUser",
		},
		{
			name:    "a non-string Action is rejected",
			access:  model.AccessAdmin,
			doc:     allowDoc(`[42]`),
			wantErr: "invalid Action",
		},
		{
			name:    "a document with no statements is rejected",
			access:  model.AccessRead,
			doc:     `{"Version":"1","Statement":[]}`,
			wantErr: "at least one statement",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckPolicy(tc.access, []byte(tc.doc))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckPolicy(%s, %s) error = %v, want nil", tc.access, tc.doc, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("CheckPolicy(%s, %s) = nil, want an error containing %q", tc.access, tc.doc, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("CheckPolicy(%s, %s) error = %q, want substring %q", tc.access, tc.doc, err.Error(), tc.wantErr)
			}
		})
	}
}

// TestBuiltinsCarryDenyStatementAndPassCheckPolicy covers the CONTRACT §16.8
// requirement that every builtin renders a document which carries the
// mandatory deny statement and satisfies the IAM prohibition at its own access
// level (and only at its own access level, where that is observable).
func TestBuiltinsCarryDenyStatementAndPassCheckPolicy(t *testing.T) {
	for _, cap := range Builtin() {
		t.Run(cap.ID, func(t *testing.T) {
			rendered, err := RenderSample(cap)
			if err != nil {
				t.Fatalf("RenderSample(%s) error = %v", cap.ID, err)
			}
			if !strings.Contains(string(rendered), DenyStatement) {
				t.Fatalf("%s rendered policy does not carry the deny statement: %s", cap.ID, rendered)
			}
			if err := CheckPolicy(cap.Access, rendered); err != nil {
				t.Fatalf("%s rendered policy fails CheckPolicy at access %s: %v", cap.ID, cap.Access, err)
			}

			// The deny is the last statement and is exactly the frozen one.
			var doc struct {
				Statement []json.RawMessage `json:"Statement"`
			}
			if err := json.Unmarshal(rendered, &doc); err != nil {
				t.Fatalf("%s: unmarshal rendered policy: %v", cap.ID, err)
			}
			if len(doc.Statement) < 2 {
				t.Fatalf("%s: rendered policy has %d statements, want the template plus the deny", cap.ID, len(doc.Statement))
			}
			if got := string(doc.Statement[len(doc.Statement)-1]); got != DenyStatement {
				t.Fatalf("%s: last statement = %s, want %s", cap.ID, got, DenyStatement)
			}
		})
	}
}

// TestBuiltinAccessLevelsAreTheTightestThatWork proves the access levels in the
// catalog are not decorative: a write builtin cannot be reclassified as read,
// and the admin builtin cannot be reclassified as write.
func TestBuiltinAccessLevelsAreTheTightestThatWork(t *testing.T) {
	tighter := map[model.AccessLevel]model.AccessLevel{
		model.AccessWrite: model.AccessRead,
		model.AccessAdmin: model.AccessWrite,
	}
	for _, cap := range Builtin() {
		lower, ok := tighter[cap.Access]
		if !ok {
			continue // read is already the tightest level
		}
		t.Run(cap.ID, func(t *testing.T) {
			demoted := cap
			demoted.Access = lower
			if _, err := RenderSample(demoted); err == nil {
				t.Fatalf("%s renders a policy that would pass at %s, so its access level is too high", cap.ID, lower)
			}
		})
	}
}

func TestCheckPolicyRejectsParserDifferentials(t *testing.T) {
	tests := []struct {
		name   string
		access model.AccessLevel
		policy string
	}{
		{"duplicate Effect in a statement", model.AccessRead,
			`{"Version":"1","Statement":[{"Effect":"Allow","Effect":"Deny","Action":"ecs:DeleteInstance","Resource":"*"}]}`},
		{"duplicate Action in a read statement", model.AccessRead,
			`{"Version":"1","Statement":[{"Effect":"Allow","Action":"ecs:DeleteInstance","Action":"ecs:DescribeInstances","Resource":"*"}]}`},
		{"case-folded duplicate key", model.AccessRead,
			`{"Version":"1","Statement":[{"Effect":"Deny","effect":"Allow","Action":"*","Resource":"*"}]}`},
		{"duplicate top-level Statement", model.AccessRead,
			`{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}],"Statement":[]}`},
		{"space inside the service part", model.AccessWrite,
			`{"Version":"1","Statement":[{"Effect":"Allow","Action":"ram :CreateUser","Resource":"*"}]}`},
		{"surrounding whitespace", model.AccessWrite,
			`{"Version":"1","Statement":[{"Effect":"Allow","Action":" ram:CreateUser","Resource":"*"}]}`},
		{"unexpected character", model.AccessWrite,
			`{"Version":"1","Statement":[{"Effect":"Allow","Action":"ecs:Start/Instance","Resource":"*"}]}`},
		{"missing colon", model.AccessWrite,
			`{"Version":"1","Statement":[{"Effect":"Allow","Action":"ramCreateUser","Resource":"*"}]}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckPolicy(tc.access, []byte(tc.policy)); err == nil {
				t.Fatalf("CheckPolicy(%s) = nil, want rejection for %s", tc.access, tc.policy)
			}
		})
	}
}

func TestRenderPolicyRejectsDuplicateTopLevelKeys(t *testing.T) {
	cap := model.Capability{
		ID:     "cap_dup",
		Access: model.AccessRead,
		PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":"ecs:DeleteInstance","Resource":"*"}],` +
			`"Statement":[{"Effect":"Allow","Action":"ecs:DescribeInstances","Resource":"*"}]}`,
	}
	if _, err := RenderPolicy(cap, nil); err == nil {
		t.Fatal("RenderPolicy accepted a template with a duplicate top-level Statement key")
	}
}

func TestRejectDuplicateKeysAcceptsNestedDistinctKeys(t *testing.T) {
	ok := `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:DescribeInstances"],"Resource":"*",` +
		`"Condition":{"IpAddress":{"acs:SourceIp":["10.0.0.0/8"]}}},{"Effect":"Deny","Action":"ram:*","Resource":"*"}]}`
	if err := RejectDuplicateKeys([]byte(ok)); err != nil {
		t.Fatalf("RejectDuplicateKeys rejected a valid document: %v", err)
	}
	if err := CheckPolicy(model.AccessRead, []byte(ok)); err != nil {
		t.Fatalf("CheckPolicy rejected a valid read document: %v", err)
	}
}

func TestCheckPolicyRejectsNullAndEmptyShapes(t *testing.T) {
	tests := []struct{ name, policy string }{
		{"null NotAction", `{"Version":"1","Statement":[{"Effect":"Allow","NotAction":null,"Resource":"*"}]}`},
		{"empty NotAction", `{"Version":"1","Statement":[{"Effect":"Allow","NotAction":[],"Resource":"*"}]}`},
		{"null NotResource", `{"Version":"1","Statement":[{"Effect":"Allow","Action":"ecs:DescribeInstances","NotResource":null}]}`},
		{"Allow with null Action", `{"Version":"1","Statement":[{"Effect":"Allow","Action":null,"Resource":"*"}]}`},
		{"Allow with missing Action", `{"Version":"1","Statement":[{"Effect":"Allow","Resource":"*"}]}`},
		{"Allow with empty Action", `{"Version":"1","Statement":[{"Effect":"Allow","Action":[],"Resource":"*"}]}`},
		{"null statement", `{"Version":"1","Statement":[null]}`},
		{"non-object statement", `{"Version":"1","Statement":["Allow"]}`},
	}
	for _, tc := range tests {
		for _, access := range []model.AccessLevel{model.AccessRead, model.AccessWrite, model.AccessAdmin} {
			if err := CheckPolicy(access, []byte(tc.policy)); err == nil {
				t.Errorf("%s at %s: CheckPolicy = nil, want rejection", tc.name, access)
			}
		}
	}
}

func TestCheckPolicyRejectsLenientShapes(t *testing.T) {
	tests := []struct{ name, policy string }{
		{"lowercase effect", `{"Version":"1","Statement":[{"Effect":"allow","Action":"ecs:DescribeInstances","Resource":"*"}]}`},
		{"padded Deny effect", `{"Version":"1","Statement":[{"Effect":"Deny ","Action":"*","Resource":"*"}]}`},
		{"unknown effect", `{"Version":"1","Statement":[{"Effect":"Permit","Action":"ecs:DescribeInstances","Resource":"*"}]}`},
		{"top-level Action", `{"Version":"1","Effect":"Allow","Action":"*","Statement":[{"Effect":"Allow","Action":"ecs:DescribeInstances","Resource":"*"}]}`},
		{"missing Statement", `{"Version":"1"}`},
		{"null document", `null`},
		{"Resource object", `{"Version":"1","Statement":[{"Effect":"Allow","Action":"ecs:DescribeInstances","Resource":{"any":"*"}}]}`},
	}
	for _, tc := range tests {
		if err := CheckPolicy(model.AccessAdmin, []byte(tc.policy)); err == nil {
			t.Errorf("%s: CheckPolicy = nil, want rejection", tc.name)
		}
	}
}

func TestTemplateAllowsEverything(t *testing.T) {
	broad := model.Capability{ID: "c1", PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`}
	if ok, err := TemplateAllowsEverything(broad, nil); err != nil || !ok {
		t.Fatalf("bare * template: got %v, %v; want true", ok, err)
	}
	narrow := model.Capability{ID: "c2", PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:*"],"Resource":"*"}]}`}
	if ok, err := TemplateAllowsEverything(narrow, nil); err != nil || ok {
		t.Fatalf("ecs:* template: got %v, %v; want false", ok, err)
	}
	denyStar := model.Capability{ID: "c3", PolicyTemplate: `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:Describe*"],"Resource":"*"},{"Effect":"Deny","Action":"*","Resource":"*"}]}`}
	if ok, err := TemplateAllowsEverything(denyStar, nil); err != nil || ok {
		t.Fatalf("Deny * template: got %v, %v; want false", ok, err)
	}
}

func TestCheckPolicyRequiresExactElementsAndResource(t *testing.T) {
	tests := []struct{ name, policy string }{
		{"missing Resource", `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:StopInstance"]}]}`},
		{"null Resource", `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:StopInstance"],"Resource":null}]}`},
		{"empty Resource", `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:StopInstance"],"Resource":[]}]}`},
		{"null Resource element", `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:StopInstance"],"Resource":[null]}]}`},
		{"lowercase statement elements", `{"Version":"1","Statement":[{"effect":"Allow","action":["ecs:StopInstance"],"resource":"*"}]}`},
		{"lowercase version", `{"version":"1","Statement":[{"Effect":"Allow","Action":["ecs:StopInstance"],"Resource":"*"}]}`},
		{"unicode-fold duplicate Resource", "{\"Version\":\"1\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"ecs:StopInstance\"],\"Resource\":\"*\",\"Reſource\":\"acs:ecs:*:*:instance/i-1\"}]}"},
		{"unknown statement element", `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:StopInstance"],"Resource":"*","Principal":"*"}]}`},
	}
	for _, tc := range tests {
		if err := CheckPolicy(model.AccessWrite, []byte(tc.policy)); err == nil {
			t.Errorf("%s: CheckPolicy = nil, want rejection", tc.name)
		}
	}
}

func TestRejectDuplicateKeysUsesUnicodeFolding(t *testing.T) {
	doc := "{\"Version\":\"1\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"ecs:DescribeInstances\"],\"Resource\":\"*\"," +
		"\"Condition\":{\"IpAddress\":{\"acs:SourceIp\":\"10.0.0.0/8\",\"acs:ſourceIp\":\"0.0.0.0/0\"}}}]}"
	if err := RejectDuplicateKeys([]byte(doc)); err == nil {
		t.Fatal("RejectDuplicateKeys accepted keys that encoding/json treats as equal")
	}
}
