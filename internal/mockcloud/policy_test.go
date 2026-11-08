package mockcloud

import (
	"testing"
)

func mustPolicy(t *testing.T, raw string) policyDoc {
	t.Helper()
	doc, err := parsePolicyDoc([]byte(raw))
	if err != nil {
		t.Fatalf("parsePolicyDoc(%s) error = %v", raw, err)
	}
	return doc
}

func TestPolicyMatcher(t *testing.T) {
	const (
		readPolicy = `{"Version":"1","Statement":[{"Effect":"Allow","Action":["ecs:Describe*","alidns:Describe*","oss:List*","sts:GetCallerIdentity"],"Resource":["*"]}]}`
		dnsPolicy  = `{"Version":"1","Statement":[{"Effect":"Allow","Action":["alidns:AddDomainRecord"],"Resource":["acs:alidns:*:*:domain/arveykao.com"]}]}`
	)

	tests := []struct {
		name     string
		policy   string
		action   string
		resource string
		want     bool
	}{
		{"wildcard action and resource allow", readPolicy, "ecs:DescribeInstances", "acs:ecs:cn-hangzhou:1234567890123456:instance/i-1", true},
		{"action matching is case-insensitive", readPolicy, "ECS:DescribeInstances", "any", true},
		{"write action denied by read policy", readPolicy, "ecs:RebootInstance", "acs:ecs:cn-hangzhou:1:instance/i-1", false},
		{"action outside service denied", readPolicy, "ram:CreateUser", "*", false},
		{"dns scoped resource allowed", dnsPolicy, "alidns:AddDomainRecord", "acs:alidns:cn-hangzhou:1234567890123456:domain/arveykao.com", true},
		{"dns other resource denied", dnsPolicy, "alidns:AddDomainRecord", "acs:alidns:cn-hangzhou:1234567890123456:domain/other.com", false},
		{"dns delete action denied by narrow policy", dnsPolicy, "alidns:DeleteDomainRecord", "acs:alidns:cn-hangzhou:1:domain/arveykao.com", false},
		{
			"deny overrides allow",
			`{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"ecs:Reboot*","Resource":"*"}]}`,
			"ecs:RebootInstance", "anything", false,
		},
		{
			"non-matching deny does not block",
			`{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"},{"Effect":"Deny","Action":"ecs:Stop*","Resource":"*"}]}`,
			"ecs:DescribeInstances", "anything", true,
		},
		{
			"deny-only policy forbids",
			`{"Version":"1","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`,
			"ecs:DescribeInstances", "anything", false,
		},
		{
			"resource matching is case-sensitive",
			`{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":["acs:ecs:*:*:instance/*"]}]}`,
			"ecs:DescribeInstances", "acs:ecs:*:*:INSTANCE/i-1", false,
		},
		{
			"question mark wildcard",
			`{"Version":"1","Statement":[{"Effect":"Allow","Action":"ecs:?escribeInstances","Resource":"*"}]}`,
			"ecs:DescribeInstances", "*", true,
		},
		{
			"single string action and resource",
			`{"Version":"1","Statement":[{"Effect":"Allow","Action":"ecs:DescribeInstances","Resource":"*"}]}`,
			"ecs:DescribeInstances", "*", true,
		},
		{
			"empty policy allows nothing",
			`{"Version":"1","Statement":[]}`,
			"ecs:DescribeInstances", "*", false,
		},
		{
			"unknown effect is ignored",
			`{"Version":"1","Statement":[{"Effect":"Maybe","Action":"*","Resource":"*"}]}`,
			"ecs:DescribeInstances", "*", false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := parsePolicyDoc([]byte(tc.policy))
			if len(tc.policy) > 0 && tc.name != "empty policy allows nothing" {
				if err != nil {
					t.Fatalf("parsePolicyDoc() error = %v", err)
				}
			}
			if tc.name == "empty policy allows nothing" {
				if err == nil {
					t.Fatalf("parsePolicyDoc() accepted a document with no statements")
				}
				return
			}
			if got := policyAllows(doc, tc.action, tc.resource); got != tc.want {
				t.Fatalf("policyAllows(%q, %q) = %v, want %v", tc.action, tc.resource, got, tc.want)
			}
		})
	}
}

func TestParsePolicyDocVariants(t *testing.T) {
	// Statement as a single object (not an array).
	doc := mustPolicy(t, `{"Version":"1","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	if !policyAllows(doc, "anything", "any") {
		t.Fatal("single-statement object was not parsed")
	}

	// Missing Version is tolerated; missing statements is not.
	if _, err := parsePolicyDoc([]byte(`{"Version":"1"}`)); err == nil {
		t.Fatal("policy without statements accepted")
	}
	if _, err := parsePolicyDoc([]byte(`not json`)); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"*", "anything", true},
		{"", "", true},
		{"", "x", false},
		{"a", "a", true},
		{"a", "b", false},
		{"a*b", "ab", true},
		{"a*b", "aXXb", true},
		{"a*b", "aXc", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"**", "abc", true},
		{"*a*b*", "xxayybzz", true},
		{"acs:ecs:*:*:instance/*", "acs:ecs:cn-hangzhou:1234567890123456:instance/i-2ze0demo001", true},
		{"acs:ecs:*:*:instance/*", "acs:ecs:cn-hangzhou:1234567890123456:disk/d-1", false},
		{"ecs:Describe*", "ecs:DescribeInstances", true},
		{"ecs:Describe*", "alidns:DescribeDomains", false},
	}
	for _, tc := range tests {
		if got := globMatch(tc.pattern, tc.s); got != tc.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.s, got, tc.want)
		}
	}
}
