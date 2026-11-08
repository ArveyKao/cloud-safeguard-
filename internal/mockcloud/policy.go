package mockcloud

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// policyDoc is an IAM policy document as carried in a mock STS token. Only the
// fields the mock cloud enforces are modelled; unknown fields (Condition, ...)
// are ignored.
type policyDoc struct {
	Version   string        `json:"Version"`
	Statement statementList `json:"Statement"`
}

// statement is one Allow/Deny statement.
type statement struct {
	Effect   string     `json:"Effect"`
	Action   stringList `json:"Action"`
	Resource stringList `json:"Resource"`
}

// statementList accepts either a single statement object or an array of them,
// matching the Alibaba Cloud RAM policy grammar.
type statementList []statement

// UnmarshalJSON implements json.Unmarshaler.
func (l *statementList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*l = nil
		return nil
	}
	if b[0] == '[' {
		var raw []json.RawMessage
		if err := json.Unmarshal(b, &raw); err != nil {
			return err
		}
		out := make(statementList, 0, len(raw))
		for _, item := range raw {
			var s statement
			if err := json.Unmarshal(item, &s); err != nil {
				return err
			}
			out = append(out, s)
		}
		*l = out
		return nil
	}
	var s statement
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*l = statementList{s}
	return nil
}

// stringList accepts either a single string or an array of strings, matching
// the Alibaba Cloud RAM policy grammar for Action and Resource.
type stringList []string

// UnmarshalJSON implements json.Unmarshaler.
func (l *stringList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*l = nil
		return nil
	}
	if b[0] == '[' {
		var out []string
		if err := json.Unmarshal(b, &out); err != nil {
			return err
		}
		*l = out
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*l = []string{s}
	return nil
}

// parsePolicyDoc parses and validates a policy document.
func parsePolicyDoc(raw []byte) (policyDoc, error) {
	var doc policyDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&doc); err != nil {
		return doc, fmt.Errorf("invalid policy document: %w", err)
	}
	if len(doc.Statement) == 0 {
		return doc, fmt.Errorf("policy document has no statements")
	}
	return doc, nil
}

// policyAllows reports whether the policy document allows (action, resource).
//
// Semantics (CONTRACT §8.3): statements with Effect Allow grant access; a
// matching Effect Deny overrides any Allow. Action patterns are matched
// case-insensitively with glob wildcards (* and ?); Resource patterns are
// matched case-sensitively with the same wildcards. No matching Allow, or any
// matching Deny, means forbidden.
func policyAllows(doc policyDoc, action, resource string) bool {
	allowed := false
	for _, st := range doc.Statement {
		if !matchAny(st.Action, action, true) || !matchAny(st.Resource, resource, false) {
			continue
		}
		switch {
		case strings.EqualFold(st.Effect, "Deny"):
			return false
		case strings.EqualFold(st.Effect, "Allow"):
			allowed = true
		}
	}
	return allowed
}

// matchAny reports whether any glob pattern matches value.
func matchAny(patterns []string, value string, caseInsensitive bool) bool {
	for _, p := range patterns {
		pattern := p
		target := value
		if caseInsensitive {
			pattern = strings.ToLower(pattern)
			target = strings.ToLower(target)
		}
		if globMatch(pattern, target) {
			return true
		}
	}
	return false
}

// globMatch matches s against a pattern supporting '*' (any sequence, including
// empty) and '?' (exactly one character). It uses the classic iterative
// backtracking algorithm so it cannot blow up on pathological patterns.
func globMatch(pattern, s string) bool {
	var (
		pi, si int
		star   = -1
		mark   int
	)
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			mark = si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
