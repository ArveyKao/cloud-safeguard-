package capcatalog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/arveykao/cloud-safeguard/internal/model"
)

// DenyStatement is the IAM deny statement appended to every rendered policy
// document (CONTRACT §16.3). It is not configurable: identity escalation
// (RAM/IAM writes and role chaining) is out of scope for every capability, at
// every access level, forever.
const DenyStatement = `{"Effect":"Deny","Action":["ram:*","sts:AssumeRole*"],"Resource":"*"}`

// Services whose actions are governed by the IAM prohibition.
const (
	ramService = "ram"
	stsService = "sts"
)

// stsReadAction is the single STS action any capability may allow.
const stsReadAction = "GetCallerIdentity"

// actionPattern is the only accepted shape of an Allow action besides the bare
// "*": a service code, a colon and an action name, with no whitespace or other
// characters a cloud parser might normalize differently from this checker.
var actionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*:[A-Za-z0-9*?_-]+$`)

// readVerbs are the action verbs a read capability may allow. The full verb
// must appear before any wildcard, so "ecs:D*" is not a read action (it would
// also match ecs:DeleteInstance).
var readVerbs = []string{"Describe", "List", "Get", "Query"}

// CheckPolicy enforces the IAM prohibition (CONTRACT §16.3) on a rendered
// policy document. Service and action comparison is case-insensitive.
//
// A document is rejected when any of these holds:
//
//  1. a statement uses NotAction or NotResource, or the document cannot be
//     parsed;
//  2. an Allow action's service part is "ram", or contains "*" or "?" — a bare
//     "*" action is the only exception, and only at access=admin;
//  3. an Allow action's service is "sts" and the action is anything other than
//     exactly GetCallerIdentity;
//  4. at access=read, an Allow action is not service: + a read verb, optional
//     literal characters and at most one trailing "*";
//  5. at access=write, an Allow action is a bare "*" ("service:*" is allowed).
//
// Deny statements are never restricted: they only ever remove permissions.
func CheckPolicy(access model.AccessLevel, policyJSON []byte) error {
	if !access.Valid() {
		return fmt.Errorf("capability access level %q is not valid", access)
	}
	// Duplicate keys first: Go keeps the last value (and matches field names
	// case-insensitively) while a cloud parser may keep the first, so a
	// document with duplicates can mean one thing here and another at the cloud.
	if err := RejectDuplicateKeys(policyJSON); err != nil {
		return fmt.Errorf("policy document cannot be checked: %v", err)
	}
	if err := checkTopLevelShape(policyJSON); err != nil {
		return fmt.Errorf("policy document cannot be checked: %v", err)
	}
	statements, err := parseIAMStatements(policyJSON)
	if err != nil {
		return fmt.Errorf("policy document cannot be checked: %v", err)
	}
	if len(statements) == 0 {
		return errors.New("policy document must contain at least one statement")
	}
	// Rule 1 runs over every statement, Deny included: a negated element
	// changes what a Deny statement covers just as much as an Allow one.
	for _, st := range statements {
		// Presence alone is prohibited: a null or empty NotAction is still a
		// NotAction, and a cloud parser may read it as "no exemptions".
		if st.NotAction != nil {
			return errors.New("policy statements must not use NotAction")
		}
		if st.NotResource != nil {
			return errors.New("policy statements must not use NotResource")
		}
	}
	for i, st := range statements {
		// Exactly "Allow" or "Deny": a cloud parser might treat any other value
		// differently from this checker (for example as Allow).
		if st.Effect != "Allow" && st.Effect != "Deny" {
			return fmt.Errorf("statement %d has Effect %q; it must be exactly Allow or Deny", i+1, st.Effect)
		}
		resources, err := jsonStringList(st.Resource)
		if err != nil || len(resources) == 0 {
			return fmt.Errorf("statement %d must have a Resource: a non-empty string or list of strings", i+1)
		}
		for _, resource := range resources {
			if strings.TrimSpace(resource) == "" || resource != strings.TrimSpace(resource) {
				return fmt.Errorf("statement %d has an empty or padded Resource entry", i+1)
			}
		}
	}
	for _, st := range statements {
		if strings.EqualFold(strings.TrimSpace(st.Effect), "Deny") {
			continue
		}
		actions, err := jsonStringList(st.Action)
		if err != nil {
			return fmt.Errorf("policy document cannot be checked: invalid Action: %v", err)
		}
		// An Allow statement must name what it allows: a missing, null or empty
		// Action is structurally invalid and could be read differently by a
		// cloud parser.
		if len(actions) == 0 {
			return errors.New("every Allow statement must list at least one Action")
		}
		for _, action := range actions {
			if err := checkAllowAction(access, action); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkAllowAction applies rules 2-5 to one Allow action.
func checkAllowAction(access model.AccessLevel, action string) error {
	candidate := strings.TrimSpace(action)
	if candidate == "" {
		return fmt.Errorf("action %q is not a valid IAM action", action)
	}
	if candidate != action {
		return fmt.Errorf("action %q must not contain surrounding whitespace", action)
	}
	if candidate == "*" {
		// Rule 2's single exception, and rule 5's rejection for write.
		if access == model.AccessAdmin {
			return nil
		}
		return fmt.Errorf("action %q is only allowed on an admin capability, not on a %s one", action, access)
	}
	service, verb, ok := strings.Cut(candidate, ":")
	if !ok {
		return fmt.Errorf("action %q must be written as service:Action", action)
	}
	if service == "" {
		return fmt.Errorf("action %q has an empty service part", action)
	}
	// Wildcard services get their specific message before the shape check.
	if strings.ContainsAny(service, "*?") {
		return fmt.Errorf("action %q uses a wildcard service part, which no capability may allow", action)
	}
	if !actionPattern.MatchString(candidate) {
		return fmt.Errorf("action %q is not a valid IAM action: expected service:Action using letters, digits, '-', '_' and wildcards", action)
	}
	// Rule 2.
	if strings.EqualFold(service, ramService) {
		return fmt.Errorf("action %q targets RAM (identity management), which no capability may allow", action)
	}
	if strings.ContainsAny(service, "*?") {
		return fmt.Errorf("action %q uses a wildcard service part, which no capability may allow", action)
	}
	// Rule 3.
	if strings.EqualFold(service, stsService) && !strings.EqualFold(verb, stsReadAction) {
		return fmt.Errorf("action %q is not allowed: %s:%s is the only permitted STS action", action, stsService, stsReadAction)
	}
	// Rule 4.
	if access == model.AccessRead {
		return checkReadAction(action, verb)
	}
	return nil
}

// checkReadAction applies rule 4 to the action part of a read capability's
// Allow action.
func checkReadAction(action, verb string) error {
	if verb == "" || verb == "*" {
		return fmt.Errorf("action %q is not a read action: a read capability must name a %s verb", action, strings.Join(readVerbs, "/"))
	}
	if strings.Contains(verb, "?") {
		return fmt.Errorf("action %q is not a read action: single-character wildcards are never allowed", action)
	}
	matched := ""
	for _, candidate := range readVerbs {
		if len(verb) >= len(candidate) && strings.EqualFold(verb[:len(candidate)], candidate) {
			matched = candidate
			break
		}
	}
	if matched == "" {
		return fmt.Errorf("action %q is not a read action: it must start with one of %s", action, strings.Join(readVerbs, ", "))
	}
	if star := strings.IndexByte(verb, '*'); star >= 0 {
		if star != len(verb)-1 {
			return fmt.Errorf("action %q is not a read action: only one trailing \"*\" is allowed", action)
		}
		if star < len(matched) {
			return fmt.Errorf("action %q is not a read action: the full verb must come before the wildcard", action)
		}
	}
	return nil
}

// checkTopLevelShape accepts only a JSON object whose keys are Version and
// Statement (case-insensitive), so no top-level Effect/Action can be read as an
// extra statement by a lenient parser.
func checkTopLevelShape(policyJSON []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(policyJSON, &top); err != nil {
		return fmt.Errorf("invalid policy document: %v", err)
	}
	if top == nil {
		return errors.New("policy document must be a JSON object")
	}
	for key := range top {
		// Exact, case-sensitive names: Alibaba Cloud policy elements are
		// case-sensitive while Go's JSON decoder is not.
		switch key {
		case "Version", "Statement":
		default:
			return fmt.Errorf("policy document has unexpected top-level key %q (only Version and Statement)", key)
		}
	}
	raws, err := rawStatementList(top["Statement"])
	if err != nil {
		return err
	}
	for i, raw := range raws {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
			continue // parseIAMStatements reports the precise shape error
		}
		for key := range fields {
			switch key {
			case "Effect", "Action", "Resource", "Condition", "NotAction", "NotResource":
				// NotAction/NotResource are rejected with a specific message below.
			default:
				return fmt.Errorf("statement %d has unexpected element %q (allowed: Effect, Action, Resource, Condition)", i+1, key)
			}
		}
	}
	return nil
}

// TemplateAllowsEverything reports whether a capability's own template (before
// the mandatory deny statement is appended) has an Allow statement whose
// Action is a bare "*". A credential minted from such a template before the
// deny existed (schema 1) could manage RAM.
func TemplateAllowsEverything(cap model.Capability, params map[string]string) (bool, error) {
	rendered, err := renderTemplate(cap, params)
	if err != nil {
		return false, err
	}
	statements, err := parseIAMStatements(rendered)
	if err != nil {
		return false, err
	}
	for _, st := range statements {
		if strings.EqualFold(strings.TrimSpace(st.Effect), "Deny") {
			continue
		}
		actions, err := jsonStringList(st.Action)
		if err != nil {
			return false, err
		}
		for _, action := range actions {
			if strings.TrimSpace(action) == "*" {
				return true, nil
			}
		}
	}
	return false, nil
}

// RejectDuplicateKeys reports an error when any JSON object in data repeats a
// key, compared case-insensitively. It walks the token stream, so nested
// objects inside arrays are checked too.
func RejectDuplicateKeys(data []byte) error {
	type frame struct {
		object    bool
		expectKey bool
		keys      map[string]bool
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid policy document: %v", err)
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if delim, ok := tok.(json.Delim); ok {
			switch delim {
			case '{', '[':
				if top != nil && top.object {
					// A nested value starts; the parent's next token is a key.
					top.expectKey = true
				}
				stack = append(stack, &frame{object: delim == '{', expectKey: delim == '{', keys: map[string]bool{}})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
			continue
		}
		if top == nil || !top.object {
			continue
		}
		if top.expectKey {
			key, _ := tok.(string)
			// strings.EqualFold uses Unicode simple folding, the same rule
			// encoding/json uses to match keys (so "Reſource" == "Resource").
			for seen := range top.keys {
				if strings.EqualFold(seen, key) {
					return fmt.Errorf("duplicate key %q in policy document", key)
				}
			}
			top.keys[key] = true
			top.expectKey = false
			continue
		}
		top.expectKey = true
	}
}

// appendDenyStatement appends DenyStatement to a policy document's statement
// list, preserving every other field. The returned document is compact, with
// Version first and Statement second so rendered policies stay stable and
// comparable.
func appendDenyStatement(policyJSON []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(policyJSON, &fields); err != nil {
		return nil, fmt.Errorf("document is not a JSON object: %v", err)
	}
	if fields == nil {
		fields = map[string]json.RawMessage{}
	}
	statements, err := rawStatementList(fields["Statement"])
	if err != nil {
		return nil, err
	}
	statements = append(statements, json.RawMessage(DenyStatement))
	encoded, err := json.Marshal(statements)
	if err != nil {
		return nil, fmt.Errorf("cannot re-encode statements: %v", err)
	}
	fields["Statement"] = encoded

	keys := make([]string, 0, len(fields))
	for key := range fields {
		if key == "Version" || key == "Statement" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make([]string, 0, len(fields)+1)
	if _, ok := fields["Version"]; ok {
		ordered = append(ordered, "Version")
	}
	ordered = append(ordered, "Statement")
	ordered = append(ordered, keys...)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, key := range ordered {
		if i > 0 {
			buf.WriteByte(',')
		}
		name, err := json.Marshal(key)
		if err != nil {
			return nil, fmt.Errorf("cannot re-encode field %q: %v", key, err)
		}
		buf.Write(name)
		buf.WriteByte(':')
		buf.Write(fields[key])
	}
	buf.WriteByte('}')

	var compact bytes.Buffer
	if err := json.Compact(&compact, buf.Bytes()); err != nil {
		return nil, fmt.Errorf("document is not valid JSON after appending the deny statement: %v", err)
	}
	return compact.Bytes(), nil
}

// iamStatement is one statement as inspected by CheckPolicy. Unknown fields
// (Condition, Sid, ...) are ignored; NotAction/NotResource are kept raw so
// their presence can be detected regardless of shape.
type iamStatement struct {
	Effect      string          `json:"Effect"`
	Action      json.RawMessage `json:"Action"`
	NotAction   json.RawMessage `json:"NotAction"`
	Resource    json.RawMessage `json:"Resource"`
	NotResource json.RawMessage `json:"NotResource"`
}

// parseIAMStatements parses a policy document's statements, accepting both the
// single-object and the array form of Statement.
func parseIAMStatements(policyJSON []byte) ([]iamStatement, error) {
	var doc struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal(policyJSON, &doc); err != nil {
		return nil, fmt.Errorf("invalid policy document: %v", err)
	}
	raws, err := rawStatementList(doc.Statement)
	if err != nil {
		return nil, err
	}
	out := make([]iamStatement, 0, len(raws))
	for i, raw := range raws {
		if !hasJSONValue(raw) {
			return nil, fmt.Errorf("statement %d is null", i+1)
		}
		trimmed := bytes.TrimSpace(raw)
		if trimmed[0] != '{' {
			return nil, fmt.Errorf("statement %d is not an object", i+1)
		}
		var st iamStatement
		if err := json.Unmarshal(raw, &st); err != nil {
			return nil, fmt.Errorf("statement %d is not a valid IAM statement: %v", i+1, err)
		}
		out = append(out, st)
	}
	return out, nil
}

// rawStatementList normalizes a Statement value into a list of raw statements.
func rawStatementList(raw json.RawMessage) ([]json.RawMessage, error) {
	if !hasJSONValue(raw) {
		return nil, nil
	}
	trimmed := bytes.TrimSpace(raw)
	switch trimmed[0] {
	case '[':
		var list []json.RawMessage
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, fmt.Errorf("Statement is not a valid statement array: %v", err)
		}
		return list, nil
	case '{':
		return []json.RawMessage{trimmed}, nil
	default:
		return nil, errors.New("Statement must be an object or an array of objects")
	}
}

// jsonStringList normalizes an Action/Resource value into a string slice,
// accepting both the single-string and the array form.
func jsonStringList(raw json.RawMessage) ([]string, error) {
	if !hasJSONValue(raw) {
		return nil, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if trimmed[0] == '[' {
		var list []string
		if err := json.Unmarshal(trimmed, &list); err != nil {
			return nil, err
		}
		return list, nil
	}
	var one string
	if err := json.Unmarshal(trimmed, &one); err != nil {
		return nil, err
	}
	return []string{one}, nil
}

// hasJSONValue reports whether a raw JSON field is present and not null.
func hasJSONValue(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}
