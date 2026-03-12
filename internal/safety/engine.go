package safety

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Config describes the rules to load into an Engine.
type Config struct {
	// InputRules are evaluated against incoming requests.
	InputRules []RuleConfig `json:"input_rules"`
	// OutputRules are evaluated against outgoing responses.
	OutputRules []RuleConfig `json:"output_rules"`
}

// RuleConfig is the user-facing (serialisable) representation of a rule.
// Either Pattern or Preset must be set, but not both.
type RuleConfig struct {
	// ID is a unique identifier. Required for custom rules; ignored for presets
	// (preset rules carry their own IDs).
	ID string `json:"id"`
	// Name is a human-readable label. Optional for presets.
	Name string `json:"name"`
	// Pattern is a regular expression string. Mutually exclusive with Preset.
	Pattern string `json:"pattern"`
	// Preset is the name of a built-in preset to expand. Mutually exclusive
	// with Pattern.
	Preset string `json:"preset"`
	// Targets lists which parts of the request/response to inspect.
	// Required for custom rules; ignored for presets (preset rules carry
	// their own targets).
	Targets []string `json:"targets"`
	// Action is "block", "mask", or "log_only". Required for custom rules;
	// ignored for presets.
	Action string `json:"action"`
	// Replacement is used for mask action. When set on a preset RuleConfig,
	// it overrides the preset's default replacement for all rules in that preset.
	Replacement string `json:"replacement"`
}

// Engine holds compiled input and output filter rules. It is safe for
// concurrent use because rules are immutable after construction.
type Engine struct {
	inputRules  []Rule
	outputRules []Rule
}

// InputViolation describes a matched input filter rule.
type InputViolation struct {
	// RuleID is the ID of the matched rule.
	RuleID string
	// RuleName is the human-readable name of the matched rule.
	RuleName string
	// Target is which part of the request was matched.
	Target Target
	// MatchedOn is the string fragment that triggered the match.
	MatchedOn string
}

// OutputResult holds the result of output filtering on body data.
type OutputResult struct {
	// Data is the (possibly modified) output data.
	Data []byte
	// Masked is true if any replacements were made.
	Masked bool
	// Matches lists which rules matched and how many times.
	Matches []OutputMatch
}

// OutputMatch records how many times a particular rule matched.
type OutputMatch struct {
	// RuleID is the ID of the matched rule.
	RuleID string
	// Count is the number of times the pattern matched.
	Count int
	// Action is the action associated with the matched rule.
	Action Action
}

// NewEngine compiles rules from the given configuration and returns an
// immutable Engine. It returns an error if any pattern fails to compile,
// a preset name is unknown, or a custom rule is missing required fields.
func NewEngine(cfg Config) (*Engine, error) {
	input, err := compileRules(cfg.InputRules)
	if err != nil {
		return nil, fmt.Errorf("input rules: %w", err)
	}
	output, err := compileRules(cfg.OutputRules)
	if err != nil {
		return nil, fmt.Errorf("output rules: %w", err)
	}
	return &Engine{
		inputRules:  input,
		outputRules: output,
	}, nil
}

// compileRules converts a slice of RuleConfig into compiled Rules.
func compileRules(configs []RuleConfig) ([]Rule, error) {
	var rules []Rule
	seen := make(map[string]bool)

	for i, rc := range configs {
		expanded, err := expandRuleConfig(rc, i)
		if err != nil {
			return nil, err
		}
		for j := range expanded {
			r := &expanded[j]
			if err := r.Validate(); err != nil {
				return nil, err
			}
			if seen[r.ID] {
				return nil, fmt.Errorf("duplicate rule ID: %q", r.ID)
			}
			seen[r.ID] = true
			rules = append(rules, *r)
		}
	}
	return rules, nil
}

// expandRuleConfig expands a single RuleConfig into one or more compiled Rules.
// Preset configs expand into multiple rules; custom configs produce exactly one.
func expandRuleConfig(rc RuleConfig, index int) ([]Rule, error) {
	if rc.Preset != "" && rc.Pattern != "" {
		return nil, fmt.Errorf("rule at index %d: pattern and preset are mutually exclusive", index)
	}

	if rc.Preset != "" {
		return expandPreset(rc)
	}

	return expandCustom(rc, index)
}

// expandPreset resolves a preset name and compiles its rules.
func expandPreset(rc RuleConfig) ([]Rule, error) {
	preset, err := LookupPreset(rc.Preset)
	if err != nil {
		return nil, fmt.Errorf("unknown preset: %q", rc.Preset)
	}

	action := ActionBlock // default action for preset rules
	if rc.Action != "" {
		a, err := ParseAction(rc.Action)
		if err != nil {
			return nil, fmt.Errorf("preset %q: %w", rc.Preset, err)
		}
		action = a
	}

	rules := make([]Rule, 0, len(preset.Rules))
	for _, pr := range preset.Rules {
		re, err := regexp.Compile(pr.Pattern)
		if err != nil {
			return nil, fmt.Errorf("preset %q rule %q: invalid pattern: %w", rc.Preset, pr.ID, err)
		}

		rules = append(rules, Rule{
			ID:          pr.ID,
			Name:        pr.Name,
			Pattern:     re,
			Targets:     pr.Targets,
			Action:      action,
			Replacement: rc.Replacement,
			Category:    preset.Name,
		})
	}
	return rules, nil
}

// expandCustom compiles a single custom rule.
func expandCustom(rc RuleConfig, index int) ([]Rule, error) {
	if rc.ID == "" {
		return nil, fmt.Errorf("rule at index %d: id is required for custom rules", index)
	}
	if rc.Pattern == "" {
		return nil, fmt.Errorf("rule %q: pattern is required for custom rules", rc.ID)
	}
	if rc.Action == "" {
		return nil, fmt.Errorf("rule %q: action is required for custom rules", rc.ID)
	}
	if len(rc.Targets) == 0 {
		return nil, fmt.Errorf("rule %q: at least one target is required", rc.ID)
	}

	re, err := regexp.Compile(rc.Pattern)
	if err != nil {
		return nil, fmt.Errorf("rule %q: invalid pattern: %w", rc.ID, err)
	}

	action, err := ParseAction(rc.Action)
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", rc.ID, err)
	}

	targets := make([]Target, 0, len(rc.Targets))
	var headerName string
	for _, ts := range rc.Targets {
		// Handle "header:Name" syntax.
		base := ts
		if strings.HasPrefix(strings.ToLower(ts), "header:") {
			headerName = ts[len("header:"):]
			base = "header"
		}
		t, err := ParseTarget(base)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rc.ID, err)
		}
		targets = append(targets, t)
	}

	name := rc.Name
	if name == "" {
		name = rc.ID
	}

	return []Rule{{
		ID:          rc.ID,
		Name:        name,
		Pattern:     re,
		Targets:     targets,
		Action:      action,
		Replacement: rc.Replacement,
		Category:    "custom",
		HeaderName:  headerName,
	}}, nil
}

// CheckInput evaluates all input rules against the given request components.
// It returns the first violation found, or nil if no rules matched.
func (e *Engine) CheckInput(body []byte, rawURL string, headers http.Header) *InputViolation {
	for i := range e.inputRules {
		r := &e.inputRules[i]
		for _, target := range r.Targets {
			matched, fragment := matchTarget(r.Pattern, target, body, rawURL, headers, r.HeaderName)
			if matched {
				return &InputViolation{
					RuleID:    r.ID,
					RuleName:  r.Name,
					Target:    target,
					MatchedOn: fragment,
				}
			}
		}
	}
	return nil
}

// matchTarget checks a compiled pattern against the specified target data.
// headerName is used with TargetHeader to restrict matching to a specific header.
func matchTarget(re *regexp.Regexp, target Target, body []byte, rawURL string, headers http.Header, headerName string) (bool, string) {
	switch target {
	case TargetBody:
		return matchBody(re, body)
	case TargetURL:
		return matchString(re, rawURL)
	case TargetQuery:
		return matchQuery(re, rawURL)
	case TargetHeader:
		if headerName != "" {
			return matchNamedHeaderValues(re, headers, headerName)
		}
		return matchHeaderValues(re, headers)
	case TargetHeaders:
		return matchAllHeaders(re, headers)
	default:
		return false, ""
	}
}

// matchBody checks the pattern against a byte slice body.
func matchBody(re *regexp.Regexp, body []byte) (bool, string) {
	loc := re.FindIndex(body)
	if loc == nil {
		return false, ""
	}
	return true, string(body[loc[0]:loc[1]])
}

// matchString checks the pattern against a plain string.
func matchString(re *regexp.Regexp, s string) (bool, string) {
	loc := re.FindStringIndex(s)
	if loc == nil {
		return false, ""
	}
	return true, s[loc[0]:loc[1]]
}

// matchQuery extracts the query string from a URL and checks the pattern.
func matchQuery(re *regexp.Regexp, rawURL string) (bool, string) {
	idx := strings.IndexByte(rawURL, '?')
	if idx < 0 {
		return false, ""
	}
	return matchString(re, rawURL[idx+1:])
}

// matchHeaderValues checks the pattern against each header value individually.
func matchHeaderValues(re *regexp.Regexp, headers http.Header) (bool, string) {
	for _, values := range headers {
		for _, v := range values {
			if m := re.FindString(v); m != "" {
				return true, m
			}
		}
	}
	return false, ""
}

// matchNamedHeaderValues checks the pattern against values of a specific header.
func matchNamedHeaderValues(re *regexp.Regexp, headers http.Header, name string) (bool, string) {
	values := headers.Values(name)
	for _, v := range values {
		if matched, fragment := matchString(re, v); matched {
			return true, fragment
		}
	}
	return false, ""
}

// matchAllHeaders concatenates all headers in sorted key order and checks the
// pattern. Sorting ensures deterministic matching order for testability.
func matchAllHeaders(re *regexp.Regexp, headers http.Header) (bool, string) {
	keys := make([]string, 0, len(headers))
	for name := range headers {
		keys = append(keys, name)
	}
	sort.Strings(keys)

	var sb strings.Builder
	for _, name := range keys {
		for _, v := range headers[name] {
			sb.WriteString(name)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
	}
	return matchString(re, sb.String())
}

// FilterOutput applies all output rules with ActionMask to the given data,
// replacing matched patterns. Rules with ActionBlock or ActionLogOnly are
// recorded in matches but do not modify data.
func (e *Engine) FilterOutput(data []byte) *OutputResult {
	result := &OutputResult{
		Data: data,
	}

	for i := range e.outputRules {
		r := &e.outputRules[i]
		// Only body target is relevant for FilterOutput.
		if !hasTarget(r.Targets, TargetBody) {
			continue
		}

		locs := r.Pattern.FindAllIndex(result.Data, -1)
		if len(locs) == 0 {
			continue
		}

		result.Matches = append(result.Matches, OutputMatch{
			RuleID: r.ID,
			Count:  len(locs),
			Action: r.Action,
		})

		if r.Action == ActionMask {
			result.Data = r.Pattern.ReplaceAll(result.Data, []byte(r.Replacement))
			result.Masked = true
		}
	}

	return result
}

// FilterOutputHeaders applies output rules with TargetHeader or TargetHeaders
// to HTTP headers. It returns the (possibly modified) headers and any matches.
func (e *Engine) FilterOutputHeaders(headers http.Header) (http.Header, []OutputMatch) {
	var matches []OutputMatch
	modified := headers.Clone()

	for i := range e.outputRules {
		r := &e.outputRules[i]

		if hasTarget(r.Targets, TargetHeaders) {
			if c := applyRuleToHeaders(r, modified, ""); c > 0 {
				matches = append(matches, OutputMatch{RuleID: r.ID, Count: c, Action: r.Action})
			}
		}

		if hasTarget(r.Targets, TargetHeader) {
			if c := applyRuleToHeaders(r, modified, r.HeaderName); c > 0 {
				matches = append(matches, OutputMatch{RuleID: r.ID, Count: c, Action: r.Action})
			}
		}
	}

	return modified, matches
}

// applyRuleToHeaders applies a rule's pattern to the given headers and returns
// the total match count. If filterName is non-empty, only the named header is
// checked; otherwise all headers are checked.
func applyRuleToHeaders(r *Rule, headers http.Header, filterName string) int {
	totalCount := 0
	for name, values := range headers {
		if filterName != "" && !strings.EqualFold(name, filterName) {
			continue
		}
		for j, v := range values {
			locs := r.Pattern.FindAllStringIndex(v, -1)
			if len(locs) == 0 {
				continue
			}
			totalCount += len(locs)
			if r.Action == ActionMask {
				headers[name][j] = r.Pattern.ReplaceAllString(v, r.Replacement)
			}
		}
	}
	return totalCount
}

// hasTarget returns true if the given target is in the list.
func hasTarget(targets []Target, t Target) bool {
	for _, tt := range targets {
		if tt == t {
			return true
		}
	}
	return false
}

// InputRules returns the compiled input rules. This is intended for
// inspection and testing only.
func (e *Engine) InputRules() []Rule {
	return e.inputRules
}

// OutputRules returns the compiled output rules. This is intended for
// inspection and testing only.
func (e *Engine) OutputRules() []Rule {
	return e.outputRules
}
