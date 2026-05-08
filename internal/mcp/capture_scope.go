package mcp

import (
	"errors"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// captureScopeInput is the proxy_start payload for the capture_scope
// recording-only observability filter (USK-776). Each rule is AND-evaluated
// across hostname / url_prefix / method; excludes take precedence over
// includes; an empty configuration captures every flow (current default).
//
// The shape mirrors the legacy USK-63 surface that was deleted in USK-705
// so existing scripts and skill data continue to work after re-introduction.
type captureScopeInput struct {
	// Includes lists rules whose match opts the flow into recording.
	// An empty slice means "all flows are eligible" — only excludes apply.
	Includes []scopeRuleInput `json:"includes,omitempty" jsonschema:"rules whose match opts a flow into recording (empty = all flows eligible)"`

	// Excludes lists rules whose match opts the flow out of recording.
	// Excludes are evaluated before includes; a flow that matches any
	// exclude is never recorded regardless of include matches.
	Excludes []scopeRuleInput `json:"excludes,omitempty" jsonschema:"rules whose match suppresses recording (evaluated before includes)"`
}

// scopeRuleInput is the JSON-facing shape of a single capture_scope rule.
// At least one of hostname / url_prefix / method must be non-empty;
// empty rules are rejected at validation time. See flow.ScopeRule for
// the runtime semantics of each field.
type scopeRuleInput struct {
	// Hostname matches the request hostname (case-insensitive). The
	// "*.example.com" wildcard prefix matches every direct or indirect
	// subdomain of example.com but NOT the apex.
	Hostname string `json:"hostname,omitempty" jsonschema:"target hostname; supports the '*.example.com' wildcard prefix"`

	// URLPrefix matches strings.HasPrefix on the request URL path
	// (case- and percent-encoding-sensitive).
	URLPrefix string `json:"url_prefix,omitempty" jsonschema:"URL path prefix (case-sensitive byte prefix)"`

	// Method matches the HTTP method (case-insensitive). Inert against
	// non-HTTP envelopes (WS / gRPC / SSE / Raw frames have no method).
	Method string `json:"method,omitempty" jsonschema:"HTTP method (case-insensitive)"`
}

// configureCaptureScope is the configure_tool payload for runtime
// updates of the capture_scope filter. The discriminator is the
// configureInput.Operation field (merge | replace).
//
// merge: applies add/remove deltas to the current rules under a single
// lock. Add operations skip rules that already exist; remove operations
// strip every entry that matches the supplied rule.
//
// replace: overwrites the entire include/exclude lists with the supplied
// values. Useful for declarative rollback to a known-good state.
type configureCaptureScope struct {
	// Merge fields.
	AddIncludes    []scopeRuleInput `json:"add_includes,omitempty" jsonschema:"(merge) include rules to add"`
	RemoveIncludes []scopeRuleInput `json:"remove_includes,omitempty" jsonschema:"(merge) include rules to remove"`
	AddExcludes    []scopeRuleInput `json:"add_excludes,omitempty" jsonschema:"(merge) exclude rules to add"`
	RemoveExcludes []scopeRuleInput `json:"remove_excludes,omitempty" jsonschema:"(merge) exclude rules to remove"`

	// Replace fields.
	Includes []scopeRuleInput `json:"includes,omitempty" jsonschema:"(replace) full list of include rules"`
	Excludes []scopeRuleInput `json:"excludes,omitempty" jsonschema:"(replace) full list of exclude rules"`
}

// scopeRuleInputToFlow converts a JSON-facing rule into the runtime
// flow.ScopeRule type used by the data path.
func scopeRuleInputToFlow(in scopeRuleInput) flow.ScopeRule {
	return flow.ScopeRule{
		Hostname:  in.Hostname,
		URLPrefix: in.URLPrefix,
		Method:    in.Method,
	}
}

// scopeRulesInputToFlow converts a slice of input rules in one pass.
// Returns nil for an empty input so callers can reflect "no rules".
func scopeRulesInputToFlow(in []scopeRuleInput) []flow.ScopeRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]flow.ScopeRule, len(in))
	for i, r := range in {
		out[i] = scopeRuleInputToFlow(r)
	}
	return out
}

// scopeRuleInputFromFlow converts a runtime rule back to the JSON
// shape, used by query{config} when echoing the active scope.
func scopeRuleInputFromFlow(r flow.ScopeRule) scopeRuleInput {
	return scopeRuleInput{
		Hostname:  r.Hostname,
		URLPrefix: r.URLPrefix,
		Method:    r.Method,
	}
}

// scopeRulesInputFromFlow converts a slice in one pass. Returns an empty
// slice rather than nil so the JSON form is always a present array.
func scopeRulesInputFromFlow(rs []flow.ScopeRule) []scopeRuleInput {
	out := make([]scopeRuleInput, 0, len(rs))
	for _, r := range rs {
		out = append(out, scopeRuleInputFromFlow(r))
	}
	return out
}

// validateCaptureScopeInput rejects empty rules (no field set) — the
// flow.RecordScope matcher would treat such a rule as a wildcard, which
// is rarely the user's intent and almost always a typo. Returns a nil
// error when in is nil or has no rules.
func validateCaptureScopeInput(in *captureScopeInput) error {
	if in == nil {
		return nil
	}
	if err := validateScopeRules("includes", in.Includes); err != nil {
		return err
	}
	return validateScopeRules("excludes", in.Excludes)
}

// validateScopeRules performs the per-rule validation shared by
// proxy_start (replace-like) and configure (merge / replace) inputs.
// section is included in the error message so callers can pinpoint the
// offending list.
func validateScopeRules(section string, rules []scopeRuleInput) error {
	for i, r := range rules {
		fr := scopeRuleInputToFlow(r)
		if fr.IsEmpty() {
			return fmt.Errorf("capture_scope.%s[%d]: rule must set at least one of hostname / url_prefix / method", section, i)
		}
	}
	return nil
}

// applyCaptureScope applies a proxy_start capture_scope payload to the
// shared *flow.RecordScope held on the Server's FlowStore component. nil
// input is a no-op (the scope was already cleared in
// resetSettingsToDefaults). Validation runs first so a malformed rule
// short-circuits before mutating runtime state.
func (s *Server) applyCaptureScope(in *captureScopeInput) error {
	if in == nil {
		return nil
	}
	if err := validateCaptureScopeInput(in); err != nil {
		return err
	}
	scope := s.flowStore.recordScope
	if scope == nil {
		return errors.New("capture_scope: record scope not initialised")
	}
	scope.SetRules(
		scopeRulesInputToFlow(in.Includes),
		scopeRulesInputToFlow(in.Excludes),
	)
	return nil
}

// applyConfigureCaptureScope applies a configure-tool capture_scope
// payload according to the operation discriminator. merge applies
// add/remove deltas; replace overwrites the rule lists.
//
// Validation rejects empty rules in any of the four merge slices and
// the two replace slices so a typo cannot install a wildcard rule.
func (s *Server) applyConfigureCaptureScope(operation string, in *configureCaptureScope) error {
	if in == nil {
		return nil
	}
	scope := s.flowStore.recordScope
	if scope == nil {
		return errors.New("capture_scope: record scope not initialised")
	}

	switch operation {
	case "", "merge":
		if err := validateScopeRules("add_includes", in.AddIncludes); err != nil {
			return err
		}
		if err := validateScopeRules("remove_includes", in.RemoveIncludes); err != nil {
			return err
		}
		if err := validateScopeRules("add_excludes", in.AddExcludes); err != nil {
			return err
		}
		if err := validateScopeRules("remove_excludes", in.RemoveExcludes); err != nil {
			return err
		}
		scope.MergeRules(
			scopeRulesInputToFlow(in.AddIncludes),
			scopeRulesInputToFlow(in.RemoveIncludes),
			scopeRulesInputToFlow(in.AddExcludes),
			scopeRulesInputToFlow(in.RemoveExcludes),
		)
	case "replace":
		if err := validateScopeRules("includes", in.Includes); err != nil {
			return err
		}
		if err := validateScopeRules("excludes", in.Excludes); err != nil {
			return err
		}
		scope.SetRules(
			scopeRulesInputToFlow(in.Includes),
			scopeRulesInputToFlow(in.Excludes),
		)
	default:
		return fmt.Errorf("capture_scope: unsupported operation %q (expected merge or replace)", operation)
	}
	return nil
}
