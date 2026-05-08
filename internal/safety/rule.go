package safety

import (
	"fmt"
	"regexp"
	"strings"
)

// Target identifies which part of a request or response a rule inspects.
type Target int

const (
	// TargetBody matches against the request or response body.
	TargetBody Target = iota
	// TargetURL matches against the raw URL string.
	TargetURL
	// TargetQuery matches against the query string portion of the URL.
	TargetQuery
	// TargetHeader matches against a specific header value (e.g. "header:Location").
	TargetHeader
	// TargetHeaders matches against all header values concatenated.
	TargetHeaders

	// Per-protocol targets accepted at config-load time so a single
	// SafetyFilter Input rule list can address WS and gRPC envelopes
	// (the live SafetyFilter path applies the same compiled rule set
	// across HTTP / WS / gRPC per-protocol engines — see
	// internal/mcpserver/safety_perprotocol.go::compileCustomInputRule).
	// The Policy Layer Engine here (internal/safety) consumes only
	// HTTP-shaped data via CheckInput(body, rawURL, headers), so these
	// targets are intentionally no-ops in matchTarget — the per-protocol
	// engines (internal/rules/{ws,grpc}) carry the actual semantics.
	// Without this acceptance, custom rules with WS/gRPC-local targets
	// would fail at boot before reaching the per-protocol engines that
	// understand them.

	// TargetPayload matches the WS frame payload (internal/rules/ws::TargetPayload)
	// or the gRPC message payload (internal/rules/grpc::TargetPayload). Shared
	// spelling because both protocols treat the message body as "payload".
	TargetPayload
	// TargetOpcode matches the WS frame opcode rendered as a hex string
	// (internal/rules/ws::TargetOpcode). WS-only.
	TargetOpcode
	// TargetMetadata matches gRPC metadata (internal/rules/grpc::TargetMetadata).
	// gRPC-only.
	TargetMetadata
	// TargetService matches the gRPC service name (internal/rules/grpc::TargetService).
	// gRPC-only.
	TargetService
	// TargetMethod matches the gRPC method name (internal/rules/grpc::TargetMethod).
	// gRPC-only.
	TargetMethod
)

// targetNames maps Target values to their string representation.
var targetNames = map[Target]string{
	TargetBody:     "body",
	TargetURL:      "url",
	TargetQuery:    "query",
	TargetHeader:   "header",
	TargetHeaders:  "headers",
	TargetPayload:  "payload",
	TargetOpcode:   "opcode",
	TargetMetadata: "metadata",
	TargetService:  "service",
	TargetMethod:   "method",
}

// String returns the human-readable name of the target.
func (t Target) String() string {
	if s, ok := targetNames[t]; ok {
		return s
	}
	return fmt.Sprintf("Target(%d)", int(t))
}

// ParseTarget converts a string to a Target value.
// It accepts the HTTP-canonical targets ("body", "url", "query", "header",
// "headers") and the per-protocol targets ("payload", "opcode", "metadata",
// "service", "method"). Header-specific targets like "header:Location"
// should be parsed by the caller; this function only handles the base
// target names.
func ParseTarget(s string) (Target, error) {
	switch strings.ToLower(s) {
	case "body":
		return TargetBody, nil
	case "url":
		return TargetURL, nil
	case "query":
		return TargetQuery, nil
	case "header":
		return TargetHeader, nil
	case "headers":
		return TargetHeaders, nil
	case "payload":
		return TargetPayload, nil
	case "opcode":
		return TargetOpcode, nil
	case "metadata":
		return TargetMetadata, nil
	case "service":
		return TargetService, nil
	case "method":
		return TargetMethod, nil
	default:
		return 0, fmt.Errorf("unknown target: %q", s)
	}
}

// Action defines what happens when a rule matches.
type Action int

const (
	// ActionBlock rejects the request entirely.
	ActionBlock Action = iota
	// ActionMask replaces matched content with a replacement string.
	ActionMask
	// ActionLogOnly logs the match but allows the request through.
	ActionLogOnly
)

// actionNames maps Action values to their string representation.
var actionNames = map[Action]string{
	ActionBlock:   "block",
	ActionMask:    "mask",
	ActionLogOnly: "log_only",
}

// String returns the human-readable name of the action.
func (a Action) String() string {
	if s, ok := actionNames[a]; ok {
		return s
	}
	return fmt.Sprintf("Action(%d)", int(a))
}

// ParseAction converts a string to an Action value.
func ParseAction(s string) (Action, error) {
	switch strings.ToLower(s) {
	case "block":
		return ActionBlock, nil
	case "mask":
		return ActionMask, nil
	case "log_only":
		return ActionLogOnly, nil
	default:
		return 0, fmt.Errorf("unknown action: %q", s)
	}
}

// Rule defines a single filter rule with a compiled regular expression.
type Rule struct {
	// ID is a unique identifier for the rule.
	ID string
	// Name is a human-readable name for the rule.
	Name string
	// Pattern is the compiled regular expression.
	Pattern *regexp.Regexp
	// Targets lists which parts of the request/response to inspect.
	Targets []Target
	// Action defines what happens when the pattern matches.
	Action Action
	// Replacement is used by ActionMask to replace matched content.
	// Supports capture group references ($1, $2, etc.).
	Replacement string
	// Category identifies the source: a preset name or "custom".
	Category string
	// HeaderName is the specific header name for TargetHeader rules
	// (e.g. "Location" from the "header:Location" syntax). Empty means
	// all headers are checked.
	HeaderName string
	// Validator is an optional function that performs additional validation
	// on a regex match. If non-nil, the match is only processed
	// (masked/counted) when Validator returns true. This enables patterns
	// like Luhn check for credit card numbers.
	//
	// Implementations must handle variable-length matches safely and must
	// not index into the match slice without bounds checking, as the
	// length of match depends on the actual matched content.
	Validator func(match []byte) bool
}

// PresetRuleConfig defines a safety filter rule before regex compilation.
// Presets use this type so that patterns are compiled once during engine
// initialisation rather than at package init time.
type PresetRuleConfig struct {
	ID      string
	Name    string
	Pattern string // Regular expression pattern (uncompiled).
	Targets []Target
	// Replacement is the default replacement string for ActionMask.
	// When a user-level RuleConfig also sets Replacement, the user value
	// takes precedence (see expandPreset).
	Replacement string
	// Validator is an optional post-match validation function.
	// See Rule.Validator for semantics.
	Validator func(match []byte) bool
}

// Preset is a named collection of rule configurations that can be referenced
// from the proxy configuration file (e.g. preset: "destructive-sql").
type Preset struct {
	Name  string
	Rules []PresetRuleConfig
}

// Validate checks that a Rule has all required fields set. This guards
// against accidentally using a zero-value Rule, where iota defaults would
// silently set Action=ActionBlock and Targets containing TargetBody.
func (r *Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule validation: id is required")
	}
	if r.Pattern == nil {
		return fmt.Errorf("rule %q validation: compiled pattern is required", r.ID)
	}
	if len(r.Targets) == 0 {
		return fmt.Errorf("rule %q validation: at least one target is required", r.ID)
	}
	return nil
}
