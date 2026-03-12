package safety

import "regexp"

// Target specifies which part of an HTTP request a rule inspects.
type Target int

const (
	// TargetBody inspects the request body.
	TargetBody Target = iota
	// TargetURL inspects the request URL path.
	TargetURL
	// TargetQuery inspects the URL query string.
	TargetQuery
	// TargetHeader inspects a specific header value.
	TargetHeader
	// TargetHeaders inspects all header values.
	TargetHeaders
)

// Action specifies the response when a rule matches.
type Action int

const (
	// ActionBlock rejects the request entirely.
	ActionBlock Action = iota
	// ActionMask redacts the matched content before forwarding.
	ActionMask
	// ActionLogOnly logs the match but forwards the request unchanged.
	ActionLogOnly
)

// Rule is a compiled safety filter rule ready for evaluation.
type Rule struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Targets     []Target
	Action      Action
	Replacement string
	Category    string
}

// RuleConfig defines a safety filter rule before regex compilation.
// Presets use this type so that patterns are compiled once during engine
// initialisation rather than at package init time.
type RuleConfig struct {
	ID      string
	Name    string
	Pattern string // Regular expression pattern (uncompiled).
	Targets []Target
}

// Preset is a named collection of rule configurations that can be referenced
// from the proxy configuration file (e.g. preset: "destructive-sql").
type Preset struct {
	Name  string
	Rules []RuleConfig
}
