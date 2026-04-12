package common

import (
	"regexp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// ActionType specifies the action to take on a held envelope.
type ActionType int

const (
	// ActionRelease forwards the envelope as-is.
	ActionRelease ActionType = iota
	// ActionModifyAndForward forwards a modified envelope.
	ActionModifyAndForward
	// ActionDrop discards the envelope.
	ActionDrop
)

// String returns a human-readable name for the action type.
func (a ActionType) String() string {
	switch a {
	case ActionRelease:
		return "release"
	case ActionModifyAndForward:
		return "modify_and_forward"
	case ActionDrop:
		return "drop"
	default:
		return "unknown"
	}
}

// HoldAction is the action returned by HoldQueue.Hold() after an external
// agent decides what to do with a held envelope.
type HoldAction struct {
	Type     ActionType
	Modified *envelope.Envelope // non-nil when Type == ActionModifyAndForward
}

// TimeoutBehavior specifies what happens when a held envelope times out.
type TimeoutBehavior string

const (
	// TimeoutAutoRelease forwards the envelope on timeout.
	TimeoutAutoRelease TimeoutBehavior = "auto_release"
	// TimeoutAutoDrop discards the envelope on timeout.
	TimeoutAutoDrop TimeoutBehavior = "auto_drop"
)

// Target identifies which part of a message a rule inspects.
type Target string

const (
	TargetBody    Target = "body"
	TargetURL     Target = "url"
	TargetQuery   Target = "query"
	TargetHeader  Target = "header"
	TargetHeaders Target = "headers"
)

// PresetRuleConfig defines a safety or intercept rule before regex compilation.
type PresetRuleConfig struct {
	ID          string
	Name        string
	Pattern     string // uncompiled regex
	Targets     []Target
	Replacement string                  // for mask action
	Validator   func(match []byte) bool // optional post-match validation (e.g. Luhn)
}

// Preset is a named collection of rule configurations.
type Preset struct {
	Name  string
	Rules []PresetRuleConfig
}

// CompiledRule is a preset rule with a compiled regex, ready for evaluation.
type CompiledRule struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Targets     []Target
	Replacement string
	Category    string // preset name or "custom"
	Validator   func(match []byte) bool
}
