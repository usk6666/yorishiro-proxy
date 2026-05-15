package sse

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// TransformActionType enumerates the supported SSE transform actions.
//
// MITM principles:
//
//   - Actions mutate envelope.SSEMessage fields directly. The session-
//     side `sseMessageMutated` field-diff (relaySSEEvent) is the
//     authoritative re-encode signal — engines do NOT clear env.Raw.
//   - Anomalies are record-only metadata; no action mutates them.
//   - PrependData / AppendData emit raw concatenation. The engine does
//     NOT auto-insert newline boundaries. Operators control "single line"
//     vs "multi-line" by including or omitting `\n` in their value.
//   - SetEvent / SetID / PrependData / AppendData / ReplaceData
//     replacement bodies reject CR or LF at compile time (CWE-113).
//     SetData accepts `\n` (multi-line data is legal per RFC 8895) but
//     rejects `\r`.
//   - SetRetry interprets the input as integer ms. 0 clears the retry
//     field (the encoder omits the line entirely when Retry == 0).
type TransformActionType int

const (
	// TransformSetEvent assigns SSEMessage.Event verbatim.
	TransformSetEvent TransformActionType = iota
	// TransformSetID assigns SSEMessage.ID verbatim.
	TransformSetID
	// TransformSetData replaces SSEMessage.Data verbatim. Empty string
	// clears the field (the encoder omits the line entirely).
	TransformSetData
	// TransformReplaceData runs a regex over SSEMessage.Data and writes
	// the result back. Replacement is global (ReplaceAllString).
	TransformReplaceData
	// TransformPrependData prepends a string to SSEMessage.Data without
	// any auto-newline insertion.
	TransformPrependData
	// TransformAppendData appends a string to SSEMessage.Data without
	// any auto-newline insertion.
	TransformAppendData
	// TransformSetRetry assigns SSEMessage.Retry from RetryMs (uint32
	// ms). 0 clears the field.
	TransformSetRetry
	// TransformDrop signals the Pipeline to drop the event. Honoured by
	// TransformStep via a Result{Action: Drop} return.
	TransformDrop
)

// TransformRule defines a single SSE transformation with match
// conditions and an action.
type TransformRule struct {
	ID       string
	Enabled  bool
	Priority int // lower values applied first; higher-priority writes win on scalar conflicts

	// Match conditions (AND-combined; empty matches all). The shape
	// mirrors InterceptRule so configure_tool can share validators.
	Direction    RuleDirection
	EventPattern *regexp.Regexp
	IDPattern    *regexp.Regexp
	DataPattern  *regexp.Regexp
	RetryMinMs   *int64
	RetryMaxMs   *int64
	Anomalies    []string

	// Action.
	ActionType         TransformActionType
	SetEventValue      string
	SetIDValue         string
	SetDataValue       string
	PrependDataValue   string
	AppendDataValue    string
	ReplaceDataPattern *regexp.Regexp
	ReplaceDataWith    string
	SetRetryMs         uint32
}

// TransformEngine applies SSE transform rules in priority order.
// Thread-safe via RWMutex.
type TransformEngine struct {
	mu    sync.RWMutex
	rules []TransformRule
}

// NewTransformEngine creates an empty engine.
func NewTransformEngine() *TransformEngine {
	return &TransformEngine{}
}

// SetRules replaces all rules atomically and re-sorts by priority.
func (e *TransformEngine) SetRules(rules []TransformRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
	sortTransformRules(e.rules)
}

// AddRule appends a rule and re-sorts by priority.
func (e *TransformEngine) AddRule(rule TransformRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	sortTransformRules(e.rules)
}

// RemoveRule removes the first rule with the given ID. Returns true when
// a rule was removed.
func (e *TransformEngine) RemoveRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.rules {
		if e.rules[i].ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return true
		}
	}
	return false
}

// EnableRule toggles the Enabled flag on the rule with the given ID.
// Returns true when a rule was updated.
func (e *TransformEngine) EnableRule(id string, enabled bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.rules {
		if e.rules[i].ID == id {
			e.rules[i].Enabled = enabled
			return true
		}
	}
	return false
}

// Rules returns a defensive copy of the current rule slice.
func (e *TransformEngine) Rules() []TransformRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]TransformRule, len(e.rules))
	copy(out, e.rules)
	return out
}

func sortTransformRules(rules []TransformRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})
}

// TransformResult reports the outcome of a Transform call.
type TransformResult struct {
	// Modified is true when at least one rule mutated the SSEMessage.
	// Mutation detection is left to the session-side `sseMessageMutated`
	// field-diff; engines do NOT need to be byte-precise. This bit is a
	// best-effort fast-path signal for callers that want to skip
	// re-encoding when no rule applied.
	Modified bool
	// Drop is true when at least one matching rule's action was
	// TransformDrop. Callers should translate this into
	// pipeline.Result{Action: Drop}.
	Drop bool
	// DropRuleID is the ID of the rule that produced the Drop signal
	// (the first matching drop rule in priority order). Empty when Drop
	// is false.
	DropRuleID string
}

// Transform applies all matching rules to an SSE event in priority
// order. Mutates msg in-place. Returns a TransformResult summarising the
// outcome.
//
// A matching Drop rule short-circuits subsequent rule application —
// engines deliberately let earlier-priority Drop wins so an operator can
// reliably gate an event regardless of later-priority mutators.
//
// ctx is accepted for symmetry with rules/ws and rules/grpc; the current
// implementation does not block on ctx.
func (e *TransformEngine) Transform(_ context.Context, env *envelope.Envelope, msg *envelope.SSEMessage) TransformResult {
	if env == nil || msg == nil {
		return TransformResult{}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	var res TransformResult
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}
		if !directionAllowed(rule.Direction, env.Direction) {
			continue
		}
		if !matchTransformConditions(rule, msg) {
			continue
		}
		if rule.ActionType == TransformDrop {
			res.Drop = true
			res.DropRuleID = rule.ID
			// Short-circuit on Drop. Earlier-priority rules already
			// landed; later rules would mutate an event we are about
			// to discard. Keep res.Modified untouched (the session-side
			// diff will decide on its own).
			return res
		}
		if applySSEAction(rule, msg) {
			res.Modified = true
		}
	}
	return res
}

// matchTransformConditions evaluates the per-field rule predicates.
// Identical structure to InterceptEngine.matchesConditions; duplicated to
// keep the rule types separate (the field layouts diverge by action set).
func matchTransformConditions(rule *TransformRule, msg *envelope.SSEMessage) bool {
	if rule.EventPattern != nil && !rule.EventPattern.MatchString(msg.Event) {
		return false
	}
	if rule.IDPattern != nil && !rule.IDPattern.MatchString(msg.ID) {
		return false
	}
	if rule.DataPattern != nil && !rule.DataPattern.MatchString(msg.Data) {
		return false
	}
	if !matchRetryRange(msg.Retry.Milliseconds(), rule.RetryMinMs, rule.RetryMaxMs) {
		return false
	}
	if !matchAnomalies(rule.Anomalies, msg.Anomalies) {
		return false
	}
	return true
}

func applySSEAction(rule *TransformRule, msg *envelope.SSEMessage) bool {
	switch rule.ActionType {
	case TransformSetEvent:
		return assignIfDiff(&msg.Event, rule.SetEventValue)
	case TransformSetID:
		return assignIfDiff(&msg.ID, rule.SetIDValue)
	case TransformSetData:
		return assignIfDiff(&msg.Data, rule.SetDataValue)
	case TransformReplaceData:
		return applyReplaceData(rule, msg)
	case TransformPrependData:
		return applyPrependData(rule, msg)
	case TransformAppendData:
		return applyAppendData(rule, msg)
	case TransformSetRetry:
		newRetry := time.Duration(rule.SetRetryMs) * time.Millisecond
		if msg.Retry == newRetry {
			return false
		}
		msg.Retry = newRetry
		return true
	default:
		// TransformDrop is handled by the caller before applySSEAction
		// is invoked; any other type is unknown.
		return false
	}
}

// assignIfDiff sets *dst to v iff *dst != v and reports whether the
// assignment happened. Used by the scalar SetEvent/SetID/SetData arms
// to keep applySSEAction below the gocyclo budget.
func assignIfDiff(dst *string, v string) bool {
	if *dst == v {
		return false
	}
	*dst = v
	return true
}

func applyReplaceData(rule *TransformRule, msg *envelope.SSEMessage) bool {
	if rule.ReplaceDataPattern == nil {
		return false
	}
	replaced := rule.ReplaceDataPattern.ReplaceAllString(msg.Data, rule.ReplaceDataWith)
	if replaced == msg.Data {
		return false
	}
	msg.Data = replaced
	return true
}

func applyPrependData(rule *TransformRule, msg *envelope.SSEMessage) bool {
	if rule.PrependDataValue == "" {
		return false
	}
	msg.Data = rule.PrependDataValue + msg.Data
	return true
}

func applyAppendData(rule *TransformRule, msg *envelope.SSEMessage) bool {
	if rule.AppendDataValue == "" {
		return false
	}
	msg.Data = msg.Data + rule.AppendDataValue
	return true
}

// CompileTransformRule compiles raw config values into a TransformRule.
//
// Several action-shape fields are mutually relevant: ReplaceDataPattern
// requires a non-empty pattern string for TransformReplaceData; the
// remaining set_/prepend_/append_ actions read their value directly from
// the matching pointer/string fields.
//
// CRLF guards (CWE-113): SetEvent / SetID / PrependData / AppendData /
// ReplaceData replacement bodies reject CR or LF. SetData accepts `\n`
// because multi-line data is legal RFC 8895 wire form (one `data:` line
// per chunk) but still rejects `\r`.
func CompileTransformRule(
	id string,
	priority int,
	direction RuleDirection,
	eventPattern, idPattern, dataPattern string,
	retryMinMs, retryMaxMs *int64,
	anomalies []string,
	actionType TransformActionType,
	setEventValue, setIDValue, setDataValue string,
	prependDataValue, appendDataValue string,
	replaceDataPattern, replaceDataWith string,
	setRetryMs uint32,
) (*TransformRule, error) {
	if err := validateSSEDirection(direction); err != nil {
		return nil, err
	}
	rule := &TransformRule{
		ID:               id,
		Enabled:          true,
		Priority:         priority,
		Direction:        direction,
		RetryMinMs:       retryMinMs,
		RetryMaxMs:       retryMaxMs,
		Anomalies:        append([]string(nil), anomalies...),
		ActionType:       actionType,
		SetEventValue:    setEventValue,
		SetIDValue:       setIDValue,
		SetDataValue:     setDataValue,
		PrependDataValue: prependDataValue,
		AppendDataValue:  appendDataValue,
		ReplaceDataWith:  replaceDataWith,
		SetRetryMs:       setRetryMs,
	}
	if eventPattern != "" {
		re, err := common.CompilePattern(eventPattern)
		if err != nil {
			return nil, fmt.Errorf("event pattern: %w", err)
		}
		rule.EventPattern = re
	}
	if idPattern != "" {
		re, err := common.CompilePattern(idPattern)
		if err != nil {
			return nil, fmt.Errorf("id pattern: %w", err)
		}
		rule.IDPattern = re
	}
	if dataPattern != "" {
		re, err := common.CompilePattern(dataPattern)
		if err != nil {
			return nil, fmt.Errorf("data pattern: %w", err)
		}
		rule.DataPattern = re
	}
	if retryMinMs != nil && retryMaxMs != nil && *retryMinMs > *retryMaxMs {
		return nil, fmt.Errorf("retry range: min %d > max %d", *retryMinMs, *retryMaxMs)
	}
	if err := validateActionForCRLF(actionType, rule); err != nil {
		return nil, err
	}
	if actionType == TransformReplaceData {
		if replaceDataPattern == "" {
			return nil, fmt.Errorf("replace_data: pattern is required")
		}
		re, err := common.CompilePattern(replaceDataPattern)
		if err != nil {
			return nil, fmt.Errorf("replace_data pattern: %w", err)
		}
		rule.ReplaceDataPattern = re
	}
	return rule, nil
}

// validateActionForCRLF runs the per-action CRLF guards. set_event /
// set_id / prepend_data / append_data / replace_data replacement reject
// CR or LF. set_data accepts `\n` but rejects `\r`.
func validateActionForCRLF(action TransformActionType, rule *TransformRule) error {
	switch action {
	case TransformSetEvent:
		if containsCRLF(rule.SetEventValue) {
			return fmt.Errorf("set_event: value must not contain CR or LF")
		}
	case TransformSetID:
		if containsCRLF(rule.SetIDValue) {
			return fmt.Errorf("set_id: value must not contain CR or LF")
		}
	case TransformSetData:
		if containsCR(rule.SetDataValue) {
			return fmt.Errorf("set_data: value must not contain CR (LF is permitted for multi-line data)")
		}
	case TransformPrependData:
		if containsCRLF(rule.PrependDataValue) {
			return fmt.Errorf("prepend_data: value must not contain CR or LF")
		}
	case TransformAppendData:
		if containsCRLF(rule.AppendDataValue) {
			return fmt.Errorf("append_data: value must not contain CR or LF")
		}
	case TransformReplaceData:
		if containsCRLF(rule.ReplaceDataWith) {
			return fmt.Errorf("replace_data: replacement value must not contain CR or LF")
		}
	default:
		// Drop / SetRetry have no string surface to guard.
	}
	return nil
}
