package http

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// TransformActionType specifies the kind of transformation.
type TransformActionType int

const (
	TransformAddHeader    TransformActionType = iota // append header (allows duplicates)
	TransformSetHeader                               // delete all matching, then add
	TransformRemoveHeader                            // delete all matching
	TransformReplaceBody                             // regex replace on body bytes
)

// TransformRule defines a single transformation with match conditions and action.
type TransformRule struct {
	ID       string
	Enabled  bool
	Priority int // lower values applied first

	// Match conditions (AND-combined, empty = match all).
	Direction   RuleDirection
	HostPattern *regexp.Regexp
	PathPattern *regexp.Regexp
	Methods     []string

	// Action.
	ActionType  TransformActionType
	HeaderName  string // for Add/Set/Remove
	HeaderValue string // for Add/Set
	BodyPattern *regexp.Regexp
	BodyReplace string // replacement (supports $1, $2 capture groups)
}

// TransformEngine applies transform rules to HTTP messages. Thread-safe.
type TransformEngine struct {
	mu    sync.RWMutex
	rules []TransformRule
}

// NewTransformEngine creates an empty TransformEngine.
func NewTransformEngine() *TransformEngine {
	return &TransformEngine{}
}

// SetRules replaces all rules atomically. Rules are sorted by priority.
func (e *TransformEngine) SetRules(rules []TransformRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
	sort.SliceStable(e.rules, func(i, j int) bool {
		return e.rules[i].Priority < e.rules[j].Priority
	})
}

// AddRule adds a rule and re-sorts by priority.
func (e *TransformEngine) AddRule(rule TransformRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	sort.SliceStable(e.rules, func(i, j int) bool {
		return e.rules[i].Priority < e.rules[j].Priority
	})
}

// RemoveRule removes the rule with the given ID. Returns true if a rule
// was removed. The configure_tool's auto_transform dispatcher uses this
// to scan all per-protocol engines for a matching ID.
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
// Returns true if a rule with that ID exists.
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

// Rules returns a defensive copy of the current rule slice for inspection
// (rule count / enabled count) by configure_tool's auto_transform result.
func (e *TransformEngine) Rules() []TransformRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]TransformRule, len(e.rules))
	copy(out, e.rules)
	return out
}

// TransformRequest applies matching rules to an HTTP request.
// Modifies msg in-place. Returns true if any modification was applied.
//
// ctx is threaded down to BodyBuffer.Bytes(ctx) so that disk-backed body
// materialization honors cancellation. On materialization error (e.g. ctx
// cancelled), the TransformReplaceBody action is skipped silently.
func (e *TransformEngine) TransformRequest(ctx context.Context, env *envelope.Envelope, msg *envelope.HTTPMessage) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	modified := false
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if rule.Direction != DirectionRequest && rule.Direction != DirectionBoth {
			continue
		}
		if !e.matchesConditions(&rule, env, msg, envelope.Send) {
			continue
		}
		if e.applyAction(ctx, &rule, msg) {
			modified = true
		}
	}
	return modified
}

// TransformResponse applies matching rules to an HTTP response.
// Modifies msg in-place. Returns true if any modification was applied.
func (e *TransformEngine) TransformResponse(ctx context.Context, env *envelope.Envelope, msg *envelope.HTTPMessage) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	modified := false
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		if rule.Direction != DirectionResponse && rule.Direction != DirectionBoth {
			continue
		}
		if !e.matchesConditions(&rule, env, msg, envelope.Receive) {
			continue
		}
		if e.applyAction(ctx, &rule, msg) {
			modified = true
		}
	}
	return modified
}

// matchesConditions evaluates a transform rule against an envelope. The dir
// parameter is the envelope direction (Send for requests, Receive for
// responses).
//
// PathPattern / Methods are evaluated against effectivePathAndMethod:
//   - Send: msg.Path / msg.Method (the wire-observed request line).
//   - Receive: env.Context.RequestPath / RequestMethod, populated by the
//     producing HTTP Layer (HTTP/1.x channel via ctxTmpl; HTTP/2 aggregator
//     via per-stream inflight state) with the paired request's fields. When
//     these are empty (legitimate direction:"response" no-paired-request
//     path, or a non-HTTP-Layer producer), the helper signals knowable=false
//     and the request-only checks are skipped — preserving the USK-824 fix
//     for direction:"response" + path_pattern.
//
// USK-833: previously these checks were guarded with `dir == envelope.Send`
// unconditionally, which silently allowed any path/method through on the
// Receive side of a direction:"both" rule. Symmetric to the intercept fix in
// intercept.go::matchesRule. Regression chain: USK-821 → USK-824 → USK-833.
func (e *TransformEngine) matchesConditions(rule *TransformRule, env *envelope.Envelope, msg *envelope.HTTPMessage, dir envelope.Direction) bool {
	// Host pattern check. Valid for both directions: TargetHost is set on
	// the EnvelopeContext at Pipeline entry and survives across the
	// request/response pair.
	if rule.HostPattern != nil {
		host := extractHostname(env.Context.TargetHost)
		if !rule.HostPattern.MatchString(host) {
			return false
		}
	}
	// USK-833: resolve the effective path/method for this direction; see
	// matchesRule in intercept.go for the rationale.
	path, method, knowable := effectivePathAndMethod(env, msg, dir)
	if rule.PathPattern != nil && knowable {
		if !rule.PathPattern.MatchString(path) {
			return false
		}
	}
	if len(rule.Methods) > 0 && knowable {
		found := false
		for _, m := range rule.Methods {
			if strings.EqualFold(m, method) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (e *TransformEngine) applyAction(ctx context.Context, rule *TransformRule, msg *envelope.HTTPMessage) bool {
	switch rule.ActionType {
	case TransformAddHeader:
		if containsCRLF(rule.HeaderName) || containsCRLF(rule.HeaderValue) {
			return false // CWE-113: reject CRLF in headers
		}
		msg.Headers = headerAdd(msg.Headers, rule.HeaderName, rule.HeaderValue)
		return true

	case TransformSetHeader:
		if containsCRLF(rule.HeaderName) || containsCRLF(rule.HeaderValue) {
			return false
		}
		msg.Headers = headerDel(msg.Headers, rule.HeaderName)
		msg.Headers = headerAdd(msg.Headers, rule.HeaderName, rule.HeaderValue)
		return true

	case TransformRemoveHeader:
		before := len(msg.Headers)
		msg.Headers = headerDel(msg.Headers, rule.HeaderName)
		return len(msg.Headers) != before

	case TransformReplaceBody:
		return e.applyReplaceBody(ctx, rule, msg)

	default:
		return false
	}
}

// applyReplaceBody implements the TransformReplaceBody action. Split out of
// applyAction to keep cyclomatic complexity manageable while documenting the
// USK-834 decode-then-replace semantics inline.
//
// Semantics:
//  1. Materialize the body bytes (Body []byte or disk-backed BodyBuffer).
//  2. If Content-Encoding names a supported codec, decode to plaintext;
//     otherwise the materialized bytes are used as-is (identity / no CE).
//  3. Apply the regex on the resulting target bytes.
//  4. On a successful decode, ALWAYS rewrite the wire-side body to plaintext
//     and strip Content-Encoding/Transfer-Encoding + re-stamp Content-Length
//     (even if the regex made no change): leaving CE on plaintext would
//     corrupt the response, the client tries to gunzip plaintext and fails.
//  5. On the identity path, only commit when the regex actually changed bytes.
//
// Fail-soft on decode anomalies (unknown codec, chained CE, malformed body,
// decoded-size cap exceeded): emit a single slog.Warn and return false, leaving
// the original compressed wire bytes intact (CLAUDE.md MITM principle #1).
func (e *TransformEngine) applyReplaceBody(ctx context.Context, rule *TransformRule, msg *envelope.HTTPMessage) bool {
	if rule.BodyPattern == nil {
		return false
	}
	// USK-834: materialize the body AND decode Content-Encoding so the
	// user's regex matches the plaintext rather than compressed wire bytes.
	target, applied, anomaly, err := materializeBodyDecoded(ctx, msg)
	if err != nil {
		slog.DebugContext(ctx, "transform: materialize body failed", "err", err)
		return false
	}
	if anomaly != nil {
		slog.WarnContext(ctx, "transform: replace_body skipped due to content-encoding decode anomaly",
			"rule_id", rule.ID,
			"content_encoding", headerGet(msg.Headers, "Content-Encoding"),
			"anomaly_type", anomaly.Type,
			"anomaly_detail", anomaly.Detail,
		)
		return false
	}
	if target == nil {
		return false // passthrough mode: skip body transform
	}
	replaced := rule.BodyPattern.ReplaceAll(target, []byte(rule.BodyReplace))
	decoded := applied != ""
	if !decoded && bytes.Equal(replaced, target) {
		return false // identity path, no regex match → nothing to do
	}
	// Commit: move authoritative body into msg.Body and release the
	// BodyBuffer reference. The pipeline snapshot holds its own Retain (via
	// CloneMessage), so the buffer survives for variant recording. See
	// USK-631 isBodyChanged pointer-identity precedent.
	msg.Body = replaced
	if msg.BodyBuffer != nil {
		_ = msg.BodyBuffer.Release()
		msg.BodyBuffer = nil
	}
	if decoded {
		// After a successful decode, msg.Body is now plaintext. Strip
		// Content-Encoding and Transfer-Encoding and re-stamp Content-Length
		// so HTTP/2 (httpaggregator forwards msg.Headers verbatim) and
		// HTTP/1.x (applyTEToCLRewrite re-stamps from len(msg.Body)) both
		// observe the consistent post-decode shape. USK-834.
		msg.Headers = headerDel(msg.Headers, "Content-Encoding")
		msg.Headers = headerDel(msg.Headers, "Transfer-Encoding")
		msg.Headers = headerDel(msg.Headers, "Content-Length")
		msg.Headers = headerAdd(msg.Headers, "Content-Length", strconv.Itoa(len(replaced)))
	}
	return true
}

// CompileTransformRule compiles a transform rule from config values.
func CompileTransformRule(id string, priority int, direction RuleDirection, hostPattern, pathPattern string, methods []string, actionType TransformActionType, headerName, headerValue, bodyPattern, bodyReplace string) (*TransformRule, error) {
	rule := &TransformRule{
		ID:          id,
		Enabled:     true,
		Priority:    priority,
		Direction:   direction,
		ActionType:  actionType,
		HeaderName:  headerName,
		HeaderValue: headerValue,
		BodyReplace: bodyReplace,
	}

	if hostPattern != "" {
		re, err := common.CompilePattern(hostPattern)
		if err != nil {
			return nil, fmt.Errorf("host pattern: %w", err)
		}
		rule.HostPattern = re
	}
	if pathPattern != "" {
		re, err := common.CompilePattern(pathPattern)
		if err != nil {
			return nil, fmt.Errorf("path pattern: %w", err)
		}
		rule.PathPattern = re
	}
	if len(methods) > 0 {
		rule.Methods = methods
	}
	if bodyPattern != "" {
		re, err := common.CompilePattern(bodyPattern)
		if err != nil {
			return nil, fmt.Errorf("body pattern: %w", err)
		}
		rule.BodyPattern = re
	}

	return rule, nil
}
