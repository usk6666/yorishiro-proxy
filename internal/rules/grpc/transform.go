package grpc

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sort"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// TransformActionType enumerates the supported gRPC transform actions.
type TransformActionType int

const (
	// TransformAddMetadata appends a metadata entry preserving casing.
	TransformAddMetadata TransformActionType = iota
	// TransformSetMetadata removes ALL case-insensitive matches and
	// appends a fresh entry with the supplied casing.
	TransformSetMetadata
	// TransformRemoveMetadata removes ALL case-insensitive matches.
	TransformRemoveMetadata
	// TransformReplacePayload runs a regex over GRPCDataMessage.Payload
	// and writes the result back. On commit env.Raw is cleared so the
	// downstream Layer re-encodes a fresh wire frame from the
	// post-mutation Payload. WireLength is left verbatim (last
	// wire-observed value); the GRPCLayer is responsible for
	// restamping the LPM length when it serializes the frame.
	TransformReplacePayload
	// TransformSetStatus sets GRPCEndMessage.Status. Any uint32 is
	// accepted (no enum validation). MITM principle: don't normalize.
	TransformSetStatus
	// TransformSetStatusMessage sets GRPCEndMessage.Message verbatim.
	TransformSetStatusMessage
)

// TransformRule defines a single transformation with match conditions
// and action.
type TransformRule struct {
	ID       string
	Enabled  bool
	Priority int // lower values applied first

	// Match conditions (AND-combined; empty matches all).
	Direction      RuleDirection
	ServicePattern *regexp.Regexp
	MethodPattern  *regexp.Regexp

	// Action.
	ActionType     TransformActionType
	MetadataName   string         // for Add/Set/Remove
	MetadataValue  string         // for Add/Set
	PayloadPattern *regexp.Regexp // for ReplacePayload
	PayloadReplace string         // replacement (supports $1, $2...)
	StatusValue    uint32         // for SetStatus
	StatusMessage  string         // for SetStatusMessage
}

// TransformEngine applies transform rules to gRPC events. Thread-safe.
type TransformEngine struct {
	mu    sync.RWMutex
	rules []TransformRule
}

// NewTransformEngine creates an empty engine.
func NewTransformEngine() *TransformEngine {
	return &TransformEngine{}
}

// SetRules replaces all rules atomically. Rules are sorted by Priority
// ascending (lower = earlier).
func (e *TransformEngine) SetRules(rules []TransformRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
	sort.SliceStable(e.rules, func(i, j int) bool {
		return e.rules[i].Priority < e.rules[j].Priority
	})
}

// AddRule appends a rule and re-sorts by priority.
func (e *TransformEngine) AddRule(rule TransformRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	sort.SliceStable(e.rules, func(i, j int) bool {
		return e.rules[i].Priority < e.rules[j].Priority
	})
}

// TransformStart applies matching rules to a GRPCStartMessage.
// Returns true when any modification was applied.
//
// On Start, only metadata mutations (Add/Set/Remove) and direction +
// service/method gates apply. Payload and Status actions are no-ops.
func (e *TransformEngine) TransformStart(ctx context.Context, env *envelope.Envelope, msg *envelope.GRPCStartMessage) bool {
	if env == nil || msg == nil {
		return false
	}
	_ = ctx // ctx threaded for symmetry with rules/http; currently unused

	e.mu.RLock()
	defer e.mu.RUnlock()

	modified := false
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}
		if !directionAllowed(rule.Direction, env.Direction) {
			continue
		}
		if !matchServiceMethodTransform(rule, msg.Service, msg.Method) {
			continue
		}
		if applyStartAction(rule, msg) {
			modified = true
		}
	}
	if modified {
		// Metadata mutations invalidate the wire-encoded HEADERS frame
		// snapshot; clear Raw so the downstream Layer re-encodes.
		env.Raw = nil
	}
	return modified
}

// TransformData applies matching rules to a GRPCDataMessage. Returns
// true on any mutation. ReplacePayload commits by writing the new
// payload AND clearing env.Raw so the downstream Layer re-encodes the
// LPM frame. WireLength is left verbatim.
func (e *TransformEngine) TransformData(ctx context.Context, env *envelope.Envelope, msg *envelope.GRPCDataMessage) bool {
	if env == nil || msg == nil {
		return false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	modified := false
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}
		if !directionAllowed(rule.Direction, env.Direction) {
			continue
		}
		if !matchServiceMethodTransform(rule, msg.Service, msg.Method) {
			continue
		}
		if applyDataAction(ctx, rule, msg) {
			modified = true
		}
	}
	if modified {
		// Payload mutation invalidates the wire-encoded LPM frame in
		// env.Raw; clear so the downstream Layer re-encodes from
		// msg.Payload. WireLength is intentionally left at its
		// last-wire-observed value (see TransformReplacePayload doc).
		env.Raw = nil
	}
	return modified
}

// TransformEnd applies matching rules to a GRPCEndMessage. SetStatus
// and SetStatusMessage actions apply here; metadata/payload actions
// are no-ops.
func (e *TransformEngine) TransformEnd(ctx context.Context, env *envelope.Envelope, msg *envelope.GRPCEndMessage) bool {
	if env == nil || msg == nil {
		return false
	}
	_ = ctx

	e.mu.RLock()
	defer e.mu.RUnlock()

	modified := false
	for i := range e.rules {
		rule := &e.rules[i]
		if !rule.Enabled {
			continue
		}
		if !directionAllowed(rule.Direction, env.Direction) {
			continue
		}
		// GRPCEndMessage carries no Service/Method, so only direction
		// gates apply here.
		if applyEndAction(rule, msg) {
			modified = true
		}
	}
	if modified {
		env.Raw = nil
	}
	return modified
}

// matchServiceMethodTransform mirrors matchServiceMethod for transform
// rules.
func matchServiceMethodTransform(rule *TransformRule, service, method string) bool {
	if rule.ServicePattern != nil && !rule.ServicePattern.MatchString(service) {
		return false
	}
	if rule.MethodPattern != nil && !rule.MethodPattern.MatchString(method) {
		return false
	}
	return true
}

func applyStartAction(rule *TransformRule, msg *envelope.GRPCStartMessage) bool {
	switch rule.ActionType {
	case TransformAddMetadata:
		if containsCRLF(rule.MetadataName) || containsCRLF(rule.MetadataValue) {
			return false // CWE-113: reject CRLF in metadata
		}
		msg.Metadata = metadataAdd(msg.Metadata, rule.MetadataName, rule.MetadataValue)
		return true

	case TransformSetMetadata:
		if containsCRLF(rule.MetadataName) || containsCRLF(rule.MetadataValue) {
			return false
		}
		msg.Metadata = metadataDel(msg.Metadata, rule.MetadataName)
		msg.Metadata = metadataAdd(msg.Metadata, rule.MetadataName, rule.MetadataValue)
		return true

	case TransformRemoveMetadata:
		before := len(msg.Metadata)
		msg.Metadata = metadataDel(msg.Metadata, rule.MetadataName)
		return len(msg.Metadata) != before

	default:
		// Payload / Status actions don't apply on Start.
		return false
	}
}

func applyDataAction(ctx context.Context, rule *TransformRule, msg *envelope.GRPCDataMessage) bool {
	if rule.ActionType != TransformReplacePayload {
		return false
	}
	if rule.PayloadPattern == nil {
		return false
	}
	target := materializePayload(ctx, msg)
	if target == nil {
		return false
	}
	replaced := rule.PayloadPattern.ReplaceAll(target, []byte(rule.PayloadReplace))
	if bytes.Equal(replaced, target) {
		return false
	}
	// Commit: write the post-replace bytes back. WireLength is left
	// verbatim per the action's contract; the GRPCLayer.Send path
	// re-encodes the LPM prefix from the new payload length when it
	// observes env.Raw == nil.
	msg.Payload = replaced
	return true
}

func applyEndAction(rule *TransformRule, msg *envelope.GRPCEndMessage) bool {
	switch rule.ActionType {
	case TransformSetStatus:
		if msg.Status == rule.StatusValue {
			return false
		}
		msg.Status = rule.StatusValue
		return true

	case TransformSetStatusMessage:
		if msg.Message == rule.StatusMessage {
			return false
		}
		msg.Message = rule.StatusMessage
		return true

	default:
		// Metadata / Payload actions don't apply on End.
		return false
	}
}

// CompileTransformRule compiles a transform rule from raw config values.
//
// Some action types ignore some fields; the unused ones may be left
// zero. Validation is intentionally minimal (matches rules/http
// precedent).
func CompileTransformRule(id string, priority int, direction RuleDirection,
	servicePattern, methodPattern string,
	actionType TransformActionType,
	metadataName, metadataValue string,
	payloadPattern, payloadReplace string,
	statusValue uint32, statusMessage string,
) (*TransformRule, error) {
	rule := &TransformRule{
		ID:             id,
		Enabled:        true,
		Priority:       priority,
		Direction:      direction,
		ActionType:     actionType,
		MetadataName:   metadataName,
		MetadataValue:  metadataValue,
		PayloadReplace: payloadReplace,
		StatusValue:    statusValue,
		StatusMessage:  statusMessage,
	}

	if servicePattern != "" {
		re, err := common.CompilePattern(servicePattern)
		if err != nil {
			return nil, fmt.Errorf("service pattern: %w", err)
		}
		rule.ServicePattern = re
	}
	if methodPattern != "" {
		re, err := common.CompilePattern(methodPattern)
		if err != nil {
			return nil, fmt.Errorf("method pattern: %w", err)
		}
		rule.MethodPattern = re
	}
	if payloadPattern != "" {
		re, err := common.CompilePattern(payloadPattern)
		if err != nil {
			return nil, fmt.Errorf("payload pattern: %w", err)
		}
		rule.PayloadPattern = re
	}

	return rule, nil
}
