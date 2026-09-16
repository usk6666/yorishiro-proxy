package grpc

import (
	"context"
	"strings"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// gRPC-local Targets. These are kept in this package (NOT in
// internal/rules/common) per the design review: common is stable and
// shouldn't be polluted with protocol-specific values. common.Target is
// a string type so common.CompiledRule can carry these values directly.
const (
	TargetMetadata common.Target = "metadata"
	TargetPayload  common.Target = "payload"
	TargetService  common.Target = "service"
	TargetMethod   common.Target = "method"
)

// SafetyEngine in this package is the live-path gRPC safety filter. It is
// invoked by internal/pipeline/safety_step.go on every Send-direction gRPC
// Start / Data envelope and MAY only return a Violation that drives a
// block / drop decision.
//
// Per RFC-001 Principle 1 (Wire fidelity), this engine MUST NOT mutate
// Envelope.Raw, GRPCStartMessage.Metadata, GRPCDataMessage.Payload, or any
// other message field. Output masking (PII redaction) is the exclusive
// responsibility of internal/safety, which is invoked at MCP response
// time — never before recording.

// Violation records a safety rule match on a gRPC event. Per the
// design review the type is per-protocol (rules/grpc.Violation), not
// promoted to common.
type Violation struct {
	RuleID   string
	RuleName string
	// Target names the matched target: "metadata", "payload",
	// "service", "method", "url", or "query" from extractTarget, or
	// "metadata:<name>" from CheckMetadataTarget. Nothing in the
	// production path branches on this value — it is operator-facing
	// only (slog field in internal/pipeline/safety_step.go).
	Target string
	Match  string // matched fragment (verbatim from regex)
}

// SafetyEngine checks gRPC events against safety rules. Thread-safe.
type SafetyEngine struct {
	mu    sync.RWMutex
	rules []common.CompiledRule
}

// NewSafetyEngine returns an empty engine.
func NewSafetyEngine() *SafetyEngine {
	return &SafetyEngine{}
}

// LoadPreset compiles and adds all rules from a named preset.
//
// LoadPreset itself performs no target remapping — the preset's Targets
// are compiled and stored verbatim, exactly as in http.LoadPreset and
// ws.LoadPreset. The reuse contract is implemented one level down, in
// extractTarget: common.TargetBody reads the gRPC payload, and
// common.TargetURL / common.TargetQuery read the Start message's :path
// and query. That is what lets the existing destructive-sql /
// destructive-os-command presets work unchanged against gRPC.
func (e *SafetyEngine) LoadPreset(name string) error {
	preset, err := common.LookupPreset(name)
	if err != nil {
		return err
	}
	compiled, err := common.CompilePreset(preset)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, compiled...)
	return nil
}

// AddRule appends a single compiled rule.
func (e *SafetyEngine) AddRule(rule common.CompiledRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
}

// SetRules replaces all rules atomically.
func (e *SafetyEngine) SetRules(rules []common.CompiledRule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
}

// RuleCount returns the number of loaded rules.
func (e *SafetyEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// CheckInput runs the loaded rules against env.Message and returns the
// first matching violation. Returns nil when no rule matches.
//
// CheckInput is symmetric with rules/http.CheckInput: ctx is threaded
// for parity (gRPC payloads don't currently spill to disk so the ctx
// is unused, but the signature matches the HTTP variant for caller
// convenience). The caller passes the typed message explicitly to
// avoid repeating the type-switch on every call site.
func (e *SafetyEngine) CheckInput(ctx context.Context, env *envelope.Envelope, msg envelope.Message) *Violation {
	if env == nil || msg == nil {
		return nil
	}
	_ = ctx // ctx threaded for symmetry with rules/http; currently unused
	e.mu.RLock()
	defer e.mu.RUnlock()

	for i := range e.rules {
		if v := e.checkRule(&e.rules[i], msg); v != nil {
			return v
		}
	}
	return nil
}

// CheckInputAll returns all violations (not just the first).
func (e *SafetyEngine) CheckInputAll(ctx context.Context, env *envelope.Envelope, msg envelope.Message) []*Violation {
	if env == nil || msg == nil {
		return nil
	}
	_ = ctx // ctx threaded for symmetry with rules/http; currently unused
	e.mu.RLock()
	defer e.mu.RUnlock()

	var violations []*Violation
	for i := range e.rules {
		if v := e.checkRule(&e.rules[i], msg); v != nil {
			violations = append(violations, v)
		}
	}
	return violations
}

func (e *SafetyEngine) checkRule(rule *common.CompiledRule, msg envelope.Message) *Violation {
	for _, target := range rule.Targets {
		data, name := extractTarget(target, msg)
		if data == "" {
			continue
		}
		match := rule.Pattern.Find([]byte(data))
		if match == nil {
			continue
		}
		if rule.Validator != nil && !rule.Validator(match) {
			continue
		}
		return &Violation{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Target:   name,
			Match:    string(match),
		}
	}
	return nil
}

// extractTarget pulls the target data out of a gRPC message. Returns
// "" when the target is not applicable to this message type (so the
// caller's loop simply continues).
//
// Three shared common.Targets are honoured so the built-in presets —
// which declare Targets{TargetBody, TargetURL, TargetQuery} — actually
// evaluate against gRPC (preset reuse contract):
//
//   - common.TargetBody aliases the gRPC payload target on a
//     GRPCDataMessage.
//   - common.TargetURL reads the full reconstructed request URL on a
//     GRPCStartMessage — scheme://authority + the request-side :path +
//     ?query, see reconstructURL — so a url rule anchored at the path
//     alone (`^/pkg\.Svc/`) never matches. common.TargetQuery reads that
//     query on its own (USK-1073).
//
// The Data and End arms deliberately have no url/query cases: neither
// message type carries Path / RawQuery / Authority / Scheme, so the
// fallthrough at the end of the function is both correct and the only
// way to stay under the gocyclo ceiling.
func extractTarget(target common.Target, msg envelope.Message) (data, name string) {
	switch m := msg.(type) {
	case *envelope.GRPCStartMessage:
		switch target {
		case TargetMetadata:
			return allMetadataString(m.Metadata), "metadata"
		case TargetService:
			return m.Service, "service"
		case TargetMethod:
			return m.Method, "method"
		// USK-1073. Scan-only: reconstructURL and m.RawQuery are read
		// verbatim, and neither this arm nor anything it calls writes
		// back to the message or to Envelope.Raw.
		//
		// Known residual (USK-1078): under the USK-702
		// modify_and_forward recheck, an operator override of
		// Service/Method on a *parseable* original :path makes
		// layer/grpc.pathForStart emit "/newSvc/newMethod" while m.Path
		// still holds the observed pre-override path — so the url target
		// scans the pre-override path. This is not a regression
		// introduced here (before USK-1073 the url target scanned
		// nothing at all), and closing it needs parseGRPCPath, which is
		// unexported in internal/layer/grpc.
		//
		// Known residual (gRPC-Web; no Issue filed yet):
		// layer/grpcweb.applyRequestOverlay copies Authority / Scheme /
		// Path onto the Start but never RawQuery — the identifier appears
		// nowhere in internal/layer/grpcweb — so on gRPC-Web traffic the
		// query target is inert and the url target carries no query.
		// Currently harmless rather than a bypass: the gRPC-Web Send path
		// rebuilds msg.Path from Service/Method, dropping the query
		// before it reaches upstream, so the unscanned bytes are also
		// never forwarded.
		case common.TargetURL:
			return reconstructURL(m), "url"
		case common.TargetQuery:
			return m.RawQuery, "query"
		}

	case *envelope.GRPCDataMessage:
		switch target {
		case TargetPayload, common.TargetBody:
			payload := materializePayload(m)
			if payload == nil {
				return "", ""
			}
			return string(payload), "payload"
		case TargetService:
			return m.Service, "service"
		case TargetMethod:
			return m.Method, "method"
		}

	case *envelope.GRPCEndMessage:
		switch target {
		case TargetMetadata:
			return allMetadataString(m.Trailers), "metadata"
		}
	}
	return "", ""
}

// CheckMetadataTarget evaluates a custom rule against a specific
// metadata entry by name. Mirrors rules/http.CheckHeaderTarget for the
// single-header lookup case.
func (e *SafetyEngine) CheckMetadataTarget(metadata []envelope.KeyValue, name string, rule *common.CompiledRule) *Violation {
	value := metadataGet(metadata, name)
	if value == "" {
		return nil
	}
	match := rule.Pattern.Find([]byte(value))
	if match == nil {
		return nil
	}
	if rule.Validator != nil && !rule.Validator(match) {
		return nil
	}
	return &Violation{
		RuleID:   rule.ID,
		RuleName: rule.Name,
		Target:   "metadata:" + name,
		Match:    string(match),
	}
}

// allMetadataString concatenates metadata in wire order for
// TargetMetadata matching. No normalization — wire casing and order
// preserved.
func allMetadataString(metadata []envelope.KeyValue) string {
	var b strings.Builder
	for _, kv := range metadata {
		b.WriteString(kv.Name)
		b.WriteString(": ")
		b.WriteString(kv.Value)
		b.WriteByte('\n')
	}
	return b.String()
}
