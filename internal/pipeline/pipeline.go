// Package pipeline defines the ordered Step chain that processes Envelope
// objects. Pipeline is protocol-agnostic: all protocols' traffic flows through
// the same Pipeline.
//
// Steps are either Envelope-only (work on identity/raw/context, never
// type-assert on Message) or Message-typed (type-switch on env.Message and
// dispatch to per-protocol engines). See RFC-001 section 3.5.
//
// Steps execute in a fixed order (HostScope → HTTPScope → Safety →
// PluginPre → Intercept → Transform → PluginPost → Record). proxybuild
// appends UpgradeStep after Record for the WS/SSE layer-swap path.
// Each Step checks Envelope.Direction to decide behavior.
package pipeline

import (
	"context"
	"reflect"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// Action indicates the outcome of a Step's processing.
type Action int

const (
	// Continue proceeds to the next Step in the Pipeline.
	Continue Action = iota
	// Drop discards the Envelope entirely.
	Drop
	// Respond short-circuits the Pipeline and returns a custom response
	// to the client.
	Respond
)

// String returns the string representation of an Action.
func (a Action) String() string {
	switch a {
	case Continue:
		return "Continue"
	case Drop:
		return "Drop"
	case Respond:
		return "Respond"
	default:
		return "Unknown"
	}
}

// Result is the return value of Step.Process.
type Result struct {
	// Envelope is the (possibly modified) Envelope to pass to subsequent
	// Steps. If nil, the original Envelope is used unchanged.
	Envelope *envelope.Envelope

	// Action indicates how the Pipeline should proceed.
	Action Action

	// Response holds the custom response Envelope when Action is Respond.
	// It is ignored for other Action values.
	Response *envelope.Envelope

	// BlockedBy carries the reason a Drop or Respond Action was emitted so
	// the session loop can record an audit Stream for the blocked envelope
	// (USK-782 / USK-829). It is surfaced by RunWithBlockedBy for both Drop
	// and Respond and may be empty when a Step short-circuits without an
	// attribution (e.g. plugin ActionDrop / RESPOND, intercept user-action
	// drop on receive — explicitly out of scope per USK-782 design). It is
	// ignored for Continue.
	//
	// Canonical values are the same set accepted by the MCP query tool's
	// blocked_by filter: "target_scope", "intercept_drop", "rate_limit",
	// "safety_filter", "budget".
	BlockedBy string
}

// Step is an individual processing unit within a Pipeline.
// Direction-based branching (Send vs Receive) is handled inside each Step
// implementation. Steps are categorized as Envelope-only (protocol-agnostic)
// or Message-typed (type-switch on env.Message).
type Step interface {
	Process(ctx context.Context, env *envelope.Envelope) Result
}

// Pipeline executes Steps sequentially on an Envelope.
type Pipeline struct {
	steps []Step
}

// New creates a Pipeline with the given Steps in order.
func New(steps ...Step) *Pipeline {
	return &Pipeline{steps: steps}
}

// Run executes all Steps sequentially. If any Step returns an Action other
// than Continue, execution stops immediately and that Step's result is
// returned. If a Step provides a non-nil Result.Envelope, subsequent Steps
// receive that Envelope instead of the original.
//
// Before executing any Steps, Run clones the Envelope (including a deep copy
// of Message via CloneMessage()) and stores the snapshot in the context.
// RecordStep uses this snapshot to detect modifications made by preceding
// Steps and record both original and modified variants.
//
// Run is the legacy 3-tuple entry point preserved for callers that do not
// need the BlockedBy audit signal. New callers (notably session.RunSession)
// should use RunWithBlockedBy.
func (p *Pipeline) Run(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, Action, *envelope.Envelope) {
	out, action, resp, _ := p.RunWithBlockedBy(ctx, env)
	return out, action, resp
}

// RunWithBlockedBy is identical to Run but additionally surfaces the
// Result.BlockedBy attribution emitted by the policy-Step that aborted
// the chain. The session loop forwards this label to a recorder
// callback so blocked envelopes are persisted as audit Streams (USK-782).
//
// USK-829: BlockedBy is now also forwarded for Action=Respond, not only
// Action=Drop. This is required because the Pipeline policy Steps
// (Intercept / HostScope / HTTPScope / Safety) emit Respond with a
// synthetic 403 when the held envelope is an HTTPMessage so the client
// receives a clean terminator rather than hanging until its read
// timeout. Audit Stream attribution must travel with that Respond so
// the recorder still sees the block reason. Continue actions return
// the empty string; plugin-driven Respond (no BlockedBy set) returns
// the empty string verbatim.
func (p *Pipeline) RunWithBlockedBy(ctx context.Context, env *envelope.Envelope) (*envelope.Envelope, Action, *envelope.Envelope, string) {
	snapshot := env.Clone()
	ctx = withSnapshot(ctx, snapshot)
	ctx = withWireEncodedState(ctx)

	for _, step := range p.steps {
		r := step.Process(ctx, env)
		if r.Action != Continue {
			blockedBy := ""
			switch r.Action {
			case Drop, Respond:
				blockedBy = r.BlockedBy
			}
			return env, r.Action, r.Response, blockedBy
		}
		if r.Envelope != nil {
			env = r.Envelope
		}
	}
	return env, Continue, nil, ""
}

// Without returns a new Pipeline that excludes all Steps whose concrete type
// matches any of the provided exclude instances. Type comparison uses
// reflect.TypeOf, so all Steps of the same concrete type are excluded.
// This is used by Macro to create a derived Pipeline without InterceptStep.
func (p *Pipeline) Without(exclude ...Step) *Pipeline {
	excludeTypes := make(map[reflect.Type]bool, len(exclude))
	for _, e := range exclude {
		excludeTypes[reflect.TypeOf(e)] = true
	}
	var filtered []Step
	for _, s := range p.steps {
		if !excludeTypes[reflect.TypeOf(s)] {
			filtered = append(filtered, s)
		}
	}
	return &Pipeline{steps: filtered}
}
