// Package pipeline defines the ordered Step chain that processes Exchange
// objects. Pipeline is protocol-agnostic: all protocols' traffic flows through
// the same Pipeline.
//
// Steps execute in a fixed order (Scope → RateLimit → Safety → Plugin(recv) →
// Intercept → Transform → Plugin(send) → Record). Each Step checks
// Exchange.Direction to decide behavior. Steps must never branch on protocol.
//
// Individual Step implementations are defined in M37. This package provides
// the Pipeline skeleton and Step interface only.
package pipeline

import (
	"context"
	"reflect"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// Action indicates the outcome of a Step's processing.
type Action int

const (
	// Continue proceeds to the next Step in the Pipeline.
	Continue Action = iota
	// Drop discards the Exchange entirely.
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
	// Exchange is the (possibly modified) Exchange to pass to subsequent
	// Steps. If nil, the original Exchange is used unchanged.
	Exchange *exchange.Exchange

	// Action indicates how the Pipeline should proceed.
	Action Action

	// Response holds the custom response Exchange when Action is Respond.
	// It is ignored for other Action values.
	Response *exchange.Exchange
}

// Step is an individual processing unit within a Pipeline.
// Direction-based branching (Send vs Receive) is handled inside each Step
// implementation. Steps must never contain protocol-specific logic.
type Step interface {
	Process(ctx context.Context, ex *exchange.Exchange) Result
}

// Pipeline executes Steps sequentially on an Exchange.
type Pipeline struct {
	steps []Step
}

// New creates a Pipeline with the given Steps in order.
func New(steps ...Step) *Pipeline {
	return &Pipeline{steps: steps}
}

// Run executes all Steps sequentially. If any Step returns an Action other
// than Continue, execution stops immediately and that Step's result is
// returned. If a Step provides a non-nil Result.Exchange, subsequent Steps
// receive that Exchange instead of the original.
func (p *Pipeline) Run(ctx context.Context, ex *exchange.Exchange) (*exchange.Exchange, Action, *exchange.Exchange) {
	for _, step := range p.steps {
		r := step.Process(ctx, ex)
		if r.Action != Continue {
			return ex, r.Action, r.Response
		}
		if r.Exchange != nil {
			ex = r.Exchange
		}
	}
	return ex, Continue, nil
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
