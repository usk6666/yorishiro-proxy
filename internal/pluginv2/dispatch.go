package pluginv2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// HookOutcome carries the typed result of dispatching a single Hook.
//
// For Action == ActionContinue, NewMessage / NewRaw / Mutation describe how
// the envelope was mutated:
//
//   - MutationUnchanged → NewMessage / NewRaw alias the originals (zero-copy
//     pass-through; callers should keep using the input envelope).
//   - MutationRawOnly   → NewRaw is the plugin-injected bytes; NewMessage
//     aliases the original Message (RFC §9.3 D4 raw verbatim path).
//   - MutationMessageOnly → NewMessage is freshly built from the dict;
//     NewRaw aliases the original Raw (callers regenerate Raw via WireEncoder
//     in the pipeline package, where the per-protocol encoders live).
//   - MutationBoth      → both are freshly built; "raw wins" per RFC §9.3 D4 —
//     callers ship NewRaw verbatim and surface NewMessage only in the variant
//     snapshot.
//
// For ActionDrop, all three are zero. For ActionRespond, Respond carries the
// typed payload (HTTP or gRPC) and the dispatcher in the pipeline package
// synthesizes the response envelope.
type HookOutcome struct {
	Action     Action
	Mutation   MutationKind
	NewMessage envelope.Message
	NewRaw     []byte
	Respond    *RespondAction
}

// ErrDisallowedAction is returned by Engine.Dispatch when a hook returns an
// action the surface table forbids for its (protocol, event) — e.g. a DROP
// from a mid-stream `grpc.on_data` hook (mid-stream events accept CONTINUE
// only). Callers should log a Warn and treat the outcome as ActionContinue
// (fail-soft: a misbehaving plugin must not break wire traffic). The error
// is surfaced rather than silently demoted so plugin authors can see the
// problem in tests; callers that want the demoted behavior errors.Is-check
// this sentinel.
var ErrDisallowedAction = errors.New("pluginv2: hook returned disallowed action for this event")

// Dispatch invokes one Hook against env. Conv / exec / read-back / surface
// validation is fully encapsulated here so callers (pipeline.PluginStepPre /
// PluginStepPost) consume an already-validated outcome.
//
// Returns ErrDisallowedAction (or wrapping) when a hook returns DROP/RESPOND
// for an event whose surface ActionMask forbids it. Returns convertMessageToDict
// errors (ErrBodyTooLarge / ErrUnsupportedMessageType) verbatim — callers
// treat these as "skip this hook" signals. Per-hook Starlark *runtime* errors
// are converted into Warn-logged ActionContinue outcomes here so a misbehaving
// hook never breaks the chain or the wire.
func (e *Engine) Dispatch(ctx context.Context, hook Hook, env *envelope.Envelope) (*HookOutcome, error) {
	d, err := convertMessageToDict(env)
	if err != nil {
		return nil, err
	}
	ctxVal := e.NewCtx(env)

	thread := &starlark.Thread{
		Name: fmt.Sprintf("pluginv2.dispatch:%s/%s/%s", hook.PluginName, hook.Protocol, hook.Event),
		Print: func(_ *starlark.Thread, msg string) {
			e.logger.Info("pluginv2: plugin print",
				slog.String("plugin", hook.PluginName),
				slog.String("hook", hook.Protocol+"."+hook.Event),
				slog.String("message", msg),
			)
		},
	}
	if steps := e.lookupMaxSteps(hook.PluginName); steps > 0 {
		thread.SetMaxExecutionSteps(steps)
	}

	// Bridge ctx cancellation into thread.Cancel so external signals (SIGINT,
	// deadline) abort hook execution promptly. The done channel stops the
	// watcher when starlark.Call returns. Mirrors Engine.loadPlugin pattern.
	done := make(chan struct{})
	defer close(done)
	if ctx != nil && ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				thread.Cancel(ctx.Err().Error())
			case <-done:
			}
		}()
	}

	args := starlark.Tuple{d, ctxVal}
	ret, callErr := starlark.Call(thread, hook.Fn, args, nil)
	if callErr != nil {
		// In-place mutations applied before the error are still committed
		// per RFC §9.3 D2 ("msg is mutable in-place"). We log the error and
		// fall through to dictToMessage read-back as if the hook had
		// returned None.
		e.logger.WarnContext(ctx, "pluginv2: hook returned error",
			slog.String("plugin", hook.PluginName),
			slog.String("hook", hook.Protocol+"."+hook.Event),
			slog.String("phase", string(hook.Phase)),
			slog.String("error", callErr.Error()),
		)
		ret = starlark.None
	}

	action, respond := interpretReturnValue(ret, hook, e.logger)

	if action == ActionRespond {
		if !surfaceAllows(hook, action) {
			return nil, fmt.Errorf("%w: %s on (%s, %s)", ErrDisallowedAction, action, hook.Protocol, hook.Event)
		}
		return &HookOutcome{Action: ActionRespond, Respond: respond}, nil
	}
	if action == ActionDrop {
		if !surfaceAllows(hook, action) {
			return nil, fmt.Errorf("%w: %s on (%s, %s)", ErrDisallowedAction, action, hook.Protocol, hook.Event)
		}
		return &HookOutcome{Action: ActionDrop}, nil
	}

	// ActionContinue: commit mutations.
	msg, raw, kind, readErr := dictToMessage(d)
	if readErr != nil {
		e.logger.WarnContext(ctx, "pluginv2: dict read-back failed",
			slog.String("plugin", hook.PluginName),
			slog.String("hook", hook.Protocol+"."+hook.Event),
			slog.String("error", readErr.Error()),
		)
		return &HookOutcome{Action: ActionContinue, Mutation: MutationUnchanged, NewMessage: env.Message, NewRaw: env.Raw}, nil
	}
	return &HookOutcome{
		Action:     ActionContinue,
		Mutation:   kind,
		NewMessage: msg,
		NewRaw:     raw,
	}, nil
}

// interpretReturnValue maps a Starlark return value to (Action, *RespondAction).
//
//	nil / None / no return / action.CONTINUE → ActionContinue
//	action.DROP                              → ActionDrop
//	*RespondAction (action.RESPOND result)   → ActionRespond + payload
//	bare "RESPOND" string                    → Warn + ActionContinue (forgot to call)
//	anything else                            → Warn log + ActionContinue
//
// Per RFC §9.3 D2: in-place mutations on `msg` are always committed regardless
// of return value, so a "wrong" return value degrades to CONTINUE rather than
// dropping the mutations.
func interpretReturnValue(ret starlark.Value, hook Hook, logger *slog.Logger) (Action, *RespondAction) {
	if ret == nil || ret == starlark.None {
		return ActionContinue, nil
	}
	switch v := ret.(type) {
	case *RespondAction:
		return ActionRespond, v
	case starlark.String:
		switch string(v) {
		case "CONTINUE":
			return ActionContinue, nil
		case "DROP":
			return ActionDrop, nil
		case "RESPOND":
			logger.Warn("pluginv2: plugin returned bare \"RESPOND\" string; call action.RESPOND(...) to build a response",
				slog.String("plugin", hook.PluginName),
				slog.String("hook", hook.Protocol+"."+hook.Event),
			)
			return ActionContinue, nil
		default:
			logger.Warn("pluginv2: plugin returned unrecognized string",
				slog.String("plugin", hook.PluginName),
				slog.String("hook", hook.Protocol+"."+hook.Event),
				slog.String("value", string(v)),
			)
			return ActionContinue, nil
		}
	default:
		logger.Warn("pluginv2: plugin returned unsupported value type",
			slog.String("plugin", hook.PluginName),
			slog.String("hook", hook.Protocol+"."+hook.Event),
			slog.String("type", ret.Type()),
		)
		return ActionContinue, nil
	}
}

// surfaceAllows reports whether the surface table permits action for this
// hook's (protocol, event). ActionContinue is always allowed.
func surfaceAllows(hook Hook, action Action) bool {
	if action == ActionContinue {
		return true
	}
	spec, ok := LookupEntry(hook.Protocol, hook.Event)
	if !ok {
		return false
	}
	return spec.Actions.Has(action)
}

// lookupMaxSteps returns the per-call step budget for the named plugin,
// defaulting to DefaultMaxSteps when no matching plugin is loaded (e.g.
// tests that register hooks directly via Registry.Register).
func (e *Engine) lookupMaxSteps(name string) uint64 {
	if name == "" {
		return DefaultMaxSteps
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, p := range e.plugins {
		cfgName := p.config.Name
		if cfgName == "" {
			cfgName = pluginName(p.config.Path)
		}
		if cfgName == name {
			return p.config.maxSteps()
		}
	}
	return DefaultMaxSteps
}
