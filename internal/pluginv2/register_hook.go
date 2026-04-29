package pluginv2

import (
	"fmt"

	"go.starlark.net/starlark"
)

// Thread-local keys used by the engine to thread the registry and the
// current plugin name into the register_hook builtin. Plugins do not
// observe these.
const (
	threadLocalRegistry   = "pluginv2.registry"
	threadLocalPluginName = "pluginv2.plugin_name"
)

// makeRegisterHookBuiltin returns the Starlark builtin for `register_hook`.
// Per RFC §9.3:
//
//	register_hook(protocol, event, fn, phase="pre_pipeline")
//
// The builtin is the same instance across plugin loads but reads the active
// registry and plugin-name from the calling thread's locals.
func makeRegisterHookBuiltin() *starlark.Builtin {
	return starlark.NewBuiltin("register_hook", registerHook)
}

func registerHook(thread *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		protocol string
		event    string
		hookFn   starlark.Value
		phaseArg = ""
	)
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs,
		"protocol", &protocol,
		"event", &event,
		"fn", &hookFn,
		"phase?", &phaseArg,
	); err != nil {
		return nil, err
	}

	pluginName, _ := thread.Local(threadLocalPluginName).(string)

	spec, ok := LookupEntry(protocol, event)
	if !ok {
		// Distinguish unknown protocol vs unknown event for clearer errors.
		if _, protoOK := surface[protocol]; !protoOK {
			return nil, &LoadError{
				Kind:       LoadErrUnknownProtocol,
				Protocol:   protocol,
				Event:      event,
				PluginName: pluginName,
				Detail:     "not in RFC §9.3 hook surface",
			}
		}
		return nil, &LoadError{
			Kind:       LoadErrUnknownEvent,
			Protocol:   protocol,
			Event:      event,
			PluginName: pluginName,
			Detail:     "not in RFC §9.3 hook surface for this protocol",
		}
	}

	resolvedPhase, err := resolvePhase(spec, phaseArg, protocol, event, pluginName)
	if err != nil {
		return nil, err
	}

	callable, ok := hookFn.(starlark.Callable)
	if !ok {
		return nil, &LoadError{
			Kind:       LoadErrNotCallable,
			Protocol:   protocol,
			Event:      event,
			PluginName: pluginName,
			Detail:     fmt.Sprintf("got %s", hookFn.Type()),
		}
	}

	registry, _ := thread.Local(threadLocalRegistry).(*Registry)
	if registry == nil {
		// Defensive: engine.loadPlugin always sets this. A missing registry
		// indicates the builtin was invoked outside an engine load (e.g. from
		// a test that bypasses the engine). Surface as a Starlark error
		// rather than panic.
		return nil, fmt.Errorf("register_hook: no registry bound to thread")
	}

	registry.Register(Hook{
		Protocol:   protocol,
		Event:      event,
		Phase:      resolvedPhase,
		Fn:         callable,
		PluginName: pluginName,
	})
	return starlark.None, nil
}

// resolvePhase converts the phase= argument (which may be unset) into a
// concrete Phase value, applying RFC §9.3 rules:
//
//   - For PhaseSupportPrePost entries: default is PhasePrePipeline; explicit
//     "pre_pipeline" or "post_pipeline" are accepted; any other value is
//     LoadErrInvalidPhase.
//   - For PhaseSupportNone entries: register_hook with no phase= argument
//     succeeds and resolves to PhaseNone. Passing phase= explicitly (even
//     "pre_pipeline") is LoadErrPhaseNotSupported (USK-665 strict-reject).
func resolvePhase(spec EntrySpec, phaseArg, protocol, event, pluginName string) (Phase, error) {
	switch spec.Phases {
	case PhaseSupportPrePost:
		if phaseArg == "" {
			return PhasePrePipeline, nil
		}
		switch Phase(phaseArg) {
		case PhasePrePipeline, PhasePostPipeline:
			return Phase(phaseArg), nil
		default:
			return "", &LoadError{
				Kind:       LoadErrInvalidPhase,
				Protocol:   protocol,
				Event:      event,
				Phase:      phaseArg,
				PluginName: pluginName,
				Detail:     `must be "pre_pipeline" or "post_pipeline"`,
			}
		}
	case PhaseSupportNone:
		if phaseArg != "" {
			return "", &LoadError{
				Kind:       LoadErrPhaseNotSupported,
				Protocol:   protocol,
				Event:      event,
				Phase:      phaseArg,
				PluginName: pluginName,
				Detail:     "this event is lifecycle/observation-only; do not pass phase=",
			}
		}
		return PhaseNone, nil
	default:
		// Future-proofing: any new PhaseSupport variant must opt in here.
		return "", fmt.Errorf("register_hook: unsupported PhaseSupport %d for (%q, %q)", spec.Phases, protocol, event)
	}
}
