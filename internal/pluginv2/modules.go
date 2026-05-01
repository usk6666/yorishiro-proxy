package pluginv2

import (
	"fmt"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// newActionModule creates the predeclared "action" module available to
// scripts. CONTINUE and DROP are sentinel strings the dispatcher recognizes
// in a hook's return value. RESPOND and RESPOND_GRPC are callable builtins
// that build a typed *RespondAction the dispatcher converts to a synthesized
// response envelope (RFC §9.3 D5; USK-671 callable shape per design review).
func newActionModule() *starlarkstruct.Module {
	return &starlarkstruct.Module{
		Name: "action",
		Members: starlark.StringDict{
			"CONTINUE":     starlark.String("CONTINUE"),
			"DROP":         starlark.String("DROP"),
			"RESPOND":      starlark.NewBuiltin("action.RESPOND", builtinRespond),
			"RESPOND_GRPC": starlark.NewBuiltin("action.RESPOND_GRPC", builtinRespondGRPC),
		},
	}
}

// newConfigDict creates a frozen Starlark dict from a plugin's Vars map.
// Per USK-665 design: Vars is map[string]any; we accept the primitive
// types a Starlark plugin can sensibly read and reject the rest at
// engine load time. The dict is frozen so plugins cannot mutate operator
// configuration at runtime.
func newConfigDict(vars map[string]any) (*starlark.Dict, error) {
	d := starlark.NewDict(len(vars))
	for k, raw := range vars {
		v, err := goPrimitiveToStarlark(raw)
		if err != nil {
			return nil, err
		}
		if err := d.SetKey(starlark.String(k), v); err != nil {
			return nil, err
		}
	}
	d.Freeze()
	return d, nil
}

// goPrimitiveToStarlark converts a Go primitive value to its Starlark
// counterpart. Used by newConfigDict; mirrors the validateStateValue
// type set so plugins see the same primitives whether they are reading
// config or per-plugin state.
func goPrimitiveToStarlark(v any) (starlark.Value, error) {
	switch x := v.(type) {
	case nil:
		return starlark.None, nil
	case string:
		return starlark.String(x), nil
	case bool:
		return starlark.Bool(x), nil
	case int:
		return starlark.MakeInt(x), nil
	case int32:
		return starlark.MakeInt(int(x)), nil
	case int64:
		return starlark.MakeInt64(x), nil
	case uint:
		return starlark.MakeUint(x), nil
	case uint32:
		return starlark.MakeUint(uint(x)), nil
	case uint64:
		return starlark.MakeUint64(x), nil
	case float32:
		return starlark.Float(float64(x)), nil
	case float64:
		return starlark.Float(x), nil
	case []byte:
		return starlark.Bytes(x), nil
	default:
		return nil, fmt.Errorf("pluginv2: unsupported config value type %T (allowed: nil, string, bool, int, float, bytes)", v)
	}
}
