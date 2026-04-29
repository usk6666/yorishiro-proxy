package pluginv2

import (
	"fmt"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// ShutdownFunc is a callback that triggers proxy shutdown with a reason.
type ShutdownFunc func(reason string)

// newProxyModule creates a Starlark "proxy" module with a shutdown function.
// The shutdown function allows plugins to trigger proxy shutdown with a reason.
func newProxyModule(shutdownFn ShutdownFunc) *starlarkstruct.Module {
	shutdownBuiltin := starlark.NewBuiltin("proxy.shutdown", func(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var reason starlark.String
		if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &reason); err != nil {
			return nil, err
		}

		reasonStr := string(reason)
		if reasonStr == "" {
			return nil, fmt.Errorf("%s: reason must not be empty", fn.Name())
		}

		if shutdownFn != nil {
			shutdownFn(reasonStr)
		}
		return starlark.None, nil
	})

	return &starlarkstruct.Module{
		Name: "proxy",
		Members: starlark.StringDict{
			"shutdown": shutdownBuiltin,
		},
	}
}
