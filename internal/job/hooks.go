package job

import (
	"context"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// MakeRunHookFunc creates a RunHookFunc that uses the given macro engine
// to execute hooks. The hook config's Macro name is used to look up a
// stored macro definition via the provided lookup function.
//
// macroLookup resolves a macro name to its definition. Returns nil if
// the macro is not found.
func MakeRunHookFunc(engine *macro.Engine, macroLookup func(name string) *macro.Macro) RunHookFunc {
	return func(ctx context.Context, hookCfg *HookConfig, kvStore map[string]string) (map[string]string, error) {
		m := macroLookup(hookCfg.Macro)
		if m == nil {
			return nil, fmt.Errorf("hook: macro %q not found", hookCfg.Macro)
		}

		// Merge the Job's KVStore with the hook's configured vars.
		// Hook vars take precedence.
		vars := make(map[string]string, len(kvStore)+len(hookCfg.Vars))
		for k, v := range kvStore {
			vars[k] = v
		}
		for k, v := range hookCfg.Vars {
			vars[k] = v
		}

		result, err := engine.Run(ctx, m, vars)
		if err != nil {
			return nil, fmt.Errorf("hook: macro %q execution: %w", hookCfg.Macro, err)
		}
		if result.Status == "error" || result.Status == "timeout" {
			return nil, fmt.Errorf("hook: macro %q failed: %s", hookCfg.Macro, result.Error)
		}

		return result.KVStore, nil
	}
}
