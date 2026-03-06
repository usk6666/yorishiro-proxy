package plugin

import (
	"fmt"

	"go.starlark.net/starlark"
)

// goToStarlark converts a Go map to a Starlark Dict.
func goToStarlark(m map[string]any) (*starlark.Dict, error) {
	dict := starlark.NewDict(len(m))
	for k, v := range m {
		sv, err := goValueToStarlark(v)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", k, err)
		}
		if err := dict.SetKey(starlark.String(k), sv); err != nil {
			return nil, fmt.Errorf("set key %q: %w", k, err)
		}
	}
	return dict, nil
}

// goValueToStarlark converts a single Go value to a Starlark value.
func goValueToStarlark(v any) (starlark.Value, error) {
	switch val := v.(type) {
	case nil:
		return starlark.None, nil
	case bool:
		return starlark.Bool(val), nil
	case int:
		return starlark.MakeInt(val), nil
	case int64:
		return starlark.MakeInt64(val), nil
	case float64:
		return starlark.Float(val), nil
	case string:
		return starlark.String(val), nil
	case []byte:
		return starlark.Bytes(val), nil
	case []any:
		list := make([]starlark.Value, len(val))
		for i, item := range val {
			sv, err := goValueToStarlark(item)
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			list[i] = sv
		}
		return starlark.NewList(list), nil
	case []string:
		list := make([]starlark.Value, len(val))
		for i, s := range val {
			list[i] = starlark.String(s)
		}
		return starlark.NewList(list), nil
	case map[string]any:
		return goToStarlark(val)
	case map[string]string:
		dict := starlark.NewDict(len(val))
		for k, v := range val {
			if err := dict.SetKey(starlark.String(k), starlark.String(v)); err != nil {
				return nil, fmt.Errorf("set key %q: %w", k, err)
			}
		}
		return dict, nil
	default:
		return starlark.String(fmt.Sprintf("%v", v)), nil
	}
}

// starlarkToGo converts a Starlark value to a Go value.
func starlarkToGo(v starlark.Value) (any, error) {
	switch val := v.(type) {
	case starlark.NoneType:
		return nil, nil
	case starlark.Bool:
		return bool(val), nil
	case starlark.Int:
		i, ok := val.Int64()
		if ok {
			return i, nil
		}
		// Fall back to string representation for very large integers.
		return val.String(), nil
	case starlark.Float:
		return float64(val), nil
	case starlark.String:
		return string(val), nil
	case starlark.Bytes:
		return []byte(val), nil
	case *starlark.List:
		result := make([]any, val.Len())
		for i := range val.Len() {
			item, err := starlarkToGo(val.Index(i))
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			result[i] = item
		}
		return result, nil
	case starlark.Tuple:
		result := make([]any, len(val))
		for i, item := range val {
			goItem, err := starlarkToGo(item)
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			result[i] = goItem
		}
		return result, nil
	case *starlark.Dict:
		result := make(map[string]any, val.Len())
		for _, item := range val.Items() {
			key, ok := starlark.AsString(item[0])
			if !ok {
				return nil, fmt.Errorf("dict key must be string, got %s", item[0].Type())
			}
			goVal, err := starlarkToGo(item[1])
			if err != nil {
				return nil, fmt.Errorf("key %q: %w", key, err)
			}
			result[key] = goVal
		}
		return result, nil
	default:
		return val.String(), nil
	}
}
