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
		return goSliceToStarlarkList(val)
	case []string:
		return goStringSliceToStarlarkList(val), nil
	case map[string]any:
		return goToStarlark(val)
	case map[string]string:
		return goStringMapToStarlarkDict(val)
	default:
		return starlark.String(fmt.Sprintf("%v", v)), nil
	}
}

// goSliceToStarlarkList converts a []any to a Starlark List.
func goSliceToStarlarkList(val []any) (*starlark.List, error) {
	list := make([]starlark.Value, len(val))
	for i, item := range val {
		sv, err := goValueToStarlark(item)
		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}
		list[i] = sv
	}
	return starlark.NewList(list), nil
}

// goStringSliceToStarlarkList converts a []string to a Starlark List.
func goStringSliceToStarlarkList(val []string) *starlark.List {
	list := make([]starlark.Value, len(val))
	for i, s := range val {
		list[i] = starlark.String(s)
	}
	return starlark.NewList(list)
}

// goStringMapToStarlarkDict converts a map[string]string to a Starlark Dict.
func goStringMapToStarlarkDict(val map[string]string) (*starlark.Dict, error) {
	dict := starlark.NewDict(len(val))
	for k, v := range val {
		if err := dict.SetKey(starlark.String(k), starlark.String(v)); err != nil {
			return nil, fmt.Errorf("set key %q: %w", k, err)
		}
	}
	return dict, nil
}

// starlarkToGo converts a Starlark value to a Go value.
func starlarkToGo(v starlark.Value) (any, error) {
	switch val := v.(type) {
	case starlark.NoneType:
		return nil, nil
	case starlark.Bool:
		return bool(val), nil
	case starlark.Int:
		return starlarkIntToGo(val), nil
	case starlark.Float:
		return float64(val), nil
	case starlark.String:
		return string(val), nil
	case starlark.Bytes:
		return []byte(val), nil
	case *starlark.List:
		return starlarkListToGo(val)
	case starlark.Tuple:
		return starlarkTupleToGo(val)
	case *starlark.Dict:
		return starlarkDictToGo(val)
	default:
		return val.String(), nil
	}
}

// starlarkIntToGo converts a Starlark Int to a Go value.
func starlarkIntToGo(val starlark.Int) any {
	i, ok := val.Int64()
	if ok {
		return i
	}
	// Fall back to string representation for very large integers.
	return val.String()
}

// starlarkListToGo converts a Starlark List to a Go slice.
func starlarkListToGo(val *starlark.List) ([]any, error) {
	result := make([]any, val.Len())
	for i := range val.Len() {
		item, err := starlarkToGo(val.Index(i))
		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}
		result[i] = item
	}
	return result, nil
}

// starlarkTupleToGo converts a Starlark Tuple to a Go slice.
func starlarkTupleToGo(val starlark.Tuple) ([]any, error) {
	result := make([]any, len(val))
	for i, item := range val {
		goItem, err := starlarkToGo(item)
		if err != nil {
			return nil, fmt.Errorf("index %d: %w", i, err)
		}
		result[i] = goItem
	}
	return result, nil
}

// starlarkDictToGo converts a Starlark Dict to a Go map.
func starlarkDictToGo(val *starlark.Dict) (map[string]any, error) {
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
}
