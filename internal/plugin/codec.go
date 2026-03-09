package plugin

import (
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

// newCodecModule creates the predeclared "codec" module available to scripts.
// It exposes encode/decode functions for each registered codec, plus chain
// operations and a list function.
//
// Usage in Starlark:
//
//	encoded = codec.base64("hello")           # "aGVsbG8="
//	decoded = codec.base64_decode("aGVsbG8=") # "hello"
//	result = codec.encode("payload", ["url_encode_query", "base64"])
//	original = codec.decode(result, ["url_encode_query", "base64"])
//	names = codec.list()
func newCodecModule() *starlarkstruct.Module {
	r := codec.DefaultRegistry()

	members := starlark.StringDict{
		"encode": starlark.NewBuiltin("codec.encode", codecChainEncode),
		"decode": starlark.NewBuiltin("codec.decode", codecChainDecode),
		"list":   starlark.NewBuiltin("codec.list", codecList),
	}

	// Register individual codec encode/decode functions.
	for _, name := range r.List() {
		n := name // capture
		members[n] = starlark.NewBuiltin("codec."+n, makeCodecEncode(r, n))
		members[n+"_decode"] = starlark.NewBuiltin("codec."+n+"_decode", makeCodecDecode(r, n))
	}

	return &starlarkstruct.Module{
		Name:    "codec",
		Members: members,
	}
}

// makeCodecEncode returns a Starlark builtin that encodes a string using the named codec.
func makeCodecEncode(r *codec.Registry, name string) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var s starlark.String
		if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &s); err != nil {
			return nil, err
		}
		c, ok := r.Get(name)
		if !ok {
			return nil, fmt.Errorf("%s: codec %q not found", fn.Name(), name)
		}
		result, err := c.Encode(string(s))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fn.Name(), err)
		}
		return starlark.String(result), nil
	}
}

// makeCodecDecode returns a Starlark builtin that decodes a string using the named codec.
func makeCodecDecode(r *codec.Registry, name string) func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error) {
	return func(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var s starlark.String
		if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &s); err != nil {
			return nil, err
		}
		c, ok := r.Get(name)
		if !ok {
			return nil, fmt.Errorf("%s: codec %q not found", fn.Name(), name)
		}
		result, err := c.Decode(string(s))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fn.Name(), err)
		}
		return starlark.String(result), nil
	}
}

// codecChainEncode implements codec.encode(value, names).
func codecChainEncode(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.String
	var namesList *starlark.List
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &value, &namesList); err != nil {
		return nil, err
	}

	names, err := starlarkListToStrings(fn.Name(), namesList)
	if err != nil {
		return nil, err
	}

	result, err := codec.DefaultRegistry().Encode(string(value), names)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}
	return starlark.String(result), nil
}

// codecChainDecode implements codec.decode(value, names).
func codecChainDecode(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.String
	var namesList *starlark.List
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &value, &namesList); err != nil {
		return nil, err
	}

	names, err := starlarkListToStrings(fn.Name(), namesList)
	if err != nil {
		return nil, err
	}

	result, err := codec.DefaultRegistry().Decode(string(value), names)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}
	return starlark.String(result), nil
}

// codecList implements codec.list() -> list of codec names.
func codecList(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}
	names := codec.DefaultRegistry().List()
	elems := make([]starlark.Value, len(names))
	for i, n := range names {
		elems[i] = starlark.String(n)
	}
	return starlark.NewList(elems), nil
}

// starlarkListToStrings converts a Starlark list to a Go string slice.
func starlarkListToStrings(fnName string, list *starlark.List) ([]string, error) {
	result := make([]string, list.Len())
	for i := 0; i < list.Len(); i++ {
		s, ok := starlark.AsString(list.Index(i))
		if !ok {
			return nil, fmt.Errorf("%s: element %d must be a string, got %s", fnName, i, list.Index(i).Type())
		}
		result[i] = s
	}
	return result, nil
}
