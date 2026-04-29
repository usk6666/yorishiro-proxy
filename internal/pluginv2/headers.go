package pluginv2

import (
	"fmt"
	"strings"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// HeadersValue is a Starlark value that wraps an ordered list of HTTP-style
// headers preserving wire case, order, and duplicates exactly as observed.
//
// Per RFC §9.3 D3 and Friction 5-B, plugins must not be able to silently
// normalize header data: only append, replace_at, delete_first, and the
// read-only get_first lookup are exposed. Sort, dedup, extend, clear,
// remove, pop, insert are deliberately not surfaced; attribute lookups for
// those names return AttributeError via the standard starlark.HasAttrs
// (nil, nil) → not-found contract.
//
// HeadersValue implements starlark.Value, Sequence, Indexable, Container,
// and HasAttrs. Indexing yields a 2-tuple (name, value); HasSetIndex is
// intentionally not implemented to prevent positional tuple writes (use
// replace_at instead — one canonical way to mutate at an index).
type HeadersValue struct {
	kvs       []envelope.KeyValue
	mutated   bool
	frozen    bool
	frozenErr error // cached "frozen" error to allocate once on the cold path
}

// NewHeadersValue wraps the given KeyValue slice. The slice is shared by
// reference; callers that need isolation should clone first via
// envelope.cloneKeyValues equivalents. Initialization preserves wire order.
func NewHeadersValue(kvs []envelope.KeyValue) *HeadersValue {
	return &HeadersValue{kvs: kvs}
}

// Mutated reports whether any of append, replace_at, or delete_first was
// invoked successfully. Read-only operations (Index, Iterate, Has,
// get_first) never set this flag.
func (h *HeadersValue) Mutated() bool {
	if h == nil {
		return false
	}
	return h.mutated
}

// Snapshot returns a copy of the current []KeyValue slice for read-back
// into envelope.Message at dictToMessage time.
func (h *HeadersValue) Snapshot() []envelope.KeyValue {
	if h == nil || h.kvs == nil {
		return nil
	}
	out := make([]envelope.KeyValue, len(h.kvs))
	copy(out, h.kvs)
	return out
}

// --- starlark.Value ---

func (h *HeadersValue) String() string {
	var b strings.Builder
	b.WriteString("headers([")
	for i, kv := range h.kvs {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "(%q, %q)", kv.Name, kv.Value)
	}
	b.WriteString("])")
	return b.String()
}

func (h *HeadersValue) Type() string { return "headers" }

func (h *HeadersValue) Freeze() { h.frozen = true }

func (h *HeadersValue) Truth() starlark.Bool { return starlark.Bool(len(h.kvs) > 0) }

// Hash reports that headers are unhashable (mutable, list-like).
func (h *HeadersValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: headers")
}

// --- starlark.Sequence + Indexable ---

func (h *HeadersValue) Len() int { return len(h.kvs) }

func (h *HeadersValue) Index(i int) starlark.Value {
	kv := h.kvs[i]
	return starlark.Tuple{starlark.String(kv.Name), starlark.String(kv.Value)}
}

func (h *HeadersValue) Iterate() starlark.Iterator { return &headersIterator{h: h, i: 0} }

type headersIterator struct {
	h *HeadersValue
	i int
}

func (it *headersIterator) Next(p *starlark.Value) bool {
	if it.i >= len(it.h.kvs) {
		return false
	}
	*p = it.h.Index(it.i)
	it.i++
	return true
}

func (it *headersIterator) Done() {}

// --- starlark.Container (`name in headers`) ---

// Has reports whether any header has Name matching y under ASCII
// case-insensitive comparison. Returns an error if y is not a string.
func (h *HeadersValue) Has(y starlark.Value) (bool, error) {
	name, ok := y.(starlark.String)
	if !ok {
		return false, fmt.Errorf("headers: expected string for membership test, got %s", y.Type())
	}
	for _, kv := range h.kvs {
		if equalASCIIFold(kv.Name, string(name)) {
			return true, nil
		}
	}
	return false, nil
}

// --- starlark.HasAttrs (methods) ---

var headersAttrNames = []string{"append", "replace_at", "delete_first", "get_first"}

func (h *HeadersValue) AttrNames() []string {
	out := make([]string, len(headersAttrNames))
	copy(out, headersAttrNames)
	return out
}

func (h *HeadersValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "append":
		return starlark.NewBuiltin("headers.append", h.bAppend).BindReceiver(h), nil
	case "replace_at":
		return starlark.NewBuiltin("headers.replace_at", h.bReplaceAt).BindReceiver(h), nil
	case "delete_first":
		return starlark.NewBuiltin("headers.delete_first", h.bDeleteFirst).BindReceiver(h), nil
	case "get_first":
		return starlark.NewBuiltin("headers.get_first", h.bGetFirst).BindReceiver(h), nil
	}
	// Returning (nil, nil) signals "no such attribute" — Starlark surfaces
	// AttributeError. Sort, dedup, extend, clear, remove, pop, insert all
	// land here intentionally.
	return nil, nil
}

func (h *HeadersValue) checkFrozen() error {
	if h.frozen {
		if h.frozenErr == nil {
			h.frozenErr = fmt.Errorf("headers: cannot mutate frozen value")
		}
		return h.frozenErr
	}
	return nil
}

// bAppend implements headers.append(name, value). Two positional arguments
// per the issue contract; tuple form is intentionally not accepted to keep
// one canonical way to add an entry.
func (h *HeadersValue) bAppend(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name, value starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &name, &value); err != nil {
		return nil, err
	}
	if err := h.checkFrozen(); err != nil {
		return nil, err
	}
	h.kvs = append(h.kvs, envelope.KeyValue{Name: string(name), Value: string(value)})
	h.mutated = true
	return starlark.None, nil
}

// bReplaceAt implements headers.replace_at(index, name, value). Negative or
// out-of-range index reports "ordered list operations only: index out of
// range" per Friction 5-B's mandate to fail loudly on invalid order ops.
func (h *HeadersValue) bReplaceAt(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var index int
	var name, value starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 3, &index, &name, &value); err != nil {
		return nil, err
	}
	if err := h.checkFrozen(); err != nil {
		return nil, err
	}
	if index < 0 || index >= len(h.kvs) {
		return nil, fmt.Errorf("ordered list operations only: index %d out of range [0, %d)", index, len(h.kvs))
	}
	h.kvs[index] = envelope.KeyValue{Name: string(name), Value: string(value)}
	h.mutated = true
	return starlark.None, nil
}

// bDeleteFirst implements headers.delete_first(name) -> bool indicating
// whether a match was removed. Comparison is ASCII case-insensitive.
// Removes only the first match, never deduplicates.
func (h *HeadersValue) bDeleteFirst(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &name); err != nil {
		return nil, err
	}
	if err := h.checkFrozen(); err != nil {
		return nil, err
	}
	target := string(name)
	for i, kv := range h.kvs {
		if equalASCIIFold(kv.Name, target) {
			h.kvs = append(h.kvs[:i], h.kvs[i+1:]...)
			h.mutated = true
			return starlark.True, nil
		}
	}
	return starlark.False, nil
}

// bGetFirst implements headers.get_first(name) -> string|None. Read-only
// case-insensitive lookup. Does not set the mutated flag.
func (h *HeadersValue) bGetFirst(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &name); err != nil {
		return nil, err
	}
	target := string(name)
	for _, kv := range h.kvs {
		if equalASCIIFold(kv.Name, target) {
			return starlark.String(kv.Value), nil
		}
	}
	return starlark.None, nil
}

// equalASCIIFold reports whether s and t are equal under ASCII case folding.
// HTTP/1 and HTTP/2 header names are ASCII-only by spec; using a
// non-allocating ASCII fold avoids the unicode normalization overhead of
// strings.EqualFold and matches the wire's case-insensitive semantics
// without ever modifying the stored case.
func equalASCIIFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		a, b := s[i], t[i]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}
