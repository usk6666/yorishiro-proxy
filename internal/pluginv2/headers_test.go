package pluginv2

import (
	"errors"
	"strings"
	"testing"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestHeadersValue_AppendPreservesCaseAndDuplicates(t *testing.T) {
	hv := NewHeadersValue(nil)
	if _, err := evalHeaders(t, hv, `
h.append("X-Test", "1")
h.append("x-test", "2")
h.append("X-TEST", "3")
`); err != nil {
		t.Fatalf("eval: %v", err)
	}
	got := hv.Snapshot()
	want := []envelope.KeyValue{
		{Name: "X-Test", Value: "1"},
		{Name: "x-test", Value: "2"},
		{Name: "X-TEST", Value: "3"},
	}
	assertKVEqual(t, got, want)
	if !hv.Mutated() {
		t.Fatalf("Mutated() = false after append")
	}
}

func TestHeadersValue_GetFirstCaseInsensitive(t *testing.T) {
	hv := NewHeadersValue([]envelope.KeyValue{
		{Name: "X-Test", Value: "1"},
		{Name: "x-test", Value: "2"},
	})
	if _, err := evalHeaders(t, hv, `v = h.get_first("X-TEST")`); err != nil {
		t.Fatalf("eval: %v", err)
	}
	if hv.Mutated() {
		t.Fatalf("get_first must not flip mutated flag")
	}
}

func TestHeadersValue_GetFirstReturnsNoneForAbsent(t *testing.T) {
	hv := NewHeadersValue(nil)
	thread := &starlark.Thread{Name: "test"}
	got, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, "test", []byte(
		`v = h.get_first("missing")
`), starlark.StringDict{"h": hv})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if got["v"] != starlark.None {
		t.Fatalf("get_first absent = %v, want None", got["v"])
	}
}

func TestHeadersValue_DeleteFirstRemovesOnlyFirstMatch(t *testing.T) {
	hv := NewHeadersValue([]envelope.KeyValue{
		{Name: "X-Test", Value: "1"},
		{Name: "x-test", Value: "2"},
		{Name: "Other", Value: "ok"},
		{Name: "X-Test", Value: "3"},
	})
	if _, err := evalHeaders(t, hv, `r = h.delete_first("X-Test")`); err != nil {
		t.Fatalf("eval: %v", err)
	}
	want := []envelope.KeyValue{
		{Name: "x-test", Value: "2"},
		{Name: "Other", Value: "ok"},
		{Name: "X-Test", Value: "3"},
	}
	assertKVEqual(t, hv.Snapshot(), want)
	if !hv.Mutated() {
		t.Fatalf("Mutated() = false after delete_first")
	}
}

func TestHeadersValue_DeleteFirstReturnsFalseWhenAbsent(t *testing.T) {
	hv := NewHeadersValue([]envelope.KeyValue{{Name: "Other", Value: "v"}})
	thread := &starlark.Thread{Name: "test"}
	got, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, "test", []byte(
		`r = h.delete_first("X-Missing")
`), starlark.StringDict{"h": hv})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if got["r"] != starlark.False {
		t.Fatalf("delete_first absent = %v, want False", got["r"])
	}
	if hv.Mutated() {
		t.Fatalf("delete_first absent must not flip mutated flag")
	}
}

func TestHeadersValue_ReplaceAtSubstitutes(t *testing.T) {
	hv := NewHeadersValue([]envelope.KeyValue{
		{Name: "Old", Value: "v"},
		{Name: "Keep", Value: "k"},
	})
	if _, err := evalHeaders(t, hv, `h.replace_at(0, "New", "n")`); err != nil {
		t.Fatalf("eval: %v", err)
	}
	want := []envelope.KeyValue{
		{Name: "New", Value: "n"},
		{Name: "Keep", Value: "k"},
	}
	assertKVEqual(t, hv.Snapshot(), want)
}

func TestHeadersValue_ReplaceAtOutOfRangeFails(t *testing.T) {
	hv := NewHeadersValue([]envelope.KeyValue{{Name: "X", Value: "1"}})
	cases := []string{
		`h.replace_at(-1, "X", "y")`,
		`h.replace_at(1, "X", "y")`,
		`h.replace_at(99, "X", "y")`,
	}
	for _, src := range cases {
		_, err := evalHeaders(t, hv, src)
		if err == nil {
			t.Fatalf("expected error for %q", src)
		}
		if !strings.Contains(err.Error(), "ordered list operations only") {
			t.Fatalf("expected mandated phrase in error, got: %v", err)
		}
	}
	if hv.Mutated() {
		t.Fatalf("failed replace_at must not flip mutated flag")
	}
}

func TestHeadersValue_ForbiddenMethodsAreNotAttributes(t *testing.T) {
	hv := NewHeadersValue([]envelope.KeyValue{{Name: "A", Value: "1"}})
	for _, method := range []string{"sort", "dedup", "extend", "clear", "pop", "remove", "insert"} {
		v, err := hv.Attr(method)
		if err != nil {
			t.Fatalf("Attr(%q) error: %v", method, err)
		}
		if v != nil {
			t.Fatalf("Attr(%q) = %v; expected (nil, nil) — surface as AttributeError", method, v)
		}
	}
}

func TestHeadersValue_IndexAndIterationYieldTuples(t *testing.T) {
	hv := NewHeadersValue([]envelope.KeyValue{
		{Name: "A", Value: "1"},
		{Name: "B", Value: "2"},
	})
	if hv.Len() != 2 {
		t.Fatalf("Len = %d, want 2", hv.Len())
	}
	got := hv.Index(0)
	tup, ok := got.(starlark.Tuple)
	if !ok {
		t.Fatalf("Index returned %T, want Tuple", got)
	}
	if len(tup) != 2 || tup[0].(starlark.String) != "A" || tup[1].(starlark.String) != "1" {
		t.Fatalf("Index(0) = %v, want (\"A\", \"1\")", tup)
	}

	// Verify iteration via Starlark `for` loop yields tuples in order
	// without flipping mutated.
	thread := &starlark.Thread{Name: "test"}
	src := `
def _collect():
    out = []
    for kv in h:
        out.append(kv)
    return out
result = _collect()
`
	out, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, "test", []byte(src),
		starlark.StringDict{"h": hv})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	list, ok := out["result"].(*starlark.List)
	if !ok {
		t.Fatalf("result is %T", out["result"])
	}
	if list.Len() != 2 {
		t.Fatalf("len(result) = %d", list.Len())
	}
	if hv.Mutated() {
		t.Fatalf("iteration flipped mutated flag")
	}
}

func TestHeadersValue_ContainsCaseInsensitive(t *testing.T) {
	hv := NewHeadersValue([]envelope.KeyValue{{Name: "Content-Type", Value: "x"}})
	thread := &starlark.Thread{Name: "test"}
	src := `
hit_lower = "content-type" in h
hit_upper = "CONTENT-TYPE" in h
miss = "absent" in h
`
	out, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, "test", []byte(src),
		starlark.StringDict{"h": hv})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if out["hit_lower"] != starlark.True || out["hit_upper"] != starlark.True {
		t.Fatalf("case-insensitive `in` failed: %v %v", out["hit_lower"], out["hit_upper"])
	}
	if out["miss"] != starlark.False {
		t.Fatalf("miss = %v, want False", out["miss"])
	}
}

func TestHeadersValue_FrozenRejectsMutation(t *testing.T) {
	hv := NewHeadersValue([]envelope.KeyValue{{Name: "A", Value: "1"}})
	hv.Freeze()
	for _, src := range []string{
		`h.append("B", "2")`,
		`h.replace_at(0, "X", "y")`,
		`h.delete_first("A")`,
	} {
		_, err := evalHeaders(t, hv, src)
		if err == nil {
			t.Fatalf("expected frozen error for %q", src)
		}
	}
}

// evalHeaders runs a one-off Starlark snippet with `h` bound to hv,
// wrapping it in a function so it may use control-flow (for/if) and
// reassign locals — Starlark forbids both at module scope. Returns
// only the error since callers already inspect hv state directly.
func evalHeaders(t *testing.T, hv *HeadersValue, src string) (starlark.Value, error) {
	t.Helper()
	thread := &starlark.Thread{Name: "test"}
	indented := strings.ReplaceAll(src, "\n", "\n    ")
	prog := "def _run():\n    " + indented + "\n_run()\n"
	_, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, "test", []byte(prog),
		starlark.StringDict{"h": hv})
	if err != nil {
		var ee *starlark.EvalError
		if errors.As(err, &ee) {
			return nil, errors.New(ee.Backtrace())
		}
		return nil, err
	}
	return starlark.None, nil
}

func assertKVEqual(t *testing.T, got, want []envelope.KeyValue) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len(got)=%d len(want)=%d\ngot:  %#v\nwant: %#v", len(got), len(want), got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("idx %d: got %#v, want %#v", i, got[i], want[i])
		}
	}
}
