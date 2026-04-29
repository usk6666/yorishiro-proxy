package pluginv2

import (
	"errors"
	"strings"
	"testing"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// runHook compiles src into a Starlark module that defines a `hook(msg)`
// function, then invokes it with the dict produced from env. Returns the
// dict (so callers can inspect mutation flags) and any error.
func runHook(t *testing.T, env *envelope.Envelope, src string) (*MessageDict, error) {
	t.Helper()
	d, err := convertMessageToDict(env)
	if err != nil {
		return nil, err
	}
	thread := &starlark.Thread{Name: "test"}
	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, "test", []byte(src), nil)
	if err != nil {
		var ee *starlark.EvalError
		if errors.As(err, &ee) {
			return d, errors.New(ee.Backtrace())
		}
		return d, err
	}
	hook, ok := globals["hook"]
	if !ok {
		return d, errors.New("hook not defined in src")
	}
	if _, err := starlark.Call(thread, hook, starlark.Tuple{d}, nil); err != nil {
		var ee *starlark.EvalError
		if errors.As(err, &ee) {
			return d, errors.New(ee.Backtrace())
		}
		return d, err
	}
	return d, nil
}

func TestRawMutation_DetectedOnSetKey(t *testing.T) {
	env := &envelope.Envelope{
		Message: &envelope.HTTPMessage{Method: "GET"},
		Raw:     []byte("GET / HTTP/1.1\r\n\r\n"),
	}
	d, err := runHook(t, env, `
def hook(msg):
    msg["raw"] = b"injected"
`)
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	if !d.RawMutated() {
		t.Fatal("RawMutated() = false after msg[\"raw\"] = ...")
	}
	if d.MessageMutated() {
		t.Fatal("MessageMutated() = true; raw-only assignment must not flip message flag")
	}
	if d.classify() != MutationRawOnly {
		t.Fatalf("classify = %s, want raw_only", d.classify())
	}
	got, raw, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationRawOnly {
		t.Fatalf("kind = %s, want raw_only", kind)
	}
	if got != env.Message {
		t.Fatalf("MutationRawOnly must alias original Message")
	}
	if string(raw) != "injected" {
		t.Fatalf("raw = %q, want \"injected\"", raw)
	}
}

func TestMessageMutation_DetectedOnHeadersAppend(t *testing.T) {
	m := &envelope.HTTPMessage{
		Method:  "GET",
		Headers: []envelope.KeyValue{{Name: "X-Existing", Value: "v"}},
	}
	env := &envelope.Envelope{Message: m, Raw: []byte("WIRE")}
	d, err := runHook(t, env, `
def hook(msg):
    msg["headers"].append("X-Added", "1")
`)
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	if d.RawMutated() {
		t.Fatal("RawMutated() = true; only headers were touched")
	}
	if !d.MessageMutated() {
		t.Fatal("MessageMutated() = false after headers.append")
	}
	if d.classify() != MutationMessageOnly {
		t.Fatalf("classify = %s, want message_only", d.classify())
	}
	got, _, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationMessageOnly {
		t.Fatalf("kind = %s, want message_only", kind)
	}
	if got == env.Message {
		t.Fatal("MutationMessageOnly must produce a fresh Message, not alias")
	}
	hm, ok := got.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("got %T, want *HTTPMessage", got)
	}
	want := []envelope.KeyValue{
		{Name: "X-Existing", Value: "v"},
		{Name: "X-Added", Value: "1"},
	}
	if len(hm.Headers) != len(want) {
		t.Fatalf("len(Headers) = %d, want %d", len(hm.Headers), len(want))
	}
	for i := range want {
		if hm.Headers[i] != want[i] {
			t.Fatalf("idx %d: got %#v, want %#v", i, hm.Headers[i], want[i])
		}
	}
}

func TestBothMutated_RawWinsButMessageReturned(t *testing.T) {
	m := &envelope.HTTPMessage{Method: "GET"}
	env := &envelope.Envelope{Message: m, Raw: []byte("ORIG")}
	d, err := runHook(t, env, `
def hook(msg):
    msg["method"] = "POST"
    msg["raw"] = b"NEW-WIRE"
`)
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	if d.classify() != MutationBoth {
		t.Fatalf("classify = %s, want both", d.classify())
	}
	got, raw, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationBoth {
		t.Fatalf("kind = %s, want both", kind)
	}
	hm := got.(*envelope.HTTPMessage)
	if hm.Method != "POST" {
		t.Fatalf("Method = %q, want POST", hm.Method)
	}
	if string(raw) != "NEW-WIRE" {
		t.Fatalf("raw = %q, want NEW-WIRE", raw)
	}
}

func TestUnknownKey_RejectedAtSetKey(t *testing.T) {
	env := &envelope.Envelope{Message: &envelope.HTTPMessage{}}
	_, err := runHook(t, env, `
def hook(msg):
    msg["headerz"] = "typo"
`)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("err = %v; want 'unknown field'", err)
	}
}

func TestReadOnlyAnomalies_RejectedAtSetKey(t *testing.T) {
	env := &envelope.Envelope{Message: &envelope.HTTPMessage{}}
	_, err := runHook(t, env, `
def hook(msg):
    msg["anomalies"] = []
`)
	if err == nil {
		t.Fatal("expected error for anomalies write")
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("err = %v; want 'read-only'", err)
	}
}

func TestReadOnlyDenormalized_RejectedAtSetKey(t *testing.T) {
	env := &envelope.Envelope{Message: &envelope.GRPCDataMessage{
		Service: "s", Method: "m", Payload: []byte("p"),
	}}
	for _, key := range []string{"service", "method"} {
		src := `
def hook(msg):
    msg["` + key + `"] = "x"
`
		_, err := runHook(t, &envelope.Envelope{Message: env.Message}, src)
		if err == nil {
			t.Fatalf("expected error for write to %q", key)
		}
		if !strings.Contains(err.Error(), "read-only") {
			t.Fatalf("err = %v; want 'read-only' for %q", err, key)
		}
	}
}

func TestRawWriteWrongType_Rejected(t *testing.T) {
	env := &envelope.Envelope{Message: &envelope.HTTPMessage{}}
	_, err := runHook(t, env, `
def hook(msg):
    msg["raw"] = "string-not-bytes"
`)
	if err == nil {
		t.Fatal("expected error for raw=string")
	}
	if !strings.Contains(err.Error(), "must be bytes") {
		t.Fatalf("err = %v; want 'must be bytes'", err)
	}
}

func TestFrozenDict_RejectsAllSetKey(t *testing.T) {
	env := &envelope.Envelope{Message: &envelope.HTTPMessage{Method: "GET"}}
	d, err := convertMessageToDict(env)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	d.Freeze()

	if err := d.SetKey(starlark.String("method"), starlark.String("POST")); err == nil {
		t.Fatal("frozen dict allowed SetKey")
	}
	if err := d.SetKey(starlark.String("raw"), starlark.Bytes("x")); err == nil {
		t.Fatal("frozen dict allowed raw SetKey")
	}
}

func TestNoMutation_StillReturnsUnchanged(t *testing.T) {
	env := &envelope.Envelope{
		Message: &envelope.HTTPMessage{Method: "GET", Headers: []envelope.KeyValue{
			{Name: "A", Value: "1"},
		}},
		Raw: []byte("WIRE"),
	}
	d, err := runHook(t, env, `
def hook(msg):
    # Read-only inspection: get_first must NOT flip mutation flags.
    msg["headers"].get_first("A")
    _ = msg["method"]
`)
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	if d.classify() != MutationUnchanged {
		t.Fatalf("classify = %s, want unchanged after read-only access", d.classify())
	}
}

func TestPlainScalarReassignmentIsMessageMutation(t *testing.T) {
	env := &envelope.Envelope{Message: &envelope.HTTPMessage{Method: "GET", Path: "/"}}
	d, err := runHook(t, env, `
def hook(msg):
    msg["method"] = "POST"
    msg["path"] = "/admin"
`)
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	if d.classify() != MutationMessageOnly {
		t.Fatalf("classify = %s, want message_only", d.classify())
	}
	got, _, _, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	hm := got.(*envelope.HTTPMessage)
	if hm.Method != "POST" || hm.Path != "/admin" {
		t.Fatalf("got Method=%q Path=%q", hm.Method, hm.Path)
	}
}

func TestHTTPMessage_BodyBufferPreservedWhenBodyUntouched(t *testing.T) {
	m := &envelope.HTTPMessage{
		Method: "POST",
		Body:   []byte("orig"),
	}
	env := &envelope.Envelope{Message: m}
	d, err := runHook(t, env, `
def hook(msg):
    msg["method"] = "PATCH"
`)
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	got, _, _, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	hm := got.(*envelope.HTTPMessage)
	// Body wasn't dirty → must alias the original byte slice.
	if &hm.Body[0] != &m.Body[0] {
		t.Fatal("untouched body must alias original (zero-copy)")
	}
}

func TestHTTPMessage_BodyMutationProducesNewBytes(t *testing.T) {
	m := &envelope.HTTPMessage{Body: []byte("original")}
	env := &envelope.Envelope{Message: m}
	d, err := runHook(t, env, `
def hook(msg):
    msg["body"] = b"replaced"
`)
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	got, _, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationMessageOnly {
		t.Fatalf("kind = %s", kind)
	}
	hm := got.(*envelope.HTTPMessage)
	if string(hm.Body) != "replaced" {
		t.Fatalf("Body = %q, want replaced", hm.Body)
	}
}

func TestRawWritePreservesOriginalRawAlias(t *testing.T) {
	// Verifying msg["raw"] writes do NOT mutate the original Envelope.Raw
	// byte slice — the dict captures origRaw by reference but never
	// modifies it, only replaces rawValue.
	orig := []byte("ORIGINAL")
	env := &envelope.Envelope{
		Message: &envelope.HTTPMessage{},
		Raw:     orig,
	}
	d, err := runHook(t, env, `
def hook(msg):
    msg["raw"] = b"X"
`)
	if err != nil {
		t.Fatalf("hook: %v", err)
	}
	if string(orig) != "ORIGINAL" {
		t.Fatalf("original Raw mutated: %q", orig)
	}
	if &d.origRaw[0] != &orig[0] {
		t.Fatal("dict origRaw must alias original Envelope.Raw")
	}
}

func TestMessageDict_ImplementsExpectedInterfaces(t *testing.T) {
	var _ starlark.Value = (*MessageDict)(nil)
	var _ starlark.Mapping = (*MessageDict)(nil)
	var _ starlark.HasSetKey = (*MessageDict)(nil)
	var _ starlark.IterableMapping = (*MessageDict)(nil)
}

func TestHeadersValue_ImplementsExpectedInterfaces(t *testing.T) {
	var _ starlark.Value = (*HeadersValue)(nil)
	var _ starlark.Sequence = (*HeadersValue)(nil)
	var _ starlark.Indexable = (*HeadersValue)(nil)
	var _ starlark.Container = (*HeadersValue)(nil)
	var _ starlark.HasAttrs = (*HeadersValue)(nil)
}
