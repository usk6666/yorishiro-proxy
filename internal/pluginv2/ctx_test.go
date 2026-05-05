package pluginv2

import (
	"net"
	"strings"
	"testing"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	return NewEngine(nil)
}

func makeHTTPEnvelope(connID, flowID, streamID, addr string) *envelope.Envelope {
	var clientAddr net.Addr
	if addr != "" {
		clientAddr = &net.TCPAddr{IP: net.ParseIP(stripPort(addr)), Port: portOf(addr)}
	}
	return &envelope.Envelope{
		StreamID: streamID,
		FlowID:   flowID,
		Protocol: envelope.ProtocolHTTP,
		Context: envelope.EnvelopeContext{
			ConnID:     connID,
			ClientAddr: clientAddr,
		},
	}
}

func stripPort(s string) string {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return host
}

func portOf(s string) int {
	_, _, err := net.SplitHostPort(s)
	if err != nil {
		return 0
	}
	// Tests pass a literal port; parse via net.SplitHostPort + plain Atoi
	// is heavier than needed, so re-derive from the original string.
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return 0
	}
	p := 0
	for _, ch := range s[i+1:] {
		if ch < '0' || ch > '9' {
			return 0
		}
		p = p*10 + int(ch-'0')
	}
	return p
}

func TestNewCtx_TransactionStatePersistsAcrossPrePost(t *testing.T) {
	e := newTestEngine(t)

	env := makeHTTPEnvelope("conn-A", "flow-1", "stream-1", "203.0.113.7:55555")

	pre := e.NewCtx(env)
	if err := pre.txState.state.set("k", starlark.String("from-pre")); err != nil {
		t.Fatalf("pre set: %v", err)
	}

	post := e.NewCtx(env)
	got := post.txState.state.get("k")
	if got != starlark.String("from-pre") {
		t.Fatalf("post read = %v, want \"from-pre\" (Pre/Post must share state)", got)
	}

	if size := e.transactionStore.size(); size != 1 {
		t.Fatalf("transactionStore size = %d, want 1", size)
	}
	e.ReleaseTransaction("conn-A", "flow-1")
	if size := e.transactionStore.size(); size != 0 {
		t.Fatalf("transactionStore size after release = %d, want 0", size)
	}
}

func TestNewCtx_RequestAndResponseDoNotShareTransaction(t *testing.T) {
	e := newTestEngine(t)

	req := makeHTTPEnvelope("conn-A", "flow-req", "stream-1", "")
	resp := makeHTTPEnvelope("conn-A", "flow-resp", "stream-1", "")

	cReq := e.NewCtx(req)
	cResp := e.NewCtx(resp)

	if err := cReq.txState.state.set("k", starlark.String("v")); err != nil {
		t.Fatalf("req set: %v", err)
	}
	if got := cResp.txState.state.get("k"); got != starlark.None {
		t.Fatalf("resp transaction_state.get(\"k\") = %v, want None — req and resp use distinct FlowID keys", got)
	}

	// Both envelopes share the same StreamID, so stream_state must be
	// shared across req and resp.
	if err := cReq.stState.state.set("rpc", starlark.String("yes")); err != nil {
		t.Fatalf("stream set: %v", err)
	}
	if got := cResp.stState.state.get("rpc"); got != starlark.String("yes") {
		t.Fatalf("stream_state.get(\"rpc\") = %v, want \"yes\" — req+resp share StreamID", got)
	}
}

func TestNewCtx_ConnectionIsolation(t *testing.T) {
	e := newTestEngine(t)

	a := e.NewCtx(makeHTTPEnvelope("conn-A", "flow-1", "stream-1", ""))
	b := e.NewCtx(makeHTTPEnvelope("conn-B", "flow-1", "stream-1", ""))

	_ = a.txState.state.set("k", starlark.String("from-A"))
	_ = b.txState.state.set("k", starlark.String("from-B"))

	if got := a.txState.state.get("k"); got != starlark.String("from-A") {
		t.Fatalf("conn-A read = %v, want \"from-A\"", got)
	}
	if got := b.txState.state.get("k"); got != starlark.String("from-B") {
		t.Fatalf("conn-B read = %v, want \"from-B\"", got)
	}

	if got := a.stState.state.get("k"); got != starlark.None {
		// Different conns must not share stream_state even when StreamID
		// strings collide.
		_ = got
	}
	_ = b.stState.state.set("k", starlark.String("from-B"))
	if got := a.stState.state.get("k"); got != starlark.None {
		t.Fatalf("cross-connection stream_state leak: conn-A got %v, expected None", got)
	}
}

func TestNewCtx_ReleaseStreamGCsScope(t *testing.T) {
	e := newTestEngine(t)
	env := makeHTTPEnvelope("conn-A", "flow-1", "stream-1", "")

	c := e.NewCtx(env)
	_ = c.stState.state.set("k", starlark.String("v"))

	if size := e.streamStore.size(); size != 1 {
		t.Fatalf("streamStore size = %d, want 1", size)
	}

	e.ReleaseStream("conn-A", "stream-1")

	if size := e.streamStore.size(); size != 0 {
		t.Fatalf("streamStore size after release = %d, want 0", size)
	}

	// The previously-captured scope must observe an empty dict so a hook
	// that captured a reference cannot leak data into a freed scope.
	if got := c.stState.state.get("k"); got != starlark.None {
		t.Fatalf("get on released stream scope = %v, want None", got)
	}
}

func TestNewCtx_NilEnvelope(t *testing.T) {
	e := newTestEngine(t)
	c := e.NewCtx(nil)

	if c.clientAddr != starlark.None {
		t.Fatalf("nil env client_addr = %v, want None", c.clientAddr)
	}
	if c.tls != starlark.None {
		t.Fatalf("nil env tls = %v, want None", c.tls)
	}

	// state proxies must not panic on get/set/keys/clear.
	if got := c.txState.state; got != nil {
		t.Fatal("nil env txState should have no backing")
	}

	v, _ := c.txState.builtinGet(nil, starlark.NewBuiltin("transaction_state.get", c.txState.builtinGet), starlark.Tuple{starlark.String("missing")}, nil)
	if v != starlark.None {
		t.Fatalf("get on nil-backed proxy = %v, want None", v)
	}
}

func TestNewCtx_NonHTTPProtocolUsesStreamIDForTransaction(t *testing.T) {
	e := newTestEngine(t)

	frame1 := &envelope.Envelope{
		StreamID: "ws-channel-1",
		FlowID:   "frame-1",
		Protocol: envelope.ProtocolWebSocket,
		Context:  envelope.EnvelopeContext{ConnID: "conn-A"},
	}
	frame2 := &envelope.Envelope{
		StreamID: "ws-channel-1",
		FlowID:   "frame-2", // different per-frame FlowID
		Protocol: envelope.ProtocolWebSocket,
		Context:  envelope.EnvelopeContext{ConnID: "conn-A"},
	}

	c1 := e.NewCtx(frame1)
	c2 := e.NewCtx(frame2)

	_ = c1.txState.state.set("k", starlark.String("v"))
	if got := c2.txState.state.get("k"); got != starlark.String("v") {
		t.Fatalf("ws frames on same channel did not share transaction_state: got %v", got)
	}
}

func TestNewCtx_ClientAddrIsIPOnly(t *testing.T) {
	e := newTestEngine(t)
	env := makeHTTPEnvelope("conn-A", "flow-1", "stream-1", "203.0.113.7:55555")

	c := e.NewCtx(env)
	got, ok := c.clientAddr.(starlark.String)
	if !ok {
		t.Fatalf("client_addr type = %T, want String", c.clientAddr)
	}
	if string(got) != "203.0.113.7" {
		t.Fatalf("client_addr = %q, want \"203.0.113.7\" (IP only)", string(got))
	}
}

func TestNewCtx_TLSDictFrozen(t *testing.T) {
	e := newTestEngine(t)

	env := makeHTTPEnvelope("conn-A", "flow-1", "stream-1", "")
	env.Context.TLS = &envelope.TLSSnapshot{
		SNI:               "example.test",
		ALPN:              "h2",
		ClientFingerprint: "ja3-hash",
	}

	c := e.NewCtx(env)
	d, ok := c.tls.(*starlark.Dict)
	if !ok {
		t.Fatalf("tls type = %T, want *starlark.Dict", c.tls)
	}
	v, _, _ := d.Get(starlark.String("sni"))
	if got, _ := v.(starlark.String); string(got) != "example.test" {
		t.Fatalf("tls.sni = %v, want \"example.test\"", v)
	}

	// Mutation must be rejected — the dict is frozen.
	if err := d.SetKey(starlark.String("sni"), starlark.String("hijacked")); err == nil {
		t.Fatal("expected frozen dict to reject SetKey")
	}
}

func TestNewCtx_StarlarkSurface(t *testing.T) {
	// Drive ctx.transaction_state via real Starlark code so the Attr +
	// builtin glue is exercised end-to-end.
	e := newTestEngine(t)
	env := makeHTTPEnvelope("conn-A", "flow-1", "stream-1", "203.0.113.7:55555")
	ctxVal := e.NewCtx(env)

	thread := &starlark.Thread{Name: "ctx-test"}

	const script = `
ctx.transaction_state.set("k", "v")
got = ctx.transaction_state.get("k")
have = ctx.transaction_state.get("missing")
keys = ctx.transaction_state.keys()
addr = ctx.client_addr
`

	predeclared := starlark.StringDict{"ctx": ctxVal}
	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, "ctx_test.star", script, predeclared)
	if err != nil {
		t.Fatalf("starlark exec: %v", err)
	}

	if got, ok := globals["got"].(starlark.String); !ok || string(got) != "v" {
		t.Fatalf("got = %v, want \"v\"", globals["got"])
	}
	if got := globals["have"]; got != starlark.None {
		t.Fatalf("have = %v, want None", got)
	}
	if got, ok := globals["addr"].(starlark.String); !ok || string(got) != "203.0.113.7" {
		t.Fatalf("addr = %v, want \"203.0.113.7\"", globals["addr"])
	}
	keys, ok := globals["keys"].(*starlark.List)
	if !ok || keys.Len() != 1 {
		t.Fatalf("keys = %v, want list of length 1", globals["keys"])
	}
}

func TestNewCtx_StarlarkClearAndDelete(t *testing.T) {
	e := newTestEngine(t)
	env := makeHTTPEnvelope("conn-A", "flow-1", "stream-1", "")
	ctxVal := e.NewCtx(env)

	thread := &starlark.Thread{Name: "ctx-test"}

	const script = `
ctx.transaction_state.set("a", 1)
ctx.transaction_state.set("b", 2)
ctx.transaction_state.delete("a")
remaining = ctx.transaction_state.keys()
ctx.transaction_state.clear()
empty = ctx.transaction_state.keys()
`

	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, "ctx_test.star", script, starlark.StringDict{"ctx": ctxVal})
	if err != nil {
		t.Fatalf("starlark exec: %v", err)
	}
	if remaining, ok := globals["remaining"].(*starlark.List); !ok || remaining.Len() != 1 {
		t.Fatalf("remaining = %v, want list of length 1", globals["remaining"])
	}
	if empty, ok := globals["empty"].(*starlark.List); !ok || empty.Len() != 0 {
		t.Fatalf("empty = %v, want []", globals["empty"])
	}
}

func TestEngine_ReleaseTransactionAndStreamAreNoOpsOnEmptyKeys(t *testing.T) {
	e := newTestEngine(t)
	// These should not panic; they should not allocate empty entries either.
	e.ReleaseTransaction("", "flow-1")
	e.ReleaseTransaction("conn-A", "")
	e.ReleaseStream("", "stream-1")
	e.ReleaseStream("conn-A", "")

	if size := e.transactionStore.size(); size != 0 {
		t.Fatalf("transactionStore unexpectedly populated: size %d", size)
	}
	if size := e.streamStore.size(); size != 0 {
		t.Fatalf("streamStore unexpectedly populated: size %d", size)
	}
}

func TestEngine_CloseClearsStateStores(t *testing.T) {
	e := newTestEngine(t)
	env := makeHTTPEnvelope("conn-A", "flow-1", "stream-1", "")
	c := e.NewCtx(env)
	_ = c.txState.state.set("k", starlark.String("v"))
	_ = c.stState.state.set("rpc", starlark.String("yes"))

	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Both stores must be empty post-Close. The captured ScopedState
	// pointers must observe an empty dict so any in-flight goroutine
	// cannot resurrect data through them.
	if size := e.transactionStore.size(); size != 0 {
		t.Fatalf("transactionStore size after Close = %d, want 0", size)
	}
	if size := e.streamStore.size(); size != 0 {
		t.Fatalf("streamStore size after Close = %d, want 0", size)
	}
	if got := c.txState.state.get("k"); got != starlark.None {
		t.Fatalf("captured txState read after Close = %v, want None", got)
	}
}
