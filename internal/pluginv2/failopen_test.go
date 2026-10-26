package pluginv2

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// loadFailOpenPlugin loads script through the real LoadPlugins path and
// returns the engine plus the single hook registered for
// (protocol, event, phase).
func loadFailOpenPlugin(t *testing.T, script, protocol, event string, phase Phase) (*Engine, Hook) {
	t.Helper()
	path := writeScript(t, script)
	eng := NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	hooks := eng.Registry().Lookup(protocol, event, phase)
	if len(hooks) != 1 {
		t.Fatalf("registered hooks for (%s, %s, %s) = %d, want 1", protocol, event, phase, len(hooks))
	}
	return eng, hooks[0]
}

// onlyFailOpen returns the FailOpen stats of the engine's single plugin.
func onlyFailOpen(t *testing.T, eng *Engine) FailOpenStats {
	t.Helper()
	infos := eng.Introspect()
	if len(infos) != 1 {
		t.Fatalf("Introspect len = %d, want 1", len(infos))
	}
	return infos[0].FailOpen
}

// T1: the Issue's acceptance scenario — action.RESPOND_GRPC returned from
// an http.on_request hook is refused, treated as CONTINUE, and the refusal
// is visible through Introspect.
func TestFailOpen_RespondGRPCOnHTTPRequest_Counted(t *testing.T) {
	eng, hook := loadFailOpenPlugin(t, `
def hook(msg, ctx):
    return action.RESPOND_GRPC(status=16, message="denied")

register_hook("http", "on_request", hook)
`, ProtoHTTP, EventOnRequest, PhasePrePipeline)

	before := time.Now()
	if _, err := eng.Dispatch(context.Background(), hook, httpEnv(t)); err == nil {
		t.Fatal("Dispatch err = nil, want the RESPOND_GRPC refused")
	}

	got := onlyFailOpen(t, eng)
	if got.Total != 1 {
		t.Fatalf("FailOpen.Total = %d, want 1", got.Total)
	}
	if got.ByKind[FailOpenRespondShapeMismatch] != 1 {
		t.Errorf("FailOpen.ByKind = %v, want %s=1", got.ByKind, FailOpenRespondShapeMismatch)
	}
	last := got.Last
	if last == nil {
		t.Fatal("FailOpen.Last = nil, want a record")
	}
	if last.Kind != FailOpenRespondShapeMismatch || last.Action != "RESPOND" ||
		last.Protocol != ProtoHTTP || last.Event != EventOnRequest || last.Phase != "pre_pipeline" {
		t.Errorf("FailOpen.Last = %+v, want {respond_shape_mismatch RESPOND http on_request pre_pipeline}", *last)
	}
	if !strings.Contains(last.Reason, "RESPOND_GRPC") {
		t.Errorf("FailOpen.Last.Reason = %q, want it to name RESPOND_GRPC", last.Reason)
	}
	if last.At.IsZero() || last.At.Before(before.Add(-time.Second)) {
		t.Errorf("FailOpen.Last.At = %v, want the dispatch time", last.At)
	}
}

// T2: every Dispatch-side fail-open source increments the counter once
// with its own kind.
func TestFailOpen_DispatchSources_CountedByKind(t *testing.T) {
	bigBody := bytes.Repeat([]byte("b"), maxPluginBodySize+1)
	cases := []struct {
		name            string
		protocol, event string
		phase           Phase
		body            string // hook body
		env             func(t *testing.T) *envelope.Envelope
		kind            FailOpenKind
		action          string
	}{
		{
			name: "http RESPOND on grpc.on_start", protocol: ProtoGRPC, event: EventOnStart, phase: PhasePrePipeline,
			body: `return action.RESPOND(status_code=403, body=b"no")`,
			env:  func(t *testing.T) *envelope.Envelope { return respondShapeEnv(t, ProtoGRPC, EventOnStart) },
			kind: FailOpenRespondShapeMismatch, action: "RESPOND",
		},
		{
			name: "http RESPOND on grpc-web.on_start", protocol: ProtoGRPCWeb, event: EventOnStart, phase: PhasePostPipeline,
			body: `return action.RESPOND(status_code=403, body=b"no")`,
			env:  func(t *testing.T) *envelope.Envelope { return respondShapeEnv(t, ProtoGRPCWeb, EventOnStart) },
			kind: FailOpenRespondShapeMismatch, action: "RESPOND",
		},
		{
			name: "RESPOND on receive 103", protocol: ProtoHTTP, event: EventOnResponse, phase: PhasePrePipeline,
			body: `return action.RESPOND(status_code=418, body=b"plugin")`,
			env:  func(t *testing.T) *envelope.Envelope { return receiveHTTPEnv(103) },
			kind: FailOpenRespondOnInformational, action: "RESPOND",
		},
		{
			name: "DROP on grpc.on_data", protocol: ProtoGRPC, event: EventOnData, phase: PhasePrePipeline,
			body: `return action.DROP`,
			env: func(t *testing.T) *envelope.Envelope {
				return &envelope.Envelope{
					StreamID: "s", FlowID: "f", Direction: envelope.Send, Protocol: envelope.ProtocolGRPC,
					Message: &envelope.GRPCDataMessage{Service: "pkg.Echo", Method: "Say", Payload: []byte("x")},
				}
			},
			kind: FailOpenActionNotAllowed, action: "DROP",
		},
		{
			name: "RESPOND on ws.on_message", protocol: ProtoWS, event: EventOnMessage, phase: PhasePrePipeline,
			body: `return action.RESPOND(status_code=403, body=b"no")`,
			env:  wsTextEnv,
			kind: FailOpenActionNotAllowed, action: "RESPOND",
		},
		{
			name: "fail() in hook", protocol: ProtoHTTP, event: EventOnRequest, phase: PhasePrePipeline,
			body: `fail("plugin blew up")`,
			env:  httpEnv,
			kind: FailOpenHookError,
		},
		{
			name: "bare RESPOND string", protocol: ProtoHTTP, event: EventOnRequest, phase: PhasePrePipeline,
			body: `return "RESPOND"`,
			env:  httpEnv,
			kind: FailOpenInvalidReturn,
		},
		{
			name: "unrecognized string", protocol: ProtoHTTP, event: EventOnRequest, phase: PhasePrePipeline,
			body: `return "BLOCK"`,
			env:  httpEnv,
			kind: FailOpenInvalidReturn,
		},
		{
			name: "unsupported return type", protocol: ProtoHTTP, event: EventOnRequest, phase: PhasePrePipeline,
			body: `return 42`,
			env:  httpEnv,
			kind: FailOpenInvalidReturn,
		},
		{
			name: "out-of-range ws opcode", protocol: ProtoWS, event: EventOnMessage, phase: PhasePrePipeline,
			body: `msg["opcode"] = 300`,
			env:  wsTextEnv,
			kind: FailOpenInvalidMutation,
		},
		{
			name: "body over plugin cap", protocol: ProtoHTTP, event: EventOnRequest, phase: PhasePrePipeline,
			body: `return action.RESPOND(status_code=403, body=b"blocked")`,
			env: func(t *testing.T) *envelope.Envelope {
				env := httpEnv(t)
				env.Message.(*envelope.HTTPMessage).Body = bigBody
				return env
			},
			kind: FailOpenBodyTooLarge,
		},
		{
			name: "raw chunk over cap", protocol: ProtoRaw, event: EventOnChunk, phase: PhasePrePipeline,
			body: fmt.Sprintf(`msg["bytes"] = bytes("A" * %d)`, maxTCPPluginChunkSize+1),
			env:  rawEnv,
			kind: FailOpenChunkTooLarge,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, hook := loadFailOpenPlugin(t, fmt.Sprintf(`
def hook(msg, ctx):
    %s

register_hook(%q, %q, hook, phase=%q)
`, tc.body, tc.protocol, tc.event, string(tc.phase)), tc.protocol, tc.event, tc.phase)

			out, err := eng.Dispatch(context.Background(), hook, tc.env(t))
			if err == nil && out != nil && out.Action != ActionContinue {
				t.Fatalf("Dispatch outcome = %v, want a fail-open (error or CONTINUE)", out.Action)
			}

			got := onlyFailOpen(t, eng)
			if got.Total != 1 {
				t.Fatalf("FailOpen.Total = %d, want 1 (err=%v)", got.Total, err)
			}
			if got.ByKind[tc.kind] != 1 || len(got.ByKind) != 1 {
				t.Errorf("FailOpen.ByKind = %v, want only %s=1", got.ByKind, tc.kind)
			}
			if got.Last == nil {
				t.Fatal("FailOpen.Last = nil")
			}
			if got.Last.Kind != tc.kind || got.Last.Action != tc.action ||
				got.Last.Protocol != tc.protocol || got.Last.Event != tc.event || got.Last.Phase != string(tc.phase) {
				t.Errorf("FailOpen.Last = %+v, want kind=%s action=%q (%s, %s, %s)",
					*got.Last, tc.kind, tc.action, tc.protocol, tc.event, tc.phase)
			}
			if got.Last.Reason == "" {
				t.Error("FailOpen.Last.Reason is empty")
			}
		})
	}
}

// wsTextEnv returns a client-to-server WebSocket text frame envelope.
func wsTextEnv(t *testing.T) *envelope.Envelope {
	t.Helper()
	return &envelope.Envelope{
		StreamID: "s", FlowID: "f", Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Masked: true, Payload: []byte("hi")},
	}
}

// T3: lifecycle hooks (FireLifecycle) count their fail-open outcomes too,
// with phase "none".
func TestFailOpen_Lifecycle_Counted(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		kind   FailOpenKind
		action string
	}{
		{name: "DROP on ws.on_close", body: `return action.DROP`, kind: FailOpenActionNotAllowed, action: "DROP"},
		{name: "fail() in ws.on_close", body: `fail("lifecycle blew up")`, kind: FailOpenHookError},
		{name: "bare RESPOND in ws.on_close", body: `return "RESPOND"`, kind: FailOpenInvalidReturn},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, _ := loadFailOpenPlugin(t, fmt.Sprintf(`
def hook(msg, ctx):
    %s

register_hook("ws", "on_close", hook)
`, tc.body), ProtoWS, EventOnClose, PhaseNone)

			act, err := eng.FireLifecycle(context.Background(), ProtoWS, EventOnClose, nil, BuildWSCloseDict(nil))
			if err != nil || act != ActionContinue {
				t.Fatalf("FireLifecycle = (%v, %v), want (CONTINUE, nil)", act, err)
			}
			got := onlyFailOpen(t, eng)
			if got.Total != 1 {
				t.Fatalf("FailOpen.Total = %d, want 1", got.Total)
			}
			if got.Last == nil || got.Last.Kind != tc.kind || got.Last.Action != tc.action ||
				got.Last.Protocol != ProtoWS || got.Last.Event != EventOnClose || got.Last.Phase != "none" {
				t.Errorf("FailOpen.Last = %+v, want kind=%s action=%q (ws, on_close, none)", got.Last, tc.kind, tc.action)
			}
		})
	}
}

// T4: honoured outcomes are not fail-open.
func TestFailOpen_HonouredOutcomes_NotCounted(t *testing.T) {
	cases := []struct {
		name            string
		protocol, event string
		body            string
		env             func(t *testing.T) *envelope.Envelope
	}{
		{name: "RESPOND on http.on_request", protocol: ProtoHTTP, event: EventOnRequest,
			body: `return action.RESPOND(status_code=403, body=b"no")`, env: httpEnv},
		{name: "RESPOND_GRPC on grpc.on_start", protocol: ProtoGRPC, event: EventOnStart,
			body: `return action.RESPOND_GRPC(status=7, message="no")`,
			env:  func(t *testing.T) *envelope.Envelope { return respondShapeEnv(t, ProtoGRPC, EventOnStart) }},
		{name: "DROP on http.on_request", protocol: ProtoHTTP, event: EventOnRequest,
			body: `return action.DROP`, env: httpEnv},
		{name: "CONTINUE with edit", protocol: ProtoHTTP, event: EventOnRequest,
			body: `msg["headers"].append("X-A", "1")`, env: httpEnv},
		{name: "explicit CONTINUE", protocol: ProtoHTTP, event: EventOnRequest,
			body: `return action.CONTINUE`, env: httpEnv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, hook := loadFailOpenPlugin(t, fmt.Sprintf(`
def hook(msg, ctx):
    %s

register_hook(%q, %q, hook)
`, tc.body, tc.protocol, tc.event), tc.protocol, tc.event, PhasePrePipeline)
			if _, err := eng.Dispatch(context.Background(), hook, tc.env(t)); err != nil {
				t.Fatalf("Dispatch err = %v", err)
			}
			got := onlyFailOpen(t, eng)
			if got.Total != 0 || got.Last != nil || len(got.ByKind) != 0 {
				t.Errorf("FailOpen = %+v, want zero for an honoured outcome", got)
			}
		})
	}
}

// T5: counters belong to the loaded plugin instance, not its name — two
// plugins whose names collide (both p.star) are counted apart.
func TestFailOpen_CollidingPluginNames_CountedPerInstance(t *testing.T) {
	failing := writeScript(t, `
def hook(msg, ctx):
    return action.RESPOND_GRPC(status=16, message="denied")

register_hook("http", "on_request", hook)
`)
	quiet := writeScript(t, `
def hook(msg, ctx):
    return None

register_hook("http", "on_request", hook)
`)
	eng := NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{
		{Path: quiet, OnError: string(OnErrorAbort)},
		{Path: failing, OnError: string(OnErrorAbort)},
	}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	for _, h := range eng.Registry().Lookup(ProtoHTTP, EventOnRequest, PhasePrePipeline) {
		_, _ = eng.Dispatch(context.Background(), h, httpEnv(t))
	}
	infos := eng.Introspect()
	if len(infos) != 2 || infos[0].Name != infos[1].Name {
		t.Fatalf("Introspect = %d plugins (names %v), want 2 with colliding names", len(infos), infos)
	}
	if infos[0].Path != quiet || infos[1].Path != failing {
		t.Fatalf("plugin order = [%s, %s], want [quiet, failing]", infos[0].Path, infos[1].Path)
	}
	if infos[0].FailOpen.Total != 0 {
		t.Errorf("quiet plugin FailOpen.Total = %d, want 0", infos[0].FailOpen.Total)
	}
	if infos[1].FailOpen.Total != 1 {
		t.Errorf("failing plugin FailOpen.Total = %d, want 1", infos[1].FailOpen.Total)
	}
}

// T6: concurrent dispatches are counted exactly while Introspect reads.
func TestFailOpen_ConcurrentDispatch_ExactCount(t *testing.T) {
	eng, hook := loadFailOpenPlugin(t, `
def hook(msg, ctx):
    return action.RESPOND_GRPC(status=16, message="denied")

register_hook("http", "on_request", hook)
`, ProtoHTTP, EventOnRequest, PhasePrePipeline)

	const workers, perWorker = 32, 25
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
				_ = eng.Introspect()
			}
		}
	}()
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				_, _ = eng.Dispatch(context.Background(), hook, httpEnv(t))
			}
		}()
	}
	wg.Wait()
	close(stop)
	<-readerDone

	got := onlyFailOpen(t, eng)
	if got.Total != workers*perWorker {
		t.Errorf("FailOpen.Total = %d, want %d", got.Total, workers*perWorker)
	}
	if got.ByKind[FailOpenRespondShapeMismatch] != workers*perWorker {
		t.Errorf("FailOpen.ByKind = %v, want %s=%d", got.ByKind, FailOpenRespondShapeMismatch, workers*perWorker)
	}
}

// T7: reasons for engine-generated kinds are fixed-format texts that
// never carry envelope content (header / body / path / payload values),
// even when the plugin echoes that content in its return value.
func TestFailOpen_EngineReasons_CarryNoEnvelopeContent(t *testing.T) {
	const sentinel = "SENTINEL7c1e"
	sentinelHTTP := func(t *testing.T) *envelope.Envelope {
		env := httpEnv(t)
		m := env.Message.(*envelope.HTTPMessage)
		m.Path = "/" + sentinel
		m.Headers = append(m.Headers, envelope.KeyValue{Name: "X-Secret", Value: sentinel})
		m.Body = []byte(sentinel)
		return env
	}
	cases := []struct {
		name            string
		protocol, event string
		body            string
		env             func(t *testing.T) *envelope.Envelope
	}{
		{name: "shape mismatch", protocol: ProtoHTTP, event: EventOnRequest,
			body: `return action.RESPOND_GRPC(status=16, message=msg["path"])`, env: sentinelHTTP},
		{name: "unrecognized string echoing the path", protocol: ProtoHTTP, event: EventOnRequest,
			body: `return "X" + msg["path"]`, env: sentinelHTTP},
		{name: "body over cap", protocol: ProtoHTTP, event: EventOnRequest,
			body: `return None`,
			env: func(t *testing.T) *envelope.Envelope {
				env := sentinelHTTP(t)
				env.Message.(*envelope.HTTPMessage).Body = append([]byte(sentinel), bytes.Repeat([]byte("b"), maxPluginBodySize)...)
				return env
			}},
		{name: "DROP on grpc.on_data", protocol: ProtoGRPC, event: EventOnData,
			body: `return action.DROP`,
			env: func(t *testing.T) *envelope.Envelope {
				return &envelope.Envelope{
					StreamID: "s", FlowID: "f", Direction: envelope.Send, Protocol: envelope.ProtocolGRPC,
					Message: &envelope.GRPCDataMessage{Service: "pkg.Echo", Method: sentinel, Payload: []byte(sentinel)},
				}
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, hook := loadFailOpenPlugin(t, fmt.Sprintf(`
def hook(msg, ctx):
    %s

register_hook(%q, %q, hook)
`, tc.body, tc.protocol, tc.event), tc.protocol, tc.event, PhasePrePipeline)
			_, _ = eng.Dispatch(context.Background(), hook, tc.env(t))
			got := onlyFailOpen(t, eng)
			if got.Last == nil {
				t.Fatal("FailOpen.Last = nil, want a record")
			}
			if strings.Contains(got.Last.Reason, sentinel) {
				t.Errorf("FailOpen.Last.Reason = %q carries envelope content %q", got.Last.Reason, sentinel)
			}
		})
	}
}

// The hook_error reason is bounded so a plugin raising a huge message
// cannot grow the record without limit.
func TestFailOpen_HookErrorReason_Bounded(t *testing.T) {
	eng, hook := loadFailOpenPlugin(t, `
def hook(msg, ctx):
    fail("é" * 5000)

register_hook("http", "on_request", hook)
`, ProtoHTTP, EventOnRequest, PhasePrePipeline)
	_, _ = eng.Dispatch(context.Background(), hook, httpEnv(t))
	got := onlyFailOpen(t, eng)
	if got.Last == nil {
		t.Fatal("FailOpen.Last = nil, want a record")
	}
	if n := len(got.Last.Reason); n == 0 || n > FailOpenReasonCap {
		t.Errorf("len(FailOpen.Last.Reason) = %d, want 1..%d", n, FailOpenReasonCap)
	}
	if !strings.ContainsRune(got.Last.Reason, 'é') || strings.ContainsRune(got.Last.Reason, '�') {
		t.Errorf("FailOpen.Last.Reason was not cut on a rune boundary: %q", got.Last.Reason[len(got.Last.Reason)-8:])
	}
}
