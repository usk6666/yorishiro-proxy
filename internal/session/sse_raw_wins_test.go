package session

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	sserules "github.com/usk6666/yorishiro-proxy/internal/rules/sse"
)

// USK-1239: RFC-001 §9.3 D4 "Raw wins" on the SSE wire. SSE events are
// written to the client by the session (relaySSEEvent /
// emitSSESyntheticEventTooLarge), not by a Layer's Channel.Send, so the
// session writer must honour Envelope.RawWins(). These tests drive
// driveSSEEventLoop — the seam shared by the HTTP/1 (chunkedTE=true or
// identity) and HTTP/2 (chunkedTE=false) SSE paths — with a real
// Pipeline carrying a real Starlark plugin loaded from a .star file.

// rawWinsOddEvent is an upstream event in a non-canonical wire form: id
// before event, "data:v1" without the optional space, and a comment
// line. The canonical encoder would emit "event: tick\nid: 7\ndata: v1\n\n".
const rawWinsOddEvent = "id: 7\nevent: tick\ndata:v1\n: keep-me\n\n"

// rawWinsSecondEvent is left untouched by every plugin below.
const rawWinsSecondEvent = "data:  second\n\n"

// rawWinsPluginBytes is what the plugins write to msg["raw"]. It is
// deliberately not a canonical encoding of any SSEMessage.
const rawWinsPluginBytes = "event: injected\ndata:x\n\n"

func writeSSERawWinsScript(t *testing.T, script string) *pluginv2.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.star")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []pluginv2.PluginConfig{{
		Path: path, OnError: string(pluginv2.OnErrorAbort),
	}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	return eng
}

func sseRawWinsEncoders() *pipeline.WireEncoderRegistry {
	reg := pipeline.NewWireEncoderRegistry()
	reg.Register(envelope.ProtocolSSE, sse.EncodeWireBytes)
	return reg
}

// buildSSERawWinsPipeline mirrors the production step order for the
// Steps that can touch an SSE event: PluginPre → Transform → PluginPost
// → Record.
func buildSSERawWinsPipeline(eng *pluginv2.Engine, te *sserules.TransformEngine, store *sseH2RecordStub) *pipeline.Pipeline {
	reg := sseRawWinsEncoders()
	return pipeline.New(
		pipeline.NewPluginStepPre(eng, reg, nil),
		pipeline.NewTransformStep(nil, nil, nil, te),
		pipeline.NewPluginStepPost(eng, reg, nil),
		pipeline.NewRecordStep(store, nil, pipeline.WithWireEncoderRegistry(reg)),
	)
}

// sseWireFrame returns the bytes writeEventToClient puts on the wire for
// one event payload.
func sseWireFrame(t *testing.T, payload []byte, chunkedTE bool) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := writeEventToClient(&b, payload, chunkedTE); err != nil {
		t.Fatalf("writeEventToClient: %v", err)
	}
	return b.Bytes()
}

func canonicalSSE(t *testing.T, msg *envelope.SSEMessage) []byte {
	t.Helper()
	b, err := sse.EncodeWireBytes(&envelope.Envelope{Protocol: envelope.ProtocolSSE, Message: msg})
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	return b
}

// runSSERawWinsLoop drives driveSSEEventLoop over upstream and returns
// the client-side wire bytes.
func runSSERawWinsLoop(t *testing.T, p *pipeline.Pipeline, upstream string, chunkedTE bool, maxEvent int) []byte {
	t.Helper()
	var client bytes.Buffer
	nextSeq := 1
	br := sse.NewEventBoundaryReader(strings.NewReader(upstream), maxEvent)
	err := driveSSEEventLoop(context.Background(), p, br, &client, chunkedTE,
		"stream-usk1239", envelope.EnvelopeContext{}, &nextSeq, maxEvent)
	if maxEvent >= len(upstream) && err != nil {
		t.Fatalf("driveSSEEventLoop: %v", err)
	}
	return client.Bytes()
}

// expectedSSEWire concatenates per-event frames plus the h1 chunked
// terminator when chunkedTE.
func expectedSSEWire(t *testing.T, chunkedTE bool, payloads ...[]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	for _, p := range payloads {
		b.Write(sseWireFrame(t, p, chunkedTE))
	}
	if chunkedTE {
		b.WriteString("0\r\n\r\n")
	}
	return b.Bytes()
}

// TestDriveSSEEventLoop_PluginRawWins covers Test Plan #3, #4, #5, #6:
// a plugin msg["raw"] write reaches the client verbatim on both the
// chunked (h1) and unframed (h1 close-delimited / h2 DATA) paths, while
// untouched and Message-only events behave as before.
func TestDriveSSEEventLoop_PluginRawWins(t *testing.T) {
	plugin := []byte(rawWinsPluginBytes)
	untouched := []byte(rawWinsSecondEvent)
	cases := []struct {
		name   string
		script string
		// first is the expected wire payload for rawWinsOddEvent.
		first []byte
		// rawRecorded: the modified variant must record the plugin bytes.
		rawRecorded bool
	}{
		{
			name: "pre_pipeline raw only",
			script: `
def on_ev(msg, ctx):
    if msg["data"] == "v1":
        msg["raw"] = b"event: injected\ndata:x\n\n"
register_hook("sse", "on_event", on_ev)
`,
			first:       plugin,
			rawRecorded: true,
		},
		{
			name: "post_pipeline raw only",
			script: `
def on_ev(msg, ctx):
    if msg["data"] == "v1":
        msg["raw"] = b"event: injected\ndata:x\n\n"
register_hook("sse", "on_event", on_ev, phase="post_pipeline")
`,
			first:       plugin,
			rawRecorded: true,
		},
		{
			name: "raw and message both written: raw wins",
			script: `
def on_ev(msg, ctx):
    if msg["data"] == "v1":
        msg["data"] = "msgside"
        msg["raw"] = b"event: injected\ndata:x\n\n"
register_hook("sse", "on_event", on_ev)
`,
			first:       plugin,
			rawRecorded: true,
		},
		{
			// Reverse guard (#5): a plugin that only reads the message
			// must not perturb the non-canonical upstream bytes.
			name: "read-only plugin keeps upstream bytes verbatim",
			script: `
def on_ev(msg, ctx):
    _ = msg["data"]
register_hook("sse", "on_event", on_ev)
`,
			first: []byte(rawWinsOddEvent),
		},
		{
			// Reverse guard (#6): a Message-only rewrite still re-encodes.
			name: "message-only rewrite re-encodes",
			script: `
def on_ev(msg, ctx):
    if msg["data"] == "v1":
        msg["data"] = "Z"
register_hook("sse", "on_event", on_ev)
`,
			first: canonicalSSE(t, &envelope.SSEMessage{Event: "tick", ID: "7", Data: "Z"}),
		},
	}
	for _, tc := range cases {
		for _, chunkedTE := range []bool{true, false} {
			name := tc.name + "/unframed"
			if chunkedTE {
				name = tc.name + "/chunked"
			}
			t.Run(name, func(t *testing.T) {
				store := &sseH2RecordStub{}
				p := buildSSERawWinsPipeline(writeSSERawWinsScript(t, tc.script), nil, store)

				got := runSSERawWinsLoop(t, p, rawWinsOddEvent+rawWinsSecondEvent, chunkedTE, 4096)
				want := expectedSSEWire(t, chunkedTE, tc.first, untouched)
				if !bytes.Equal(got, want) {
					t.Errorf("client wire =\n%q\nwant\n%q", got, want)
				}
				if tc.rawRecorded {
					assertSSEModifiedRaw(t, store, plugin)
				}
			})
		}
	}
}

func assertSSEModifiedRaw(t *testing.T, store *sseH2RecordStub, want []byte) {
	t.Helper()
	for _, fl := range store.snapshotFlows() {
		if fl.Metadata["variant"] == "modified" {
			if !bytes.Equal(fl.RawBytes, want) {
				t.Errorf("modified variant RawBytes = %q, want %q", fl.RawBytes, want)
			}
			return
		}
	}
	t.Error("modified variant flow not recorded")
}

// TestDriveSSEEventLoop_PluginRawWins_TransformPrecedence covers Test
// Plan #7: precedence is pipeline order, last writer wins. A
// pre_pipeline raw write followed by a firing SSE Transform hands the
// wire back to the Message path; a post_pipeline raw write after the
// Transform wins.
func TestDriveSSEEventLoop_PluginRawWins_TransformPrecedence(t *testing.T) {
	newTE := func(t *testing.T) *sserules.TransformEngine {
		t.Helper()
		r, err := sserules.CompileTransformRule("set", 0, "", "^tick$", "", "", nil, nil, nil,
			sserules.TransformSetData, "", "", "TRANSFORMED", "", "", "", "", 0)
		if err != nil {
			t.Fatalf("CompileTransformRule: %v", err)
		}
		te := sserules.NewTransformEngine()
		te.AddRule(*r)
		return te
	}
	cases := []struct {
		name   string
		phase  string
		first  []byte
		reason string
	}{
		{
			// Note: green on main (no marker honoured, Transform output
			// re-encoded); turns red if the session honours RawWins()
			// without TransformStep clearing the marker.
			name:   "pre_pipeline raw then Transform: Transform wins",
			phase:  "pre_pipeline",
			first:  canonicalSSE(t, &envelope.SSEMessage{Event: "tick", ID: "7", Data: "TRANSFORMED"}),
			reason: "a Transform that fires after a pre_pipeline raw write is the last writer",
		},
		{
			name:   "Transform then post_pipeline raw: raw wins",
			phase:  "post_pipeline",
			first:  []byte(rawWinsPluginBytes),
			reason: "a post_pipeline raw write is the last writer",
		},
	}
	for _, tc := range cases {
		for _, chunkedTE := range []bool{true, false} {
			name := tc.name + "/unframed"
			if chunkedTE {
				name = tc.name + "/chunked"
			}
			t.Run(name, func(t *testing.T) {
				script := `
def on_ev(msg, ctx):
    if msg["event"] == "tick":
        msg["raw"] = b"event: injected\ndata:x\n\n"
register_hook("sse", "on_event", on_ev, phase="` + tc.phase + `")
`
				store := &sseH2RecordStub{}
				p := buildSSERawWinsPipeline(writeSSERawWinsScript(t, script), newTE(t), store)
				got := runSSERawWinsLoop(t, p, rawWinsOddEvent+rawWinsSecondEvent, chunkedTE, 4096)
				want := expectedSSEWire(t, chunkedTE, tc.first, []byte(rawWinsSecondEvent))
				if !bytes.Equal(got, want) {
					t.Errorf("%s: client wire =\n%q\nwant\n%q", tc.reason, got, want)
				}
			})
		}
	}
}

// TestDriveSSEEventLoop_PluginRawWins_SyntheticEventTooLarge covers Test
// Plan #9: the proxy-synthesised event:error envelope also honours a
// plugin msg["raw"] write.
func TestDriveSSEEventLoop_PluginRawWins_SyntheticEventTooLarge(t *testing.T) {
	const capBytes = 64
	script := `
def on_ev(msg, ctx):
    if msg["event"] == "error":
        msg["raw"] = b"event: injected\ndata:x\n\n"
register_hook("sse", "on_event", on_ev)
`
	for _, chunkedTE := range []bool{true, false} {
		name := "unframed"
		if chunkedTE {
			name = "chunked"
		}
		t.Run(name, func(t *testing.T) {
			store := &sseH2RecordStub{}
			p := buildSSERawWinsPipeline(writeSSERawWinsScript(t, script), nil, store)
			upstream := "data: " + strings.Repeat("x", capBytes*2) + "\n\n"
			got := runSSERawWinsLoop(t, p, upstream, chunkedTE, capBytes)
			want := expectedSSEWire(t, chunkedTE, []byte(rawWinsPluginBytes))
			if !bytes.Equal(got, want) {
				t.Errorf("client wire =\n%q\nwant plugin bytes\n%q", got, want)
			}
		})
	}
}
