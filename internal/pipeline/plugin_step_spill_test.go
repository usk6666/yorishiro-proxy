package pipeline

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// Plugin mutations on a disk-spilled HTTP/1.x envelope, driven through
// PluginStepPre + RecordStep. The session refcount backstop is simulated
// after Run: it releases the input envelope's RawBuffer twice (Layer +
// snapshot), the input BodyBuffer once for the snapshot, and once more for
// the Layer only when the returned envelope still points at it.

const pluginSpillPrefix = "yorishiro-body-"

const (
	spillReqHead = "POST /spill HTTP/1.1\r\nHost: example.com\r\nContent-Length: 20\r\n\r\n"
	spillReqBody = "spilled-request-body"
)

func newSpillFile(t *testing.T, dir, data string) *bodybuf.BodyBuffer {
	t.Helper()
	buf, err := bodybuf.NewFile(dir, pluginSpillPrefix, 1<<20)
	if err != nil {
		t.Fatalf("bodybuf.NewFile: %v", err)
	}
	if _, err := buf.Write([]byte(data)); err != nil {
		t.Fatalf("bodybuf.Write: %v", err)
	}
	return buf
}

func countPluginSpillFiles(t *testing.T, dir string) int {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, pluginSpillPrefix+"*"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	return len(m)
}

// spilledH1Request is the shape the HTTP/1.x Layer hands the session for an
// over-threshold request: Raw is the header section, RawBuffer the wire
// body and HTTPMessage.BodyBuffer the decoded body, each file-backed at
// refCount=1.
func spilledH1Request(t *testing.T, dir string) *envelope.Envelope {
	t.Helper()
	return &envelope.Envelope{
		StreamID:  "stream-spill",
		FlowID:    "flow-spill",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte(spillReqHead),
		RawBuffer: newSpillFile(t, dir, spillReqBody),
		Context:   envelope.EnvelopeContext{ConnID: "conn-spill"},
		Message: &envelope.HTTPMessage{
			Method:    "POST",
			Scheme:    "http",
			Authority: "example.com",
			Path:      "/spill",
			Headers: []envelope.KeyValue{
				{Name: "Host", Value: "example.com"},
				{Name: "Content-Length", Value: "20"},
			},
			BodyBuffer: newSpillFile(t, dir, spillReqBody),
		},
	}
}

func setKeyHook(key string, val starlark.Value) pluginv2.Hook {
	return pluginv2.Hook{
		Protocol: pluginv2.ProtoHTTP, Event: pluginv2.EventOnRequest,
		Phase: pluginv2.PhasePrePipeline, PluginName: "spill",
		Fn: hookCallable("set_"+key, func(args starlark.Tuple) (starlark.Value, error) {
			msg := args[0].(*pluginv2.MessageDict)
			return starlark.None, msg.SetKey(starlark.String(key), val)
		}),
	}
}

func variantFlow(t *testing.T, store *mockWriter, variant string) *flow.Flow {
	t.Helper()
	for _, fl := range store.flows {
		if fl.Metadata["variant"] == variant {
			return fl
		}
	}
	t.Fatalf("%s variant flow not recorded", variant)
	return nil
}

// simulateBackstop releases the references session.runPipelineTracked
// would register for an input envelope whose buffers were pre / preRaw
// and whose Pipeline output is out.
func simulateBackstop(pre, preRaw *bodybuf.BodyBuffer, out *envelope.Envelope) {
	if pre != nil {
		_ = pre.Release()
		if m, ok := out.Message.(*envelope.HTTPMessage); ok && m != nil && m.BodyBuffer == pre {
			_ = pre.Release()
		}
	}
	if preRaw != nil {
		_ = preRaw.Release()
		_ = preRaw.Release()
	}
}

// TestPluginStepPre_SpilledBodyReplace_ReleasesLayerReference: replacing a
// spilled body still records the original variant from the snapshot, the
// modified variant carries the plugin bytes, and once the backstop has run
// no spill file remains.
func TestPluginStepPre_SpilledBodyReplace_ReleasesLayerReference(t *testing.T) {
	dir := t.TempDir()
	env := spilledH1Request(t, dir)
	pre := env.Message.(*envelope.HTTPMessage).BodyBuffer
	preRaw := env.RawBuffer

	eng := pluginv2.NewEngine(nil)
	eng.Registry().Register(setKeyHook("body", starlark.Bytes("new")))
	store := &mockWriter{}
	out, action, _ := New(
		NewPluginStepPre(eng, nil, nil),
		NewRecordStep(store, nil),
	).Run(context.Background(), env)
	if action != Continue {
		t.Fatalf("action = %v, want Continue", action)
	}

	if got := variantFlow(t, store, "original").Body; string(got) != spillReqBody {
		t.Errorf("original variant body = %q, want %q", got, spillReqBody)
	}
	if got := variantFlow(t, store, "modified").Body; string(got) != "new" {
		t.Errorf("modified variant body = %q, want %q", got, "new")
	}

	simulateBackstop(pre, preRaw, out)
	if got := countPluginSpillFiles(t, dir); got != 0 {
		t.Errorf("after backstop: spill files = %d, want 0 (the replaced body's Layer reference was never released)", got)
	}
}

// TestPluginStepPre_SpilledMessageOnly_ModifiedRawBytesExact: a MessageOnly
// mutation on a spilled HTTP/1.x envelope records the re-encoded message as
// the modified variant's RawBytes — without the stale wire body from
// RawBuffer stitched after it — while the original variant keeps the wire
// bytes.
func TestPluginStepPre_SpilledMessageOnly_ModifiedRawBytesExact(t *testing.T) {
	cases := []struct {
		name string
		hook pluginv2.Hook
	}{
		{name: "body_replacement", hook: setKeyHook("body", starlark.Bytes("new"))},
		{name: "header_only", hook: setKeyHook("path", starlark.String("/changed"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			env := spilledH1Request(t, dir)
			pre := env.Message.(*envelope.HTTPMessage).BodyBuffer
			preRaw := env.RawBuffer

			reg := NewWireEncoderRegistry()
			reg.Register(envelope.ProtocolHTTP, http1.EncodeWireBytes)
			eng := pluginv2.NewEngine(nil)
			eng.Registry().Register(c.hook)
			store := &mockWriter{}
			out, action, _ := New(
				NewPluginStepPre(eng, reg, nil),
				NewRecordStep(store, nil, WithWireEncoderRegistry(reg)),
			).Run(context.Background(), env)
			if action != Continue {
				t.Fatalf("action = %v, want Continue", action)
			}

			want, err := http1.EncodeWireBytes(out)
			if err != nil {
				t.Fatalf("EncodeWireBytes: %v", err)
			}
			mod := variantFlow(t, store, "modified")
			if !bytes.Equal(mod.RawBytes, want) {
				t.Errorf("modified variant RawBytes (%d bytes) = %q, want the re-encoded message (%d bytes) %q",
					len(mod.RawBytes), mod.RawBytes, len(want), want)
			}
			if orig := variantFlow(t, store, "original"); string(orig.RawBytes) != spillReqHead+spillReqBody {
				t.Errorf("original variant RawBytes = %q, want the wire bytes %q", orig.RawBytes, spillReqHead+spillReqBody)
			}

			simulateBackstop(pre, preRaw, out)
			if got := countPluginSpillFiles(t, dir); got != 0 {
				t.Errorf("after backstop: spill files = %d, want 0", got)
			}
		})
	}
}
