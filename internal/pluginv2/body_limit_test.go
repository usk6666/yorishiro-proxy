package pluginv2

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
)

// USK-1408: plugin_max_body_size replaces the fixed 1 MiB plugin body cap
// with an Engine setting. A body above the cap is never handed to the hook
// (ErrBodyTooLarge → the caller skips the hook); a body within it is.

func bodyLimitEnv(body []byte, buffered bool) *envelope.Envelope {
	m := &envelope.HTTPMessage{Method: "POST", Path: "/", Authority: "example.com"}
	if buffered {
		m.BodyBuffer = bodybuf.NewMemory(body)
	} else {
		m.Body = body
	}
	return &envelope.Envelope{
		StreamID: "s", FlowID: "f", Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP, Message: m,
	}
}

func TestEngine_SetMaxBodySize_GatesDispatch(t *testing.T) {
	const script = `
def hook(msg, ctx):
    msg["headers"].append("X-Seen", str(len(msg["body"])))

register_hook("http", "on_request", hook)
`
	cases := []struct {
		name     string
		limit    int64
		bodyLen  int
		buffered bool
		wantSkip bool
	}{
		{name: "4 KiB body over a 2 KiB cap is skipped", limit: 2048, bodyLen: 4096, wantSkip: true},
		{name: "4 KiB buffered body over a 2 KiB cap is skipped", limit: 2048, bodyLen: 4096, buffered: true, wantSkip: true},
		{name: "1 KiB body under a 2 KiB cap is dispatched", limit: 2048, bodyLen: 1024},
		{name: "body exactly at the cap is dispatched", limit: 2048, bodyLen: 2048},
		{name: "2 MiB body under a raised 4 MiB cap is dispatched", limit: 4 << 20, bodyLen: 2 << 20},
		{name: "zero restores the 1 MiB default", limit: 0, bodyLen: (1 << 20) + 1, wantSkip: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, hook := loadFailOpenPlugin(t, script, ProtoHTTP, EventOnRequest, PhasePrePipeline)
			eng.SetMaxBodySize(tc.limit)

			env := bodyLimitEnv(bytes.Repeat([]byte("b"), tc.bodyLen), tc.buffered)
			out, err := eng.Dispatch(context.Background(), hook, env)
			if tc.wantSkip {
				if !errors.Is(err, ErrBodyTooLarge) {
					t.Fatalf("Dispatch err = %v, want ErrBodyTooLarge (hook must not see a %d-byte body under a %d cap)", err, tc.bodyLen, tc.limit)
				}
				return
			}
			if err != nil {
				t.Fatalf("Dispatch err = %v, want nil", err)
			}
			if out == nil || out.Mutation == MutationUnchanged {
				t.Fatalf("Dispatch outcome = %+v, want the hook's header mutation", out)
			}
		})
	}
}

func TestEngine_MaxBodySize_ReportsEffectiveCap(t *testing.T) {
	eng := NewEngine(nil)
	if got := eng.MaxBodySize(); got != 1<<20 {
		t.Errorf("default MaxBodySize = %d, want %d", got, 1<<20)
	}
	eng.SetMaxBodySize(2048)
	if got := eng.MaxBodySize(); got != 2048 {
		t.Errorf("MaxBodySize after SetMaxBodySize(2048) = %d, want 2048", got)
	}
	eng.SetMaxBodySize(-1)
	if got := eng.MaxBodySize(); got != 1<<20 {
		t.Errorf("MaxBodySize after SetMaxBodySize(-1) = %d, want default %d", got, 1<<20)
	}
}
