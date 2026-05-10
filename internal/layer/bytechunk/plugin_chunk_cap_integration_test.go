//go:build e2e && !e2e_smoke

// Integration test for USK-803: confirms that an oversized chunk produced
// by a (raw, on_chunk) Starlark plugin is rejected by the pluginv2
// dispatch-time cap and that the bytechunk Layer's Send forwards the
// ORIGINAL chunk verbatim (fail-soft pattern). The cap is enforced inside
// internal/pluginv2/dispatch.go (mirrors config.MaxTCPPluginChunkSize =
// 1 MiB; the bytechunk relay buffer is 32 KiB so plugins are budgeted
// 32× expansion as a CWE-400 mitigation).
//
// Test placement adjacent to smuggling_integration_test.go matches the
// Issue's directive — no bytechunk source code changes; bytechunk Channel.Send
// is the egress surface that would have written the unbounded bytes if the
// cap were missing.

package bytechunk_test

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// captureHandler records slog records into an in-memory slice so the test
// can verify a Warn was emitted for the cap-hit. Concurrency-safe.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *captureHandler) findWarn(needle string) (slog.Record, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Level != slog.LevelWarn {
			continue
		}
		if strings.Contains(r.Message, needle) {
			return r, true
		}
		// Some implementations push detail into attrs only.
		var match bool
		r.Attrs(func(a slog.Attr) bool {
			if strings.Contains(a.Value.String(), needle) {
				match = true
				return false
			}
			return true
		})
		if match {
			return r, true
		}
	}
	return slog.Record{}, false
}

// rawHookCallable wraps a Go function as a Starlark Callable suitable for
// pluginv2.Hook.Fn. Mirrors the helper in pluginv2/dispatch_test.go
// (builtinHook) but minimised for this test.
func rawHookCallable(name string, fn func(args starlark.Tuple) (starlark.Value, error)) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		return fn(args)
	})
}

// TestRawOnChunkPlugin_OversizedBytes_FailsSoftToWire verifies the full
// chain end-to-end:
//
//   - A (raw, on_chunk) Starlark hook is registered that returns 2 MiB via
//     msg["bytes"] (i.e. *envelope.RawMessage.Bytes mutation).
//   - The Pipeline's PluginStepPre dispatches the hook through
//     pluginv2.Engine.Dispatch.
//   - Engine.Dispatch surfaces ErrChunkTooLarge.
//   - The Pipeline dispatcher catches the sentinel, emits slog.Warn, and
//     continues with the previous (un-mutated) envelope.
//   - The resulting envelope is handed to bytechunk.Channel.Send which
//     writes the ORIGINAL chunk to the wire — confirmed by reading the
//     other end of net.Pipe.
//
// This is the regression-prevention test for the USK-803 attack: it
// proves that an oversized plugin output cannot reach the wire through
// the bytechunk Layer.
func TestRawOnChunkPlugin_OversizedBytes_FailsSoftToWire(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logHandler := &captureHandler{}
	logger := slog.New(logHandler)

	// Register a (raw, on_chunk) hook that returns 2 MiB of "X" bytes —
	// well over the 1 MiB cap — via the msg["bytes"] path.
	eng := pluginv2.NewEngine(logger)
	oversized := bytes.Repeat([]byte("X"), 2<<20)
	eng.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoRaw,
		Event:      pluginv2.EventOnChunk,
		Phase:      pluginv2.PhasePrePipeline,
		PluginName: "oversized-tcp",
		Fn: rawHookCallable("oversize", func(args starlark.Tuple) (starlark.Value, error) {
			if len(args) < 1 {
				return starlark.None, nil
			}
			if d, ok := args[0].(starlark.HasSetKey); ok {
				if err := d.SetKey(starlark.String("bytes"), starlark.Bytes(oversized)); err != nil {
					return nil, err
				}
			}
			return starlark.None, nil
		}),
	})

	// Build a Pipeline with PluginStepPre as the only Step. nil encoders is
	// fine: a (raw, on_chunk) hit either returns RawOnly/Both (Raw is shipped
	// verbatim) or MessageOnly (no encoder for ProtocolRaw is registered, so
	// next.Raw falls back to the original — which is exactly the behaviour
	// we want to verify when the cap fires and the Pipeline preserves the
	// previous envelope).
	pipe := pipeline.New(pipeline.NewPluginStepPre(eng, nil, logger))

	// Wire bytechunk Channel.Send into a net.Pipe so we can read what
	// would actually be written to the wire after Pipeline processing.
	proxySide, peerSide := net.Pipe()
	defer proxySide.Close()
	defer peerSide.Close()

	layer := bytechunk.New(proxySide, "stream-cap-test", envelope.Receive)
	defer layer.Close()
	sendCh := <-layer.Channels()

	// Original chunk: small enough to be obviously distinct from the
	// oversized plugin output.
	original := []byte("ORIGINAL_SMALL_CHUNK")
	originalEnv := &envelope.Envelope{
		StreamID:  "stream-cap-test",
		FlowID:    "flow-1",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolRaw,
		Raw:       append([]byte(nil), original...),
		Message:   &envelope.RawMessage{Bytes: append([]byte(nil), original...)},
		Context:   envelope.EnvelopeContext{ConnID: "conn-1"},
	}

	// Reader goroutine drains the peer side into a buffer.
	type readResult struct {
		data []byte
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 4<<20) // generous so we'd see oversized if it came through
		_ = peerSide.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := peerSide.Read(buf)
		readDone <- readResult{data: append([]byte(nil), buf[:n]...), err: err}
	}()

	// Run the Pipeline. With cap fail-soft, the result envelope must be
	// the original envelope (Pipeline returns the input when no Step
	// produced a new envelope). Even if the dispatcher returned the
	// previous envelope, .Bytes must equal the original.
	procEnv, action, _ := pipe.Run(ctx, originalEnv)
	if action != pipeline.Continue {
		t.Fatalf("Pipeline action = %v, want Continue (fail-soft)", action)
	}
	envToSend := procEnv
	if envToSend == nil {
		envToSend = originalEnv
	}

	// Sanity check: the message bytes that we are about to send must be
	// the original — proving the cap kicked in before the mutation
	// reached downstream.
	rm, ok := envToSend.Message.(*envelope.RawMessage)
	if !ok {
		t.Fatalf("Pipeline output Message type %T, want *envelope.RawMessage", envToSend.Message)
	}
	if !bytes.Equal(rm.Bytes, original) {
		t.Fatalf("Pipeline output Bytes len=%d (first 32: %q), want original len=%d (first 32: %q)",
			len(rm.Bytes), trunc(rm.Bytes, 32), len(original), trunc(original, 32))
	}

	// Send to the bytechunk Channel — this is the actual wire egress path.
	if err := sendCh.Send(ctx, envToSend); err != nil {
		t.Fatalf("Channel.Send: %v", err)
	}

	// Verify the peer received exactly the original bytes — NOT the
	// 2 MiB plugin output.
	res := <-readDone
	if res.err != nil && len(res.data) == 0 {
		t.Fatalf("peer read error: %v", res.err)
	}
	if !bytes.Equal(res.data, original) {
		t.Fatalf("peer received %d bytes, want %d (original); cap did not fail-soft as expected",
			len(res.data), len(original))
	}

	// Verify Warn log was emitted referencing the chunk-too-large condition.
	if _, ok := logHandler.findWarn("rejected"); !ok {
		t.Errorf("expected Warn log mentioning 'rejected'; got %d records", len(logHandler.records))
		for _, r := range logHandler.records {
			t.Logf("  level=%v msg=%q", r.Level, r.Message)
		}
	}
}

func trunc(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}
