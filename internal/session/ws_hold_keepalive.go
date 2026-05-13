package session

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// wsHoldKeepaliveStreamStateKey is the canonical ctx.stream_state key a
// plugin sets to opt out of WS hold-window keepalive injection per-Stream.
// A (ws, on_upgrade, pre) hook setting this to False suppresses Ping
// injection regardless of the global web_socket.hold_keepalive_enabled
// config knob.
const wsHoldKeepaliveStreamStateKey = "ws_hold_keepalive"

// wsSendSerializer wraps a layer.Channel Send call site with a sync.Mutex
// so the post-swap WS Channel sees serialised Sends from BOTH the main
// relay loop AND the USK-854 keepalive goroutine. The wsChannel.Send
// contract is documented "NOT safe for concurrent invocation from multiple
// goroutines"; this wrapper preserves that invariant without modifying
// the Channel implementation.
//
// One serialiser is constructed per relay-direction. The main relay loop
// and the keepalive goroutine both call Send via the same instance.
type wsSendSerializer struct {
	mu sync.Mutex
	ch layer.Channel
}

// Send acquires the per-Channel mutex and forwards to the underlying
// Channel.Send.
func (s *wsSendSerializer) Send(ctx context.Context, env *envelope.Envelope) error {
	if s == nil {
		return fmt.Errorf("ws: nil sender")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ch.Send(ctx, env)
}

// newWSSendSerializer wraps dst. Returns nil when dst is nil so callers
// can pass through nil-safe.
func newWSSendSerializer(dst layer.Channel) *wsSendSerializer {
	if dst == nil {
		return nil
	}
	return &wsSendSerializer{ch: dst}
}

// serializedSendChannel wraps a layer.Channel and routes every Send
// through a shared wsSendSerializer so the keepalive goroutine and the
// main relay observe single-flight Sends. All other Channel methods
// forward directly to the underlying instance — only the Send path is
// gated. The wrapper satisfies layer.Channel so callers (including
// dispatchClientAction) treat it identically to the bare WS Channel.
type serializedSendChannel struct {
	layer.Channel
	sender *wsSendSerializer
}

// Send routes through the shared serialiser. The receiver's wsSendSerializer
// holds a reference to the same underlying Channel, so we delegate
// directly to it.
func (c *serializedSendChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	return c.sender.Send(ctx, env)
}

// wrapWSChannelForKeepalive returns a Channel that serialises Send via
// sender when WS keepalive is enabled for the supplied session options;
// otherwise it returns ch unchanged. Centralising this decision here
// keeps the runUpgradeWS / runUpgradeWSOverH2 sites short and ensures the
// wrapper / bare-channel choice is uniform across both upgrade paths.
func wrapWSChannelForKeepalive(ch layer.Channel, opt SessionOptions) (layer.Channel, *wsSendSerializer) {
	if ch == nil || !opt.WSHoldKeepaliveEnabled || opt.InterceptHoldTracker == nil {
		return ch, nil
	}
	sender := newWSSendSerializer(ch)
	return &serializedSendChannel{Channel: ch, sender: sender}, sender
}

// startWSHoldKeepalive spawns the per-Stream goroutine that injects
// synthetic WS Ping frames toward the dst served by sender while a hold
// is in flight on the supplied (streamID, dstDirection) tuple. Returns a
// stop function the caller MUST invoke on relay teardown (defer) to
// guarantee goroutine termination.
//
// The goroutine terminates on any of: ctx cancel, dst.Closed(), a Send
// error, or plugin opt-out re-evaluated to False on a tick. Transient
// IsHeld=false ticks do NOT terminate the goroutine — they simply skip
// the synthetic Ping send so a later hold on the same relay direction is
// served without spawn overhead. The relay's stop() invocation on
// teardown is the canonical hard-stop.
//
// Concurrency Checklist (CLAUDE.md):
//   - Termination: ctx cancel, dst.Closed(), Send error, done close — all
//     converge on the for-select loop below.
//   - Channel close ownership: done is closed exactly once via sync.Once.
//   - Teardown centralized: the returned stop function is the only path
//     callers use; do not close done directly.
//   - Read loops do not block on external backpressure: Send is serialised
//     via the shared mutex but does not couple to a slow reader.
//   - dst.Close stops the goroutine: select on dst.Closed() inside the loop.
//   - Cascade-close: the keepalive never closes dst; only the main relay
//     owns dst lifetime.
//
// Returns a no-op stop when keepalive is disabled (opt.WSHoldKeepaliveEnabled=false,
// nil sender / tracker, empty streamID, or plugin opt-out). The caller can
// defer the stop unconditionally.
func startWSHoldKeepalive(
	ctx context.Context,
	opt SessionOptions,
	sender *wsSendSerializer,
	streamID string,
	dstDirection envelope.Direction,
	connID string,
) func() {
	noop := func() {}

	if !opt.WSHoldKeepaliveEnabled {
		return noop
	}
	if opt.InterceptHoldTracker == nil || sender == nil || streamID == "" {
		return noop
	}
	// Restrict to the Send-direction relay. The keepalive's purpose is to
	// reset the upstream's WS idle timer; the upstream is reached via the
	// Send-direction dst Channel. The Receive-direction relay's dst is
	// the client Channel and the client is local (no idle-timeout concern
	// the proxy can serve from here). USK-851 follow-up B can extend to
	// Receive-direction holds when a concrete operator scenario surfaces.
	if dstDirection != envelope.Send {
		return noop
	}

	// Plugin opt-out: per-Stream stream_state["ws_hold_keepalive"] = False
	// terminates the goroutine before the first tick. The lookup is non-
	// mutating; the plugin author retains the ability to flip the value
	// later (the goroutine re-reads on each tick).
	if opt.PluginEngine != nil && connID != "" {
		if v, ok := opt.PluginEngine.LookupStreamStateBool(connID, streamID, wsHoldKeepaliveStreamStateKey); ok && !v {
			return noop
		}
	}

	interval := opt.WSHoldKeepaliveInterval
	if interval <= 0 {
		// Defensive: the caller (proxybuild.buildSessionOptions) resolves
		// the default before populating SessionOptions. Belt-and-braces in
		// case a test path constructs SessionOptions inline.
		interval = 5 * time.Second
	}

	done := make(chan struct{})
	var once sync.Once
	stop := func() {
		once.Do(func() { close(done) })
	}

	go runWSHoldKeepaliveLoop(ctx, opt, sender, streamID, dstDirection, connID, interval, done)
	return stop
}

// runWSHoldKeepaliveLoop is the keepalive goroutine body. Extracted from
// startWSHoldKeepalive so the spawn site stays short. See startWSHoldKeepalive
// for the full Concurrency Checklist application.
func runWSHoldKeepaliveLoop(
	ctx context.Context,
	opt SessionOptions,
	sender *wsSendSerializer,
	streamID string,
	dstDirection envelope.Direction,
	connID string,
	interval time.Duration,
	done <-chan struct{},
) {
	slog.Debug("session: ws hold-keepalive start",
		"stream_id", streamID,
		"direction", dstDirection.String(),
		"interval", interval,
	)
	defer slog.Debug("session: ws hold-keepalive stop",
		"stream_id", streamID,
		"direction", dstDirection.String(),
	)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-sender.ch.Closed():
			return
		case <-ticker.C:
			// Plugin opt-out is re-checked on each tick so a plugin can
			// flip the per-Stream switch dynamically (e.g. set False from
			// an on_message hook). The PluginEngine is process-singleton
			// and the lookup is non-allocating.
			if opt.PluginEngine != nil && connID != "" {
				if v, ok := opt.PluginEngine.LookupStreamStateBool(connID, streamID, wsHoldKeepaliveStreamStateKey); ok && !v {
					return
				}
			}
			// Tracker observation: inject only when a hold is currently in
			// flight. While the hold queue is empty we simply skip the
			// tick — the goroutine stays alive for the lifetime of the
			// relay so a subsequent hold can be served without re-spawn.
			// The goroutine itself terminates on ctx cancel / dst.Closed /
			// stop / Send error, not on a transient IsHeld=false.
			if !opt.InterceptHoldTracker.IsHeld(streamID, dstDirection) {
				continue
			}
			if err := sendSyntheticPing(ctx, sender, streamID, dstDirection, connID); err != nil {
				// Send failure is terminal. Most failures here are an
				// already-closed Channel (the peer half-closed during the
				// tick, or context cancel raced the send). Warn-level
				// because keepalive injection is opt-in and a failure here
				// surfaces a wire-event the operator may care about.
				slog.Warn("session: ws hold-keepalive send failed; goroutine exiting",
					slog.String("stream_id", streamID),
					slog.String("direction", dstDirection.String()),
					slog.String("error", err.Error()),
				)
				return
			}
		}
	}
}

// sendSyntheticPing builds a synthetic WS Ping Envelope (empty payload,
// Context.Synthetic=true, fresh FlowID) and Sends it through the shared
// serialiser.
//
// The Pipeline is intentionally NOT run inline. The keepalive goroutine
// has only the destination Channel + serialiser in scope; running the
// full Pipeline would require threading the Pipeline pointer through
// SessionOptions, would risk a circular dispatch (PluginPost re-entry on
// a synthetic frame), and would force a second pass through InterceptStep
// (which skips Synthetic correctly but would still allocate the Clone in
// Pipeline.Run for every keepalive tick).
//
// Recording compromise. The synthetic Ping does NOT flow through the
// RecordStep on the Send side. The peer's reflected Pong DOES — it arrives
// on src.Next inside the regular relay loop and runs the full Pipeline,
// so operators see one Pong flow per keepalive tick (Receive-side) with
// the wire bytes intact under env.Raw. The synthetic Ping itself is
// observable on the upstream wire but not in the proxy's recorded flow
// store. This satisfies the Issue's "Record the Ping/Pong as Envelope.Raw
// on the existing WS Stream" requirement for the reflection path. A
// follow-up Issue can add Send-side recording without re-running the
// Pipeline if operators need symmetric visibility.
func sendSyntheticPing(
	ctx context.Context,
	sender *wsSendSerializer,
	streamID string,
	direction envelope.Direction,
	connID string,
) error {
	env := buildSyntheticPingEnvelope(streamID, direction, connID)
	if err := sender.Send(ctx, env); err != nil {
		return fmt.Errorf("synthetic ping send: %w", err)
	}
	return nil
}

// buildSyntheticPingEnvelope constructs the per-tick synthetic Ping
// Envelope. The WS Layer's ctxTmpl (set via ws.WithEnvelopeContext at
// post-swap time) is the canonical wire-observed context — but the
// keepalive goroutine does not have a handle to that template, only to
// the Channel. We populate the bare minimum Context (ConnID, Synthetic
// flag) explicitly; the WS Layer's Send path does not read Envelope.Context
// (it composes a wire frame from env.Message), so the under-populated
// Context is purely an artifact visible to any future Step that observes
// the Send-side envelope (currently none, per the design comment on
// sendSyntheticPing).
func buildSyntheticPingEnvelope(streamID string, direction envelope.Direction, connID string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    uuid.New().String(),
		Direction: direction,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSPing,
			Fin:     true,
			Payload: nil, // RFC 6455 §5.5.2 permits empty Ping
		},
		Context: envelope.EnvelopeContext{
			ConnID:    connID,
			Synthetic: true,
		},
	}
}
