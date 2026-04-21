// Package session implements the universal session loop that drives all
// protocols through the Channel + Pipeline architecture. RunSession is
// protocol-agnostic: it only knows Channel (read/write envelopes) and Pipeline
// (ordered processing steps). Two goroutines handle the bidirectional data
// flow: client-to-upstream and upstream-to-client.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"golang.org/x/sync/errgroup"
)

// DialFunc creates an upstream Channel lazily. It is called with the first
// Send Envelope so that the target address can be derived from the envelope's
// Context.TargetHost.
type DialFunc func(ctx context.Context, env *envelope.Envelope) (layer.Channel, error)

// SessionOptions configures optional callbacks for RunSession.
type SessionOptions struct {
	// OnComplete is called after both goroutines have terminated.
	// streamID is the StreamID captured from the first Envelope (may be empty
	// if no Envelope was processed). err is nil on normal EOF termination, or
	// the error that caused the session to end.
	//
	// The context passed to OnComplete is derived from the original context
	// (not the errgroup context), so it remains valid for store writes even
	// after the errgroup cancels its derived context.
	OnComplete func(ctx context.Context, streamID string, err error)
}

// streamCapture captures the StreamID from the first Envelope in a
// goroutine-safe manner.
type streamCapture struct {
	mu       sync.Mutex
	streamID string
	captured bool
}

// set records the StreamID if it has not been captured yet.
func (s *streamCapture) set(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.captured {
		s.streamID = id
		s.captured = true
	}
}

// get returns the captured StreamID.
func (s *streamCapture) get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streamID
}

// upstreamHolder passes the upstream Channel from goroutine 1 to goroutine 2
// with proper synchronization via the ready channel. The done channel is
// closed when goroutine 1 exits, allowing goroutine 2 to detect that no
// upstream will ever be established.
type upstreamHolder struct {
	ch    layer.Channel
	ready chan struct{} // closed when upstream Channel is established
	done  chan struct{} // closed when goroutine 1 (client->upstream) exits
}

// RunSession is the universal session loop for all protocols.
//
// It reads Envelopes from the client Channel, runs them through the Pipeline,
// and forwards them to an upstream Channel created lazily via dial. A second
// goroutine reads responses from upstream, runs them through the Pipeline,
// and sends them back to the client.
//
// Both goroutines are managed by errgroup.WithContext: if either returns an
// error the context is cancelled and the other goroutine terminates. io.EOF
// from Channel.Next is treated as normal stream termination, not an error.
func RunSession(ctx context.Context, client layer.Channel, dial DialFunc, p *pipeline.Pipeline, opts ...SessionOptions) error {
	defer client.Close()

	var opt SessionOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	// Keep a reference to the original context for OnComplete, because
	// errgroup.WithContext creates a derived context that is cancelled when
	// Wait() returns — making it unusable for store writes.
	origCtx := ctx

	uh := &upstreamHolder{
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}
	defer func() {
		if uh.ch != nil {
			uh.ch.Close()
		}
	}()

	sc := &streamCapture{}

	// upstreamDone is closed by upstreamToClient on exit. The late-error
	// watcher uses this to stop polling once the response side has already
	// finished (whether normally or due to an error).
	upstreamDone := make(chan struct{})

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer close(uh.done)
		return clientToUpstream(ctx, client, dial, p, uh, sc)
	})

	g.Go(func() error {
		defer close(upstreamDone)
		return upstreamToClient(ctx, client, p, uh, sc)
	})

	g.Go(func() error {
		return lateClientErrorWatcher(ctx, client, uh, upstreamDone)
	})

	result := g.Wait()

	if opt.OnComplete != nil {
		opt.OnComplete(context.WithoutCancel(origCtx), sc.get(), result)
	}

	return result
}

// clientToUpstream reads Envelopes from the client, runs them through the
// Pipeline, and forwards them to the upstream Channel. It creates the upstream
// Channel lazily on the first forwarded Envelope and signals uh.ready.
func clientToUpstream(
	ctx context.Context,
	client layer.Channel,
	dial DialFunc,
	p *pipeline.Pipeline,
	uh *upstreamHolder,
	sc *streamCapture,
) (err error) {
	// When the client-side goroutine exits abnormally (e.g., client-side
	// RST_STREAM, stream error, pipeline error), actively tear the upstream
	// channel so the response-side goroutine's pending Next unblocks with the
	// corresponding error. HTTP/2 channel.Close emits RST_STREAM(CANCEL) +
	// delivers a StreamError via errCh + closes the recv queue, causing
	// upstreamToClient's Next to return promptly. HTTP/1.x Channel.Close is a
	// no-op because its lifetime is tied to the Layer, not the exchange.
	//
	// Normal EOF (err == nil) intentionally leaves the upstream open so the
	// in-flight response can finish streaming — this is critical for HTTP/1.x
	// single-request semantics, where the client half-closes after sending the
	// request and the response is still being delivered.
	defer func() {
		if err != nil && uh.ch != nil {
			_ = uh.ch.Close()
		}
	}()

	for {
		env, nerr := client.Next(ctx)
		if nerr != nil {
			if errors.Is(nerr, io.EOF) {
				return nil
			}
			return fmt.Errorf("client.Next: %w", nerr)
		}

		sc.set(env.StreamID)

		env, action, resp := p.Run(ctx, env)
		switch action {
		case pipeline.Drop:
			continue
		case pipeline.Respond:
			if serr := client.Send(ctx, resp); serr != nil {
				return fmt.Errorf("client.Send (respond): %w", serr)
			}
			continue
		}

		// Continue: forward to upstream.
		if uh.ch == nil {
			u, derr := dial(ctx, env)
			if derr != nil {
				return fmt.Errorf("dial: %w", derr)
			}
			uh.ch = u
			close(uh.ready)
		}

		if serr := uh.ch.Send(ctx, env); serr != nil {
			return fmt.Errorf("upstream.Send: %w", serr)
		}
	}
}

// upstreamToClient waits for the upstream Channel to be established, then reads
// Envelopes from it, runs them through the Pipeline, and sends them to the
// client Channel. It returns nil on io.EOF (normal termination) or if goroutine 1
// exits without establishing upstream.
func upstreamToClient(
	ctx context.Context,
	client layer.Channel,
	p *pipeline.Pipeline,
	uh *upstreamHolder,
	sc *streamCapture,
) error {
	// Wait for upstream to be established, goroutine 1 to exit, or context
	// cancellation. If goroutine 1 exits without establishing upstream
	// (e.g., all Envelopes were dropped), we return immediately.
	//
	// Priority handling: goroutine 1 closes uh.ready before uh.done, so if
	// we see uh.done we must re-check uh.ready before bailing out — the
	// select-random-choice rule means a naive select could pick uh.done even
	// when uh.ready was closed first. The outer non-blocking probe handles
	// the common fast-path where ready is already closed on entry; the
	// inner re-check handles the case where ready closes just before done
	// while we are waiting.
	select {
	case <-uh.ready:
	default:
		select {
		case <-uh.ready:
		case <-uh.done:
			// goroutine 1 may have closed ready immediately before done.
			// Re-check non-blockingly: if ready is now closed, upstream was
			// established and we must process it; otherwise bail.
			select {
			case <-uh.ready:
			default:
				return nil
			}
		case <-ctx.Done():
			return nil
		}
	}

	// Unify StreamID across the exchange. The upstream Channel generates
	// its own identifier (HTTP/2 ServerRole and ClientRole Layers each
	// allocate independent UUIDs per stream; HTTP/1.x leaves the upstream
	// Receive channel's per-request ID unset). Without this rewrite the
	// Receive flow is recorded under an identifier with no matching
	// flow.Stream — MITM analysts can no longer retrieve both halves of
	// one logical exchange from a single Stream record.
	//
	// sc is populated by clientToUpstream via sc.set on its first client
	// envelope; happens-before is enforced by streamCapture's mutex plus
	// the uh.ready close that gates this loop's entry. streamCapture is
	// set-once, so hoist the read out of the per-envelope loop.
	clientID := sc.get()

	for {
		env, err := uh.ch.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("upstream.Next: %w", err)
		}

		if clientID != "" {
			env.StreamID = clientID
		}

		env, action, _ := p.Run(ctx, env)
		if action == pipeline.Drop {
			continue
		}

		if err := client.Send(ctx, env); err != nil {
			return fmt.Errorf("client.Send: %w", err)
		}
	}
}

// lateClientErrorWatcher observes late non-EOF errors on the client Channel
// after clientToUpstream has already exited on EOF.
//
// Rationale: the client Channel's main read path can miss a RST_STREAM that
// arrives just after the request half-closed. For HTTP/2 with a GET request,
// the client sends HEADERS(endStream=true), the Channel's recv is closed by
// the assembler, and Next returns io.EOF on the session's next iteration.
// Any RST_STREAM that arrives after that point fills the Channel's errCh but
// is not observed because nobody calls Next anymore. Without this watcher,
// upstreamToClient would block on upstream.Next forever while the upstream
// server still holds the response.
//
// The watcher starts after uh.done and stops when upstreamDone fires or the
// session context is cancelled. It polls client.Next with a short interval
// so that Next drains a filled errCh on any subsequent iteration. On a
// non-EOF error it closes the upstream Channel (HTTP/2: RST_STREAM(CANCEL)
// + errCh delivery + recv close) and returns the wrapped error, so the
// errgroup classifies the session as an error result and OnComplete can
// surface the StreamError for MITM classification.
//
// See USK-616.
func lateClientErrorWatcher(
	ctx context.Context,
	client layer.Channel,
	uh *upstreamHolder,
	upstreamDone <-chan struct{},
) error {
	// Hold until clientToUpstream finishes. Until then, the main loop owns
	// client.Next and a concurrent read would race for envelopes.
	select {
	case <-uh.done:
	case <-ctx.Done():
		return nil
	case <-upstreamDone:
		// Response side already terminated; no cascade is possible or useful.
		return nil
	}

	// No cascade needed if no upstream was ever established.
	if uh.ch == nil {
		return nil
	}

	for {
		// Stop once upstreamToClient completes (normal EOF or otherwise) —
		// a late cancel at that point is irrelevant, the session is already
		// winding down.
		select {
		case <-upstreamDone:
			return nil
		case <-ctx.Done():
			return nil
		default:
		}

		_, nerr := client.Next(ctx)
		if nerr == nil {
			// Unexpected: after client-side EOF no further envelopes should
			// arrive. Bail out rather than loop.
			return nil
		}
		if errors.Is(nerr, io.EOF) {
			// Still EOF; no late error yet. Brief wait then retry, or exit
			// early if the response side or session context is done.
			select {
			case <-upstreamDone:
				return nil
			case <-ctx.Done():
				return nil
			case <-time.After(lateErrorPollInterval):
			}
			continue
		}
		// Non-EOF error observed after client-side EOF (late cancel).
		// Close upstream to propagate the cancel to the response side, and
		// return the error so g.Wait classifies the session result.
		_ = uh.ch.Close()
		return fmt.Errorf("client late cancel: %w", nerr)
	}
}

// lateErrorPollInterval controls how often lateClientErrorWatcher polls
// client.Next for a late stream-level error after the client has
// half-closed. Chosen to balance latency-to-detect against CPU overhead.
const lateErrorPollInterval = 5 * time.Millisecond
