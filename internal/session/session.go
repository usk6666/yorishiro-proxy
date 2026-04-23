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

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
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

// bodyBufRegistry owns the BodyBuffer references a session accumulates via
// variant-snapshot Retains inside Pipeline.Run, and Releases them in a single
// drain after both session goroutines exit.
//
// Ownership model. For every non-nil HTTPMessage.BodyBuffer entering
// Pipeline.Run, Envelope.Clone invokes HTTPMessage.CloneMessage which calls
// BodyBuffer.Retain — the snapshot stored in ctx thereby holds one extra
// reference. The snapshot is reachable only through that ctx, which goes out
// of scope when Run returns; Go's GC can reclaim the snapshot struct but will
// never decrement the refcount, so the backing temp file would leak.
// bodyBufRegistry captures the pre-Run pointer into a session-scoped slice and
// issues one Release per slot at session end, matching the one Retain per Run.
//
// The registry never dedupes: two Retains demand two Releases, so appending
// duplicate pointers is correct when two different envelopes happen to share
// the same buffer pointer (not a current scenario but a safe default).
// Release errors from os.Remove surface only the filesystem-level failure
// and are ignored — the bodybuf teardown already logs inconsistencies, and a
// Release error must not override the session's primary result.
type bodyBufRegistry struct {
	mu   sync.Mutex
	bufs []*bodybuf.BodyBuffer
}

// track records a BodyBuffer pointer for terminal Release. A nil pointer is a
// no-op so callers can forward extracted fields unconditionally.
func (r *bodyBufRegistry) track(b *bodybuf.BodyBuffer) {
	if b == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bufs = append(r.bufs, b)
}

// trackEnvelope tracks the BodyBuffer carried by env if env is HTTP-typed.
// Non-HTTP envelopes (Raw, WS, gRPC, etc.) have no BodyBuffer and are skipped.
//
// Contract for callers that synthesize Respond-path envelopes (rules,
// plugins, safety Steps): the response Envelope's HTTPMessage.BodyBuffer MUST
// be a distinct pointer from the request's, OR the synthesizer must issue
// an extra Retain to match the extra Release that this registry will later
// issue. Aliasing without a compensating Retain would cause drain() to
// double-Release the shared pointer, panicking on the zero-refcount contract
// of bodybuf.Release. No current Step aliases, and the panic is fail-loud
// rather than fail-silent, so regressions surface immediately.
func (r *bodyBufRegistry) trackEnvelope(env *envelope.Envelope) {
	if env == nil || env.Message == nil {
		return
	}
	if m, ok := env.Message.(*envelope.HTTPMessage); ok && m != nil {
		r.track(m.BodyBuffer)
	}
}

// drain releases all tracked buffers and clears the backing slice. Safe to
// call multiple times; subsequent calls are no-ops.
func (r *bodyBufRegistry) drain() {
	r.mu.Lock()
	bufs := r.bufs
	r.bufs = nil
	r.mu.Unlock()
	for _, b := range bufs {
		_ = b.Release()
	}
}

// runPipelineTracked runs p on env and registers the buffer refcounts that
// the session backstop must Release at drain time.
//
// Refcount accounting (USK-635 follow-up to USK-634):
// Every disk-backed HTTP body arrives with two outstanding Retains that the
// session is responsible for releasing at end of session:
//
//  1. The Layer-owned Retain from bodybuf.NewFile at parse time. The downstream
//     channel.Send reads the buffer to emit wire bytes but does NOT Release
//     (the buffer is immutable wire source for zero-copy fidelity). For the
//     Drop / Respond / DialFailure paths the buffer is never Sent, so nothing
//     consumes this Retain either. The session backstop therefore owns it —
//     EXCEPT on the Transform commit path, where TransformReplaceBody calls
//     msg.BodyBuffer.Release() + msg.BodyBuffer = nil to swap in the rewritten
//     bytes. We detect that case via pointer identity: if post-Run
//     msg.BodyBuffer is nil (or different from pre), Transform already
//     cancelled the Layer Retain and the backstop must not.
//
//  2. The Pipeline.Run variant-snapshot Retain from HTTPMessage.CloneMessage.
//     The snapshot lives only inside the ctx threaded into Run; when Run
//     returns the ctx goes out of scope and Go's GC can reclaim the snapshot
//     struct, but the BodyBuffer's refcount never decrements automatically.
//     The backstop always owns this Retain (one per Pipeline.Run invocation
//     with a non-nil pre-Run BodyBuffer).
//
// For the synthetic resp envelope on the Respond path: its BodyBuffer (if
// any) was not traversed by Pipeline.Run so it holds only the Layer Retain
// — one track is enough. No current Step populates resp.Message.BodyBuffer
// but the pre-emptive track prevents a future Step from introducing a leak.
//
// Panic safety: a Step panic inside p.Run unwinds through this function
// without reaching the post-Run reg.track calls. This is intentional —
// errgroup (golang.org/x/sync/errgroup v0.19.0) does not recover panics, so
// a Step panic terminates the process. Any deferred registration at this
// layer would not run either (the process dies before RunSession's
// defer reg.drain() executes). Temp-file cleanup on process crash falls to
// the startup orphan sweep in config.SweepOrphanBodyFiles.
func runPipelineTracked(
	ctx context.Context,
	p *pipeline.Pipeline,
	env *envelope.Envelope,
	reg *bodyBufRegistry,
) (*envelope.Envelope, pipeline.Action, *envelope.Envelope) {
	var pre *bodybuf.BodyBuffer
	if env != nil && env.Message != nil {
		if m, ok := env.Message.(*envelope.HTTPMessage); ok && m != nil {
			pre = m.BodyBuffer
		}
	}

	outEnv, action, resp := p.Run(ctx, env)

	if pre != nil {
		// Always register the Pipeline snapshot Retain (Clone added one).
		reg.track(pre)
		// Additionally register the Layer Retain unless Transform's commit
		// path already Released it. Transform sets msg.BodyBuffer=nil; any
		// other outcome (nil pre, pointer unchanged) means the Layer Retain
		// is still outstanding and the backstop owns it.
		if m, ok := outEnv.Message.(*envelope.HTTPMessage); ok && m != nil && m.BodyBuffer == pre {
			reg.track(pre)
		}
	}
	if action == pipeline.Respond {
		reg.trackEnvelope(resp)
	}

	return outEnv, action, resp
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

// ClassifyError returns the canonical label for a stream-level error if err
// wraps a *layer.StreamError, or the empty string otherwise. Callers wire
// the result into flow.StreamUpdate.FailureReason from OnComplete so that
// analysts can distinguish GOAWAY-refused streams from cancels and protocol
// errors in recordings.
//
// Values mirror layer.ErrorCode.String(): "canceled", "aborted",
// "internal_error", "refused", "protocol_error".
//
// Non-StreamError failures (context cancellation, dial errors, pipeline
// errors) intentionally return the empty string. FailureReason reflects a
// wire-observed protocol signal, not local control-flow.
func ClassifyError(err error) string {
	if err == nil {
		return ""
	}
	var se *layer.StreamError
	if errors.As(err, &se) && se != nil {
		return se.Code.String()
	}
	return ""
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

	// Backstop for BodyBuffer references that Pipeline.Run's variant-snapshot
	// Clone retained. Drained after g.Wait() returns and after OnComplete, so
	// post-session hooks can still materialize bodies via BodyBuffer.Bytes.
	reg := &bodyBufRegistry{}
	defer reg.drain()

	// upstreamDone is closed by upstreamToClient on exit. The late-error
	// watcher uses this to stop polling once the response side has already
	// finished (whether normally or due to an error).
	upstreamDone := make(chan struct{})

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer close(uh.done)
		return clientToUpstream(ctx, client, dial, p, uh, sc, reg)
	})

	g.Go(func() error {
		defer close(upstreamDone)
		return upstreamToClient(ctx, client, p, uh, sc, reg)
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
	reg *bodyBufRegistry,
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

		env, action, resp := runPipelineTracked(ctx, p, env, reg)
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
	reg *bodyBufRegistry,
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

		env, action, _ := runPipelineTracked(ctx, p, env, reg)
		if action == pipeline.Drop {
			continue
		}

		// USK-623: synthetic PUSH_PROMISE envelopes are delivered by the
		// HTTP/2 upstream Layer onto the origin stream for observability
		// (so the origin stream's recording shows that a push was
		// promised). They carry request-shaped HTTPMessage fields
		// (Method/Path/Authority) but no :status, so forwarding to the
		// client Layer would emit a malformed response. The MITM default
		// posture is to terminate push at the proxy: the pushed stream
		// itself is recorded independently via the upstream push recorder
		// (see internal/pushrecorder/push_recorder.go).
		if m, ok := env.Message.(*envelope.HTTPMessage); ok && envelope.HasPushPromiseAnomaly(m) {
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
// Any RST_STREAM that arrives after that point is stored on the Channel
// but is not observed because nobody calls Next anymore. Without this
// watcher, upstreamToClient would block on upstream.Next forever while the
// upstream server still holds the response.
//
// The watcher starts after uh.done and waits on the Channel's Closed
// signal. Implementations populate the terminal error (Err) before closing
// the signal, so when Closed fires a non-EOF value from Err indicates a
// late abnormal event. On such an error the watcher closes the upstream
// Channel (HTTP/2: RST_STREAM(CANCEL)) and returns the wrapped error so
// the errgroup classifies the session as an error result and OnComplete
// can surface the StreamError for MITM classification.
//
// See USK-616, USK-625.
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

	select {
	case <-client.Closed():
		if err := client.Err(); err != nil && !errors.Is(err, io.EOF) {
			// Late abnormal event (e.g., RST_STREAM) arrived after the
			// client's recv half-closed. Propagate the cancel to the
			// response side and surface the error for classification.
			_ = uh.ch.Close()
			return fmt.Errorf("client late cancel: %w", err)
		}
		return nil
	case <-upstreamDone:
		return nil
	case <-ctx.Done():
		return nil
	}
}
