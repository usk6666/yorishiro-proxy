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

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
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
func RunSession(ctx context.Context, client layer.Channel, dial DialFunc, p *pipeline.Pipeline, opts ...SessionOptions) (retErr error) {
	// Cleanup is conditional: when the session exits with ErrUpgradePending
	// the caller (RunStackSession) needs the underlying wires alive so it
	// can DetachStream and construct the post-upgrade Layer. A normal exit
	// closes both wires.
	defer func() {
		if errors.Is(retErr, ErrUpgradePending) {
			return
		}
		_ = client.Close()
	}()

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
		if errors.Is(retErr, ErrUpgradePending) {
			return
		}
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

	// On upgrade, expose the still-live upstream Channel via the session's
	// notice helper so RunStackSession can construct the post-upgrade Layer
	// without re-dialing.
	if errors.Is(result, ErrUpgradePending) {
		if notice := UpgradeNoticeFromContext(origCtx); notice != nil {
			notice.attachUpstream(uh.ch)
		}
	}

	if opt.OnComplete != nil {
		opt.OnComplete(context.WithoutCancel(origCtx), sc.get(), result)
	}

	return result
}

// RunStackSession is the upgrade-aware entry point. It wraps RunSession in
// a restart loop that detects HTTP→WebSocket Upgrade or HTTP→SSE response
// envelopes via UpgradeStep + UpgradeNotice (plumbed through ctx), drains
// both session goroutines via ErrUpgradePending, swaps the topmost client
// and/or upstream Layer on the supplied ConnectionStack, and recursively
// re-runs the session on the new Channels.
//
// The recursion depth is bounded by 2 (HTTP → WS, no further upgrades) per
// RFC-001 N7. After the recursive call returns a non-ErrUpgradePending
// error, the caller's OnComplete fires exactly once with the terminal
// result — the first session's OnComplete invocation is suppressed (it
// would carry ErrUpgradePending which is not a user-visible error).
//
// Friction 2-C strict ordering preserved (per design review R4):
//  1. clientToUpstream forwards the request to upstream.
//  2. upstreamToClient receives 101, runs Pipeline (UpgradeStep flips notice).
//  3. upstreamToClient forwards 101 to client (must succeed before swap).
//  4. upstreamToClient returns ErrUpgradePending.
//  5. errgroup ctx cancels clientToUpstream which also returns ErrUpgradePending.
//  6. RunSession returns ErrUpgradePending; this function takes over.
//  7. DetachStream on both sides (or only upstream for SSE).
//  8. Construct new Layer(s); call ReplaceClientTop / ReplaceUpstreamTop.
//  9. Recursively call RunStackSession on the new Channel(s).
//
// Type-assertion guard (R19): WS upgrade requires *http1.Layer on the
// client side. A non-http1 topmost surfaces a wrapped error.
//
// Production OnStack wiring is downstream of this issue (R20); existing
// tests using RunSession directly remain unchanged.
func RunStackSession(
	ctx context.Context,
	stack *connector.ConnectionStack,
	dial DialFunc,
	p *pipeline.Pipeline,
	opts ...SessionOptions,
) error {
	if stack == nil {
		return errors.New("session: RunStackSession requires non-nil ConnectionStack")
	}

	var userOpt SessionOptions
	if len(opts) > 0 {
		userOpt = opts[0]
	}

	clientTop := stack.ClientTopmost()
	if clientTop == nil {
		return errors.New("session: ConnectionStack has no client topmost layer")
	}

	// The first session reads from the current client topmost Layer's
	// Channel. We range-receive the (possibly already-buffered) Channel
	// out of the Layer.
	clientCh, ok := <-clientTop.Channels()
	if !ok || clientCh == nil {
		return errors.New("session: client topmost layer produced no Channel")
	}

	notice := &UpgradeNotice{}
	sessCtx := WithUpgradeNotice(ctx, notice)

	// Wrap user OnComplete: suppress the first session's callback when it
	// fires with ErrUpgradePending, otherwise pass through.
	wrapped := SessionOptions{
		OnComplete: func(cbCtx context.Context, streamID string, err error) {
			if errors.Is(err, ErrUpgradePending) {
				return
			}
			if userOpt.OnComplete != nil {
				userOpt.OnComplete(cbCtx, streamID, err)
			}
		},
	}

	err := RunSession(sessCtx, clientCh, dial, p, wrapped)
	if !errors.Is(err, ErrUpgradePending) {
		return err
	}

	// Upgrade detected. Acquire the still-live upstream Channel from the
	// notice (RunSession parked it before the OnComplete suppression).
	upstreamCh := notice.Upstream()
	if upstreamCh == nil {
		return errors.New("session: upgrade pending but upstream Channel was never established")
	}

	switch notice.Pending() {
	case UpgradeWS:
		return runUpgradeWS(ctx, stack, dial, p, userOpt, upstreamCh)
	case UpgradeSSE:
		return runUpgradeSSE(ctx, stack, dial, p, userOpt, upstreamCh, notice.SSEFirstResponse())
	default:
		// ErrUpgradePending without a kind set is a logic bug; surface it
		// rather than silently looping.
		return errors.New("session: ErrUpgradePending observed but UpgradeNotice.Pending() is empty")
	}
}

// runUpgradeWS performs the WS-side swap: detach both the client and
// upstream HTTP/1.x Layers, construct ws.Layers (RoleServer client side,
// RoleClient upstream side), install them via ReplaceClient/UpstreamTop,
// then recursively call RunStackSession with a trivial DialFunc that
// returns the pre-acquired upstream WS Channel.
func runUpgradeWS(
	ctx context.Context,
	stack *connector.ConnectionStack,
	_ DialFunc,
	p *pipeline.Pipeline,
	userOpt SessionOptions,
	upstreamCh layer.Channel,
) error {
	clientTop := stack.ClientTopmost()
	clientHTTP, ok := clientTop.(*http1.Layer)
	if !ok {
		return fmt.Errorf("session: ws upgrade requires *http1.Layer client topmost, got %T", clientTop)
	}

	upstreamTop := stack.UpstreamTopmost()
	upstreamHTTP, ok := upstreamTop.(*http1.Layer)
	if !ok {
		return fmt.Errorf("session: ws upgrade requires *http1.Layer upstream topmost, got %T", upstreamTop)
	}

	clientReader, clientWriter, clientCloser, err := clientHTTP.DetachStream()
	if err != nil {
		return fmt.Errorf("session: detach client http1: %w", err)
	}
	upReader, upWriter, upCloser, err := upstreamHTTP.DetachStream()
	if err != nil {
		return fmt.Errorf("session: detach upstream http1: %w", err)
	}

	// Hygiene: close the old http1 Layer wrappers to mark their internal
	// Channels terminated. DetachStream already transferred ownership of
	// the conn so Close is a no-op for the wire (R21).
	_ = clientHTTP.Close()
	_ = upstreamHTTP.Close()

	clientStreamID := upstreamCh.StreamID()

	clientWS := ws.New(clientReader, clientWriter, clientCloser, clientStreamID, ws.RoleServer)
	upstreamWS := ws.New(upReader, upWriter, upCloser, clientStreamID, ws.RoleClient)

	stack.ReplaceClientTop(clientWS)
	stack.ReplaceUpstreamTop(upstreamWS)

	// Pull the upstream WS Channel up-front so the recursive dial returns
	// it without blocking on Channels() inside RunSession's goroutine.
	upstreamWSCh, ok := <-upstreamWS.Channels()
	if !ok || upstreamWSCh == nil {
		return errors.New("session: upstream ws layer produced no Channel")
	}
	upgradeDial := DialFunc(func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return upstreamWSCh, nil
	})

	return RunStackSession(ctx, stack, upgradeDial, p, userOpt)
}

// runUpgradeSSE performs the SSE-side swap: the upstream side is replaced
// with sse.Wrap (adapter wrapping the SSE Channel) and the post-swap
// session loop is driven directly here rather than via a recursive
// RunSession. SSE is half-duplex (server→client) so there is no client→
// upstream traffic to plumb; only the SSE event stream from upstream
// needs to flow through the Pipeline (for recording) AND onto the client
// wire (for the browser).
//
// firstResp is the actual response envelope captured by UpgradeStep at
// detection time. When non-nil, it provides real Context (TLS / ConnID)
// and headers to sse.Wrap, and the wrapper is constructed with
// WithSkipFirstEmit so we do not double-record the response that the
// pre-swap Pipeline already projected. When nil (test paths exercising
// runUpgradeSSE directly), a minimal placeholder is synthesized.
//
// The upstream HTTP/1.x Layer must have been built with
// http1.WithStreamingResponseDetect(http1.IsSSEResponse) (USK-655) so the
// streaming response body did not get drained at parse time. The body
// reader is then claimed via Layer.DetachStreamingBody.
//
// Wire-forwarding is performed via io.TeeReader: as sse.Wrap reads the
// upstream body bytes for parsing, the same bytes are written to the
// client wire (the underlying writer of the client http1 Layer, claimed
// via DetachStream). This is what activates the full chain for SSE
// (USK-657 deliverable) — without it the recursive session would record
// events but the browser would never see them.
func runUpgradeSSE(
	ctx context.Context,
	stack *connector.ConnectionStack,
	_ DialFunc,
	p *pipeline.Pipeline,
	userOpt SessionOptions,
	upstreamCh layer.Channel,
	firstResp *envelope.Envelope,
) (retErr error) {
	upstreamTop := stack.UpstreamTopmost()
	upstreamHTTP, ok := upstreamTop.(*http1.Layer)
	if !ok {
		return fmt.Errorf("session: sse upgrade requires *http1.Layer upstream topmost, got %T", upstreamTop)
	}

	clientTop := stack.ClientTopmost()
	clientHTTP, ok := clientTop.(*http1.Layer)
	if !ok {
		return fmt.Errorf("session: sse upgrade requires *http1.Layer client topmost, got %T", clientTop)
	}

	// Streaming-body detach: the http1 channel suppressed body draining
	// for the SSE response (predicate matched), so the body is still
	// pending on the wire. Hand it to sse.Wrap.
	upBody, err := upstreamHTTP.DetachStreamingBody()
	if err != nil {
		return fmt.Errorf("session: detach upstream http1 streaming body (sse): %w", err)
	}
	// Close is a no-op for the conn after detach (ownership transferred
	// to upBody); kept for parity with the WS path so any observer parked
	// on the inner Channel's Closed() unblocks.
	_ = upstreamHTTP.Close()
	defer func() { _ = upBody.Close() }()

	// Detach the client conn writer so post-swap SSE event bytes can be
	// forwarded to the browser. DetachStream transfers ownership of the
	// conn closer; clientHTTP.Close becomes a no-op for the wire (R21).
	_, clientWriter, clientCloser, err := clientHTTP.DetachStream()
	if err != nil {
		return fmt.Errorf("session: detach client http1 (sse): %w", err)
	}
	_ = clientHTTP.Close()
	defer func() { _ = clientCloser.Close() }()

	wrapOpts := []sse.Option{}
	if firstResp == nil {
		// Test path: synthesize a minimal placeholder. Production reaches
		// here via UpgradeStep so firstResp is always non-nil there.
		firstResp = &envelope.Envelope{
			StreamID:  upstreamCh.StreamID(),
			Direction: envelope.Receive,
			Protocol:  envelope.ProtocolHTTP,
			Message: &envelope.HTTPMessage{
				Status:  200,
				Headers: []envelope.KeyValue{{Name: "Content-Type", Value: "text/event-stream"}},
			},
		}
	} else {
		// Production path: the response was already recorded pre-swap;
		// suppress the duplicate emit so the analyst sees one Receive
		// flow per HTTP response, not two.
		wrapOpts = append(wrapOpts, sse.WithSkipFirstEmit())
	}

	// io.TeeReader: every byte that sse.Wrap reads for parsing is also
	// written to the client wire. The browser sees a continuous SSE
	// stream (200 OK headers from pre-swap + event bytes from here).
	teedBody := io.TeeReader(upBody, clientWriter)

	sseCh := sse.Wrap(upstreamCh, firstResp, teedBody, wrapOpts...)
	adapter := newSSELayerAdapter(sseCh)
	stack.ReplaceUpstreamTop(adapter)

	// Use the unified streamID from firstResp so OnComplete and the
	// SSE event flows recorded by Pipeline all line up under the same
	// flow.Stream the GET created.
	streamID := firstResp.StreamID

	defer func() {
		if errors.Is(retErr, ErrUpgradePending) {
			// Defensive: SSE has no nested upgrade. If we ever propagate
			// ErrUpgradePending it would be a logic bug and should not
			// surface to userOpt.OnComplete, which expects a terminal
			// session result.
			return
		}
		if userOpt.OnComplete != nil {
			userOpt.OnComplete(context.WithoutCancel(ctx), streamID, retErr)
		}
	}()

	// Manual session loop. SSE is server→client only, so there is no
	// clientToUpstream goroutine; we drive sseCh.Next directly and the
	// Pipeline records each event. Wire forwarding is handled by the
	// io.TeeReader above.
	for {
		env, nerr := sseCh.Next(ctx)
		if nerr != nil {
			if errors.Is(nerr, io.EOF) {
				return nil
			}
			return nerr
		}
		if env == nil {
			continue
		}
		_, _, _ = p.Run(ctx, env)
	}
}

// upgradePending returns true when notice has latched a pending UpgradeKind.
// Centralised so the goroutines can express "exit cleanly for upgrade swap"
// without re-implementing the nil-guard at every call site.
func upgradePending(notice *UpgradeNotice) bool {
	return notice != nil && notice.Pending() != ""
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
	// Cascade-close discipline (feedback_session_cascade_pattern.md):
	//   * Genuine err → close upstream so peer goroutine unblocks promptly.
	//   * Normal EOF (err == nil) → leave open; the response may still arrive.
	//   * ErrUpgradePending → leave open; RunStackSession owns the wire.
	defer func() {
		if err == nil || errors.Is(err, ErrUpgradePending) || uh.ch == nil {
			return
		}
		_ = uh.ch.Close()
	}()

	notice := UpgradeNoticeFromContext(ctx)

	for {
		env, nerr := client.Next(ctx)
		if nerr != nil {
			// Upgrade-pending takes precedence over EOF/errors: when the
			// peer goroutine latched a Pending UpgradeKind, the only
			// correct exit code is ErrUpgradePending so RunStackSession
			// can run the swap. Otherwise a client half-close (the SSE
			// case where the browser sends FIN after the GET, or the WS
			// case where the client conn closes on Upgrade) would silently
			// degrade to a normal "session ended" return and the swap
			// would never run.
			if upgradePending(notice) {
				return ErrUpgradePending
			}
			if errors.Is(nerr, io.EOF) {
				return nil
			}
			return fmt.Errorf("client.Next: %w", nerr)
		}

		sc.set(env.StreamID)

		env, action, resp := runPipelineTracked(ctx, p, env, reg)
		if perr := dispatchClientAction(ctx, client, uh, dial, env, resp, action); perr != nil {
			return perr
		}
		// UpgradeStep may have flipped the notice during Pipeline.Run or
		// the receive-side goroutine may have flipped it concurrently.
		if upgradePending(notice) {
			return ErrUpgradePending
		}
	}
}

// dispatchClientAction performs the post-Pipeline action on a client-side
// envelope: Drop, Respond (client.Send), or Continue (upstream.Send). It
// also handles the lazy dial-and-publish on first forwarded envelope.
//
// Returning a non-nil error terminates clientToUpstream; returning nil
// loops to the next iteration. The "should I exit for upgrade?" check
// stays in the caller because it must run AFTER this returns nil so the
// final envelope (the WS upgrade request) reaches upstream first
// (Friction 2-C).
func dispatchClientAction(
	ctx context.Context,
	client layer.Channel,
	uh *upstreamHolder,
	dial DialFunc,
	env *envelope.Envelope,
	resp *envelope.Envelope,
	action pipeline.Action,
) error {
	switch action {
	case pipeline.Drop:
		return nil
	case pipeline.Respond:
		if serr := client.Send(ctx, resp); serr != nil {
			return fmt.Errorf("client.Send (respond): %w", serr)
		}
		return nil
	}

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
	return nil
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
	if !waitUpstreamReady(ctx, uh) {
		return nil
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

	notice := UpgradeNoticeFromContext(ctx)

	for {
		env, err := upstreamNext(ctx, uh.ch, notice)
		if err != nil {
			return err
		}
		if env == nil {
			// Normal EOF.
			return nil
		}

		if clientID != "" {
			env.StreamID = clientID
		}

		env, action, _ := runPipelineTracked(ctx, p, env, reg)
		if action == pipeline.Drop {
			if upgradePending(notice) {
				return ErrUpgradePending
			}
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

		// Friction 2-C strict ordering: the 101 response (or first SSE
		// event-stream response) MUST be delivered to the client BEFORE
		// the goroutine exits. After Send returns we are safe to surface
		// ErrUpgradePending so the errgroup ctx cancels the peer
		// goroutine and RunStackSession can reclaim both wires.
		if upgradePending(notice) {
			return ErrUpgradePending
		}
	}
}

// waitUpstreamReady blocks until the client-to-upstream goroutine has
// established the upstream Channel (uh.ready closes), or it exits without
// establishing one (uh.done closes), or ctx is cancelled. Returns true
// when upstream is ready and the loop should proceed; false when the loop
// should return nil immediately.
//
// Priority handling: goroutine 1 closes uh.ready before uh.done, so if we
// see uh.done we must re-check uh.ready before bailing out — the
// select-random-choice rule means a naive select could pick uh.done even
// when uh.ready was closed first. The outer non-blocking probe handles
// the common fast-path where ready is already closed on entry; the inner
// re-check handles the case where ready closes just before done while we
// are waiting.
func waitUpstreamReady(ctx context.Context, uh *upstreamHolder) bool {
	select {
	case <-uh.ready:
		return true
	default:
	}
	select {
	case <-uh.ready:
		return true
	case <-uh.done:
		select {
		case <-uh.ready:
			return true
		default:
			return false
		}
	case <-ctx.Done():
		return false
	}
}

// upstreamNext encapsulates the read-from-upstream + EOF / upgrade-pending /
// other-error classification. Returns:
//
//	(env, nil)   — successful read; caller proceeds.
//	(nil, nil)   — normal EOF; caller returns nil.
//	(nil, err)   — wrap-and-return; either ErrUpgradePending or wrapped err.
func upstreamNext(ctx context.Context, ch layer.Channel, notice *UpgradeNotice) (*envelope.Envelope, error) {
	env, err := ch.Next(ctx)
	if err == nil {
		return env, nil
	}
	if errors.Is(err, io.EOF) {
		return nil, nil
	}
	if upgradePending(notice) {
		return nil, ErrUpgradePending
	}
	return nil, fmt.Errorf("upstream.Next: %w", err)
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
