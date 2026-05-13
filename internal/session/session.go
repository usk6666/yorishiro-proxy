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
	"log/slog"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
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

	// LifecycleEngine, when non-nil, is the pluginv2 Engine that
	// upgrade-time Layer constructors (currently runUpgradeWS) attach via
	// WithLifecycleEngine so terminal-event hooks (ws.on_close) fire from
	// the post-Upgrade Layer. SessionOptions is the canonical session-scope
	// plumbing channel for this kind of cross-Layer wiring; threading it
	// through SessionOptions avoids growing connector.BuildConfig with
	// session-only fields.
	LifecycleEngine *pluginv2.Engine

	// StateReleaser, when non-nil, is the pluginv2 StateReleaser that
	// upgrade-time Layer constructors attach via WithStateReleaser so the
	// new Layer releases per-transaction / per-stream scoped state at its
	// own terminal events. *pluginv2.Engine satisfies this interface, so
	// callers typically populate both LifecycleEngine and StateReleaser
	// with the same engine pointer.
	StateReleaser pluginv2.StateReleaser

	// OnPipelineDrop, when non-nil, is invoked once per Pipeline.Run that
	// returned Action=Drop with a non-empty BlockedBy attribution. The
	// session calls this AFTER it has skipped wire forwarding, so the
	// callback runs while the session goroutines are still scheduled —
	// store writes complete before the session terminates.
	//
	// Production wiring (proxybuild.buildPipelineDropRecorder) writes a
	// flow.Stream with State="error" and BlockedBy=blockedBy. The
	// callback is not consulted for the capture_scope filter (USK-776):
	// blocked envelopes are always recorded regardless of scope, which
	// is the AC #3 deferral that USK-782 closes.
	//
	// env is the (possibly Pipeline-mutated) Envelope that was Dropped.
	// Implementations must not retain env beyond the call — its Message
	// may share BodyBuffer references with the snapshot held by the
	// bodyBufRegistry.
	OnPipelineDrop func(ctx context.Context, env *envelope.Envelope, blockedBy string)

	// WSMaxFrameSize, when positive, is the per-frame WebSocket payload cap
	// applied to the post-Upgrade *ws.Layer pair on both client- and
	// upstream-facing sides. Zero falls back to the layer default
	// (config.MaxWebSocketFrameSize, 16 MiB). Bridged from
	// connector.BuildConfig.WSMaxFrameSize by proxybuild.buildSessionOptions.
	// USK-806.
	WSMaxFrameSize int64

	// SSEMaxEventSize, when positive, caps the per-event raw byte size on the
	// post-Upgrade SSE Channel built by sse.Wrap. Zero falls back to the
	// layer default (config.MaxSSEEventSize, 1 MiB). Bridged from
	// connector.BuildConfig.SSEMaxEventSize by proxybuild.buildSessionOptions.
	// USK-806.
	SSEMaxEventSize int

	// InterceptReleaseTracker, when non-nil, records the timestamps the MCP
	// intercept tool's Release path stamps each time a held envelope is
	// unblocked. The session relay loops query the tracker on EOF and, when
	// a recent release on the opposite Direction is found within
	// InterceptReleaseEOFWindow, invoke OnInterceptReleaseEOF so the
	// operator-facing Stream tag can be appended.
	//
	// Plumbing is fire-and-forget: a missing tracker (nil) disables the
	// USK-851 detection without affecting wire behaviour.
	InterceptReleaseTracker *common.ReleaseTracker

	// InterceptReleaseEOFWindow is the correlation window applied to
	// InterceptReleaseTracker lookups. Zero falls back to a 2-second
	// hard-coded default — see USK-851 design review decision U3. The
	// window is intentionally NOT exposed as configuration in this Issue;
	// changing it is a follow-up (approach B) tracked under the same Issue
	// thread.
	InterceptReleaseEOFWindow time.Duration

	// OnInterceptReleaseEOF, when non-nil, is invoked once per Stream when
	// a relay goroutine observes EOF on src.Next within
	// InterceptReleaseEOFWindow of a recent release on the OPPOSITE
	// Direction. Production wiring (proxybuild) appends the Stream tag
	// "intercept_hold_outcome=upstream_closed_after_intercept_release"
	// via flow.Store.UpdateStream so operators querying
	// `resource=stream id=<…>` see the diagnostic without trawling logs.
	//
	// The callback fires AT MOST ONCE per Stream — the relay loop uses
	// ReleaseTracker.LookupAndForgetOpposite, which atomically performs
	// the lookup and entry-clear under the tracker's mutex, so even when
	// both relay goroutines observe EOF concurrently only one observation
	// finds the opposite-direction release. Empty streamID is filtered by
	// the relay before invocation.
	//
	// Implementations must not block the relay goroutine; the production
	// recorder writes asynchronously via the store's single-writer queue.
	OnInterceptReleaseEOF func(ctx context.Context, streamID string)

	// InterceptHoldTracker, when non-nil, is the shared HoldTracker that
	// InterceptStep stamps on hold-enter / hold-exit. The session relay
	// goroutines query it on each USK-854 keepalive tick to learn whether
	// a hold is still in flight. A nil tracker disables the keepalive
	// injection entirely (the only effect is that WSHoldKeepaliveEnabled
	// has no observable behaviour).
	InterceptHoldTracker *common.HoldTracker

	// WSHoldKeepaliveEnabled toggles the USK-854 synthetic WS Ping
	// injection during a hold. Default false: keepalive is opt-in because
	// Ping injection is wire-observable. Resolved from
	// ProxyConfig.WebSocket.HoldKeepaliveEnabled (USK-799 precedent: wire
	// caps on ProxyConfig per-protocol section, not in a top-level
	// intercept namespace).
	WSHoldKeepaliveEnabled bool

	// WSHoldKeepaliveInterval is the cadence at which the keepalive
	// goroutine emits synthetic Ping frames while a hold is in flight.
	// Zero falls back to config.DefaultWSHoldKeepaliveInterval (5s).
	WSHoldKeepaliveInterval time.Duration

	// PluginEngine, when non-nil, is the pluginv2 Engine consulted by the
	// USK-854 keepalive goroutine for the per-Stream opt-out. A plugin
	// sets ctx.stream_state["ws_hold_keepalive"] = False from a
	// (ws, on_upgrade, pre) hook to suppress injection on a specific
	// Stream without disabling the global config knob. Distinct from
	// LifecycleEngine semantically — both fields typically point at the
	// same *pluginv2.Engine in production.
	PluginEngine *pluginv2.Engine
}

// interceptReleaseEOFDefaultWindow is the canonical correlation window for
// the USK-851 detection rule. Exported so tests can mirror the production
// constant without redefining it.
const interceptReleaseEOFDefaultWindow = 2 * time.Second

// checkInterceptReleaseEOF inspects InterceptReleaseTracker for a recent
// release on the OPPOSITE direction of dir and, on a hit within the
// configured window, invokes OnInterceptReleaseEOF. The lookup-and-clear
// is performed atomically via LookupAndForgetOpposite, so even when both
// relay goroutines observe EOF concurrently the callback fires at most
// once per Stream.
//
// streamID == "" or InterceptReleaseTracker == nil short-circuits to a
// no-op — keeps callers free of nil checks at each EOF site.
//
// USK-860: the oppositeRelayed argument tells the helper whether the
// relay loop in the OPPOSITE direction successfully forwarded at least
// one envelope between the matching release and this EOF. When true, the
// callback is suppressed because the post-release wire conversation
// completed normally (e.g. a request was modify_and_forwarded, the
// upstream answered with a 200 OK that the proxy fully relayed back, and
// the upstream then closed cleanly with Connection: close). The
// LookupAndForgetOpposite call is still issued so the tracker entry is
// cleared — only the callback firing is gated. The cleared tracker entry
// preserves "at most once" semantics for any subsequent EOF on the
// peer relay goroutine (which would otherwise observe the same release
// timestamp).
func checkInterceptReleaseEOF(ctx context.Context, opt SessionOptions, streamID string, dir envelope.Direction, oppositeRelayed bool) {
	if streamID == "" || opt.InterceptReleaseTracker == nil || opt.OnInterceptReleaseEOF == nil {
		return
	}
	window := opt.InterceptReleaseEOFWindow
	if window <= 0 {
		window = interceptReleaseEOFDefaultWindow
	}
	if _, ok := opt.InterceptReleaseTracker.LookupAndForgetOpposite(streamID, dir, time.Now(), window); !ok {
		return
	}
	if oppositeRelayed {
		// The matching release was followed by a successful opposite-
		// direction relay; the EOF here is the normal end of conversation,
		// not the "long-held frame caused upstream half-close" symptom the
		// tag describes. Suppress the callback while still letting the
		// lookup-and-forget above clear the tracker entry.
		return
	}
	opt.OnInterceptReleaseEOF(ctx, streamID)
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

// trackEnvelope tracks the BodyBuffer carried by env if env is HTTP-typed,
// plus env.RawBuffer (USK-772) when populated by the HTTP/1.x parser's
// disk-spill path. Non-HTTP envelopes have no BodyBuffer; pre-USK-772
// envelopes have no RawBuffer.
//
// Contract for callers that synthesize Respond-path envelopes (rules,
// plugins, safety Steps): the response Envelope's HTTPMessage.BodyBuffer MUST
// be a distinct pointer from the request's, OR the synthesizer must issue
// an extra Retain to match the extra Release that this registry will later
// issue. Aliasing without a compensating Retain would cause drain() to
// double-Release the shared pointer, panicking on the zero-refcount contract
// of bodybuf.Release. No current Step aliases, and the panic is fail-loud
// rather than fail-silent, so regressions surface immediately. The same
// constraint applies to env.RawBuffer.
func (r *bodyBufRegistry) trackEnvelope(env *envelope.Envelope) {
	if env == nil {
		return
	}
	if env.RawBuffer != nil {
		r.track(env.RawBuffer)
	}
	if env.Message == nil {
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
) (*envelope.Envelope, pipeline.Action, *envelope.Envelope, string) {
	var pre *bodybuf.BodyBuffer
	var preRaw *bodybuf.BodyBuffer
	if env != nil {
		preRaw = env.RawBuffer
		if env.Message != nil {
			if m, ok := env.Message.(*envelope.HTTPMessage); ok && m != nil {
				pre = m.BodyBuffer
			}
		}
	}

	outEnv, action, resp, blockedBy := p.RunWithBlockedBy(ctx, env)

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
	if preRaw != nil {
		// USK-772: env.RawBuffer carries two outstanding Retains entering
		// runPipelineTracked, mirroring HTTPMessage.BodyBuffer:
		//
		//  1. The Layer-owned Retain from bodybuf.NewFile at parse time
		//     (the parser's disk-spill bodybuf is created with refCount=1
		//     and that reference is transferred to env.RawBuffer).
		//  2. The Pipeline.Run variant-snapshot Retain from Envelope.Clone
		//     (when a snapshot lives on for variant recording).
		//
		// No production Step currently mutates env.RawBuffer (unlike
		// HTTPMessage.BodyBuffer where Transform may swap it), so the Layer
		// Retain is always outstanding post-Run; we register both
		// unconditionally.
		reg.track(preRaw)
		reg.track(preRaw)
	}
	if action == pipeline.Respond {
		reg.trackEnvelope(resp)
	}

	return outEnv, action, resp, blockedBy
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
		return clientToUpstream(ctx, client, dial, p, uh, sc, reg, opt)
	})

	g.Go(func() error {
		defer close(upstreamDone)
		return upstreamToClient(ctx, client, p, uh, sc, reg, opt)
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

	return RunStackSessionExchange(ctx, stack, clientCh, dial, p, opts...)
}

// RunStackSessionExchange is the per-exchange variant of RunStackSession.
// It accepts a pre-fetched client Channel rather than pulling one from
// stack.ClientTopmost().Channels(). This is the entry point used by HTTP/1.x
// keep-alive (USK-730), where the proxybuild OnStack wiring iterates the
// client Layer's Channels() and runs one session per exchange.
//
// Upgrade orchestration is unchanged: an upgrading exchange detaches the
// client + upstream HTTP/1 Layers, swaps them with ws / sse Layers, and
// recursively calls RunStackSession (which pulls one Channel from the new
// Layer's Channels()). The recursion depth is still bounded by 2.
func RunStackSessionExchange(
	ctx context.Context,
	stack *connector.ConnectionStack,
	clientCh layer.Channel,
	dial DialFunc,
	p *pipeline.Pipeline,
	opts ...SessionOptions,
) error {
	if stack == nil {
		return errors.New("session: RunStackSessionExchange requires non-nil ConnectionStack")
	}
	if clientCh == nil {
		return errors.New("session: RunStackSessionExchange requires non-nil client Channel")
	}

	var userOpt SessionOptions
	if len(opts) > 0 {
		userOpt = opts[0]
	}

	notice := &UpgradeNotice{}
	sessCtx := WithUpgradeNotice(ctx, notice)

	// Wrap user OnComplete: suppress the first session's callback when it
	// fires with ErrUpgradePending, otherwise pass through. All other
	// SessionOptions fields are preserved verbatim so terminal-event hooks
	// (LifecycleEngine, StateReleaser) and audit hooks (OnPipelineDrop —
	// USK-782) reach RunSession unmodified.
	wrapped := userOpt
	wrapped.OnComplete = func(cbCtx context.Context, streamID string, err error) {
		if errors.Is(err, ErrUpgradePending) {
			return
		}
		if userOpt.OnComplete != nil {
			userOpt.OnComplete(cbCtx, streamID, err)
		}
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

	// USK-841 Phase A milestone (a): upgrade detected by UpgradeStep + the
	// pre-swap session has fully drained. Operators correlate this trace
	// with the symptom ("frames not recorded") by phase+streamID matching.
	// At this point notice.markSendUpgrade was seen, the 101 was observed,
	// and the first session returned ErrUpgradePending.
	clientChStreamID := ""
	if clientCh != nil {
		clientChStreamID = clientCh.StreamID()
	}
	upstreamChStreamID := upstreamCh.StreamID()
	slog.Debug("session: upgrade-pending observed by RunStackSessionExchange",
		"phase", "upgrade-detected",
		"kind", string(notice.Pending()),
		"clientStreamID", clientChStreamID,
		"upstreamStreamID", upstreamChStreamID,
	)

	switch notice.Pending() {
	case UpgradeWS:
		return runUpgradeWS(ctx, stack, dial, p, userOpt, upstreamCh, notice.WSUpgradeRequest(), notice.WSExtensionHeader())
	case UpgradeWSOverH2:
		return runUpgradeWSOverH2(ctx, stack, p, userOpt, clientCh, upstreamCh, notice.WSUpgradeRequest(), notice.WSExtensionHeader())
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
//
// upgradeReq is the WS upgrade request envelope captured by UpgradeStep
// at observation time. Its Context (ConnID / ClientAddr / TargetHost /
// TLS) and HTTPMessage (Path / RawQuery) are propagated onto the post-
// swap ws.Layer's envelope template via ws.WithEnvelopeContext so per-
// frame envelopes carry the connection-scoped metadata that
// capture_scope / capture filters key on. Without this propagation every
// WS frame envelope emerges with an empty Context and is rejected as
// out-of-scope (USK-841). nil is tolerated for the test paths that
// construct runUpgradeWS directly without going through
// RunStackSessionExchange.
//
// extensionHeader is the verbatim wire-observed value of the
// Sec-WebSocket-Extensions response header (101 Switching Protocols).
// Propagated via ws.WithDeflateFromExtensionHeader so the post-swap
// ws.Layer honors the negotiated permessage-deflate (RFC 7692)
// parameters; empty means "no extension negotiated" and the Option is a
// no-op (USK-847).
func runUpgradeWS(
	ctx context.Context,
	stack *connector.ConnectionStack,
	_ DialFunc,
	p *pipeline.Pipeline,
	userOpt SessionOptions,
	upstreamCh layer.Channel,
	upgradeReq *envelope.Envelope,
	extensionHeader string,
) error {
	clientTop := stack.ClientTopmost()
	upstreamTop := stack.UpstreamTopmost()

	// USK-841 Phase A milestone (b): runUpgradeWS was invoked. The trace
	// fires BEFORE any DetachStream call so a partial-orchestration failure
	// (wrong Layer type, missing topmost) is identifiable as "runUpgradeWS
	// reached but blocked on Layer-type assert" vs "runUpgradeWS never
	// reached".
	//
	// USK-848: upstreamStreamID is the legacy connection-level id
	// ("<connID>/upstream"); handshakeStreamID is the wire-observed per-
	// exchange UUID minted by http1.parseRequest and propagated through
	// attachWSUpgradeRequest. Both are logged so the trace makes the
	// identity unambiguous; the chosen post-swap clientStreamID is
	// resolved (and logged again) once the upgradeReq nil-fallback is
	// applied below.
	slog.Debug("session: runUpgradeWS entered",
		"phase", "runUpgradeWS-entry",
		"upstreamStreamID", upstreamCh.StreamID(),
		"handshakeStreamID", wsHandshakeStreamID(upgradeReq),
		"clientTopType", fmt.Sprintf("%T", clientTop),
		"upstreamTopType", fmt.Sprintf("%T", upstreamTop),
	)

	clientHTTP, ok := clientTop.(*http1.Layer)
	if !ok {
		return fmt.Errorf("session: ws upgrade requires *http1.Layer client topmost, got %T", clientTop)
	}

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

	// USK-848: prefer the handshake's per-exchange UUID (minted in
	// http1.parseRequest, propagated through UpgradeStep ->
	// attachWSUpgradeRequest -> notice.WSUpgradeRequest()) so the post-
	// swap WS Stream is the SAME row as the pre-swap HTTP handshake
	// Stream. RecordStep.maybeRetagProtocol then flips Stream.Protocol
	// from "http" -> "ws" exactly once (USK-781 precedent), and the
	// session's OnComplete on close finalises the unified Stream
	// (implicitly closing USK-850's "parent HTTP Stream stuck at
	// state=active"). When upgradeReq is nil (test paths that call
	// runUpgradeWS directly, bypassing UpgradeStep) we fall back to the
	// legacy connection-level id "<connID>/upstream" — preserving prior
	// behaviour for callers documented in the function comment above.
	clientStreamID := upstreamCh.StreamID()
	if id := wsHandshakeStreamID(upgradeReq); id != "" {
		clientStreamID = id
	}

	// USK-841 Phase A milestone (c): DetachStream returned on both sides.
	// The clientReader type discriminates whether the http1 capture path
	// fired (io.MultiReader = some post-Interrupt bytes were drained and
	// prepended; bare *bufio.Reader = nothing to replay). The upstreamReader
	// type is always the upstream's bufio.Reader since UpgradeStep never
	// calls PrepareSwap on the upstream side (one of the H4 hypotheses).
	// If upstreamReaderType is *bufio.Reader and the upstream had pushed
	// bytes right after 101, those bytes are sitting in bufio's buffered
	// remainder — readable by the new ws.Layer — so the only way they get
	// lost is if the buffered slice between PrepareSwap-window and
	// DetachStream is non-empty AND the http1 reader was the source. The
	// trace shows the raw type so Phase B can correlate.
	//
	// USK-848: streamID is the chosen post-swap clientStreamID (handshake
	// UUID when available, otherwise the legacy "<connID>/upstream"); the
	// raw upstreamStreamID is logged separately so a future operator can
	// still see which fallback path fired.
	slog.Debug("session: runUpgradeWS DetachStream complete",
		"phase", "runUpgradeWS-detached",
		"streamID", clientStreamID,
		"upstreamStreamID", upstreamCh.StreamID(),
		"clientReaderType", fmt.Sprintf("%T", clientReader),
		"upstreamReaderType", fmt.Sprintf("%T", upReader),
	)

	wsOpts := wsLifecycleOptions(userOpt)
	// USK-841: propagate the wire-observed EnvelopeContext from the pre-
	// swap WS Upgrade request onto the post-swap WS Layer pair. Without
	// this, every WS frame envelope emerges with empty ConnID /
	// TargetHost / TLS, and capture_scope (which keys on hostname for
	// non-HTTP envelopes via Context.TargetHost / Context.TLS.SNI) drops
	// every frame as out-of-scope. The Option is prepended so callers
	// that pass extra Options downstream of wsLifecycleOptions still take
	// precedence — wsLifecycleOptions does not carry an EnvelopeContext.
	if envCtx, ok := wsEnvelopeContextFromUpgradeReq(upgradeReq); ok {
		wsOpts = append([]ws.Option{ws.WithEnvelopeContext(envCtx)}, wsOpts...)
	}
	// USK-848: when we reuse the handshake StreamID (USK-781 precedent),
	// Sequence 0 (Send) is already occupied by the HTTP upgrade request
	// and Sequence 1 (Receive) by the 101 Switching Protocols response
	// flow records under the same StreamID. The post-swap WS Channels
	// must seed their per-direction counters past those slots so the
	// flow store's (stream_id, sequence, direction, variant) UNIQUE
	// constraint does not reject the first WS frame in either direction.
	// Same wss-over-h2 pattern at session.go:842-845 (seeded at 1 there
	// because the h2 swap has only the CONNECT request at Send/Seq=0 +
	// the 2xx response at Receive/Seq=0; h1.1 has the additional 101
	// hop). The seed is gated on the upgradeReq-fallback branch firing —
	// when we keep the legacy connection-scoped StreamID the WS Stream
	// is fresh and Sequence=0 is safe.
	if wsHandshakeStreamID(upgradeReq) != "" {
		wsOpts = append(wsOpts, ws.WithInitialSequence(2))
	}
	// USK-847: propagate the wire-observed Sec-WebSocket-Extensions
	// response header onto the post-swap WS Layer pair so the negotiated
	// permessage-deflate (RFC 7692) parameters are honored on both
	// directions. WithDeflateFromExtensionHeader is a no-op on an empty
	// string, so an unconditional append keeps the wiring simple while
	// remaining harmless when no extension was negotiated.
	wsOpts = append(wsOpts, ws.WithDeflateFromExtensionHeader(extensionHeader))
	clientWS := ws.New(clientReader, clientWriter, clientCloser, clientStreamID, ws.RoleServer, wsOpts...)
	upstreamWS := ws.New(upReader, upWriter, upCloser, clientStreamID, ws.RoleClient, wsOpts...)

	stack.ReplaceClientTop(clientWS)
	stack.ReplaceUpstreamTop(upstreamWS)

	// Pull the upstream WS Channel up-front so the recursive dial returns
	// it without blocking on Channels() inside RunSession's goroutine.
	upstreamWSCh, ok := <-upstreamWS.Channels()
	if !ok || upstreamWSCh == nil {
		return errors.New("session: upstream ws layer produced no Channel")
	}

	// USK-854: arm the WS hold-window keepalive against the upstream WS
	// Channel. The wrapped Channel routes Send through a shared mutex so
	// the keepalive goroutine and dispatchClientAction observe single-
	// flight Sends. wrapWSChannelForKeepalive returns the bare Channel
	// + nil sender when keepalive is disabled, so non-WS sessions and
	// opt-in misses incur no overhead.
	wrappedUpstreamCh, keepaliveSender := wrapWSChannelForKeepalive(upstreamWSCh, userOpt)
	keepaliveConnID := wsChannelConnID(upstreamWSCh)
	keepaliveStop := startWSHoldKeepalive(ctx, userOpt, keepaliveSender, clientStreamID, envelope.Send, keepaliveConnID)
	defer keepaliveStop()

	upgradeDial := DialFunc(func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return wrappedUpstreamCh, nil
	})

	// USK-841 Phase A milestone (d): the post-swap recursive session is
	// about to start. Both ws.Layers are installed on the ConnectionStack
	// via ReplaceClient/UpstreamTop; the upstream Channel was successfully
	// pulled out of upstreamWS.Channels(). If the recursive session never
	// records any WS frame, the failure is downstream of this point: most
	// likely inside the new ws.Layer's wsChannel.Next path (milestone (e))
	// or the upstream bufio reader's positioning relative to the wire.
	slog.Debug("session: runUpgradeWS recursive RunStackSession entry",
		"phase", "recursive-session-entry",
		"streamID", clientStreamID,
		"upstreamStreamID", upstreamCh.StreamID(),
	)

	return RunStackSession(ctx, stack, upgradeDial, p, userOpt)
}

// wsHandshakeStreamID returns the per-exchange UUID minted by
// http1.parseRequest (or the per-stream UUID from the h2 aggregator) on
// the wire-observed WS upgrade request, propagated through
// attachWSUpgradeRequest's defensive deep-clone (USK-841). Returns the
// empty string when upgradeReq is nil (test paths that bypass UpgradeStep)
// or when its StreamID is empty (defensive — should not happen with the
// production wiring). USK-848: runUpgradeWS adopts this id as the post-
// swap WS clientStreamID so the post-swap WS Stream is the SAME row as
// the pre-swap HTTP handshake Stream (USK-781 retag flips Protocol to
// "ws"; OnComplete on close finalises the unified Stream).
func wsHandshakeStreamID(upgradeReq *envelope.Envelope) string {
	if upgradeReq == nil {
		return ""
	}
	return upgradeReq.StreamID
}

// wsEnvelopeContextFromUpgradeReq derives the EnvelopeContext template
// stamped on every post-swap WS frame envelope from the pre-swap upgrade
// request envelope captured by UpgradeStep. The connection-scoped fields
// (ConnID, ClientAddr, TargetHost, TLS) are copied verbatim; the request-
// line URL is reshaped into UpgradePath / UpgradeQuery so it surfaces as
// "the URL the WS conversation was bootstrapped against" rather than
// being mistaken for an HTTP request line (the WS envelopes are not HTTP
// transactions — leaving RequestPath / RequestMethod / RequestRawQuery
// zero is intentional). Returns ok=false when upgradeReq is nil (test
// path that bypassed UpgradeStep) or carries no usable connection
// metadata; the caller then constructs the WS Layer without an envelope
// context template (legacy behaviour pre-USK-841).
//
// MITM principle 1 (do not normalize the wire): the Path and RawQuery
// are taken verbatim from the wire-observed HTTPMessage, not from any
// derived URL parser, so case / percent-encoding / empty-query distinction
// survives onto the WS envelope.
func wsEnvelopeContextFromUpgradeReq(upgradeReq *envelope.Envelope) (envelope.EnvelopeContext, bool) {
	if upgradeReq == nil {
		return envelope.EnvelopeContext{}, false
	}
	src := upgradeReq.Context
	out := envelope.EnvelopeContext{
		ConnID:     src.ConnID,
		ClientAddr: src.ClientAddr,
		TargetHost: src.TargetHost,
		TLS:        src.TLS,
		// ReceivedAt is intentionally zero — the per-envelope path stamps
		// the actual frame arrival time on every Envelope it emits.
		// RequestPath / RequestMethod / RequestRawQuery are intentionally
		// zero: those carry HTTP-transaction metadata and a WS frame is
		// not an HTTP transaction. The wire-observed request URL is
		// surfaced via UpgradePath / UpgradeQuery instead.
	}
	if msg, ok := upgradeReq.Message.(*envelope.HTTPMessage); ok && msg != nil {
		out.UpgradePath = msg.Path
		out.UpgradeQuery = msg.RawQuery
	}
	// If none of the carry-forward fields are populated, surface ok=false
	// so the caller can skip appending a no-op Option. Conservative:
	// presence of any one of these fields is enough to be useful to
	// downstream capture_scope / intercept rules.
	if out.ConnID == "" && out.TargetHost == "" && out.TLS == nil &&
		out.UpgradePath == "" && out.UpgradeQuery == "" && out.ClientAddr == nil {
		return envelope.EnvelopeContext{}, false
	}
	return out, true
}

// wsLifecycleOptions translates SessionOptions plumbing into the
// post-Upgrade WebSocket Layer's Option slice. Despite the name, it
// carries both pluginv2 lifecycle wiring (LifecycleEngine /
// StateReleaser) and per-Layer wire-cap knobs (WSMaxFrameSize, USK-806).
// Returns nil when no fields are wired, so callers splat into
// ws.New(... opts...) without conditional branching.
func wsLifecycleOptions(userOpt SessionOptions) []ws.Option {
	var out []ws.Option
	if userOpt.LifecycleEngine != nil {
		out = append(out, ws.WithLifecycleEngine(userOpt.LifecycleEngine))
	}
	if userOpt.StateReleaser != nil {
		out = append(out, ws.WithStateReleaser(userOpt.StateReleaser))
	}
	// USK-806: thread the operator-configured per-frame payload cap into
	// both client- and upstream-facing ws.Layer constructions. The Option
	// is no-op on n <= 0 so the > 0 guard is defensive (avoids appending
	// a noise Option) but not strictly required for correctness.
	if userOpt.WSMaxFrameSize > 0 {
		out = append(out, ws.WithMaxFrameSize(userOpt.WSMaxFrameSize))
	}
	return out
}

// h2StreamIDer is the optional surface a layer.Channel may implement to
// expose its underlying HTTP/2 stream id. Both *http2.channel and
// *httpaggregator.aggregatorChannel implement this; the upgrade
// orchestrator type-asserts via this interface so it does not have to
// import either concrete type (avoids an import cycle from session to
// http2).
type h2StreamIDer interface {
	H2StreamID() uint32
}

// extractH2StreamID returns the h2 stream id carried by ch, or 0 with a
// descriptive error when ch does not expose one. The empty-id case is an
// orchestrator pre-condition violation: an h2 extended-CONNECT upgrade
// cannot be performed without knowing the wire stream id.
func extractH2StreamID(ch layer.Channel, side string) (uint32, error) {
	if ch == nil {
		return 0, fmt.Errorf("session: h2 ws upgrade: %s channel is nil", side)
	}
	idr, ok := ch.(h2StreamIDer)
	if !ok {
		return 0, fmt.Errorf("session: h2 ws upgrade: %s channel %T does not expose H2StreamID", side, ch)
	}
	id := idr.H2StreamID()
	if id == 0 {
		return 0, fmt.Errorf("session: h2 ws upgrade: %s channel reports h2 stream id 0", side)
	}
	return id, nil
}

// runUpgradeWSOverH2 performs the per-stream WS-over-h2 swap (RFC-001
// §3.4.1 / §4.5; RFC 8441 extended CONNECT). Distinct from runUpgradeWS:
//
//   - The connection-level Layers stay *http2.Layer for sibling streams.
//     ReplaceClient/UpstreamTop is INTENTIONALLY NOT CALLED — multiplex
//     correctness MUST is preserved by the per-stream sub-stack overlay.
//   - DetachStream(streamID) on each h2 Layer peels framing for the
//     affected stream only; the returned (reader, writer, closer) triple
//     is opaque bytes that ws.New(... ws.WithH2Mode(true) ...) wraps.
//   - The new ws.Layer pair is registered on stack.streamSubStacks.
//     ClientTopmostForStream(streamID) returns the per-stream client
//     ws.Layer; sibling-stream lookups still resolve to the connection-
//     level h2 Layer.
//
// The post-swap session loop runs on the new ws Channels. On terminal
// state, the sub-stack is released so the connection-level h2 Layer is
// the sole reference to the stream id again (RFC-001 §3.4.1 lifetime
// MUST).
func runUpgradeWSOverH2(
	ctx context.Context,
	stack *connector.ConnectionStack,
	p *pipeline.Pipeline,
	userOpt SessionOptions,
	clientCh, upstreamCh layer.Channel,
	upgradeReq *envelope.Envelope,
	extensionHeader string,
) (retErr error) {
	clientH2, upstreamH2, err := h2LayersFromStack(stack)
	if err != nil {
		return err
	}
	clientStreamID, upstreamStreamID, err := h2StreamIDsForUpgrade(clientCh, upstreamCh)
	if err != nil {
		return err
	}
	cR, cW, cClose, uR, uW, uClose, err := detachBothSides(clientH2, upstreamH2, clientStreamID, upstreamStreamID)
	if err != nil {
		return err
	}

	// Stable session-scope identifier — reuse the client channel's
	// envelope StreamID (a UUID) so post-swap flows correlate with the
	// pre-swap CONNECT request and 2xx response in flow records.
	sessionStreamID := clientCh.StreamID()

	// Sequence 0 on the post-swap StreamID is already occupied by the
	// pre-swap CONNECT request (Send) and 2xx response (Receive) flow
	// records. The post-swap WS Channels must skip past 0 so the flow
	// store's (stream_id, sequence, direction, variant) UNIQUE constraint
	// does not reject the first WS frame in either direction. USK-781.
	wsOpts := append([]ws.Option{
		ws.WithH2Mode(true),
		ws.WithInitialSequence(1),
	}, wsLifecycleOptions(userOpt)...)
	// USK-841: propagate the wire-observed EnvelopeContext from the pre-
	// swap extended-CONNECT request onto the post-swap WS Layer pair.
	// Same rationale as runUpgradeWS — without this, per-frame envelopes
	// carry empty Context and capture_scope rejects them as out-of-scope.
	if envCtx, ok := wsEnvelopeContextFromUpgradeReq(upgradeReq); ok {
		wsOpts = append(wsOpts, ws.WithEnvelopeContext(envCtx))
	}
	// USK-847: propagate the wire-observed Sec-WebSocket-Extensions
	// response header from the extended-CONNECT 2xx accept onto the
	// post-swap WS Layer pair. RFC 8441 §5 does not redefine the
	// negotiation surface, so RFC 7692 parameters ride on the same
	// header. WithDeflateFromExtensionHeader is a no-op on empty input.
	wsOpts = append(wsOpts, ws.WithDeflateFromExtensionHeader(extensionHeader))
	clientWS := ws.New(cR, cW, &detachCloserAdapter{f: cClose}, sessionStreamID, ws.RoleServer, wsOpts...)
	upstreamWS := ws.New(uR, uW, &detachCloserAdapter{f: uClose}, sessionStreamID, ws.RoleClient, wsOpts...)

	if regErr := stack.RegisterStreamSubStack(sessionStreamID, clientWS, upstreamWS); regErr != nil {
		_ = clientWS.Close()
		_ = upstreamWS.Close()
		return fmt.Errorf("session: register sub-stack for stream %d (%s): %w", clientStreamID, sessionStreamID, regErr)
	}

	// Lifetime release: when the post-swap session terminates (graceful
	// EOF, error, or context cancel), the sub-stack is removed and the
	// per-stream Layer pair is closed. Sibling streams continue running.
	defer func() {
		// ReleaseStreamSubStack is idempotent — Close inside the session
		// loop's OnComplete may have already torn things down. Errors are
		// joined into retErr only when retErr is nil so we don't shadow
		// the actual session result.
		if relErr := stack.ReleaseStreamSubStack(sessionStreamID); relErr != nil && retErr == nil {
			retErr = relErr
		}
	}()

	clientWSCh, upstreamWSCh, err := pullWSChannels(clientWS, upstreamWS)
	if err != nil {
		return err
	}
	if err := assertSubStackLookups(stack, sessionStreamID, clientWS, upstreamWS); err != nil {
		return err
	}

	// Run a custom WS relay loop instead of recursing into RunSession.
	// USK-781 rationale: the generic RunSession does not know how to
	// propagate a per-stream half-close across the swap. When the client
	// emits HTTP/2 END_STREAM (e.g. half-closing the WS bytestream), the
	// proxy must mirror that signal onto the upstream h2 stream — not by
	// closing the connection (which would kill sibling streams) but by
	// writing an empty END_STREAM DATA frame on the SAME stream id. The
	// detach writers returned by http2.Layer.DetachStream do exactly that
	// on Close (see detachWriter.Close), so the relay calls them on EOF
	// in either direction.
	return runWSOverH2Relay(ctx, p, userOpt, clientWSCh, upstreamWSCh, cW, uW, sessionStreamID)
}

// runWSOverH2Relay drives the post-swap WS-over-h2 session. Two goroutines
// shuttle WS envelopes through the Pipeline in opposite directions; on EOF
// in either direction the corresponding upstream/client h2 detach writer is
// closed so an empty END_STREAM DATA frame propagates the half-close to
// the peer. Without this propagation the upstream HTTP handler stays parked
// on r.Body.Read forever after the client half-closes, even though the
// proxy itself has correctly observed the END_STREAM DATA frame on the
// client side.
//
// Concurrency notes (CLAUDE.md Concurrency Checklist):
//   - Termination: clientToUpstream goroutine exits on clientWSCh.Next EOF
//     OR ctx cancel; same for the reverse direction. Each defers a single
//     Close on the OPPOSITE side's detach writer to half-close the wire,
//     which causes the peer goroutine's Next to surface EOF in turn.
//   - Single-writer close: each io.Closer is a *detachWriter; its Close
//     uses sync.Mutex + closed flag so re-entry is safe even if both
//     directions race to close on errors.
//   - Cascade-close: half-close ONLY on EOF (graceful). On any other
//     terminal error we surface the error to the errgroup which cancels
//     the peer ctx; the deferred sub-stack release closes both detach
//     writers via Layer.Close → closeDetached().
func runWSOverH2Relay(
	ctx context.Context,
	p *pipeline.Pipeline,
	userOpt SessionOptions,
	clientWSCh, upstreamWSCh layer.Channel,
	clientDetachW, upstreamDetachW io.WriteCloser,
	sessionStreamID string,
) (retErr error) {
	origCtx := ctx
	g, ctx := errgroup.WithContext(ctx)

	reg := &bodyBufRegistry{}
	defer reg.drain()

	// client → upstream: read WS frames from client wire, run Pipeline,
	// forward to upstream. On graceful EOF, half-close the upstream write
	// side so the upstream HTTP handler observes EOF on its request body.
	g.Go(func() error {
		err := wsRelayDirection(ctx, p, reg, clientWSCh, upstreamWSCh, userOpt, envelope.Send)
		if err == nil {
			// Graceful EOF on client side: half-close the upstream wire.
			// detachWriter.Close emits empty DATA(END_STREAM) on the
			// upstream h2 stream id. Errors are intentionally swallowed —
			// the writer may already be closed by a concurrent terminal
			// path (Layer.Close cascade), and the detachWriter itself
			// is safe against double-Close (sync.Mutex + closed flag).
			_ = upstreamDetachW.Close()
		}
		return err
	})

	// upstream → client: read WS frames from upstream wire, run Pipeline,
	// forward to client. On graceful EOF, half-close the client write
	// side so the test client observes EOF on the response body (and the
	// h2 stream cleanly transitions to closed).
	g.Go(func() error {
		err := wsRelayDirection(ctx, p, reg, upstreamWSCh, clientWSCh, userOpt, envelope.Receive)
		if err == nil {
			_ = clientDetachW.Close()
		}
		return err
	})

	result := g.Wait()

	// userOpt.OnComplete is invoked exactly once at the end of the post-
	// swap session so the recorder marks the Stream as complete (or
	// error) once both directions have terminated. The orchestrator
	// (RunStackSessionExchange) deliberately suppresses the first-session
	// OnComplete with ErrUpgradePending, so this is the only place the
	// post-swap result surfaces to the user callback.
	if userOpt.OnComplete != nil {
		userOpt.OnComplete(context.WithoutCancel(origCtx), sessionStreamID, result)
	}
	return result
}

// wsRelayDirection reads envelopes from src, runs them through the
// Pipeline, and Sends each non-Drop envelope on dst. Returns nil on
// graceful EOF and a wrapped error otherwise. Drop / Respond actions are
// honoured (Respond writes back to src for symmetry with RunSession,
// matching plugin / intercept semantics).
//
// srcDir labels the direction of the envelopes flowing in from src, used
// only by the USK-851 EOF correlation. The other side (Send-side
// envelopes flowing client→upstream OR Receive-side envelopes flowing
// upstream→client) maps directly: a client-side ws.Layer emits Send
// envelopes; an upstream-side ws.Layer emits Receive envelopes. The
// correlation key uses the OPPOSITE direction on the same StreamID — see
// ReleaseTracker.LookupAndForgetOpposite.
func wsRelayDirection(
	ctx context.Context,
	p *pipeline.Pipeline,
	reg *bodyBufRegistry,
	src, dst layer.Channel,
	userOpt SessionOptions,
	srcDir envelope.Direction,
) error {
	// streamID is captured from the first envelope so the EOF-correlation
	// path knows which Stream to attribute on graceful close. The src
	// Channel exposes StreamID() before the first Next on most Channel
	// implementations, but treating the first envelope as the source of
	// truth matches what the rest of the session does (streamCapture
	// pattern in RunSession).
	streamID := src.StreamID()

	// USK-854: wrap the dst Send call site with a per-relay-direction
	// serialiser so the keepalive goroutine can co-Send synthetic Ping
	// frames without violating wsChannel.Send's "caller-serialised"
	// contract. dstDir is the direction the keepalive goroutine stamps on
	// its synthetic envelopes (the WS Layer composes wire frames from
	// env.Message, not env.Direction, so the value is informational).
	//
	// dst-side direction mapping: when the main relay reads from a client
	// ws.Layer (RoleServer) and writes to an upstream ws.Layer (RoleClient),
	// the synthetic Ping leaves the proxy heading toward the upstream —
	// envelope.Send. The keepalive watches the HoldTracker on the same
	// (streamID, srcDir) pair the InterceptStep stamps (because the held
	// envelope was the one we received from src on its way to dst).
	sender := newWSSendSerializer(dst)
	connID := wsRelayConnID(src, dst)
	stop := startWSHoldKeepalive(ctx, userOpt, sender, streamID, srcDir, connID)
	defer stop()

	// USK-860: per-relay-direction "did we forward an envelope?" gate. Set
	// to true after the first successful sender.Send below. Read by
	// wsRelayNextErr inside checkInterceptReleaseEOF to suppress the
	// upstream_closed_after_intercept_release tag when the wire
	// conversation actually completed end-to-end. Single-goroutine read
	// and write (this loop owns the variable) — a plain bool is
	// sufficient; no atomics needed.
	var relayed bool

	for {
		env, err := src.Next(ctx)
		if err != nil {
			return wsRelayNextErr(ctx, err, userOpt, streamID, srcDir, relayed)
		}
		if streamID == "" {
			streamID = env.StreamID
		}
		env, action, resp, blockedBy := runPipelineTracked(ctx, p, env, reg)
		if action == pipeline.Drop || action == pipeline.Respond {
			if serr := wsRelayHandlePolicy(ctx, src, action, env, resp, blockedBy, userOpt.OnPipelineDrop); serr != nil {
				return serr
			}
			continue
		}
		if env == nil {
			continue
		}
		if serr := sender.Send(ctx, env); serr != nil {
			return fmt.Errorf("ws/h2 relay: dst.Send: %w", serr)
		}
		relayed = true
	}
}

// wsRelayConnID derives the EnvelopeContext.ConnID from whichever Channel
// exposes a non-empty value via a ContextSnapshot-like accessor. Today the
// WS Channel does not expose its ctxTmpl directly; we fall back to the
// emitted first-envelope's ConnID if needed (read at relay-loop time).
// The plugin opt-out only requires ConnID to be non-empty when a plugin
// has set stream_state via a (ws, on_upgrade, pre) hook — that hook fires
// with the canonical envelope context populated by the http1 / http2
// upgrade path, so the stream_state lookup at runtime sees the SAME
// ConnID regardless of how the keepalive obtains it.
//
// Returns the empty string when neither Channel exposes a ConnID; the
// keepalive then skips the plugin opt-out lookup (and defaults to "no
// opt-out", which is the conservative behaviour for the opt-in feature).
func wsRelayConnID(src, dst layer.Channel) string {
	if c := wsChannelConnID(src); c != "" {
		return c
	}
	return wsChannelConnID(dst)
}

// wsChannelConnIDSnapshot is the narrow interface a Channel can implement
// to expose its EnvelopeContext.ConnID. Currently only *ws.wsChannel
// implements it via a tiny accessor (see internal/layer/ws/channel.go).
// Test stacks that pass other Channel types fall back to the empty string.
type wsChannelConnIDSnapshot interface {
	EnvelopeConnID() string
}

func wsChannelConnID(ch layer.Channel) string {
	if ch == nil {
		return ""
	}
	if s, ok := ch.(wsChannelConnIDSnapshot); ok {
		return s.EnvelopeConnID()
	}
	return ""
}

// wsRelayNextErr maps an src.Next error into the wsRelayDirection return
// contract. Extracted to keep wsRelayDirection under the gocyclo budget.
//
// relayed is the per-relay-direction "did we forward an envelope?" gate
// owned by wsRelayDirection (USK-860). Forwarded as-is to
// checkInterceptReleaseEOF so the diagnostic tag is suppressed when the
// peer relay completed normally before the EOF observed here.
func wsRelayNextErr(ctx context.Context, err error, userOpt SessionOptions, streamID string, srcDir envelope.Direction, relayed bool) error {
	// USK-851: on either graceful EOF OR a stream-level error (the WS
	// Layer maps a peer-closed TCP into layer.StreamError{Protocol|
	// Aborted}), check the OPPOSITE-direction release tracker. A hit
	// means the upstream stopped talking shortly after we forwarded a
	// long-held frame — surface that via the operator-facing Stream tag.
	// context.Canceled is excluded: it is a normal teardown from the
	// errgroup peer, not a wire-observed event worth attributing.
	if !errors.Is(err, context.Canceled) {
		checkInterceptReleaseEOF(ctx, userOpt, streamID, srcDir, relayed)
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return ctx.Err()
	}
	return fmt.Errorf("ws/h2 relay: src.Next: %w", err)
}

// wsRelayHandlePolicy applies a Drop / Respond pipeline action. Returns a
// non-nil error only when src.Send fails on the Respond path. Drop and
// nil-resp Respond both return nil so the caller's loop continues. The
// onDrop attribution mirrors RunSession's dispatchClientAction.
func wsRelayHandlePolicy(
	ctx context.Context,
	src layer.Channel,
	action pipeline.Action,
	env, resp *envelope.Envelope,
	blockedBy string,
	onDrop func(context.Context, *envelope.Envelope, string),
) error {
	if blockedBy != "" && onDrop != nil {
		onDrop(ctx, env, blockedBy)
	}
	if action == pipeline.Drop || resp == nil {
		return nil
	}
	if serr := src.Send(ctx, resp); serr != nil {
		return fmt.Errorf("ws/h2 relay: src.Send (respond): %w", serr)
	}
	return nil
}

// h2LayersFromStack returns the client and upstream connection-level
// HTTP/2 Layers for the ws-over-h2 swap. The client-side Layer is always
// the stack's ClientTopmost. The upstream-side Layer lives in one of two
// places depending on how the stack was built:
//
//   - "h2" ALPN route (the production wss-over-h2 case): the upstream
//     HTTP/2 Layer is held by the connection pool and exposed via
//     stack.UpstreamH2Layer(). It is NOT pushed onto stack.upstream so
//     that its lifecycle stays with the pool — stack.Close() must not
//     close a pooled Layer (RFC-001 §3.4.1; see stack_builder.go
//     buildH2Stack rationale).
//   - Test paths that wire the upstream H2 Layer via PushUpstream: the
//     Layer surfaces through stack.UpstreamTopmost(). Older session-
//     level tests (session_upgrade_test.go) follow this shape, so the
//     fallback keeps them working without forcing every caller to hand
//     the Layer in separately.
//
// USK-781: before this fallback, runUpgradeWSOverH2 always asked for
// UpstreamTopmost() and failed with a "<nil>" error on the live h2 route,
// silently aborting the post-swap session before any WS frame could
// flow.
func h2LayersFromStack(stack *connector.ConnectionStack) (*http2.Layer, *http2.Layer, error) {
	return h2LayersFromAccessor(stack)
}

// h2StackAccessor is the slice of *connector.ConnectionStack that
// h2LayersFromStack needs. Extracting this interface lets unit tests
// fake the stack without constructing real *http2.Layer instances on
// both sides (USK-783). Production code passes a *connector.ConnectionStack
// (which satisfies this interface verbatim).
type h2StackAccessor interface {
	ClientTopmost() layer.Layer
	UpstreamTopmost() layer.Layer
	UpstreamH2Layer() *http2.Layer
}

// h2LayersFromAccessor is the test-shaped implementation of
// h2LayersFromStack. Behavior is identical; only the input type differs.
func h2LayersFromAccessor(stack h2StackAccessor) (*http2.Layer, *http2.Layer, error) {
	clientTop := stack.ClientTopmost()
	clientH2, ok := clientTop.(*http2.Layer)
	if !ok {
		return nil, nil, fmt.Errorf("session: ws/h2 upgrade requires *http2.Layer client topmost, got %T", clientTop)
	}
	if pooled := stack.UpstreamH2Layer(); pooled != nil {
		return clientH2, pooled, nil
	}
	upstreamTop := stack.UpstreamTopmost()
	upstreamH2, ok := upstreamTop.(*http2.Layer)
	if !ok {
		return nil, nil, fmt.Errorf("session: ws/h2 upgrade requires *http2.Layer upstream layer (pool or topmost), got %T", upstreamTop)
	}
	return clientH2, upstreamH2, nil
}

// h2StreamIDsForUpgrade extracts both the client- and upstream-side h2
// stream ids from the channels passed by the orchestrator.
func h2StreamIDsForUpgrade(clientCh, upstreamCh layer.Channel) (uint32, uint32, error) {
	c, err := extractH2StreamID(clientCh, "client")
	if err != nil {
		return 0, 0, err
	}
	u, err := extractH2StreamID(upstreamCh, "upstream")
	if err != nil {
		return 0, 0, err
	}
	return c, u, nil
}

// detachBothSides peels per-stream framing on both Layers; rolls back
// the client-side detach if the upstream-side fails, so the wire is not
// left in an inconsistent state.
func detachBothSides(clientH2, upstreamH2 *http2.Layer, clientStreamID, upstreamStreamID uint32) (
	io.ReadCloser, io.WriteCloser, func() error,
	io.ReadCloser, io.WriteCloser, func() error,
	error,
) {
	cR, cW, cClose, err := clientH2.DetachStream(clientStreamID)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("session: detach client h2 stream %d: %w", clientStreamID, err)
	}
	uR, uW, uClose, err := upstreamH2.DetachStream(upstreamStreamID)
	if err != nil {
		_ = cClose()
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("session: detach upstream h2 stream %d: %w", upstreamStreamID, err)
	}
	return cR, cW, cClose, uR, uW, uClose, nil
}

// pullWSChannels fetches the single Channel each ws Layer yields.
func pullWSChannels(clientWS, upstreamWS *ws.Layer) (layer.Channel, layer.Channel, error) {
	cCh, ok := <-clientWS.Channels()
	if !ok || cCh == nil {
		return nil, nil, errors.New("session: client ws/h2 layer produced no Channel")
	}
	uCh, ok := <-upstreamWS.Channels()
	if !ok || uCh == nil {
		return nil, nil, errors.New("session: upstream ws/h2 layer produced no Channel")
	}
	return cCh, uCh, nil
}

// assertSubStackLookups defends against a silent registration failure:
// if the stack does not surface the registered ws Layers via *ForStream,
// proceeding would hand the post-swap session the connection-level h2
// Layer — a multiplex-isolation violation.
func assertSubStackLookups(stack *connector.ConnectionStack, streamID string, clientWS, upstreamWS *ws.Layer) error {
	if got := stack.ClientTopmostForStream(streamID); got != clientWS {
		return fmt.Errorf("session: ClientTopmostForStream(%s) returned %T, expected registered ws.Layer", streamID, got)
	}
	if got := stack.UpstreamTopmostForStream(streamID); got != upstreamWS {
		return fmt.Errorf("session: UpstreamTopmostForStream(%s) returned %T, expected registered ws.Layer", streamID, got)
	}
	return nil
}

// detachCloserAdapter adapts a func() error returned by
// http2.Layer.DetachStream into the io.Closer that ws.New expects. The
// underlying h2 connection is NOT closed; only the per-stream framing is.
type detachCloserAdapter struct {
	f    func() error
	once sync.Once
	err  error
}

// Close is idempotent.
func (c *detachCloserAdapter) Close() error {
	c.once.Do(func() {
		if c.f != nil {
			c.err = c.f()
		}
	})
	return c.err
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
	// USK-806: thread the operator-configured per-event byte cap into the
	// SSE Channel. Option is no-op on n <= 0 so the > 0 guard is purely
	// defensive (avoids a noise Option append).
	if userOpt.SSEMaxEventSize > 0 {
		wrapOpts = append(wrapOpts, sse.WithMaxEventSize(userOpt.SSEMaxEventSize))
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
	opt SessionOptions,
) (err error) {
	onDrop := opt.OnPipelineDrop
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

	// USK-860: per-relay-direction "did we forward an envelope upstream?"
	// gate. Set to true after dispatchClientAction reports a successful
	// upstream.Send. Read inside checkInterceptReleaseEOF below to
	// suppress the upstream_closed_after_intercept_release tag when the
	// proxy actually relayed the post-release client envelope (e.g.
	// modify_and_forward of an HTTP request) before the EOF here.
	// Single-goroutine read and write — plain bool is sufficient.
	var relayed bool

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
			// USK-851: on client teardown (graceful EOF or stream-level
			// error), surface the "upstream-closed-after-intercept-release"
			// tag when a recent release on the Receive side correlates.
			// Symmetric with the upstreamToClient path so either side
			// observing the teardown attributes it to the long-hold cause.
			// USK-860: the relayed gate suppresses the callback when this
			// loop already forwarded the released envelope upstream.
			checkInterceptReleaseEOF(ctx, opt, sc.get(), envelope.Send, relayed)
			if errors.Is(nerr, io.EOF) {
				return nil
			}
			return fmt.Errorf("client.Next: %w", nerr)
		}
		sc.set(env.StreamID)

		env, action, resp, blockedBy := runPipelineTracked(ctx, p, env, reg)
		// USK-782 / USK-829: surface the BlockedBy attribution to the
		// session-side recorder before continuing the loop. Wire
		// forwarding still short-circuits on Drop (dispatchClientAction
		// returns nil); on Respond the synthetic 403 is delivered via
		// client.Send below. The recorder fires synchronously so the
		// audit Stream is persisted while the goroutine is still
		// scheduled. Respond carries blockedBy only when emitted by a
		// policy Step (Intercept / HostScope / HTTPScope / Safety);
		// plugin-driven Respond passes blockedBy="" through unchanged.
		if blockedBy != "" && onDrop != nil &&
			(action == pipeline.Drop || action == pipeline.Respond) {
			onDrop(ctx, env, blockedBy)
		}
		forwarded, perr := dispatchClientAction(ctx, client, uh, dial, env, resp, action)
		if perr != nil {
			return perr
		}
		if forwarded {
			relayed = true
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
//
// USK-860: forwarded reports whether the envelope was actually sent
// upstream (action == Continue and uh.ch.Send succeeded). The caller
// uses this to update the per-relay-direction "did we relay?" gate that
// suppresses the upstream_closed_after_intercept_release diagnostic
// tag when the post-release wire conversation completed normally. Drop
// and Respond return forwarded=false because neither produces a
// proxy-to-upstream envelope on the relay's natural direction.
func dispatchClientAction(
	ctx context.Context,
	client layer.Channel,
	uh *upstreamHolder,
	dial DialFunc,
	env *envelope.Envelope,
	resp *envelope.Envelope,
	action pipeline.Action,
) (forwarded bool, err error) {
	switch action {
	case pipeline.Drop:
		return false, nil
	case pipeline.Respond:
		if serr := client.Send(ctx, resp); serr != nil {
			return false, fmt.Errorf("client.Send (respond): %w", serr)
		}
		return false, nil
	}

	if uh.ch == nil {
		u, derr := dial(ctx, env)
		if derr != nil {
			return false, fmt.Errorf("dial: %w", derr)
		}
		uh.ch = u
		close(uh.ready)
	}

	// USK-854: when uh.ch is the serializedSendChannel wrapper installed
	// by runUpgradeWS, .Send routes through the shared sync.Mutex so the
	// keepalive goroutine and this main path co-Send without violating
	// wsChannel.Send's "caller-serialised" contract. Non-WS sessions
	// see the bare Channel and incur no overhead.
	if serr := uh.ch.Send(ctx, env); serr != nil {
		return false, fmt.Errorf("upstream.Send: %w", serr)
	}
	return true, nil
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
	opt SessionOptions,
) error {
	onDrop := opt.OnPipelineDrop
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

	// USK-860: per-relay-direction "did we forward an envelope downstream?"
	// gate. Set to true after the first successful client.Send below.
	// Read inside upstreamToClientFinish to suppress the
	// upstream_closed_after_intercept_release tag when the wire response
	// completed end-to-end (the canonical user-reported bug:
	// modify_and_forward request → 200 OK relayed back → upstream closes
	// with Connection: close). Single-goroutine read and write — plain
	// bool is sufficient.
	var relayed bool

	for {
		env, err := upstreamNext(ctx, uh.ch, notice)
		if err != nil || env == nil {
			return upstreamToClientFinish(ctx, opt, clientID, err, relayed)
		}

		if clientID != "" {
			env.StreamID = clientID
		}

		env, action, _, blockedBy := runPipelineTracked(ctx, p, env, reg)
		if action == pipeline.Drop {
			// USK-782: receive-direction Drops (e.g. Safety on a Receive
			// arm — currently no engine emits one, but the path is wired
			// for future per-protocol Output Filters) surface to the
			// audit recorder symmetrically with Send-direction Drops.
			if blockedBy != "" && onDrop != nil {
				onDrop(ctx, env, blockedBy)
			}
			if upgradePending(notice) {
				return ErrUpgradePending
			}
			continue
		}

		// USK-823: defense in depth. The HTTP/2 upstream Layer no longer
		// surfaces PUSH_PROMISE as synthetic envelopes — server-push
		// recording was retired; anomalous PUSH_PROMISE is rejected at
		// the reader as PROTOCOL_ERROR before any envelope is built. A
		// plugin could still synthesize a Message carrying the
		// H2PushPromise anomaly, and forwarding such a request-shaped
		// envelope to the client Layer would emit a malformed response.
		// Continue past it rather than relay.
		if m, ok := env.Message.(*envelope.HTTPMessage); ok && envelope.HasPushPromiseAnomaly(m) {
			continue
		}

		// USK-715: when the Pipeline flipped the upgrade notice, prime
		// the post-Upgrade side-buffer capture on the client Channel
		// BEFORE Send(101) writes the response. This closes the race
		// window where the test client receives 101, writes a WS frame,
		// and the proxy's parker.conn.Read returns successfully with
		// those WS bytes BEFORE Interrupt can set the read deadline (and
		// thus before capture is enabled). With PrepareSwap pre-Send,
		// any post-101 byte arrival is recorded for replay by
		// http1.Layer.DetachStream regardless of which goroutine wins
		// the netpoll-vs-deadline race.
		//
		// USK-841 Phase B: also prime the upstream-side capture
		// symmetrically. When the upstream pushes WS frame bytes
		// immediately after flushing its 101 (Fly.io edge behavior),
		// those bytes can land in the kernel TCP buffer for the upstream
		// conn before runUpgradeWS detaches. Without an active capture
		// the upstream-side detachStream returns the bare bufio.Reader;
		// any post-101 bytes the parser had already pulled past the
		// 101's CRLFCRLF into bufio's buffered remainder are recoverable
		// (bufio.Reader serves them on its next Read), but the explicit
		// capture mirrors the client side so the operator-visible
		// upstreamReaderType trace transitions from *bufio.Reader to
		// io.MultiReader and any future bufio-bypass change cannot
		// silently strand bytes.
		if upgradePending(notice) {
			prepareChannelSwap(client)
			prepareChannelSwap(uh.ch)
		}

		if err := client.Send(ctx, env); err != nil {
			return fmt.Errorf("client.Send: %w", err)
		}
		relayed = true

		// Friction 2-C strict ordering: the 101 response (or first SSE
		// event-stream response) MUST be delivered to the client BEFORE
		// the goroutine exits. After Send returns we are safe to surface
		// ErrUpgradePending so the errgroup ctx cancels the peer
		// goroutine and RunStackSession can reclaim both wires.
		if upgradePending(notice) {
			// USK-701: also poke the peer goroutine awake. clientToUpstream
			// is parked inside client.Next which, for HTTP/1.x, does not
			// honor ctx (parser.ParseRequest → bufio.Reader → conn.Read).
			// Without an active wake the errgroup ctx cancellation cannot
			// propagate and g.Wait() never returns, so the swap orchestrator
			// (runUpgradeWS / runUpgradeSSE) cannot reclaim the wires.
			// Interrupt is idempotent + a no-op for Channels that don't need
			// it (h2 / ws / sse / httpaggregator are already ctx-aware).
			interruptChannel(client)
			return ErrUpgradePending
		}
	}
}

// upstreamToClientFinish is the EOF / terminal-error tail of
// upstreamToClient. Extracted so the main loop stays under the gocyclo
// budget and so the USK-851 detection runs on every path the read loop
// returns through.
//
// Contract:
//   - err == nil (env was nil): graceful EOF; check release tracker and
//     return nil so the caller's errgroup sees a clean exit.
//   - err == ErrUpgradePending: control-flow signal from upstreamNext;
//     surface verbatim WITHOUT touching the tracker (it is not a wire
//     teardown).
//   - any other err: stream-level error (e.g. WS Layer's mapped
//     StreamError on peer-reset); check the tracker (same reasoning as
//     EOF — the upstream stopped talking) and return the original err.
//
// USK-860: relayed reflects whether the upstream→client relay loop
// successfully forwarded at least one envelope before this terminal
// outcome. Forwarded as-is to checkInterceptReleaseEOF so the
// diagnostic tag is suppressed on the canonical false-positive path
// (modify_and_forward request → 200 OK relayed end-to-end → normal
// upstream close).
func upstreamToClientFinish(ctx context.Context, opt SessionOptions, clientID string, err error, relayed bool) error {
	if errors.Is(err, ErrUpgradePending) {
		return err
	}
	checkInterceptReleaseEOF(ctx, opt, clientID, envelope.Receive, relayed)
	return err
}

// channelInterrupter is satisfied by Channels (currently only http1) that
// expose a cancel-the-parked-Next primitive. The session orchestrator uses
// it to wake a peer goroutine that would otherwise stay parked because the
// underlying Channel.Next does not honor ctx.
//
// Implementations: http1.channel.Interrupt (SetReadDeadline(time.Now())).
type channelInterrupter interface {
	Interrupt() error
}

// interruptChannel is the type-assertion wrapper used by the session
// orchestrator. Cheap no-op for Channels that do not implement
// channelInterrupter.
func interruptChannel(ch layer.Channel) {
	if ic, ok := ch.(channelInterrupter); ok {
		_ = ic.Interrupt()
	}
}

// channelSwapPreparer is satisfied by Channels (currently only http1) that
// support priming an Interrupt-time side-buffer BEFORE the deadline arms.
// The session orchestrator calls PrepareSwap right after the Pipeline
// flips the upgrade notice and BEFORE client.Send(101). See
// http1.channel.PrepareSwap for the rationale (USK-715).
type channelSwapPreparer interface {
	PrepareSwap()
}

// prepareChannelSwap is the type-assertion wrapper for channelSwapPreparer.
// Cheap no-op for Channels that do not implement the interface.
func prepareChannelSwap(ch layer.Channel) {
	if sp, ok := ch.(channelSwapPreparer); ok {
		sp.PrepareSwap()
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
