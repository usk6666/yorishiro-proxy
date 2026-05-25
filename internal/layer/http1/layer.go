package http1

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// healthCheckProbeDeadline bounds the one-byte probe read in
// [Layer.HealthCheck]. Long enough for the Go netpoller to surface a
// queued peer FIN / RST (typically sub-millisecond); short enough that
// a healthy connection's dial is not visibly delayed.
const healthCheckProbeDeadline = 1 * time.Millisecond

// Layer wraps a net.Conn in an HTTP/1.x Layer. It yields one Channel per
// HTTP request-response exchange (RFC-001 §3.3 — Channel granularity is the
// logical stream, not the connection). Multiple exchanges on a keep-alive
// connection produce multiple Channels.
//
// Direction semantics:
//   - envelope.Send (server-facing): a spawn loop parses each incoming request
//     and yields a per-exchange Channel via Channels(). The Channel carries
//     the request envelope on its first Next() call; Send writes the response
//     back to the wire.
//   - envelope.Receive (upstream-facing): callers obtain a per-exchange
//     Channel via OpenExchange(); they Send the request, then Next() returns
//     the parsed response. Channels() also yields these for back-compat with
//     test/MCP-resend single-shot consumers.
//
// The Layer owns the connection and closes it on Close(). It enforces
// HTTP/1.1 wire-serialization across exchanges (only one write at a time;
// upstream responses are demultiplexed in FIFO request-send order).
type Layer struct {
	conn          net.Conn
	reader        *bufio.Reader
	captureReader *interruptCaptureReader
	streamID      string
	direction     envelope.Direction
	opts          options

	// chOut is the channel returned by Channels(). The spawn goroutine
	// writes per-exchange Channels here; closed when the spawn loop exits.
	chOut chan layer.Channel

	// closed is signalled by Close() to shut down the spawn goroutine.
	closed    chan struct{}
	closeOnce sync.Once

	// writeMu serializes Channel.Send across all exchanges so concurrent
	// Sends on different per-exchange Channels never interleave wire bytes.
	// HTTP/1.1 is strictly serial on the wire (RFC 9112 §9.5).
	writeMu sync.Mutex

	// Receive-direction state: pendingQ is the FIFO of Channels awaiting
	// their response. consumers add to it via OpenExchange (after registering)
	// then Send the request. The spawn loop pops from the head when ready
	// to parse the next response.
	pendingMu     sync.Mutex
	pendingQ      []*channel
	pendingNotify chan struct{} // wakes the receive spawn loop

	// activeMu guards `active`, the most-recently-yielded Channel. Layer-level
	// upgrade primitives (Interrupt / PrepareSwap / DetachStream /
	// DetachStreamingBody) forward to it for back-compat with callers that
	// hold the Layer rather than the Channel.
	activeMu sync.RWMutex
	active   *channel

	// detached is set when DetachStream / DetachStreamingBody transfers
	// conn ownership to a successor Layer (ws / sse). Subsequent Close
	// calls become conn-close no-ops.
	detached bool

	// stateReleaser invocation is per-Channel; the Layer-level field is held
	// only so newly spawned channels inherit it.

	// connInfo stable across exchanges
	envCtx envelope.EnvelopeContext
}

// StreamingResponsePredicate decides whether a Receive-direction response
// should bypass body draining. The Channel evaluates this predicate against
// the parsed response (headers + status, before the body is consumed). When
// true, the response Envelope is emitted with an empty body and the still-
// open body reader is held on the Channel for [Channel.DetachStreamingBody].
type StreamingResponsePredicate func(*parser.RawResponse) bool

// options holds Layer configuration.
type options struct {
	scheme             string
	ctx                envelope.EnvelopeContext
	bufSize            int
	bodySpillDir       string
	bodySpillThreshold int64
	maxBody            int64
	maxRawCapture      int64
	streamingDetect    StreamingResponsePredicate

	// stateReleaser is the optional pluginv2 hook invoked when a Channel
	// reaches its terminal state. Drives ReleaseTransaction(ConnID, FlowID)
	// for every envelope the Channel emitted via Next. nil = no-op.
	stateReleaser pluginv2.StateReleaser
}

// Option configures a Layer.
type Option func(*options)

// WithScheme sets the HTTP scheme ("http" or "https") for envelopes.
func WithScheme(scheme string) Option {
	return func(o *options) { o.scheme = scheme }
}

// WithEnvelopeContext sets the template EnvelopeContext stamped onto every
// envelope produced by Channels of this Layer. ReceivedAt is overwritten
// per-envelope.
func WithEnvelopeContext(ctx envelope.EnvelopeContext) Option {
	return func(o *options) { o.ctx = ctx }
}

// WithBufioSize sets the bufio.Reader buffer size. Default is 4096.
func WithBufioSize(size int) Option {
	return func(o *options) { o.bufSize = size }
}

// WithBodySpillDir sets the directory used for temp files when a body
// exceeds BodySpillThreshold. Defaults to os.TempDir() if unset.
func WithBodySpillDir(dir string) Option {
	return func(o *options) { o.bodySpillDir = dir }
}

// WithBodySpillThreshold sets the in-memory body size limit above which
// bodies spill to disk. Defaults to config.DefaultBodySpillThreshold (10 MiB).
func WithBodySpillThreshold(n int64) Option {
	return func(o *options) { o.bodySpillThreshold = n }
}

// WithMaxBodySize sets the absolute body size cap. Defaults to config.MaxBodySize
// (254 MiB). Writes exceeding this cap surface as *layer.StreamError with
// Code=layer.ErrorInternalError.
func WithMaxBodySize(n int64) Option {
	return func(o *options) { o.maxBody = n }
}

// WithMaxRawCaptureSize sets the per-message HTTP/1.x raw-bytes capture cap
// (header section + memory-mode RawBody). Defaults to
// config.DefaultMaxRawCaptureSize (2 MiB) when n is zero. Negative values
// are treated as zero.
//
// Spill-mode interaction (USK-769 / USK-772): when body spill is configured
// and the body capture sink promotes to a disk-backed BodyBuffer, the body
// cap moves to MaxBodySize and this knob no longer bounds body bytes. Header
// capture remains bounded by this knob in both modes.
func WithMaxRawCaptureSize(n int64) Option {
	return func(o *options) { o.maxRawCapture = n }
}

// WithStateReleaser injects a pluginv2.StateReleaser invoked when each
// per-exchange Channel reaches its terminal state. The release fires
// ReleaseTransaction(ConnID, FlowID) once for every envelope the Channel
// emitted via Next during its lifetime — RFC §9.3 D6 / Q26 maps the HTTP
// transaction scope to (ConnID, FlowID). Mirrors http2 / ws / httpaggregator
// shape. nil = no-op.
func WithStateReleaser(r pluginv2.StateReleaser) Option {
	return func(o *options) { o.stateReleaser = r }
}

// WithStreamingResponseDetect installs a predicate evaluated against each
// response on a Receive-direction Channel. When the predicate returns true,
// Channel.Next emits the response Envelope with an empty body and keeps the
// still-open body reader pending on the Channel; the swap orchestrator can
// then claim the body via [Channel.DetachStreamingBody] (or the Layer
// shorthand of the same name). The predicate is a no-op on Send-direction
// Channels (which read requests, not responses).
//
// This is the primitive that makes HTTP/1.x → SSE swap possible without
// blocking on a body that has no end (text/event-stream is open-ended; a
// CL-bounded drain would never return).
func WithStreamingResponseDetect(predicate StreamingResponsePredicate) Option {
	return func(o *options) { o.streamingDetect = predicate }
}

// IsSSEResponse is the canonical predicate for [WithStreamingResponseDetect].
// It returns true when rawResp's Content-Type media type is
// text/event-stream (case-insensitive; parameters such as ";charset=utf-8"
// are ignored) AND the status is 2xx — mirroring the equivalent check in
// session.UpgradeStep so detection at the http1 Channel and detection at
// the Pipeline Step agree on the same wire condition.
//
// Per RFC 8895 the canonical content-type for SSE is text/event-stream; we
// accept any 2xx status because servers occasionally use 200, 206, 207 etc.
// for streamed responses (and the wire-fidelity principle says the proxy
// reports what the server sent).
func IsSSEResponse(rawResp *parser.RawResponse) bool {
	if rawResp == nil {
		return false
	}
	if rawResp.StatusCode < 200 || rawResp.StatusCode >= 300 {
		return false
	}
	ct := rawResp.Headers.Get("Content-Type")
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "text/event-stream")
}

// New creates an HTTP/1.x Layer wrapping conn.
//
// direction determines the Layer role:
//   - envelope.Send: server-facing; spawn loop parses incoming requests and
//     yields one Channel per request via Channels().
//   - envelope.Receive: upstream-facing; callers must call OpenExchange() to
//     register a Channel, then Send a request and Next a response. For
//     back-compat with single-shot consumers (tests, MCP resend), one
//     auto-opened Channel is also yielded via Channels().
//
// streamID is the connection-level identifier returned by Channel.StreamID()
// for diagnostic correlation; envelopes themselves carry per-exchange
// StreamIDs minted by the spawn loop.
func New(conn net.Conn, streamID string, direction envelope.Direction, opts ...Option) *Layer {
	o := options{
		scheme:             "http",
		bufSize:            4096,
		bodySpillDir:       "",
		bodySpillThreshold: config.DefaultBodySpillThreshold,
		maxBody:            config.MaxBodySize,
		maxRawCapture:      config.DefaultMaxRawCaptureSize,
	}
	for _, opt := range opts {
		opt(&o)
	}

	// USK-715: bufio.Reader sits atop interruptCaptureReader rather than the
	// raw conn so a post-Interrupt SetReadDeadline race that lets a
	// successful conn.Read return WS frame bytes to bufio (where the parser
	// would consume + lose them) is mitigated by replay at DetachStream.
	captureReader := newInterruptCaptureReader(conn)
	reader := bufio.NewReaderSize(captureReader, o.bufSize)

	l := &Layer{
		conn:          conn,
		reader:        reader,
		captureReader: captureReader,
		streamID:      streamID,
		direction:     direction,
		opts:          o,
		envCtx:        o.ctx,
		chOut:         make(chan layer.Channel),
		closed:        make(chan struct{}),
		pendingNotify: make(chan struct{}, 1),
	}

	switch direction {
	case envelope.Send:
		// Pre-yield one initial Channel before the spawn loop starts so
		// legacy single-shot consumers (tests that do `<-l.Channels()`
		// without explicitly waiting for a parsed request) still see a
		// Channel immediately. The initial Channel's Next() reaches into
		// the parent Layer's reader on first call (deferred parse). The
		// spawn loop yields additional Channels (one per subsequent
		// keep-alive request) AFTER the initial has been consumed and the
		// parse handed off, so the bufio.Reader is never accessed
		// concurrently.
		initial := l.newChannelLocked()
		initial.deferredParse = true
		go func() {
			defer close(l.chOut)
			select {
			case l.chOut <- initial:
			case <-l.closed:
				return
			}
			// Wait for the initial exchange to fully terminate (session
			// closed the Channel, parse failed, or Layer-level close)
			// BEFORE entering the spawn loop. Doing so keeps the spawn
			// loop's reader access strictly sequential with the session's
			// per-exchange Channel access — necessary because HTTP/1.1 is
			// wire-serial and because Upgrade flows (WS / SSE) call
			// DetachStream synchronously on a still-open Layer; a
			// concurrently parking spawn loop on conn.Read would race
			// with the Detach handover. termDone fires from:
			//   - session.RunSession's deferred client.Close (normal end)
			//   - parser error inside nextSend's deferred parse path
			//   - Upgrade flow's DetachStream → markTerminated
			//   - Layer.Close pulling all pending Channels down
			select {
			case <-initial.termDone:
			case <-l.closed:
				return
			}
			// Skip the spawn loop on terminal conditions:
			//   - connClosed: request had Connection: close → no more reqs
			//   - isDetached: upgrade transferred conn ownership
			//   - parseFailed: parseRequest error left the bufio in a bad
			//     state; another parse would just compound the failure
			if initial.connClosed || l.isDetached() || initial.parseFailed {
				return
			}
			l.spawnLoopSend()
		}()
	case envelope.Receive:
		// For back-compat with single-shot consumers (tests, MCP resend), the
		// Layer auto-yields one Channel via Channels() so the legacy pattern
		// `ch := <-l.Channels(); ch.Send(req); ch.Next()` keeps working.
		// Multi-exchange consumers (production keep-alive) call OpenExchange
		// for each additional exchange. Channels are added to pendingQ
		// lazily inside sendRequest (atomically with the wire write under
		// writeMu) so FIFO order matches the on-wire request-send order even
		// when multiple Channels are interleaved.
		//
		// USK-730: appendPending is deferred until the consumer either Sends
		// (production path) or Next's (legacy back-compat path with no Send).
		// Eager appending here would wake spawnLoopReceive before the test
		// has finished mutating the Channel, racing tests like
		// TestChannel_NextResponse_EarlyHints_ThenFinal that pre-set
		// currentStreamID after Channels() and before Next.
		initial := l.newChannelLocked()
		go func() {
			defer close(l.chOut)
			select {
			case l.chOut <- initial:
			case <-l.closed:
				return
			}
			<-l.closed
		}()
		go l.spawnLoopReceive()
	}

	return l
}

// Channels returns a channel that yields per-exchange Channels.
//
// Send direction: the spawn loop yields one Channel per parsed request,
// closing the result when the connection EOFs or errors.
//
// Receive direction: yields one auto-opened Channel for back-compat with
// single-shot use; additional Channels must be obtained via OpenExchange().
// The result closes when Close() is called.
func (l *Layer) Channels() <-chan layer.Channel { return l.chOut }

// OpenExchange returns a new per-exchange Channel for the upstream (Receive
// direction) Layer. The caller MUST then Send a request on the returned
// Channel; the Layer's spawn loop will demultiplex the next response
// (in FIFO send order) to the Channel's Next().
//
// The returned Channel is registered in the parent Layer's response queue
// only on Send (atomically with the wire write under writeMu) so the
// receive FIFO matches the on-wire request order regardless of consumer
// interleaving.
//
// Calling OpenExchange on a Send-direction Layer returns nil — the spawn
// loop already produces Channels via Channels().
//
// After Close(), OpenExchange returns nil.
func (l *Layer) OpenExchange() layer.Channel {
	if l.direction != envelope.Receive {
		return nil
	}
	select {
	case <-l.closed:
		return nil
	default:
	}
	return l.newChannelLocked()
}

// newChannelLocked constructs a fresh per-exchange channel inheriting
// Layer-level configuration. Caller must NOT hold any of l's mutexes.
func (l *Layer) newChannelLocked() *channel {
	ch := &channel{
		layer:           l,
		streamID:        l.streamID,
		direction:       l.direction,
		scheme:          l.opts.scheme,
		ctxTmpl:         l.envCtx,
		bodyOpts:        bodyOpts{spillDir: l.opts.bodySpillDir, spillThreshold: l.opts.bodySpillThreshold, maxBody: l.opts.maxBody, maxRawCapture: l.opts.maxRawCapture},
		streamingDetect: l.opts.streamingDetect,
		stateReleaser:   l.opts.stateReleaser,
		termDone:        make(chan struct{}),
		responseReady:   make(chan responseDelivery, 4),
		readerReleased:  make(chan struct{}),
	}
	l.activeMu.Lock()
	l.active = ch
	l.activeMu.Unlock()
	return ch
}

// appendPending registers ch as awaiting its response and wakes the parser
// goroutine. Idempotent per Channel: a Channel can be registered via two
// paths (sendRequest's per-Send append, or the back-compat
// "Channels() consumed" hook for tests) and the second is a no-op.
// Receive-direction only.
func (l *Layer) appendPending(ch *channel) {
	if ch == nil {
		return
	}
	ch.pendingOnce.Do(func() {
		l.pendingMu.Lock()
		l.pendingQ = append(l.pendingQ, ch)
		l.pendingMu.Unlock()
		select {
		case l.pendingNotify <- struct{}{}:
		default:
		}
	})
}

// popPending removes and returns the head of pendingQ, or nil if empty.
func (l *Layer) popPending() *channel {
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	if len(l.pendingQ) == 0 {
		return nil
	}
	ch := l.pendingQ[0]
	l.pendingQ = l.pendingQ[1:]
	return ch
}

// peekPending returns the head of pendingQ without removing it. Used while
// streaming 1xx informational responses on the same exchange.
func (l *Layer) peekPending() *channel {
	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	if len(l.pendingQ) == 0 {
		return nil
	}
	return l.pendingQ[0]
}

// spawnLoopSend parses requests sequentially and yields one Channel per
// request to chOut. Each iteration waits for the previously yielded Channel
// to fully terminate (session.Close fires markTerminated → close(termDone))
// before parsing the next request, so the bufio.Reader and the conn are
// never accessed concurrently with a still-active session — necessary for
// safe DetachStream handover on Upgrade flows and for HTTP/1.1's
// wire-serial semantics.
//
// Exits on EOF / parse error / Connection: close / Layer detach. The
// caller is responsible for closing l.chOut after this returns (the
// deferred-parse goroutine in New() handles that via its own defer).
func (l *Layer) spawnLoopSend() {
	for {
		select {
		case <-l.closed:
			return
		default:
		}

		// Build a fresh Channel before the parse so the Channel can be the
		// receiver of any error envelope (terminal state propagation).
		ch := l.newChannelLocked()
		env, perr := ch.parseRequest()
		if perr != nil {
			ch.markTerminated(perr)
			if errors.Is(perr, io.EOF) {
				return
			}
			// Yield the channel so consumers see the terminal state, then
			// exit (the conn is unlikely to recover from a parse error).
			select {
			case l.chOut <- ch:
			case <-l.closed:
			}
			return
		}
		ch.queuedEnv = env

		select {
		case l.chOut <- ch:
		case <-l.closed:
			return
		}

		// Wait for the yielded Channel's session to fully terminate
		// before parsing the next keep-alive request. This serializes
		// the spawn loop with the consumer's session loop and avoids
		// concurrent access to the bufio.Reader / conn during Upgrade
		// (WS / SSE) DetachStream handovers.
		select {
		case <-ch.termDone:
		case <-l.closed:
			return
		}

		// USK-655: if the just-completed exchange triggered an Upgrade
		// (DetachStream → markDetached), the bufio.Reader / conn are now
		// owned by the successor Layer; we must not parse another
		// request.
		if l.isDetached() {
			return
		}
		// connection-close honored from the parsed request: stop spawning
		// because the peer will close the wire after this response.
		if ch.connClosed {
			return
		}
	}
}

// spawnLoopReceive parses responses and demultiplexes them in FIFO order to
// the head of pendingQ. Handles 1xx informational responses by leaving the
// head Channel in place across multiple deliveries until a final response
// (status >= 200) arrives.
func (l *Layer) spawnLoopReceive() {
	for {
		select {
		case <-l.closed:
			return
		case <-l.pendingNotify:
		}

		// Drain all currently pending exchanges. Each iteration parses one
		// response; on 1xx we keep the head, on final we pop.
		for {
			head := l.peekPending()
			if head == nil {
				break
			}

			// USK-715 / detach hygiene: if the conn was reclaimed, fail any
			// still-pending channels with EOF.
			if l.isDetached() {
				for ch := l.popPending(); ch != nil; ch = l.popPending() {
					ch.deliverResponse(nil, io.EOF)
				}
				return
			}

			env, isInformational, perr := head.parseResponse()
			if perr != nil {
				// Drain all remaining pending channels with the terminal err.
				for ch := l.popPending(); ch != nil; ch = l.popPending() {
					ch.deliverResponse(nil, perr)
				}
				return
			}
			head.deliverResponse(env, nil)
			if !isInformational {
				_ = l.popPending()
				if head.connClosed || l.isDetached() {
					// Peer signalled connection-close; remaining pendings are
					// futile.
					for ch := l.popPending(); ch != nil; ch = l.popPending() {
						ch.deliverResponse(nil, io.EOF)
					}
					return
				}
			}
		}
	}
}

// isDetached reports whether DetachStream / DetachStreamingBody transferred
// conn ownership to a successor Layer.
func (l *Layer) isDetached() bool {
	l.activeMu.RLock()
	defer l.activeMu.RUnlock()
	return l.detached
}

// Close closes the underlying connection (unless DetachStream transferred
// ownership) and signals all live Channels and the spawn loop to terminate.
func (l *Layer) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)

		l.activeMu.Lock()
		detached := l.detached
		l.activeMu.Unlock()
		if !detached {
			err = l.conn.Close()
		}

		// Mark every pending Channel terminated so observers parked on
		// Closed() unblock.
		l.pendingMu.Lock()
		pending := l.pendingQ
		l.pendingQ = nil
		l.pendingMu.Unlock()
		for _, ch := range pending {
			// Best-effort wake of any Next() parked on responseReady. Use
			// closeResponseReady (sync.Once) instead of a raw send so a
			// concurrent close from spawnLoopReceive (or a prior Channel
			// .Close) does not turn into a "send on closed channel" panic.
			ch.markTerminated(io.EOF)
			ch.closeResponseReady()
		}
		l.activeMu.RLock()
		active := l.active
		l.activeMu.RUnlock()
		if active != nil {
			active.markTerminated(io.EOF)
		}
	})
	return err
}

// EnvelopeContextTemplate returns a value copy of the EnvelopeContext stamped
// onto envelopes produced by this Layer. Used by the proxybuild h1 redial
// chain (USK-998) to give a freshly redialed Layer the same ConnID /
// TargetHost / TLS provenance for wire-log continuity. Mirrors
// [http2.Layer.EnvelopeContextTemplate].
func (l *Layer) EnvelopeContextTemplate() envelope.EnvelopeContext {
	return l.envCtx
}

// HealthCheck performs a non-blocking peek on the underlying conn to detect
// a stale upstream connection (USK-998). It is intended for the
// Receive-direction (upstream-facing) Layer when no exchange is currently
// in flight — typically called by the proxybuild h1 redial chain inside
// the per-exchange dial closure, before the next request is registered.
//
// Returns nil when the connection is alive (or when this Layer is
// Send-direction, or when pendingQ is non-empty — in which case
// spawnLoopReceive will observe any FIN naturally as part of the next
// parseResponse). Returns a non-nil error when the connection is stale
// (peer-closed, RST, or any non-timeout read error). The caller should
// Close this Layer and redial when stale.
//
// Mechanism: a 1ms read deadline is set on the conn, then a one-byte
// peek read runs against it. The 1ms window is long enough for Go's
// netpoller cycle to surface a peer FIN / RST that the kernel has
// already queued on the socket, but short enough that the proactive
// probe does not visibly stall the per-exchange dial when the connection
// is healthy. The deadline is restored on defer so subsequent legitimate
// reads from spawnLoopReceive are not pre-poisoned. Errors classified:
//   - net.Error.Timeout / os.ErrDeadlineExceeded → alive (no FIN observed)
//   - any other read error (io.EOF / net.ErrClosed / ECONNRESET / …) → stale
//   - n > 0 (server wrote a byte during idle) → stale; the surplus byte is
//     dropped (see Trade-off below)
//
// Invariant: the caller must arrange that no in-flight exchange is
// registered on this Layer when calling HealthCheck. The proxybuild h1
// chain calls it only from the dial closure, before any Send is dispatched
// for the new exchange. As a defence in depth, if pendingQ is non-empty
// HealthCheck short-circuits with nil (treating the connection as alive)
// rather than disrupting an in-flight exchange.
//
// Concurrency: HealthCheck holds pendingMu for the duration of the read.
// spawnLoopReceive parks on pendingNotify (without holding pendingMu)
// while pendingQ is empty, so the deadline-driven read does not race
// with the parser goroutine in the expected use case.
//
// Trade-off (wire fidelity): if the upstream wrote one or more bytes
// during idle when pendingQ is empty, those bytes cannot be attributed to
// any HTTP transaction. RFC 9112 forbids idle keep-alive connections from
// carrying data between exchanges, so any such byte is either a
// wire-protocol violation by the peer or a TLS close_notify alert. Either
// way the connection is being terminated, so HealthCheck treats this as a
// stale signal and the surplus byte is dropped — accepting a single-byte
// fidelity loss in exchange for not propagating a corrupt connection into
// the next exchange.
func (l *Layer) HealthCheck() error {
	if l == nil {
		return nil
	}
	// Send-direction (client-facing) is driven by spawnLoopSend which is
	// always actively reading; the proactive peek does not apply.
	if l.direction != envelope.Receive {
		return nil
	}

	// Already-closed Layers are stale by definition.
	select {
	case <-l.closed:
		return net.ErrClosed
	default:
	}

	l.pendingMu.Lock()
	defer l.pendingMu.Unlock()
	if len(l.pendingQ) > 0 {
		// In-flight exchange: spawnLoopReceive is responsible for observing
		// FIN as part of its parseResponse. Treat as alive — the caller
		// must not call HealthCheck mid-exchange.
		return nil
	}

	if l.conn == nil {
		return nil
	}

	// 1ms deadline lets the netpoller surface a queued FIN/RST without
	// stalling the dial on a healthy conn (the proxy is already paying
	// for the round trip to upstream a moment later). Using a strictly
	// past deadline (time.Now()) would short-circuit before the runtime
	// could observe the kernel's RDHUP state on some platforms.
	_ = l.conn.SetReadDeadline(time.Now().Add(healthCheckProbeDeadline))
	defer func() { _ = l.conn.SetReadDeadline(time.Time{}) }()

	var buf [1]byte
	n, err := l.conn.Read(buf[:])
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return nil
		}
		return err
	}
	if n > 0 {
		// RFC 9112 violation by the upstream, or TLS alert. Either way
		// the connection is unusable; report stale and drop the byte.
		return fmt.Errorf("http1: unexpected idle byte from upstream (n=%d)", n)
	}
	return nil
}

// activeChannel returns the most-recently-yielded Channel for Layer-level
// upgrade primitives. Returns nil if no Channel has been yielded yet.
func (l *Layer) activeChannel() *channel {
	l.activeMu.RLock()
	defer l.activeMu.RUnlock()
	return l.active
}

// markDetached transfers conn ownership to a successor Layer. After this
// call, Close becomes a conn-close no-op and the spawn loop exits.
func (l *Layer) markDetached() {
	l.activeMu.Lock()
	l.detached = true
	l.activeMu.Unlock()
	// Wake any parker (spawn loops, pending Channel Next).
	select {
	case l.pendingNotify <- struct{}{}:
	default:
	}
}

// DetachStream tears down the HTTP/1 layer after an Upgrade response and
// returns the buffered reader, writer, and underlying closer so the next
// layer (WebSocket) can be constructed on top of the same wire.
//
// Forwards to the active Channel (the one that just emitted the 101). After
// this call, the Layer becomes unusable and the spawn loop exits.
//
// Returns a sentinel error if no active Channel exists or if DetachStream
// was already called.
func (l *Layer) DetachStream() (io.Reader, io.Writer, io.Closer, error) {
	l.activeMu.RLock()
	if l.detached {
		l.activeMu.RUnlock()
		return nil, nil, nil, errors.New("http1: stream already detached")
	}
	active := l.active
	l.activeMu.RUnlock()
	if active == nil {
		return nil, nil, nil, errors.New("http1: no active channel to detach")
	}
	return active.detachStream()
}

// Interrupt forwards to the active Channel's Interrupt method.
//
// See channel.Interrupt for the mechanism. Returns nil if no active Channel
// exists or after DetachStream.
func (l *Layer) Interrupt() error {
	if l.isDetached() {
		return nil
	}
	if active := l.activeChannel(); active != nil {
		return active.Interrupt()
	}
	if l.conn == nil {
		return nil
	}
	return l.conn.SetReadDeadline(time.Now())
}

// PrepareSwap forwards to the active Channel's PrepareSwap method. The
// session orchestrator calls this BEFORE Send(101) when a Pipeline
// UpgradeStep has flipped the upgrade notice.
//
// No-op after DetachStream or when no Channel is active.
func (l *Layer) PrepareSwap() {
	if l.isDetached() {
		return
	}
	if active := l.activeChannel(); active != nil {
		active.PrepareSwap()
	}
}

// DetachStreamingBody forwards to the active Channel's DetachStreamingBody.
// Pre-condition: the most recent Channel.Next() must have emitted a response
// Envelope whose body draining was suppressed by [WithStreamingResponseDetect].
//
// Variadic StreamingBodyOption values configure optional per-detach
// behaviour; today the only supported option is WithChunkRecordCallback
// (USK-895). Passing no options preserves the pre-USK-895 contract
// verbatim.
func (l *Layer) DetachStreamingBody(opts ...StreamingBodyOption) (io.ReadCloser, error) {
	if l.isDetached() {
		return nil, errors.New("http1: stream already detached")
	}
	active := l.activeChannel()
	if active == nil {
		return nil, errors.New("http1: no active channel for streaming body")
	}
	cfg := &streamingBodyOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	return active.detachStreamingBody(cfg)
}

// streamingBodyOptions collects values supplied to DetachStreamingBody via
// the variadic StreamingBodyOption mechanism. Defined as a struct so future
// fields can be added without breaking existing callers, mirroring the
// USK-889 detachConfig precedent in internal/layer/http2.
type streamingBodyOptions struct {
	// chunkRecordCB is the optional synchronous callback that fires for
	// every chunk boundary on the SSE-over-h1-chunked detach path. nil
	// when no caller installed the option. See WithChunkRecordCallback
	// for the contract.
	chunkRecordCB func(chunkRaw []byte)
	// chunkRecordMaxBytes is the per-chunk wire-bytes cap threaded into
	// the parser. Zero means MaxRawCaptureSize at parse time.
	chunkRecordMaxBytes int64
}

// StreamingBodyOption configures DetachStreamingBody. The variadic-option
// shape lets future per-call configuration land without breaking existing
// callers, mirroring the USK-802 / USK-889 Option precedents elsewhere in
// the codebase.
type StreamingBodyOption func(*streamingBodyOptions)

// WithChunkRecordCallback installs a synchronous per-chunk record
// callback invoked from the parser's dechunked-read loop for every chunk
// boundary on the SSE-over-h1-chunked detach path (USK-895). The callback
// receives the full on-wire chunk bytes: chunk-size line (including any
// chunk-extension) + chunk-data + trailing CRLF. The terminal "0\r\n…\r\n"
// chunk (with any trailer section) is emitted as its own callback.
//
// Timing: the callback fires AFTER the chunk has been fully consumed from
// the wire — the recorder snapshot reflects the wire observation, not the
// post-delivery state the SSE event-boundary reader will see. This matches
// the USK-889 pattern (h2 frame callback fires BEFORE pipe.Write) in
// spirit: the recorder learns about the chunk as soon as the wire view is
// complete and irreversible.
//
// Contract:
//   - cb MUST NOT block. The chunk-record callback fires synchronously on
//     the consumer's read goroutine inside the parser's dechunkedReader.
//     Any block here stalls the streaming body relay carrying the
//     dechunked payload to the SSE event-boundary reader. If the
//     orchestrator's recording path needs to perform IO that may block,
//     it must dispatch its own goroutine inside cb.
//   - cb receives a fresh defensive copy of the chunk bytes. The slice may
//     be stashed on an envelope without coordinating with the parser.
//   - maxBytes caps the wire bytes captured for a single chunk. Zero means
//     the parser default (MaxRawCaptureSize). Over-cap chunks are skipped
//     (no callback fired) — Principle #5 / USK-893 fitness check defence
//     against a malicious upstream sending a 4 GiB single chunk.
//
// On the non-chunked SSE path (HTTP/1.0 / Connection: close / Content-
// Length) the option is a no-op: there are no chunks to record.
//
// Passing a nil cb is equivalent to not supplying the option at all.
func WithChunkRecordCallback(cb func(chunkRaw []byte), maxBytes int64) StreamingBodyOption {
	return func(o *streamingBodyOptions) {
		o.chunkRecordCB = cb
		o.chunkRecordMaxBytes = maxBytes
	}
}

// streamingBodyCloser pairs the parser's body reader with the conn so the
// swap orchestrator can dispose of the wire by closing the body.
type streamingBodyCloser struct {
	r    io.Reader
	conn net.Conn
}

func (s *streamingBodyCloser) Read(p []byte) (int, error) { return s.r.Read(p) }
func (s *streamingBodyCloser) Close() error               { return s.conn.Close() }

// responseDelivery carries the parser result from spawnLoopReceive to a
// pending Channel's Next() goroutine.
type responseDelivery struct {
	env *envelope.Envelope
	err error
}

// ctxOrBackground is a tiny helper: returns ctx if non-nil, else
// context.Background. Used to keep the parser's cancellation surface
// uniform regardless of whether the caller threaded a ctx.
func ctxOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
