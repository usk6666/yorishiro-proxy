package http1

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// opaqueHTTP1 holds Layer-specific data stored in Envelope.Opaque.
// Pipeline Steps must not type-assert on this.
type opaqueHTTP1 struct {
	rawReq         *parser.RawRequest
	rawResp        *parser.RawResponse
	origKV         []envelope.KeyValue // header snapshot at Next() time
	origBody       []byte              // body snapshot at Next() time (nil for buffer-backed)
	origBodyBuffer *bodybuf.BodyBuffer // buffer-backed body snapshot (nil for memory-backed)
}

// bodyOpts are the per-channel body assembly options inherited from the Layer.
type bodyOpts struct {
	spillDir       string
	spillThreshold int64
	maxBody        int64
	// maxRawCapture caps memory-mode raw-bytes capture (header + body).
	// Zero means use parser.MaxRawCaptureSize / config.DefaultMaxRawCaptureSize.
	// Spill-mode body capture honors maxBody instead.
	maxRawCapture int64
}

// channel implements layer.Channel for one HTTP/1.x request-response exchange.
// Multiple exchanges on a keep-alive connection produce multiple channel
// instances, all sharing the parent Layer's net.Conn / bufio.Reader / writer.
type channel struct {
	layer     *Layer
	streamID  string // connection-level identifier for diagnostics
	direction envelope.Direction
	scheme    string
	ctxTmpl   envelope.EnvelopeContext
	bodyOpts  bodyOpts

	// streamingDetect, when non-nil and direction == Receive, decides
	// whether to bypass body draining for a parsed response. See
	// [WithStreamingResponseDetect] / [Channel.DetachStreamingBody].
	streamingDetect StreamingResponsePredicate

	// streamingBody holds the pending response body io.Reader after the
	// predicate matched. detachStreamingBody claims it.
	streamingBody io.Reader

	// queuedEnv is the request envelope pre-parsed by the spawn loop for
	// Send direction (when deferredParse=false). The first Next() call
	// drains it; subsequent calls return io.EOF.
	queuedEnv *envelope.Envelope
	queuedErr error // terminal error to surface on first Next (Send direction)
	delivered bool  // Send direction only: Next already returned queuedEnv

	// deferredParse indicates this Channel was pre-yielded by the Layer
	// without a pre-parsed envelope. On the first Next() call the Channel
	// itself does the parser.ParseRequest call, then signals readerReleased
	// so the parent Layer's spawn loop can take over for subsequent
	// keep-alive requests. Used only for the auto-yielded initial Channel
	// of Send-direction Layers (test/MCP back-compat).
	deferredParse bool

	// readerReleased is closed when this Channel relinquishes exclusive
	// access to the parent Layer's bufio.Reader — either after a deferred
	// Next() returns, or on Close. Only meaningful when deferredParse=true.
	readerReleased    chan struct{}
	readerReleaseOnce sync.Once

	// parseFailed is set when the deferred-parse Next() returned a
	// parser error (vs successful parse + later Close). The deferred-parse
	// goroutine in Layer.New() reads this to decide whether to enter
	// spawnLoopSend; entering after a parse error would just compound
	// the failure on a wedged bufio.Reader.
	parseFailed bool

	// responseReady carries response deliveries from spawnLoopReceive to
	// Next() for the Receive direction. Buffered to allow 1xx + final to
	// queue without blocking the spawn loop. Closed when no more responses
	// will be delivered (final received, EOF, error).
	//
	// USK-798: responseReadyMu serializes close(responseReady) against sends
	// from spawnLoopReceive (deliverResponse). The producer holds it for the
	// duration of a send-select; closeResponseReady acquires it before closing.
	// Close() sequences markTerminated → closeResponseReady so a producer
	// blocked in the send-select unblocks via the termDone case and releases
	// responseReadyMu before close runs — no deadlock. Mirrors the HTTP/2
	// recvMu pattern (USK-739/USK-740).
	responseReady       chan responseDelivery
	responseReadyMu     sync.Mutex
	responseReadyClosed atomic.Bool
	closeOnce           sync.Once

	// Per-exchange state.
	currentStreamID string // minted in parseRequest / inherited via response delivery
	sequence        int    // 0=request; 1+=responses (1xx-aware)
	connClosed      bool   // peer signalled Connection: close on this exchange

	// USK-721: priorRespWasInformational tracks whether the previous response
	// emitted on this Channel was 1xx, so the next response advances Sequence.
	priorRespWasInformational bool

	// stateReleaser, when non-nil, is invoked once per emitted FlowID at
	// terminal state (RFC §9.3 D6 / Q26 — HTTP transaction scope).
	stateReleaser pluginv2.StateReleaser

	// emittedFlowIDs accumulates the FlowID of every envelope this Channel
	// emitted via Next. Drained by releaseTransactionStates at termination.
	emittedFlowIDs []string

	// Terminal-state tracking.
	termMu   sync.Mutex
	termErr  error
	termOnce sync.Once
	termDone chan struct{}

	// pendingOnce makes appendPending idempotent per Channel. The two
	// registration paths (Send-time appendPending, and the back-compat
	// "Channels() consumed" hook for tests) must not double-append.
	pendingOnce sync.Once
}

// StreamID returns the connection-level identifier for this channel.
func (c *channel) StreamID() string { return c.streamID }

// Interrupt unblocks any goroutine currently parked inside the parent
// Layer's parser on the underlying conn. Mechanism is
// conn.SetReadDeadline(time.Now()) — the in-flight Read inside
// parser.ParseRequest → bufio.Reader → conn.Read surfaces
// os.ErrDeadlineExceeded so the parse returns and the session-level
// upgrade-pending precedence rule maps the parse-error to ErrUpgradePending.
//
// USK-715: Interrupt also enables a side-buffer capture on the conn read
// wrapper so that any post-Upgrade bytes the kernel hands the in-flight
// conn.Read syscall — between the Send(101) returning and the read deadline
// taking effect — are recorded for replay by [channel.detachStream].
//
// Idempotent.
func (c *channel) Interrupt() error {
	if c.layer == nil || c.layer.conn == nil {
		return nil
	}
	if c.layer.captureReader != nil {
		c.layer.captureReader.StartCapture()
	}
	return c.layer.conn.SetReadDeadline(time.Now())
}

// PrepareSwap enables the post-Upgrade side-buffer capture WITHOUT arming
// the read deadline. The session orchestrator calls this BEFORE Send(101)
// when a Pipeline UpgradeStep has flipped the upgrade notice.
//
// Idempotent.
func (c *channel) PrepareSwap() {
	if c.layer != nil && c.layer.captureReader != nil {
		c.layer.captureReader.StartCapture()
	}
}

// detachStream tears down the HTTP/1 layer after an Upgrade response and
// returns the buffered reader, writer, and underlying closer for the
// successor (ws) Layer. Marks the parent Layer detached so its spawn loop
// exits and Close becomes a conn-close no-op.
//
// USK-715: drains any post-Interrupt capture and prepends to the returned
// reader to rebuild wire-order under a slow CI runner race.
func (c *channel) detachStream() (io.Reader, io.Writer, io.Closer, error) {
	if c.layer == nil || c.layer.conn == nil {
		return nil, nil, nil, errors.New("http1: channel has no underlying conn")
	}
	c.layer.markDetached()
	// Clear any past-deadline a prior Interrupt installed.
	_ = c.layer.conn.SetReadDeadline(time.Time{})
	c.markTerminated(io.EOF)

	// USK-715: drain capture and replay any "lost" bytes the parser pulled
	// from bufio and discarded on parse failure.
	var reader io.Reader = c.layer.reader
	if c.layer.captureReader != nil {
		captured := c.layer.captureReader.Drain()
		if n := len(captured); n > 0 {
			buffered := c.layer.reader.Buffered()
			if buffered < n {
				lost := captured[:n-buffered]
				reader = io.MultiReader(bytes.NewReader(lost), c.layer.reader)
			}
		}
	}
	return reader, c.layer.conn, c.layer.conn, nil
}

// detachStreamingBody hands the still-open response body io.ReadCloser to
// the swap orchestrator. Pre-condition: the most recent Channel.Next()
// emitted a response Envelope whose body draining was suppressed by the
// configured [WithStreamingResponseDetect] predicate.
func (c *channel) detachStreamingBody() (io.ReadCloser, error) {
	if c.layer == nil {
		return nil, errors.New("http1: channel has no parent layer")
	}
	if c.streamingBody == nil {
		return nil, errors.New("http1: no streaming body pending (predicate did not match or channel never read)")
	}
	body := c.streamingBody
	c.streamingBody = nil
	c.layer.markDetached()
	_ = c.layer.conn.SetReadDeadline(time.Time{})
	if c.layer.captureReader != nil {
		_ = c.layer.captureReader.Drain()
	}
	c.markTerminated(io.EOF)
	return &streamingBodyCloser{r: body, conn: c.layer.conn}, nil
}

// Next reads the next HTTP message from the wire and returns it as an
// Envelope.
//
// Send direction: returns the request envelope queued by the spawn loop on
// the first call; subsequent calls return io.EOF (each Channel handles
// exactly one exchange).
//
// Receive direction: returns the next response envelope delivered by the
// spawn loop. Multiple calls may return 1xx informationals before the final
// response; after the final response (or on error/EOF) subsequent calls
// return io.EOF.
func (c *channel) Next(ctx context.Context) (*envelope.Envelope, error) {
	switch c.direction {
	case envelope.Send:
		return c.nextSend(ctx)
	case envelope.Receive:
		return c.nextReceive(ctx)
	default:
		err := fmt.Errorf("http1: unknown direction %d", c.direction)
		c.markTerminated(err)
		return nil, err
	}
}

func (c *channel) nextSend(_ context.Context) (*envelope.Envelope, error) {
	// USK-730: a second Next on a per-exchange Channel after the request was
	// already returned must NOT fire markTerminated. The session loop calls
	// Next in a loop and treats EOF as "consumer is done reading from this
	// Channel for this exchange"; firing markTerminated here would close
	// termDone before the session has decided whether the exchange ended
	// normally (defer client.Close → spawn next request) or escalated to an
	// Upgrade (runUpgradeWS → DetachStream → ws.Layer takes the conn). The
	// premature termDone wakes the spawn-loop goroutine to parse another
	// request from the bufio.Reader, racing the post-Upgrade ws.Layer reads.
	// termDone is now fired exclusively by Close / detachStream / Layer.Close
	// / parse error — i.e., by the consumer or by an actual terminal event.

	// Deferred-parse path: the back-compat auto-yielded initial Channel
	// did not have a pre-parsed envelope. Parse synchronously now, then
	// release the parent Layer's reader so the spawn loop can take over
	// for additional keep-alive requests.
	if c.deferredParse {
		if c.delivered {
			return nil, io.EOF
		}
		env, err := c.parseRequest()
		if err != nil {
			c.parseFailed = true
		}
		c.releaseReader()
		if err != nil {
			c.markTerminated(err)
			return nil, err
		}
		c.delivered = true
		return env, nil
	}

	if c.queuedErr != nil {
		err := c.queuedErr
		c.queuedErr = nil
		return nil, err
	}
	if c.delivered {
		return nil, io.EOF
	}
	if c.queuedEnv == nil {
		// Defensive — spawn loop should always set queuedEnv before yielding.
		// markTerminated is safe here because reaching this branch means the
		// spawn loop yielded a Channel without a queuedEnv (parse error path
		// already markTerminated'd; this is fail-loud for any future bug that
		// yields without queuedEnv or queuedErr).
		c.markTerminated(io.EOF)
		return nil, io.EOF
	}
	c.delivered = true
	return c.queuedEnv, nil
}

// releaseReader signals to the parent Layer's deferred-parse goroutine that
// this Channel has finished accessing the bufio.Reader and the spawn loop
// can take over. Idempotent.
func (c *channel) releaseReader() {
	if c.readerReleased == nil {
		return
	}
	c.readerReleaseOnce.Do(func() {
		close(c.readerReleased)
	})
}

func (c *channel) nextReceive(ctx context.Context) (*envelope.Envelope, error) {
	ctx = ctxOrBackground(ctx)
	// USK-730: legacy single-shot consumers (tests, MCP resend) call Next
	// without first calling Send. Register this Channel in the parent Layer's
	// pendingQ so spawnLoopReceive parses the next response into it. The
	// appendPending is idempotent per Channel (sync.Once-guarded) so a later
	// Send-driven append (production sendRequest) is a no-op.
	if c.layer != nil {
		c.layer.appendPending(c)
	}
	select {
	case d, ok := <-c.responseReady:
		if !ok {
			c.markTerminated(io.EOF)
			return nil, io.EOF
		}
		if d.err != nil {
			c.markTerminated(d.err)
			return nil, d.err
		}
		return d.env, nil
	case <-ctx.Done():
		err := ctx.Err()
		c.markTerminated(err)
		return nil, err
	}
}

// deliverResponse routes a parsed response envelope (or error) to this
// Channel's Next() call. Called by the parent Layer's spawnLoopReceive.
// On nil err with 1xx status, the head Channel stays in pendingQ; on final
// response or error, this is the last delivery and responseReady is closed
// after the send.
//
// USK-798 race-safety: Channel.Close (via Layer.Close or session.go's defer)
// may attempt to close c.responseReady concurrently with this send. The
// previous recover()-based guard suppressed the resulting panic but did not
// eliminate the underlying memory data race that -race flags. We now hold
// c.responseReadyMu around the send-select and re-check c.responseReadyClosed
// under the lock so close-vs-send is mutually exclusive. Close() sequences
// markTerminated (closes termDone) → closeResponseReady (acquires the mutex)
// so any send-select blocked here observes termDone first, releases the
// lock, and lets close proceed — no deadlock. Mirrors HTTP/2 deliverEnvelope
// (USK-739/USK-740).
func (c *channel) deliverResponse(env *envelope.Envelope, err error) {
	if err != nil {
		c.responseReadyMu.Lock()
		if c.responseReadyClosed.Load() {
			c.responseReadyMu.Unlock()
			return
		}
		select {
		case c.responseReady <- responseDelivery{err: err}:
		default:
		}
		c.responseReadyMu.Unlock()
		c.closeResponseReady()
		return
	}
	c.responseReadyMu.Lock()
	// Re-check under the lock; Close() may have closed responseReady between
	// the producer's entry and lock acquisition.
	if c.responseReadyClosed.Load() {
		c.responseReadyMu.Unlock()
		return
	}
	select {
	case c.responseReady <- responseDelivery{env: env}:
	case <-c.termDone:
		c.responseReadyMu.Unlock()
		return
	}
	c.responseReadyMu.Unlock()
	if env == nil {
		c.closeResponseReady()
		return
	}
	if msg, ok := env.Message.(*envelope.HTTPMessage); ok {
		if msg.Status < 100 || msg.Status >= 200 {
			c.closeResponseReady()
		}
	}
}

// closeResponseReady idempotently closes c.responseReady. Acquires
// c.responseReadyMu so the close cannot race deliverResponse's send.
//
// USK-798: callers MUST close termDone (via markTerminated) before invoking
// closeResponseReady — otherwise a producer parked on the send-select can
// hold responseReadyMu indefinitely (it has no other unblock signal once
// the buffer is full). Close() and Layer.Close obey this ordering.
func (c *channel) closeResponseReady() {
	c.responseReadyMu.Lock()
	defer c.responseReadyMu.Unlock()
	c.closeOnce.Do(func() {
		c.responseReadyClosed.Store(true)
		close(c.responseReady)
	})
}

// Send writes an Envelope to the wire under the parent Layer's writeMu so
// concurrent Sends across Channels never interleave (HTTP/1.1 wire
// serialization, RFC 9112 §9.5).
//
// For direction=Send (server-facing), it serializes responses.
// For direction=Receive (upstream-facing), it serializes requests.
func (c *channel) Send(ctx context.Context, env *envelope.Envelope) error {
	_ = ctxOrBackground(ctx)

	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		return fmt.Errorf("http1: Send requires *HTTPMessage, got %T", env.Message)
	}
	if c.layer == nil {
		return errors.New("http1: channel has no parent layer")
	}

	c.layer.writeMu.Lock()
	defer c.layer.writeMu.Unlock()

	switch c.direction {
	case envelope.Send:
		// Server-facing layer: Next parsed a request, Send writes the response.
		return c.sendResponse(msg, env)
	case envelope.Receive:
		// Upstream-facing layer: Next parses responses, Send writes the request.
		return c.sendRequest(msg, env)
	default:
		return fmt.Errorf("http1: unknown direction %d", c.direction)
	}
}

// Close marks this exchange's Channel terminated. The underlying conn is
// owned by the parent Layer and survives Channel.Close so the next
// exchange's Channel can keep using it.
//
// USK-798 ordering: markTerminated MUST run before closeResponseReady so
// any producer (spawnLoopReceive's deliverResponse) blocked in the
// send-select observes termDone, releases responseReadyMu, and then lets
// closeResponseReady acquire the mutex to close the channel. Reversing
// this order would deadlock against a full responseReady buffer.
func (c *channel) Close() error {
	c.markTerminated(io.EOF)
	c.closeResponseReady()
	c.releaseReader()
	return nil
}

// Closed returns a channel closed when this Channel has reached its terminal
// state. See layer.Channel for the contract.
func (c *channel) Closed() <-chan struct{} { return c.termDone }

// Err returns the terminal error. See layer.Channel for the contract.
func (c *channel) Err() error {
	c.termMu.Lock()
	defer c.termMu.Unlock()
	return c.termErr
}

// markTerminated stores err (first-writer-wins) and closes termDone exactly
// once. Callers must guarantee err is non-nil.
//
// On the first call we also fire pluginv2 state release in two waves:
// per-transaction first (via releaseTransactionStates — one fire per
// emitted FlowID), then per-stream (via releaseStreamState — one fire
// for the Channel's minted StreamID). The stream release is gated to
// the Send-direction owner and suppressed when the Layer has been
// detached so ownership of the StreamID transfers to the post-swap
// Layer (USK-853 / RFC §9.3 D6).
func (c *channel) markTerminated(err error) {
	c.termMu.Lock()
	if c.termErr == nil {
		c.termErr = err
	}
	c.termMu.Unlock()
	c.termOnce.Do(func() {
		close(c.termDone)
		c.releaseTransactionStates()
		c.releaseStreamState()
	})
}

// recordEmittedFlowID appends flowID to the set of envelopes the Channel
// emitted via Next.
func (c *channel) recordEmittedFlowID(flowID string) {
	if flowID == "" {
		return
	}
	c.termMu.Lock()
	c.emittedFlowIDs = append(c.emittedFlowIDs, flowID)
	c.termMu.Unlock()
}

// releaseTransactionStates fires the configured pluginv2.StateReleaser for
// every FlowID this Channel emitted.
func (c *channel) releaseTransactionStates() {
	if c.stateReleaser == nil {
		return
	}
	if c.ctxTmpl.ConnID == "" {
		return
	}
	c.termMu.Lock()
	if len(c.emittedFlowIDs) == 0 {
		c.termMu.Unlock()
		return
	}
	snapshot := make([]string, len(c.emittedFlowIDs))
	copy(snapshot, c.emittedFlowIDs)
	c.termMu.Unlock()

	connID := c.ctxTmpl.ConnID
	for _, flowID := range snapshot {
		c.stateReleaser.ReleaseTransaction(connID, flowID)
	}
}

// releaseStreamState fires the configured pluginv2.StateReleaser for the
// Channel's minted per-exchange StreamID exactly once at terminal state
// (USK-853). The HTTP/1.x Channel is the canonical owner of
// currentStreamID, so the release here mirrors the http2 Channel pattern
// at internal/layer/http2/channel.go:157.
//
// Gates (USK-853 design D3/D4/D5):
//   - Send-direction only: avoids a double-fire across the proxy
//     round-trip; the Receive-direction Channel inherits a peer's
//     StreamID rather than minting its own.
//   - Suppress when the Layer is detached: post-Upgrade ownership of
//     the StreamID transferred to the successor (ws / sse) Layer, which
//     fires its own release at terminal — Option (a) per Issue
//     acceptance #3.
//   - Empty ConnID / empty StreamID short-circuit (scopeStore.release is
//     idempotent on these, but the Layer should not issue spurious
//     calls).
func (c *channel) releaseStreamState() {
	if c.stateReleaser == nil {
		return
	}
	if c.direction != envelope.Send {
		return
	}
	if c.layer != nil && c.layer.isDetached() {
		return
	}
	if c.currentStreamID == "" || c.ctxTmpl.ConnID == "" {
		return
	}
	c.stateReleaser.ReleaseStream(c.ctxTmpl.ConnID, c.currentStreamID)
}

// --- Parse implementations (called by Layer.spawnLoop) ---

// parseRequest reads one HTTP request from the parent Layer's bufio.Reader
// and returns the envelope. Sets c.connClosed if the request had
// Connection: close.
func (c *channel) parseRequest() (*envelope.Envelope, error) {
	rawReq, err := parser.ParseRequestWithOptions(c.layer.reader, parser.ParseOptions{
		MaxRawCapture: c.bodyOpts.maxRawCapture,
	})
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("http1: parse request: %w", err)
	}

	// Mint per-exchange identity.
	c.currentStreamID = uuid.New().String()
	c.sequence = 0

	path, rawQuery, authority := parseRequestURI(rawReq.RequestURI, rawReq.Headers)

	// USK-833: stash the wire-observed request line on the per-Channel ctxTmpl
	// so the response envelope built by parseResponse can carry forward the
	// paired request's path/method/query for direction:"both" rule matching.
	// One HTTP/1.x Channel handles exactly one exchange, so this is safe to
	// overwrite without coordination.
	c.ctxTmpl.RequestPath = path
	c.ctxTmpl.RequestMethod = rawReq.Method
	c.ctxTmpl.RequestRawQuery = rawQuery

	// USK-772: configure raw-body disk-spill on the parser body reader before
	// drain so chunked / identity bodies above BodySpillThreshold are captured
	// to a temp file rather than truncated at MaxRawCaptureSize.
	configureRawBodySpill(rawReq.Body, c.bodyOpts)

	bb, body, err := readBodyWithThreshold(rawReq.Body,
		c.bodyOpts.spillDir, c.bodyOpts.spillThreshold, c.bodyOpts.maxBody)
	if err != nil {
		// USK-772: the parser body reader's bodyCaptureSink may have
		// promoted to a temp file before readBodyWithThreshold tripped its
		// cap. Release that orphan so it is not left for the startup
		// orphan sweep.
		releaseOrphanRawBodyBuffer(rawReq.Body)
		return nil, fmt.Errorf("http1: read request body: %w", err)
	}
	defer func() {
		if err != nil && bb != nil {
			_ = bb.Release()
		}
	}()

	// USK-769: populate RawBody from the body reader's RawBodyProvider after
	// the body has been fully drained. RawBody preserves the on-wire bytes
	// (chunk framing for chunked TE, identity bytes otherwise) so opaque
	// pass-through send paths re-emit them verbatim.
	// USK-772: when the captured body crossed the spill threshold, the disk-
	// backed bodybuf is returned alongside; in that case RawBody is nil and
	// RawBodyBuffer holds the wire bytes.
	rawReq.RawBody, rawReq.RawBodyBuffer, rawReq.RawBodyTruncated = extractRawBody(rawReq.Body)
	defer func() {
		if err != nil && rawReq.RawBodyBuffer != nil {
			_ = rawReq.RawBodyBuffer.Release()
		}
	}()
	anomalies := convertAnomalies(rawReq.Anomalies)
	if rawReq.RawBodyTruncated {
		cap := capForTruncationDetail(c.bodyOpts, rawReq.RawBodyBuffer != nil)
		anomalies = append(anomalies, envelope.Anomaly{
			Type:   envelope.AnomalyRawBodyTruncated,
			Detail: fmt.Sprintf("RawBody capped at %d bytes", cap),
		})
	}
	trailers, trailerAnomalies := extractTrailers(rawReq.Body)
	anomalies = append(anomalies, trailerAnomalies...)

	msg := &envelope.HTTPMessage{
		Method:      rawReq.Method,
		Scheme:      c.scheme,
		Authority:   authority,
		Path:        path,
		RawQuery:    rawQuery,
		HTTPVersion: envelope.HTTPVersionFromProto(rawReq.Proto),
		Headers:     rawHeadersToKV(rawReq.Headers),
		Trailers:    trailers,
		Body:        body,
		BodyBuffer:  bb,
		Anomalies:   anomalies,
	}

	envCtx := c.ctxTmpl
	envCtx.ReceivedAt = time.Now()

	env := &envelope.Envelope{
		StreamID:  c.currentStreamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.sequence,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		// USK-773: Envelope.Raw is the complete wire snapshot (header section
		// + on-wire body section). For chunked TE the body section preserves
		// chunk framing, extensions, trailers, and the terminating
		// "0\r\n\r\n"; for identity bodies it is the verbatim body bytes.
		// rawReq.RawBytes (header-only) remains the source of truth for
		// header-section-only consumers (e.g. opaque send fast path).
		// USK-772: when the body was disk-spilled, Raw is nil and RawBuffer
		// carries the disk-backed wire bytes; consumers must call WireBytes(ctx)
		// to read the snapshot uniformly.
		Raw:       concatRawWireBytes(rawReq.RawBytes, rawReq.RawBody, rawReq.RawBodyBuffer),
		RawBuffer: rawReq.RawBodyBuffer,
		Message:   msg,
		Context:   envCtx,
		Opaque: &opaqueHTTP1{
			rawReq:         rawReq,
			origKV:         cloneKV(msg.Headers),
			origBody:       cloneBytes(body),
			origBodyBuffer: bb,
		},
	}

	c.connClosed = rawReq.Close
	c.recordEmittedFlowID(env.FlowID)
	return env, nil
}

// parseResponse reads one HTTP response from the parent Layer's bufio.Reader
// and returns the envelope. The bool return value is true when the response
// is a 1xx informational (the parent Layer must keep parsing on the same
// channel for the final response).
func (c *channel) parseResponse() (*envelope.Envelope, bool, error) {
	rawResp, err := parser.ParseResponseWithOptions(c.layer.reader, parser.ParseOptions{
		MaxRawCapture: c.bodyOpts.maxRawCapture,
	})
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, false, io.EOF
		}
		return nil, false, fmt.Errorf("http1: parse response: %w", err)
	}

	// Streaming-body bypass (USK-655): when the configured predicate matches
	// (e.g. text/event-stream), emit the response Envelope with empty body
	// and stash the still-open body reader on the channel for the swap
	// orchestrator to claim via detachStreamingBody. Streaming responses
	// are by definition final.
	if c.streamingDetect != nil && c.streamingDetect(rawResp) {
		return c.buildStreamingResponseEnvelope(rawResp), false, nil
	}

	bb, body, anomalies, trailers, err := c.assembleResponseBody(rawResp)
	if err != nil {
		return nil, false, err
	}
	defer func() {
		if err != nil && bb != nil {
			_ = bb.Release()
		}
		if err != nil && rawResp.RawBodyBuffer != nil {
			_ = rawResp.RawBodyBuffer.Release()
		}
	}()
	anomalies = append(anomalies, convertAnomalies(rawResp.Anomalies)...)

	statusReason := extractStatusReason(rawResp.Status)
	msg := &envelope.HTTPMessage{
		Status:       rawResp.StatusCode,
		StatusReason: statusReason,
		HTTPVersion:  envelope.HTTPVersionFromProto(rawResp.Proto),
		Headers:      rawHeadersToKV(rawResp.Headers),
		Trailers:     trailers,
		Body:         body,
		BodyBuffer:   bb,
		Anomalies:    anomalies,
	}

	envCtx := c.ctxTmpl
	envCtx.ReceivedAt = time.Now()

	emitSeq, isInformational := c.advanceResponseSequence(rawResp.StatusCode)

	// Mint per-exchange StreamID on first response if Send direction never
	// ran (Receive-direction Channel obtained via OpenExchange inherits the
	// StreamID assigned on the request side via Send; otherwise mint here).
	if c.currentStreamID == "" {
		c.currentStreamID = uuid.New().String()
	}

	env := &envelope.Envelope{
		StreamID:  c.currentStreamID,
		FlowID:    uuid.New().String(),
		Sequence:  emitSeq,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		// USK-773: Envelope.Raw is the complete wire snapshot (header section
		// + on-wire body section). See parseRequest for rationale. USK-772:
		// when the body was disk-spilled, Raw is nil and RawBuffer carries
		// the disk-backed wire bytes; consumers should call WireBytes(ctx)
		// to read the snapshot uniformly.
		Raw:       concatRawWireBytes(rawResp.RawBytes, rawResp.RawBody, rawResp.RawBodyBuffer),
		RawBuffer: rawResp.RawBodyBuffer,
		Message:   msg,
		Context:   envCtx,
		Opaque: &opaqueHTTP1{
			rawResp:        rawResp,
			origKV:         cloneKV(msg.Headers),
			origBody:       cloneBytes(body),
			origBodyBuffer: bb,
		},
	}

	c.recordEmittedFlowID(env.FlowID)
	return env, isInformational, nil
}

// buildStreamingResponseEnvelope assembles the response Envelope for the
// streaming-body bypass path. The body is NOT drained; the post-headers
// byte stream is stashed on c.streamingBody for the swap orchestrator
// to claim via detachStreamingBody.
//
// USK-883: when the response uses Transfer-Encoding: chunked, the body
// source must be the parser's already-constructed dechunked reader
// (rawResp.Body), not the parent Layer's raw bufio.Reader. Earlier code
// stashed the raw reader unconditionally, so chunked framing
// (e.g. "D\r\n", "F\r\n", "9A\r\n") leaked into the streaming consumer
// (e.g. the SSE parser) as if it were body data — surfacing a literal
// hex-length prefix at the start of small events.
//
// For the open-ended HTTP/1.1 SSE case (no Content-Length, no chunked
// TE, no Connection: close), the parser returns a zero-length identity
// reader (the spec-strict reading is "no body"). In practice servers
// stream events on such a connection indefinitely, so we keep using the
// raw bufio.Reader there — same behaviour as before the fix for that
// specific shape. For Content-Length / Connection: close streamed
// responses, rawResp.Body is also the correct reader.
func (c *channel) buildStreamingResponseEnvelope(rawResp *parser.RawResponse) *envelope.Envelope {
	statusReason := extractStatusReason(rawResp.Status)
	anomalies := convertAnomalies(rawResp.Anomalies)

	msg := &envelope.HTTPMessage{
		Status:       rawResp.StatusCode,
		StatusReason: statusReason,
		HTTPVersion:  envelope.HTTPVersionFromProto(rawResp.Proto),
		Headers:      rawHeadersToKV(rawResp.Headers),
		Anomalies:    anomalies,
	}

	envCtx := c.ctxTmpl
	envCtx.ReceivedAt = time.Now()

	c.streamingBody = pickStreamingBody(rawResp, c.layer.reader)

	if c.priorRespWasInformational {
		c.sequence++
	}
	emitSeq := c.sequence + 1
	c.priorRespWasInformational = false

	if c.currentStreamID == "" {
		c.currentStreamID = uuid.New().String()
	}

	env := &envelope.Envelope{
		StreamID:  c.currentStreamID,
		FlowID:    uuid.New().String(),
		Sequence:  emitSeq,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawResp.RawBytes,
		Message:   msg,
		Context:   envCtx,
		Opaque: &opaqueHTTP1{
			rawResp: rawResp,
			origKV:  cloneKV(msg.Headers),
		},
	}
	c.recordEmittedFlowID(env.FlowID)
	return env
}

// pickStreamingBody returns the appropriate body reader for a streaming
// (body-drain-bypassed) response. See [buildStreamingResponseEnvelope]
// for the USK-883 rationale.
//
//   - Transfer-Encoding: chunked → rawResp.Body (the parser's dechunked
//     reader). Using the raw bufio.Reader would feed chunk-size lines
//     into the consumer as body bytes.
//   - HTTP/1.0 / Connection: close → rawResp.Body (the parser's
//     EOF-delimited identity reader is correct).
//   - Content-Length → rawResp.Body (LimitReader-wrapped). In practice
//     streaming responses do not use Content-Length, but if a peer does,
//     we honor the framing.
//   - HTTP/1.1 with no length indicators (the legacy open-ended SSE
//     case) → fallback raw bufio.Reader, because the parser returns a
//     zero-length identity reader there (RFC-strict "no body") and we
//     need to keep consuming the open stream.
func pickStreamingBody(rawResp *parser.RawResponse, rawReader io.Reader) io.Reader {
	if rawResp == nil {
		return rawReader
	}
	if responseUsesChunkedTE(rawResp) {
		return rawResp.Body
	}
	if rawResp.Proto == "HTTP/1.0" || responseConnectionClose(rawResp) {
		return rawResp.Body
	}
	if rawResp.Headers.Get("Content-Length") != "" {
		return rawResp.Body
	}
	// HTTP/1.1, no chunked TE, no Content-Length, no Connection: close.
	// Legacy open-ended SSE: keep using the raw bufio.Reader so the
	// stream continues indefinitely. (The parser would hand us a
	// zero-length identity reader here.)
	return rawReader
}

// responseUsesChunkedTE mirrors the parser's chunked-TE detection (see
// parser.hasChunkedTE, kept package-private) so we can decide framing
// at the channel layer without exposing internals.
func responseUsesChunkedTE(rawResp *parser.RawResponse) bool {
	if rawResp.Proto == "HTTP/1.0" {
		return false
	}
	for _, te := range rawResp.Headers.Values("Transfer-Encoding") {
		// Trim and compare each comma-separated token case-insensitively.
		for _, tok := range strings.Split(te, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "chunked") {
				return true
			}
		}
	}
	return false
}

// responseConnectionClose reports whether the response carries a
// Connection: close token (case-insensitive, any comma-separated value).
func responseConnectionClose(rawResp *parser.RawResponse) bool {
	for _, v := range rawResp.Headers.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "close") {
				return true
			}
		}
	}
	return false
}

// --- Send() implementation: write helpers (write under c.layer.writeMu) ---

func (c *channel) sendRequest(msg *envelope.HTTPMessage, env *envelope.Envelope) error {
	opaque, _ := env.Opaque.(*opaqueHTTP1)

	// Capture the StreamID into this Receive-direction Channel so the
	// response we later parse adopts the same StreamID — preserves the
	// "request and response share one exchange identifier" invariant
	// without the session-level StreamID rewrite that pre-USK-730 had.
	if c.currentStreamID == "" && env.StreamID != "" {
		c.currentStreamID = env.StreamID
	}

	// USK-833: capture the paired request line on this upstream-facing
	// Channel so the matching response we later parse stamps Context with
	// the paired request's path/method/query (parseResponse copies ctxTmpl).
	// Mirror of the parseRequest stamping on the client-facing channel,
	// applied here because the upstream-facing Channel's ctxTmpl is not
	// populated by parseRequest (this Channel never parses a request — it
	// forwards one).
	c.ctxTmpl.RequestPath = msg.Path
	c.ctxTmpl.RequestMethod = msg.Method
	c.ctxTmpl.RequestRawQuery = msg.RawQuery

	// USK-730: register this Channel in the parent Layer's pendingQ
	// atomically with the wire write so the response FIFO matches the
	// on-wire request order. Caller (Send) holds writeMu, so this append
	// is serialized with respect to other Channels' sendRequest invocations.
	if c.layer != nil {
		c.layer.appendPending(c)
	}

	if opaque != nil && opaque.rawReq != nil {
		return c.sendRequestOpaque(msg, opaque)
	}
	return c.sendRequestSynthetic(msg)
}

func (c *channel) sendResponse(msg *envelope.HTTPMessage, env *envelope.Envelope) error {
	opaque, _ := env.Opaque.(*opaqueHTTP1)

	if opaque != nil && opaque.rawResp != nil {
		return c.sendResponseOpaque(msg, opaque)
	}
	return c.sendResponseSynthetic(msg)
}

// --- Send Path 1: Opaque-based (raw-first patching) ---

// opaqueSendDecision summarises the four-way classification on which the
// opaque HTTP/1.x send paths dispatch:
//
//   - useRawBody: the upstream wire was chunked-Transfer-Encoded and the
//     captured RawBody fits in MaxRawCaptureSize, so it can be re-emitted
//     verbatim (preserves chunk framing).
//   - rewriteTEToCL: the upstream wire was chunked but RawBody overflowed
//     the capture cap. We must drop Transfer-Encoding and re-stamp
//     Content-Length from the dechunked body so the wire stays internally
//     consistent. The truncation surfaces as AnomalyRawBodyTruncated on
//     the envelope.
//   - headersChanged / bodyChanged are also reported here so callers can
//     skip the zero-copy fast path when either is set.
//
// USK-769.
type opaqueSendDecision struct {
	headersChanged bool
	bodyChanged    bool
	useRawBody     bool
	rewriteTEToCL  bool
}

// classifyOpaqueSend computes the decision for a request/response opaque send.
// The wire chunked check is shared via parser.IsChunked.
//
// USK-772: rawBodyBuffered signals that the on-wire body was captured to a
// disk-backed bodybuf because it crossed the spill threshold. The chunked
// passthrough path streams from the buffer instead of copying memory bytes —
// see writeOpaqueBody.
func classifyOpaqueSend(headers parser.RawHeaders, rawBody []byte, rawBodyBuffered, rawBodyTruncated, headersChanged, bodyChanged bool) opaqueSendDecision {
	wireChunked := parser.IsChunked(headers)
	d := opaqueSendDecision{
		headersChanged: headersChanged,
		bodyChanged:    bodyChanged,
	}
	if !bodyChanged && wireChunked {
		if rawBodyTruncated {
			d.rewriteTEToCL = true
		} else if len(rawBody) > 0 || rawBodyBuffered {
			d.useRawBody = true
		}
	}
	return d
}

// applyTEToCLRewrite drops Transfer-Encoding and re-stamps Content-Length on
// rawHeaders based on msg's body. Used by the bodyChanged and
// rewriteTEToCL paths in the opaque send branches.
func applyTEToCLRewrite(rawHeaders *parser.RawHeaders, msg *envelope.HTTPMessage) {
	rawHeaders.Del("Transfer-Encoding")
	switch {
	case msg.Body != nil:
		rawHeaders.Set("Content-Length", strconv.Itoa(len(msg.Body)))
	case msg.BodyBuffer != nil:
		rawHeaders.Set("Content-Length", strconv.FormatInt(msg.BodyBuffer.Len(), 10))
	default:
		rawHeaders.Set("Content-Length", "0")
	}
}

func (c *channel) sendRequestOpaque(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) error {
	rawReq := opaque.rawReq
	d := classifyOpaqueSend(rawReq.Headers, rawReq.RawBody, rawReq.RawBodyBuffer != nil, rawReq.RawBodyTruncated,
		!kvEqual(msg.Headers, opaque.origKV), isBodyChanged(msg, opaque))

	// Zero-copy fast path: nothing changed and we don't need a TE→CL rewrite.
	if !d.headersChanged && !d.bodyChanged && !d.rewriteTEToCL && len(rawReq.RawBytes) > 0 {
		if _, err := c.layer.conn.Write(rawReq.RawBytes); err != nil {
			return fmt.Errorf("http1: send request raw: %w", err)
		}
		return c.writeOpaqueBody(msg, rawReq.RawBody, rawReq.RawBodyBuffer, d.useRawBody, "request")
	}

	if d.headersChanged {
		rawReq.Headers = applyHeaderPatch(opaque.origKV, msg.Headers, rawReq.Headers)
	}
	if d.bodyChanged || d.rewriteTEToCL {
		applyTEToCLRewrite(&rawReq.Headers, msg)
	}

	headerBytes := serializeRequestHeader(rawReq)
	if _, err := c.layer.conn.Write(headerBytes); err != nil {
		return fmt.Errorf("http1: send request: %w", err)
	}
	return c.writeOpaqueBody(msg, rawReq.RawBody, rawReq.RawBodyBuffer, d.useRawBody, "request")
}

func (c *channel) sendResponseOpaque(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) error {
	rawResp := opaque.rawResp
	d := classifyOpaqueSend(rawResp.Headers, rawResp.RawBody, rawResp.RawBodyBuffer != nil, rawResp.RawBodyTruncated,
		!kvEqual(msg.Headers, opaque.origKV), isBodyChanged(msg, opaque))

	if !d.headersChanged && !d.bodyChanged && !d.rewriteTEToCL && len(rawResp.RawBytes) > 0 {
		if _, err := c.layer.conn.Write(rawResp.RawBytes); err != nil {
			return fmt.Errorf("http1: send response raw: %w", err)
		}
		return c.writeOpaqueBody(msg, rawResp.RawBody, rawResp.RawBodyBuffer, d.useRawBody, "response")
	}

	if d.headersChanged {
		rawResp.Headers = applyHeaderPatch(opaque.origKV, msg.Headers, rawResp.Headers)
	}
	if d.bodyChanged || d.rewriteTEToCL {
		applyTEToCLRewrite(&rawResp.Headers, msg)
	}

	headerBytes := serializeResponseHeader(rawResp)
	if _, err := c.layer.conn.Write(headerBytes); err != nil {
		return fmt.Errorf("http1: send response: %w", err)
	}
	return c.writeOpaqueBody(msg, rawResp.RawBody, rawResp.RawBodyBuffer, d.useRawBody, "response")
}

// writeOpaqueBody writes either the on-wire RawBody (preserving chunk
// framing) or the dechunked semantic body via writeBody. When rawBodyBuffer
// is non-nil and useRawBody is true, the body is streamed from the disk-
// backed buffer via io.Copy; the in-memory rawBody is preferred otherwise.
// kind is "request" or "response" — used purely for error wrapping.
//
// USK-772: rawBodyBuffer streaming preserves byte-level wire fidelity for
// chunked bodies that exceeded MaxRawCaptureSize. The body cap (MaxBodySize)
// already bounded what was captured; the relay path itself does not apply
// further truncation.
func (c *channel) writeOpaqueBody(msg *envelope.HTTPMessage, rawBody []byte, rawBodyBuffer *bodybuf.BodyBuffer, useRawBody bool, kind string) error {
	if useRawBody {
		if rawBodyBuffer != nil {
			r, err := rawBodyBuffer.Reader()
			if err != nil {
				return fmt.Errorf("http1: open %s raw body buffer: %w", kind, err)
			}
			defer r.Close()
			if _, err := io.Copy(c.layer.conn, r); err != nil {
				return fmt.Errorf("http1: send %s raw body: %w", kind, err)
			}
			return nil
		}
		if _, err := c.layer.conn.Write(rawBody); err != nil {
			return fmt.Errorf("http1: send %s raw body: %w", kind, err)
		}
		return nil
	}
	return c.writeBody(msg)
}

// --- Send Path 2: Synthetic (no Opaque) ---

func (c *channel) sendRequestSynthetic(msg *envelope.HTTPMessage) error {
	var buf bytes.Buffer

	requestURI := msg.Path
	if msg.RawQuery != "" {
		requestURI += "?" + msg.RawQuery
	}
	if requestURI == "" {
		requestURI = "/"
	}
	if err := serializeRequestLine(&buf, msg.Method, requestURI, "HTTP/1.1"); err != nil {
		return fmt.Errorf("http1: send synthetic request line: %w", err)
	}

	headers := kvToRawHeaders(msg.Headers)
	if headers.Get("Content-Length") == "" {
		switch {
		case msg.Body != nil:
			headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		case msg.BodyBuffer != nil:
			headers.Set("Content-Length", strconv.FormatInt(msg.BodyBuffer.Len(), 10))
		}
	}

	if err := serializeHeaders(&buf, headers); err != nil {
		return fmt.Errorf("http1: send synthetic request headers: %w", err)
	}

	if _, err := c.layer.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("http1: send synthetic request: %w", err)
	}

	return c.writeBody(msg)
}

func (c *channel) sendResponseSynthetic(msg *envelope.HTTPMessage) error {
	var buf bytes.Buffer

	status := fmt.Sprintf("%d %s", msg.Status, msg.StatusReason)
	if msg.StatusReason == "" {
		text := statusText(msg.Status)
		if text == "" {
			text = "Unknown"
		}
		status = fmt.Sprintf("%d %s", msg.Status, text)
	}
	if err := serializeStatusLine(&buf, "HTTP/1.1", status, msg.Status); err != nil {
		return fmt.Errorf("http1: send synthetic status line: %w", err)
	}

	headers := kvToRawHeaders(msg.Headers)
	if headers.Get("Content-Length") == "" {
		switch {
		case msg.Body != nil:
			headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		case msg.BodyBuffer != nil:
			headers.Set("Content-Length", strconv.FormatInt(msg.BodyBuffer.Len(), 10))
		}
	}

	if err := serializeHeaders(&buf, headers); err != nil {
		return fmt.Errorf("http1: send synthetic response headers: %w", err)
	}

	if _, err := c.layer.conn.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("http1: send synthetic response: %w", err)
	}

	return c.writeBody(msg)
}

// --- Helpers (unchanged from pre-refactor; preserved as channel methods or
// package functions where they were before). ---

func (c *channel) writeBody(msg *envelope.HTTPMessage) error {
	if msg.Body != nil {
		if _, err := c.layer.conn.Write(msg.Body); err != nil {
			return fmt.Errorf("http1: write body: %w", err)
		}
		return nil
	}
	if msg.BodyBuffer != nil {
		r, err := msg.BodyBuffer.Reader()
		if err != nil {
			return fmt.Errorf("http1: open body buffer: %w", err)
		}
		defer r.Close()
		if _, err := io.Copy(c.layer.conn, r); err != nil {
			return fmt.Errorf("http1: write body buffer: %w", err)
		}
	}
	return nil
}

func readBodyWithThreshold(r io.Reader, spillDir string, spillThreshold, maxBody int64) (bb *bodybuf.BodyBuffer, body []byte, retErr error) {
	if r == nil {
		return nil, nil, nil
	}
	if spillThreshold <= 0 {
		spillThreshold = config.DefaultBodySpillThreshold
	}
	if maxBody <= 0 {
		maxBody = config.MaxBodySize
	}

	scratch := make([]byte, spillThreshold+1)
	n, readErr := io.ReadFull(r, scratch)

	if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
		if n == 0 {
			return nil, []byte{}, nil
		}
		out := make([]byte, n)
		copy(out, scratch[:n])
		return nil, out, nil
	}
	if readErr != nil {
		return nil, nil, fmt.Errorf("http1: read body: %w", readErr)
	}

	bb, err := bodybuf.NewFile(spillDir, config.BodySpillPrefix, maxBody)
	if err != nil {
		return nil, nil, fmt.Errorf("http1: create body file: %w", err)
	}
	defer func() {
		if retErr != nil && bb != nil {
			_ = bb.Release()
			bb = nil
		}
	}()

	if _, werr := bb.Write(scratch[:n]); werr != nil {
		if errors.Is(werr, bodybuf.ErrMaxSizeExceeded) {
			return nil, nil, &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "http1: body exceeds max size",
			}
		}
		return nil, nil, fmt.Errorf("http1: write body: %w", werr)
	}

	if _, cerr := io.Copy(bb, r); cerr != nil {
		if errors.Is(cerr, bodybuf.ErrMaxSizeExceeded) {
			return nil, nil, &layer.StreamError{
				Code:   layer.ErrorInternalError,
				Reason: "http1: body exceeds max size",
			}
		}
		return nil, nil, fmt.Errorf("http1: read body: %w", cerr)
	}

	return bb, nil, nil
}

func parseRequestURI(requestURI string, headers parser.RawHeaders) (path, rawQuery, authority string) {
	authority = headers.Get("Host")

	if requestURI == "*" {
		return "*", "", authority
	}

	u, err := url.ParseRequestURI(requestURI)
	if err != nil {
		return requestURI, "", authority
	}

	path = u.Path
	rawQuery = u.RawQuery

	if u.Host != "" && authority == "" {
		authority = u.Host
	}

	return path, rawQuery, authority
}

func extractStatusReason(status string) string {
	if idx := strings.IndexByte(status, ' '); idx >= 0 {
		return status[idx+1:]
	}
	return ""
}

func rawHeadersToKV(raw parser.RawHeaders) []envelope.KeyValue {
	kv := make([]envelope.KeyValue, len(raw))
	for i, h := range raw {
		kv[i] = envelope.KeyValue{Name: h.Name, Value: h.Value}
	}
	return kv
}

func kvToRawHeaders(kv []envelope.KeyValue) parser.RawHeaders {
	raw := make(parser.RawHeaders, len(kv))
	for i, h := range kv {
		raw[i] = parser.RawHeader{Name: h.Name, Value: h.Value}
	}
	return raw
}

func cloneKV(kv []envelope.KeyValue) []envelope.KeyValue {
	if kv == nil {
		return nil
	}
	out := make([]envelope.KeyValue, len(kv))
	copy(out, kv)
	return out
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func kvEqual(a, b []envelope.KeyValue) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}

func isBodyChanged(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) bool {
	if msg.BodyBuffer != opaque.origBodyBuffer {
		return true
	}
	if opaque.origBodyBuffer != nil {
		return msg.Body != nil
	}
	if msg.Body == nil && opaque.origBody == nil {
		return false
	}
	if opaque.origBody == nil {
		return true
	}
	if msg.Body == nil {
		return true
	}
	return !bytes.Equal(msg.Body, opaque.origBody)
}

func convertAnomalies(parserAnomalies []parser.Anomaly) []envelope.Anomaly {
	if len(parserAnomalies) == 0 {
		return nil
	}
	anomalies := make([]envelope.Anomaly, len(parserAnomalies))
	for i, a := range parserAnomalies {
		anomalies[i] = envelope.Anomaly{
			Type:   envelope.AnomalyType(a.Type),
			Detail: a.Detail,
		}
	}
	return anomalies
}

func extractTrailers(parserBody io.Reader) ([]envelope.KeyValue, []envelope.Anomaly) {
	tp, ok := parserBody.(parser.TrailerProvider)
	if !ok {
		return nil, nil
	}
	var trailers []envelope.KeyValue
	if raw := tp.Trailers(); len(raw) > 0 {
		trailers = rawHeadersToKV(raw)
	}
	anomalies := convertAnomalies(tp.TrailerAnomalies())
	return trailers, anomalies
}

// extractRawBody returns the on-wire body bytes captured by the parser body
// reader (chunked framing for chunked TE, identity bytes otherwise). The
// second return value is the disk-backed bodybuf when the body crossed the
// spill threshold (USK-772), nil otherwise. The third return value is true
// when capture was capped at the absolute byte cap.
//
// USK-769: opaque pass-through send paths use these bytes to re-emit the
// body verbatim, satisfying RFC-001 §3.1 (wire-observed raw bytes must not
// be destroyed or modified). For bodies whose reader does not implement
// RawBodyProvider (e.g. legacy test fixtures), returns (nil, nil, false).
func extractRawBody(parserBody io.Reader) ([]byte, *bodybuf.BodyBuffer, bool) {
	rp, ok := parserBody.(parser.RawBodyProvider)
	if !ok {
		return nil, nil, false
	}
	return rp.RawBody(), rp.RawBodyBuffer(), rp.RawBodyTruncated()
}

// releaseOrphanRawBodyBuffer is the error-path companion of extractRawBody:
// it pulls the disk-backed bodybuf off the parser body reader (if any) and
// Releases it. Used when the dechunked-body assembler errors before
// extractRawBody runs — without this the spill file would only be reaped on
// the next-process startup orphan sweep.
//
// USK-772.
func releaseOrphanRawBodyBuffer(parserBody io.Reader) {
	if parserBody == nil {
		return
	}
	rp, ok := parserBody.(parser.RawBodyProvider)
	if !ok {
		return
	}
	if buf := rp.RawBodyBuffer(); buf != nil {
		_ = buf.Release()
	}
}

// configureRawBodySpill installs USK-772 disk-spill on the parser body
// reader (when it satisfies the optional rawBodySpiller interface), so the
// captured RawBody can survive bodies larger than MaxRawCaptureSize. Body
// readers backed by *parser.dechunkedReader / *parser.identityBodyReader
// (the production paths) implement the interface; legacy test fixtures may
// not, in which case this is a no-op.
func configureRawBodySpill(parserBody io.Reader, opts bodyOpts) {
	if parserBody == nil {
		return
	}
	type rawBodySpiller interface {
		EnableRawBodySpill(dir, prefix string, threshold, maxSize int64)
	}
	sp, ok := parserBody.(rawBodySpiller)
	if !ok {
		return
	}
	threshold := opts.spillThreshold
	if threshold <= 0 {
		threshold = config.DefaultBodySpillThreshold
	}
	maxSize := opts.maxBody
	if maxSize <= 0 {
		maxSize = config.MaxBodySize
	}
	// rawSpillPrefix is distinct from BodySpillPrefix so analysts (and
	// orphan-sweep observers) can tell apart dechunked-body spill files
	// (yorishiro-body-*) from raw-body spill files (yorishiro-body-*-raw).
	// The prefix bodybuf appends "-*" to is "yorishiro-body-raw-" so the
	// generated name is e.g. "yorishiro-body-raw-12345678". Both spill
	// types share the BodySpillPrefix substring "yorishiro-body-" so the
	// orphan sweep (config.SweepOrphanBodyFiles) cleans both without code
	// changes — verified in TestSweepOrphanBodyFiles_RawSpillPrefix.
	sp.EnableRawBodySpill(opts.spillDir, config.BodySpillPrefix+"raw-", threshold, maxSize)
}

// concatWireBytes returns the full wire snapshot of an HTTP/1.x message:
// the header section bytes captured by the parser concatenated with the
// on-wire body bytes (chunk framing for chunked TE, identity bytes
// otherwise). Returns headerBytes verbatim (no allocation) when bodyBytes
// is empty.
//
// USK-773: this is the projection point that promotes Envelope.Raw from
// "header section only" to "complete wire bytes" so Flow Store / WebUI /
// `query` MCP tool consumers see chunked frames + trailers + extensions.
func concatWireBytes(headerBytes, bodyBytes []byte) []byte {
	if len(bodyBytes) == 0 {
		return headerBytes
	}
	out := make([]byte, 0, len(headerBytes)+len(bodyBytes))
	out = append(out, headerBytes...)
	out = append(out, bodyBytes...)
	return out
}

// assembleResponseBody drains the body, configures USK-772 disk-spill, and
// returns the dechunked-body BodyBuffer/bytes plus the anomalies and
// trailers that the caller must merge into the resulting HTTPMessage.
//
// Pulled out of parseResponse to keep that function under the
// gocyclo threshold (15) — the body extraction + anomaly accumulation
// is a single logical concern.
func (c *channel) assembleResponseBody(rawResp *parser.RawResponse) (*bodybuf.BodyBuffer, []byte, []envelope.Anomaly, []envelope.KeyValue, error) {
	// USK-772: configure raw-body disk-spill on the parser body reader before
	// drain. See parseRequest for rationale.
	configureRawBodySpill(rawResp.Body, c.bodyOpts)

	bb, body, err := readBodyWithThreshold(rawResp.Body,
		c.bodyOpts.spillDir, c.bodyOpts.spillThreshold, c.bodyOpts.maxBody)
	if err != nil {
		// USK-772: same rationale as parseRequest — release any spilled
		// raw-body temp file the parser sink had already promoted before
		// readBodyWithThreshold tripped its cap.
		releaseOrphanRawBodyBuffer(rawResp.Body)
		return nil, nil, nil, nil, fmt.Errorf("http1: read response body: %w", err)
	}

	// USK-769: populate RawBody from the body reader's RawBodyProvider after
	// drain. USK-772: capture RawBodyBuffer when the on-wire body crossed
	// the spill threshold.
	rawResp.RawBody, rawResp.RawBodyBuffer, rawResp.RawBodyTruncated = extractRawBody(rawResp.Body)

	var anomalies []envelope.Anomaly
	if rawResp.RawBodyTruncated {
		cap := capForTruncationDetail(c.bodyOpts, rawResp.RawBodyBuffer != nil)
		anomalies = append(anomalies, envelope.Anomaly{
			Type:   envelope.AnomalyRawBodyTruncated,
			Detail: fmt.Sprintf("RawBody capped at %d bytes", cap),
		})
	}
	trailers, trailerAnomalies := extractTrailers(rawResp.Body)
	anomalies = append(anomalies, trailerAnomalies...)
	return bb, body, anomalies, trailers, nil
}

// advanceResponseSequence applies the USK-721 1xx-aware sequence accounting
// for the next response on this Channel and returns the Sequence to emit.
// USK-730: 101 Switching Protocols is excluded from "informational" because
// it is the final HTTP message on the wire.
func (c *channel) advanceResponseSequence(statusCode int) (emitSeq int, isInformational bool) {
	isInformational = statusCode >= 100 && statusCode < 200 && statusCode != 101
	if c.priorRespWasInformational {
		c.sequence++
	}
	emitSeq = c.sequence + 1
	c.priorRespWasInformational = isInformational
	return emitSeq, isInformational
}

// concatRawWireBytes assembles the in-memory portion of Envelope.Raw for an
// HTTP/1.x message. When the body was disk-spilled (rawBodyBuffer non-nil),
// only the header section bytes are kept in Raw and the body section lives
// in Envelope.RawBuffer; Envelope.WireBytes(ctx) stitches the two for
// callers that want the full wire snapshot.
//
// USK-772: introduced to express the memory/disk split for Raw vs RawBuffer.
// See concatWireBytes for the memory-only path.
func concatRawWireBytes(headerBytes, bodyBytes []byte, rawBodyBuffer *bodybuf.BodyBuffer) []byte {
	if rawBodyBuffer != nil {
		// Disk-spill path: keep just the header section in Raw; WireBytes
		// concatenates Raw with RawBuffer.Bytes(ctx) on demand.
		out := make([]byte, len(headerBytes))
		copy(out, headerBytes)
		return out
	}
	return concatWireBytes(headerBytes, bodyBytes)
}

// capForTruncationDetail returns the byte cap that a truncation anomaly
// detail string should reference. The value depends on whether the capture
// path was memory-only (the per-Layer maxRawCapture, falling back to
// parser.MaxRawCaptureSize) or disk-spill (MaxBodySize). Reading from the
// per-Layer cap keeps the anomaly Detail accurate when the operator has
// reconfigured the knob via WithMaxRawCaptureSize / Config.MaxRawCaptureSize.
func capForTruncationDetail(opts bodyOpts, spilled bool) int64 {
	if !spilled {
		if opts.maxRawCapture > 0 {
			return opts.maxRawCapture
		}
		return int64(parser.MaxRawCaptureSize)
	}
	if opts.maxBody > 0 {
		return opts.maxBody
	}
	return config.MaxBodySize
}
