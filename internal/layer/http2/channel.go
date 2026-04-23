package http2

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// channel implements layer.Channel for one HTTP/2 stream.
//
// recv is bounded (size 1) so the assembler applies natural backpressure.
// errCh is bounded (size 1) so a single stream-level error can be delivered.
// Closing recv is gated by closeRecvOnce — the reader and Close both racey-
// close it.
type channel struct {
	layer    *Layer
	streamID string // UUID-based identifier returned by StreamID()
	h2Stream uint32 // HTTP/2 stream identifier
	isPush   bool

	// originStreamID is set on push channels (isPush=true) to the UUID
	// StreamID of the channel that carried the PUSH_PROMISE. Zero value on
	// client-initiated streams. Surfaced via PushOriginChannelStreamID so
	// the upstream push recorder can tag pushed flows with the origin's
	// identifier.
	originStreamID string

	recv          chan *envelope.Envelope
	errCh         chan *layer.StreamError
	closeRecvOnce sync.Once
	closeSendOnce sync.Once

	mu         sync.Mutex
	sequence   int
	headersHas bool // true after first request HEADERS sent (client side)
	closed     bool

	// sentEndStream is set after Send returns successfully. Both Send paths
	// (opaque and synthetic) always terminate the message with END_STREAM, so
	// a successful return implies the send half is closed. recvEndStream is
	// set by the reader/assembler path when natural end-of-stream is observed
	// (asmDone), via markRecvEnded. Abnormal terminations (failStream,
	// failStreamsAfterGoAway, broadcastShutdown) deliberately do NOT set
	// recvEndStream — those paths leave it false so Close still emits
	// RST_STREAM for the abnormal-teardown case.
	//
	// Close reads both flags to decide whether RST_STREAM(CANCEL) is needed.
	// When both are true and the channel is not a push stream, the stream is
	// bilaterally closed on the wire and any RST would arrive on a closed
	// state, provoking a peer PROTOCOL_ERROR + GOAWAY (RFC 9113 §5.1).
	sentEndStream bool
	recvEndStream bool

	// Terminal-state tracking. Populated before termDone closes so any
	// observer of Closed sees a stable Err value.
	//
	// markTerminated is deliberately NOT invoked on normal END_STREAM
	// (assembler asmDone path). A peer may still deliver a late RST_STREAM
	// on a stream it half-closed, and firing Closed on asmDone would
	// latch io.EOF as the terminal error and prevent the subsequent
	// StreamError from becoming visible through Err.
	termMu   sync.Mutex
	termErr  error
	termOnce sync.Once
	termDone chan struct{}
}

// newChannel constructs a channel bound to layer for h2 stream id.
func newChannel(l *Layer, h2Stream uint32, isPush bool) *channel {
	return &channel{
		layer:    l,
		streamID: uuid.New().String(),
		h2Stream: h2Stream,
		isPush:   isPush,
		recv:     make(chan *envelope.Envelope, 1),
		errCh:    make(chan *layer.StreamError, 1),
		termDone: make(chan struct{}),
	}
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
// once. Callers must guarantee err is non-nil; io.EOF is used for normal
// termination.
func (c *channel) markTerminated(err error) {
	c.termMu.Lock()
	if c.termErr == nil {
		c.termErr = err
	}
	c.termMu.Unlock()
	c.termOnce.Do(func() { close(c.termDone) })
}

// markRecvEnded records that the reader/assembler has observed the natural
// end of the receive half (asmDone). Called from reader paths that close
// the recv channel due to END_STREAM, NOT from abnormal-termination paths
// (failStream, failStreamsAfterGoAway, broadcastShutdown) so Close can
// still distinguish bilateral close from abnormal teardown.
func (c *channel) markRecvEnded() {
	c.mu.Lock()
	c.recvEndStream = true
	c.mu.Unlock()
}

// nextSequence returns the next sequence number, atomically.
func (c *channel) nextSequence() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.sequence
	c.sequence++
	return n
}

// StreamID returns the channel's stable identifier (a UUID, not the h2 stream id).
func (c *channel) StreamID() string { return c.streamID }

// Next returns the next envelope on this channel.
//
// Returns io.EOF on normal close, *layer.StreamError on stream error,
// ctx.Err() on cancellation.
func (c *channel) Next(ctx context.Context) (*envelope.Envelope, error) {
	select {
	case env, ok := <-c.recv:
		if !ok {
			// Drain a pending error if any.
			select {
			case se := <-c.errCh:
				return nil, se
			default:
			}
			return nil, io.EOF
		}
		return env, nil
	case se := <-c.errCh:
		return nil, se
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.layer.shutdown:
		return nil, io.EOF
	}
}

// Send writes the envelope as one logical message on this stream.
//
// For push channels, only RST_STREAM is permitted (the channel models a
// server-initiated stream we did not request).
func (c *channel) Send(ctx context.Context, env *envelope.Envelope) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("http2: send on closed channel")
	}
	c.mu.Unlock()

	if c.isPush {
		return errors.New("http2: send on push channel rejected — only RST_STREAM is valid")
	}

	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		return fmt.Errorf("http2: Send requires *HTTPMessage, got %T", env.Message)
	}

	if handled, err := c.trySendOpaque(ctx, env, msg); handled {
		return err
	}
	return c.sendSynthetic(ctx, env, msg)
}

// trySendOpaque returns (handled=true, err) when the opaque zero-copy path
// applies, (false, nil) otherwise. Restricted to same-Layer sends: cross-
// Layer forwarding cannot use raw frames because HPACK dynamic-table indices
// are per-connection and MAX_FRAME_SIZE / flow-control state differ.
func (c *channel) trySendOpaque(ctx context.Context, env *envelope.Envelope, msg *envelope.HTTPMessage) (bool, error) {
	op, ok := env.Opaque.(*opaqueHTTP2)
	if !ok || op == nil || op.layer != c.layer || op.streamID != c.h2Stream {
		return false, nil
	}
	if headersChanged(msg, op) || bodyChanged(msg, op) || len(op.frames) == 0 {
		return false, nil
	}
	done := make(chan error, 1)
	c.layer.enqueueWrite(writeRequest{opaque: &writeOpaque{
		streamID: c.h2Stream,
		frames:   op.frames,
		done:     done,
	}})
	if err := waitDone(ctx, done, c.layer.shutdown); err != nil {
		return true, err
	}
	// The opaque snapshot is captured when the reader has observed the full
	// inbound message (assembler asmDone), so op.frames always include
	// END_STREAM on the last frame. Successful dispatch therefore means our
	// send half is closed.
	c.mu.Lock()
	c.sentEndStream = true
	c.mu.Unlock()
	return true, nil
}

// sendSynthetic re-encodes the message into HEADERS (+ CONTINUATION) + DATA
// + trailer HEADERS via the Layer's HPACK encoder and frame writer.
func (c *channel) sendSynthetic(ctx context.Context, env *envelope.Envelope, msg *envelope.HTTPMessage) error {
	headers := buildHeaderFields(env, msg)
	trailers, trailerAnomalies := buildTrailerFields(msg.Trailers)
	if len(trailerAnomalies) > 0 {
		msg.Anomalies = append(msg.Anomalies, trailerAnomalies...)
	}

	sendBody, sendReader, err := selectSendBody(msg)
	if err != nil {
		return err
	}

	done := make(chan error, 1)
	c.layer.enqueueWrite(writeRequest{message: &writeMessage{
		streamID:   c.h2Stream,
		headers:    headers,
		body:       sendBody,
		bodyReader: sendReader,
		trailers:   trailers,
		endStream:  true,
		done:       done,
	}})
	if err := waitDone(ctx, done, c.layer.shutdown); err != nil {
		return err
	}
	c.mu.Lock()
	c.headersHas = true
	// writeMessage always sets endStream=true, so a successful return means
	// we have closed the send half.
	c.sentEndStream = true
	c.mu.Unlock()
	return nil
}

// selectSendBody picks the body representation the writer goroutine should
// use, in priority order:
//
//  1. msg.Body != nil — memory-resident bytes from the pipeline.
//  2. msg.BodyBuffer != nil — open a fresh reader (file-mode opens a new
//     fd independent of the Write handle; memory-mode wraps the slice).
//  3. msg.BodyStream != nil — reserved for future streaming protocols.
//  4. none set — headers-only message; writeMessage emits HEADERS with
//     END_STREAM.
func selectSendBody(msg *envelope.HTTPMessage) ([]byte, io.Reader, error) {
	if msg.Body != nil {
		return msg.Body, nil, nil
	}
	if msg.BodyBuffer != nil {
		r, rerr := msg.BodyBuffer.Reader()
		if rerr != nil {
			return nil, nil, fmt.Errorf("http2: open body buffer reader: %w", rerr)
		}
		// writeStreamingBody drains to EOF; wrap in a closer-closing reader
		// so the underlying fd (for file-backed buffers) is released when
		// the writer goroutine finishes with it.
		return nil, &readCloserOnce{rc: r}, nil
	}
	if msg.BodyStream != nil {
		return nil, msg.BodyStream, nil
	}
	return nil, nil, nil
}

// Close tears down the receive side and, for abnormal terminations, emits
// RST_STREAM(CANCEL). Idempotent.
//
// RST_STREAM is suppressed when the stream has completed bilaterally on the
// wire — both sides have sent END_STREAM. In that case the stream is
// already in RFC 9113 §5.1 "closed" state; sending RST would arrive on a
// closed stream and provoke a peer PROTOCOL_ERROR + GOAWAY, aborting other
// concurrent streams on the shared connection. session.RunSession defers
// Close on every session exit (normal or abnormal), so this gate is the
// difference between a quiet cleanup and a connection-wide cascade.
//
// Push channels always RST on Close: we never requested them, and an
// unwanted-push rejection is legitimate regardless of peer state
// (RFC 9113 §8.4).
func (c *channel) Close() error {
	c.closeSendOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		sentEnd := c.sentEndStream
		recvEnd := c.recvEndStream
		c.mu.Unlock()

		// Emit RST_STREAM(CANCEL) unless the stream has completed
		// bilaterally — in which case wire-level "closed" state forbids
		// any further frames on this stream (RFC 9113 §5.1).
		if c.isPush || !sentEnd || !recvEnd {
			c.layer.enqueueWrite(writeRequest{rst: &writeRST{
				streamID: c.h2Stream,
				code:     ErrCodeCancel,
			}})
		}
		c.layer.closeChannelRecv(c)
		// Local cancellation is "normal" from the watcher's perspective:
		// we initiated it and do not want the session's late-error path
		// to cascade the close back onto the peer.
		c.markTerminated(io.EOF)
	})
	return nil
}

// opaqueHTTP2 holds Layer-internal state for raw-first patching.
//
// The opaque zero-copy fast path in channel.Send is valid only when the
// receiving Channel belongs to the same Layer that produced the snapshot:
// HPACK dynamic-table indices embedded in op.frames are meaningful only
// within the encoder/decoder pair of one connection. Cross-Layer forwarding
// (e.g., upstream → client in a MITM proxy) must re-encode through the
// destination Layer's HPACK context. The layer field records the owning
// Layer for this identity check.
//
// Body snapshot semantics mirror HTTP/1.x (USK-631):
//   - origBody carries a defensive copy of msg.Body at envelope creation
//     time when the assembler finalized into memory mode.
//   - origBodyBuffer records the BodyBuffer pointer when the assembler
//     finalized into file-backed mode. The assembler does NOT Retain when
//     stamping opaqueHTTP2 — origBodyBuffer and msg.BodyBuffer share the
//     single refcount the assembler minted. That is safe because
//     opaqueHTTP2 only reads the pointer (for identity comparison in
//     bodyChanged) and never calls Reader/Bytes/Release itself. The
//     terminal Release is performed by session OnComplete (USK-634).
//
// bodyChanged compares pointers first (file-backed path), then falls back
// to byte comparison against origBody (memory path).
type opaqueHTTP2 struct {
	layer          *Layer // owning Layer; gates the zero-copy fast path to same-Layer sends
	streamID       uint32 // HTTP/2 stream ID (scoped to layer)
	frames         [][]byte
	origHeaders    []hpack.HeaderField
	origBody       []byte
	origBodyBuffer *bodybuf.BodyBuffer
	isPush         bool
}

// headersChanged reports whether the message's headers differ from the
// original (pre-Pipeline) ones.
//
// We must NOT compare positionally because buildHeaderFields generates the
// pseudo-header list in a fixed canonical order (:method, :scheme,
// :authority, :path / :status), while op.origHeaders preserves the wire
// order the peer used. A positional mismatch on a non-canonical-order peer
// would falsely claim "headers changed", forcing every Send through the
// HPACK re-encode path and defeating the opaque zero-copy fast path.
//
// Instead, separately compare the pseudo-header values (set semantics) and
// the regular header sequence (which IS order-sensitive on the wire).
func headersChanged(msg *envelope.HTTPMessage, op *opaqueHTTP2) bool {
	if op == nil || op.origHeaders == nil {
		return true
	}
	origPseudo, origRegular := splitOrigHeaders(op.origHeaders)
	if pseudoChanged(msg, origPseudo) {
		return true
	}
	return regularHeadersChanged(msg.Headers, origRegular)
}

// splitOrigHeaders separates a wire-order header list into a pseudo-header
// value map (first-occurrence-wins) and the regular-header sequence.
func splitOrigHeaders(orig []hpack.HeaderField) (map[string]string, []hpack.HeaderField) {
	pseudo := map[string]string{}
	regular := make([]hpack.HeaderField, 0, len(orig))
	for _, hf := range orig {
		if strings.HasPrefix(hf.Name, ":") {
			if _, ok := pseudo[hf.Name]; !ok {
				pseudo[hf.Name] = hf.Value
			}
			continue
		}
		regular = append(regular, hf)
	}
	return pseudo, regular
}

// pseudoChanged reports whether msg's request/response pseudo-headers differ
// from origPseudo. Direction is inferred from whether origPseudo carries a
// :status (response) or msg.Status is set.
func pseudoChanged(msg *envelope.HTTPMessage, origPseudo map[string]string) bool {
	if msg.Status != 0 || origPseudo[":status"] != "" {
		return pseudoStatus(msg) != origPseudo[":status"]
	}
	if msg.Method != origPseudo[":method"] {
		return true
	}
	if msg.Scheme != origPseudo[":scheme"] {
		return true
	}
	if msg.Authority != origPseudo[":authority"] {
		return true
	}
	return reconstructPath(msg) != origPseudo[":path"]
}

// regularHeadersChanged reports whether the wire-order regular header
// sequence differs (including duplicates and order). Names are compared
// case-insensitively because the wire form is lowercase per RFC 9113 §8.2.1.
func regularHeadersChanged(msgHeaders []envelope.KeyValue, origRegular []hpack.HeaderField) bool {
	if len(msgHeaders) != len(origRegular) {
		return true
	}
	for i, kv := range msgHeaders {
		if strings.ToLower(kv.Name) != origRegular[i].Name {
			return true
		}
		if kv.Value != origRegular[i].Value {
			return true
		}
	}
	return false
}

// pseudoStatus returns the :status pseudo-header value buildHeaderFields
// would emit for msg. Mirrors the response branch in buildHeaderFields.
func pseudoStatus(msg *envelope.HTTPMessage) string {
	if msg.Status == 0 {
		return "200"
	}
	return strconv.Itoa(msg.Status)
}

// reconstructPath returns the :path pseudo-header value buildHeaderFields
// would emit for msg. Mirrors the request branch in buildHeaderFields.
func reconstructPath(msg *envelope.HTTPMessage) string {
	path := msg.Path
	if path == "" {
		path = "/"
	}
	if msg.RawQuery != "" {
		path = path + "?" + msg.RawQuery
	}
	return path
}

// bodyChanged reports whether the message body was modified after the
// assembler handed the envelope to the pipeline.
//
// Two tracks mirror the HTTP/1.x layer (USK-631):
//
//   - File-backed: assembler stamped op.origBodyBuffer with the pointer
//     handed to msg.BodyBuffer. Pointer inequality signals a change
//     (pipeline replaced, dropped, or materialized the buffer). A match
//     with msg.BodyBuffer non-nil permits opaque reuse.
//   - Memory-backed: assembler left op.origBodyBuffer == nil and stamped
//     op.origBody with a defensive copy of msg.Body. Modifications are
//     detected by comparing msg.Body to op.origBody; differences force the
//     synthetic path.
//
// A defensive "mixed state" guard: when either side swapped tracks (e.g.
// pipeline added a BodyBuffer where origBody was set), treat as changed —
// the opaque frames correspond to the original storage mode, and
// reconstructing them from the new representation is not a fast-path
// concern.
func bodyChanged(msg *envelope.HTTPMessage, op *opaqueHTTP2) bool {
	// File-backed track: BodyBuffer pointer identity decides.
	if op.origBodyBuffer != nil || msg.BodyBuffer != nil {
		return op.origBodyBuffer != msg.BodyBuffer
	}
	// Memory track: compare bytes against the defensive snapshot.
	if len(msg.Body) != len(op.origBody) {
		return true
	}
	for i, b := range msg.Body {
		if b != op.origBody[i] {
			return true
		}
	}
	return false
}

// readCloserOnce wraps an io.ReadCloser so that io.Copy-style callers
// (writeStreamingBody) see the Read surface while Close is fired once on
// any terminal Read outcome. The h2 writer goroutine owns the lifetime
// and discards the reader after a terminal error or EOF, so firing Close
// on the first non-nil error is the correct fd-release hook for
// file-backed BodyBuffer readers — an EOF-only gate would leak the
// underlying os.File fd if writeStreamingBody returned on a non-EOF read
// error or on a wire write error.
type readCloserOnce struct {
	rc     io.ReadCloser
	closed bool
}

func (r *readCloserOnce) Read(p []byte) (int, error) {
	n, err := r.rc.Read(p)
	if err != nil && !r.closed {
		r.closed = true
		_ = r.rc.Close()
	}
	return n, err
}

// buildHeaderFields constructs the HPACK header field list for a message,
// generating the appropriate pseudo-headers from the envelope/HTTPMessage.
func buildHeaderFields(env *envelope.Envelope, msg *envelope.HTTPMessage) []hpack.HeaderField {
	out := make([]hpack.HeaderField, 0, len(msg.Headers)+5)

	if msg.Status != 0 || isResponse(env, msg) {
		// Response.
		status := strconv.Itoa(msg.Status)
		if msg.Status == 0 {
			status = "200"
		}
		out = append(out, hpack.HeaderField{Name: ":status", Value: status})
	} else {
		// Request.
		method := msg.Method
		if method == "" {
			method = "GET"
		}
		out = append(out, hpack.HeaderField{Name: ":method", Value: method})
		scheme := msg.Scheme
		if scheme == "" {
			scheme = "https"
		}
		out = append(out, hpack.HeaderField{Name: ":scheme", Value: scheme})
		if msg.Authority != "" {
			out = append(out, hpack.HeaderField{Name: ":authority", Value: msg.Authority})
		}
		path := msg.Path
		if path == "" {
			path = "/"
		}
		if msg.RawQuery != "" {
			path = path + "?" + msg.RawQuery
		}
		out = append(out, hpack.HeaderField{Name: ":path", Value: path})
	}

	for _, kv := range msg.Headers {
		// Per RFC 9113 §8.2.1, header names in HTTP/2 MUST be lowercase on
		// the wire; uppercase names cause peers to treat the message as
		// malformed (and likely RST_STREAM with PROTOCOL_ERROR).
		//
		// MITM-fidelity caveat: this means the Send path normalizes case,
		// while the Receive path (assembler.go) preserves wire case and
		// flags H2UppercaseHeaderName as an anomaly. Operators wishing to
		// pentest a server's behavior on uppercase header names cannot
		// currently emit them through this path; they must use the opaque
		// zero-copy path with hand-crafted frames or extend this layer to
		// honor an explicit "preserve case" flag on KeyValue.
		name := strings.ToLower(kv.Name)
		out = append(out, hpack.HeaderField{Name: name, Value: kv.Value})
	}
	return out
}

// buildTrailerFields converts HTTPMessage.Trailers to lowercase hpack.HeaderField
// entries for the trailer HEADERS frame, and returns anomalies describing any
// diagnostic issues in the supplied trailers. Returns nil fields when there are
// no trailers so the writer's hasTrailers check stays false and no frame is
// emitted.
//
// HTTP/2 trailers must not contain pseudo-headers (RFC 9113 §8.1); any such
// entries are dropped from the wire (they would cause the peer to treat the
// stream as malformed) but flagged with H2InvalidPseudoHeader on msg.Anomalies
// so the diagnostic record captures what the caller attempted. Wire case is
// normalized to lowercase per the same rule as initial headers (documented
// limitation in buildHeaderFields).
//
// Connection-specific headers (RFC 9113 §8.2.2 — Connection, Keep-Alive,
// Transfer-Encoding, Upgrade, and TE != "trailers") and uppercase names are
// NOT filtered. MITM wire-fidelity policy prohibits silent normalization on
// the Send path. Instead we mirror the Receive path's regularHeaderAnomalies
// helper (assembler.go) so operators see the same diagnostic record whether
// the anomaly originated client-side or server-side.
func buildTrailerFields(trailers []envelope.KeyValue) ([]hpack.HeaderField, []envelope.Anomaly) {
	if len(trailers) == 0 {
		return nil, nil
	}
	out := make([]hpack.HeaderField, 0, len(trailers))
	var anomalies []envelope.Anomaly
	for _, kv := range trailers {
		if strings.HasPrefix(kv.Name, ":") {
			anomalies = append(anomalies, envelope.Anomaly{
				Type:   envelope.H2InvalidPseudoHeader,
				Detail: "in trailers: " + kv.Name,
			})
			continue
		}
		// Flag anomalies against the ORIGINAL (pre-lowercase) name so
		// H2UppercaseHeaderName is actually observable. regularHeaderAnomalies
		// handles the §8.2.2 set (h1-only names + malformed "te:") identically
		// for initial headers and trailers per RFC 9113 §8.1.
		anomalies = append(anomalies, regularHeaderAnomalies(hpack.HeaderField{
			Name:  kv.Name,
			Value: kv.Value,
		})...)
		out = append(out, hpack.HeaderField{
			Name:  strings.ToLower(kv.Name),
			Value: kv.Value,
		})
	}
	if len(out) == 0 {
		return nil, anomalies
	}
	return out, anomalies
}

// isResponse infers whether msg is a response (vs request) when env is nil
// or env.Direction is unset.
func isResponse(env *envelope.Envelope, msg *envelope.HTTPMessage) bool {
	if env != nil {
		return env.Direction == envelope.Receive
	}
	return msg.Status != 0
}

// waitDone blocks until the writer signals done, or ctx/shutdown fires.
func waitDone(ctx context.Context, done chan error, shutdown chan struct{}) error {
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-shutdown:
		return errWriterClosed
	}
}
