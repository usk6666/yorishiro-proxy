package ws

import (
	"io"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// options holds resolved configuration for a Layer constructed via New.
type options struct {
	// ctxTmpl is stamped onto every emitted Envelope (Context field).
	// EnvelopeContext.UpgradePath / UpgradeQuery should be set by the
	// caller before passing the value here so per-frame envelopes carry
	// the wire-observed Upgrade request URL.
	ctxTmpl envelope.EnvelopeContext

	// deflateEnabled is the master switch for permessage-deflate. When
	// false, every frame is treated as uncompressed regardless of the
	// per-direction params.
	deflateEnabled bool

	// clientDeflate / serverDeflate are the per-direction compressor
	// states. They are only consulted when deflateEnabled is true.
	clientDeflate deflateParams
	serverDeflate deflateParams

	// maxFrameSize caps Receive payloads (pre-decompression) and Send
	// payloads (pre-mask). Default = maxFramePayloadSize (16 MiB).
	maxFrameSize int64

	// stateReleaser is the optional pluginv2 hook invoked when the Channel
	// reaches its terminal state. Drives ReleaseTransaction for the WS
	// upgrade-pair scope. nil = no-op (legacy parallel).
	stateReleaser pluginv2.StateReleaser

	// lifecycleEngine is the optional pluginv2 Engine consulted on
	// terminal-state transitions to fire (ws, on_close) hooks. nil =
	// no-op. The Engine and the StateReleaser are typically the same
	// *pluginv2.Engine instance but are wired through separate Options
	// so tests / future N9 production wiring can compose them
	// independently.
	lifecycleEngine *pluginv2.Engine
}

// Option tunes the WSLayer.
type Option func(*options)

// WithEnvelopeContext sets the EnvelopeContext template stamped on every
// emitted Envelope. The caller is expected to populate
// EnvelopeContext.UpgradePath and UpgradeQuery from the wire-observed
// HTTP Upgrade request URL.
func WithEnvelopeContext(ctx envelope.EnvelopeContext) Option {
	return func(o *options) { o.ctxTmpl = ctx }
}

// WithDeflateEnabled toggles the permessage-deflate (RFC 7692) feature.
// Default is false. Even when true, the per-direction WithClientDeflate /
// WithServerDeflate Options must opt the corresponding direction into the
// extension; otherwise the direction is treated as uncompressed.
//
// Setting WithDeflateEnabled(false) overrides any per-direction
// compressor params, acting as a kill switch.
func WithDeflateEnabled(enabled bool) Option {
	return func(o *options) { o.deflateEnabled = enabled }
}

// WithClientDeflate configures the client→server direction's
// permessage-deflate state. The shape matches parseDeflateExtension's
// "client" return value.
func WithClientDeflate(p deflateParams) Option {
	return func(o *options) { o.clientDeflate = p }
}

// WithServerDeflate configures the server→client direction's
// permessage-deflate state.
func WithServerDeflate(p deflateParams) Option {
	return func(o *options) { o.serverDeflate = p }
}

// WithMaxFrameSize caps the per-frame payload byte count. The cap applies
// to both Receive (pre-decompression) and Send (pre-mask). Non-positive n
// leaves the default in place.
func WithMaxFrameSize(n int64) Option {
	return func(o *options) {
		if n > 0 {
			o.maxFrameSize = n
		}
	}
}

// WithStateReleaser injects a pluginv2.StateReleaser the Layer invokes
// when the Channel reaches its terminal state. The release fires
// ReleaseTransaction(ConnID, StreamID) — the WS upgrade-pair is the
// transaction scope per RFC §9.3 D6. nil = no-op.
func WithStateReleaser(r pluginv2.StateReleaser) Option {
	return func(o *options) { o.stateReleaser = r }
}

// WithLifecycleEngine injects a pluginv2 Engine the Layer consults on
// terminal-state transitions to fire (ws, on_close) hooks per RFC §9.3
// PhaseSupportNone. The hook fires once per Channel — between recvDone
// close and the transaction state release — so plugin code observing
// the close still sees live transaction_state. nil = no-op.
func WithLifecycleEngine(e *pluginv2.Engine) Option {
	return func(o *options) { o.lifecycleEngine = e }
}

// WithDeflateFromExtensionHeader configures permessage-deflate (RFC 7692)
// from a Sec-WebSocket-Extensions header value (typically the server's
// 101 response value, which is authoritative on what got negotiated). The
// header is parsed for the "permessage-deflate" extension and both
// directions are configured from the resulting parameters. An empty
// header or a header without "permessage-deflate" leaves deflate disabled.
//
// This is the preferred entry point for callers that recover deflate
// state from a recorded handshake (e.g. the resend_ws MCP tool). The
// internal deflateParams shape stays unexported so future RFC 7692
// parameter additions can land without breaking the caller-visible API.
func WithDeflateFromExtensionHeader(serverNegotiated string) Option {
	return func(o *options) {
		if serverNegotiated == "" {
			return
		}
		client, server := parseDeflateExtension(serverNegotiated)
		if !client.enabled && !server.enabled {
			return
		}
		o.deflateEnabled = true
		o.clientDeflate = client
		o.serverDeflate = server
	}
}

// Layer wraps a bidirectional WebSocket byte stream — a (reader, writer,
// closer) triple typically obtained from http1.Layer.DetachStream after a
// successful HTTP/1.1 Upgrade — and yields exactly one Channel that emits
// one Envelope per WebSocket frame (frame-per-Envelope per RFC-001 §3.2.2).
//
// The Layer OWNS the supplied reader/writer/closer. Close cascades to
// closer.Close() and marks the Channel terminated.
//
// Read-time Direction is derived from Role:
//   - RoleServer (client-facing) → Direction=Send  (reads from client, masked)
//   - RoleClient (upstream-facing) → Direction=Receive (reads from server, unmasked)
//
// Send-time Direction is derived symmetrically:
//   - RoleServer writes Direction=Receive frames (unmasked)
//   - RoleClient writes Direction=Send frames (masked, key regenerated
//     from crypto/rand per frame)
//
// The Layer does NOT auto-respond to Ping (the proxy must surface them to
// the Pipeline so the recording layer can observe the wire).
//
// Limitations:
//   - No background watcher goroutine for post-EOF RST observation; if the
//     wire is closed by the peer between Next calls, the next Next observes
//     io.EOF (graceful) or *layer.StreamError{Code: ErrorAborted}. Late
//     RST detection is owned by USK-643 (Session-level RST handling).
//   - Send-side fragmentation is the caller's responsibility: the Layer
//     emits exactly one wire frame per Send call. Callers that want to
//     fragment a large message must split it across multiple Send calls
//     with the appropriate Fin / Opcode values (matching RFC 6455 §5.4).
//   - Fragmented compressed messages (RFC 7692): continuation envelopes
//     carry the compressed-verbatim payload + Compressed=true. The FIN
//     frame's envelope carries the decompressed payload of the entire
//     reassembled message (Compressed=true, Fin=true). On Send, callers
//     must flag continuations + the FIN frame consistently; the Layer
//     compresses each Send frame independently when Compressed=true is
//     set (same wire shape as the legacy /protocol/ws path).
type Layer struct {
	reader io.Reader
	writer io.Writer
	closer io.Closer

	ch        chan layer.Channel
	channel   *wsChannel
	closeOnce sync.Once
}

// New constructs a WSLayer over (reader, writer, closer). The Layer owns
// the resources: Close cascades to closer.Close(). streamID is the
// stream-level identifier returned by the produced Channel's StreamID.
//
// reader is typically a *bufio.Reader returned by
// http1.Layer.DetachStream so any post-CRLFCRLF bytes already buffered
// from the 101 response are visible to the WebSocket frame parser.
func New(reader io.Reader, writer io.Writer, closer io.Closer, streamID string, role Role, opts ...Option) *Layer {
	o := options{
		maxFrameSize: maxFramePayloadSize,
	}
	for _, opt := range opts {
		opt(&o)
	}

	l := &Layer{
		reader: reader,
		writer: writer,
		closer: closer,
		ch:     make(chan layer.Channel, 1),
	}

	c := newChannel(l, streamID, role, &o)
	l.channel = c
	l.ch <- c
	close(l.ch)
	return l
}

// Channels returns a buffered channel that yields exactly one Channel
// (the wrapper for this connection) and is then closed. Subsequent
// receives return the zero value and ok=false (one-shot semantics).
func (l *Layer) Channels() <-chan layer.Channel { return l.ch }

// Close cascades closer.Close() to the underlying transport and marks the
// inner Channel terminated. Idempotent via sync.Once: a second Close
// returns the cached error from the first call (typically nil).
func (l *Layer) Close() error {
	var err error
	l.closeOnce.Do(func() {
		if l.closer != nil {
			err = l.closer.Close()
		}
		if l.channel != nil {
			l.channel.markTerminated(io.EOF)
		}
	})
	return err
}
