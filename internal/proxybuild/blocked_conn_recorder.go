package proxybuild

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// blockedConn describes a connection a listener-level gate refused (or
// could not serve) before any envelope existed — a scope or rate-limit
// refusal, a failed upstream dial, a failed TLS MITM handshake. No
// upstream socket was handed to a Layer, so the recorded Stream has no
// ServerAddr and no Flow rows: the payload never reached the flow store.
type blockedConn struct {
	// Protocol / Scheme are the Stream's protocol family and scheme.
	Protocol string
	Scheme   string
	// ClientAddr is the client's remote address.
	ClientAddr string
	// ScopeHost / SNI feed the capture_scope check (the target host, then
	// the ClientHello SNI when one was seen).
	ScopeHost string
	SNI       string
	// BlockedBy is the refusal attribution (target_scope, rate_limit);
	// empty for a failure that is not a policy refusal.
	BlockedBy     string
	FailureReason string
	// ClientJA3 / ClientJA4 are the client fingerprints, when a
	// ClientHello was peeked.
	ClientJA3 string
	ClientJA4 string
	// Tags are the Stream's audit tags (via, target, reason, and e.g.
	// RateLimitDenial.Tags).
	Tags map[string]string
}

// blockedConnRecorder writes one self-contained State="error" Stream per
// blockedConn. It is the recording seam shared by the listener-level gates
// that refuse a connection before the Pipeline runs: the transparent
// listener's Observer.OnBlocked, the tcp_forwards accept-time rate-limit
// gate, and the CONNECT / plain-HTTP forward / SOCKS5 rate-limit gates
// (connector.OnGateRefusalFunc, via gateRefusalCallback). A nil recorder
// (no flow store) records nothing.
//
// Each record is one synchronous SaveStream on the refused connection's own
// goroutine, bounded by a 5s timeout. A refusal costs at most what an
// admitted connection would have cost (which records at least one Stream),
// so a refusal flood does not amplify the DB load beyond the traffic that
// produced it; the listener's max_connections bounds how many such writes
// run at once (a refused connection holds its slot until the write ends).
type blockedConnRecorder struct {
	store        flow.Writer
	listenerName string
	logger       *slog.Logger
	scope        *flow.RecordScope
}

// newBlockedConnRecorder returns the recorder; a nil store yields nil.
func newBlockedConnRecorder(store flow.Writer, listenerName string, logger *slog.Logger, scope *flow.RecordScope) *blockedConnRecorder {
	if store == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &blockedConnRecorder{store: store, listenerName: listenerName, logger: logger, scope: scope}
}

// record persists b. ctx supplies the conn ID (connector.ConnIDFromContext);
// the write itself runs under its own timeout so a cancelled connection
// context does not drop the audit row. Out-of-capture_scope targets are not
// written.
func (r *blockedConnRecorder) record(ctx context.Context, b blockedConn) {
	if r == nil {
		return
	}
	streamID := uuid.New().String()
	if r.scope != nil && !r.scope.IsEmpty() {
		obs := connector.PassthroughObservation{RemoteAddr: b.ClientAddr, TargetHost: b.ScopeHost, SNI: b.SNI}
		pr := passthroughRecorder{}
		if !r.scope.ShouldRecord(pr.envelopeForScope(streamID, obs)) {
			return
		}
	}
	st := &flow.Stream{
		ID:            streamID,
		ConnID:        connector.ConnIDFromContext(ctx),
		Protocol:      b.Protocol,
		Scheme:        b.Scheme,
		State:         "error",
		FailureReason: b.FailureReason,
		BlockedBy:     b.BlockedBy,
		Timestamp:     time.Now(),
		Origin:        flow.OriginProxy,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr:   b.ClientAddr,
			TLSClientJA3: b.ClientJA3,
			TLSClientJA4: b.ClientJA4,
		},
		ListenerName: r.listenerName,
		Tags:         b.Tags,
	}
	saveCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.store.SaveStream(saveCtx, st); err != nil {
		r.logger.Error("blocked connection recorder: audit stream save failed",
			"stream_id", streamID, "blocked_by", b.BlockedBy, "error", err)
	}
}

// gateRefusalCallback adapts r to the connector's CONNECT / plain-HTTP
// forward / SOCKS5 gate-refusal hook (USK-1381). A nil recorder yields a
// nil callback, so the handlers only log.
func gateRefusalCallback(r *blockedConnRecorder) connector.OnGateRefusalFunc {
	if r == nil {
		return nil
	}
	return func(ctx context.Context, g connector.GateRefusal) {
		protocol, scheme := gateRefusalProtocolScheme(g.Via)
		r.record(ctx, blockedConn{
			Protocol:      protocol,
			Scheme:        scheme,
			ClientAddr:    g.ClientAddr,
			ScopeHost:     g.Host,
			BlockedBy:     g.BlockedBy,
			FailureReason: g.BlockedBy,
			Tags:          g.Tags,
		})
	}
}

// gateRefusalProtocolScheme maps a refusing gate to its Stream protocol
// and scheme. A CONNECT and a plain-HTTP forward are HTTP exchanges; only
// the forward has a known scheme (the CONNECT tunnel's inner transport
// was never established). A SOCKS5 tunnel is a transport, recorded raw
// with no scheme.
func gateRefusalProtocolScheme(via string) (protocol, scheme string) {
	switch via {
	case "http1-forward":
		return string(envelope.ProtocolHTTP), "http"
	case "connect":
		return string(envelope.ProtocolHTTP), ""
	default:
		return string(envelope.ProtocolRaw), ""
	}
}
