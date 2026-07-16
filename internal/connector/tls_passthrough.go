package connector

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/tlsfingerprint"
)

// PassthroughObservation captures everything the proxy could observe about
// a single TLS passthrough relay. It is the value type the connector
// surfaces to upstream observers (USK-790 audit-trail meta flow recorder).
//
// Observation lifecycle:
//   - PassthroughObserver.OnStart fires after the upstream TCP dial
//     succeeds and the SNI peek completes. UpstreamAddr and SNI are set;
//     byte counters are zero; ErrorReason is empty.
//   - PassthroughObserver.OnComplete fires after the bidirectional relay
//     returns. Byte counters reflect the totals io.Copy reported. When the
//     relay aborted abnormally, ErrorReason carries a short string and
//     Outcome is "failed"; otherwise Outcome is "tunneled".
//
// Both callbacks must be cheap on the relay path — they are invoked
// synchronously from the connector goroutine that owns the connection.
// Observers that persist to a database should defer the write to a
// background goroutine and treat the call as best-effort.
type PassthroughObservation struct {
	// SNI is the host_name extracted from the client's first TLS
	// ClientHello, or empty when the client sent no SNI extension or
	// the peek failed before any bytes arrived.
	SNI string

	// LocalAddr is the proxy-side local address of the client-facing
	// socket (host:port). Always set when the observer fires.
	LocalAddr string

	// RemoteAddr is the connecting client's remote address (host:port).
	// Always set when the observer fires.
	RemoteAddr string

	// UpstreamAddr is the resolved upstream address dialed by the proxy
	// for the relay (host:port). Set on OnStart when the dial succeeded;
	// empty when the dial itself failed (in which case OnComplete is
	// invoked with Outcome="failed" and OnStart never fired).
	UpstreamAddr string

	// ClientJA3 / ClientJA4 are the client's ClientHello fingerprints
	// computed from the SNI peek buffer (USK-1015). Empty when the peek
	// failed or the ClientHello was malformed. Under passthrough the proxy
	// never decrypts the tunnel, but the ClientHello is sent in the clear
	// before the encrypted handshake body, so the fingerprint is a legal
	// observation (unlike ALPN / negotiated version, which are not).
	ClientJA3 string
	ClientJA4 string

	// TargetHost is the hostname portion of the CONNECT / SOCKS5 target
	// authority the client requested (without ":port"). Unlike
	// UpstreamAddr (a resolved IP literal), this preserves the hostname
	// the client actually addressed, which is required for
	// capture_scope.hostname matching on the synthetic audit envelope
	// (USK-845). Always populated when set by the connector — both the
	// post-dial OnStart obs and the pre-OnStart dial-failure obs carry it.
	// May be empty only when callers construct an observation by hand in
	// tests; in that case capture_scope falls back to SNI.
	TargetHost string

	// BytesClientToUpstream is the total bytes io.Copy relayed from the
	// client side to the upstream side over the lifetime of the relay.
	// Always zero on OnStart.
	BytesClientToUpstream int64

	// BytesUpstreamToClient is the total bytes io.Copy relayed from the
	// upstream side to the client side. Always zero on OnStart.
	BytesUpstreamToClient int64

	// Outcome reflects the proxy's view of the relay (NOT the inner TLS
	// handshake result, which is opaque under passthrough). Canonical
	// values: "tunneled" for clean completion, "failed" when the dial or
	// io.Copy errored. Always empty on OnStart.
	Outcome string

	// ErrorReason carries a short, human-readable explanation when
	// Outcome is "failed". Empty when Outcome is "tunneled".
	ErrorReason string
}

// PassthroughObserver is the audit hook the connector invokes around the
// passthrough relay so callers (proxybuild) can persist the meta flow
// surface required by USK-790.
//
// OnStart fires once after the upstream TCP dial succeeds and the SNI peek
// completed (with or without a host_name). Observers typically persist a
// flow.Stream + an initial flow.Flow at this point so a partial record is
// available to MCP consumers even if the relay then runs for a long time.
//
// OnComplete fires exactly once when the relay returns, regardless of
// outcome. It carries the final byte counters and the outcome
// classification. The observer should finalise the previously-recorded
// stream's State field here.
//
// When the upstream dial itself fails OnStart is NOT invoked — only
// OnComplete fires with UpstreamAddr empty, Outcome="failed", and
// ErrorReason populated. The observer is then responsible for emitting a
// state="error" stream for the failed dial.
type PassthroughObserver interface {
	OnStart(ctx context.Context, obs PassthroughObservation)
	OnComplete(ctx context.Context, obs PassthroughObservation)
}

// PassthroughObserverFunc adapts a function pair to PassthroughObserver.
// Either field may be nil; the connector skips the call when so.
type PassthroughObserverFunc struct {
	Start    func(ctx context.Context, obs PassthroughObservation)
	Complete func(ctx context.Context, obs PassthroughObservation)
}

// OnStart implements PassthroughObserver.
func (f PassthroughObserverFunc) OnStart(ctx context.Context, obs PassthroughObservation) {
	if f.Start != nil {
		f.Start(ctx, obs)
	}
}

// OnComplete implements PassthroughObserver.
func (f PassthroughObserverFunc) OnComplete(ctx context.Context, obs PassthroughObservation) {
	if f.Complete != nil {
		f.Complete(ctx, obs)
	}
}

// RelayTLSPassthrough performs a bidirectional raw TCP relay between the
// client connection and an upstream connection dialed to the given target.
// No TLS termination occurs — the proxy forwards the client's encrypted
// TLS traffic directly to upstream (and vice versa).
//
// This is used for hosts in the TLS passthrough list where the proxy should
// not perform MITM. No Pipeline, Layer, or ConnectionStack is involved.
//
// The function blocks until both directions are complete or ctx is cancelled.
//
// USK-790: Pass a non-nil observer to record a TLSHandshakeMessage audit
// flow for the relay. The observer's OnStart fires after the upstream dial
// succeeds and the SNI peek completes; OnComplete fires after the relay
// returns. Both callbacks are invoked synchronously on the relay
// goroutine — observers that touch persistent storage should treat the
// call as best-effort and not block.
func RelayTLSPassthrough(ctx context.Context, clientConn net.Conn, target string, opts DialRawOpts) error {
	return relayTLSPassthroughWithObserver(ctx, clientConn, target, opts, nil)
}

// RelayTLSPassthroughObserved is the observer-aware entry point for the
// passthrough relay. The connector handlers (CONNECT / SOCKS5) call this
// when a non-nil PassthroughObserver is configured so the relay records a
// TLSHandshakeMessage meta flow.
func RelayTLSPassthroughObserved(ctx context.Context, clientConn net.Conn, target string, opts DialRawOpts, observer PassthroughObserver) error {
	return relayTLSPassthroughWithObserver(ctx, clientConn, target, opts, observer)
}

// relayTLSPassthroughWithObserver is the shared implementation. observer
// may be nil — the byte-counting wrappers and SNI peek are skipped in that
// case so the no-observer path stays close to a plain io.Copy hot loop.
func relayTLSPassthroughWithObserver(
	ctx context.Context,
	clientConn net.Conn,
	target string,
	opts DialRawOpts,
	observer PassthroughObserver,
) error {
	// Dial upstream as plain TCP (no TLS — we relay the client's TLS directly).
	opts.TLSConfig = nil
	upstreamConn, _, dialErr := DialUpstreamRaw(ctx, target, opts)
	if dialErr != nil {
		if observer != nil {
			obs := PassthroughObservation{
				LocalAddr:   netAddrString(clientConn.LocalAddr()),
				RemoteAddr:  netAddrString(clientConn.RemoteAddr()),
				TargetHost:  hostOnly(target),
				Outcome:     "failed",
				ErrorReason: dialErr.Error(),
			}
			observer.OnComplete(ctx, obs)
		}
		return dialErr
	}

	slog.Debug("connector: TLS passthrough relay started", "target", target)

	// Best-effort SNI peek before the relay starts. The peek is bounded by
	// passthroughSNIPeekTimeout so a misbehaving client cannot stall the
	// relay forever; failure is logged and the audit flow records SNI="".
	var sni, clientJA3, clientJA4 string
	if observer != nil {
		sni, clientJA3, clientJA4 = peekClientHelloSNI(clientConn)
	}

	obs := PassthroughObservation{
		SNI:          sni,
		ClientJA3:    clientJA3,
		ClientJA4:    clientJA4,
		LocalAddr:    netAddrString(clientConn.LocalAddr()),
		RemoteAddr:   netAddrString(clientConn.RemoteAddr()),
		UpstreamAddr: netAddrString(upstreamConn.RemoteAddr()),
		TargetHost:   hostOnly(target),
	}
	if observer != nil {
		observer.OnStart(ctx, obs)
	}

	// Counted relay so OnComplete carries accurate byte totals.
	var (
		clientToUpstream atomic.Int64
		upstreamToClient atomic.Int64
	)
	relayErr := relayBidirectionalCounted(ctx, clientConn, upstreamConn, &clientToUpstream, &upstreamToClient)

	obs.BytesClientToUpstream = clientToUpstream.Load()
	obs.BytesUpstreamToClient = upstreamToClient.Load()
	if isTunneledOutcome(relayErr) {
		obs.Outcome = "tunneled"
	} else {
		obs.Outcome = "failed"
		obs.ErrorReason = relayErr.Error()
	}

	if observer != nil {
		observer.OnComplete(ctx, obs)
	}

	slog.Debug("connector: TLS passthrough relay ended",
		"target", target,
		"sni", sni,
		"bytes_client_to_upstream", obs.BytesClientToUpstream,
		"bytes_upstream_to_client", obs.BytesUpstreamToClient,
		"outcome", obs.Outcome,
		"error", relayErr,
	)
	return relayErr
}

// peekClientHelloSNI reads the first TLS record from clientConn without
// consuming it (when the conn is a *PeekConn — every connector entry point
// wraps the inbound conn in PeekConn before dispatching) and extracts the
// server_name extension's host_name. Returns the empty string on any
// failure mode (timeout, malformed record, no SNI extension); failures
// are logged at Debug since they are routine on the wire (TLS 1.2 fallbacks,
// TLS-over-something exotic, etc.).
//
// The peek is bounded by clientHelloPeekTimeout. Resetting the read
// deadline after the peek is critical: bufio.Reader.Peek reads from the
// underlying conn under the deadline, and leaving the deadline armed
// would cause the relay's first io.Copy read to fail with a deadline
// error before any TLS bytes flowed.
//
// USK-1015: the peek also computes the client's JA3/JA4 fingerprints from
// the same buffer. Under passthrough the proxy never decrypts the tunnel,
// but the ClientHello is on the wire in the clear, so the fingerprint is a
// legal observation (added ONLY here; ALPN / negotiated version stay absent
// to keep the "no fabricated data" contract). Empty on any peek/parse
// failure, matching the SNI fallback.
func peekClientHelloSNI(clientConn net.Conn) (sni, ja3, ja4 string) {
	pc, ok := clientConn.(*PeekConn)
	if !ok {
		return "", "", ""
	}
	if err := pc.SetReadDeadline(time.Now().Add(clientHelloPeekTimeout)); err != nil {
		slog.Debug("connector: passthrough SNI peek deadline arm failed", "error", err)
		return "", "", ""
	}
	defer func() {
		// Clear the deadline regardless of peek outcome so the relay's
		// io.Copy is not torpedoed by a pending timeout.
		_ = pc.SetReadDeadline(time.Time{})
	}()

	buf, err := pc.Peek(clientHelloPeekSize)
	if err != nil && len(buf) == 0 {
		// True peek failure (timeout / EOF / closed). Audit flow records
		// SNI="" and the relay still runs (the underlying io.Copy will
		// either see a closed conn and return promptly, or unblock on
		// the next byte the client sends).
		slog.Debug("connector: passthrough SNI peek failed", "error", err)
		return "", "", ""
	}
	ja3, ja4 = tlsfingerprint.Compute(buf)
	sni, parseErr := parseClientHelloSNI(buf)
	if parseErr != nil && !errors.Is(parseErr, errNotClientHello) && !errors.Is(parseErr, errClientHelloIncomplete) {
		slog.Debug("connector: passthrough SNI parse failed", "error", parseErr, "buffered", len(buf))
	}
	return sni, ja3, ja4
}

// netAddrString returns a.String() or empty when a is nil.
func netAddrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// hostOnly returns the host portion of a "host:port" authority, falling
// back to the raw value when no port is present (covers IP-literal-no-port
// and bare-hostname edge cases). USK-845 plumbs the CONNECT / SOCKS5
// target authority onto PassthroughObservation.TargetHost so the audit
// envelope's Context.TargetHost is the hostname the client requested
// rather than the proxy-side resolved IP — restoring the matcher's
// TargetHost → SNI fallback chain for capture_scope.hostname.
func hostOnly(authority string) string {
	if authority == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(authority); err == nil {
		return h
	}
	return authority
}

// isTunneledOutcome classifies relay return errors for the audit
// observation. The distinction the audit consumer cares about is "the
// proxy successfully relayed bytes for the lifetime of the connection"
// vs "the proxy aborted mid-relay". Connection-close conditions —
// io.EOF, "use of closed network connection" once the client or
// upstream initiated TCP FIN, broken-pipe race after a peer-side close,
// io.ErrClosedPipe on net.Pipe-backed test fixtures, and
// "connection reset by peer" (ECONNRESET) when a peer closes without
// draining pending bytes (TLS close_notify in flight, abrupt browser /
// mobile-handover close, etc.) — are all "tunneled" outcomes from the
// audit perspective: they describe the terminal close, not a mid-stream
// failure.
//
// This classification is deliberately tolerant: under-classifying an
// outcome as "failed" trains operators to ignore the field, which is
// worse than the rare false-tunneled on a genuine partial-relay error.
// When a connection genuinely fails the dial path or io.Copy errors
// out with a non-close error (e.g. "i/o timeout" mid-stream, a
// deadline-exceeded read, "no route to host") and that lands in the
// "failed" bucket. ECONNRESET intentionally moved to "tunneled" after
// USK-952: in MITM passthrough the dominant cause is ungraceful peer
// close after bytes have flowed, not a genuine partial-relay error.
func isTunneledOutcome(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	if errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	return false
}

// relayBidirectional copies data between a and b in both directions
// concurrently. It returns when both directions are done or ctx is cancelled.
// Both connections are closed when the function returns.
func relayBidirectional(ctx context.Context, a, b net.Conn) error {
	return relayBidirectionalCounted(ctx, a, b, nil, nil)
}

// relayBidirectionalCounted is the byte-counted variant. When aToB or bToA
// is non-nil the bytes copied in that direction are accumulated into the
// supplied counter. Either or both may be nil — the no-counter path is
// the original io.Copy hot loop without an extra wrapper.
func relayBidirectionalCounted(ctx context.Context, a, b net.Conn, aToB, bToA *atomic.Int64) error {
	defer a.Close()
	defer b.Close()

	// Cancel-driven shutdown: when ctx is cancelled, close both connections
	// to unblock the io.Copy goroutines. The done channel ensures the
	// goroutine exits promptly when the relay completes normally without
	// waiting for context cancellation.
	done := make(chan struct{})
	defer close(done)

	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				a.Close()
				b.Close()
			case <-done:
			}
		}()
	}

	var (
		wg      sync.WaitGroup
		errOnce sync.Once
		copyErr error
	)

	wg.Add(2)

	go func() {
		defer wg.Done()
		n, err := io.Copy(b, a)
		if aToB != nil {
			aToB.Store(n)
		}
		if err != nil {
			errOnce.Do(func() { copyErr = err })
		}
		// Half-close: signal the other direction that this side is done.
		if tc, ok := b.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		n, err := io.Copy(a, b)
		if bToA != nil {
			bToA.Store(n)
		}
		if err != nil {
			errOnce.Do(func() { copyErr = err })
		}
		if tc, ok := a.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()

	// If the context was cancelled, report that instead of the copy error.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return copyErr
}
