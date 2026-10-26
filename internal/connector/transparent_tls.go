package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// Transparent TLS route (USK-1317). A connection whose first byte is 0x16
// is routed by its ClientHello:
//
//   - an ALPN offer naming h2 or http/1.1 → MITM through
//     BuildConnectionStack's sniff-first path (the offer is forwarded
//     upstream verbatim, the client is advertised the upstream's pick);
//   - no ALPN offer → MITM, then the decrypted bytes decide: an HTTP/1.x
//     request from the client → HTTP/1, anything else (server-first,
//     opaque, h2c preface, nested TLS) → raw bytechunk;
//   - an offer of non-HTTP values only, or a ClientHello that could not be
//     parsed → the metadata-only passthrough (unchanged from USK-1316).
//
// The MITM upstream is dialed at the original destination with the SNI as
// the TLS name (UpstreamTarget{Dial: dst, TLS: sni:port}); a ClientHello
// without SNI uses the destination IP as the TLS name, so the MITM
// certificate carries an IP SAN and no SNI is sent upstream.

// transparentTLSClass is how the transparent listener handles a TLS
// connection, decided from its ClientHello.
type transparentTLSClass int

const (
	// transparentTLSPassthrough: metadata-only passthrough (no MITM).
	transparentTLSPassthrough transparentTLSClass = iota
	// transparentTLSMITM: the ALPN offer names an HTTP protocol; MITM
	// through BuildConnectionStack's sniff-first path.
	transparentTLSMITM
	// transparentTLSMITMNoALPN: no ALPN offered; MITM, then the decrypted
	// bytes decide HTTP/1 or raw.
	transparentTLSMITMNoALPN
)

// Transparent TLS MITM failure classifications (the FailureReason of the
// audit record; same taxonomy as the CONNECT recorder, USK-858).
const (
	TransparentFailureClientTLS   = "client_tls_error"
	TransparentFailureUpstreamTLS = "upstream_tls_error"
)

// classifyTransparentTLS classifies a peeked ClientHello. The ALPN values
// are compared byte-exact (MITM Principle 1): "HTTP/1.1" is not
// "http/1.1".
func classifyTransparentTLS(p ClientHelloPeek) transparentTLSClass {
	if !p.ExtensionsParsed {
		return transparentTLSPassthrough
	}
	if len(p.ALPN) == 0 {
		return transparentTLSMITMNoALPN
	}
	if alpnListContains(p.ALPN, ALPNProtocolH2) || alpnListContains(p.ALPN, ALPNProtocolHTTP11) {
		return transparentTLSMITM
	}
	return transparentTLSPassthrough
}

// transparentUpstreamTarget is the MITM target of a transparent TLS
// connection: dial the original destination, speak TLS as the SNI — or as
// the destination IP when the client sent none.
func transparentUpstreamTarget(dst netip.AddrPort, sni string) UpstreamTarget {
	ut := UpstreamTarget{Dial: dst.String(), TLS: dst.String()}
	if sni != "" {
		ut.TLS = net.JoinHostPort(sni, strconv.Itoa(int(dst.Port())))
	}
	return ut
}

// handleTLS runs the TLS route: ClientHello peek, classification, gate,
// then the passthrough relay or the MITM.
func (h *TransparentHandler) handleTLS(ctx context.Context, pc *PeekConn, dst netip.AddrPort, logger *slog.Logger) error {
	hello := peekClientHelloSNIAndALPN(pc)
	ut := transparentUpstreamTarget(dst, hello.SNI)
	class := classifyTransparentTLS(hello)
	if class != transparentTLSPassthrough && classifyTunnelRoute(h.cfg.PassthroughList, h.cfg.BuildCfg, ut).passthrough {
		class = transparentTLSPassthrough
	}
	// A route that never yields a request path — the passthrough relay, or
	// a raw_passthrough_hosts MITM — is checked strictly, as CONNECT does.
	opaque := class == transparentTLSPassthrough || ut.isRawPassthrough(h.cfg.BuildCfg)
	v := h.scopeTLS(dst, hello.SNI, opaque)
	nameAdmitted := v.allowed && v.needBinding
	if nameAdmitted {
		v = h.bindNames(ctx, dst, []string{hello.SNI})
	}
	if !v.allowed {
		h.refuse(ctx, pc, dst, TransparentRouteTLS, v, hello.SNI, logger)
		return nil
	}
	// The rate-limit gate is shared by both TLS classes and runs before
	// any TLS byte is written: a refused connection is reset (no 429 —
	// answering inside TLS would need a client-only handshake).
	if h.rateLimited(ctx, pc, dst, TransparentRouteTLS, hello.SNI, hello, logger) {
		return nil
	}
	sni := hello.SNI
	admit := func() (bool, string) {
		r := h.scopeTLS(dst, sni, opaque)
		return r.allowed, r.reason
	}
	if class == transparentTLSPassthrough {
		obs := h.newObservation(pc, dst, TransparentRouteTLS)
		obs.SNI, obs.ALPN, obs.ClientJA3, obs.ClientJA4 = hello.SNI, hello.ALPN, hello.ClientJA3, hello.ClientJA4
		return h.passthrough(ctx, pc, dst, obs, admit, logger)
	}
	// A MITM route admitted provisionally (opaque=false) may still resolve
	// to the raw relay (no-ALPN, non-HTTP bytes); the strict variant lets
	// LiveConns re-evaluate it as such once it does, as CONNECT does.
	var admitOpaque LiveConnAdmitFunc
	if !opaque {
		admitOpaque = func() (bool, string) {
			r := h.scopeTLS(dst, sni, true)
			return r.allowed, r.reason
		}
	}
	return h.mitmTLS(ctx, pc, dst, ut, hello, class, admit, admitOpaque, nameAdmitted, logger)
}

// mitmTLS registers the admitted connection, builds the MITM stack
// (dialing the original destination once) and runs its session.
func (h *TransparentHandler) mitmTLS(ctx context.Context, pc *PeekConn, dst netip.AddrPort, ut UpstreamTarget, hello ClientHelloPeek, class transparentTLSClass, admit, admitOpaque LiveConnAdmitFunc, nameAdmitted bool, logger *slog.Logger) error {
	ctx, release, ok := h.register(ctx, dst, admit, admitOpaque, logger)
	defer release()
	if !ok {
		h.refuse(ctx, pc, dst, TransparentRouteTLS, refuseScope("policy changed during admission"), hello.SNI, logger)
		return nil
	}
	if h.looped(pc) {
		logger.Warn("transparent loop: connection from the proxy's own upstream dial rejected (exclude the proxy's traffic from the REDIRECT rule by UID / cgroup)")
		return nil
	}
	ctx, forget := h.trackOwnDials(ctx)
	defer forget()

	ts := &TransparentScope{Dst: dst, Binder: h.binder}
	if nameAdmitted {
		// Owner decision U4: the SNI that admitted the connection (allowed,
		// not denied, bound by DNS) admits its non-HTTP envelopes too;
		// HostScopeStep re-checks it per envelope.
		ts.AdmittedBySNI = hello.SNI
	}
	ctx = ContextWithTransparentScope(ctx, ts)

	var (
		stack                    *ConnectionStack
		clientSnap, upstreamSnap *envelope.TLSSnapshot
		err                      error
	)
	if class == transparentTLSMITMNoALPN {
		stack, clientSnap, upstreamSnap, err = buildTransparentNoALPNStack(ctx, pc, ut, h.cfg.BuildCfg, hello, h.cfg.PeekTimeout)
	} else {
		stack, clientSnap, upstreamSnap, err = BuildConnectionStack(ctx, pc, ut, h.cfg.BuildCfg, hello)
	}
	if err != nil {
		h.mitmFailed(ctx, pc, dst, hello, err, logger)
		return nil
	}
	stack.SetBuildConfig(h.cfg.BuildCfg)
	logger.Debug("transparent TLS MITM stack built", "sni", hello.SNI, "tls_authority", ut.TLS)
	dispatchStack(ctx, stack, clientSnap, upstreamSnap, ut.Dial, h.cfg.BuildCfg, h.cfg.OnStack, h.cfg.OnHTTP2Stack)
	return nil
}

// trackOwnDials returns ctx carrying a dial socket hook that registers
// every upstream socket the MITM build (and its redials) opens in the loop
// registry, and the cleanup that forgets them all. After the cleanup a
// late dial registers nothing.
func (h *TransparentHandler) trackOwnDials(ctx context.Context) (context.Context, func()) {
	var (
		mu     sync.Mutex
		opened []netip.AddrPort
		done   bool
	)
	hook := func(c net.Conn) {
		local, ok := addrPortOf(c.LocalAddr())
		if !ok {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if done {
			return
		}
		h.ownDials.Store(local, struct{}{})
		opened = append(opened, local)
	}
	forget := func() {
		mu.Lock()
		defer mu.Unlock()
		done = true
		for _, local := range opened {
			h.ownDials.Delete(local)
		}
		opened = nil
	}
	return contextWithDialSocketHook(ctx, hook), forget
}

// mitmFailed handles a failed MITM stack build. A failure before any TLS
// byte reached the upstream (TCP connect, upstream-proxy tunnel or
// rotation) resets the client like every transparent dial failure; a
// TLS failure on either side is recorded with the ClientHello's SNI and
// fingerprints (owner decision U2).
func (h *TransparentHandler) mitmFailed(ctx context.Context, pc *PeekConn, dst netip.AddrPort, hello ClientHelloPeek, err error, logger *slog.Logger) {
	clientSide := errors.Is(err, ErrClientTLSMITMHandshake)
	if !clientSide && isUpstreamTCPDialError(err) {
		logger.Debug("transparent upstream dial failed", "error", err)
		h.dialFailed(ctx, pc, dst, TransparentRouteTLS, err)
		return
	}
	failure := TransparentFailureUpstreamTLS
	if clientSide {
		// Cert-pinning clients and clients without the CA installed land
		// here routinely (owner decision 4: no automatic passthrough).
		failure = TransparentFailureClientTLS
		logger.Debug("transparent TLS MITM: client rejected the handshake", "sni", hello.SNI, "error", err)
	} else {
		logger.Warn("transparent TLS MITM: upstream TLS failed", "sni", hello.SNI, "error", err)
	}
	if h.cfg.Observer != nil {
		h.cfg.Observer.OnBlocked(context.WithoutCancel(ctx), TransparentBlock{
			RemoteAddr:    netAddrString(pc.RemoteAddr()),
			OriginalDst:   dst.String(),
			Route:         TransparentRouteTLS,
			FailureReason: failure,
			Name:          hello.SNI,
			ClientJA3:     hello.ClientJA3,
			ClientJA4:     hello.ClientJA4,
			Error:         err.Error(),
		})
	}
}

// buildTransparentNoALPNStack builds the MITM stack of a transparent TLS
// connection whose ClientHello offered no ALPN. It never adds an ALPN
// offer the client did not send (MITM Principle 1) — unlike
// BuildConnectionStack's legacy path, which offers [h2 http/1.1]
// upstream and is what CONNECT / SOCKS5 keep using. The upstream is
// dialed first with standard crypto/tls (never the tls_fingerprint uTLS
// profile, whose ClientHello carries its own ALPN offer) and offered no
// ALPN; the client MITM advertises none; then
// the client's first decrypted bytes, peeked within peekTimeout, pick the
// route: an HTTP/1.x request → http1, anything else (including a silent
// client — a server-first protocol inside TLS) → bytechunk. No h2 pool,
// no ALPN cache. raw_passthrough_hosts keep BuildConnectionStack's raw
// passthrough stack.
func buildTransparentNoALPNStack(
	ctx context.Context,
	clientConn net.Conn,
	ut UpstreamTarget,
	cfg *BuildConfig,
	peeked ClientHelloPeek,
	peekTimeout time.Duration,
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	if cfg == nil || cfg.ProxyConfig == nil || cfg.Issuer == nil {
		return nil, nil, nil, fmt.Errorf("connector: transparent no-ALPN stack: nil config or issuer")
	}
	if ut.isRawPassthrough(cfg) {
		return BuildConnectionStack(ctx, clientConn, ut, cfg, peeked)
	}
	host, err := ut.validate()
	if err != nil {
		return nil, nil, nil, err
	}
	hostTLS, err := resolvePerHostTLS(ut.tlsAuthority(), cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	connID := uuid.New().String()

	upstreamConn, upstreamSnap, err := dialUpstreamStandardNoALPN(ctx, ut, host, hostTLS, cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	clientTLSConn, clientSnap, err := performClientMITM(ctx, clientConn, host, nil, peeked, cfg)
	if err != nil {
		_ = upstreamConn.Close()
		return nil, nil, nil, err
	}

	inner := NewPeekConn(clientTLSConn)
	route := "bytechunk"
	if peekTransparentRoute(inner, peekTimeout) == TransparentRouteHTTP {
		route = "http1"
	}
	slog.Debug("connector: transparent no-ALPN MITM routed",
		"target", ut.Dial, "tls_authority", ut.tlsAuthority(), "conn_id", connID, "route", route)

	stack, clientSnap, upstreamSnap, err := buildStackFromRoute(ctx, inner, upstreamConn, ut, connID, route, clientSnap, upstreamSnap, hostTLS, cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	stack.setUpstreamTarget(ut)
	// An h1 redial (RedialUpstreamH1) must dial this leg the same way.
	stack.setUpstreamTLSShape(UpstreamTLSStandardNoALPN)
	return stack, clientSnap, upstreamSnap, nil
}

// dialUpstreamStandardNoALPN dials ut.Dial with Go's standard crypto/tls
// and no ALPN extension, under SNI host — the UpstreamTLSStandardNoALPN
// shape, shared by buildTransparentNoALPNStack and the h1 redial so the two
// cannot drift.
//
// Standard crypto/tls, not the configured uTLS profile: a uTLS profile's
// ClientHello carries its own ALPN offer (Firefox: [h2 http/1.1]), which
// tlslayer replaces only with a non-empty offer. Offering nothing therefore
// needs a ClientHello without the ALPN extension — at the cost of
// tls_fingerprint on this leg only.
//
// ctx is used as given, so a socket hook the caller attached (the
// transparent listener's own-dial tracking) sees the socket; dialUpstreamTLS
// stamps the dial target the rotation resolver keys on.
func dialUpstreamStandardNoALPN(ctx context.Context, ut UpstreamTarget, host string, hostTLS *resolvedTLS, cfg *BuildConfig) (net.Conn, *envelope.TLSSnapshot, error) {
	return dialUpstreamTLS(ctx, ut.Dial, host,
		nil, "", hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg)
}
