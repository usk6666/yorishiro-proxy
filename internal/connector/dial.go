// dial.go implements DialUpstream — the single source of truth for upstream
// connection establishment in the new Codec + Pipeline + Session architecture.
//
// DialUpstream is called from two paths:
//
//  1. TunnelHandler (CONNECT / SOCKS5) eager dial. Used to learn the real
//     ALPN negotiated with upstream before talking to the client.
//  2. session.DialFunc lazy dial. Used by plain HTTP forward proxy when the
//     first Send Exchange arrives and the upstream address can be derived
//     from the request URL.
//
// Both paths must produce identical upstream behaviour (uTLS fingerprint,
// mTLS, upstream proxy, ALPN negotiation, CRLF injection guard). Keeping this
// logic in a single function guarantees that M42 resend/fuzz jobs reproduce
// normal traffic bit-for-bit.
package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/codec/http1"
	"github.com/usk6666/yorishiro-proxy/internal/codec/tcp"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// defaultDialTimeout is the fallback dial timeout when DialOpts.DialTimeout
// is zero.
const defaultDialTimeout = 30 * time.Second

// ErrHTTP2NotImplemented is returned when ALPN negotiates "h2" but no HTTP/2
// Codec has been registered. HTTP/2 Codec registration is scheduled for M40.
var ErrHTTP2NotImplemented = errors.New("connector: HTTP/2 Codec not implemented in M39 (scheduled for M40)")

// DialOpts configures a DialUpstream call.
//
// TLSConfig is the canonical signal that TLS is required: when TLSConfig is
// non-nil, DialUpstream performs a TLS handshake after the TCP connection is
// established. ServerName, RootCAs, and other settings on TLSConfig are used
// as the base; InsecureSkipVerify, ClientCert and OfferALPN override /
// extend those settings.
//
// UTLSProfile selects a uTLS ClientHelloID (e.g. "chrome", "firefox",
// "safari", "edge", "random"). When empty, the standard crypto/tls library
// is used. The choice of uTLS vs standard TLS is transparent to callers:
// the returned Conn always exposes the negotiated ALPN via
// ConnectionState().NegotiatedProtocol.
type DialOpts struct {
	// TLSConfig is the base TLS configuration. When nil, no TLS handshake is
	// performed (plain TCP). When non-nil, TLSConfig is cloned and used as
	// the starting point for the handshake.
	TLSConfig *tls.Config

	// InsecureSkipVerify disables server certificate verification on the
	// dialled TLS connection. When true, it overrides TLSConfig.InsecureSkipVerify.
	InsecureSkipVerify bool

	// UTLSProfile selects a uTLS browser fingerprint (chrome, firefox,
	// safari, edge, random). Empty string selects the standard crypto/tls library.
	UTLSProfile string

	// ClientCert, if non-nil, is used as the mTLS client certificate. It
	// overrides TLSConfig.Certificates.
	ClientCert *tls.Certificate

	// UpstreamProxy, if non-nil, tunnels the TCP connection through an HTTP
	// CONNECT or SOCKS5 proxy. CRLF injection guards (CWE-93) apply.
	UpstreamProxy *url.URL

	// DialTimeout bounds the TCP dial (and upstream-proxy handshake if
	// applicable) and any subsequent TLS handshake. Zero defaults to
	// defaultDialTimeout (30s).
	DialTimeout time.Duration

	// OfferALPN is the list of ALPN protocols to offer during the TLS
	// handshake (e.g. []string{"h2", "http/1.1"}). When empty, the TLS stack
	// default is used. For uTLS, when empty, the browser profile's default
	// ALPN extension is left untouched.
	OfferALPN []string
}

// DialResult is the result of a successful DialUpstream call.
type DialResult struct {
	// Conn is the established (possibly TLS-wrapped) connection.
	Conn net.Conn

	// ALPN is the ALPN protocol negotiated during the TLS handshake. Empty
	// for plain TCP or when no ALPN was negotiated.
	ALPN string

	// Codec is the UpstreamRole Codec chosen for the negotiated ALPN by the
	// Codec factory.
	Codec codec.Codec
}

// DialUpstream establishes an upstream connection. The target argument must
// be in "host:port" form.
//
// Steps:
//  1. Dial TCP directly or through the upstream proxy (CRLF injection
//     protected).
//  2. If TLSConfig is non-nil, perform a standard or uTLS handshake with the
//     requested ALPN list.
//  3. Select an UpstreamRole Codec from the ALPN factory.
func DialUpstream(ctx context.Context, target string, opts DialOpts) (*DialResult, error) {
	if err := validateTarget(target); err != nil {
		return nil, err
	}

	timeout := opts.DialTimeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}

	// Apply the timeout via context so every subsequent step respects it,
	// including TLS handshake and upstream-proxy CONNECT / SOCKS5.
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rawConn, err := dialTCP(dialCtx, target, opts.UpstreamProxy, timeout)
	if err != nil {
		return nil, err
	}

	if opts.TLSConfig == nil {
		// Plain TCP upstream. No ALPN → fall through to the factory.
		cdc, err := buildCodec("", rawConn)
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		return &DialResult{Conn: rawConn, ALPN: "", Codec: cdc}, nil
	}

	tlsConn, alpn, err := performTLSHandshake(dialCtx, rawConn, opts)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	cdc, err := buildCodec(alpn, tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}
	return &DialResult{Conn: tlsConn, ALPN: alpn, Codec: cdc}, nil
}

// validateTarget enforces "host:port" form and rejects CRLF so that
// the target string cannot be smuggled into an HTTP CONNECT request line
// (CWE-93). It is deliberately stricter than net.SplitHostPort alone.
func validateTarget(target string) error {
	if target == "" {
		return fmt.Errorf("connector: empty target address")
	}
	if strings.ContainsAny(target, "\r\n") {
		return fmt.Errorf("connector: target address contains CR/LF characters")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("connector: invalid target %q: %w", target, err)
	}
	if host == "" || port == "" {
		return fmt.Errorf("connector: target %q missing host or port", target)
	}
	return nil
}

// dialTCP establishes a raw TCP connection, optionally through an upstream
// proxy. Timeout is already bounded by the caller's context, but the proxy
// helpers require an explicit duration for compatibility with the moved
// proxy.DialViaUpstreamProxy API.
func dialTCP(ctx context.Context, target string, upstreamProxy *url.URL, timeout time.Duration) (net.Conn, error) {
	if upstreamProxy != nil {
		slog.Debug("connector: dialing via upstream proxy", "target", target, "proxy", RedactProxyURL(upstreamProxy.String()))
		conn, err := DialViaUpstreamProxy(ctx, upstreamProxy, target, timeout)
		if err != nil {
			return nil, fmt.Errorf("connector: dial via upstream proxy: %w", err)
		}
		return conn, nil
	}

	slog.Debug("connector: dialing direct", "target", target)
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("connector: dial %s: %w", target, err)
	}
	return conn, nil
}

// performTLSHandshake wraps conn with TLS using standard crypto/tls or uTLS
// depending on DialOpts.UTLSProfile. It returns the wrapped connection and
// the negotiated ALPN. The returned Conn always exposes ConnectionState()
// via TLSConnectionState.
func performTLSHandshake(ctx context.Context, conn net.Conn, opts DialOpts) (net.Conn, string, error) {
	if opts.UTLSProfile != "" {
		return performUTLSHandshake(ctx, conn, opts)
	}
	return performStandardTLSHandshake(ctx, conn, opts)
}

// performStandardTLSHandshake uses crypto/tls.
func performStandardTLSHandshake(ctx context.Context, conn net.Conn, opts DialOpts) (net.Conn, string, error) {
	cfg := opts.TLSConfig.Clone()
	if opts.InsecureSkipVerify {
		cfg.InsecureSkipVerify = true //nolint:gosec // proxy requires MITM
	}
	if len(opts.OfferALPN) > 0 {
		cfg.NextProtos = append([]string(nil), opts.OfferALPN...)
	}
	if opts.ClientCert != nil {
		cfg.Certificates = []tls.Certificate{*opts.ClientCert}
	}

	slog.Debug("connector: standard TLS handshake starting", "server", cfg.ServerName,
		"insecure_skip_verify", cfg.InsecureSkipVerify, "alpn_offer", cfg.NextProtos)

	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, "", fmt.Errorf("connector: standard TLS handshake with %s: %w", cfg.ServerName, err)
	}
	state := tlsConn.ConnectionState()
	slog.Debug("connector: standard TLS handshake complete", "server", cfg.ServerName,
		"alpn", state.NegotiatedProtocol)
	return tlsConn, state.NegotiatedProtocol, nil
}

// utlsProfileIDs maps the public profile name to its uTLS ClientHelloID.
// The map is populated lazily on first use to keep init cost low.
var utlsProfileIDs = map[string]*utls.ClientHelloID{
	"chrome":  &utls.HelloChrome_Auto,
	"firefox": &utls.HelloFirefox_Auto,
	"safari":  &utls.HelloSafari_Auto,
	"edge":    &utls.HelloEdge_Auto,
	"random":  &utls.HelloRandomized,
}

// performUTLSHandshake uses refraction-networking/utls to produce a
// browser-like TLS ClientHello.
func performUTLSHandshake(ctx context.Context, conn net.Conn, opts DialOpts) (net.Conn, string, error) {
	profile := strings.ToLower(strings.TrimSpace(opts.UTLSProfile))
	helloID, ok := utlsProfileIDs[profile]
	if !ok {
		return nil, "", fmt.Errorf("connector: unsupported uTLS profile %q", opts.UTLSProfile)
	}

	base := opts.TLSConfig.Clone()
	ucfg := &utls.Config{
		ServerName:         base.ServerName,
		InsecureSkipVerify: base.InsecureSkipVerify, //nolint:gosec // proxy requires MITM
		RootCAs:            base.RootCAs,
		MinVersion:         tls.VersionTLS12,
	}
	if opts.InsecureSkipVerify {
		ucfg.InsecureSkipVerify = true //nolint:gosec // proxy requires MITM
	}
	if opts.ClientCert != nil {
		ucfg.Certificates = []utls.Certificate{{
			Certificate:                 opts.ClientCert.Certificate,
			PrivateKey:                  opts.ClientCert.PrivateKey,
			OCSPStaple:                  opts.ClientCert.OCSPStaple,
			SignedCertificateTimestamps: opts.ClientCert.SignedCertificateTimestamps,
			Leaf:                        opts.ClientCert.Leaf,
		}}
	}

	slog.Debug("connector: uTLS handshake starting", "server", ucfg.ServerName,
		"profile", profile, "insecure_skip_verify", ucfg.InsecureSkipVerify, "alpn_offer", opts.OfferALPN)

	uConn := utls.UClient(conn, ucfg, *helloID)

	// Replace ALPN extension after BuildHandshakeState if the caller
	// requested a specific ALPN list. This preserves the rest of the browser
	// fingerprint while restricting ALPN.
	if len(opts.OfferALPN) > 0 {
		if err := uConn.BuildHandshakeState(); err != nil {
			return nil, "", fmt.Errorf("connector: uTLS build handshake state: %w", err)
		}
		replaced := false
		for _, ext := range uConn.Extensions {
			if alpnExt, ok := ext.(*utls.ALPNExtension); ok {
				alpnExt.AlpnProtocols = append([]string(nil), opts.OfferALPN...)
				replaced = true
				break
			}
		}
		if !replaced {
			// Browser profile has no ALPN extension; append one so the
			// caller's OfferALPN is actually offered.
			uConn.Extensions = append(uConn.Extensions, &utls.ALPNExtension{
				AlpnProtocols: append([]string(nil), opts.OfferALPN...),
			})
		}
	}

	if err := uConn.HandshakeContext(ctx); err != nil {
		return nil, "", fmt.Errorf("connector: uTLS handshake with %s (profile=%s): %w", ucfg.ServerName, profile, err)
	}
	state := uConn.ConnectionState()
	slog.Debug("connector: uTLS handshake complete", "server", ucfg.ServerName,
		"profile", profile, "alpn", state.NegotiatedProtocol)
	return uConn, state.NegotiatedProtocol, nil
}

// --- ALPN → Codec factory -----------------------------------------------------

// CodecBuilder constructs an UpstreamRole Codec for a previously negotiated
// connection.
type CodecBuilder func(conn net.Conn) (codec.Codec, error)

var (
	alpnFactoryMu sync.RWMutex
	alpnFactory   = map[string]CodecBuilder{
		"": func(conn net.Conn) (codec.Codec, error) {
			return http1.NewCodec(conn, http1.UpstreamRole), nil
		},
		"http/1.1": func(conn net.Conn) (codec.Codec, error) {
			return http1.NewCodec(conn, http1.UpstreamRole), nil
		},
		"h2": func(_ net.Conn) (codec.Codec, error) {
			return nil, ErrHTTP2NotImplemented
		},
	}
)

// RegisterALPNCodec registers a CodecBuilder for an ALPN protocol string.
// M40 will call this during init() to register HTTP/2 without modifying
// dial.go. Passing a nil builder is a programming error.
func RegisterALPNCodec(alpn string, builder CodecBuilder) {
	if builder == nil {
		panic("connector: RegisterALPNCodec called with nil builder")
	}
	alpnFactoryMu.Lock()
	defer alpnFactoryMu.Unlock()
	alpnFactory[alpn] = builder
}

// UnregisterALPNCodec removes a registration. It is primarily intended for
// tests so that a registration cannot leak between parallel test cases.
func UnregisterALPNCodec(alpn string) {
	alpnFactoryMu.Lock()
	defer alpnFactoryMu.Unlock()
	delete(alpnFactory, alpn)
}

// buildCodec consults the ALPN factory. Unknown ALPN values fall back to the
// TCP identity codec so that arbitrary tunneled protocols still flow through
// the pipeline as Raw TCP exchanges.
func buildCodec(alpn string, conn net.Conn) (codec.Codec, error) {
	alpnFactoryMu.RLock()
	builder, ok := alpnFactory[alpn]
	alpnFactoryMu.RUnlock()
	if ok {
		return builder(conn)
	}
	// Unknown ALPN → TCP Codec fallback (L4-capable principle).
	return tcp.NewWithStreamID(conn, exchange.Receive), nil
}

// --- session.DialFunc adapter -------------------------------------------------

// DialFunc is the dial-upstream callback type used by the universal session
// loop. It is identical in shape to session.DialFunc; we redeclare it here
// instead of importing internal/session because the session package
// transitively imports internal/pipeline → internal/proxy → internal/connector,
// which would create an import cycle. Values of this type are assignable to
// session.DialFunc at the call site.
type DialFunc func(ctx context.Context, ex *exchange.Exchange) (codec.Codec, error)

// MakeDialFunc adapts DialUpstream to a DialFunc for the plain HTTP forward
// proxy path. The returned function derives the upstream target from the
// first Send Exchange's URL.
//
// CONNECT / SOCKS5 tunnel paths do NOT use MakeDialFunc; TunnelHandler
// (USK-560) performs an eager DialUpstream and wraps the result in a
// closure-based DialFunc instead, so that the already-established connection
// is reused rather than re-dialled.
func MakeDialFunc(opts DialOpts) DialFunc {
	return func(ctx context.Context, ex *exchange.Exchange) (codec.Codec, error) {
		target, err := targetFromExchange(ex)
		if err != nil {
			return nil, err
		}
		result, err := DialUpstream(ctx, target, opts)
		if err != nil {
			return nil, err
		}
		return result.Codec, nil
	}
}

// targetFromExchange extracts a "host:port" target from ex.URL, filling in
// the default port for http/https when omitted.
func targetFromExchange(ex *exchange.Exchange) (string, error) {
	if ex == nil || ex.URL == nil {
		return "", fmt.Errorf("connector: exchange has no URL")
	}
	host := ex.URL.Hostname()
	if host == "" {
		return "", fmt.Errorf("connector: exchange URL has no host: %s", ex.URL.String())
	}
	port := ex.URL.Port()
	if port == "" {
		switch strings.ToLower(ex.URL.Scheme) {
		case "https", "wss":
			port = "443"
		case "http", "ws", "":
			port = "80"
		default:
			return "", fmt.Errorf("connector: exchange URL has unknown scheme %q and no explicit port", ex.URL.Scheme)
		}
	}
	return net.JoinHostPort(host, port), nil
}
