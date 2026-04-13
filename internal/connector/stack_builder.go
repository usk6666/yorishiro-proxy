package connector

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/url"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/tlslayer"
)

// BuildConfig holds configuration for BuildConnectionStack.
type BuildConfig struct {
	// ProxyConfig is the loaded proxy configuration containing
	// RawPassthroughHosts and TLS settings.
	ProxyConfig *config.ProxyConfig

	// Issuer dynamically generates TLS server certificates for MITM.
	Issuer *cert.Issuer

	// InsecureSkipVerify disables TLS certificate verification on upstream.
	InsecureSkipVerify bool

	// TLSFingerprint selects the uTLS browser fingerprint profile for upstream.
	TLSFingerprint string

	// ClientCert is the global mTLS client certificate for upstream, if any.
	ClientCert *tls.Certificate

	// UpstreamProxy, if non-nil, tunnels upstream connections through an
	// HTTP CONNECT or SOCKS5 proxy.
	UpstreamProxy *url.URL

	// HostTLSResolver resolves per-host TLS overrides (InsecureSkipVerify,
	// ClientCert, RootCAs). Nil means use global settings for all hosts.
	HostTLSResolver *HostTLSResolver

	// ALPNCache caches upstream ALPN negotiation results to avoid an extra
	// upstream dial for ALPN learning on subsequent connections.
	// Nil disables caching (every connection dials upstream to learn ALPN).
	ALPNCache *ALPNCache
}

// BuildConnectionStack constructs a ConnectionStack for the given CONNECT
// target and client connection, based on per-host configuration policy.
//
// Three modes are supported:
//   - raw_passthrough: client [TLS MITM → ByteChunk], upstream [TLS → ByteChunk]
//     (config-level override, ignores ALPN)
//   - ALPN-routed MITM: upstream dial first to learn ALPN, then client MITM
//     offering the learned ALPN, then layer selection based on ALPN
//   - ALPN cache hit: client MITM offering cached ALPN, upstream dial with
//     cached ALPN, verify match
//
// The client-side TLS MITM handshake is performed inside this function
// because the stack builder owns the TLS layer decision.
func BuildConnectionStack(
	ctx context.Context,
	clientConn net.Conn,
	target string,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, error) {
	if cfg == nil || cfg.ProxyConfig == nil {
		return nil, nil, fmt.Errorf("connector: BuildConnectionStack: nil config")
	}
	if cfg.Issuer == nil {
		return nil, nil, fmt.Errorf("connector: BuildConnectionStack: nil issuer")
	}

	connID := uuid.New().String()

	// Raw passthrough mode bypasses ALPN routing entirely — always ByteChunk.
	if cfg.ProxyConfig.IsRawPassthrough(target) {
		return buildRawPassthroughStack(ctx, clientConn, target, connID, cfg)
	}

	return buildALPNRoutedStack(ctx, clientConn, target, connID, cfg)
}

// buildALPNRoutedStack dials upstream first to learn the negotiated ALPN,
// then performs client-side TLS MITM offering the learned ALPN, and finally
// selects the appropriate Layer based on the ALPN routing table.
//
// With ALPN cache:
//   - Cache hit: client MITM first (offering cached ALPN), then upstream dial
//     (offering cached ALPN). Verify match; invalidate cache on mismatch.
//   - Cache miss: upstream dial first (offering h2+http/1.1), learn ALPN,
//     cache result, then client MITM (offering learned ALPN).
//
// resolvedTLS holds per-host TLS settings resolved from HostTLSResolver.
type resolvedTLS struct {
	insecureSkip bool
	clientCert   *tls.Certificate
	rootCAs      *tls.Config
}

// resolvePerHostTLS resolves per-host TLS overrides from the BuildConfig.
func resolvePerHostTLS(target string, cfg *BuildConfig) (*resolvedTLS, error) {
	r := &resolvedTLS{
		insecureSkip: cfg.InsecureSkipVerify,
		clientCert:   cfg.ClientCert,
	}
	if cfg.HostTLSResolver == nil {
		return r, nil
	}

	resolved, err := cfg.HostTLSResolver.Resolve(target)
	if err != nil {
		return nil, fmt.Errorf("connector: resolve host TLS for %s: %w", target, err)
	}
	if resolved == nil {
		return r, nil
	}
	if resolved.InsecureSkipVerify != nil {
		r.insecureSkip = *resolved.InsecureSkipVerify
	}
	if resolved.ClientCert != nil {
		r.clientCert = resolved.ClientCert
	}
	if resolved.RootCAs != nil {
		r.rootCAs = &tls.Config{RootCAs: resolved.RootCAs}
	}
	return r, nil
}

func buildALPNRoutedStack(
	ctx context.Context,
	clientConn net.Conn,
	target string,
	connID string,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: invalid target %q: %w", target, err)
	}

	hostTLS, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		return nil, nil, err
	}

	// Check ALPN cache.
	var cacheKey ALPNCacheKey
	cachedALPN, cacheHit := "", false
	if cfg.ALPNCache != nil {
		cacheKey = ALPNCacheKeyFromConfig(target, cfg)
		if entry, ok := cfg.ALPNCache.Get(cacheKey); ok {
			cachedALPN = entry.Protocol
			cacheHit = true
		}
	}

	var negotiatedALPN string
	var clientTLSConn net.Conn
	var upstreamConn net.Conn
	var clientSnap *envelope.TLSSnapshot

	if cacheHit {
		clientTLSConn, upstreamConn, clientSnap, negotiatedALPN, err = buildCacheHitPath(
			ctx, clientConn, target, host, cachedALPN, cacheKey, hostTLS, cfg)
	} else {
		clientTLSConn, upstreamConn, clientSnap, negotiatedALPN, err = buildCacheMissPath(
			ctx, clientConn, target, host, cacheKey, hostTLS, cfg)
	}
	if err != nil {
		return nil, nil, err
	}

	route, routeErr := alpnRoute(negotiatedALPN)
	if routeErr != nil {
		upstreamConn.Close()
		clientTLSConn.Close()
		return nil, nil, fmt.Errorf("connector: %s: %w", target, routeErr)
	}

	slog.Debug("connector: ALPN routed",
		"target", target, "conn_id", connID,
		"alpn", negotiatedALPN, "route", route, "cache_hit", cacheHit,
	)

	return buildStackFromRoute(clientTLSConn, upstreamConn, target, connID, route, clientSnap)
}

// buildCacheHitPath handles the ALPN cache hit: client MITM first (offering
// cached ALPN), then upstream dial (offering cached ALPN), verify match.
// Returns the TLS-wrapped client connection (not the original plain conn).
func buildCacheHitPath(
	ctx context.Context,
	clientConn net.Conn,
	target, host, cachedALPN string,
	cacheKey ALPNCacheKey,
	hostTLS *resolvedTLS,
	cfg *BuildConfig,
) (clientTLSConn net.Conn, upstreamConn net.Conn, clientSnap *envelope.TLSSnapshot, negotiatedALPN string, err error) {
	clientTLSConn, clientSnap, err = performClientMITM(ctx, clientConn, host, cachedALPN, cfg)
	if err != nil {
		return nil, nil, nil, "", err
	}

	upstreamConn, negotiatedALPN, err = dialUpstreamWithALPN(ctx, target, host,
		[]string{cachedALPN}, hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg)
	if err != nil {
		clientConn.Close()
		return nil, nil, nil, "", err
	}

	if negotiatedALPN != cachedALPN {
		cfg.ALPNCache.Delete(cacheKey)
		upstreamConn.Close()
		clientConn.Close()
		return nil, nil, nil, "", fmt.Errorf("connector: ALPN mismatch for %s: cached %q, got %q",
			target, cachedALPN, negotiatedALPN)
	}

	return clientTLSConn, upstreamConn, clientSnap, negotiatedALPN, nil
}

// buildCacheMissPath handles the ALPN cache miss: upstream dial first (to
// learn ALPN), then client MITM (offering learned ALPN).
// Returns the TLS-wrapped client connection (not the original plain conn).
func buildCacheMissPath(
	ctx context.Context,
	clientConn net.Conn,
	target, host string,
	cacheKey ALPNCacheKey,
	hostTLS *resolvedTLS,
	cfg *BuildConfig,
) (clientTLSConn net.Conn, upstreamConn net.Conn, clientSnap *envelope.TLSSnapshot, negotiatedALPN string, err error) {
	upstreamConn, negotiatedALPN, err = dialUpstreamWithALPN(ctx, target, host,
		defaultALPNOffer, hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg)
	if err != nil {
		return nil, nil, nil, "", err
	}

	// Validate ALPN route early so we don't waste a client MITM handshake.
	if _, routeErr := alpnRoute(negotiatedALPN); routeErr != nil {
		upstreamConn.Close()
		return nil, nil, nil, "", fmt.Errorf("connector: %s: %w", target, routeErr)
	}

	// Cache the learned ALPN.
	if cfg.ALPNCache != nil {
		cfg.ALPNCache.Set(cacheKey, negotiatedALPN)
	}

	// Client MITM offering the learned ALPN.
	alpnOffer := negotiatedALPN
	if alpnOffer == "" {
		alpnOffer = ALPNProtocolHTTP11
	}
	clientTLSConn, clientSnap, err = performClientMITM(ctx, clientConn, host, alpnOffer, cfg)
	if err != nil {
		upstreamConn.Close()
		return nil, nil, nil, "", err
	}

	return clientTLSConn, upstreamConn, clientSnap, negotiatedALPN, nil
}

// performClientMITM performs the client-side TLS MITM handshake, issuing a
// certificate for the given host and offering the specified ALPN protocol.
// Returns the TLS-wrapped connection (which must be used for subsequent I/O
// instead of the original plain connection) and the TLS snapshot.
func performClientMITM(
	ctx context.Context,
	clientConn net.Conn,
	host string,
	alpnOffer string,
	cfg *BuildConfig,
) (net.Conn, *envelope.TLSSnapshot, error) {
	mitmCert, err := cfg.Issuer.GetCertificate(host)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: MITM cert for %s: %w", host, err)
	}

	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{*mitmCert},
	}
	if alpnOffer != "" {
		serverTLSCfg.NextProtos = []string{alpnOffer}
	}

	tlsConn, clientSnap, err := tlslayer.Server(ctx, clientConn, serverTLSCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: client TLS MITM handshake: %w", err)
	}
	return tlsConn, clientSnap, nil
}

// dialUpstreamWithALPN dials upstream and performs TLS, returning the
// connection, negotiated ALPN, and any error.
func dialUpstreamWithALPN(
	ctx context.Context,
	target, host string,
	offerALPN []string,
	insecureSkip bool,
	clientCert *tls.Certificate,
	rootCAsConfig *tls.Config,
	cfg *BuildConfig,
) (net.Conn, string, error) {
	upstreamTLSCfg := &tls.Config{
		ServerName: host,
	}
	if rootCAsConfig != nil {
		upstreamTLSCfg.RootCAs = rootCAsConfig.RootCAs
	}

	conn, snap, err := DialUpstreamRaw(ctx, target, DialRawOpts{
		TLSConfig:          upstreamTLSCfg,
		InsecureSkipVerify: insecureSkip,
		UTLSProfile:        cfg.TLSFingerprint,
		ClientCert:         clientCert,
		OfferALPN:          offerALPN,
		UpstreamProxy:      cfg.UpstreamProxy,
	})
	if err != nil {
		return nil, "", fmt.Errorf("connector: upstream dial for %s: %w", target, err)
	}

	alpn := ""
	if snap != nil {
		alpn = snap.ALPN
	}
	return conn, alpn, nil
}

// buildStackFromRoute constructs a ConnectionStack with the appropriate
// Layers based on the ALPN route decision.
func buildStackFromRoute(
	clientConn, upstreamConn net.Conn,
	target, connID, route string,
	clientSnap *envelope.TLSSnapshot,
) (*ConnectionStack, *envelope.TLSSnapshot, error) {
	envCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		TLS:        clientSnap,
	}

	stack := NewConnectionStack(connID)

	switch route {
	case "http1":
		clientLayer := http1.New(clientConn, connID+"/client", envelope.Send,
			http1.WithScheme("https"),
			http1.WithEnvelopeContext(envCtx),
		)
		stack.PushClient(clientLayer)

		upstreamLayer := http1.New(upstreamConn, connID+"/upstream", envelope.Receive,
			http1.WithScheme("https"),
			http1.WithEnvelopeContext(envCtx),
		)
		stack.PushUpstream(upstreamLayer)

	case "bytechunk":
		clientLayer := bytechunk.New(clientConn, connID+"/client", envelope.Send)
		stack.PushClient(clientLayer)

		upstreamLayer := bytechunk.New(upstreamConn, connID+"/upstream", envelope.Receive)
		stack.PushUpstream(upstreamLayer)

	default:
		upstreamConn.Close()
		clientConn.Close()
		return nil, nil, fmt.Errorf("connector: unknown route %q", route)
	}

	return stack, clientSnap, nil
}

// buildRawPassthroughStack builds a [TLS → ByteChunk] stack on both sides.
// This is the config-level raw_passthrough mode that bypasses ALPN routing.
func buildRawPassthroughStack(
	ctx context.Context,
	clientConn net.Conn,
	target string,
	connID string,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: invalid target %q: %w", target, err)
	}

	// --- Client-side TLS MITM ---

	mitmCert, err := cfg.Issuer.GetCertificate(host)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: MITM cert for %s: %w", host, err)
	}

	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{*mitmCert},
	}

	clientTLSConn, clientSnap, err := tlslayer.Server(ctx, clientConn, serverTLSCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: client TLS MITM handshake for %s: %w", target, err)
	}

	slog.Debug("connector: client-side MITM handshake complete",
		"target", target,
		"conn_id", connID,
	)

	// --- Upstream TLS ---

	upstreamTLSCfg := &tls.Config{
		ServerName: host,
	}

	insecureSkip := cfg.InsecureSkipVerify
	clientCert := cfg.ClientCert

	// Apply per-host TLS overrides if configured.
	if cfg.HostTLSResolver != nil {
		resolved, resolveErr := cfg.HostTLSResolver.Resolve(target)
		if resolveErr != nil {
			clientTLSConn.Close()
			return nil, nil, fmt.Errorf("connector: resolve host TLS for %s: %w", target, resolveErr)
		}
		if resolved != nil {
			if resolved.InsecureSkipVerify != nil {
				insecureSkip = *resolved.InsecureSkipVerify
			}
			if resolved.ClientCert != nil {
				clientCert = resolved.ClientCert
			}
			if resolved.RootCAs != nil {
				upstreamTLSCfg.RootCAs = resolved.RootCAs
			}
		}
	}

	upstreamConn, _, err := DialUpstreamRaw(ctx, target, DialRawOpts{
		TLSConfig:          upstreamTLSCfg,
		InsecureSkipVerify: insecureSkip,
		UTLSProfile:        cfg.TLSFingerprint,
		ClientCert:         clientCert,
		OfferALPN:          []string{"http/1.1"},
		UpstreamProxy:      cfg.UpstreamProxy,
	})
	if err != nil {
		clientTLSConn.Close()
		return nil, nil, fmt.Errorf("connector: upstream dial for %s: %w", target, err)
	}

	slog.Debug("connector: upstream connection established",
		"target", target,
		"conn_id", connID,
	)

	// --- Build the stack ---

	stack := NewConnectionStack(connID)

	// Client: ByteChunk layer over the MITM'd TLS conn (reads client→server)
	clientLayer := bytechunk.New(clientTLSConn, connID+"/client", envelope.Send)
	stack.PushClient(clientLayer)

	// Upstream: ByteChunk layer over the upstream TLS conn (reads server→client)
	upstreamLayer := bytechunk.New(upstreamConn, connID+"/upstream", envelope.Receive)
	stack.PushUpstream(upstreamLayer)

	return stack, clientSnap, nil
}
