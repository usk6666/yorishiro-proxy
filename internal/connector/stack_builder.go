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
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
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

	// HTTP2Pool caches upstream HTTP/2 Layers keyed by (host:port, TLS config
	// hash). When non-nil, buildStackFromRoute hands h2-routed upstream
	// connections to the pool (via GetOrDial) so later streams for the same
	// target reuse a single *http2.Layer. Nil disables pooling: every
	// h2-routed connection builds a fresh Layer and the handler closes it on
	// exit. Disabling the pool is a supported diagnostic mode (useful for
	// debugging per-connection state without the confounder of reuse).
	HTTP2Pool *pool.Pool

	// OnHTTP2UpstreamDialed, if non-nil, is invoked exactly once per
	// upstream *http2.Layer at the moment it is freshly dialed (i.e.,
	// inside the pool's dialFn on a miss, or inline when HTTP2Pool is
	// nil). It is NOT invoked on pool hits — the callback is meant to
	// attach goroutines whose lifetime should match the Layer, and running
	// them again for every reused CONNECT would race.
	//
	// USK-623: the primary use is to spawn the upstream push recorder
	// (internal/pushrecorder) on the Layer so pushed streams surfaced via
	// Layer.Channels() are drained and recorded. Without this hook the
	// Layer.channelOut buffer fills after 8 pushes and the reader
	// goroutine stalls — a correctness problem independent of the
	// observability feature.
	//
	// The callback must not block. The Layer is already fully initialized
	// (preface done, reader+writer goroutines running) when the callback
	// fires; the callback may call any Layer method but must not close
	// the Layer (ownership stays with the pool/caller).
	//
	// Pushrecorder is wired outside the connector package (see
	// internal/pushrecorder) to keep this package free of pipeline/flow
	// dependencies; callers that want the feature construct a closure in
	// their bootstrap code and install it here.
	OnHTTP2UpstreamDialed func(l *http2.Layer)

	// BodySpillDir is the directory used for temp files when a message body
	// exceeds BodySpillThreshold. Empty means os.TempDir() (resolved by the
	// bodybuf package). Pre-resolve at the bootstrap layer using
	// config.ResolveBodySpillDir if spill location is configurable.
	BodySpillDir string

	// BodySpillThreshold is the size above which a body spills from memory
	// to a temp file. Zero means the layer's internal default
	// (config.DefaultBodySpillThreshold, 10 MiB).
	BodySpillThreshold int64

	// MaxBodySize is the absolute cap on body size. Exceeding it produces a
	// layer.StreamError with Code=ErrorInternalError. Zero means the
	// layer's internal default (config.MaxBodySize, 254 MiB).
	MaxBodySize int64

	// WSMaxFrameSize is the per-frame WebSocket payload cap applied when
	// the connector constructs a *ws.Layer. Resolved at BuildConfig
	// construction time from ProxyConfig.WebSocket via
	// config.ResolveWSMaxFrameSize. Zero falls back to the Layer default
	// (config.MaxWebSocketFrameSize, 16 MiB). Read by the N7 Upgrade swap
	// orchestrator (USK-643); BuildConfig holds the resolved value here so
	// the swap site does not need to re-resolve.
	WSMaxFrameSize int64

	// WSDeflateEnabled toggles permessage-deflate (RFC 7692) on the
	// WebSocket Layer. Defaults to true (config-resolved by
	// ResolveWSDeflateEnabled). Read by USK-643's Upgrade swap orchestrator.
	WSDeflateEnabled bool

	// GRPCMaxMessageSize caps the per-LPM payload size on both the gRPC
	// (internal/layer/grpc) and gRPC-Web (internal/layer/grpcweb) Layers.
	// Threaded through h2_dispatch into grpc.Wrap; gRPC-Web wiring is
	// owned by the gRPC-Web wrap site. Zero falls back to the Layer
	// default (config.MaxGRPCMessageSize, 254 MiB).
	GRPCMaxMessageSize uint32

	// SSEMaxEventSize caps the per-event raw byte size on the SSE Layer.
	// Currently consumed only by USK-643's Upgrade swap orchestrator; this
	// field is the resolved bridge between ProxyConfig.SSE and the
	// future sse.WithMaxEventSize Option call.
	SSEMaxEventSize int
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
//
// Returns the stack, the client-facing MITM TLS snapshot (synthetic cert
// we presented to the client), and the upstream TLS snapshot (the real
// cert observed from upstream). Both snapshots are per-Layer per RFC-001
// §3.1 and must not be conflated.
func BuildConnectionStack(
	ctx context.Context,
	clientConn net.Conn,
	target string,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	if cfg == nil || cfg.ProxyConfig == nil {
		return nil, nil, nil, fmt.Errorf("connector: BuildConnectionStack: nil config")
	}
	if cfg.Issuer == nil {
		return nil, nil, nil, fmt.Errorf("connector: BuildConnectionStack: nil issuer")
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
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connector: invalid target %q: %w", target, err)
	}

	hostTLS, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	// H2 pool fast path: consult the pool BEFORE upstream TLS dial. On hit
	// we reuse the cached Layer and skip the upstream handshake entirely —
	// the whole point of pooling, and externally observable via upstream
	// TCP accept count staying flat across same-target CONNECTs.
	//
	// A pool hit implies ALPN=h2 because poolKeyForH2 is only minted for
	// the h2 route, so we can offer "h2" to the client MITM without
	// consulting the ALPN cache. On miss (including Pool.Get returning
	// ErrClosed, a dead Layer, or a capacity-capped Layer) fall through
	// to the existing ALPN-cache / upstream-dial flow.
	if cfg.HTTP2Pool != nil {
		poolKey := poolKeyForH2(target, cfg)
		if pooled, perr := cfg.HTTP2Pool.Get(poolKey); perr == nil && pooled != nil {
			return buildPoolHitFastPath(ctx, clientConn, target, host, connID, pooled, poolKey, cfg)
		}
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

	var clientTLSConn net.Conn
	var upstreamConn net.Conn
	var clientSnap, upstreamSnap *envelope.TLSSnapshot

	if cacheHit {
		clientTLSConn, upstreamConn, clientSnap, upstreamSnap, err = buildCacheHitPath(
			ctx, clientConn, target, host, cachedALPN, cacheKey, hostTLS, cfg)
	} else {
		clientTLSConn, upstreamConn, clientSnap, upstreamSnap, err = buildCacheMissPath(
			ctx, clientConn, target, host, cacheKey, hostTLS, cfg)
	}
	if err != nil {
		return nil, nil, nil, err
	}

	negotiatedALPN := ""
	if upstreamSnap != nil {
		negotiatedALPN = upstreamSnap.ALPN
	}

	route, routeErr := alpnRoute(negotiatedALPN)
	if routeErr != nil {
		upstreamConn.Close()
		clientTLSConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: %s: %w", target, routeErr)
	}

	slog.Debug("connector: ALPN routed",
		"target", target, "conn_id", connID,
		"alpn", negotiatedALPN, "route", route, "cache_hit", cacheHit,
	)

	return buildStackFromRoute(ctx, clientTLSConn, upstreamConn, target, connID, route, clientSnap, upstreamSnap, cfg)
}

// buildCacheHitPath handles the ALPN cache hit: client MITM first (offering
// cached ALPN), then upstream dial (offering cached ALPN), verify match.
// Returns the TLS-wrapped client connection (not the original plain conn)
// plus both TLS snapshots.
func buildCacheHitPath(
	ctx context.Context,
	clientConn net.Conn,
	target, host, cachedALPN string,
	cacheKey ALPNCacheKey,
	hostTLS *resolvedTLS,
	cfg *BuildConfig,
) (clientTLSConn net.Conn, upstreamConn net.Conn, clientSnap, upstreamSnap *envelope.TLSSnapshot, err error) {
	clientTLSConn, clientSnap, err = performClientMITM(ctx, clientConn, host, cachedALPN, cfg)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	upstreamConn, upstreamSnap, err = dialUpstreamWithALPN(ctx, target, host,
		[]string{cachedALPN}, hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg)
	if err != nil {
		clientConn.Close()
		return nil, nil, nil, nil, err
	}

	negotiatedALPN := ""
	if upstreamSnap != nil {
		negotiatedALPN = upstreamSnap.ALPN
	}
	if negotiatedALPN != cachedALPN {
		cfg.ALPNCache.Delete(cacheKey)
		upstreamConn.Close()
		clientConn.Close()
		return nil, nil, nil, nil, fmt.Errorf("connector: ALPN mismatch for %s: cached %q, got %q",
			target, cachedALPN, negotiatedALPN)
	}

	return clientTLSConn, upstreamConn, clientSnap, upstreamSnap, nil
}

// buildCacheMissPath handles the ALPN cache miss: upstream dial first (to
// learn ALPN), then client MITM (offering learned ALPN).
// Returns the TLS-wrapped client connection (not the original plain conn)
// plus both TLS snapshots.
func buildCacheMissPath(
	ctx context.Context,
	clientConn net.Conn,
	target, host string,
	cacheKey ALPNCacheKey,
	hostTLS *resolvedTLS,
	cfg *BuildConfig,
) (clientTLSConn net.Conn, upstreamConn net.Conn, clientSnap, upstreamSnap *envelope.TLSSnapshot, err error) {
	upstreamConn, upstreamSnap, err = dialUpstreamWithALPN(ctx, target, host,
		defaultALPNOffer, hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	negotiatedALPN := ""
	if upstreamSnap != nil {
		negotiatedALPN = upstreamSnap.ALPN
	}

	// Validate ALPN route early so we don't waste a client MITM handshake.
	if _, routeErr := alpnRoute(negotiatedALPN); routeErr != nil {
		upstreamConn.Close()
		return nil, nil, nil, nil, fmt.Errorf("connector: %s: %w", target, routeErr)
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
		return nil, nil, nil, nil, err
	}

	return clientTLSConn, upstreamConn, clientSnap, upstreamSnap, nil
}

// buildPoolHitFastPath constructs the ConnectionStack without dialing
// upstream — the cached h2 Layer is reused as-is. The caller has already
// obtained pooled via cfg.HTTP2Pool.Get (inUseCount is incremented);
// the stack's deferred Pool.Put in dispatchStack balances that on handler
// exit. If client MITM fails before the stack is returned, this function
// calls Pool.Put inline to release the reservation (the cached Layer is
// healthy — Evict would destroy a reusable connection for an unrelated
// client-side problem).
//
// Returns (stack, clientSnap, upstreamSnap, err). The upstreamSnap is read
// from pooled.EnvelopeContextTemplate() — authoritative per USK-619 (the
// stored snap was captured at the cached Layer's original dial).
func buildPoolHitFastPath(
	ctx context.Context,
	clientConn net.Conn,
	target, host, connID string,
	pooled *http2.Layer,
	poolKey pool.PoolKey,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	clientTLSConn, clientSnap, err := performClientMITM(ctx, clientConn, host, ALPNProtocolH2, cfg)
	if err != nil {
		// Release the pool reservation — Layer is healthy, we just didn't
		// complete the client-side handshake. Put (not Evict) keeps the
		// Layer available for the next caller.
		cfg.HTTP2Pool.Put(poolKey, pooled)
		return nil, nil, nil, err
	}

	upstreamSnap := pooled.EnvelopeContextTemplate().TLS

	clientEnvCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		TLS:        clientSnap,
	}

	clientLayer, err := http2.New(clientTLSConn, connID+"/client", http2.ServerRole,
		http2.WithScheme("https"),
		http2.WithEnvelopeContext(clientEnvCtx),
		http2.WithBodySpillDir(cfg.BodySpillDir),
		http2.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http2.WithMaxBodySize(cfg.MaxBodySize),
	)
	if err != nil {
		cfg.HTTP2Pool.Put(poolKey, pooled)
		clientTLSConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: h2 client layer: %w", err)
	}

	stack := NewConnectionStack(connID)
	stack.PushClient(clientLayer)
	stack.setUpstreamH2(pooled, poolKey)

	slog.Debug("connector: h2 pool fast-path hit",
		"target", target, "conn_id", connID, "key", poolKey.String(),
	)

	return stack, clientSnap, upstreamSnap, nil
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
// connection, the full upstream TLS snapshot (authoritative upstream reality
// for downstream EnvelopeContext stamping and ConnInfo recording), and any
// error. Callers extract the negotiated ALPN from snap.ALPN.
func dialUpstreamWithALPN(
	ctx context.Context,
	target, host string,
	offerALPN []string,
	insecureSkip bool,
	clientCert *tls.Certificate,
	rootCAsConfig *tls.Config,
	cfg *BuildConfig,
) (net.Conn, *envelope.TLSSnapshot, error) {
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
		return nil, nil, fmt.Errorf("connector: upstream dial for %s: %w", target, err)
	}

	return conn, snap, nil
}

// buildStackFromRoute constructs a ConnectionStack with the appropriate
// Layers based on the ALPN route decision. Each Layer's EnvelopeContext
// carries the TLS snapshot for its own wire (clientSnap for the client-
// facing Layer, upstreamSnap for the upstream-facing Layer) per RFC-001
// §3.1 (TLS is per-Layer, not per-stack).
func buildStackFromRoute(
	ctx context.Context,
	clientConn, upstreamConn net.Conn,
	target, connID, route string,
	clientSnap, upstreamSnap *envelope.TLSSnapshot,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	clientEnvCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		TLS:        clientSnap,
	}
	upstreamEnvCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		TLS:        upstreamSnap,
	}

	stack := NewConnectionStack(connID)

	switch route {
	case "http1":
		clientLayer := http1.New(clientConn, connID+"/client", envelope.Send,
			http1.WithScheme("https"),
			http1.WithEnvelopeContext(clientEnvCtx),
			http1.WithBodySpillDir(cfg.BodySpillDir),
			http1.WithBodySpillThreshold(cfg.BodySpillThreshold),
			http1.WithMaxBodySize(cfg.MaxBodySize),
		)
		stack.PushClient(clientLayer)

		upstreamLayer := http1.New(upstreamConn, connID+"/upstream", envelope.Receive,
			http1.WithScheme("https"),
			http1.WithEnvelopeContext(upstreamEnvCtx),
			http1.WithBodySpillDir(cfg.BodySpillDir),
			http1.WithBodySpillThreshold(cfg.BodySpillThreshold),
			http1.WithMaxBodySize(cfg.MaxBodySize),
		)
		stack.PushUpstream(upstreamLayer)

	case "h2":
		return buildH2Stack(ctx, stack, clientConn, upstreamConn, target, connID, clientEnvCtx, upstreamEnvCtx, clientSnap, upstreamSnap, cfg)

	case "bytechunk":
		clientLayer := bytechunk.New(clientConn, connID+"/client", envelope.Send)
		stack.PushClient(clientLayer)

		upstreamLayer := bytechunk.New(upstreamConn, connID+"/upstream", envelope.Receive)
		stack.PushUpstream(upstreamLayer)

	default:
		upstreamConn.Close()
		clientConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: unknown route %q", route)
	}

	return stack, clientSnap, upstreamSnap, nil
}

// buildH2Stack specializes buildStackFromRoute for the "h2" route.
//
// Client side: a ServerRole http2.Layer is pushed onto the client stack.
// Upstream side: the pre-dialed upstreamConn is handed to the pool (if
// non-nil) or used directly to construct a ClientRole http2.Layer. The
// upstream Layer is NOT pushed into the stack — it lives on
// ConnectionStack.upstreamH2 so that its lifecycle stays with the pool
// and does not get swept by stack.Close.
//
// Single-consumption guarantee: upstreamConn is consumed exactly once. If
// the pool returns a hit, the pre-dialed conn is orphaned and closed. If
// the pool invokes dialFn (miss), dialFn wraps the pre-dialed conn in
// http2.New; on internal failure http2.New already closes conn, so no
// double-close is possible.
//
// TLS snapshot correctness: the upstream Layer is constructed with
// upstreamEnvCtx (TLS=upstreamSnap). Pool hits return a cached Layer whose
// original EnvelopeContext carries the correct upstream snap from its
// original dial; pool hits on a second connection discard the freshly-dialed
// upstream snap as expected (the cached Layer is authoritative).
func buildH2Stack(
	ctx context.Context,
	stack *ConnectionStack,
	clientConn, upstreamConn net.Conn,
	target, connID string,
	clientEnvCtx, upstreamEnvCtx envelope.EnvelopeContext,
	clientSnap, upstreamSnap *envelope.TLSSnapshot,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	// Client-side Layer (ServerRole = local acts as HTTP/2 server).
	clientLayer, err := http2.New(clientConn, connID+"/client", http2.ServerRole,
		http2.WithScheme("https"),
		http2.WithEnvelopeContext(clientEnvCtx),
		http2.WithBodySpillDir(cfg.BodySpillDir),
		http2.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http2.WithMaxBodySize(cfg.MaxBodySize),
	)
	if err != nil {
		upstreamConn.Close()
		clientConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: h2 client layer: %w", err)
	}
	stack.PushClient(clientLayer)

	poolKey := poolKeyForH2(target, cfg)

	// consumed tracks whether dialFn ran (true = upstreamConn is owned by
	// http2.New and must not be closed by the caller). On pool hit, remains
	// false and we close upstreamConn as an orphan.
	var consumed bool

	dialFn := func() (*http2.Layer, error) {
		consumed = true
		l, lerr := http2.New(upstreamConn, connID+"/upstream", http2.ClientRole,
			http2.WithScheme("https"),
			http2.WithEnvelopeContext(upstreamEnvCtx),
			http2.WithBodySpillDir(cfg.BodySpillDir),
			http2.WithBodySpillThreshold(cfg.BodySpillThreshold),
			http2.WithMaxBodySize(cfg.MaxBodySize),
		)
		if lerr != nil {
			// http2.New already closed upstreamConn on failure.
			return nil, lerr
		}
		// USK-623: notify the caller once about the freshly-dialed Layer
		// so push-channel observers (e.g., the upstream push recorder)
		// can attach before any PUSH_PROMISE frames arrive. On pool hit
		// dialFn is not invoked, so the callback never fires for reuse
		// — observers attached on the original dial keep running for
		// the pooled Layer's full lifetime.
		if cfg != nil && cfg.OnHTTP2UpstreamDialed != nil {
			cfg.OnHTTP2UpstreamDialed(l)
		}
		return l, nil
	}

	var upstreamH2 *http2.Layer
	if cfg != nil && cfg.HTTP2Pool != nil {
		l, getErr := cfg.HTTP2Pool.GetOrDial(ctx, poolKey, dialFn)
		if getErr != nil {
			if !consumed {
				upstreamConn.Close()
			}
			clientLayer.Close()
			return nil, nil, nil, fmt.Errorf("connector: h2 pool get-or-dial: %w", getErr)
		}
		upstreamH2 = l
	} else {
		l, dErr := dialFn()
		if dErr != nil {
			clientLayer.Close()
			return nil, nil, nil, fmt.Errorf("connector: h2 upstream layer: %w", dErr)
		}
		upstreamH2 = l
	}

	if !consumed {
		// Pool hit: orphan the pre-dialed conn. The pool already owns a live
		// upstream Layer for this key, so the fresh dial is wasted — close
		// it to avoid a fd leak.
		upstreamConn.Close()
	}

	stack.setUpstreamH2(upstreamH2, poolKey)
	return stack, clientSnap, upstreamSnap, nil
}

// buildRawPassthroughStack builds a [TLS → ByteChunk] stack on both sides.
// This is the config-level raw_passthrough mode that bypasses ALPN routing.
//
// Returns both the client-facing MITM snapshot and the upstream snapshot.
// NOTE: bytechunk.Layer does not currently stamp an EnvelopeContext on its
// envelopes, so upstreamSnap surfaces via BuildConnectionStack's return
// value but is not embedded into each envelope. Threading upstream snap
// into bytechunk-produced envelopes is deferred (follow-up issue).
func buildRawPassthroughStack(
	ctx context.Context,
	clientConn net.Conn,
	target string,
	connID string,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connector: invalid target %q: %w", target, err)
	}

	// --- Client-side TLS MITM ---

	mitmCert, err := cfg.Issuer.GetCertificate(host)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connector: MITM cert for %s: %w", host, err)
	}

	serverTLSCfg := &tls.Config{
		Certificates: []tls.Certificate{*mitmCert},
	}

	clientTLSConn, clientSnap, err := tlslayer.Server(ctx, clientConn, serverTLSCfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connector: client TLS MITM handshake for %s: %w", target, err)
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
			return nil, nil, nil, fmt.Errorf("connector: resolve host TLS for %s: %w", target, resolveErr)
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

	upstreamConn, upstreamSnap, err := DialUpstreamRaw(ctx, target, DialRawOpts{
		TLSConfig:          upstreamTLSCfg,
		InsecureSkipVerify: insecureSkip,
		UTLSProfile:        cfg.TLSFingerprint,
		ClientCert:         clientCert,
		OfferALPN:          []string{"http/1.1"},
		UpstreamProxy:      cfg.UpstreamProxy,
	})
	if err != nil {
		clientTLSConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: upstream dial for %s: %w", target, err)
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

	return stack, clientSnap, upstreamSnap, nil
}
