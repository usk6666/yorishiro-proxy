package connector

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/layer/tlslayer"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
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
	// This is the static (init-time) value; runtime updates from
	// proxy_start / configure flow through SetTLSFingerprint and
	// EffectiveTLSFingerprint. Live data-path readers MUST call
	// EffectiveTLSFingerprint() — direct field reads observe only the
	// boot-time value (USK-809).
	TLSFingerprint string

	// tlsFingerprintDynamic stores the runtime-mutable TLS fingerprint
	// profile installed by proxy_start / configure (USK-809). It overrides
	// the static TLSFingerprint field when non-nil. atomic.Pointer is used
	// so dial-path readers (per-connection goroutines) and the MCP-tool
	// writer (proxy_start / configure handler goroutine) do not race on
	// the *string pointer. A nil load means "fall back to TLSFingerprint".
	tlsFingerprintDynamic atomic.Pointer[string]

	// ClientCert is the global mTLS client certificate for upstream, if any.
	ClientCert *tls.Certificate

	// UpstreamProxy, if non-nil, tunnels upstream connections through an
	// HTTP CONNECT or SOCKS5 proxy. This is the static (init-time) value;
	// runtime updates from proxy_start / configure flow through
	// SetUpstreamProxy and EffectiveUpstreamProxy. Live data-path readers
	// MUST call EffectiveUpstreamProxy() — direct field reads observe only
	// the boot-time value (USK-734).
	UpstreamProxy *url.URL

	// upstreamProxyDynamic stores the runtime-mutable upstream proxy URL
	// installed by proxy_start / configure (USK-734). It overrides the
	// static UpstreamProxy field when non-nil. atomic.Pointer is used so
	// dial-path readers (per-connection goroutines) and the MCP-tool
	// writer (proxy_start handler goroutine) do not race on the *url.URL
	// pointer. A nil load means "fall back to UpstreamProxy".
	upstreamProxyDynamic atomic.Pointer[url.URL]

	// enabledProtocolsDynamic stores the runtime-mutable enabled-protocols
	// allow-list installed by proxy_start / configure (USK-808). The data
	// path consults this snapshot at MITM-handshake time to filter the
	// ALPN list advertised to the client so e.g. proxy_start with
	// protocols=["HTTP/1.x","HTTPS"] does not advertise "h2" — thus
	// keeping browsers on HTTP/1.1 as the operator requested. atomic
	// .Pointer is used so dial-path readers (per-connection goroutines)
	// and the MCP-tool writer (proxy_start handler goroutine) do not
	// race on the slice header. A nil load (or zero-length slice) means
	// "no filter" — legacy "all-allowed" semantics.
	//
	// Note: this filter applies ONLY to the client-facing MITM ALPN
	// offer; upstream-facing dial offers are intentionally not filtered
	// because wire fidelity to upstream is a strict MITM principle and
	// h2-only origins must remain reachable. The post-MITM redial via
	// canonicalRedialALPNOffer (USK-793) collapses upstream to http/1.1
	// when the client picked http/1.1, so the inner stack is already
	// single-protocol end-to-end.
	enabledProtocolsDynamic atomic.Pointer[[]string]

	// HostTLSResolver resolves per-host TLS overrides (InsecureSkipVerify,
	// ClientCert, RootCAs). Nil means use global settings for all hosts.
	HostTLSResolver *HostTLSResolver

	// HostTLSRegistry, when non-nil, is consulted at dial time for runtime
	// per-host TLS material — including the global mTLS client certificate
	// installed by `proxy_start(client_cert=..., client_key=...)`. Lookup
	// happens on the dial hot path; the registry is concurrency-safe
	// (sync.RWMutex) and falls back to the global slot when no host-specific
	// entry matches.
	//
	// Resolution order at dial time (USK-733):
	//
	//  1. HostTLSRegistry per-host entry (runtime-mutable; includes
	//     wildcard match → global fallback within the registry).
	//  2. HostTLSResolver per-host entry (built at startup from the
	//     proxy config file's `host_tls` map).
	//  3. BuildConfig.ClientCert / InsecureSkipVerify (the legacy
	//     `-client-cert` flag snapshot).
	//
	// The registry surfaces runtime updates from proxy_start that the
	// startup-time HostTLSResolver and ClientCert snapshot cannot.
	HostTLSRegistry *transport.HostTLSRegistry

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

	// MaxRawCaptureSize caps per-message HTTP/1.x raw-bytes capture in
	// memory mode (header section + RawBody when body spill is not active).
	// Zero means the layer's internal default
	// (config.DefaultMaxRawCaptureSize, 2 MiB). Threaded into both http1
	// Layer constructions (client-facing and upstream-facing) via
	// http1.WithMaxRawCaptureSize. HTTP/2 and other protocols are
	// unaffected — this is an HTTP/1.x-only knob.
	MaxRawCaptureSize int64

	// WSMaxFrameSize is the per-frame WebSocket payload cap applied to
	// the post-Upgrade *ws.Layer pair on both client- and upstream-facing
	// sides. Resolved at BuildConfig construction time from
	// ProxyConfig.WebSocket via config.ResolveWSMaxFrameSize. Zero falls
	// back to the Layer default (config.MaxWebSocketFrameSize, 16 MiB).
	// Read by proxybuild.buildSessionOptions, threaded through
	// session.SessionOptions.WSMaxFrameSize, and applied by runUpgradeWS
	// / runUpgradeWSOverH2 to both ws.New constructions via
	// ws.WithMaxFrameSize (USK-806).
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

	// SSEMaxEventSize caps the per-event raw byte size on the post-Upgrade
	// SSE Channel built by sse.Wrap. Resolved at BuildConfig construction
	// time from ProxyConfig.SSE via config.ResolveSSEMaxEventSize. Zero
	// falls back to the Layer default (config.MaxSSEEventSize, 1 MiB).
	// Read by proxybuild.buildSessionOptions, threaded through
	// session.SessionOptions.SSEMaxEventSize, and applied by
	// runUpgradeSSE via sse.WithMaxEventSize (USK-806).
	SSEMaxEventSize int

	// GRPCMaxMessagesPerStream caps the number of GRPCDataMessage envelopes
	// recorded by RecordStep per stream (USK-802). Once exceeded, further
	// gRPC data envelopes are still forwarded on the wire (Channels are
	// untouched) but no longer persisted to the flow store. Start/End
	// envelopes are always recorded regardless of this cap. Resolved at
	// BuildConfig construction time from ProxyConfig.GRPC via
	// config.ResolveGRPCMaxMessagesPerStream. Zero falls back to the
	// RecordStep default (config.MaxGRPCMessagesPerStream, 10000). Read by
	// proxybuild/builder.go when constructing RecordStep.
	GRPCMaxMessagesPerStream int

	// SSEMaxEventsPerStream caps the number of SSEMessage envelopes
	// recorded by RecordStep per stream (USK-802). Same wire-passthrough
	// guarantee as GRPCMaxMessagesPerStream — events still flow through
	// the SSE Layer's TeeReader, only the persisted flow rows are bounded.
	// Resolved at BuildConfig construction time from ProxyConfig.SSE via
	// config.ResolveSSEMaxEventsPerStream. Zero falls back to the
	// RecordStep default (config.MaxSSEEventsPerStream, 100000).
	SSEMaxEventsPerStream int

	// PluginV2Engine is the optional pluginv2 Engine consulted for
	// (tls, on_handshake) lifecycle hooks (USK-683 / RFC §9.3). The
	// hook fires once per successful tlslayer.Server (server-side) and
	// once per successful upstream TLS handshake (client-side) with a
	// `side` field on the payload distinguishing them. nil disables.
	PluginV2Engine *pluginv2.Engine

	// MaxConcurrentStreams caps the per-connection HTTP/2 stream
	// concurrency advertised to clients via SETTINGS_MAX_CONCURRENT_STREAMS
	// on the client-facing (ServerRole) Layer. Streams beyond this cap are
	// rejected with REFUSED_STREAM per RFC 9113 §5.1.2, bounding the
	// per-connection goroutine fan-out under load. Zero means use the H2
	// layer's compile-time default (currently 100); see
	// internal/layer/http2/connstate.go defaultMaxConcurrentStreams.
	// Applied only to the inbound (client-facing) Layer; the outbound
	// (upstream / ClientRole) Layer continues to honour the peer's
	// advertised limit.
	MaxConcurrentStreams uint32
}

// EffectiveUpstreamProxy returns the upstream proxy URL the live data path
// should consult for the next dial. Runtime updates installed via
// SetUpstreamProxy take precedence over the static UpstreamProxy field set
// at boot. Returns nil when neither is configured (direct dial). This is
// the canonical accessor for live dial-path code (USK-734); callers MUST
// NOT read the UpstreamProxy field directly because it observes only the
// boot-time value.
func (c *BuildConfig) EffectiveUpstreamProxy() *url.URL {
	if c == nil {
		return nil
	}
	if dyn := c.upstreamProxyDynamic.Load(); dyn != nil {
		return dyn
	}
	return c.UpstreamProxy
}

// SetUpstreamProxy installs a runtime override for the upstream proxy URL.
// Subsequent calls to EffectiveUpstreamProxy return u (or fall back to the
// static UpstreamProxy field when u is nil). The runtime override is the
// wire-up consumed by proxy_start / configure to make the URL change
// reach the live dial path (USK-734); writes are atomic with respect to
// concurrent dial-path reads. Passing nil clears the override.
func (c *BuildConfig) SetUpstreamProxy(u *url.URL) {
	if c == nil {
		return
	}
	c.upstreamProxyDynamic.Store(u)
}

// EffectiveTLSFingerprint returns the uTLS browser fingerprint profile
// the live data path should use for the next upstream dial. Runtime
// updates installed via SetTLSFingerprint take precedence over the
// static TLSFingerprint field set at boot. Returns the empty string when
// neither is configured (the dial path then falls back to standard TLS).
// This is the canonical accessor for live dial-path code (USK-809);
// callers MUST NOT read the TLSFingerprint field directly because it
// observes only the boot-time value.
func (c *BuildConfig) EffectiveTLSFingerprint() string {
	if c == nil {
		return ""
	}
	if dyn := c.tlsFingerprintDynamic.Load(); dyn != nil {
		return *dyn
	}
	return c.TLSFingerprint
}

// SetTLSFingerprint installs a runtime override for the uTLS browser
// fingerprint profile. Subsequent calls to EffectiveTLSFingerprint
// return profile (or fall back to the static TLSFingerprint field when
// profile is empty). The runtime override is the wire-up consumed by
// proxy_start / configure to make the fingerprint change reach the
// live dial path (USK-809); writes are atomic with respect to
// concurrent dial-path reads. Passing the empty string clears the
// override.
func (c *BuildConfig) SetTLSFingerprint(profile string) {
	if c == nil {
		return
	}
	if profile == "" {
		c.tlsFingerprintDynamic.Store(nil)
		return
	}
	p := profile
	c.tlsFingerprintDynamic.Store(&p)
}

// SetEnabledProtocols installs a runtime override for the enabled-protocols
// allow-list. Subsequent calls to EffectiveEnabledProtocols return a copy
// of protocols, or nil when protocols is nil/empty (legacy "all-allowed"
// semantic). The runtime override is the wire-up consumed by proxy_start /
// configure (USK-808) to make the allow-list reach the client-facing MITM
// ALPN filter so e.g. omitting "HTTP/2" from protocols actually keeps "h2"
// out of the advertised ALPN list.
//
// A defensive copy is taken so later mutation of the caller's slice
// cannot perturb the stored snapshot. Writes are atomic with respect to
// concurrent dial-path reads.
func (c *BuildConfig) SetEnabledProtocols(protocols []string) {
	if c == nil {
		return
	}
	if len(protocols) == 0 {
		c.enabledProtocolsDynamic.Store(nil)
		return
	}
	cp := make([]string, len(protocols))
	copy(cp, protocols)
	c.enabledProtocolsDynamic.Store(&cp)
}

// EffectiveEnabledProtocols returns a defensive copy of the runtime
// enabled-protocols allow-list installed by SetEnabledProtocols, or nil
// when no filter is active. This is the canonical accessor for live
// data-path code that needs to apply the operator's protocol allow-list
// at MITM handshake time (USK-808).
//
// nil / empty means "all allowed" — callers must treat that as the
// identity (no filtering) per USK-808 design decision #5.
func (c *BuildConfig) EffectiveEnabledProtocols() []string {
	if c == nil {
		return nil
	}
	p := c.enabledProtocolsDynamic.Load()
	if p == nil || len(*p) == 0 {
		return nil
	}
	out := make([]string, len(*p))
	copy(out, *p)
	return out
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

	// caBundleHash is a stable hex-encoded hash of the CA bundle PEM bytes
	// that produced rootCAs (when rootCAs was set from a per-host config).
	// Empty when the global / system CA pool is in effect. Used by the
	// h2 pool key (poolKeyForH2) so that runtime CA-bundle replacement
	// invalidates pooled connections established under the prior bundle.
	caBundleHash string
}

// clientH2MaxConcurrentStreamsOption returns an http2.Option threading the
// configured SETTINGS_MAX_CONCURRENT_STREAMS into the client-facing
// (ServerRole) Layer's preface. Returns nil when cfg.MaxConcurrentStreams
// is zero so the Layer keeps its compile-time default
// (defaultMaxConcurrentStreams in internal/layer/http2/connstate.go).
// Callers must guard against nil before appending.
func clientH2MaxConcurrentStreamsOption(cfg *BuildConfig) http2.Option {
	if cfg == nil || cfg.MaxConcurrentStreams == 0 {
		return nil
	}
	return http2.WithMaxConcurrentStreams(cfg.MaxConcurrentStreams)
}

// resolvePerHostTLS resolves per-host TLS overrides from the BuildConfig.
//
// Resolution order (USK-733):
//  1. Static cfg.ClientCert / cfg.InsecureSkipVerify (boot-time fallbacks).
//  2. cfg.HostTLSResolver per-host entry (startup-time proxy config map).
//  3. cfg.HostTLSRegistry per-host entry (runtime-mutable; takes precedence
//     so `proxy_start(client_cert=..., client_key=...)` and other runtime
//     installers reach the live dial path).
//
// Each layer overrides only the fields it provides, so a runtime registry
// entry that sets only ClientCert leaves InsecureSkipVerify / RootCAs from
// earlier layers untouched.
func resolvePerHostTLS(target string, cfg *BuildConfig) (*resolvedTLS, error) {
	r := &resolvedTLS{
		insecureSkip: cfg.InsecureSkipVerify,
		clientCert:   cfg.ClientCert,
	}

	if cfg.HostTLSResolver != nil {
		resolved, err := cfg.HostTLSResolver.Resolve(target)
		if err != nil {
			return nil, fmt.Errorf("connector: resolve host TLS for %s: %w", target, err)
		}
		if resolved != nil {
			if resolved.InsecureSkipVerify != nil {
				r.insecureSkip = *resolved.InsecureSkipVerify
			}
			if resolved.ClientCert != nil {
				r.clientCert = resolved.ClientCert
			}
			if resolved.RootCAs != nil {
				r.rootCAs = &tls.Config{RootCAs: resolved.RootCAs}
				r.caBundleHash = resolved.CABundleHash
			}
		}
	}

	if cfg.HostTLSRegistry != nil {
		if err := applyHostTLSRegistry(r, target, cfg.HostTLSRegistry); err != nil {
			return nil, fmt.Errorf("connector: resolve host TLS for %s: %w", target, err)
		}
	}

	return r, nil
}

// applyHostTLSRegistry consults the runtime-mutable HostTLSRegistry and
// overlays its lookup result onto the partially-resolved tls knobs. Empty
// fields in the registry entry leave the corresponding slot untouched so a
// registry entry that only carries a client cert does not clobber an earlier
// layer's RootCAs / InsecureSkipVerify.
//
// The registry's Lookup performs exact → wildcard → global fallback under a
// single RLock so the dial-time read is consistent.
func applyHostTLSRegistry(r *resolvedTLS, target string, reg *transport.HostTLSRegistry) error {
	host := extractHost(target)
	hostCfg := reg.Lookup(host)
	if hostCfg == nil {
		return nil
	}
	cert, err := hostCfg.LoadClientCert()
	if err != nil {
		return err
	}
	if cert != nil {
		r.clientCert = cert
	}
	if hostCfg.TLSVerify != nil {
		r.insecureSkip = !*hostCfg.TLSVerify
	}
	pool, err := hostCfg.LoadCABundle()
	if err != nil {
		return err
	}
	if pool != nil {
		r.rootCAs = &tls.Config{RootCAs: pool}
		hash, herr := hostCfg.CABundleHash()
		if herr != nil {
			return herr
		}
		r.caBundleHash = hash
	}
	return nil
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
		poolKey := poolKeyForH2(target, cfg, hostTLS)
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

	// USK-793: route the post-CONNECT dispatch off the CLIENT-side
	// negotiated ALPN, not upstream. After the redial logic in
	// buildCacheMissPath / buildCacheHitPath upstream's ALPN matches the
	// client's, but the source of truth is the client because that is
	// what determines what bytes the proxy will see arriving on
	// clientTLSConn next. An empty client ALPN (no offer / no overlap)
	// collapses to http/1.1 in alpnRoute.
	clientALPN := ""
	if clientSnap != nil {
		clientALPN = clientSnap.ALPN
	}
	upstreamALPNObserved := ""
	if upstreamSnap != nil {
		upstreamALPNObserved = upstreamSnap.ALPN
	}

	route, routeErr := alpnRoute(clientALPN)
	if routeErr != nil {
		upstreamConn.Close()
		clientTLSConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: %s: %w", target, routeErr)
	}

	slog.Debug("connector: ALPN routed",
		"target", target, "conn_id", connID,
		"client_alpn", clientALPN, "upstream_alpn", upstreamALPNObserved,
		"route", route, "cache_hit", cacheHit,
	)

	return buildStackFromRoute(ctx, clientTLSConn, upstreamConn, target, connID, route, clientSnap, upstreamSnap, hostTLS, cfg)
}

// buildCacheHitPath handles the ALPN cache hit: client MITM first offering
// both the cached ALPN and http/1.1 fallback (USK-793), then upstream dial
// using whatever the client actually negotiated. Verify upstream agrees.
//
// Why offer both protocols even on a cache hit (USK-793): the cache reflects
// what _previous_ clients negotiated with upstream, not what the current
// client speaks. If the proxy advertised only the cached "h2" and the
// current client offered only "http/1.1", Go's crypto/tls would complete
// the handshake with empty NegotiatedProtocol, and the client would speak
// HTTP/1.x on a stack the proxy then dispatched as HTTP/2. By advertising
// both we let the client pick a protocol it can actually speak, and the
// upstream re-dial below honours that choice.
//
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
	clientOffers := clientALPNOffersForUpstream(cachedALPN, cfg.EffectiveEnabledProtocols())
	clientTLSConn, clientSnap, err = performClientMITM(ctx, clientConn, host, clientOffers, cfg)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	clientALPN := ""
	if clientSnap != nil {
		clientALPN = clientSnap.ALPN
	}

	// Dial upstream offering only the protocol the client picked so the
	// data path stays single-protocol end-to-end. An empty client ALPN
	// (no offers, or offers with no overlap) collapses to http/1.1.
	upstreamOffer := canonicalRedialALPNOffer(clientALPN)
	upstreamConn, upstreamSnap, err = dialUpstreamWithALPN(ctx, target, host,
		upstreamOffer, hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg)
	if err != nil {
		_ = clientTLSConn.Close()
		return nil, nil, nil, nil, err
	}

	upstreamALPN := ""
	if upstreamSnap != nil {
		upstreamALPN = upstreamSnap.ALPN
	}
	if !clientALPNMatchesUpstream(clientALPN, upstreamALPN) {
		// Upstream changed its mind since the cached value was learned.
		// Invalidate so the next CONNECT relearns from scratch.
		if cfg.ALPNCache != nil {
			cfg.ALPNCache.Delete(cacheKey)
		}
		_ = upstreamConn.Close()
		_ = clientTLSConn.Close()
		return nil, nil, nil, nil, fmt.Errorf("connector: ALPN mismatch for %s: client %q, upstream %q",
			target, clientALPN, upstreamALPN)
	}

	// Refresh cache so a subsequent connection sees the now-current
	// upstream behaviour (especially when the client picked the alternative
	// to the cached protocol).
	if cfg.ALPNCache != nil && upstreamALPN != cachedALPN {
		cfg.ALPNCache.Set(cacheKey, upstreamALPN)
	}

	return clientTLSConn, upstreamConn, clientSnap, upstreamSnap, nil
}

// buildCacheMissPath handles the ALPN cache miss: upstream dial first (to
// learn ALPN), then client MITM offering the upstream-supported protocols
// (h2 and http/1.1) so the client picks one it actually speaks.
//
// Why offer both to the client (USK-793): if the proxy only advertises the
// upstream-selected ALPN (e.g. only "h2") and the client cannot speak it
// (curl --http1.1 offers only "http/1.1"), Go's crypto/tls server silently
// completes the handshake with NegotiatedProtocol="" and the client speaks
// HTTP/1.x on a connection the proxy then routes through the HTTP/2 stack.
// Result: "http2: invalid client preface" and a 0-byte timeout. By offering
// both protocols and letting the client choose, the post-TLS dispatch can
// honour what the client actually negotiated.
//
// If the client picks an ALPN that does not match upstream's selection
// (e.g. upstream chose h2 but client picked http/1.1), the cache is
// invalidated and the upstream connection is re-dialled with only the
// client's ALPN so the on-the-wire stack matches end-to-end. This keeps
// stack_builder honest about its single-protocol-per-stack invariant: we
// do not bridge h1↔h2 in the data path.
//
// Returns the TLS-wrapped client connection plus both TLS snapshots. The
// upstreamConn returned reflects the (possibly redialed) connection whose
// ALPN matches the client's negotiation.
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

	upstreamALPN := ""
	if upstreamSnap != nil {
		upstreamALPN = upstreamSnap.ALPN
	}

	// Validate ALPN route early so we don't waste a client MITM handshake.
	if _, routeErr := alpnRoute(upstreamALPN); routeErr != nil {
		upstreamConn.Close()
		return nil, nil, nil, nil, fmt.Errorf("connector: %s: %w", target, routeErr)
	}

	// Cache the learned upstream ALPN. If the client subsequently picks a
	// different protocol we invalidate this entry below.
	if cfg.ALPNCache != nil {
		cfg.ALPNCache.Set(cacheKey, upstreamALPN)
	}

	// Offer the client every ALPN we believe upstream supports plus the
	// fallback http/1.1, so a client that cannot speak h2 still negotiates
	// a non-empty protocol the proxy can dispatch on. See function comment
	// for the rationale (USK-793). The offers are then filtered through
	// the operator's enabled_protocols allow-list (USK-808) so disabled
	// protocols are never advertised.
	clientOffers := clientALPNOffersForUpstream(upstreamALPN, cfg.EffectiveEnabledProtocols())
	clientTLSConn, clientSnap, err = performClientMITM(ctx, clientConn, host, clientOffers, cfg)
	if err != nil {
		upstreamConn.Close()
		return nil, nil, nil, nil, err
	}

	clientALPN := ""
	if clientSnap != nil {
		clientALPN = clientSnap.ALPN
	}

	if !clientALPNMatchesUpstream(clientALPN, upstreamALPN) {
		// Client picked something different from upstream — usually means
		// the client speaks h1 but upstream offered h2, or vice versa. The
		// existing upstreamConn is unusable for this client, so re-dial
		// with the client's negotiated ALPN and invalidate the cached
		// upstream-only result.
		slog.Debug("connector: client/upstream ALPN mismatch; re-dialing upstream",
			"target", target, "client_alpn", clientALPN, "upstream_alpn", upstreamALPN,
		)
		if cfg.ALPNCache != nil {
			cfg.ALPNCache.Delete(cacheKey)
		}
		_ = upstreamConn.Close()
		upstreamConn = nil
		upstreamSnap = nil

		redialOffer := canonicalRedialALPNOffer(clientALPN)
		upstreamConn, upstreamSnap, err = dialUpstreamWithALPN(ctx, target, host,
			redialOffer, hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg)
		if err != nil {
			_ = clientTLSConn.Close()
			return nil, nil, nil, nil, err
		}
		// Refresh the cache with the now-known client-side ALPN reality so
		// the next CONNECT to the same target reuses the matching path.
		if cfg.ALPNCache != nil && upstreamSnap != nil {
			cfg.ALPNCache.Set(cacheKey, upstreamSnap.ALPN)
		}
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
// USK-793: the client MITM offers both [h2, http/1.1] so a client that
// cannot speak h2 (e.g. curl --http1.1) negotiates a non-empty protocol
// the proxy can dispatch on. If the client picks anything other than h2,
// the pool reservation is released (Put, not Evict — the cached Layer is
// healthy) and we fall back to a fresh ALPN-routed dial that re-negotiates
// upstream with http/1.1 to match the client. The pooled h2 Layer remains
// available for the next CONNECT whose client _can_ speak h2.
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
	// USK-808: filter through enabled_protocols so a pool entry warmed
	// while h2 was permitted does not advertise h2 once the operator
	// disabled it via proxy_start. When the filter excludes h2 entirely,
	// the helper returns ["http/1.1"]; the client then cannot pick h2,
	// the post-handshake clientALPN check below falls through to
	// fallbackPoolHitToFreshDial, and the pool entry is released for the
	// next h2-capable caller (or for after the operator re-enables h2).
	clientOffers := clientALPNOffersForUpstream(ALPNProtocolH2, cfg.EffectiveEnabledProtocols())
	clientTLSConn, clientSnap, err := performClientMITM(ctx, clientConn, host, clientOffers, cfg)
	if err != nil {
		// Release the pool reservation — Layer is healthy, we just didn't
		// complete the client-side handshake. Put (not Evict) keeps the
		// Layer available for the next caller.
		cfg.HTTP2Pool.Put(poolKey, pooled)
		return nil, nil, nil, err
	}

	clientALPN := ""
	if clientSnap != nil {
		clientALPN = clientSnap.ALPN
	}
	if clientALPN != ALPNProtocolH2 {
		// Client cannot (or will not) speak h2; the pooled h2 Layer is
		// unusable for this connection. Release the reservation (the
		// pooled Layer is still healthy for h2-capable clients) and fall
		// back to a fresh dial that re-negotiates upstream with the
		// client's chosen protocol. fallbackPoolHitToFreshDial owns the
		// rest of the stack build using the already-handshaked client
		// TLS connection.
		cfg.HTTP2Pool.Put(poolKey, pooled)
		slog.Debug("connector: pool hit but client picked non-h2 ALPN; falling back to fresh dial",
			"target", target, "conn_id", connID, "client_alpn", clientALPN,
		)
		return fallbackPoolHitToFreshDial(ctx, clientTLSConn, clientSnap, target, host, connID, cfg)
	}

	upstreamSnap := pooled.EnvelopeContextTemplate().TLS

	clientEnvCtx := envelope.EnvelopeContext{
		ConnID:     connID,
		TargetHost: target,
		TLS:        clientSnap,
	}

	clientH2Opts := []http2.Option{
		http2.WithScheme("https"),
		http2.WithEnvelopeContext(clientEnvCtx),
		http2.WithBodySpillDir(cfg.BodySpillDir),
		http2.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http2.WithMaxBodySize(cfg.MaxBodySize),
		http2.WithStateReleaser(cfg.PluginV2Engine),
	}
	if mcsOpt := clientH2MaxConcurrentStreamsOption(cfg); mcsOpt != nil {
		clientH2Opts = append(clientH2Opts, mcsOpt)
	}
	clientLayer, err := http2.New(clientTLSConn, connID+"/client", http2.ServerRole, clientH2Opts...)
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

// fallbackPoolHitToFreshDial completes a stack build after a pool-hit
// fast path discovered a client/upstream ALPN mismatch (USK-793). The
// client TLS handshake has already happened (clientTLSConn is live and
// clientSnap reflects what the client negotiated). The caller has already
// returned the pool reservation, so this function only owns the upstream
// dial and the post-dispatch stack assembly.
//
// The upstream is dialed with only the client's negotiated ALPN so the
// resulting stack is single-protocol end-to-end. On dial failure or
// post-dial route validation failure clientTLSConn is closed.
func fallbackPoolHitToFreshDial(
	ctx context.Context,
	clientTLSConn net.Conn,
	clientSnap *envelope.TLSSnapshot,
	target, host, connID string,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	hostTLS, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		_ = clientTLSConn.Close()
		return nil, nil, nil, err
	}

	clientALPN := ""
	if clientSnap != nil {
		clientALPN = clientSnap.ALPN
	}
	upstreamOffer := canonicalRedialALPNOffer(clientALPN)

	upstreamConn, upstreamSnap, err := dialUpstreamWithALPN(ctx, target, host,
		upstreamOffer, hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg)
	if err != nil {
		_ = clientTLSConn.Close()
		return nil, nil, nil, err
	}

	route, routeErr := alpnRoute(clientALPN)
	if routeErr != nil {
		_ = upstreamConn.Close()
		_ = clientTLSConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: %s: %w", target, routeErr)
	}

	slog.Debug("connector: ALPN routed (pool fallback)",
		"target", target, "conn_id", connID,
		"client_alpn", clientALPN, "route", route,
	)

	return buildStackFromRoute(ctx, clientTLSConn, upstreamConn, target, connID, route, clientSnap, upstreamSnap, hostTLS, cfg)
}

// performClientMITM performs the client-side TLS MITM handshake, issuing a
// certificate for the given host and offering the specified ALPN protocols.
// Returns the TLS-wrapped connection (which must be used for subsequent I/O
// instead of the original plain connection) and the TLS snapshot.
//
// alpnOffers are the ALPN protocols the proxy advertises to the client. The
// client picks one (or none) and the result is observable via
// clientSnap.ALPN. The caller MUST consult clientSnap.ALPN — not the upstream
// negotiation result — when selecting the post-TLS dispatch route (USK-793):
// when clientSnap.ALPN is empty the client either offered no ALPN or offered
// a set with no overlap, in which case Go's crypto/tls server completes the
// handshake silently and the client almost certainly speaks HTTP/1.x next.
//
// An empty / nil alpnOffers leaves NextProtos unset so the client never sees
// the ALPN extension; the client will speak whatever default it prefers
// (HTTP/1.x for browsers and curl).
func performClientMITM(
	ctx context.Context,
	clientConn net.Conn,
	host string,
	alpnOffers []string,
	cfg *BuildConfig,
) (net.Conn, *envelope.TLSSnapshot, error) {
	// Pre-warm the cert cache so a missing/invalid CA surfaces as a clear
	// "MITM cert for <host>" error rather than failing later inside the
	// handshake's GetCertificate callback (USK-795).
	if _, err := cfg.Issuer.GetCertificate(host); err != nil {
		return nil, nil, fmt.Errorf("connector: MITM cert for %s: %w", host, err)
	}

	// Reuse a shared *tls.Config keyed by (host, alpnOffers) so crypto/tls's
	// lazy session ticket encryption key persists across connections; a
	// fresh Config per call would generate a new random key each time and
	// invalidate every browser-held ticket (USK-795). MITMServerConfig
	// makes a defensive copy of alpnOffers internally.
	serverTLSCfg := cfg.Issuer.MITMServerConfig(host, alpnOffers)

	tlsConn, clientSnap, err := tlslayer.Server(ctx, clientConn, serverTLSCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("connector: client TLS MITM handshake: %w", err)
	}
	fireTLSHandshakeHook(ctx, cfg, "server", clientSnap)
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
		UTLSProfile:        cfg.EffectiveTLSFingerprint(),
		ClientCert:         clientCert,
		OfferALPN:          offerALPN,
		UpstreamProxy:      cfg.EffectiveUpstreamProxy(),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("connector: upstream dial for %s: %w", target, err)
	}

	// Fire (tls, on_handshake) for the client-side handshake (proxy
	// dialing upstream). snap is non-nil only when a TLS handshake
	// actually happened — DialUpstreamRaw returns a nil snap when the
	// caller's TLSConfig is nil (plain TCP); guard so observation-only
	// hooks see a real handshake.
	if snap != nil {
		fireTLSHandshakeHook(ctx, cfg, "client", snap)
	}
	return conn, snap, nil
}

// fireTLSHandshakeHook dispatches (tls, on_handshake) hooks for one
// successful TLS handshake. side is "server" when the proxy presented
// the MITM cert to the client, "client" when the proxy completed the
// upstream-side handshake. No-op when no PluginV2Engine is wired.
// Errors are swallowed (USK-671 fail-soft).
func fireTLSHandshakeHook(ctx context.Context, cfg *BuildConfig, side string, snap *envelope.TLSSnapshot) {
	if cfg == nil || cfg.PluginV2Engine == nil {
		return
	}
	hookCtx, cancel := context.WithTimeout(ctx, hookTimeout)
	defer cancel()
	payload := pluginv2.BuildTLSHandshakeDict(side, snap)
	if _, err := cfg.PluginV2Engine.FireLifecycle(hookCtx, pluginv2.ProtoTLS, pluginv2.EventOnHandshake, nil, payload); err != nil {
		slog.WarnContext(ctx, "pluginv2 tls on_handshake hook error",
			"error", err, "side", side)
	}
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
	hostTLS *resolvedTLS,
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
			http1.WithMaxRawCaptureSize(cfg.MaxRawCaptureSize),
			http1.WithStateReleaser(cfg.PluginV2Engine),
		)
		stack.PushClient(clientLayer)

		upstreamLayer := http1.New(upstreamConn, connID+"/upstream", envelope.Receive,
			http1.WithScheme("https"),
			http1.WithEnvelopeContext(upstreamEnvCtx),
			http1.WithBodySpillDir(cfg.BodySpillDir),
			http1.WithBodySpillThreshold(cfg.BodySpillThreshold),
			http1.WithMaxBodySize(cfg.MaxBodySize),
			http1.WithMaxRawCaptureSize(cfg.MaxRawCaptureSize),
			http1.WithStateReleaser(cfg.PluginV2Engine),
			// USK-655: bypass body draining for SSE responses so the swap
			// orchestrator (session.runUpgradeSSE) can hand the still-open
			// body to sse.Wrap without blocking on a never-ending drain.
			http1.WithStreamingResponseDetect(http1.IsSSEResponse),
		)
		stack.PushUpstream(upstreamLayer)

	case "h2":
		return buildH2Stack(ctx, stack, clientConn, upstreamConn, target, connID, clientEnvCtx, upstreamEnvCtx, clientSnap, upstreamSnap, hostTLS, cfg)

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
	hostTLS *resolvedTLS,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	// Client-side Layer (ServerRole = local acts as HTTP/2 server).
	clientH2Opts := []http2.Option{
		http2.WithScheme("https"),
		http2.WithEnvelopeContext(clientEnvCtx),
		http2.WithBodySpillDir(cfg.BodySpillDir),
		http2.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http2.WithMaxBodySize(cfg.MaxBodySize),
		http2.WithStateReleaser(cfg.PluginV2Engine),
	}
	if mcsOpt := clientH2MaxConcurrentStreamsOption(cfg); mcsOpt != nil {
		clientH2Opts = append(clientH2Opts, mcsOpt)
	}
	clientLayer, err := http2.New(clientConn, connID+"/client", http2.ServerRole, clientH2Opts...)
	if err != nil {
		upstreamConn.Close()
		clientConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: h2 client layer: %w", err)
	}
	stack.PushClient(clientLayer)

	poolKey := poolKeyForH2(target, cfg, hostTLS)

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
			http2.WithStateReleaser(cfg.PluginV2Engine),
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

	// Pre-warm the cert cache so CA-side issues surface as a recognizable
	// "MITM cert for <host>" error (USK-795).
	if _, err := cfg.Issuer.GetCertificate(host); err != nil {
		return nil, nil, nil, fmt.Errorf("connector: MITM cert for %s: %w", host, err)
	}

	// Raw passthrough offers no ALPN — the tunnel is opaque after the
	// MITM handshake. Reuse a shared *tls.Config so crypto/tls's session
	// ticket key is stable across connections to the same host (USK-795).
	serverTLSCfg := cfg.Issuer.MITMServerConfig(host, nil)

	clientTLSConn, clientSnap, err := tlslayer.Server(ctx, clientConn, serverTLSCfg)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("connector: client TLS MITM handshake for %s: %w", target, err)
	}
	fireTLSHandshakeHook(ctx, cfg, "server", clientSnap)

	slog.Debug("connector: client-side MITM handshake complete",
		"target", target,
		"conn_id", connID,
	)

	// --- Upstream TLS ---

	upstreamTLSCfg := &tls.Config{
		ServerName: host,
	}

	// Apply per-host TLS overrides. Resolution order (USK-733):
	// HostTLSResolver (startup-time) → HostTLSRegistry (runtime-mutable).
	hostTLS, resolveErr := resolvePerHostTLS(target, cfg)
	if resolveErr != nil {
		clientTLSConn.Close()
		return nil, nil, nil, resolveErr
	}
	insecureSkip := hostTLS.insecureSkip
	clientCert := hostTLS.clientCert
	if hostTLS.rootCAs != nil {
		upstreamTLSCfg.RootCAs = hostTLS.rootCAs.RootCAs
	}

	upstreamConn, upstreamSnap, err := DialUpstreamRaw(ctx, target, DialRawOpts{
		TLSConfig:          upstreamTLSCfg,
		InsecureSkipVerify: insecureSkip,
		UTLSProfile:        cfg.EffectiveTLSFingerprint(),
		ClientCert:         clientCert,
		OfferALPN:          []string{"http/1.1"},
		UpstreamProxy:      cfg.EffectiveUpstreamProxy(),
	})
	if err != nil {
		clientTLSConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: upstream dial for %s: %w", target, err)
	}
	if upstreamSnap != nil {
		fireTLSHandshakeHook(ctx, cfg, "client", upstreamSnap)
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
