package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

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

// ErrClientTLSMITMHandshake wraps client-side TLS MITM handshake failures
// returned by BuildConnectionStack. The wire-observed direction is
// browser→proxy (the client refused the proxy's MITM certificate — e.g.
// Chromium pinning, a bad / missing CA install, or an unknown_certificate
// TLS alert), not proxy→upstream. proxybuild uses errors.Is to distinguish
// these from upstream-side TLS failures when classifying FailureReason
// (USK-858). The wrapped underlying error from tlslayer.Server remains
// accessible via errors.Unwrap, so the existing diagnostic surface
// (Tags["error"] = err.Error()) is unchanged.
var ErrClientTLSMITMHandshake = errors.New("connector: client TLS MITM handshake")

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
	//
	// USK-826: this slot is the legacy process-global override and is now
	// only consulted as a fallback when no per-listener override is set
	// for the current connection's listener. Multi-listener setups should
	// write per-listener URLs via SetUpstreamProxyForListener so chained
	// MITM (listener A → listener B) does not self-recurse.
	upstreamProxyDynamic atomic.Pointer[url.URL]

	// upstreamProxyPerListener stores runtime-mutable upstream proxy URLs
	// keyed by listener name (USK-826). The dial path consults this map
	// first via EffectiveUpstreamProxyForCtx, falling back to
	// upstreamProxyDynamic / UpstreamProxy when the current connection's
	// listener has no per-listener override. Writers are MCP-tool
	// goroutines (proxy_start / configure handlers); readers are
	// per-connection dial-path goroutines. RWMutex is used to allow
	// concurrent reads on the hot dial path while serialising the rarer
	// writes from the MCP layer.
	//
	// Entries are deleted (not stored as nil) via
	// SetUpstreamProxyForListener(name, nil) so the global / boot-time
	// fallback re-emerges for that listener — this matches the SOCKS5
	// per-listener auth registry shape (presence vs absence).
	upstreamProxyPerListenerMu sync.RWMutex
	upstreamProxyPerListener   map[string]*url.URL

	// rotationByListener stores per-listener RotationResolvers for the
	// per-listener template-driven rotation surface (USK-959). The
	// dial path consults the resolver INSIDE EffectiveUpstreamProxyForCtx
	// between the ctx-override (priority 0) and the per-listener static
	// URL (priority 1) so all upstream-proxy call sites participate
	// without per-site edits. The map is keyed by listener name; a
	// resolver presence overrides the static per-listener URL for that
	// listener.
	//
	// Writers are MCP-tool goroutines (configure_tool /
	// proxy_start_tool); readers are per-connection dial-path
	// goroutines. RWMutex matches the per-listener static map.
	rotationByListenerMu sync.RWMutex
	rotationByListener   map[string]*RotationResolver

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

	// WSHoldKeepaliveEnabled toggles the USK-854 synthetic WS Ping
	// injection during intercept holds. Resolved at BuildConfig
	// construction time from ProxyConfig.WebSocket via
	// config.ResolveWSHoldKeepaliveEnabled. Default false: opt-in because
	// Ping injection is wire-observable. Bridged to
	// session.SessionOptions.WSHoldKeepaliveEnabled by
	// proxybuild.buildSessionOptions.
	WSHoldKeepaliveEnabled bool

	// WSHoldKeepaliveInterval is the cadence at which the keepalive
	// goroutine emits synthetic Ping frames while a hold is in flight.
	// Resolved at BuildConfig construction time from
	// ProxyConfig.WebSocket via config.ResolveWSHoldKeepaliveInterval.
	// Zero falls back to config.DefaultWSHoldKeepaliveInterval (5s).
	WSHoldKeepaliveInterval time.Duration

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
	// layer's compile-time default (currently 500, USK-862 bumped 100 →
	// 500); see internal/layer/http2/connstate.go
	// defaultMaxConcurrentStreams. Applied only to the inbound (client-
	// facing) Layer; the outbound (upstream / ClientRole) Layer continues
	// to honour the peer's advertised limit.
	//
	// Per-connection stream worst-case under the default fan-out:
	// MaxConcurrentStreams × MaxConnections = 500 × 128 = 64,000 streams.
	// See internal/config/limits.go for the RAM-side worst-case math.
	//
	// This is the static (boot-time) value; runtime updates from
	// proxy_start / configure flow through SetMaxConcurrentStreams and
	// EffectiveMaxConcurrentStreams. Live data-path readers MUST call
	// EffectiveMaxConcurrentStreams() — direct field reads observe only
	// the boot-time value (USK-862).
	MaxConcurrentStreams uint32

	// maxConcurrentStreamsDynamic stores the runtime-mutable value
	// installed by proxy_start / configure (USK-862). It overrides the
	// static MaxConcurrentStreams field when non-zero. atomic.Uint32 is
	// used so dial-path readers (per-connection goroutines) and the
	// MCP-tool writer (proxy_start / configure handler goroutine) do not
	// race on the value. A zero load means "fall back to
	// MaxConcurrentStreams". Next-connection semantics: in-flight H2
	// connections retain the cap captured at their stack-assembly time;
	// the new value takes effect at the next stack assembly.
	maxConcurrentStreamsDynamic atomic.Uint32

	// clientMITMHandshakes counts entries to performClientMITM (USK-813).
	// Used by e2e tests to verify that the pool fast-path short-circuits
	// before the wasted client TLS handshake when h2 is disabled at
	// runtime; production paths do not branch on this value. Read via
	// ClientMITMHandshakeCount; reset via ResetClientMITMHandshakeCount.
	clientMITMHandshakes atomic.Uint64

	// DisableClientHelloPeek is a test-only opt-out for the sniff-first
	// ClientHello peek (USK-997). When true, runTLSMITM skips
	// peekClientHelloSNIAndALPN and threads an empty ClientHelloPeek into
	// BuildConnectionStack so callers exercise the legacy fallback paths
	// (buildCacheHitPath / buildCacheMissPath / buildPoolHitFastPath).
	//
	// Production code MUST NOT set this. The flag exists solely so the
	// e2e integration tests that historically exercised the
	// speculative-then-redial path (alpn_mismatch_integration_test,
	// alpn_cache_ratchet_integration_test) can keep verifying the
	// fallback path now that sniff-first is the primary route. Matches
	// the USK-813 ClientMITMHandshakeCount precedent: production
	// observability/test-only knobs may sit on BuildConfig as long as
	// the godoc says "test-only".
	DisableClientHelloPeek bool
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
//
// USK-826: this is the process-global slot, kept for backwards compatibility
// (boot-time config-file UpstreamProxy promotion + tests that do not need
// per-listener scoping). Live MCP wiring should prefer
// SetUpstreamProxyForListener so multi-listener chains do not all share a
// single URL.
func (c *BuildConfig) SetUpstreamProxy(u *url.URL) {
	if c == nil {
		return
	}
	c.upstreamProxyDynamic.Store(u)
}

// SetUpstreamProxyForListener installs a runtime upstream-proxy override
// scoped to the named listener (USK-826). The dial path consults the
// per-listener entry first via EffectiveUpstreamProxyForCtx, falling back
// to the process-global slot only when the listener has no per-listener
// entry. Passing nil for u removes the listener's entry so the
// process-global / boot-time fallback re-emerges for that listener.
//
// This is the canonical setter for the multi-listener case: a chained
// MITM (listener A on :8080, listener B on :8090 → A) must scope the
// "send my traffic through A" decision to listener B so listener A is
// not also forced to recurse through itself. The mirror of the SOCKS5
// per-listener auth registry (internal/connector/socks5.go).
//
// An empty name is treated as DefaultListenerName so callers that have
// not yet adopted explicit naming hit the same slot as the implicit
// default listener.
func (c *BuildConfig) SetUpstreamProxyForListener(name string, u *url.URL) {
	if c == nil {
		return
	}
	if name == "" {
		name = DefaultListenerName
	}
	c.upstreamProxyPerListenerMu.Lock()
	defer c.upstreamProxyPerListenerMu.Unlock()
	if u == nil {
		// Remove the entry so the global / boot-time fallback re-emerges
		// for this listener. Distinct from "store nil" — a present-but-nil
		// entry would override the global slot with "direct".
		delete(c.upstreamProxyPerListener, name)
		return
	}
	if c.upstreamProxyPerListener == nil {
		c.upstreamProxyPerListener = make(map[string]*url.URL)
	}
	c.upstreamProxyPerListener[name] = u
}

// UpstreamProxyForListener returns the per-listener upstream proxy URL
// installed via SetUpstreamProxyForListener for the named listener
// (USK-826). Returns nil when no per-listener entry is set; callers
// that want the effective URL (with fallback to global / boot-time)
// should use EffectiveUpstreamProxyForCtx instead.
//
// An empty name is treated as DefaultListenerName.
func (c *BuildConfig) UpstreamProxyForListener(name string) *url.URL {
	if c == nil {
		return nil
	}
	if name == "" {
		name = DefaultListenerName
	}
	c.upstreamProxyPerListenerMu.RLock()
	defer c.upstreamProxyPerListenerMu.RUnlock()
	return c.upstreamProxyPerListener[name]
}

// SetRotationForListener installs (or clears) a per-listener
// RotationResolver (USK-959). When non-nil, the resolver overrides
// the per-listener static URL (SetUpstreamProxyForListener) so the
// dial path mints / consults an expanded URL per pass according to
// the resolver's policy. Passing nil clears the resolver so the
// static per-listener URL re-emerges.
//
// An empty name is treated as DefaultListenerName. Writers are
// configure_tool / proxy_start_tool goroutines; readers are
// per-connection dial-path goroutines.
func (c *BuildConfig) SetRotationForListener(name string, r *RotationResolver) {
	if c == nil {
		return
	}
	if name == "" {
		name = DefaultListenerName
	}
	c.rotationByListenerMu.Lock()
	defer c.rotationByListenerMu.Unlock()
	if r == nil {
		delete(c.rotationByListener, name)
		return
	}
	if c.rotationByListener == nil {
		c.rotationByListener = make(map[string]*RotationResolver)
	}
	c.rotationByListener[name] = r
}

// RotationForListener returns the per-listener RotationResolver
// installed via SetRotationForListener, or nil when no resolver is
// configured. An empty name is treated as DefaultListenerName.
func (c *BuildConfig) RotationForListener(name string) *RotationResolver {
	if c == nil {
		return nil
	}
	if name == "" {
		name = DefaultListenerName
	}
	c.rotationByListenerMu.RLock()
	defer c.rotationByListenerMu.RUnlock()
	return c.rotationByListener[name]
}

// ReleaseConnectionState drops any per-connection state held by
// per-listener resolvers for connID (USK-959). Called from
// ConnectionStack.Close so per_connection rotation entries do not leak
// across the client disconnect. No-op when c is nil or no resolvers
// are installed.
func (c *BuildConfig) ReleaseConnectionState(connID string) {
	if c == nil || connID == "" {
		return
	}
	c.rotationByListenerMu.RLock()
	resolvers := make([]*RotationResolver, 0, len(c.rotationByListener))
	for _, r := range c.rotationByListener {
		if r != nil {
			resolvers = append(resolvers, r)
		}
	}
	c.rotationByListenerMu.RUnlock()
	for _, r := range resolvers {
		r.ReleaseConnection(connID)
	}
}

// EffectiveUpstreamProxyForCtx returns the upstream proxy URL the live
// dial path should use for a connection whose ctx carries a listener name
// (set by FullListener via ContextWithListenerName) (USK-826).
//
// Resolution order:
//  0. Per-flow override installed via ContextWithUpstreamProxyOverride.
//     Present-but-nil is honoured as an explicit "direct dial" — the
//     resolver returns nil without consulting any lower-priority slot.
//     Used by control-plane resend / fuzz per-iteration rotation
//     (residential proxy IP switching).
//  1. Per-listener RotationResolver installed via SetRotationForListener
//     for the ctx's listener name (USK-959). The resolver mints / picks
//     an expanded URL according to its policy. A resolver error (macro
//     expansion / CRLF / parse failure) is silently swallowed in this
//     accessor — callers that need the error must use the parallel
//     EffectiveUpstreamProxyForCtxErr method. Existing legacy callers
//     using this method continue to work but observe a nil URL on
//     resolver error (effectively "direct dial" fallback). USK-959
//     migrates all dial-path callers to the Err variant so this
//     fail-open path is unreachable in production.
//  2. Per-listener static URL installed via SetUpstreamProxyForListener
//     for the ctx's listener name.
//  3. Process-global override installed via SetUpstreamProxy.
//  4. Boot-time UpstreamProxy field.
//
// Falls back to EffectiveUpstreamProxy() when the ctx does not carry a
// listener name (e.g. control-plane resend paths that do not flow through
// FullListener). This is the canonical accessor for live data-path code
// once USK-826 is wired in; callers must NOT read the UpstreamProxy field
// directly because it observes only the boot-time value.
func (c *BuildConfig) EffectiveUpstreamProxyForCtx(ctx context.Context) *url.URL {
	u, _ := c.EffectiveUpstreamProxyForCtxErr(ctx)
	return u
}

// EffectiveUpstreamProxyForCtxErr is the error-returning sibling of
// EffectiveUpstreamProxyForCtx (USK-959). Returns the resolved URL plus
// any error surfaced by a per-listener RotationResolver (macro expansion
// / CRLF guard / ParseUpstreamProxy failure). Callers MUST fail closed
// on a non-nil error — never fall back to a direct dial, which would
// silently bypass the configured upstream proxy and leak the dial to the
// open internet.
//
// Resolution order matches EffectiveUpstreamProxyForCtx; the only
// difference is the surfaced error on rotation failure.
func (c *BuildConfig) EffectiveUpstreamProxyForCtxErr(ctx context.Context) (*url.URL, error) {
	if c == nil {
		return nil, nil
	}
	if u, present := UpstreamProxyOverrideFromContext(ctx); present {
		return u, nil
	}
	if name := ListenerNameFromContext(ctx); name != "" {
		c.rotationByListenerMu.RLock()
		resolver := c.rotationByListener[name]
		c.rotationByListenerMu.RUnlock()
		if resolver != nil {
			target := DialTargetFromContext(ctx)
			return resolver.Resolve(ctx, name, target)
		}
		c.upstreamProxyPerListenerMu.RLock()
		u, ok := c.upstreamProxyPerListener[name]
		c.upstreamProxyPerListenerMu.RUnlock()
		if ok {
			return u, nil
		}
	}
	return c.EffectiveUpstreamProxy(), nil
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

// ClientMITMHandshakeCount returns the cumulative number of times the
// client-side MITM TLS handshake (performClientMITM) has been entered for
// this BuildConfig. It is a test-only observability hook (USK-813) used
// by e2e tests to verify that the pool fast-path short-circuit avoids a
// wasted handshake when h2 is disabled at runtime; production code paths
// do not branch on this value.
func (c *BuildConfig) ClientMITMHandshakeCount() uint64 {
	if c == nil {
		return 0
	}
	return c.clientMITMHandshakes.Load()
}

// ResetClientMITMHandshakeCount resets the test-only client MITM
// handshake counter to zero (USK-813). Tests use this to snapshot a
// baseline between phases of a multi-phase scenario.
func (c *BuildConfig) ResetClientMITMHandshakeCount() {
	if c == nil {
		return
	}
	c.clientMITMHandshakes.Store(0)
}

// ClientHelloPeek carries the SNI + ALPN list extracted from the client's
// first TLS ClientHello by runTLSMITM via peekClientHelloSNIAndALPN
// (USK-997). It is threaded through BuildConnectionStack so the
// sniff-first MITM path can forward the client's ALPN list verbatim to
// upstream and advertise upstream's pick back to the client.
//
// Zero-value semantics: callers that do not (or cannot) peek pass
// ClientHelloPeek{}; both fields empty steer BuildConnectionStack into
// the legacy fallback paths (cache hit / miss / pool) so the
// pre-USK-997 behaviour is preserved by construction. Stack-builder unit
// tests rely on this zero-value contract; integration tests that need
// the same effect for FullListener-driven flows set
// BuildConfig.DisableClientHelloPeek instead.
//
// Wire fidelity (CLAUDE.md MITM Principle #1, #3): the ALPN slice
// preserves the client's wire order exactly. Do not sort, dedup, or
// case-normalise — the upstream's ALPN pick depends on the offer list
// being byte-identical to what the client sent.
type ClientHelloPeek struct {
	// SNI is the host_name value from the client's server_name
	// extension, or empty when the client sent no SNI extension or the
	// peek failed. The MITM cert presentation path can take advantage
	// of an early SNI value even if the ALPN field is nil (partial
	// peek success — User-Confirmed Decision #U3).
	SNI string

	// ALPN is the offered ProtocolNameList in wire order, or nil when
	// the client sent no ALPN extension, the peek failed, or the ALPN
	// extension itself was truncated. nil means "fall back to the
	// legacy widening logic for the ALPN axis"; a non-nil slice means
	// "forward this list verbatim to upstream and advertise upstream's
	// pick back to the client".
	ALPN []string
}

// BuildConnectionStack constructs a ConnectionStack for the given CONNECT
// target and client connection, based on per-host configuration policy.
//
// Three modes are supported:
//   - raw_passthrough: client [TLS MITM → ByteChunk], upstream [TLS → ByteChunk]
//     (config-level override, ignores ALPN)
//   - sniff-first MITM (USK-997): when peeked.ALPN is non-empty, dial
//     upstream offering peeked.ALPN verbatim, then perform the client
//     MITM with NextProtos = [upstreamPick]. End-to-end single ALPN
//     holds by construction; mismatch-redial logic becomes fallback-only.
//   - legacy ALPN-routed MITM (peeked.ALPN nil / fallback): upstream dial
//     first to learn ALPN, then client MITM offering the learned ALPN,
//     with refresh-on-mismatch redial.
//
// The client-side TLS MITM handshake is performed inside this function
// because the stack builder owns the TLS layer decision.
//
// peeked carries the SNI + ALPN list captured from the client's first
// TLS ClientHello (typically by runTLSMITM via peekClientHelloSNIAndALPN).
// Passing ClientHelloPeek{} (zero value) steers the build through the
// legacy fallback paths — this is the canonical opt-out for stack-builder
// unit tests that do not exercise the new sniff path.
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
	peeked ClientHelloPeek,
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	if cfg == nil || cfg.ProxyConfig == nil {
		return nil, nil, nil, fmt.Errorf("connector: BuildConnectionStack: nil config")
	}
	// USK-959: stamp the dial target on ctx so the per-listener
	// rotation resolver (consulted inside dialUpstreamWithALPN via
	// EffectiveUpstreamProxyForCtxErr) can scope state by upstream
	// host. Idempotent — re-stamping the same key on a child ctx is
	// harmless.
	ctx = ContextWithDialTarget(ctx, target)
	if cfg.Issuer == nil {
		return nil, nil, nil, fmt.Errorf("connector: BuildConnectionStack: nil issuer")
	}

	connID := uuid.New().String()

	// Raw passthrough mode bypasses ALPN routing entirely — always ByteChunk.
	if cfg.ProxyConfig.IsRawPassthrough(target) {
		return buildRawPassthroughStack(ctx, clientConn, target, connID, cfg)
	}

	return buildALPNRoutedStack(ctx, clientConn, target, connID, cfg, peeked)
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
// effective SETTINGS_MAX_CONCURRENT_STREAMS into the client-facing
// (ServerRole) Layer's preface. Returns nil when the effective value is
// zero so the Layer keeps its compile-time default
// (defaultMaxConcurrentStreams in internal/layer/http2/connstate.go).
// Callers must guard against nil before appending.
//
// The effective value is the runtime-mutable dynamic slot when set, else
// the boot-time MaxConcurrentStreams field (USK-862). Read here at
// stack-assembly time so each new H2 stack picks up the latest operator
// override without recycling already-accepted connections.
func clientH2MaxConcurrentStreamsOption(cfg *BuildConfig) http2.Option {
	if cfg == nil {
		return nil
	}
	v := cfg.EffectiveMaxConcurrentStreams()
	if v == 0 {
		return nil
	}
	return http2.WithMaxConcurrentStreams(v)
}

// EffectiveMaxConcurrentStreams returns the wire-effective
// SETTINGS_MAX_CONCURRENT_STREAMS value. Runtime updates installed via
// SetMaxConcurrentStreams take precedence over the static
// MaxConcurrentStreams field set at boot. A zero return means "no
// override" — the H2 Layer keeps its compile-time default
// (defaultMaxConcurrentStreams in internal/layer/http2/connstate.go).
// This is the canonical accessor for live stack-assembly code (USK-862);
// callers MUST NOT read the MaxConcurrentStreams field directly because
// it observes only the boot-time value.
func (c *BuildConfig) EffectiveMaxConcurrentStreams() uint32 {
	if c == nil {
		return 0
	}
	if dyn := c.maxConcurrentStreamsDynamic.Load(); dyn != 0 {
		return dyn
	}
	return c.MaxConcurrentStreams
}

// SetMaxConcurrentStreams installs a runtime override for the HTTP/2
// SETTINGS_MAX_CONCURRENT_STREAMS advertised to clients. Subsequent stack
// assemblies (next H2 connection) read the new value via
// EffectiveMaxConcurrentStreams; in-flight H2 connections retain the cap
// captured at their assembly time (next-connection semantics — RFC 9113
// §6.5.3 reserves live mid-stream SETTINGS reissue for the wire surface,
// not the operator override surface). Passing 0 clears the override so
// subsequent reads fall back to the boot-time MaxConcurrentStreams field
// (and ultimately the Layer default). Writes are atomic with respect to
// concurrent stack-assembly reads (USK-862).
func (c *BuildConfig) SetMaxConcurrentStreams(v uint32) {
	if c == nil {
		return
	}
	c.maxConcurrentStreamsDynamic.Store(v)
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
	peeked ClientHelloPeek,
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
	// the h2 route. USK-997: when sniff-first peeked.ALPN is set, only
	// take the fast path when the client actually advertised h2 — otherwise
	// the cached Layer is unusable for this client and we'd burn a redial
	// anyway. Release the reservation back to the pool (it stays healthy
	// for the next h2-capable caller) and fall through to miss/sniff path.
	if cfg.HTTP2Pool != nil {
		poolKey := poolKeyForH2(ctx, target, cfg, hostTLS)
		if pooled, perr := cfg.HTTP2Pool.Get(poolKey); perr == nil && pooled != nil {
			if peeked.ALPN != nil && !alpnListContains(peeked.ALPN, ALPNProtocolH2) {
				// Sniff saw the client cannot speak h2 — pool hit is
				// useless. Release and fall through; the cached Layer
				// stays available for the next h2 client.
				cfg.HTTP2Pool.Put(poolKey, pooled)
				slog.Debug("connector: h2 pool entry skipped (sniff-first: client cannot speak h2)",
					"target", target, "conn_id", connID, "client_offered", peeked.ALPN,
				)
			} else {
				stack, cs, us, ferr := buildPoolHitFastPath(ctx, clientConn, target, host, connID, pooled, poolKey, cfg, peeked)
				if ferr == nil {
					return stack, cs, us, nil
				}
				return nil, nil, nil, ferr
			}
		}
	}

	// Sniff-first branch (USK-997): when the client's ALPN list is in hand,
	// forward it verbatim to upstream and advertise upstream's pick back
	// to the client. End-to-end single ALPN holds by construction; the
	// legacy mismatch-redial logic stays reachable only for the fallback
	// path (peeked.ALPN == nil).
	if peeked.ALPN != nil {
		return buildSniffFirstStack(ctx, clientConn, target, host, connID, peeked, hostTLS, cfg)
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
// the HTTP-family superset (USK-793, USK-884), then upstream dial using
// whatever the client actually negotiated. Verify upstream agrees.
//
// Why offer the HTTP-family superset even on a cache hit (USK-793, USK-884):
// the cache reflects what _previous_ clients negotiated with upstream, not
// what the current client speaks. If the proxy advertised only the cached
// "h2" and the current client offered only "http/1.1", Go's crypto/tls would
// complete the handshake with empty NegotiatedProtocol, and the client would
// speak HTTP/1.x on a stack the proxy then dispatched as HTTP/2 (USK-793).
// Symmetrically, if the cache was seeded with "http/1.1" by an h1-only
// client and a later h2-capable client connected, advertising only
// "http/1.1" pinned every subsequent client to HTTP/1.1 for the cache TTL
// window (USK-884 one-way ratchet). clientALPNOffersForUpstream now returns
// [h2, http/1.1] for any HTTP-family cached value, so the client picks a
// protocol it can actually speak; the refresh-on-mismatch block below
// rewrites the cache entry when the chosen ALPN differs from the seed.
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
	clientOffers := clientALPNOffersForUpstream(cachedALPN)
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
	// for the rationale (USK-793).
	clientOffers := clientALPNOffersForUpstream(upstreamALPN)
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

// buildSniffFirstStack handles the USK-997 sniff-first MITM path: the
// client's offered ALPN list (captured by runTLSMITM's
// peekClientHelloSNIAndALPN call) is forwarded verbatim to upstream;
// upstream's negotiated pick is then offered as a single-element ALPN
// list to the MITM client. End-to-end single ALPN holds by construction
// — no mismatch redial is needed on the happy path.
//
// Order matters:
//  1. Dial upstream with offerALPN = peeked.ALPN exactly (wire order
//     preserved; MITM Principle #1).
//  2. Build the MITM advertise from upstreamSnap.ALPN
//     (mitmAdvertiseFromUpstreamPick: single-element list, empty → nil).
//  3. Run the client MITM TLS handshake.
//  4. Defence-in-depth assert: if the client picks something other than
//     upstream's choice (should be impossible given step 2 advertises a
//     single element), Warn-log with structured fields and fall through
//     to canonicalRedialALPNOffer-based redial. RFC 7301 §3.2 violation
//     servers cannot trigger this because step 2 already narrowed to
//     [upstream pick]; the assert covers genuinely-broken clients.
//  5. ALPN cache: Set the upstream pick (single string) so later legacy
//     fallback paths benefit from the learned value.
//
// On any failure the relevant conn is closed before return.
func buildSniffFirstStack(
	ctx context.Context,
	clientConn net.Conn,
	target, host, connID string,
	peeked ClientHelloPeek,
	hostTLS *resolvedTLS,
	cfg *BuildConfig,
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	// Step 1: dial upstream with the client's offered list verbatim.
	upstreamConn, upstreamSnap, err := dialUpstreamWithALPN(ctx, target, host,
		peeked.ALPN, hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg)
	if err != nil {
		return nil, nil, nil, err
	}

	upstreamALPN := ""
	if upstreamSnap != nil {
		upstreamALPN = upstreamSnap.ALPN
	}

	// Early validate the route so we don't waste a client MITM handshake on
	// an unknown / unroutable upstream ALPN.
	if _, routeErr := alpnRoute(upstreamALPN); routeErr != nil {
		_ = upstreamConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: %s: %w", target, routeErr)
	}

	// Step 2: build the MITM advertise. Single-element list — the client
	// can only pick this one, so by construction the post-handshake
	// client ALPN equals upstream's pick.
	clientOffers := mitmAdvertiseFromUpstreamPick(upstreamALPN)

	// Step 3: client MITM TLS handshake.
	clientTLSConn, clientSnap, err := performClientMITM(ctx, clientConn, host, clientOffers, cfg)
	if err != nil {
		_ = upstreamConn.Close()
		return nil, nil, nil, err
	}

	clientALPN := ""
	if clientSnap != nil {
		clientALPN = clientSnap.ALPN
	}

	// Step 4: defense-in-depth assert. Should never fire on the happy
	// path: clientOffers has at most one element, so the client cannot
	// negotiate anything else. A mismatch indicates either an
	// upstream-empty-ALPN handshake (clientOffers=nil → client picks
	// "" which matches "" upstream) or a genuinely broken client.
	// Treat as soft-recoverable: Warn + fall through to redial logic.
	if !clientALPNMatchesUpstream(clientALPN, upstreamALPN) {
		slog.WarnContext(ctx, "connector: sniff-first ALPN mismatch (defense-in-depth)",
			"target", target,
			"conn_id", connID,
			"peeked_alpn", peeked.ALPN,
			"upstream_alpn", upstreamALPN,
			"client_alpn", clientALPN,
		)
		// Redial upstream with the client's effective pick so the inner
		// stack stays single-protocol. This mirrors buildCacheMissPath's
		// mismatch branch.
		_ = upstreamConn.Close()
		redialOffer := canonicalRedialALPNOffer(clientALPN)
		upstreamConn, upstreamSnap, err = dialUpstreamWithALPN(ctx, target, host,
			redialOffer, hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg)
		if err != nil {
			_ = clientTLSConn.Close()
			return nil, nil, nil, err
		}
		if upstreamSnap != nil {
			upstreamALPN = upstreamSnap.ALPN
		}
	}

	// Step 5: cache the learned upstream pick. Single string per Resolved
	// Decision #13 / User-Confirmed Decision #U2 — schema unchanged.
	if cfg.ALPNCache != nil {
		cacheKey := ALPNCacheKeyFromConfig(target, cfg)
		cfg.ALPNCache.Set(cacheKey, upstreamALPN)
	}

	// USK-793: source of truth for routing is the client-negotiated ALPN
	// (which here equals upstream's pick by construction or by post-redial
	// reality).
	route, routeErr := alpnRoute(clientALPN)
	if routeErr != nil {
		_ = upstreamConn.Close()
		_ = clientTLSConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: %s: %w", target, routeErr)
	}

	slog.Debug("connector: sniff-first ALPN routed",
		"target", target, "conn_id", connID,
		"peeked_alpn", peeked.ALPN,
		"client_alpn", clientALPN, "upstream_alpn", upstreamALPN,
		"route", route,
	)

	return buildStackFromRoute(ctx, clientTLSConn, upstreamConn, target, connID, route, clientSnap, upstreamSnap, hostTLS, cfg)
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
// USK-793 (legacy / fallback): the client MITM offers both [h2, http/1.1]
// so a client that cannot speak h2 (e.g. curl --http1.1) negotiates a
// non-empty protocol the proxy can dispatch on. If the client picks
// anything other than h2, the pool reservation is released (Put, not
// Evict — the cached Layer is healthy) and we fall back to a fresh
// ALPN-routed dial that re-negotiates upstream with http/1.1 to match
// the client.
//
// USK-997: when peeked.ALPN is non-empty AND contains h2 (the caller
// already gated for this), the client MITM offers only [h2] — the sniff
// confirmed the client speaks it, so the legacy widening is unnecessary
// and counter-productive (it would let a buggy client pick http/1.1
// after explicitly advertising h2 in its sniffed list).
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
	peeked ClientHelloPeek,
) (*ConnectionStack, *envelope.TLSSnapshot, *envelope.TLSSnapshot, error) {
	clientOffers := clientALPNOffersForUpstream(ALPNProtocolH2)
	// USK-997: when the client's offer list is in hand and includes h2,
	// narrow to [h2] only — the sniff already confirmed h2 is acceptable
	// to the client, no need to widen.
	if peeked.ALPN != nil && alpnListContains(peeked.ALPN, ALPNProtocolH2) {
		clientOffers = []string{ALPNProtocolH2}
	}

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

	// USK-871: mirror upstream's SETTINGS_ENABLE_CONNECT_PROTOCOL into the
	// client-facing ServerRole's advertise. The pooled upstream Layer is
	// only returned from the pool after a previous CONNECT to the same
	// target finished its WaitPeerSettings wait (success or timeout-
	// fallback) and called Put, so by the time we pool-hit here the
	// upstream's reader goroutine has had ample wall-clock time to apply
	// the peer SETTINGS asynchronously. Reading PeerSettings() directly
	// is therefore sound without a fresh wait.
	enableConnectProtocol := resolveEnableConnectProtocol(ctx, pooled, true, connID, target)

	clientH2Opts := []http2.Option{
		http2.WithScheme("https"),
		http2.WithEnvelopeContext(clientEnvCtx),
		http2.WithBodySpillDir(cfg.BodySpillDir),
		http2.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http2.WithMaxBodySize(cfg.MaxBodySize),
		http2.WithStateReleaser(cfg.PluginV2Engine),
		http2.WithEnableConnectProtocol(enableConnectProtocol),
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
	// USK-813: count entries for the test-only ClientMITMHandshakeCount
	// observability hook. Counter increments on every entry — even on
	// failure paths — so tests can verify the call path was actually
	// reached.
	if cfg != nil {
		cfg.clientMITMHandshakes.Add(1)
	}
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
		return nil, nil, fmt.Errorf("%w: %w", ErrClientTLSMITMHandshake, err)
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

	upstreamProxy, proxyErr := cfg.EffectiveUpstreamProxyForCtxErr(ctx)
	if proxyErr != nil {
		// USK-959: fail-closed on rotation resolver error. Do NOT fall
		// back to a direct dial — silent bypass = privacy regression.
		slog.WarnContext(ctx, "connector: upstream proxy rotation failed; failing closed",
			"target", target, "error", proxyErr)
		return nil, nil, fmt.Errorf("connector: upstream dial for %s: upstream proxy rotation: %w", target, proxyErr)
	}
	conn, snap, err := DialUpstreamRaw(ctx, target, DialRawOpts{
		TLSConfig:          upstreamTLSCfg,
		InsecureSkipVerify: insecureSkip,
		UTLSProfile:        cfg.EffectiveTLSFingerprint(),
		ClientCert:         clientCert,
		OfferALPN:          offerALPN,
		UpstreamProxy:      upstreamProxy,
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
	// USK-871: Construct upstream ClientRole first so we can observe the
	// peer's initial SETTINGS frame (notably SETTINGS_ENABLE_CONNECT_PROTOCOL)
	// before deciding what to advertise to the client. The prior order
	// (ServerRole-then-ClientRole) emitted ENABLE_CONNECT_PROTOCOL=1
	// unconditionally, which misled browsers into using Extended CONNECT
	// (RFC 8441) for WS on h1.1-only upstreams.
	poolKey := poolKeyForH2(ctx, target, cfg, hostTLS)

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
		return l, nil
	}

	var upstreamH2 *http2.Layer
	if cfg != nil && cfg.HTTP2Pool != nil {
		l, getErr := cfg.HTTP2Pool.GetOrDial(ctx, poolKey, dialFn)
		if getErr != nil {
			if !consumed {
				upstreamConn.Close()
			}
			clientConn.Close()
			return nil, nil, nil, fmt.Errorf("connector: h2 pool get-or-dial: %w", getErr)
		}
		upstreamH2 = l
	} else {
		l, dErr := dialFn()
		if dErr != nil {
			clientConn.Close()
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

	// USK-871: mirror upstream's SETTINGS_ENABLE_CONNECT_PROTOCOL into the
	// client-facing ServerRole's advertise. On the pool-hit branch
	// (!consumed) the pooled upstream Layer was already drained through a
	// previous caller's WaitPeerSettings (success or timeout-fallback)
	// before being returned to the pool via Put, so the reader goroutine
	// has had ample wall-clock time to apply the peer SETTINGS
	// asynchronously and we do not wait again here. On the fresh-dial
	// branch (consumed) we wait via WaitPeerSettings below.
	enableConnectProtocol := resolveEnableConnectProtocol(ctx, upstreamH2, !consumed, connID, target)

	// Client-side Layer (ServerRole = local acts as HTTP/2 server).
	clientH2Opts := []http2.Option{
		http2.WithScheme("https"),
		http2.WithEnvelopeContext(clientEnvCtx),
		http2.WithBodySpillDir(cfg.BodySpillDir),
		http2.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http2.WithMaxBodySize(cfg.MaxBodySize),
		http2.WithStateReleaser(cfg.PluginV2Engine),
		http2.WithEnableConnectProtocol(enableConnectProtocol),
	}
	if mcsOpt := clientH2MaxConcurrentStreamsOption(cfg); mcsOpt != nil {
		clientH2Opts = append(clientH2Opts, mcsOpt)
	}
	clientLayer, err := http2.New(clientConn, connID+"/client", http2.ServerRole, clientH2Opts...)
	if err != nil {
		// Upstream Layer is healthy — only the client-side handshake failed.
		// Return it to the pool if pooling is enabled so the next CONNECT to
		// the same target can reuse it; otherwise close it to free the fd.
		if cfg != nil && cfg.HTTP2Pool != nil {
			cfg.HTTP2Pool.Put(poolKey, upstreamH2)
		} else {
			upstreamH2.Close()
		}
		clientConn.Close()
		return nil, nil, nil, fmt.Errorf("connector: h2 client layer: %w", err)
	}
	stack.PushClient(clientLayer)

	stack.setUpstreamH2(upstreamH2, poolKey)
	return stack, clientSnap, upstreamSnap, nil
}

// upstreamPeerSettingsWaitTimeout bounds how long buildH2Stack will wait for
// the upstream's first SETTINGS frame before falling back to advertising
// ENABLE_CONNECT_PROTOCOL=1 (the pre-USK-871 default). One RTT is typical;
// 5s comfortably covers slow upstreams. Not exposed as a config knob —
// operators have not asked for configurability and a hard ceiling keeps
// the failure mode bounded.
const upstreamPeerSettingsWaitTimeout = 5 * time.Second

// resolveEnableConnectProtocol returns the ENABLE_CONNECT_PROTOCOL value to
// advertise on the client-facing ServerRole, mirroring the upstream peer's
// advertisement per RFC 8441 §3.
//
// Semantics:
//   - pool-hit (poolHit == true): the pooled upstream Layer was returned
//     from the pool only after a previous CONNECT finished its own
//     WaitPeerSettings (success or timeout-fallback). The reader goroutine
//     has had wall-clock time to apply the peer SETTINGS asynchronously by
//     now, so we read PeerSettings() directly without a fresh wait. There
//     is no formal happens-before between pool-insertion and peer SETTINGS
//     apply, but the previous caller's wait makes the field-read sound in
//     practice for the EnableConnectProtocol use case.
//   - pool-miss / no-pool: wait up to upstreamPeerSettingsWaitTimeout for
//     the upstream's first SETTINGS frame. On success, return whether the
//     peer advertised value 1. On context timeout or layer shutdown, log
//     a Warn and fall back to true (advertising 1 preserves USK-764's
//     prior unconditional default).
//
// USK-871 fix invariant: the returned bool is passed verbatim to
// http2.WithEnableConnectProtocol — true → advertise 1, false → omit the
// setting from the initial SETTINGS frame (per RFC 8441 §3, the default).
func resolveEnableConnectProtocol(ctx context.Context, upstream *http2.Layer, poolHit bool, connID, target string) bool {
	if upstream == nil {
		// Defensive: the caller should have already returned on dial failure.
		// Fall back to the pre-USK-871 default.
		return true
	}
	if poolHit {
		// Pool entry was inserted after preface + first peer SETTINGS, so
		// PeerSettingsReceived must be true. Read the value directly.
		peerVal := upstream.PeerSettings().EnableConnectProtocol == 1
		slog.Debug("connector: h2 ENABLE_CONNECT_PROTOCOL mirrored from upstream (pool-hit)",
			"target", target,
			"conn_id", connID,
			"peer_advertised", peerVal,
			"enable_connect_protocol_advertised", peerVal,
			"wait_outcome", "pool-hit",
		)
		return peerVal
	}

	waitCtx, cancel := context.WithTimeout(ctx, upstreamPeerSettingsWaitTimeout)
	defer cancel()
	err := upstream.WaitPeerSettings(waitCtx)
	if err == nil {
		peerVal := upstream.PeerSettings().EnableConnectProtocol == 1
		slog.Debug("connector: h2 ENABLE_CONNECT_PROTOCOL mirrored from upstream",
			"target", target,
			"conn_id", connID,
			"peer_advertised", peerVal,
			"enable_connect_protocol_advertised", peerVal,
			"wait_outcome", "received",
		)
		return peerVal
	}

	// Fail-open: advertise 1 (the pre-USK-871 default) so existing clients
	// that depend on Extended CONNECT keep working. Operator can see the
	// fallback firing via slog.Warn.
	outcome := "timeout"
	if errors.Is(err, http2.ErrShutdownBeforePeerSettings) {
		outcome = "shutdown"
	}
	slog.Warn("connector: h2 ENABLE_CONNECT_PROTOCOL upstream sniff fell back to default",
		"target", target,
		"conn_id", connID,
		"wait_outcome", outcome,
		"enable_connect_protocol_advertised", true,
		"err", err.Error(),
	)
	return true
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
		return nil, nil, nil, fmt.Errorf("%w for %s: %w", ErrClientTLSMITMHandshake, target, err)
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

	upstreamProxy, proxyErr := cfg.EffectiveUpstreamProxyForCtxErr(ctx)
	if proxyErr != nil {
		clientTLSConn.Close()
		slog.WarnContext(ctx, "connector: upstream proxy rotation failed (raw passthrough); failing closed",
			"target", target, "error", proxyErr)
		return nil, nil, nil, fmt.Errorf("connector: upstream dial for %s: upstream proxy rotation: %w", target, proxyErr)
	}
	upstreamConn, upstreamSnap, err := DialUpstreamRaw(ctx, target, DialRawOpts{
		TLSConfig:          upstreamTLSCfg,
		InsecureSkipVerify: insecureSkip,
		UTLSProfile:        cfg.EffectiveTLSFingerprint(),
		ClientCert:         clientCert,
		OfferALPN:          []string{"http/1.1"},
		UpstreamProxy:      upstreamProxy,
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
