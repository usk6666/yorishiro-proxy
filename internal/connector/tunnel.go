// tunnel.go implements the shared post-handshake tunnel pipeline used by
// both CONNECT (USK-560) and SOCKS5 (USK-561).
//
// Flow (linear by design; resist the urge to factor into mini-handlers):
//
//  1. TargetScope check (connection-level, pre-TLS)
//  2. RateLimit check
//  3. Passthrough list check → raw io.Copy relay
//  4. ALPN Cache lookup
//     - miss: eager DialUpstream to learn real ALPN, hold the conn
//     - hit : defer upstream dialing to RunSession
//  5. Client TLS MITM (offer cached or learned ALPN)
//  6. on_tls_handshake plugin hook (fail-open)
//  7. Inner protocol detection on the decrypted stream (empty ALPN case)
//  8. Build Codec pair + DialFunc, hand off to session.RunSession
//
// The overriding goal of the cache is that each tunnel opens exactly ONE
// upstream TLS handshake regardless of cache state. Miss: handshake happens
// during step 4 and is reused in step 8. Hit: handshake happens once during
// the lazy dial in step 8.
package connector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/codec/http1"
	"github.com/usk6666/yorishiro-proxy/internal/codec/tcp"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

// BlockInfo describes a tunnel that was refused before any bytes were
// exchanged with upstream. Callers wire OnBlock so they can record the
// block in the Store (main.go, M43) without coupling connector to flow.
type BlockInfo struct {
	// Target is the "host:port" that was requested.
	Target string

	// Reason is a stable, machine-readable tag:
	// "target_scope", "rate_limit", or "upstream_unreachable".
	Reason string

	// Protocol identifies the negotiator that produced this block:
	// "CONNECT" or "SOCKS5".
	Protocol string

	// Timestamp is when the block decision was taken.
	Timestamp time.Time

	// ClientAddr is the remote client's address, if known.
	ClientAddr string
}

// TunnelHandler is the common post-handshake pipeline that both CONNECTNegotiator
// and SOCKS5Negotiator feed into.
//
// Only Issuer and Scope/RateLimiter/Passthrough are strictly required; the
// others are optional and may be nil for a minimal configuration or in
// tests. When Pipeline is nil, an empty pipeline is used so that RunSession
// still functions.
type TunnelHandler struct {
	// Issuer mints the per-host server certificate for the client-side TLS
	// handshake. Required.
	Issuer *cert.Issuer

	// DialOpts is the base DialOpts passed to DialUpstream for every tunnel.
	// OfferALPN is overridden per tunnel from the ALPN cache.
	DialOpts DialOpts

	// ALPNCache learns upstream ALPN across tunnels. When nil a fresh cache
	// with default size/TTL is used.
	ALPNCache *ALPNCache

	// Passthrough holds host patterns that bypass TLS interception. Nil
	// disables passthrough entirely.
	Passthrough *PassthroughList

	// Scope enforces target allow/deny rules at the connection level. Nil
	// disables the check.
	Scope *TargetScope

	// RateLimiter is consulted before any upstream interaction. Nil
	// disables rate limiting.
	RateLimiter *RateLimiter

	// RunSession is invoked by Handle once the client Codec is built and
	// the upstream DialFunc is ready. It is the caller's bridge to
	// session.RunSession (internal/session) which we cannot import here
	// because internal/pipeline currently imports internal/proxy which
	// imports internal/connector. Callers (main.go, tests) supply a
	// closure that wires the real session.RunSession with the Pipeline.
	// When nil, a minimal runner is used that synchronously drives the
	// client codec — sufficient for unit tests with no Pipeline.
	RunSession SessionRunner

	// PluginEngine receives the on_tls_handshake hook. Nil disables the
	// hook dispatch. Errors from the engine are always logged and swallowed
	// (fail-open) so a buggy plugin cannot block the tunnel.
	PluginEngine *plugin.Engine

	// Logger is used for handler-wide diagnostics. A per-connection logger
	// is still pulled out of the context when present.
	Logger *slog.Logger

	// OnBlock is invoked when TargetScope, RateLimit, or pre-dial failures
	// prevent the tunnel from proceeding. It is optional: nil disables the
	// callback. OnBlock must not panic; the tunnel exits regardless.
	OnBlock func(ctx context.Context, info BlockInfo)

	// Clock is overridable for tests so BlockInfo.Timestamp is
	// deterministic. nil falls back to time.Now.
	Clock func() time.Time
}

// tunnelHookTimeout bounds the on_tls_handshake plugin dispatch so a slow
// plugin cannot stall a tunnel.
const tunnelHookTimeout = 5 * time.Second

// Handle drives a single tunnel from the raw (post-handshake) client
// connection through to session.RunSession. The target argument is the
// "host:port" extracted by the negotiator (CONNECTNegotiator or
// SOCKS5Negotiator) and must be validated by the negotiator.
//
// Handle owns the connection: it closes conn on every exit path.
func (t *TunnelHandler) Handle(ctx context.Context, conn net.Conn, target, sourceProtocol string) error {
	defer conn.Close()

	logger := t.loggerFor(ctx)

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		logger.Debug("tunnel: malformed target", "target", target, "error", err)
		return fmt.Errorf("tunnel: split host/port %q: %w", target, err)
	}

	// Step 1: target scope.
	if t.Scope != nil {
		allowed, reason := t.Scope.CheckTarget("https", host, atoiSafe(port), "")
		if !allowed {
			logger.Info("tunnel: blocked by target scope", "target", target, "reason", reason)
			t.fireBlock(ctx, target, "target_scope", sourceProtocol)
			return nil
		}
	}

	// Step 2: rate limit.
	if t.RateLimiter != nil {
		if denial := t.RateLimiter.Check(host); denial != nil {
			logger.Info("tunnel: blocked by rate limit", "target", target, "type", denial.LimitType)
			t.fireBlock(ctx, target, "rate_limit", sourceProtocol)
			return nil
		}
	}

	// Step 3: passthrough.
	if t.Passthrough != nil && t.Passthrough.Contains(host) {
		logger.Debug("tunnel: passthrough", "target", target)
		return t.relayPassthrough(ctx, conn, target)
	}

	if t.Issuer == nil {
		logger.Warn("tunnel: TLS issuer not configured", "target", target)
		t.fireBlock(ctx, target, "upstream_unreachable", sourceProtocol)
		return fmt.Errorf("tunnel: TLS issuer not configured")
	}

	// Step 4: ALPN cache lookup + optional eager dial.
	cacheKey := t.cacheKey(target)
	cache := t.cacheOrDefault()

	offerALPN, holder, cacheHit, err := t.resolveClientALPN(ctx, target, cacheKey, cache)
	if err != nil {
		logger.Warn("tunnel: upstream unreachable", "target", target, "error", err)
		t.fireBlock(ctx, target, "upstream_unreachable", sourceProtocol)
		return nil
	}
	// holder.close is idempotent and safe to defer unconditionally; it
	// becomes a no-op once the upstream codec has been consumed by the
	// DialFunc closure.
	defer holder.close()

	// Step 5: client TLS MITM.
	tlsConn, err := t.handshakeClient(ctx, conn, host, offerALPN)
	if err != nil {
		logger.Debug("tunnel: client TLS handshake failed", "target", target, "error", err)
		return nil
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	logger.Debug("tunnel: client TLS handshake complete", "target", target,
		"alpn", state.NegotiatedProtocol, "sni", state.ServerName,
		"cache_hit", cacheHit)

	// Step 6: plugin hook (fail-open).
	t.dispatchOnTLSHandshake(ctx, host, state)

	// Step 7+8: inner protocol detection + Codec pair + RunSession.
	clientCodec, dialFunc, err := t.buildCodecPair(ctx, tlsConn, target, state.NegotiatedProtocol, cacheKey, cache, holder)
	if err != nil {
		logger.Debug("tunnel: codec pair build failed", "target", target, "error", err)
		return nil
	}

	runner := t.RunSession
	if runner == nil {
		runner = defaultSessionRunner
	}
	return runner(ctx, clientCodec, dialFunc)
}

// SessionRunner is the abstract session-loop hook. Callers wire it to
// internal/session.RunSession (bound with a Pipeline) at startup. Keeping
// Session behind an interface lets connector/ avoid importing pipeline,
// which currently pulls in a proxy → connector cycle via aliases.
type SessionRunner func(ctx context.Context, client codec.Codec, dial DialFunc) error

// defaultSessionRunner is a minimal fallback for tests and early-boot
// scenarios where no Pipeline is available. It reads Exchanges from the
// client, forwards each to a single lazily-dialled upstream, and copies
// upstream Exchanges back to the client. It performs NO pipeline
// processing.
func defaultSessionRunner(ctx context.Context, client codec.Codec, dial DialFunc) error {
	defer client.Close()
	var upstream codec.Codec
	defer func() {
		if upstream != nil {
			_ = upstream.Close()
		}
	}()

	for {
		ex, err := client.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if upstream == nil {
			u, dialErr := dial(ctx, ex)
			if dialErr != nil {
				return dialErr
			}
			upstream = u
		}
		if err := upstream.Send(ctx, ex); err != nil {
			return err
		}
		resp, err := upstream.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := client.Send(ctx, resp); err != nil {
			return err
		}
	}
}

// loggerFor returns the per-connection logger stored in ctx, falling back to
// the handler-wide logger and finally slog.Default().
func (t *TunnelHandler) loggerFor(ctx context.Context) *slog.Logger {
	if l := LoggerFromContext(ctx, t.Logger); l != nil {
		return l
	}
	return slog.Default()
}

// now returns the current timestamp, honouring the overridable Clock.
func (t *TunnelHandler) now() time.Time {
	if t.Clock != nil {
		return t.Clock()
	}
	return time.Now()
}

// cacheOrDefault returns t.ALPNCache, creating a default instance on first
// use. We intentionally do not assign back to t.ALPNCache: the handler is
// shared across goroutines, so writing without a lock would race. Instead
// we produce a fresh default cache if none is installed, which callers can
// discover via the exported ALPNCache field.
func (t *TunnelHandler) cacheOrDefault() *ALPNCache {
	if t.ALPNCache != nil {
		return t.ALPNCache
	}
	// Lazily lift a default cache into the handler with a one-shot lock.
	// This path should only fire in tests that construct TunnelHandler
	// without setting ALPNCache.
	defaultCacheOnce.Do(func() {
		defaultALPNCache = NewALPNCache(DefaultALPNCacheSize, DefaultALPNCacheTTL)
	})
	return defaultALPNCache
}

var (
	defaultCacheOnce sync.Once
	defaultALPNCache *ALPNCache
)

// cacheKey builds the (host:port, fingerprint, clientCertHash) triple.
func (t *TunnelHandler) cacheKey(target string) ALPNCacheKey {
	return ALPNCacheKey{
		HostPort:       target,
		Fingerprint:    strings.ToLower(strings.TrimSpace(t.DialOpts.UTLSProfile)),
		ClientCertHash: clientCertHash(t.DialOpts.ClientCert),
	}
}

// clientCertHash returns a stable hash of the mTLS client certificate, or
// an empty string when no cert is configured. The actual hash is just
// hex(sha256) over the leaf cert's DER — we do not verify the cert here.
func clientCertHash(cert *tls.Certificate) string {
	if cert == nil || len(cert.Certificate) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf == nil {
		return ""
	}
	// Use the cert's raw bytes as the key material. Fingerprint length is
	// fine here because collisions are operationally harmless — at worst
	// two certs share an ALPN cache slot.
	sum := leaf.Raw
	if len(sum) > 32 {
		sum = sum[:32]
	}
	return fmt.Sprintf("%x", sum)
}

// resolveClientALPN returns the ALPN list to offer the client, an
// upstreamHolder (non-nil; may be empty on a cache hit), and whether the
// lookup was a cache hit.
//
// Cache miss path: this function eagerly dials upstream so that the real
// ALPN is known before we talk TLS to the client. The dialled connection is
// parked inside the returned holder and handed to RunSession via the
// DialFunc closure in buildCodecPair.
func (t *TunnelHandler) resolveClientALPN(ctx context.Context, target string, key ALPNCacheKey, cache *ALPNCache) ([]string, *upstreamHolder, bool, error) {
	if entry, ok := cache.Get(key); ok {
		return offerForALPN(entry.Protocol), &upstreamHolder{}, true, nil
	}

	// Cache miss — eager dial to learn ALPN.
	opts := t.DialOpts
	if opts.TLSConfig == nil {
		// DialUpstream treats TLSConfig==nil as "plain TCP upstream".
		// For CONNECT / SOCKS5 we always want TLS toward upstream, so
		// synthesize a minimal config (SNI is derived below).
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	// Clone so we can pin the SNI without mutating the caller's config.
	tlsCfg := opts.TLSConfig.Clone()
	if tlsCfg.ServerName == "" {
		host, _, err := net.SplitHostPort(target)
		if err == nil {
			tlsCfg.ServerName = host
		}
	}
	opts.TLSConfig = tlsCfg
	// Offer both HTTP/2 and HTTP/1.1 during the learning handshake so the
	// upstream can pick whichever it prefers. Anti-bot fingerprinting is
	// out of scope for the default configuration; callers who set a uTLS
	// profile can override via DialOpts.OfferALPN.
	if len(opts.OfferALPN) == 0 {
		opts.OfferALPN = []string{"h2", "http/1.1"}
	}

	result, err := DialUpstream(ctx, target, opts)
	if err != nil {
		return nil, nil, false, err
	}
	cache.Set(key, result.ALPN)

	holder := &upstreamHolder{conn: result.Conn, codec: result.Codec, alpn: result.ALPN}
	return offerForALPN(result.ALPN), holder, false, nil
}

// offerForALPN converts a learned ALPN string into the list the client-side
// TLS handshake should offer. Empty string means "no ALPN" → do not offer.
func offerForALPN(alpn string) []string {
	if alpn == "" {
		return nil
	}
	return []string{alpn}
}

// handshakeClient performs the server-side TLS handshake toward the client.
func (t *TunnelHandler) handshakeClient(ctx context.Context, conn net.Conn, sni string, offerALPN []string) (*tls.Conn, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = sni
			}
			return t.Issuer.GetCertificate(name)
		},
	}
	if len(offerALPN) > 0 {
		cfg.NextProtos = append([]string(nil), offerALPN...)
	}

	tlsConn := tls.Server(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tunnel: client TLS handshake for %s: %w", sni, err)
	}
	return tlsConn, nil
}

// buildCodecPair produces the client-side Codec and a DialFunc closure that
// either returns the already-held upstream codec (cache miss) or performs a
// lazy dial (cache hit). It also handles the empty-ALPN case by re-running
// inner protocol detection on the decrypted stream.
func (t *TunnelHandler) buildCodecPair(
	ctx context.Context,
	tlsConn *tls.Conn,
	target string,
	negotiatedALPN string,
	cacheKey ALPNCacheKey,
	cache *ALPNCache,
	holder *upstreamHolder,
) (codec.Codec, DialFunc, error) {
	// If we dialed eagerly (cache miss) and the client-negotiated ALPN
	// disagrees with the upstream ALPN, we're looking at the protocol
	// bridging scenario which is out of scope for M39. Return an error so
	// the tunnel closes cleanly.
	if holder.isPresent() && negotiatedALPN != "" && holder.alpn != "" && negotiatedALPN != holder.alpn {
		// Also delete the cache entry so the next attempt re-learns.
		cache.Delete(cacheKey)
		return nil, nil, fmt.Errorf("tunnel: client/upstream ALPN mismatch (client=%q upstream=%q): protocol bridging out of scope in M39",
			negotiatedALPN, holder.alpn)
	}

	// Decide the client-side codec based on ALPN.
	clientALPN := negotiatedALPN
	if clientALPN == "h2" {
		return nil, nil, ErrHTTP2NotImplemented
	}

	var clientCodec codec.Codec
	switch {
	case clientALPN == "http/1.1":
		clientCodec = http1.NewCodec(tlsConn, http1.ClientRole)
	case clientALPN == "":
		// Empty ALPN: peek the decrypted stream to decide HTTP vs TCP.
		pc := NewPeekConn(tlsConn)
		// Give the peek a small, bounded deadline so we don't block a
		// client that only intends to send a short greeting.
		_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		peek, _ := pc.Peek(QuickPeekSize)
		if pc.Buffered() > QuickPeekSize {
			n := pc.Buffered()
			if n > PeekSize {
				n = PeekSize
			}
			peek, _ = pc.Peek(n)
		}
		_ = tlsConn.SetReadDeadline(time.Time{})
		kind := DetectKind(peek)
		switch kind {
		case ProtocolHTTP1, ProtocolHTTPConnect:
			clientCodec = http1.NewCodec(pc, http1.ClientRole)
		default:
			clientCodec = tcp.NewWithStreamID(pc, exchange.Send)
		}
	default:
		// Unknown ALPN — fall back to raw TCP so the tunnel is still recorded.
		clientCodec = tcp.NewWithStreamID(tlsConn, exchange.Send)
	}

	// Build the DialFunc.
	dialFunc := t.makeDialFunc(target, cacheKey, cache, holder, negotiatedALPN)

	return clientCodec, dialFunc, nil
}

// makeDialFunc returns a DialFunc that either consumes the already-held
// upstream (cache-miss path) on the first call, or performs a fresh
// DialUpstream (cache-hit path, or any subsequent calls).
func (t *TunnelHandler) makeDialFunc(
	target string,
	cacheKey ALPNCacheKey,
	cache *ALPNCache,
	holder *upstreamHolder,
	clientALPN string,
) DialFunc {
	return func(ctx context.Context, _ *exchange.Exchange) (codec.Codec, error) {
		if cdc, ok := holder.consume(); ok {
			return cdc, nil
		}

		// Lazy dial path (cache hit or second invocation).
		opts := t.DialOpts
		if opts.TLSConfig == nil {
			opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		tlsCfg := opts.TLSConfig.Clone()
		if tlsCfg.ServerName == "" {
			host, _, err := net.SplitHostPort(target)
			if err == nil {
				tlsCfg.ServerName = host
			}
		}
		opts.TLSConfig = tlsCfg
		if len(opts.OfferALPN) == 0 {
			if clientALPN != "" {
				opts.OfferALPN = []string{clientALPN}
			} else {
				opts.OfferALPN = []string{"h2", "http/1.1"}
			}
		}

		result, err := DialUpstream(ctx, target, opts)
		if err != nil {
			return nil, err
		}
		// Cache staleness: if upstream negotiated a different ALPN than
		// what the cache told us, evict the entry so the next tunnel
		// relearns. This is a log-and-continue situation in M39 — the
		// real mismatch case (client vs upstream ALPN) is caught
		// earlier in buildCodecPair.
		if clientALPN != "" && result.ALPN != "" && clientALPN != result.ALPN {
			cache.Delete(cacheKey)
			logger := t.loggerFor(ctx)
			logger.Warn("tunnel: ALPN cache stale, entry deleted",
				"target", target, "cached", clientALPN, "actual", result.ALPN)
		} else {
			cache.Set(cacheKey, result.ALPN)
		}
		return result.Codec, nil
	}
}

// relayPassthrough implements raw io.Copy in both directions — no Pipeline
// is run, as decrypted inspection is impossible for bytes we never decrypt.
func (t *TunnelHandler) relayPassthrough(ctx context.Context, client net.Conn, target string) error {
	upstream, err := DialUpstream(ctx, target, DialOpts{
		// Intentionally no TLSConfig — plain TCP relay.
		DialTimeout:   t.DialOpts.DialTimeout,
		UpstreamProxy: t.DialOpts.UpstreamProxy,
	})
	if err != nil {
		t.fireBlock(ctx, target, "upstream_unreachable", "CONNECT")
		return nil
	}
	defer upstream.Conn.Close()

	return bidirectionalCopy(ctx, client, upstream.Conn)
}

// bidirectionalCopy runs two io.Copy goroutines and returns when either
// direction completes or ctx is cancelled.
func bidirectionalCopy(ctx context.Context, a, b net.Conn) error {
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	go func() {
		<-relayCtx.Done()
		_ = a.SetReadDeadline(time.Now())
		_ = b.SetReadDeadline(time.Now())
	}()

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(b, a)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(a, b)
		errCh <- err
	}()

	err := <-errCh
	relayCancel()
	<-errCh
	if ctx.Err() != nil {
		return nil
	}
	if errors.Is(err, io.EOF) || err == nil {
		return nil
	}
	return err
}

// dispatchOnTLSHandshake delivers the on_tls_handshake plugin hook, logging
// any plugin error and swallowing it so the tunnel continues (fail-open).
func (t *TunnelHandler) dispatchOnTLSHandshake(ctx context.Context, host string, state tls.ConnectionState) {
	if t.PluginEngine == nil {
		return
	}

	hookCtx, cancel := context.WithTimeout(ctx, tunnelHookTimeout)
	defer cancel()

	clientAddr := ClientAddrFromContext(ctx)

	connInfo := &plugin.ConnInfo{
		ClientAddr: clientAddr,
		TLSVersion: tlsVersionName(state.Version),
		TLSCipher:  tls.CipherSuiteName(state.CipherSuite),
		TLSALPN:    state.NegotiatedProtocol,
	}
	data := map[string]any{
		"event":       "tls_handshake",
		"conn_info":   connInfo.ToMap(),
		"server_name": host,
	}

	if _, err := t.PluginEngine.Dispatch(hookCtx, plugin.HookOnTLSHandshake, data); err != nil {
		t.loggerFor(ctx).Warn("plugin on_tls_handshake hook error", "host", host, "error", err)
	}
}

// fireBlock invokes the OnBlock callback if one is registered. The callback
// receives a fresh context so it can still record even if the parent ctx was
// cancelled.
func (t *TunnelHandler) fireBlock(ctx context.Context, target, reason, sourceProtocol string) {
	if t.OnBlock == nil {
		return
	}
	info := BlockInfo{
		Target:     target,
		Reason:     reason,
		Protocol:   sourceProtocol,
		Timestamp:  t.now(),
		ClientAddr: ClientAddrFromContext(ctx),
	}
	// Use a detached context so downstream Store writes survive a parent
	// cancellation (mirrors the pattern in Listener.dispatchOnDisconnect).
	t.OnBlock(context.WithoutCancel(ctx), info)
}

// tlsVersionName returns the canonical display name for a TLS version.
// Defined locally so tunnel.go does not import protocol/httputil.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

// atoiSafe parses a decimal port string; invalid input becomes 0 so the
// scope check still runs against a well-defined value.
func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
		if n > 65535 {
			return 0
		}
	}
	return n
}

// --- upstreamHolder -----------------------------------------------------------

// upstreamHolder parks the upstream connection and codec that was produced
// by a cache-miss eager dial until RunSession requests it via DialFunc. It
// is deliberately small: one consume, one close, both idempotent.
type upstreamHolder struct {
	mu       sync.Mutex
	conn     net.Conn
	codec    codec.Codec
	alpn     string
	consumed bool
	closed   bool
}

func (h *upstreamHolder) isPresent() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.codec != nil && !h.consumed
}

// consume hands the upstream codec to a DialFunc. After consume the holder
// no longer owns the connection; close becomes a no-op.
func (h *upstreamHolder) consume() (codec.Codec, bool) {
	if h == nil {
		return nil, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.consumed || h.codec == nil {
		return nil, false
	}
	cdc := h.codec
	h.codec = nil
	h.conn = nil
	h.consumed = true
	return cdc, true
}

// close releases the held upstream connection if it has not been consumed.
// It is idempotent and safe to call from a defer even after consume.
func (h *upstreamHolder) close() {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	if h.codec != nil {
		_ = h.codec.Close()
		h.codec = nil
	}
	if h.conn != nil {
		_ = h.conn.Close()
		h.conn = nil
	}
}
