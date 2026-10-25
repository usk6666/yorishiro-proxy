package connector

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// DefaultTransparentPeekTimeout is how long a transparent listener waits
// for the client's first bytes before treating the connection as
// server-first (owner decision U1, USK-1316).
const DefaultTransparentPeekTimeout = 1 * time.Second

// TransparentRoute is the route a transparent connection was given after
// its first-bytes peek.
type TransparentRoute string

// Transparent routes.
const (
	// TransparentRouteHTTP: the client spoke HTTP/1.x first; relayed
	// through the L7 HTTP/1 path.
	TransparentRouteHTTP TransparentRoute = "http"
	// TransparentRouteTLS: the first byte was 0x16; passthrough with the
	// ClientHello metadata recorded (no MITM).
	TransparentRouteTLS TransparentRoute = "tls"
	// TransparentRouteServerFirst: the client sent nothing before the
	// peek deadline; passthrough.
	TransparentRouteServerFirst TransparentRoute = "server_first"
	// TransparentRouteLateTLS: a server-first passthrough whose first
	// client byte, after the deadline, was 0x16.
	TransparentRouteLateTLS TransparentRoute = "late_tls"
	// TransparentRouteH2C: the client sent the HTTP/2 prior-knowledge
	// preface; passthrough (h2c L7 is a follow-up).
	TransparentRouteH2C TransparentRoute = "h2c"
	// TransparentRouteOpaque: any other client-first bytes; passthrough.
	TransparentRouteOpaque TransparentRoute = "opaque"
)

// TransparentObservation is what a transparent passthrough relay
// observed. It extends the TLS passthrough audit shape
// (PassthroughObservation) with the route, the offered ALPN list (wire
// order, verbatim) and the original destination.
type TransparentObservation struct {
	PassthroughObservation
	Route       TransparentRoute
	ALPN        []string
	OriginalDst string
}

// TransparentBlock describes a transparent connection refused before any
// upstream contact (TargetScope deny, name not bound) or whose upstream
// dial failed.
type TransparentBlock struct {
	RemoteAddr  string
	OriginalDst string
	Route       TransparentRoute
	// BlockedBy is "target_scope" for a scope refusal, empty for a dial
	// failure.
	BlockedBy string
	// FailureReason is the audit classification (e.g. "target_scope",
	// ReasonNameNotBound, "transparent_dial_failed").
	FailureReason string
	// Reason is the human-readable detail.
	Reason string
	// Name is the SNI / Host the decision looked at, if any.
	Name string
}

// TransparentObserver persists transparent audit records. Calls are
// synchronous on the connection goroutine.
type TransparentObserver interface {
	OnStart(ctx context.Context, obs TransparentObservation)
	OnComplete(ctx context.Context, obs TransparentObservation)
	OnBlocked(ctx context.Context, b TransparentBlock)
}

// TransparentHandlerConfig configures NewTransparentHandler.
type TransparentHandlerConfig struct {
	// BuildCfg supplies the upstream proxy and the HTTP/1 stack config.
	BuildCfg *BuildConfig
	// Scope is the TargetScope; nil allows all.
	Scope *TargetScope
	// LiveConns registers admitted connections (revoke on policy change).
	LiveConns *LiveConns
	// NameBinder binds SNI / Host names to the original destination when
	// a name admits a connection whose IP is not allow-listed. Nil uses a
	// cache over net.DefaultResolver.
	NameBinder *NameBindingCache
	// PeekTimeout is the first-bytes peek deadline. Zero =
	// DefaultTransparentPeekTimeout.
	PeekTimeout time.Duration
	// DialTimeout bounds the upstream dial. Zero = 30s.
	DialTimeout time.Duration
	// Observer records passthrough metadata and refusals. Nil disables.
	Observer TransparentObserver
	// OnHTTPStack runs the L7 session on the assembled [http1 → http1]
	// stack of the HTTP route; it owns the stack and must close it.
	OnHTTPStack func(ctx context.Context, stack *ConnectionStack, target string)
	// Logger; nil uses slog.Default().
	Logger *slog.Logger
}

// transparentDialTimeout is the default upstream dial timeout.
const transparentDialTimeout = 30 * time.Second

// transparentHeadTimeout bounds the pre-dial first-request-head read of
// the HTTP route when a Host must admit the connection.
const transparentHeadTimeout = forwardPeekTimeout

// Transparent audit classifications.
const (
	// TransparentFailureScope is the FailureReason of a TargetScope refusal.
	TransparentFailureScope = "target_scope"
	// TransparentFailureDial is the FailureReason of an upstream dial failure.
	TransparentFailureDial = "transparent_dial_failed"
	// transparentVia is the LiveConn.Via / audit "via" label.
	transparentVia = "transparent"
)

// transparentDenyResponse answers a refused plain-HTTP transparent
// connection (mirrors the tcp_forward gate's 403).
var transparentDenyResponse = []byte("HTTP/1.1 403 Forbidden\r\n" +
	"Server: yorishiro-proxy\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Length: 40\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"yorishiro-proxy: target blocked by scope")

// TransparentHandler routes the connections a transparent (REDIRECT)
// listener accepted (USK-1316). Per connection, in this order: own-dial
// loop check → first-bytes peek (short deadline) → route scope gate
// (original destination, SNI, first request Host; name binding) → one
// upstream dial to the original destination → the route (L7 HTTP/1
// session, or the metadata-only passthrough relay). A refused
// connection never reaches the upstream. Construct with
// NewTransparentHandler.
type TransparentHandler struct {
	cfg    TransparentHandlerConfig
	logger *slog.Logger
	binder *NameBindingCache

	// ownDials holds the local address of every upstream socket this
	// handler dialed directly and still has open (decision R4): a
	// connection accepted from one of them is the proxy's own dial
	// REDIRECTed back to it.
	ownDials sync.Map // netip.AddrPort → struct{}
}

// NewTransparentHandler returns a handler for FullListenerConfig.OnTransparent
// (use its Handle method).
func NewTransparentHandler(cfg TransparentHandlerConfig) *TransparentHandler {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.PeekTimeout <= 0 {
		cfg.PeekTimeout = DefaultTransparentPeekTimeout
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = transparentDialTimeout
	}
	binder := cfg.NameBinder
	if binder == nil {
		binder = NewNameBindingCache(nil, NameBindingConfig{})
	}
	return &TransparentHandler{cfg: cfg, logger: logger, binder: binder}
}

// transparentVerdict is a route gate's decision.
type transparentVerdict struct {
	allowed bool
	// needBinding: admitted by a name leg, not by the original
	// destination's own allow — the name must also resolve to it.
	needBinding bool
	// failure / reason classify and explain a refusal.
	failure string
	reason  string
}

func refuseScope(reason string) transparentVerdict {
	return transparentVerdict{failure: TransparentFailureScope, reason: reason}
}

// Handle is the HandlerFunc. The original destination must be on ctx
// (ContextWithOriginalDst, set by the FullListener).
func (h *TransparentHandler) Handle(ctx context.Context, pc *PeekConn) error {
	defer pc.Close()
	logger := LoggerFromContext(ctx, h.logger)
	dst, ok := OriginalDstFromContext(ctx)
	if !ok {
		logger.Warn("transparent connection without an original destination; closing")
		return nil
	}
	logger = logger.With("original_dst", dst.String(), "via", transparentVia)
	if h.looped(pc) {
		logger.Warn("transparent loop: connection from the proxy's own upstream dial rejected (exclude the proxy's traffic from the REDIRECT rule by UID / cgroup)")
		return nil
	}

	route := peekTransparentRoute(pc, h.cfg.PeekTimeout)
	logger.Debug("transparent route decided", "route", string(route))

	switch route {
	case TransparentRouteHTTP:
		return h.handleHTTP(ctx, pc, dst, logger)
	case TransparentRouteTLS:
		return h.handleTLS(ctx, pc, dst, logger)
	default:
		return h.handleOpaque(ctx, pc, dst, route, logger)
	}
}

// looped reports whether pc comes from one of this handler's own live
// upstream sockets.
func (h *TransparentHandler) looped(pc *PeekConn) bool {
	remote, ok := addrPortOf(pc.RemoteAddr())
	if !ok {
		return false
	}
	_, hit := h.ownDials.Load(remote)
	return hit
}

// scopeHasRules reports whether a scope check is needed at all.
func (h *TransparentHandler) scopeHasRules() bool {
	return h.cfg.Scope != nil && h.cfg.Scope.HasRules()
}

// dstCheck evaluates the original destination for scheme: denyOK is false
// when a deny (or the fail-closed guard) refuses it; full reports that an
// allow rule (or no allow list) admits it by itself. opaque selects the
// strict check of a route that never yields a request path.
func (h *TransparentHandler) dstCheck(scheme string, dst netip.AddrPort, opaque bool) (full, denyOK bool, reason string) {
	if !h.scopeHasRules() {
		return true, true, ""
	}
	host, port := dst.Addr().String(), int(dst.Port())
	if ok, r := h.cfg.Scope.CheckDenyOnly(scheme, host, port, ""); !ok {
		return false, false, r
	}
	full, reason = gateScopeCheck(h.cfg.Scope, scheme, host, port, opaque)
	return full, true, reason
}

// scopeOpaque is the gate of the routes that carry no name (server-first,
// opaque, h2c, late TLS): the dial leg is plaintext TCP ("http") and the
// original destination itself must be allowed.
func (h *TransparentHandler) scopeOpaque(dst netip.AddrPort) transparentVerdict {
	full, denyOK, reason := h.dstCheck("http", dst, true)
	if !denyOK || !full {
		return refuseScope(reason)
	}
	return transparentVerdict{allowed: true}
}

// scopeTLS is the TLS route's gate: the original destination as "https"
// (opaque — passthrough carries no request path) and the SNI as a name
// leg. A destination no allow rule admits needs an allowed SNI (bound by
// DNS, see needBinding).
func (h *TransparentHandler) scopeTLS(dst netip.AddrPort, sni string) transparentVerdict {
	full, denyOK, reason := h.dstCheck("https", dst, true)
	if !denyOK {
		return refuseScope(reason)
	}
	if sni != "" && h.scopeHasRules() {
		authority := net.JoinHostPort(sni, strconv.Itoa(int(dst.Port())))
		if ok, r := h.cfg.Scope.CheckAuthority("https", authority, "", dst.String()); !ok {
			return refuseScope(r)
		}
	}
	if full {
		return transparentVerdict{allowed: true}
	}
	if sni == "" {
		return refuseScope("original destination not in the allow list and no SNI to admit it")
	}
	return transparentVerdict{allowed: true, needBinding: true}
}

// scopeHTTPNames is the HTTP route's name gate for a destination no
// allow rule admits: every Host value and the absolute-form authority
// must pass as name legs (so must match an allow rule), and there must be
// at least one.
func (h *TransparentHandler) scopeHTTPNames(dst netip.AddrPort, head transparentRequestHead) transparentVerdict {
	names := head.names()
	if len(names) == 0 {
		return refuseScope("original destination not in the allow list and no Host to admit it")
	}
	for _, v := range head.hostValues {
		if ok, r := h.cfg.Scope.CheckHostHeader("http", v, head.path, dst.String()); !ok {
			return refuseScope(r)
		}
	}
	if head.absoluteAuthority != "" {
		if ok, r := h.cfg.Scope.CheckAbsoluteFormAuthority("http", head.absoluteAuthority, head.path, dst.String()); !ok {
			return refuseScope(r)
		}
	}
	return transparentVerdict{allowed: true, needBinding: true}
}

// bindNames checks that every name resolves to dst (owner amendment to
// U3). The first failure's reason is returned.
func (h *TransparentHandler) bindNames(ctx context.Context, dst netip.AddrPort, names []string) transparentVerdict {
	for _, n := range names {
		if ok, reason := h.binder.Bound(ctx, nameHost(n), dst.Addr()); !ok {
			return transparentVerdict{failure: reason, reason: "name " + n + " is not bound to the original destination by DNS"}
		}
	}
	return transparentVerdict{allowed: true}
}

// nameHost returns the host part of a name value ("host", "host:port",
// "[v6]:port").
func nameHost(v string) string {
	if h, _, err := net.SplitHostPort(v); err == nil {
		return h
	}
	return v
}

// handleTLS runs the TLS route: ClientHello peek, gate, passthrough.
func (h *TransparentHandler) handleTLS(ctx context.Context, pc *PeekConn, dst netip.AddrPort, logger *slog.Logger) error {
	hello := peekClientHelloSNIAndALPN(pc)
	v := h.scopeTLS(dst, hello.SNI)
	if v.allowed && v.needBinding {
		v = h.bindNames(ctx, dst, []string{hello.SNI})
	}
	obs := h.newObservation(pc, dst, TransparentRouteTLS)
	obs.SNI, obs.ALPN, obs.ClientJA3, obs.ClientJA4 = hello.SNI, hello.ALPN, hello.ClientJA3, hello.ClientJA4
	if !v.allowed {
		h.refuse(ctx, pc, dst, TransparentRouteTLS, v, hello.SNI, logger)
		return nil
	}
	sni := hello.SNI
	admit := func() (bool, string) {
		r := h.scopeTLS(dst, sni)
		return r.allowed, r.reason
	}
	return h.passthrough(ctx, pc, dst, obs, admit, logger)
}

// handleOpaque runs the server-first / opaque / h2c routes.
func (h *TransparentHandler) handleOpaque(ctx context.Context, pc *PeekConn, dst netip.AddrPort, route TransparentRoute, logger *slog.Logger) error {
	v := h.scopeOpaque(dst)
	if !v.allowed {
		h.refuse(ctx, pc, dst, route, v, "", logger)
		return nil
	}
	admit := func() (bool, string) {
		r := h.scopeOpaque(dst)
		return r.allowed, r.reason
	}
	return h.passthrough(ctx, pc, dst, h.newObservation(pc, dst, route), admit, logger)
}

// handleHTTP runs the plain-HTTP route: gate (reading the first request
// head first when a Host must admit the connection), one dial, then the
// L7 HTTP/1 session pinned to the original destination.
func (h *TransparentHandler) handleHTTP(ctx context.Context, pc *PeekConn, dst netip.AddrPort, logger *slog.Logger) error {
	full, denyOK, reason := h.dstCheck("http", dst, false)
	v := transparentVerdict{allowed: true}
	var head transparentRequestHead
	switch {
	case !denyOK:
		v = refuseScope(reason)
	case !full:
		head = readTransparentRequestHead(pc, transparentHeadTimeout)
		v = h.scopeHTTPNames(dst, head)
		if v.allowed {
			v = h.bindNames(ctx, dst, head.names())
		}
	}
	if !v.allowed {
		h.refuse(ctx, pc, dst, TransparentRouteHTTP, v, strings.Join(head.names(), ","), logger)
		return nil
	}
	admit := func() (bool, string) {
		full, denyOK, reason := h.dstCheck("http", dst, false)
		if !denyOK {
			return false, reason
		}
		if full {
			return true, ""
		}
		r := h.scopeHTTPNames(dst, head)
		return r.allowed, r.reason
	}
	ctx, release, ok := h.register(ctx, dst, admit, logger)
	defer release()
	if !ok {
		h.refuse(ctx, pc, dst, TransparentRouteHTTP, refuseScope("policy changed during admission"), "", logger)
		return nil
	}
	up, ok := h.dial(ctx, pc, dst, TransparentRouteHTTP, logger)
	if !ok {
		return nil
	}
	defer h.forgetDial(up)

	stack, err := BuildConnectionStackWithTarget(ctx, pc, up, TargetOverrideParams{
		Target:   dst.String(),
		Protocol: ForwardProtocolHTTP,
	}, h.cfg.BuildCfg)
	if err != nil {
		_ = up.Close()
		logger.Debug("transparent http stack build failed", "error", err)
		return nil
	}
	ctx = ContextWithTransparentScope(ctx, &TransparentScope{Dst: dst, Binder: h.binder})
	if h.cfg.OnHTTPStack == nil {
		return stack.Close()
	}
	h.cfg.OnHTTPStack(ctx, stack, dst.String())
	return nil
}

// newObservation seeds the passthrough observation of a connection.
func (h *TransparentHandler) newObservation(pc *PeekConn, dst netip.AddrPort, route TransparentRoute) TransparentObservation {
	return TransparentObservation{
		PassthroughObservation: PassthroughObservation{
			LocalAddr:  netAddrString(pc.LocalAddr()),
			RemoteAddr: netAddrString(pc.RemoteAddr()),
			TargetHost: dst.Addr().String(),
		},
		Route:       route,
		OriginalDst: dst.String(),
	}
}

// passthrough registers, dials and relays a metadata-only passthrough.
func (h *TransparentHandler) passthrough(ctx context.Context, pc *PeekConn, dst netip.AddrPort, obs TransparentObservation, admit LiveConnAdmitFunc, logger *slog.Logger) error {
	ctx, release, ok := h.register(ctx, dst, admit, logger)
	defer release()
	if !ok {
		h.refuse(ctx, pc, dst, obs.Route, refuseScope("policy changed during admission"), obs.SNI, logger)
		return nil
	}
	up, ok := h.dial(ctx, pc, dst, obs.Route, logger)
	if !ok {
		return nil
	}
	defer h.forgetDial(up)

	obs.UpstreamAddr = netAddrString(up.RemoteAddr())
	obs.UpstreamProxy = UpstreamProxyOf(up)
	if h.cfg.Observer != nil {
		h.cfg.Observer.OnStart(ctx, obs)
	}

	// Late TLS (decision R13): on the server-first route, a first client
	// byte of 0x16 — sent only after the peek deadline — is a ClientHello
	// whose metadata is recorded. The upstream→client direction is already
	// running, so the banner is never held back.
	var beforeClient func()
	late := obs
	if obs.Route == TransparentRouteServerFirst {
		beforeClient = func() {
			b, err := pc.Peek(1)
			if err != nil || len(b) == 0 || b[0] != tlsContentTypeHandshake {
				return
			}
			hello := peekClientHelloSNIAndALPN(pc)
			late.Route = TransparentRouteLateTLS
			late.SNI, late.ALPN, late.ClientJA3, late.ClientJA4 = hello.SNI, hello.ALPN, hello.ClientJA3, hello.ClientJA4
		}
	}

	var c2u, u2c atomic.Int64
	relayErr := relayTransparent(ctx, pc, up, &c2u, &u2c, beforeClient)
	if late.Route == TransparentRouteLateTLS {
		obs.Route, obs.SNI, obs.ALPN, obs.ClientJA3, obs.ClientJA4 = late.Route, late.SNI, late.ALPN, late.ClientJA3, late.ClientJA4
	}
	obs.BytesClientToUpstream = c2u.Load()
	obs.BytesUpstreamToClient = u2c.Load()
	if relayErr == nil {
		obs.Outcome = envelope.TLSHandshakeOutcomeTunneled
	} else {
		obs.Outcome = envelope.TLSHandshakeOutcomeFailed
		obs.ErrorReason = relayErr.Error()
	}
	if h.cfg.Observer != nil {
		h.cfg.Observer.OnComplete(context.WithoutCancel(ctx), obs)
	}
	logger.Debug("transparent passthrough ended",
		"route", string(obs.Route),
		"bytes_client_to_upstream", obs.BytesClientToUpstream,
		"bytes_upstream_to_client", obs.BytesUpstreamToClient,
		"error", relayErr)
	return nil
}

// register tracks the admitted connection in the live-connection
// registry so a policy change that no longer admits it closes it.
func (h *TransparentHandler) register(ctx context.Context, dst netip.AddrPort, admit LiveConnAdmitFunc, logger *slog.Logger) (context.Context, func(), bool) {
	if h.cfg.LiveConns == nil {
		return ctx, func() {}, true
	}
	rctx, release, err := h.cfg.LiveConns.Register(ctx, LiveConn{
		ConnID:   ConnIDFromContext(ctx),
		Listener: ListenerNameFromContext(ctx),
		Via:      transparentVia,
		Target:   dst.String(),
		Admit:    admit,
	})
	if err != nil {
		logger.Info("transparent target blocked by scope (policy changed during admission)", "error", err)
		release()
		return ctx, func() {}, false
	}
	return rctx, release, true
}

// dial connects to the original destination exactly once — directly, or
// through the upstream proxy with CONNECT ip:port (decision R14). On
// failure the client is reset (no synthetic response), the failure is
// recorded and ok is false. The loop registry is re-checked first: a
// looped connection may have been accepted before its originating dial
// was registered.
func (h *TransparentHandler) dial(ctx context.Context, pc *PeekConn, dst netip.AddrPort, route TransparentRoute, logger *slog.Logger) (net.Conn, bool) {
	if h.looped(pc) {
		logger.Warn("transparent loop: connection from the proxy's own upstream dial rejected (exclude the proxy's traffic from the REDIRECT rule by UID / cgroup)")
		return nil, false
	}
	target := dst.String()
	dialCtx := ContextWithDialTarget(ctx, target)
	opts := DialRawOpts{DialTimeout: h.cfg.DialTimeout}
	if h.cfg.BuildCfg != nil {
		u, err := h.cfg.BuildCfg.EffectiveUpstreamProxyForCtxErr(dialCtx)
		if err != nil {
			logger.Warn("transparent upstream proxy rotation failed; failing closed", "error", err)
			h.dialFailed(ctx, pc, dst, route, err)
			return nil, false
		}
		opts.UpstreamProxy = u
	}
	up, _, err := DialUpstreamRaw(dialCtx, target, opts)
	if err != nil {
		logger.Debug("transparent upstream dial failed", "error", err)
		h.dialFailed(ctx, pc, dst, route, err)
		return nil, false
	}
	if UpstreamProxyOf(up) == "" {
		if local, ok := addrPortOf(up.LocalAddr()); ok {
			h.ownDials.Store(local, struct{}{})
		}
	}
	return up, true
}

// forgetDial removes up from the loop registry and closes it.
func (h *TransparentHandler) forgetDial(up net.Conn) {
	if local, ok := addrPortOf(up.LocalAddr()); ok {
		h.ownDials.Delete(local)
	}
	_ = up.Close()
}

// dialFailed resets the client and records the failure.
func (h *TransparentHandler) dialFailed(ctx context.Context, pc *PeekConn, dst netip.AddrPort, route TransparentRoute, err error) {
	if tc, ok := pc.Conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	if h.cfg.Observer != nil {
		h.cfg.Observer.OnBlocked(context.WithoutCancel(ctx), TransparentBlock{
			RemoteAddr:    netAddrString(pc.RemoteAddr()),
			OriginalDst:   dst.String(),
			Route:         route,
			FailureReason: TransparentFailureDial,
			Reason:        err.Error(),
		})
	}
}

// refuse answers a refused connection — a canned 403 on the HTTP route,
// a silent close otherwise — and records it. Nothing reaches the
// upstream.
func (h *TransparentHandler) refuse(ctx context.Context, pc *PeekConn, dst netip.AddrPort, route TransparentRoute, v transparentVerdict, name string, logger *slog.Logger) {
	logger.Info("transparent target blocked by scope",
		"route", string(route), "name", name, "failure", v.failure, "reason", v.reason)
	if route == TransparentRouteHTTP {
		_ = pc.SetDeadline(time.Now().Add(tcpForwardDenyDrainTimeout))
		if _, err := pc.Write(transparentDenyResponse); err == nil {
			_ = pc.CloseWrite()
			_, _ = io.CopyN(io.Discard, pc, tcpForwardDenyDrainLimit)
		}
	}
	if h.cfg.Observer != nil {
		h.cfg.Observer.OnBlocked(context.WithoutCancel(ctx), TransparentBlock{
			RemoteAddr:    netAddrString(pc.RemoteAddr()),
			OriginalDst:   dst.String(),
			Route:         route,
			BlockedBy:     TransparentFailureScope,
			FailureReason: v.failure,
			Reason:        v.reason,
			Name:          name,
		})
	}
}

// Deny-drain bounds for a refused plain-HTTP connection: the client's
// unread request bytes are drained after the 403 so the close is a FIN,
// not a RST that would discard the 403.
const (
	tcpForwardDenyDrainTimeout = 2 * time.Second
	tcpForwardDenyDrainLimit   = 64 << 10
)

// TransparentScope is the per-connection transparent admission context
// the HTTP route carries on its ctx for the Pipeline's scope Steps
// (decision U3 amended): on a transparent connection the dial target
// (the original destination) is a deny-only leg when no allow rule
// admits it, and every request's names must then be allow-listed AND
// bound to it by DNS.
type TransparentScope struct {
	Dst    netip.AddrPort
	Binder *NameBindingCache
}

type transparentScopeKey struct{}

// ContextWithTransparentScope returns ctx carrying ts.
func ContextWithTransparentScope(ctx context.Context, ts *TransparentScope) context.Context {
	return context.WithValue(ctx, transparentScopeKey{}, ts)
}

// TransparentScopeFromContext returns the TransparentScope on ctx, or nil
// on every non-transparent connection.
func TransparentScopeFromContext(ctx context.Context) *TransparentScope {
	ts, _ := ctx.Value(transparentScopeKey{}).(*TransparentScope)
	return ts
}

// NamesBound reports whether every name value (host, host:port, [v6]:port)
// resolves to the original destination.
func (ts *TransparentScope) NamesBound(ctx context.Context, names []string) bool {
	if ts == nil || ts.Binder == nil {
		return false
	}
	for _, n := range names {
		if ok, _ := ts.Binder.Bound(ctx, nameHost(n), ts.Dst.Addr()); !ok {
			return false
		}
	}
	return len(names) > 0
}
