package connector

import (
	"context"
	"log/slog"
	"time"
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

// TransparentHandler routes the connections a transparent (REDIRECT)
// listener accepted. Construct with NewTransparentHandler.
type TransparentHandler struct {
	cfg TransparentHandlerConfig
}

// NewTransparentHandler returns a handler for FullListenerConfig.OnTransparent.
func NewTransparentHandler(cfg TransparentHandlerConfig) *TransparentHandler {
	return &TransparentHandler{cfg: cfg}
}

// Handle is the HandlerFunc. The original destination must be on ctx
// (ContextWithOriginalDst, set by the FullListener).
func (h *TransparentHandler) Handle(ctx context.Context, pc *PeekConn) error {
	_ = ctx
	return pc.Close()
}
