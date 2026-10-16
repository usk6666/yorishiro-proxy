package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// Live-connection registry (USK-1160).
//
// The CONNECT, SOCKS5 and plain-HTTP-forward gates check TargetScope once,
// at admission. Some routes are never checked again — the TLS passthrough
// relay, the bytechunk (raw TCP) route, the server→client half of a MITM'd
// WebSocket / SSE / gRPC stream, idle upstream connections, the h2 pre-warm
// redial — so without this registry a policy change that denies a host
// would leave every connection already open to it running.
//
// Every connection a gate admits is registered with the predicate the gate
// used (the exact CheckTarget call, keyed on the CONNECT / SOCKS5 authority
// or the forward target — never on SNI). Reconcile re-evaluates every entry
// and cancels the context of each one that would not be admitted now; the
// handlers pass that context to the relay / stack / session, whose existing
// ctx watchers close both legs. The invariant is:
//
//	a live connection survives a policy change iff an identical new
//	connection would be admitted now.
//
// A path_prefix-only deny therefore never cuts a connection (the gates check
// path ""); per-request HTTPScopeStep covers those. TargetScope stays a pure
// engine: the writers of the scope (the policy reloader and the MCP
// security tool) call Reconcile after a successful write.

// ErrTargetScopeRevoked is the context cancel cause of a live connection
// that a policy change no longer admits. Handlers and relays can test for
// it with errors.Is(context.Cause(ctx), ErrTargetScopeRevoked).
var ErrTargetScopeRevoked = errors.New("target scope no longer admits this connection")

// LiveConnAdmitFunc re-runs the admission scope check of the gate that
// admitted a connection. It must be the same check the gate ran (same
// scheme literal, host, port and path ""), so a connection is kept iff an
// identical new one would be admitted.
type LiveConnAdmitFunc func() (allowed bool, reason string)

// LiveConn describes one connection admitted by a CONNECT / SOCKS5 /
// plain-HTTP-forward gate. ConnID, Listener, Via and Target are only used
// for logging.
type LiveConn struct {
	ConnID   string
	Listener string
	// Via names the gate: "connect", "socks5" or "http1-forward".
	Via string
	// Target is the authority the gate admitted (host:port).
	Target string
	// Admit is the gate's admission check. A nil Admit is never cut.
	Admit LiveConnAdmitFunc
}

type liveConnEntry struct {
	info   LiveConn
	cancel context.CancelCauseFunc
	// cut is set (under LiveConns.mu) once Reconcile cancelled the entry,
	// so a later Reconcile does not count or log it again before the
	// handler unwinds and releases it.
	cut bool
}

// LiveConns is the process-wide registry of admitted live connections. The
// zero value is not usable; construct with NewLiveConns. A nil *LiveConns
// is valid and inert (Register tracks nothing, Reconcile closes nothing).
type LiveConns struct {
	logger *slog.Logger

	mu     sync.Mutex
	nextID uint64
	conns  map[uint64]*liveConnEntry
}

// NewLiveConns returns an empty registry. A nil logger uses slog.Default().
func NewLiveConns(logger *slog.Logger) *LiveConns {
	if logger == nil {
		logger = slog.Default()
	}
	return &LiveConns{logger: logger, conns: make(map[uint64]*liveConnEntry)}
}

// Register tracks an admitted connection. It returns a context derived
// from ctx that Reconcile cancels (cause wrapping ErrTargetScopeRevoked)
// once c.Admit fails, and a release function the handler must call when
// the connection ends (defer it). release is idempotent.
//
// The entry is inserted first and c.Admit is then re-run once, so a policy
// change that lands between the gate's admission check and Register is
// never missed: either Reconcile sees the entry, or this re-check sees the
// new rules. When the re-check fails, nothing stays registered and an
// error wrapping ErrTargetScopeRevoked is returned; the caller must reject
// the connection.
//
// On a nil registry Register returns ctx unchanged and a no-op release.
func (r *LiveConns) Register(ctx context.Context, c LiveConn) (context.Context, func(), error) {
	if r == nil {
		return ctx, func() {}, nil
	}
	cctx, cancel := context.WithCancelCause(ctx)
	e := &liveConnEntry{info: c, cancel: cancel}

	r.mu.Lock()
	r.nextID++
	id := r.nextID
	r.conns[id] = e
	r.mu.Unlock()

	var once sync.Once
	release := func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.conns, id)
			r.mu.Unlock()
			cancel(nil)
		})
	}

	if c.Admit != nil {
		if allowed, reason := c.Admit(); !allowed {
			err := fmt.Errorf("%w: %s", ErrTargetScopeRevoked, reason)
			cancel(err)
			release()
			return cctx, release, err
		}
	}
	return cctx, release, nil
}

// Reconcile re-evaluates every live connection against the current scope
// and cancels each one that would not be admitted now. trigger labels the
// policy change in the log ("SIGHUP", "security_tool", ...). It returns the
// number of connections closed by this call; a connection already closed
// by an earlier Reconcile is not counted again. Widening or unchanged
// rules close nothing, so calling it after every write is safe.
func (r *LiveConns) Reconcile(trigger string) int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	snapshot := make([]*liveConnEntry, 0, len(r.conns))
	for _, e := range r.conns {
		if !e.cut && e.info.Admit != nil {
			snapshot = append(snapshot, e)
		}
	}
	r.mu.Unlock()

	// The predicates take the TargetScope read lock; evaluate them outside
	// r.mu so a slow scope read never stalls Register / release.
	closed := 0
	for _, e := range snapshot {
		allowed, reason := e.info.Admit()
		if allowed {
			continue
		}
		r.mu.Lock()
		already := e.cut
		e.cut = true
		r.mu.Unlock()
		if already {
			continue // a concurrent Reconcile got there first
		}
		e.cancel(fmt.Errorf("%w: %s", ErrTargetScopeRevoked, reason))
		closed++
		r.logger.Info("live connection closed: target no longer in scope",
			"conn_id", e.info.ConnID,
			"listener", e.info.Listener,
			"via", e.info.Via,
			"target", e.info.Target,
			"reason", reason,
			"trigger", trigger,
		)
	}
	return closed
}

// Len returns the number of registered live connections.
func (r *LiveConns) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

// trackAdmitted registers a connection a gate just admitted. ok=false means
// a policy change landed between the gate's check and the registration and
// the connection must be rejected (an Info line was logged). On ok=true the
// caller must use the returned ctx for everything that follows and defer
// release.
func trackAdmitted(ctx context.Context, reg *LiveConns, via, target string, admit LiveConnAdmitFunc, logger *slog.Logger) (context.Context, func(), bool) {
	tctx, release, err := reg.Register(ctx, LiveConn{
		ConnID:   ConnIDFromContext(ctx),
		Listener: ListenerNameFromContext(ctx),
		Via:      via,
		Target:   target,
		Admit:    admit,
	})
	if err != nil {
		logger.Info("target blocked by scope (policy changed during admission)",
			"via", via, "error", err)
		return tctx, release, false
	}
	return tctx, release, true
}
