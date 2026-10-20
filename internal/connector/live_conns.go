package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
)

// Live-connection registry (USK-1160).
//
// The CONNECT, SOCKS5, plain-HTTP-forward and TCP forward (tcp_forwards,
// in internal/proxybuild, USK-1161) gates check TargetScope once, at
// admission. Some routes are never checked again — the TLS passthrough
// relay, the bytechunk (raw TCP) route, the server→client half of a MITM'd
// WebSocket / SSE / gRPC stream, idle upstream connections, the h2 pre-warm
// redial — so without this registry a policy change that denies a host
// would leave every connection already open to it running.
//
// Every connection a gate admits is registered with the predicate the gate
// used (the exact CheckTarget call, keyed on the CONNECT / SOCKS5 authority,
// the forward target or the tcp_forwards target — never on SNI). Reconcile re-evaluates every entry
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
//
// A connection carrying intercept holds is revoked but not cut at once
// (USK-1192): cutting it would make each held request vanish without an
// answer or a record. The Pipeline pins the connection for every hold
// (LiveConnHandle.Pin, keyed through the Register context) and, when the
// hold resolves, hands the pin to the session relay loop that ran the pass
// (HoldPinHandoff, USK-1196), which keeps it until it dispatched the hold's
// Result; HostScopeStep blocks every new Send-direction envelope on a
// revoked connection; and the session settles the cut after the last
// hold's Result was dispatched (HoldPinHandoff.Release, then
// SettleLiveConn), so the release re-check's 403 target_scope reaches the
// client and the audit record first — even when a sibling stream of the
// same h2 connection Settles meanwhile. Receive-direction data from the
// denied host keeps flowing until then: bounded by the hold timeout plus
// however long the Result's client.Send stays parked (Pin refuses a
// revoke-pending connection, so no new hold extends the deferral; see the
// Reconcile note on a client that never reads).

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
// plain-HTTP-forward / TCP forward gate. ConnID, Listener, Via and Target are only used
// for logging.
type LiveConn struct {
	ConnID   string
	Listener string
	// Via names the gate: "connect", "socks5", "http1-forward" or
	// "tcp-forward".
	Via string
	// Target is the authority the gate admitted (host:port).
	Target string
	// Admit is the gate's admission check. A nil Admit is never cut.
	Admit LiveConnAdmitFunc
	// AdmitOpaque is the gate's check run strictly, as for a route that
	// never yields an HTTP request path (CheckOpaqueTarget, USK-1130).
	// A gate that admits path-scoped allows provisionally sets it so the
	// raw relay can refuse once the route resolves to raw bytes (see
	// LiveConnHandle.AdmitOpaque). Nil means Admit is already strict.
	AdmitOpaque LiveConnAdmitFunc
}

type liveConnEntry struct {
	info   LiveConn
	cancel context.CancelCauseFunc
	// cut is set (under LiveConns.mu) once the entry was cancelled, so a
	// later Reconcile does not count or log it again before the handler
	// unwinds and releases it. Atomic so RevokePending reads it without
	// the lock. A cut entry keeps pending as it was.
	cut atomic.Bool
	// pins counts the intercept holds in flight on this connection
	// (LiveConnHandle.Pin / Unpin, USK-1192), including resolved holds
	// whose Result the session has not dispatched yet (HoldPinHandoff,
	// USK-1196). Guarded by LiveConns.mu.
	pins int
	// pending is set when Reconcile revoked the entry while pins > 0: the
	// cut is deferred until the last hold resolved and its Result was
	// dispatched (LiveConnHandle.Settle). Written only under
	// LiveConns.mu; atomic so the per-envelope RevokePending read on the
	// data path takes no lock.
	pending atomic.Bool
	// trigger labels the policy change that revoked a pending entry; the
	// deferred cut logs it. Guarded by LiveConns.mu.
	trigger string
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
// the connection ends (defer it). release is idempotent. The returned
// context carries the connection's *LiveConnHandle (LiveConnFromContext),
// through which the Pipeline defers the cut while an intercept hold is in
// flight (USK-1192).
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
	cctx = context.WithValue(cctx, liveConnKey{}, &LiveConnHandle{reg: r, e: e})

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
// and revokes each one that would not be admitted now. trigger labels the
// policy change in the log ("SIGHUP", "security_tool", ...). It returns the
// number of connections revoked by this call; a connection already revoked
// by an earlier Reconcile is not counted again. Widening or unchanged
// rules revoke nothing, so calling it after every write is safe.
//
// A revoked connection is cut (its context cancelled) at once, unless it
// has intercept holds in flight (LiveConnHandle.Pin, USK-1192): then the
// cut is deferred until the last hold resolved and its Result was
// dispatched (LiveConnHandle.Settle), so a held request is answered and
// recorded instead of vanishing with its connection. While deferred the
// connection is RevokePending and HostScopeStep blocks every new
// Send-direction envelope on it. A deferred connection whose target is
// admitted again by a later Reconcile (or by Settle's re-check) is no
// longer revoked.
//
// A resolved hold whose Result the session has not dispatched yet still
// counts as pinned (its pin was handed off to the session relay loop,
// HoldPinHandoff, USK-1196), so a second Reconcile landing in that gap
// defers like the first instead of cutting the connection under the
// Result. The pins == 0 branch below remains the backstop for a Settle
// that never runs.
//
// Deferred (USK-1196, owner USK-1182): a client that never reads now keeps
// the handed-off pin for as long as the Result's client.Send is parked on
// it, so the revoked connection is not cut until that Send fails or
// returns (before USK-1196 a second Reconcile could cut it). The denied
// upstream receives no Send-direction data meanwhile (HostScopeStep blocks
// it), but Receive-direction data keeps flowing. On HTTP/2 the client can
// stall only the held stream: withholding WINDOW_UPDATE for it parks the
// Result's DATA in the writer's flow-control scheduler (USK-1166), so the
// Send stays blocked while the client keeps reading the connection and
// already-open sibling streams (SSE, gRPC streaming) from the revoked host
// keep relaying with no time limit. Re-open trigger: M54 exposing the proxy
// listener to untrusted clients — bound the parked Result Send itself (a
// socket write deadline alone does not cover the h2 per-stream stall), per
// USK-1182.
func (r *LiveConns) Reconcile(trigger string) int {
	revoked, _ := r.ReconcileWithDeferred(trigger)
	return revoked
}

// ReconcileWithDeferred is Reconcile that also reports how many of the
// revoked connections had their cut deferred for in-flight intercept
// holds (deferred <= revoked).
func (r *LiveConns) ReconcileWithDeferred(trigger string) (revoked, deferred int) {
	if r == nil {
		return 0, 0
	}
	r.mu.Lock()
	snapshot := make([]*liveConnEntry, 0, len(r.conns))
	for _, e := range r.conns {
		if !e.cut.Load() && e.info.Admit != nil {
			snapshot = append(snapshot, e)
		}
	}
	r.mu.Unlock()

	// The predicates take the TargetScope read lock; evaluate them outside
	// r.mu so a slow scope read never stalls Register / release / Pin.
	for _, e := range snapshot {
		allowed, reason := e.info.Admit()
		r.mu.Lock()
		if e.cut.Load() {
			r.mu.Unlock()
			continue // a concurrent Reconcile / Settle got there first
		}
		wasPending := e.pending.Load()
		if allowed {
			if wasPending {
				e.pending.Store(false)
				e.trigger = ""
			}
			r.mu.Unlock()
			if wasPending {
				r.logger.Info("live connection revocation withdrawn: target admitted again",
					r.logAttrs(e, "trigger", trigger)...)
			}
			continue
		}
		if e.pins > 0 {
			if !wasPending {
				e.pending.Store(true)
				e.trigger = trigger
			}
			holds := e.pins
			r.mu.Unlock()
			if !wasPending {
				revoked++
				deferred++
				r.logger.Info("live connection revoked: close deferred until intercept holds resolve",
					r.logAttrs(e, "reason", reason, "trigger", trigger, "holds", holds)...)
			}
			continue
		}
		// No hold in flight: cut now. A pending entry whose holds all
		// resolved without a Settle (backstop) was counted when it was
		// revoked.
		e.cut.Store(true)
		r.mu.Unlock()
		e.cancel(fmt.Errorf("%w: %s", ErrTargetScopeRevoked, reason))
		if !wasPending {
			revoked++
		}
		r.logger.Info("live connection closed: target no longer in scope",
			r.logAttrs(e, "reason", reason, "trigger", trigger, "deferred", wasPending)...)
	}
	return revoked, deferred
}

// logAttrs returns the per-connection log attributes followed by extra.
func (r *LiveConns) logAttrs(e *liveConnEntry, extra ...any) []any {
	return append([]any{
		"conn_id", e.info.ConnID,
		"listener", e.info.Listener,
		"via", e.info.Via,
		"target", e.info.Target,
	}, extra...)
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
//
// admitOpaque is the gate's strict check (LiveConn.AdmitOpaque); nil when
// admit is already strict.
func trackAdmitted(ctx context.Context, reg *LiveConns, via, target string, admit, admitOpaque LiveConnAdmitFunc, logger *slog.Logger) (context.Context, func(), bool) {
	tctx, release, err := reg.Register(ctx, LiveConn{
		ConnID:      ConnIDFromContext(ctx),
		Listener:    ListenerNameFromContext(ctx),
		Via:         via,
		Target:      target,
		Admit:       admit,
		AdmitOpaque: admitOpaque,
	})
	if err != nil {
		logger.Info("target blocked by scope (policy changed during admission)",
			"via", via, "error", err)
		return tctx, release, false
	}
	return tctx, release, true
}

// liveConnKey is the context key under which Register stores the
// connection's *LiveConnHandle.
type liveConnKey struct{}

// LiveConnHandle is the Pipeline's view of one registered live connection
// (USK-1192). Every method is nil-safe; a nil handle (a connection that no
// gate registered, or a nil registry) is inert: Pin succeeds, RevokePending
// is false, Unpin and Settle do nothing.
type LiveConnHandle struct {
	reg *LiveConns
	e   *liveConnEntry
}

// LiveConnFromContext returns the handle of the live connection whose
// Register context ctx derives from, or nil.
func LiveConnFromContext(ctx context.Context) *LiveConnHandle {
	if ctx == nil {
		return nil
	}
	h, _ := ctx.Value(liveConnKey{}).(*LiveConnHandle)
	return h
}

// SettleLiveConn settles the live connection carried by ctx (see
// LiveConnHandle.Settle). The session calls it after dispatching each
// Pipeline Result — right after releasing the pins handed off for that
// Result (HoldPinHandoff.Release) — so a deferred cut runs only once the
// Result of the last hold reached the wire. A ctx without a handle is a
// no-op.
func SettleLiveConn(ctx context.Context) {
	LiveConnFromContext(ctx).Settle()
}

// Pin records an intercept hold about to start on the connection, so a
// Reconcile that revokes the connection defers its cut. It reports false
// when the connection was already cut or is revoke-pending: the caller
// must not hold, and answers the envelope as a target scope block instead.
// Each successful Pin must be paired with exactly one Unpin — by the
// caller, or by the HoldPinHandoff it handed the pin to.
//
// Refusing while pending keeps the deferral bounded: only the holds that
// were in flight when the connection was revoked delay the cut. Otherwise
// concurrent long-lived streams (h2 gRPC / SSE with a Receive intercept
// rule) could chain new holds so the pin count never reaches 0 and the
// connection is never cut. While pending only Receive envelopes reach
// Pin — HostScopeStep blocks every Send first. A revocation withdrawn by
// a widening Reconcile / Settle clears pending, so Pin succeeds again.
func (h *LiveConnHandle) Pin() bool {
	if h == nil {
		return true
	}
	h.reg.mu.Lock()
	defer h.reg.mu.Unlock()
	if h.e.cut.Load() || h.e.pending.Load() {
		return false
	}
	h.e.pins++
	return true
}

// Unpin drops one pin. It never cuts the connection: Settle (called by the
// session after dispatch) decides the cut. Inside a session relay loop the
// InterceptStep does not Unpin at hold resolution but hands the pin off
// (HandOffHoldPin), and the loop Unpins it after dispatching the hold's
// Result (HoldPinHandoff.Release).
func (h *LiveConnHandle) Unpin() {
	if h == nil {
		return
	}
	h.reg.mu.Lock()
	if h.e.pins > 0 {
		h.e.pins--
	}
	h.reg.mu.Unlock()
}

// RevokePending reports whether the connection was revoked by a policy
// change — its cut is deferred for in-flight holds, or it was already cut.
// Lock-free; HostScopeStep calls it for every Send-direction envelope.
func (h *LiveConnHandle) RevokePending() bool {
	if h == nil {
		return false
	}
	if h.e.pending.Load() {
		return true
	}
	return h.e.cut.Load()
}

// AdmitOpaque re-runs the admitting gate's scope check strictly, as for a
// route that never yields an HTTP request path (USK-1130 review S-1). The
// raw relay calls it once before relaying: a gate admits a path-scoped
// allow provisionally on routes that may still carry HTTP, and a route
// that resolved to raw bytes must then be refused as the strict gate
// would have refused it. It falls back to the gate's own check when the
// gate registered no strict variant; a nil handle allows.
func (h *LiveConnHandle) AdmitOpaque() (allowed bool, reason string) {
	if h == nil {
		return true, ""
	}
	switch {
	case h.e.info.AdmitOpaque != nil:
		return h.e.info.AdmitOpaque()
	case h.e.info.Admit != nil:
		return h.e.info.Admit()
	default:
		return true, ""
	}
}

// ResolveOpaque is a not-yet-implemented stub for USK-1283.
func (h *LiveConnHandle) ResolveOpaque() (allowed bool, reason string) {
	return h.AdmitOpaque()
}

// Settle cuts the connection iff it is revoke-pending, no hold is in
// flight, and its admission check still fails; if the check passes again
// (the scope was widened meanwhile) the revocation is withdrawn instead.
// The fast path (not pending) takes no lock.
func (h *LiveConnHandle) Settle() {
	if h == nil || !h.e.pending.Load() {
		return
	}
	r, e := h.reg, h.e
	r.mu.Lock()
	ready := !e.cut.Load() && e.pending.Load() && e.pins == 0
	r.mu.Unlock()
	if !ready {
		return
	}
	allowed, reason := true, ""
	if e.info.Admit != nil {
		allowed, reason = e.info.Admit()
	}

	r.mu.Lock()
	if e.cut.Load() || !e.pending.Load() || e.pins > 0 {
		// A concurrent Reconcile / Settle decided (a widening one may
		// also have let a new hold Pin since).
		r.mu.Unlock()
		return
	}
	trigger := e.trigger
	if allowed {
		e.pending.Store(false)
		e.trigger = ""
		r.mu.Unlock()
		r.logger.Info("live connection revocation withdrawn: target admitted again",
			r.logAttrs(e, "trigger", trigger)...)
		return
	}
	e.cut.Store(true)
	r.mu.Unlock()
	e.cancel(fmt.Errorf("%w: %s", ErrTargetScopeRevoked, reason))
	r.logger.Info("live connection closed: target no longer in scope",
		r.logAttrs(e, "reason", reason, "trigger", trigger, "deferred", true)...)
}

// holdPinHandoffKey is the context key under which WithHoldPinHandoff
// stores its *HoldPinHandoff.
type holdPinHandoffKey struct{}

// HoldPinHandoff carries the live-connection pins of intercept holds that
// resolved during one Pipeline pass from the InterceptStep to the session
// relay loop that runs the pass (USK-1196). The hold's pin must outlive
// the hold itself: it is released only after the session dispatched the
// hold's Result (client.Send of the 403, the released frame / event, ...),
// so that a sibling stream's Settle — or a second Reconcile — cannot cut
// the shared connection while that Result is still on its way to the wire.
//
// One collector belongs to one relay-loop goroutine. The loop releases it
// before every Settle (loop top and exit), so each adopted pin is unpinned
// exactly once.
type HoldPinHandoff struct {
	// n mirrors len(pins) so Release with nothing adopted (every pass
	// without a hold) takes no lock.
	n    atomic.Int32
	mu   sync.Mutex
	pins []*LiveConnHandle
}

// WithHoldPinHandoff returns a context derived from ctx that carries a new
// HoldPinHandoff, and the collector itself. Pass the derived context only
// to the calls that run the Pipeline.
func WithHoldPinHandoff(ctx context.Context) (context.Context, *HoldPinHandoff) {
	c := &HoldPinHandoff{}
	return context.WithValue(ctx, holdPinHandoffKey{}, c), c
}

// HandOffHoldPin transfers ownership of one successful Pin of h to the
// HoldPinHandoff carried by ctx. It reports false — and the caller keeps
// the pin and must Unpin it — when h is nil or ctx carries no collector
// (a Pipeline run outside a session relay loop: MCP resend / fuzz,
// record-only pipelines).
func HandOffHoldPin(ctx context.Context, h *LiveConnHandle) bool {
	if h == nil || ctx == nil {
		return false
	}
	c, _ := ctx.Value(holdPinHandoffKey{}).(*HoldPinHandoff)
	if c == nil {
		return false
	}
	c.mu.Lock()
	c.pins = append(c.pins, h)
	c.n.Store(int32(len(c.pins)))
	c.mu.Unlock()
	return true
}

// Release unpins every pin handed off to c since the previous Release, so
// each adopted pin is unpinned exactly once. Call it before Settle, after
// the Result of the pass was dispatched. Idempotent; nil-safe.
func (c *HoldPinHandoff) Release() {
	if c == nil || c.n.Load() == 0 {
		return
	}
	c.mu.Lock()
	pins := c.pins
	c.pins = nil
	c.n.Store(0)
	c.mu.Unlock()
	for _, h := range pins {
		h.Unpin()
	}
}
