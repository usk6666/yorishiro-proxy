package pluginv2

import (
	"fmt"
	"net"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// Ctx is the Starlark value handed to a plugin hook as its second
// positional argument (`fn(msg, ctx)`). It surfaces per-call read-only
// metadata (`ctx.client_addr`, `ctx.tls`) and the two mutable scoped
// dicts (`ctx.transaction_state`, `ctx.stream_state`) whose lifetime is
// owned by the Layer that produced the envelope (RFC §9.3 D6 / Friction
// 5-C).
//
// Two *Ctx instances created from envelopes that share the same
// (ConnID, FlowID) — e.g. the pre and post phase invocations on a single
// HTTP envelope — wrap the same backing *ScopedState, so values stashed
// by the pre hook are observable by the post hook. The same applies to
// stream_state across (ConnID, StreamID).
//
// Ctx is constructed per-hook by Engine.NewCtx; USK-671 will call that
// constructor from the Pipeline's plugin Step.
type Ctx struct {
	clientAddr starlark.Value // starlark.String (IP only) or starlark.None
	tls        starlark.Value // *starlark.Dict (frozen) or starlark.None
	txState    *scopedStateValue
	stState    *scopedStateValue
}

// String / Type / Freeze / Truth / Hash satisfy starlark.Value.

func (c *Ctx) String() string        { return "ctx" }
func (c *Ctx) Type() string          { return "ctx" }
func (c *Ctx) Freeze()               {} // backing scoped state is shared; do not freeze
func (c *Ctx) Truth() starlark.Bool  { return starlark.True }
func (c *Ctx) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable type: ctx") }

// Attr implements starlark.HasAttrs. The four attributes correspond to
// RFC §9.3 D6's `ctx.transaction_state` / `ctx.stream_state` plus the
// connection-level read-onlys `ctx.client_addr` / `ctx.tls`.
func (c *Ctx) Attr(name string) (starlark.Value, error) {
	switch name {
	case "transaction_state":
		return c.txState, nil
	case "stream_state":
		return c.stState, nil
	case "client_addr":
		return c.clientAddr, nil
	case "tls":
		return c.tls, nil
	}
	return nil, nil
}

func (c *Ctx) AttrNames() []string {
	return []string{"client_addr", "stream_state", "tls", "transaction_state"}
}

// scopedStateValue is the Starlark.Value that represents either
// ctx.transaction_state or ctx.stream_state. It wraps a *ScopedState
// pointer (or nil — for envelopes without a usable scope) and surfaces
// get / set / delete / keys / clear via the Attr interface.
type scopedStateValue struct {
	state *ScopedState
	label string // "transaction_state" or "stream_state"
}

func (sv *scopedStateValue) String() string       { return "ctx." + sv.label }
func (sv *scopedStateValue) Type() string         { return "ctx." + sv.label }
func (sv *scopedStateValue) Freeze()              {} // shared mutable backing
func (sv *scopedStateValue) Truth() starlark.Bool { return starlark.True }
func (sv *scopedStateValue) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: %s", sv.Type())
}

func (sv *scopedStateValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "get":
		return starlark.NewBuiltin(sv.label+".get", sv.builtinGet), nil
	case "set":
		return starlark.NewBuiltin(sv.label+".set", sv.builtinSet), nil
	case "delete":
		return starlark.NewBuiltin(sv.label+".delete", sv.builtinDelete), nil
	case "keys":
		return starlark.NewBuiltin(sv.label+".keys", sv.builtinKeys), nil
	case "clear":
		return starlark.NewBuiltin(sv.label+".clear", sv.builtinClear), nil
	}
	return nil, nil
}

func (sv *scopedStateValue) AttrNames() []string {
	return []string{"clear", "delete", "get", "keys", "set"}
}

// builtinGet implements `ctx.<scope>.get(key) -> value | None`. A nil
// backing ScopedState (released between hook firing and call, or empty
// ConnID at construction) returns None, matching Starlark's "missing
// key" idiom.
func (sv *scopedStateValue) builtinGet(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key); err != nil {
		return nil, err
	}
	if sv.state == nil {
		return starlark.None, nil
	}
	return sv.state.get(string(key)), nil
}

// builtinSet implements `ctx.<scope>.set(key, value)`. Drops the write
// silently when the backing scope has been released so a stale captured
// reference cannot resurrect a freed scope. Returns None.
func (sv *scopedStateValue) builtinSet(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key starlark.String
	var v starlark.Value
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 2, &key, &v); err != nil {
		return nil, err
	}
	if sv.state == nil {
		return starlark.None, nil
	}
	if err := sv.state.set(string(key), v); err != nil {
		return nil, fmt.Errorf("%s: %w", fn.Name(), err)
	}
	return starlark.None, nil
}

// builtinDelete implements `ctx.<scope>.delete(key)`. Deleting a missing
// key is a no-op; matches state.delete semantics.
func (sv *scopedStateValue) builtinDelete(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var key starlark.String
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 1, &key); err != nil {
		return nil, err
	}
	if sv.state != nil {
		sv.state.del(string(key))
	}
	return starlark.None, nil
}

// builtinKeys implements `ctx.<scope>.keys() -> list[str]`. A nil scope
// returns the empty list.
func (sv *scopedStateValue) builtinKeys(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}
	if sv.state == nil {
		return starlark.NewList(nil), nil
	}
	keys := sv.state.keys()
	out := make([]starlark.Value, 0, len(keys))
	for _, k := range keys {
		out = append(out, starlark.String(k))
	}
	return starlark.NewList(out), nil
}

// builtinClear implements `ctx.<scope>.clear()`. Empties the backing
// scope but does NOT release it — the Layer remains the sole owner of
// the entry's lifetime.
func (sv *scopedStateValue) builtinClear(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackPositionalArgs(fn.Name(), args, kwargs, 0); err != nil {
		return nil, err
	}
	if sv.state != nil {
		sv.state.clear()
	}
	return starlark.None, nil
}

// NewCtx constructs the Ctx Starlark value for a single hook invocation.
// The returned *Ctx wraps the engine's transaction and stream stores
// keyed by:
//
//   - transaction: (ConnID, FlowID) for envelope.ProtocolHTTP; (ConnID,
//     StreamID) for any other protocol. The HTTP rule lets pre and post
//     phase hooks on the same envelope share a dict; the streaming rule
//     scopes the dict to the Channel's lifetime so an `on_start` hook
//     can stash values an `on_data` hook can read across many frames.
//   - stream: (ConnID, StreamID) regardless of protocol — the StreamID is
//     a connection-stable UUID set by the Layer when the channel is
//     created, never the H2 wire integer (RFC-001 keeps StreamID at the
//     L7-first level).
//
// nil env yields a Ctx with no live backing — None for client_addr/tls,
// no-op state proxies. Used by tests and by USK-671 when synthesizing a
// hook invocation outside any Layer-driven flow.
func (e *Engine) NewCtx(env *envelope.Envelope) *Ctx {
	if env == nil {
		return &Ctx{
			clientAddr: starlark.None,
			tls:        starlark.None,
			txState:    &scopedStateValue{label: "transaction_state"},
			stState:    &scopedStateValue{label: "stream_state"},
		}
	}
	connID := env.Context.ConnID
	tx := e.transactionStore.getOrCreate(connID, transactionKey(env))
	st := e.streamStore.getOrCreate(connID, env.StreamID)

	return &Ctx{
		clientAddr: clientAddrValue(env.Context.ClientAddr),
		tls:        tlsSnapshotValue(env.Context.TLS),
		txState:    &scopedStateValue{state: tx, label: "transaction_state"},
		stState:    &scopedStateValue{state: st, label: "stream_state"},
	}
}

// transactionKey selects the second component of the (ConnID, ?) key
// used to look up transaction_state. HTTP envelopes are per-direction
// (FlowID); streaming protocols (WS, SSE, gRPC, raw) scope the
// transaction to the Channel's lifetime by using StreamID.
func transactionKey(env *envelope.Envelope) string {
	if env.Protocol == envelope.ProtocolHTTP {
		return env.FlowID
	}
	return env.StreamID
}

// ReleaseTransaction implements StateReleaser. Layers (httpaggregator,
// ws) invoke this when the transaction scope ends.
func (e *Engine) ReleaseTransaction(connID, flowID string) {
	if e == nil {
		return
	}
	e.transactionStore.release(connID, flowID)
}

// ReleaseStream implements StateReleaser. The HTTP/2 Layer invokes this
// at every terminal-state transition (via channel.markTerminated, which
// covers Close, RST_STREAM, peer GOAWAY-driven failStream, and
// broadcastShutdown).
func (e *Engine) ReleaseStream(connID, streamID string) {
	if e == nil {
		return
	}
	e.streamStore.release(connID, streamID)
}

// clientAddrValue projects a net.Addr into the IP-only string surfaced
// via ctx.client_addr. Per the Linear scope, ctx.client_addr is the
// client IP without port. SplitHostPort failure surfaces the unparsed
// string so a misbehaving listener does not hide diagnostic info.
func clientAddrValue(a net.Addr) starlark.Value {
	if a == nil {
		return starlark.None
	}
	s := a.String()
	if host, _, err := net.SplitHostPort(s); err == nil {
		return starlark.String(host)
	}
	return starlark.String(s)
}

// tlsSnapshotValue projects a *envelope.TLSSnapshot into a frozen
// snake_case Starlark Dict, matching the USK-669 message-dict naming
// convention. Returns None when no TLS layer is in the stack.
//
// The dict is frozen so plugin code cannot mutate the operator-visible
// fingerprint/version strings — a small fitness item for the wire-
// fidelity principle even though TLSSnapshot lives outside the wire
// payload.
func tlsSnapshotValue(s *envelope.TLSSnapshot) starlark.Value {
	if s == nil {
		return starlark.None
	}
	d := starlark.NewDict(6)
	_ = d.SetKey(starlark.String("sni"), starlark.String(s.SNI))
	_ = d.SetKey(starlark.String("alpn"), starlark.String(s.ALPN))
	_ = d.SetKey(starlark.String("version_name"), starlark.String(s.VersionName()))
	_ = d.SetKey(starlark.String("cipher_name"), starlark.String(s.CipherName()))
	_ = d.SetKey(starlark.String("peer_cert_subject"), starlark.String(s.PeerCertSubject()))
	_ = d.SetKey(starlark.String("client_fingerprint"), starlark.String(s.ClientFingerprint))
	d.Freeze()
	return d
}
