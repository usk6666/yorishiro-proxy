package pluginv2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// FireLifecycle iterates every hook registered for (protocol, event,
// PhaseNone) and invokes it with the supplied msg + a Ctx derived from env.
// It is the surface USK-683 Layer / connector code uses to dispatch the
// PhaseSupportNone rows of the RFC §9.3 hook surface (the seven lifecycle
// events listed in the table: ws.on_close, grpc.on_end, grpc-web.on_end,
// connection.on_connect, connection.on_disconnect, tls.on_handshake,
// socks5.on_connect).
//
// Action semantics:
//
//   - Hooks fire in registration order. The first hook that returns DROP
//     (only for connection.on_connect / socks5.on_connect — the surface
//     table forbids DROP for the other five events) short-circuits and
//     returns ActionDrop. For DROP-capable events the caller closes the
//     accepting connection without further Layer construction.
//   - Hooks that return DROP / RESPOND on observation-only events surface
//     ErrDisallowedAction; FireLifecycle Warn-logs and treats the outcome
//     as Continue (matches USK-671 fail-soft policy: "plugin must not
//     break wire").
//   - Plugin Starlark runtime errors are already converted into Continue
//     by Engine.Dispatch's per-hook handler, so the chain keeps moving.
//   - msg is passed verbatim as the plugin's first positional argument.
//     Callers typically build it via one of the BuildLifecycle*Dict
//     helpers below (frozen *starlark.Dict). Mutations to msg by a hook
//     are ignored — lifecycle events are not Pipeline-coupled, so there is
//     no Envelope to commit changes to.
//
// nil engine and empty hook list are no-ops returning ActionContinue.
//
// env is forwarded to Engine.NewCtx so transaction_state / stream_state /
// client_addr / tls behave consistently with USK-670/671 hook invocations.
// Callers may pass a fully populated envelope (e.g. ws.on_close fires with
// the close-frame envelope), a synthetic envelope carrying only
// EnvelopeContext (tls.on_handshake), or nil (connection.on_connect, fired
// before any Layer exists).
func (e *Engine) FireLifecycle(ctx context.Context, protocol, event string, env *envelope.Envelope, msg starlark.Value) (Action, error) {
	if e == nil {
		return ActionContinue, nil
	}
	hooks := e.registry.Lookup(protocol, event, PhaseNone)
	if len(hooks) == 0 {
		return ActionContinue, nil
	}

	if msg == nil {
		// Engine.Dispatch's contract ("nil envelope/Message rejected")
		// applies to PluginStepPre/Post; for lifecycle dispatch the
		// caller is expected to supply a payload. Defend against
		// programming error by substituting an empty frozen dict so a
		// plugin that probes msg["x"] reads None instead of NPE-ing.
		empty := starlark.NewDict(0)
		empty.Freeze()
		msg = empty
	}

	for _, hook := range hooks {
		action, err := e.dispatchLifecycleHook(ctx, hook, env, msg)
		if err != nil {
			if errors.Is(err, ErrDisallowedAction) {
				e.logger.WarnContext(ctx, "pluginv2: lifecycle hook returned disallowed action; treating as continue",
					slog.String("plugin", hook.PluginName),
					slog.String("hook", hook.Protocol+"."+hook.Event),
					slog.String("error", err.Error()),
				)
				continue
			}
			// convertMessageToDict-class errors do not apply here (we
			// supply msg ourselves) but any other surface-level error
			// fails open to keep the wire alive.
			e.logger.WarnContext(ctx, "pluginv2: lifecycle hook dispatch error; continuing",
				slog.String("plugin", hook.PluginName),
				slog.String("hook", hook.Protocol+"."+hook.Event),
				slog.String("error", err.Error()),
			)
			continue
		}
		if action == ActionDrop {
			return ActionDrop, nil
		}
	}
	return ActionContinue, nil
}

// dispatchLifecycleHook invokes one Hook with the supplied msg. It is the
// lifecycle-flavored counterpart of Engine.Dispatch: same Starlark thread
// + ctx-cancel goroutine + step budget setup, but no convertMessageToDict
// (msg is caller-supplied) and no dictToMessage read-back (lifecycle
// events have no envelope to commit mutations to).
func (e *Engine) dispatchLifecycleHook(ctx context.Context, hook Hook, env *envelope.Envelope, msg starlark.Value) (Action, error) {
	ctxVal := e.NewCtx(env)

	thread := &starlark.Thread{
		Name: fmt.Sprintf("pluginv2.lifecycle:%s/%s/%s", hook.PluginName, hook.Protocol, hook.Event),
		Print: func(_ *starlark.Thread, m string) {
			e.logger.Info("pluginv2: plugin print",
				slog.String("plugin", hook.PluginName),
				slog.String("hook", hook.Protocol+"."+hook.Event),
				slog.String("message", m),
			)
		},
	}
	if steps := e.lookupMaxSteps(hook.PluginName); steps > 0 {
		thread.SetMaxExecutionSteps(steps)
	}

	done := make(chan struct{})
	defer close(done)
	if ctx != nil && ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				thread.Cancel(ctx.Err().Error())
			case <-done:
			}
		}()
	}

	args := starlark.Tuple{msg, ctxVal}
	ret, callErr := starlark.Call(thread, hook.Fn, args, nil)
	if callErr != nil {
		e.logger.WarnContext(ctx, "pluginv2: lifecycle hook returned error; treating as continue",
			slog.String("plugin", hook.PluginName),
			slog.String("hook", hook.Protocol+"."+hook.Event),
			slog.String("error", callErr.Error()),
		)
		return ActionContinue, nil
	}

	action, _ := interpretReturnValue(ret, hook, e.logger)
	if action == ActionContinue {
		return ActionContinue, nil
	}
	if !surfaceAllows(hook, action) {
		return action, fmt.Errorf("%w: %s on (%s, %s)", ErrDisallowedAction, action, hook.Protocol, hook.Event)
	}
	// RESPOND is allowed by the surface table for connection.on_connect /
	// socks5.on_connect under DROP semantics only — surface table
	// (surface.go) sets Actions = Continue|Drop for these (no Respond).
	// So an allowed non-Continue action here is always Drop.
	return ActionDrop, nil
}

// BuildConnectionConnectDict builds the frozen Starlark dict supplied to
// (connection, on_connect) plugins. Snake_case keys mirror USK-669
// convention so existing plugin authors recognize the shape.
func BuildConnectionConnectDict(connID, clientAddr, listenerName string) *starlark.Dict {
	d := starlark.NewDict(3)
	_ = d.SetKey(starlark.String("conn_id"), starlark.String(connID))
	_ = d.SetKey(starlark.String("client_addr"), starlark.String(clientAddr))
	_ = d.SetKey(starlark.String("listener_name"), starlark.String(listenerName))
	d.Freeze()
	return d
}

// BuildConnectionDisconnectDict builds the frozen Starlark dict supplied
// to (connection, on_disconnect) plugins. duration_ms is the wall-clock
// time the connection was alive, mirroring the legacy on_disconnect shape
// for consumer compatibility (legacy will be removed in N9).
func BuildConnectionDisconnectDict(connID, clientAddr string, durationMs int64) *starlark.Dict {
	d := starlark.NewDict(3)
	_ = d.SetKey(starlark.String("conn_id"), starlark.String(connID))
	_ = d.SetKey(starlark.String("client_addr"), starlark.String(clientAddr))
	_ = d.SetKey(starlark.String("duration_ms"), starlark.MakeInt64(durationMs))
	d.Freeze()
	return d
}

// BuildSOCKS5ConnectDict builds the frozen Starlark dict supplied to
// (socks5, on_connect) plugins. target_addr is the negotiated CONNECT
// destination (host:port).
func BuildSOCKS5ConnectDict(connID, clientAddr, targetAddr string) *starlark.Dict {
	d := starlark.NewDict(3)
	_ = d.SetKey(starlark.String("conn_id"), starlark.String(connID))
	_ = d.SetKey(starlark.String("client_addr"), starlark.String(clientAddr))
	_ = d.SetKey(starlark.String("target_addr"), starlark.String(targetAddr))
	d.Freeze()
	return d
}

// BuildTLSHandshakeDict builds the frozen Starlark dict supplied to
// (tls, on_handshake) plugins. side is "server" when the proxy presented
// its MITM certificate to the client, "client" when the proxy completed
// the upstream-side handshake. Snapshot fields mirror tlsSnapshotValue
// (USK-670) so plugin authors see one shape across ctx.tls and the
// lifecycle dict.
func BuildTLSHandshakeDict(side string, snap *envelope.TLSSnapshot) *starlark.Dict {
	d := starlark.NewDict(7)
	_ = d.SetKey(starlark.String("side"), starlark.String(side))
	if snap != nil {
		_ = d.SetKey(starlark.String("sni"), starlark.String(snap.SNI))
		_ = d.SetKey(starlark.String("alpn"), starlark.String(snap.ALPN))
		_ = d.SetKey(starlark.String("version_name"), starlark.String(snap.VersionName()))
		_ = d.SetKey(starlark.String("cipher_name"), starlark.String(snap.CipherName()))
		_ = d.SetKey(starlark.String("peer_cert_subject"), starlark.String(snap.PeerCertSubject()))
		_ = d.SetKey(starlark.String("client_fingerprint"), starlark.String(snap.ClientFingerprint))
	} else {
		_ = d.SetKey(starlark.String("sni"), starlark.String(""))
		_ = d.SetKey(starlark.String("alpn"), starlark.String(""))
		_ = d.SetKey(starlark.String("version_name"), starlark.String(""))
		_ = d.SetKey(starlark.String("cipher_name"), starlark.String(""))
		_ = d.SetKey(starlark.String("peer_cert_subject"), starlark.String(""))
		_ = d.SetKey(starlark.String("client_fingerprint"), starlark.String(""))
	}
	d.Freeze()
	return d
}

// BuildWSCloseDict builds the frozen Starlark dict supplied to
// (ws, on_close) plugins. The shape mirrors the (ws, on_message) dict
// (USK-669) so a plugin reading msg["close_code"] / msg["close_reason"]
// works the same regardless of which fire path delivered the close. m may
// be nil when the channel terminated without ever observing a Close frame
// (e.g. RST mid-stream); in that case the caller may pass a synthetic
// WSMessage with Opcode=WSClose, CloseCode=1006 (abnormal closure).
func BuildWSCloseDict(m *envelope.WSMessage) *starlark.Dict {
	d := starlark.NewDict(8)
	if m == nil {
		_ = d.SetKey(starlark.String("opcode"), starlark.MakeInt(int(envelope.WSClose)))
		_ = d.SetKey(starlark.String("fin"), starlark.True)
		_ = d.SetKey(starlark.String("masked"), starlark.False)
		_ = d.SetKey(starlark.String("payload"), starlark.Bytes(""))
		_ = d.SetKey(starlark.String("close_code"), starlark.MakeInt(0))
		_ = d.SetKey(starlark.String("close_reason"), starlark.String(""))
		_ = d.SetKey(starlark.String("compressed"), starlark.False)
	} else {
		_ = d.SetKey(starlark.String("opcode"), starlark.MakeInt(int(m.Opcode)))
		_ = d.SetKey(starlark.String("fin"), starlark.Bool(m.Fin))
		_ = d.SetKey(starlark.String("masked"), starlark.Bool(m.Masked))
		_ = d.SetKey(starlark.String("payload"), starlark.Bytes(m.Payload))
		_ = d.SetKey(starlark.String("close_code"), starlark.MakeInt(int(m.CloseCode)))
		_ = d.SetKey(starlark.String("close_reason"), starlark.String(m.CloseReason))
		_ = d.SetKey(starlark.String("compressed"), starlark.Bool(m.Compressed))
	}
	d.Freeze()
	return d
}

// BuildGRPCEndDict builds the frozen Starlark dict supplied to (grpc,
// on_end) and (grpc-web, on_end) plugins. m may be a synthesized End for
// abnormal terminations (RST mid-stream → Status=2 UNKNOWN per RFC §9.3
// resolution) or the wire-observed End envelope.
func BuildGRPCEndDict(m *envelope.GRPCEndMessage) *starlark.Dict {
	d := starlark.NewDict(4)
	if m == nil {
		_ = d.SetKey(starlark.String("status"), starlark.MakeUint64(0))
		_ = d.SetKey(starlark.String("message"), starlark.String(""))
		_ = d.SetKey(starlark.String("status_details"), starlark.Bytes(""))
		_ = d.SetKey(starlark.String("trailers"), starlark.NewList(nil))
	} else {
		_ = d.SetKey(starlark.String("status"), starlark.MakeUint64(uint64(m.Status)))
		_ = d.SetKey(starlark.String("message"), starlark.String(m.Message))
		_ = d.SetKey(starlark.String("status_details"), starlark.Bytes(m.StatusDetails))
		trailers := make([]starlark.Value, 0, len(m.Trailers))
		for _, kv := range m.Trailers {
			t := starlark.Tuple{
				starlark.String(kv.Name),
				starlark.String(kv.Value),
			}
			trailers = append(trailers, t)
		}
		_ = d.SetKey(starlark.String("trailers"), starlark.NewList(trailers))
	}
	d.Freeze()
	return d
}
