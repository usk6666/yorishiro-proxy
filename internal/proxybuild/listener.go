package proxybuild

import (
	"context"
	"log/slog"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// hookTimeout bounds each lifecycle hook dispatch so a slow Starlark plugin
// cannot stall connection handling. Mirrors the value used by the M39-era
// Listener at internal/connector/listener.go.
const hookTimeout = 5 * time.Second

// Listener wraps a connector.FullListener with a bound pluginv2.Engine.
//
// The wrapper exists so that connection.on_connect / connection.on_disconnect
// pluginv2 lifecycle hooks (RFC §9.3) fire on production connections without
// modifying connector.FullListener itself. FullListener stays transport-only;
// proxybuild.Listener interposes per-protocol HandlerFunc closures that fire
// the lifecycle hook around the user-supplied handler.
//
// Because interposition happens at the per-protocol handler entry, the hook
// fires AFTER protocol detection — slightly later than the M39 Listener
// pattern. This is an acceptable scaffold-level semantic for USK-688; the
// USK-690 production wiring can revisit if pre-detection firing is required.
type Listener struct {
	full   *connector.FullListener
	engine *pluginv2.Engine
	name   string
	logger *slog.Logger
}

// PluginV2Engine returns the pluginv2 Engine bound to this listener, or
// nil when no engine is wired. Satisfies the USK-688 acceptance criterion
// that the engine is reachable through the listener surface.
func (l *Listener) PluginV2Engine() *pluginv2.Engine {
	if l == nil {
		return nil
	}
	return l.engine
}

// FullListener returns the underlying connector.FullListener. Callers use
// this to drive Start / Addr / Ready / ActiveConnections / SetMaxConnections
// / SetPeekTimeout. Returning the underlying type rather than re-exporting
// every method keeps the wrapper's surface small; the FullListener API is
// stable and well-tested.
func (l *Listener) FullListener() *connector.FullListener {
	if l == nil {
		return nil
	}
	return l.full
}

// Start begins accepting connections on the underlying FullListener and
// blocks until ctx is cancelled. Convenience method so callers do not have
// to reach through FullListener for the most common operation.
func (l *Listener) Start(ctx context.Context) error {
	return l.full.Start(ctx)
}

// Ready returns the channel that closes once the underlying FullListener
// is accepting connections.
func (l *Listener) Ready() <-chan struct{} {
	return l.full.Ready()
}

// Addr returns the listener's bound address, or "" if Start has not yet
// progressed past net.Listen.
func (l *Listener) Addr() string {
	return l.full.Addr()
}

// ActiveConnections returns the count of connections currently in flight.
func (l *Listener) ActiveConnections() int {
	return l.full.ActiveConnections()
}

// MaxConnections returns the configured concurrent-connection cap.
func (l *Listener) MaxConnections() int {
	return l.full.MaxConnections()
}

// SetMaxConnections updates the concurrent-connection cap. The new limit
// applies to subsequent accepts.
func (l *Listener) SetMaxConnections(n int) {
	l.full.SetMaxConnections(n)
}

// PeekTimeout returns the protocol detection timeout.
func (l *Listener) PeekTimeout() time.Duration {
	return l.full.PeekTimeout()
}

// SetPeekTimeout updates the protocol detection timeout.
func (l *Listener) SetPeekTimeout(d time.Duration) {
	l.full.SetPeekTimeout(d)
}

// Name returns the listener's name as supplied at construction.
func (l *Listener) Name() string {
	return l.name
}

// wrapHandler returns a HandlerFunc that fires the connection.on_connect
// pluginv2 lifecycle hook before delegating to inner, then defers
// connection.on_disconnect after inner returns. inner == nil yields nil
// (no handler registered for this protocol).
//
// A DROP outcome from on_connect skips the inner handler; the deferred
// on_disconnect still fires (the connection was accepted then closed —
// symmetric with the kernel-accepted-then-rejected case in the M39
// listener).
func (l *Listener) wrapHandler(inner connector.HandlerFunc) connector.HandlerFunc {
	if inner == nil {
		return nil
	}
	if l.engine == nil {
		return inner
	}
	return func(ctx context.Context, pc *connector.PeekConn) error {
		connID := connector.ConnIDFromContext(ctx)
		clientAddr := connector.ClientAddrFromContext(ctx)
		logger := connector.LoggerFromContext(ctx, l.logger)

		// Defer on_disconnect first so a DROP-returning on_connect still
		// emits a paired disconnect event.
		connStart := time.Now()
		defer l.fireDisconnect(connID, clientAddr, connStart, logger)

		if l.fireConnect(ctx, connID, clientAddr, logger) == pluginv2.ActionDrop {
			logger.Info("connection dropped by pluginv2 on_connect hook",
				"hook", "connection.on_connect")
			return nil
		}
		return inner(ctx, pc)
	}
}

// fireConnect dispatches the (connection, on_connect) lifecycle hook.
// Returns ActionContinue when no engine is wired, no hooks are registered,
// or an error occurred (fail-soft: a misbehaving plugin must not break
// wire acceptance).
func (l *Listener) fireConnect(ctx context.Context, connID, clientAddr string, logger *slog.Logger) pluginv2.Action {
	hookCtx, cancel := context.WithTimeout(ctx, hookTimeout)
	defer cancel()

	payload := pluginv2.BuildConnectionConnectDict(connID, clientAddr, l.name)
	action, err := l.engine.FireLifecycle(hookCtx, pluginv2.ProtoConnection, pluginv2.EventOnConnect, nil, payload)
	if err != nil {
		logger.Warn("pluginv2 on_connect hook error", "error", err)
		return pluginv2.ActionContinue
	}
	return action
}

// fireDisconnect dispatches the (connection, on_disconnect) lifecycle hook.
// Uses a fresh background-derived context so the hook still fires during
// graceful shutdown when the parent ctx has already been cancelled.
func (l *Listener) fireDisconnect(connID, clientAddr string, connStart time.Time, logger *slog.Logger) {
	hookCtx, cancel := context.WithTimeout(context.Background(), hookTimeout)
	defer cancel()

	durationMs := time.Since(connStart).Milliseconds()
	payload := pluginv2.BuildConnectionDisconnectDict(connID, clientAddr, durationMs)
	if _, err := l.engine.FireLifecycle(hookCtx, pluginv2.ProtoConnection, pluginv2.EventOnDisconnect, nil, payload); err != nil {
		logger.Warn("pluginv2 on_disconnect hook error", "error", err)
	}
}
