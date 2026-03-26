// Package tcp implements a Raw TCP fallback handler for the proxy.
// It catches any connection that is not matched by a more specific protocol
// handler, relays data bidirectionally to a configured forwarding target,
// and records all traffic chunks to the flow store.
package tcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// Handler implements proxy.ProtocolHandler for raw TCP connections.
// It acts as a fallback handler: Detect always returns true, so it must be
// registered last in the protocol detector.
type Handler struct {
	store        flow.FlowWriter
	forwards     map[string]*config.ForwardConfig // listen port -> forward config
	logger       *slog.Logger
	pluginEngine *plugin.Engine
	mu           sync.Mutex
}

// NewHandler creates a new raw TCP handler.
//
// forwards maps local listen ports to forward configurations.
// Connections arriving on a port without a mapping are closed immediately.
func NewHandler(store flow.FlowWriter, forwards map[string]*config.ForwardConfig, logger *slog.Logger) *Handler {
	if forwards == nil {
		forwards = make(map[string]*config.ForwardConfig)
	}
	return &Handler{
		store:    store,
		forwards: forwards,
		logger:   logger,
	}
}

// Name returns the protocol name.
func (h *Handler) Name() string {
	return "TCP"
}

// SetForwards merges the given forward mappings into the existing map so that
// previously configured forwards remain active. This is safe for concurrent use.
func (h *Handler) SetForwards(forwards map[string]*config.ForwardConfig) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for port, fc := range forwards {
		h.forwards[port] = fc
	}
}

// Forwards returns a snapshot of the current forward mappings.
// The returned map is a copy and safe to modify.
func (h *Handler) Forwards() map[string]*config.ForwardConfig {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]*config.ForwardConfig, len(h.forwards))
	for k, v := range h.forwards {
		copied := *v
		out[k] = &copied
	}
	return out
}

// SetPluginEngine sets the plugin engine for dispatching hooks during
// TCP relay. If engine is nil, plugin hooks are skipped.
func (h *Handler) SetPluginEngine(engine *plugin.Engine) {
	h.pluginEngine = engine
}

// Detect always returns true. This handler is intended as a fallback and must
// be registered last in the protocol detector.
func (h *Handler) Detect(_ []byte) bool {
	return true
}

// Handle takes ownership of the connection, establishes a forwarding connection
// to the configured upstream target, and relays data bidirectionally while
// recording all chunks to the flow store.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	logger := proxy.LoggerFromContext(ctx, h.logger)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	target, err := h.resolveTarget(ctx, conn, logger)
	if err != nil {
		return err
	}
	if target == "" {
		return nil // no forward configured; logged by resolveTarget
	}

	// Create flow record before dialing so that connection failures are recorded.
	start := time.Now()
	fl := &flow.Flow{
		ConnID:    connID,
		Protocol:  "TCP",
		Scheme:    "tcp",
		FlowType:  "bidirectional",
		State:     "active",
		Timestamp: start,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: clientAddr,
			ServerAddr: target,
		},
	}

	if h.store != nil {
		if err := h.store.SaveFlow(ctx, fl); err != nil {
			logger.Error("TCP flow save failed", "error", err)
			// Continue even if recording fails.
		}
	}

	// Dial upstream.
	upstream, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		logger.Error("TCP upstream dial failed", "target", target, "error", err)
		h.recordFlowError(ctx, fl.ID, start, logger)
		return fmt.Errorf("dial upstream %s: %w", target, err)
	}
	defer upstream.Close()

	logger.Info("TCP relay established", "target", target)

	// Build plugin ConnInfo from the flow's ConnectionInfo.
	var pluginConnInfo *plugin.ConnInfo
	if fl.ConnInfo != nil {
		pluginConnInfo = &plugin.ConnInfo{
			ClientAddr: fl.ConnInfo.ClientAddr,
			ServerAddr: fl.ConnInfo.ServerAddr,
		}
	}

	// Run bidirectional relay with recording.
	relayErr := RunRelay(ctx, conn, upstream, RelayConfig{
		Store:        h.store,
		FlowID:       fl.ID,
		Logger:       logger,
		PluginEngine: h.pluginEngine,
		ConnInfo:     pluginConnInfo,
		Target:       target,
	})

	// Update flow state to complete.
	duration := time.Since(start)
	if h.store != nil {
		state := "complete"
		if relayErr != nil && ctx.Err() == nil {
			state = "error"
		}
		if err := h.store.UpdateFlow(ctx, fl.ID, flow.FlowUpdate{
			State:    state,
			Duration: duration,
		}); err != nil {
			logger.Error("TCP session update failed", "error", err)
		}
	}

	logger.Info("TCP relay closed", "target", target, "duration_ms", duration.Milliseconds())

	// Context cancellation is expected during graceful shutdown.
	if relayErr != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return relayErr
}

// resolveTarget determines the upstream forwarding target for a connection.
// Priority: port-based forward mapping > context-injected forward target.
// Returns empty string (and logs a warning) when no target is configured.
func (h *Handler) resolveTarget(ctx context.Context, conn net.Conn, logger *slog.Logger) (string, error) {
	localAddr := conn.LocalAddr().String()
	_, port, err := net.SplitHostPort(localAddr)
	if err != nil {
		logger.Error("failed to parse local address", "addr", localAddr, "error", err)
		return "", fmt.Errorf("parse local address %s: %w", localAddr, err)
	}

	h.mu.Lock()
	fc, ok := h.forwards[port]
	h.mu.Unlock()
	if ok && fc != nil {
		return fc.Target, nil
	}

	// TCPForwardListener injects the target via context.
	if ctxTarget, ctxOk := proxy.ForwardTargetFromContext(ctx); ctxOk {
		return ctxTarget, nil
	}

	logger.Warn("no TCP forward configured for port, closing connection", "port", port)
	return "", nil
}

// recordFlowError updates a flow to error state. Errors are logged but not propagated.
func (h *Handler) recordFlowError(ctx context.Context, flowID string, start time.Time, logger *slog.Logger) {
	if h.store == nil {
		return
	}
	duration := time.Since(start)
	if err := h.store.UpdateFlow(ctx, flowID, flow.FlowUpdate{
		State:    "error",
		Duration: duration,
	}); err != nil {
		logger.Error("TCP flow update failed", "error", err)
	}
}
