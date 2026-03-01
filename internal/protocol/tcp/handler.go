// Package tcp implements a Raw TCP fallback handler for the proxy.
// It catches any connection that is not matched by a more specific protocol
// handler, relays data bidirectionally to a configured forwarding target,
// and records all traffic chunks to the session store.
package tcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// Handler implements proxy.ProtocolHandler for raw TCP connections.
// It acts as a fallback handler: Detect always returns true, so it must be
// registered last in the protocol detector.
type Handler struct {
	store    session.Store
	forwards map[string]string // listen port -> forward address
	logger   *slog.Logger
	mu       sync.Mutex
}

// NewHandler creates a new raw TCP handler.
//
// forwards maps local listen ports to upstream addresses
// (e.g. {"3306": "db.example.com:3306"}). Connections arriving on a port
// without a mapping are closed immediately.
func NewHandler(store session.Store, forwards map[string]string, logger *slog.Logger) *Handler {
	if forwards == nil {
		forwards = make(map[string]string)
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
func (h *Handler) SetForwards(forwards map[string]string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for port, target := range forwards {
		h.forwards[port] = target
	}
}

// Forwards returns a snapshot of the current forward mappings.
// The returned map is a copy and safe to modify.
func (h *Handler) Forwards() map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make(map[string]string, len(h.forwards))
	for k, v := range h.forwards {
		out[k] = v
	}
	return out
}

// Detect always returns true. This handler is intended as a fallback and must
// be registered last in the protocol detector.
func (h *Handler) Detect(_ []byte) bool {
	return true
}

// Handle takes ownership of the connection, establishes a forwarding connection
// to the configured upstream target, and relays data bidirectionally while
// recording all chunks to the session store.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	logger := proxy.LoggerFromContext(ctx, h.logger)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	// Resolve the forwarding target from the local port.
	localAddr := conn.LocalAddr().String()
	_, port, err := net.SplitHostPort(localAddr)
	if err != nil {
		logger.Error("failed to parse local address", "addr", localAddr, "error", err)
		return fmt.Errorf("parse local address %s: %w", localAddr, err)
	}

	h.mu.Lock()
	target, ok := h.forwards[port]
	h.mu.Unlock()
	if !ok {
		logger.Warn("no TCP forward configured for port, closing connection", "port", port)
		return nil
	}

	// Dial upstream.
	upstream, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		logger.Error("TCP upstream dial failed", "target", target, "error", err)
		return fmt.Errorf("dial upstream %s: %w", target, err)
	}
	defer upstream.Close()

	logger.Info("TCP relay established", "target", target)

	// Create session record.
	start := time.Now()
	sess := &session.Session{
		ConnID:      connID,
		Protocol:    "TCP",
		SessionType: "bidirectional",
		State:       "active",
		Timestamp:   start,
		ConnInfo: &session.ConnectionInfo{
			ClientAddr: clientAddr,
			ServerAddr: target,
		},
	}

	if h.store != nil {
		if err := h.store.SaveSession(ctx, sess); err != nil {
			logger.Error("TCP session save failed", "error", err)
			// Continue relaying even if recording fails.
		}
	}

	// Run bidirectional relay with recording.
	r := &relay{
		store:     h.store,
		sessionID: sess.ID,
		logger:    logger,
	}
	relayErr := r.run(ctx, conn, upstream)

	// Update session state to complete.
	duration := time.Since(start)
	if h.store != nil {
		state := "complete"
		if relayErr != nil && ctx.Err() == nil {
			state = "error"
		}
		if err := h.store.UpdateSession(ctx, sess.ID, session.SessionUpdate{
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
