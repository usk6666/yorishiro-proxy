package connector

import (
	"context"
	"errors"
	"log/slog"
)

// ErrTargetScopeRevoked is the context cancel cause of a live connection
// that a policy change no longer admits (USK-1160).
var ErrTargetScopeRevoked = errors.New("target scope no longer admits this connection")

// LiveConnAdmitFunc re-runs the admission scope check of the gate that
// admitted a connection.
type LiveConnAdmitFunc func() (allowed bool, reason string)

// LiveConn describes one connection admitted by a CONNECT / SOCKS5 /
// plain-HTTP-forward gate.
type LiveConn struct {
	ConnID   string
	Listener string
	Via      string
	Target   string
	Admit    LiveConnAdmitFunc
}

// LiveConns is the process-wide registry of admitted live connections.
type LiveConns struct {
	logger *slog.Logger
}

// NewLiveConns returns an empty registry.
func NewLiveConns(logger *slog.Logger) *LiveConns {
	return &LiveConns{logger: logger}
}

// Register is not implemented yet (USK-1160 red phase).
func (r *LiveConns) Register(ctx context.Context, c LiveConn) (context.Context, func(), error) {
	return ctx, func() {}, nil
}

// Reconcile is not implemented yet (USK-1160 red phase).
func (r *LiveConns) Reconcile(trigger string) int { return 0 }

// Len is not implemented yet (USK-1160 red phase).
func (r *LiveConns) Len() int { return 0 }
