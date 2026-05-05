package pipeline

import (
	"context"
	"net"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// HostScopeStep is an Envelope-only Pipeline Step that validates the
// connection's target host against the TargetScope policy. It uses
// Envelope.Context.TargetHost (populated from CONNECT or SOCKS5 target)
// and never type-asserts on Message.
//
// This is the host-level scope check. Path-based HTTP scope is a separate
// Step added in N3 (HTTPScopeStep).
type HostScopeStep struct {
	scope *connector.TargetScope
}

// NewHostScopeStep creates a HostScopeStep with the given TargetScope.
// If scope is nil, Process always continues (no filtering).
func NewHostScopeStep(scope *connector.TargetScope) *HostScopeStep {
	return &HostScopeStep{scope: scope}
}

// Process checks whether the envelope's target host is allowed by the
// TargetScope policy. Returns Drop if the target is blocked, Continue
// otherwise. Envelopes without a TargetHost are always allowed.
func (s *HostScopeStep) Process(_ context.Context, env *envelope.Envelope) Result {
	if s.scope == nil || env.Context.TargetHost == "" {
		return Result{}
	}

	host, portStr, err := net.SplitHostPort(env.Context.TargetHost)
	if err != nil {
		// TargetHost might be a bare hostname without port.
		host = env.Context.TargetHost
		portStr = ""
	}

	port := 0
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}

	// Pass empty scheme and path — HostScopeStep is a connection-level
	// check that only validates hostname and port.
	allowed, _ := s.scope.CheckTarget("", host, port, "")
	if !allowed {
		return Result{Action: Drop}
	}
	return Result{}
}
