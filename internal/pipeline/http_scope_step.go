package pipeline

import (
	"context"
	"net"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// HTTPScopeStep is a Message-typed Pipeline Step that validates HTTP
// request targets against the TargetScope policy at the request level
// (scheme + authority + path). This complements HostScopeStep, which
// operates at the connection level using TargetHost.
//
// Only Send-direction HTTPMessage envelopes are checked. Receive and
// non-HTTP messages always pass through.
type HTTPScopeStep struct {
	scope *connector.TargetScope
}

// NewHTTPScopeStep creates an HTTPScopeStep. If scope is nil, all
// messages pass through.
func NewHTTPScopeStep(scope *connector.TargetScope) *HTTPScopeStep {
	return &HTTPScopeStep{scope: scope}
}

// Process checks Send-direction HTTPMessage envelopes against the
// TargetScope. Returns Drop if the target is blocked, Continue otherwise.
func (s *HTTPScopeStep) Process(_ context.Context, env *envelope.Envelope) Result {
	if env.Direction != envelope.Send {
		return Result{}
	}

	switch msg := env.Message.(type) {
	case *envelope.HTTPMessage:
		return s.processHTTP(msg)
	default:
		return Result{}
	}
}

func (s *HTTPScopeStep) processHTTP(msg *envelope.HTTPMessage) Result {
	if s.scope == nil || !s.scope.HasRules() {
		return Result{}
	}

	scheme := msg.Scheme
	authority := msg.Authority
	path := msg.Path

	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		// Authority without port (e.g., "example.com").
		host = authority
		portStr = ""
	}

	port := 0
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}
	if port == 0 {
		port = defaultPortForScheme(scheme)
	}

	allowed, _ := s.scope.CheckTarget(scheme, host, port, path)
	if !allowed {
		return Result{Action: Drop}
	}
	return Result{}
}

// defaultPortForScheme returns the well-known default port for HTTP schemes.
func defaultPortForScheme(scheme string) int {
	switch scheme {
	case "https":
		return 443
	case "http":
		return 80
	default:
		return 0
	}
}
