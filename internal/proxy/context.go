package proxy

// This file is a backward-compatibility shim. The real implementations live
// in internal/connector/. The wrappers here keep existing internal/proxy/
// handlers compiling during the M36-M44 architecture rewrite; both the
// wrappers and the legacy proxy package are scheduled for deletion in M44.

import (
	"context"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// ContextWithForwardTarget stores the TCP forward target address in the
// context. Delegates to connector.ContextWithForwardTarget.
func ContextWithForwardTarget(ctx context.Context, target string) context.Context {
	return connector.ContextWithForwardTarget(ctx, target)
}

// ForwardTargetFromContext retrieves the TCP forward target address from the
// context. Delegates to connector.ForwardTargetFromContext.
func ForwardTargetFromContext(ctx context.Context) (string, bool) {
	return connector.ForwardTargetFromContext(ctx)
}
