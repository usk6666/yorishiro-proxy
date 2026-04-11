package proxy

// This file is a backward-compatibility shim. The real TargetScope type
// lives in internal/connector/. The aliases here keep existing
// internal/proxy/ handlers and tests compiling during the M36-M44
// architecture rewrite; both the aliases and the legacy proxy package are
// scheduled for deletion in M44.

import (
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// TargetScope is an alias for connector.TargetScope.
type TargetScope = connector.TargetScope

// TargetRule is an alias for connector.TargetRule.
type TargetRule = connector.TargetRule

// NewTargetScope creates a new empty TargetScope. Delegates to
// connector.NewTargetScope.
func NewTargetScope() *TargetScope {
	return connector.NewTargetScope()
}
