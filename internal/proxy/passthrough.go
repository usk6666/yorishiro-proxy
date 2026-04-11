package proxy

// This file is a backward-compatibility shim. The real PassthroughList type
// lives in internal/connector/. The alias here keeps existing
// internal/proxy/ handlers and tests compiling during the M36-M44
// architecture rewrite; both the alias and the legacy proxy package are
// scheduled for deletion in M44.

import (
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// PassthroughList is an alias for connector.PassthroughList.
type PassthroughList = connector.PassthroughList

// NewPassthroughList creates an empty PassthroughList. Delegates to
// connector.NewPassthroughList.
func NewPassthroughList() *PassthroughList {
	return connector.NewPassthroughList()
}
