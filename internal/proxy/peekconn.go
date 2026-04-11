package proxy

// This file is a backward-compatibility shim. The real PeekConn lives in
// internal/connector/. The alias here keeps existing internal/proxy/
// handlers compiling during the M36-M44 architecture rewrite; both the
// alias and the legacy proxy package are scheduled for deletion in M44.

import (
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// PeekConn is an alias for connector.PeekConn.
type PeekConn = connector.PeekConn

// NewPeekConn wraps conn with a buffered reader. It delegates to
// connector.NewPeekConn.
func NewPeekConn(conn net.Conn) *PeekConn {
	return connector.NewPeekConn(conn)
}
