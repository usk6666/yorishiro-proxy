// Package connector owns the connection layer of yorishiro-proxy.
//
// It accepts TCP connections via Listener, performs two-stage protocol
// Detection, and dispatches each connection to a Codec pair (client-side +
// upstream-side) that is then driven by internal/session.RunSession. It also
// holds the permanent connection-level policy types: TargetScope, RateLimiter,
// and PassthroughList.
//
// The package was introduced in M39 (architecture rewrite M36-M44) as the
// replacement for the connection-management code that previously lived in
// internal/proxy/. That legacy package is scheduled for deletion in M44 and
// must not be imported from connector/: connector is the permanent package
// and the old proxy/ package currently retains type aliases so that the
// legacy protocol handlers keep compiling during the transition.
//
// Protocol Detection uses a Codec factory registration mechanism so new
// protocols (HTTP/2 in M40, etc.) can be added without modifying detect.go.
// See Detector.Register for details.
package connector
