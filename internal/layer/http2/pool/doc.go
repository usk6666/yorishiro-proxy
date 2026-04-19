// Package pool provides an upstream HTTP/2 connection pool.
//
// A Pool reuses one *http2.Layer per (host:port, TLS config hash) target so
// multiple concurrent streams can leverage HTTP/2 multiplexing on a single
// upstream connection. See RFC-001 §4.4 and envelope-implementation.md
// Friction 3-A for the design baseline.
package pool
