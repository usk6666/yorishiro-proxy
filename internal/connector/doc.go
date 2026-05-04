// Package connector owns the connection layer of yorishiro-proxy.
//
// It accepts TCP connections via FullListener, performs two-stage protocol
// detection, and assembles a per-connection Layer stack (via
// BuildConnectionStack) that is then driven by internal/session.RunSession.
// It also holds the permanent connection-level policy types: TargetScope,
// RateLimiter, and PassthroughList.
//
// Protocol detection uses a small ProtocolKind enum (TLS / HTTP/1.x / SOCKS5
// / Raw TCP). HTTP/2 is detected after TLS handshake via ALPN. See detect.go
// for the byte-level signatures.
package connector
