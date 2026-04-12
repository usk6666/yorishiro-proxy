// Package tlslayer provides TLS handshake functions for the Envelope + Layered
// Connection Model (RFC-001). These are byte-stream layer operations that
// transform a plain net.Conn into a TLS-wrapped net.Conn.
//
// [Server] performs a server-side TLS handshake (MITM cert presentation).
// [Client] performs a client-side TLS handshake toward an upstream, with
// optional uTLS fingerprint evasion and mTLS client certificate support.
//
// Both functions return a [*envelope.TLSSnapshot] capturing the negotiated
// TLS parameters (SNI, ALPN, peer certificate, cipher suite, version).
//
// The TLS handshake logic is copied from the proven M39 connector/dial.go
// implementation. Only the API surface has changed; the internal logic is
// intentionally identical.
package tlslayer
