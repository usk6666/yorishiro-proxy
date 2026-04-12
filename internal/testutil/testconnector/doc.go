// Package testconnector provides an E2E test harness for the M39 Connector
// stack. It wires the full Codec + Pipeline + Session + Connector path —
// Listener, Detector, KindDispatcher, CONNECT/SOCKS5 Negotiators,
// TunnelHandler with ALPN cache and TLS issuer, and a real Pipeline covering
// Scope, RateLimit, Safety, Plugin (PhaseRecv + PhaseSend), Intercept,
// Transform, and Record — against a per-test ephemeral TCP listener.
//
// It is the new-architecture counterpart to testutil/testproxy which covers
// the HTTP/1.x + raw TCP surface. testproxy is unchanged and continues to
// own its own scenarios.
//
// Usage (from an _integration_test.go file tagged //go:build e2e):
//
//	h := testconnector.Start(t, testconnector.WithPassthroughHosts([]string{"raw.test"}))
//	defer h.Stop()
//	// drive traffic at h.ClientAddr using h.CAPool to trust the MITM CA
//
// The harness exposes references to every stateful component that tests need
// to inspect (ALPNCache, Store, BlockCh, PipelineObserver). Options control
// cache sizing, TLS passthrough, scope/rate-limit denies, SOCKS5 auth, and
// extra pipeline steps so that a single integration_test file can focus on
// its scenario without reinventing the wiring.
package testconnector
