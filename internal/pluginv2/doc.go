// Package pluginv2 implements the RFC-001 §9.3 Starlark plugin engine.
//
// Hook identity is the 3-tuple (Protocol, Event, Phase). Plugins register
// hooks at script load time via the predeclared register_hook() builtin;
// the runtime looks them up via Registry.Lookup(protocol, event, phase).
//
// This package is the v2 foundation. Legacy internal/plugin coexists until
// N9; v2 will replace it once Pipeline integration (USK-671), message
// marshaling (USK-669), and per-stream state (USK-670) land.
//
// The plugin protocol vocabulary (http, ws, grpc, grpc-web, sse, raw, tls,
// connection, socks5) is intentionally distinct from envelope.Protocol —
// see surface.go for the full enumeration and the rationale.
package pluginv2
