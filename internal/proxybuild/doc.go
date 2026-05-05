// Package proxybuild assembles the live RFC-001 proxy stack.
//
// Responsibilities:
//
//   - BuildLiveStack constructs a per-listener Stack: a connector.FullListener
//     wired with CONNECT/SOCKS5 handlers, a pluginv2.Engine bound for
//     connection.on_connect / on_disconnect dispatch, the canonical 8-step
//     Pipeline (HostScope → HTTPScope → Safety → PluginPre → Intercept →
//     Transform → PluginPost → Record), and a shared WireEncoderRegistry.
//
//   - Manager orchestrates one or more named live Stacks. It exposes
//     Start/Stop/Status/SetMaxConnections/SetPeekTimeout/SetUpstreamProxy and
//     related methods consumed by the MCP proxy_start / proxy_stop tools.
//
// proxybuild is the single seam where RFC-001 stack assembly lives.
//
// What proxybuild does NOT do (deferred):
//
//   - Layer Option fan-out (WithStateReleaser on http1/http2/ws/httpaggregator,
//     WithLifecycleEngine on ws/grpc/grpcweb). These threaded into
//     connector.BuildConfig.PluginV2Engine consumers are owned by USK-690.
//   - LoadPlugins from ProxyConfig.Plugins. Owned by USK-690.
//   - TCP forward listeners (StartTCPForwardsNamed, TCPForwardAddrs).
//     Manager exposes stub methods returning ErrTCPForwardsNotSupported so
//     signature compatibility with proxy.Manager holds; the real impl folds
//     into USK-690 or a sub-issue.
//   - Hot-swap of the pluginv2.Engine after construction.
//
// HTTP wire encoder note: HTTP/1.x (http1.EncodeWireBytes) and HTTP/2
// (httpaggregator.EncodeWireBytes) both register against
// envelope.ProtocolHTTP and are mutually exclusive in a single registry.
// BuildLiveStack does NOT register an HTTP encoder by default — the
// strategy is owned by USK-690 production wiring. Callers that need HTTP
// re-encode in tests pass a pre-built registry via Deps.WireEncoderRegistry.
package proxybuild
