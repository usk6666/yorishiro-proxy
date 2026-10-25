/**
 * Pure helpers used by FlowDetailPage and ResendPage to dispatch on a flow's
 * `protocol` string. Kept free of React imports so they can be tested with
 * vitest's pure-TS runner (no @testing-library required).
 *
 * Legacy spellings: the server records canonical Stream.Protocol values
 * (http, ws, grpc, grpc-web, sse, raw, tls-handshake; HTTP/2 is "http" plus
 * `http_version`). The helpers below that READ a recorded `protocol` still
 * accept the older display spellings ("HTTP/1.x", "HTTP/2", "WebSocket",
 * "TCP", ...) because no migration rewrites Stream.Protocol and the Store /
 * JSONL import accept any string, so old DBs and imports keep legacy
 * values. This is the only place legacy spellings may appear: filter
 * values and defaults the WebUI sends must be canonical
 * (see ./protocols.ts and src/legacyProtocolLiterals.test.ts).
 */

import type {
  FlowDetailResult,
  PluginIntrospectInfo,
  PluginIntrospectResult,
} from "./types.js";

/** The five Message-typed display kinds the FlowDetail page renders. */
export type FlowDetailKind = "http" | "ws" | "grpc" | "raw" | "sse";

/**
 * Pick the per-protocol component kind for a given flow protocol string.
 *
 * The matcher is intentionally tolerant: it lower-cases the input and accepts
 * common spellings ("HTTP/1.x", "http", "h2", "grpc-web", "websocket"), so
 * server-side casing changes don't break the UI. Unknown protocols fall back
 * to "raw" (the lossless byte-stream view) rather than throwing.
 */
export function pickFlowDetailKind(
  protocol: string | null | undefined,
): FlowDetailKind {
  const proto = (protocol ?? "").toLowerCase();
  if (proto === "websocket" || proto === "ws") return "ws";
  if (proto === "grpc" || proto === "grpc-web") return "grpc";
  if (proto === "sse") return "sse";
  if (proto === "tcp" || proto === "raw") return "raw";
  if (
    proto === "http/1.x" ||
    proto === "http/1.1" ||
    proto === "http/1.0" ||
    proto === "http" ||
    proto === "https" ||
    proto === "http/2" ||
    proto === "h2"
  ) {
    return "http";
  }
  return "raw";
}

/** The protocol-typed resend tool names plus the legacy fallback. */
export type ResendToolName =
  | "resend_http"
  | "resend_ws"
  | "resend_grpc"
  | "resend_raw"
  | "resend";

/**
 * Pick the appropriate resend_* MCP tool for a flow's protocol.
 *
 * Returns "resend" (the legacy tool) for unknown protocols so existing
 * behaviour is preserved. Callers may always fall back to the legacy tool by
 * ignoring this helper.
 */
export function pickResendTool(
  protocol: string | null | undefined,
): ResendToolName {
  const proto = (protocol ?? "").toLowerCase();
  if (proto === "websocket" || proto === "ws") return "resend_ws";
  if (proto === "grpc" || proto === "grpc-web") return "resend_grpc";
  if (proto === "tcp" || proto === "raw") return "resend_raw";
  if (
    proto === "http/1.x" ||
    proto === "http/1.1" ||
    proto === "http/1.0" ||
    proto === "http" ||
    proto === "https" ||
    proto === "http/2" ||
    proto === "h2"
  ) {
    return "resend_http";
  }
  return "resend";
}

/**
 * The protocol-typed fuzz tool names.
 *
 * Unlike {@link ResendToolName} there is no legacy `"fuzz"` fallback — the
 * backend removed the untyped `fuzz` MCP tool in favour of the typed quartet,
 * so {@link pickFuzzTool} returns `null` for unknown protocols rather than a
 * tool name that would fail at the wire (USK-937).
 */
export type FuzzToolName =
  | "fuzz_http"
  | "fuzz_ws"
  | "fuzz_grpc"
  | "fuzz_raw";

/**
 * Pick the appropriate fuzz_* MCP tool for a flow's protocol.
 *
 * Returns `null` for unknown / empty / nullish protocols. Callers should
 * surface a user-visible error in that case (the legacy `fuzz` tool no
 * longer exists at the backend, so there is no fallback to try).
 *
 * @remarks
 * Intended for flow-context launchers that dispatch off a recorded flow's
 * `protocol` string (e.g., a future "Fuzz this flow" button on FlowDetail).
 * The FuzzPage campaign form does NOT use this helper — it routes off a
 * user-selected protocol dropdown rather than a flow protocol, so it calls
 * `client.fuzzHttp / fuzzWs / fuzzGrpc / fuzzRaw` directly. Kept exported
 * for parity with `pickResendTool` and so flow-context callers can reuse the
 * same protocol-string parser.
 */
export function pickFuzzTool(
  protocol: string | null | undefined,
): FuzzToolName | null {
  const proto = (protocol ?? "").toLowerCase();
  if (proto === "websocket" || proto === "ws") return "fuzz_ws";
  if (proto === "grpc" || proto === "grpc-web") return "fuzz_grpc";
  if (proto === "tcp" || proto === "raw") return "fuzz_raw";
  if (
    proto === "http/1.x" ||
    proto === "http/1.1" ||
    proto === "http/1.0" ||
    proto === "http" ||
    proto === "https" ||
    proto === "http/2" ||
    proto === "h2"
  ) {
    return "fuzz_http";
  }
  return null;
}

/**
 * Whether a flow is HTTP/2 (h2 over TLS or h2c cleartext).
 *
 * HTTP/2 streams are recorded as `protocol: "http"`; the wire version lives
 * in `http_version` ("h2" / "h2c"), which `query resource=flow` returns.
 * gRPC / gRPC-Web also ride on HTTP/2 but are their own protocol families
 * and are not reported here.
 */
export function isHttp2(
  flow: Pick<FlowDetailResult, "protocol" | "http_version"> | null | undefined,
): boolean {
  if (!flow) return false;
  if (pickFlowDetailKind(flow.protocol) !== "http") return false;
  return flow.http_version === "h2" || flow.http_version === "h2c";
}

/** Whether a recorded protocol is gRPC or gRPC-Web (legacy-tolerant). */
export function isGrpcProtocol(protocol: string | null | undefined): boolean {
  const proto = (protocol ?? "").toLowerCase();
  return proto === "grpc" || proto === "grpc-web";
}

/** Whether a recorded protocol is WebSocket (legacy-tolerant). */
export function isWsProtocol(protocol: string | null | undefined): boolean {
  const proto = (protocol ?? "").toLowerCase();
  return proto === "ws" || proto === "websocket";
}

/** Whether a recorded protocol is a raw TCP byte stream (legacy-tolerant). */
export function isRawProtocol(protocol: string | null | undefined): boolean {
  const proto = (protocol ?? "").toLowerCase();
  return proto === "raw" || proto === "tcp";
}

/** Badge variants used for protocol badges. */
export type ProtocolBadgeVariant =
  | "default"
  | "success"
  | "warning"
  | "danger"
  | "info";

/**
 * Badge colour for a recorded protocol, keyed on the protocol family.
 * Case-insensitive and legacy-tolerant (rows may predate canonical names);
 * unknown or missing input gets "default".
 */
export function protocolVariant(
  protocol: string | null | undefined,
): ProtocolBadgeVariant {
  const proto = (protocol ?? "").toLowerCase();
  if (isWsProtocol(proto) || proto === "sse") return "info";
  if (isGrpcProtocol(proto)) return "warning";
  if (isRawProtocol(proto)) return "danger";
  return "default";
}

/**
 * Whether a flow uses one of the streaming flow_types that produces a per-message
 * timeline (WebSocket, gRPC server/client/bidi streaming, SSE).
 *
 * Mirrors FlowDetailPage's local helper but accepts a partial flow shape so it
 * can be unit tested without constructing a full FlowDetailResult.
 */
export function isStreamingFlow(
  flow: Pick<FlowDetailResult, "flow_type"> | null | undefined,
): boolean {
  if (!flow) return false;
  return (flow.flow_type ?? "") !== "unary";
}

/**
 * Whether a flow recorded a response. Used to decide between rendering a
 * response panel vs an explanatory empty state. Tolerant to missing fields.
 */
export function hasResponse(
  flow: FlowDetailResult | null | undefined,
): boolean {
  if (!flow) return false;
  if ((flow.response_status_code ?? 0) > 0) return true;
  const headers = flow.response_headers;
  if (headers != null && Object.keys(headers).length > 0) return true;
  return false;
}

/**
 * Sort plugin_introspect plugins for stable display:
 *   - enabled plugins first
 *   - then alphabetically by name
 *
 * Pure function on the input array; never mutates. Returns an empty list when
 * the input is null/undefined or shaped unexpectedly.
 */
export function sortIntrospectedPlugins(
  result: PluginIntrospectResult | null | undefined,
): PluginIntrospectInfo[] {
  const plugins = result?.plugins;
  if (!Array.isArray(plugins)) return [];
  const copy = plugins.slice();
  copy.sort((a, b) => {
    const ae = a?.enabled ? 1 : 0;
    const be = b?.enabled ? 1 : 0;
    if (ae !== be) return be - ae;
    const an = a?.name ?? "";
    const bn = b?.name ?? "";
    return an.localeCompare(bn);
  });
  return copy;
}

/**
 * Render a single Vars value as a string for display, preserving the literal
 * "<redacted>" sentinel applied server-side via redact_keys. Objects/arrays
 * are rendered as compact JSON so analysts see the structure verbatim.
 */
export function formatVarsValue(value: unknown): string {
  if (value == null) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
