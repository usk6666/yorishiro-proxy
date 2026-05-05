/**
 * Pure helpers used by FlowDetailPage and ResendPage to dispatch on a flow's
 * `protocol` string. Kept free of React imports so they can be tested with
 * vitest's pure-TS runner (no @testing-library required).
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
