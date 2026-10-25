/**
 * Filter values the WebUI sends in `query` `filter.protocol` /
 * `filter.http_version` / `filter.scheme`, shared by FlowsPage and
 * DashboardPage.
 */

import type { QueryFilter } from "./types.js";

// Scaffolding: the values the pages currently send, replaced by the fix.
export const PROTOCOL_FILTER_VALUES: readonly string[] = ["HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "gRPC-Web", "TCP", "SOCKS5+HTTPS", "SOCKS5+HTTP"];

export const HTTP_VERSION_FILTER_VALUES: readonly string[] = [];

export const SCHEME_FILTER_VALUES: readonly string[] = ["https", "http", "wss", "ws", "tcp"];

/** One row of the Dashboard "Flows by Protocol" breakdown. */
export interface ProtocolBreakdownEntry {
  label: string;
  filter: QueryFilter;
}

export const PROTOCOL_BREAKDOWN: readonly ProtocolBreakdownEntry[] = [
  "HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "gRPC-Web", "TCP",
].map((p) => ({ label: p, filter: { protocol: p } }));
