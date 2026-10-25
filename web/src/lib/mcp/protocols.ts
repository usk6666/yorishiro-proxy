/**
 * Filter values the WebUI sends in `query` `filter.protocol` /
 * `filter.http_version` / `filter.scheme`, shared by FlowsPage and
 * DashboardPage.
 *
 * These must be values the query handler accepts (validFilterProtocols /
 * validFilterHTTPVersions / validFilterSchemes in internal/mcp/query_tool.go)
 * and that the recorder actually writes. canonicalProtocol.test.ts checks
 * them against fixtures generated from the server.
 */

import type { QueryFilter } from "./types.js";

/** Canonical Stream.Protocol values (internal/envelope Protocol constants). */
export const PROTOCOL_FILTER_VALUES = [
  "http",
  "ws",
  "grpc",
  "grpc-web",
  "sse",
  "raw",
  "tls-handshake",
] as const;

/** A canonical Stream.Protocol value. */
export type CanonicalProtocol = (typeof PROTOCOL_FILTER_VALUES)[number];

/**
 * Wire HTTP versions for `filter.http_version`. HTTP/2 streams are
 * `protocol: "http"`, so this is how a user narrows to h2 / h2c.
 */
export const HTTP_VERSION_FILTER_VALUES = [
  "h2",
  "h2c",
  "http/1.1",
  "http/1.0",
] as const;

/**
 * Stream.Scheme values for `filter.scheme`: the handshake transport only.
 * "ws" / "wss" are rejected by the server — use protocol "ws" instead.
 */
export const SCHEME_FILTER_VALUES = ["https", "http", "tcp"] as const;

/** One row of the Dashboard "Flows by Protocol" breakdown. */
export interface ProtocolBreakdownEntry {
  label: string;
  filter: QueryFilter;
}

/**
 * Dashboard breakdown rows: one per canonical protocol, plus the h2 / h2c
 * share of "http" (those rows overlap the "http" row by design).
 */
export const PROTOCOL_BREAKDOWN: readonly ProtocolBreakdownEntry[] = [
  ...PROTOCOL_FILTER_VALUES.map((p) => ({ label: p, filter: { protocol: p } })),
  { label: "http (h2)", filter: { protocol: "http", http_version: "h2" } },
  { label: "http (h2c)", filter: { protocol: "http", http_version: "h2c" } },
];
