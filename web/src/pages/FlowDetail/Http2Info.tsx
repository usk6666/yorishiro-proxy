/**
 * Http2Info -- Displays HTTP/2-specific information for a flow.
 *
 * Features:
 * - h2 (TLS) vs h2c (cleartext) badge
 * - Stream ID from metadata
 * - ALPN negotiation result
 * - HTTP/2 pseudo-headers separated from regular headers
 * - Stream grouping for multi-stream message views
 */

import { Badge } from "../../components/ui/Badge.js";
import type { FlowDetailResult, MessageEntry } from "../../lib/mcp/types.js";
import "./FlowDetailPage.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface Http2InfoProps {
  flow: FlowDetailResult;
}

export interface Http2PseudoHeadersProps {
  headers: Record<string, string[]> | undefined;
  type: "request" | "response";
}

export interface Http2StreamGroupProps {
  messages: MessageEntry[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** HTTP/2 request pseudo-header names. */
const REQUEST_PSEUDO_HEADERS = [":method", ":path", ":authority", ":scheme"];

/** HTTP/2 response pseudo-header names. */
const RESPONSE_PSEUDO_HEADERS = [":status"];

/** All HTTP/2 pseudo-header names. */
const ALL_PSEUDO_HEADERS = new Set([
  ...REQUEST_PSEUDO_HEADERS,
  ...RESPONSE_PSEUDO_HEADERS,
]);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Determine if this is an h2 (TLS) or h2c (cleartext) connection. */
function isH2TLS(flow: FlowDetailResult): boolean {
  // If there is TLS version info in conn_info, it is h2 (TLS).
  if (flow.conn_info?.tls_version) {
    return true;
  }
  // If protocol_summary has scheme "https", it is h2.
  if (flow.protocol_summary?.scheme === "https") {
    return true;
  }
  // If ALPN is set, it must be h2 (TLS ALPN negotiation).
  if (flow.conn_info?.tls_alpn) {
    return true;
  }
  return false;
}

/** Extract stream ID from a message's metadata. */
function getStreamId(msg: MessageEntry): string | undefined {
  return msg.metadata?.stream_id;
}

/** Check if a header name is an HTTP/2 pseudo-header. */
export function isPseudoHeader(name: string): boolean {
  return ALL_PSEUDO_HEADERS.has(name.toLowerCase());
}

/** Extract pseudo-headers from a header map. */
function extractPseudoHeaders(
  headers: Record<string, string[]> | undefined,
  pseudoNames: string[],
): [string, string][] {
  if (!headers) return [];

  const result: [string, string][] = [];
  for (const name of pseudoNames) {
    // Check both lowercase and original case.
    const values = headers[name] ?? headers[name.toUpperCase()];
    if (values) {
      for (const value of values) {
        result.push([name, value]);
      }
    }
  }
  return result;
}

/** Filter out pseudo-headers from a header map, returning only regular headers. */
export function filterRegularHeaders(
  headers: Record<string, string[]> | undefined,
): Record<string, string[]> | undefined {
  if (!headers) return headers;

  const filtered: Record<string, string[]> = {};
  let hasRegular = false;
  for (const [key, values] of Object.entries(headers)) {
    if (!isPseudoHeader(key)) {
      filtered[key] = values;
      hasRegular = true;
    }
  }
  return hasRegular ? filtered : headers;
}

/** Group messages by stream ID. Returns null if no stream_id metadata exists. */
function groupByStream(
  messages: MessageEntry[],
): Map<string, MessageEntry[]> | null {
  let hasStreamId = false;
  const groups = new Map<string, MessageEntry[]>();

  for (const msg of messages) {
    const streamId = getStreamId(msg);
    if (streamId) {
      hasStreamId = true;
      const group = groups.get(streamId) ?? [];
      group.push(msg);
      groups.set(streamId, group);
    } else {
      // Messages without stream_id go to "unknown" group.
      const group = groups.get("--") ?? [];
      group.push(msg);
      groups.set("--", group);
    }
  }

  return hasStreamId ? groups : null;
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

/**
 * Http2Badge -- Shows h2 (TLS) or h2c (cleartext) badge.
 */
export function Http2Badge({ flow }: { flow: FlowDetailResult }) {
  if (flow.protocol !== "HTTP/2") return null;

  const isTLS = isH2TLS(flow);
  return (
    <Badge variant={isTLS ? "success" : "warning"}>
      {isTLS ? "h2" : "h2c"}
    </Badge>
  );
}

/**
 * Http2PseudoHeaders -- Displays HTTP/2 pseudo-headers as a separate section.
 */
export function Http2PseudoHeaders({
  headers,
  type,
}: Http2PseudoHeadersProps) {
  const pseudoNames =
    type === "request" ? REQUEST_PSEUDO_HEADERS : RESPONSE_PSEUDO_HEADERS;
  const entries = extractPseudoHeaders(headers, pseudoNames);

  if (entries.length === 0) return null;

  return (
    <div className="sd-h2-pseudo-headers">
      <span className="sd-h2-pseudo-headers-title">
        HTTP/2 Pseudo-Headers
      </span>
      <div className="sd-h2-pseudo-headers-list">
        {entries.map(([name, value], idx) => (
          <div key={`${name}-${idx}`} className="sd-h2-pseudo-header-item">
            <span className="sd-h2-pseudo-header-name">{name}</span>
            <span className="sd-h2-pseudo-header-value">{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Http2StreamGroups -- Groups and displays messages by HTTP/2 stream ID.
 */
export function Http2StreamGroups({ messages }: Http2StreamGroupProps) {
  const groups = groupByStream(messages);
  if (!groups || groups.size <= 1) return null;

  const sortedEntries = Array.from(groups.entries()).sort(([a], [b]) => {
    if (a === "--") return 1;
    if (b === "--") return -1;
    return Number(a) - Number(b);
  });

  return (
    <div className="sd-h2-stream-groups">
      <span className="sd-h2-stream-groups-title">
        Streams ({groups.size})
      </span>
      <div className="sd-h2-stream-groups-list">
        {sortedEntries.map(([streamId, msgs]) => {
          const sendCount = msgs.filter((m) => m.direction === "send").length;
          const recvCount = msgs.filter(
            (m) => m.direction === "receive",
          ).length;
          return (
            <div key={streamId} className="sd-h2-stream-group-item">
              <Badge variant="info">Stream {streamId}</Badge>
              <span className="sd-h2-stream-group-stats">
                {sendCount} req / {recvCount} resp
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/**
 * Http2Info -- Main component combining all HTTP/2-specific info.
 */
export function Http2Info({ flow }: Http2InfoProps) {
  if (flow.protocol !== "HTTP/2") return null;

  const isTLS = isH2TLS(flow);
  const alpn = flow.conn_info?.tls_alpn;
  const streamCount = flow.protocol_summary?.stream_count;

  return (
    <div className="sd-h2-info">
      <div className="sd-h2-info-badges">
        <div className="sd-meta-item">
          <span className="sd-meta-label">Transport</span>
          <Badge variant={isTLS ? "success" : "warning"}>
            {isTLS ? "h2 (TLS)" : "h2c (cleartext)"}
          </Badge>
        </div>

        {alpn && (
          <div className="sd-meta-item">
            <span className="sd-meta-label">ALPN</span>
            <span className="sd-meta-value">{alpn}</span>
          </div>
        )}

        {streamCount && (
          <div className="sd-meta-item">
            <span className="sd-meta-label">Streams</span>
            <span className="sd-meta-value">{streamCount}</span>
          </div>
        )}
      </div>
    </div>
  );
}
