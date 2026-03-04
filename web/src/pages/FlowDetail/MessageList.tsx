/**
 * MessageList — Displays streaming flow messages (WebSocket, gRPC).
 *
 * Shows direction, sequence, content, and metadata with pagination support.
 */

import { useState, useMemo } from "react";
import type { MessageEntry } from "../../lib/mcp/types.js";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Table } from "../../components/ui/Table.js";
import { BodyViewer } from "./BodyViewer.js";
import "./FlowDetailPage.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface MessageListProps {
  messages: MessageEntry[];
  total: number;
  offset: number;
  limit: number;
  loading: boolean;
  onPageChange: (newOffset: number) => void;
  protocol: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format an ISO timestamp to a short time string with milliseconds. */
function formatTime(ts: string): string {
  try {
    const d = new Date(ts);
    const time = d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
    const ms = String(d.getMilliseconds()).padStart(3, "0");
    return `${time}.${ms}`;
  } catch {
    return ts;
  }
}

/** Get a direction badge. */
function directionBadge(
  direction: string,
): { variant: "success" | "info" | "default"; label: string } {
  switch (direction) {
    case "send":
      return { variant: "success", label: "SEND" };
    case "receive":
      return { variant: "info", label: "RECV" };
    default:
      return { variant: "default", label: direction };
  }
}

/** Truncate a string for table display. */
function truncateBody(body: string, maxLen: number = 120): string {
  if (!body) return "(empty)";
  if (body.length <= maxLen) return body;
  return body.slice(0, maxLen) + "...";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function MessageList({
  messages,
  total,
  offset,
  limit,
  loading,
  onPageChange,
  protocol,
}: MessageListProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const isGrpc = protocol === "gRPC";

  // Pagination info
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const currentPage = Math.floor(offset / limit) + 1;

  // Selected message for detail view
  const expandedMessage = useMemo(() => {
    if (!expandedId) return null;
    return messages.find((m) => m.id === expandedId) ?? null;
  }, [expandedId, messages]);

  if (loading && messages.length === 0) {
    return (
      <div className="sd-messages-loading">
        <Spinner size="sm" />
        <span>Loading messages...</span>
      </div>
    );
  }

  if (messages.length === 0) {
    return <div className="sd-empty-section">No messages</div>;
  }

  return (
    <div className="sd-messages">
      <div className="sd-messages-table-wrapper">
        <Table className="sd-messages-table">
          <thead>
            <tr>
              <th>#</th>
              <th>Direction</th>
              {isGrpc && <th>Service</th>}
              {isGrpc && <th>Method</th>}
              <th>Content</th>
              <th>Time</th>
              {isGrpc && <th>Status</th>}
            </tr>
          </thead>
          <tbody>
            {messages.map((msg) => {
              const dir = directionBadge(msg.direction);
              const isExpanded = expandedId === msg.id;

              return (
                <tr
                  key={msg.id}
                  className={`sd-message-row ${isExpanded ? "sd-message-row--selected" : ""}`}
                  onClick={() =>
                    setExpandedId(isExpanded ? null : msg.id)
                  }
                >
                  <td className="sd-message-seq">{msg.sequence}</td>
                  <td>
                    <Badge variant={dir.variant}>{dir.label}</Badge>
                  </td>
                  {isGrpc && (
                    <td className="sd-message-meta">
                      {msg.metadata?.service ?? "--"}
                    </td>
                  )}
                  {isGrpc && (
                    <td className="sd-message-meta">
                      {msg.metadata?.method ?? "--"}
                    </td>
                  )}
                  <td className="sd-message-body-preview">
                    {msg.body_encoding === "base64"
                      ? "(binary)"
                      : truncateBody(msg.body)}
                  </td>
                  <td className="sd-message-time">
                    {formatTime(msg.timestamp)}
                  </td>
                  {isGrpc && (
                    <td className="sd-message-meta">
                      {msg.metadata?.grpc_status ?? "--"}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </Table>
      </div>

      {/* Expanded message detail */}
      {expandedMessage && (
        <div className="sd-message-detail">
          <div className="sd-message-detail-header">
            <span className="sd-message-detail-title">
              Message #{expandedMessage.sequence}
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setExpandedId(null)}
            >
              Close
            </Button>
          </div>

          {/* Message metadata */}
          {expandedMessage.metadata &&
            Object.keys(expandedMessage.metadata).length > 0 && (
              <div className="sd-message-detail-meta">
                {Object.entries(expandedMessage.metadata).map(
                  ([key, value]) => (
                    <div key={key} className="sd-meta-item">
                      <span className="sd-meta-label">{key}</span>
                      <span className="sd-meta-value">{value}</span>
                    </div>
                  ),
                )}
              </div>
            )}

          {/* Message headers */}
          {expandedMessage.headers &&
            Object.keys(expandedMessage.headers).length > 0 && (
              <div className="sd-message-detail-section">
                <span className="sd-message-detail-section-title">
                  Headers
                </span>
                <table className="sd-headers-table">
                  <thead>
                    <tr>
                      <th>Header</th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(expandedMessage.headers).map(
                      ([key, values]) =>
                        values.map((value, idx) => (
                          <tr key={`${key}-${idx}`}>
                            <td className="sd-header-key">{key}</td>
                            <td className="sd-header-value">{value}</td>
                          </tr>
                        )),
                    )}
                  </tbody>
                </table>
              </div>
            )}

          {/* Message body */}
          <div className="sd-message-detail-section">
            <span className="sd-message-detail-section-title">Body</span>
            <BodyViewer
              body={expandedMessage.body}
              encoding={expandedMessage.body_encoding}
              truncated={false}
              headers={expandedMessage.headers}
            />
          </div>
        </div>
      )}

      {/* Pagination */}
      {total > limit && (
        <div className="sd-messages-pagination">
          <div className="sd-messages-pagination-info">
            Showing {offset + 1}--{Math.min(offset + limit, total)} of {total}{" "}
            messages
          </div>
          <div className="sd-messages-pagination-controls">
            <Button
              variant="ghost"
              size="sm"
              disabled={currentPage <= 1}
              onClick={() => onPageChange((currentPage - 2) * limit)}
            >
              Prev
            </Button>
            <span className="sd-messages-pagination-info">
              {currentPage} / {totalPages}
            </span>
            <Button
              variant="ghost"
              size="sm"
              disabled={currentPage >= totalPages}
              onClick={() => onPageChange(currentPage * limit)}
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
