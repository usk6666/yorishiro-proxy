/**
 * WebSocketMessageList -- Enhanced message display for WebSocket flows.
 *
 * Features:
 * - Opcode badge (Text, Binary, Close, Ping, Pong)
 * - Direction arrows with color distinction (send=green, receive=blue)
 * - Binary message Hex/Base64 toggle
 * - Text message JSON detection + pretty-print
 * - Message size display
 * - Close frame status code + reason parsing
 */

import { useCallback, useMemo, useState } from "react";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Spinner } from "../../components/ui/Spinner.js";
import type { MessageEntry } from "../../lib/mcp/types.js";
import "./FlowDetailPage.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WebSocketMessageListProps {
  messages: MessageEntry[];
  total: number;
  offset: number;
  limit: number;
  loading: boolean;
  onPageChange: (newOffset: number) => void;
}

/** Binary display mode for the detail view. */
type BinaryDisplayMode = "hex" | "base64";

// ---------------------------------------------------------------------------
// WebSocket Opcode Helpers
// ---------------------------------------------------------------------------

/** WebSocket opcode constants (RFC 6455 Section 11.8). */
const WS_OPCODE = {
  TEXT: "1",
  BINARY: "2",
  CLOSE: "8",
  PING: "9",
  PONG: "10",
} as const;

/** Map opcode string to a human-readable label. */
function opcodeLabel(opcode: string): string {
  switch (opcode) {
    case WS_OPCODE.TEXT:
      return "Text";
    case WS_OPCODE.BINARY:
      return "Binary";
    case WS_OPCODE.CLOSE:
      return "Close";
    case WS_OPCODE.PING:
      return "Ping";
    case WS_OPCODE.PONG:
      return "Pong";
    default:
      return `0x${Number(opcode).toString(16)}`;
  }
}

/** Get the Badge variant for an opcode. */
function opcodeBadgeVariant(
  opcode: string,
): "default" | "success" | "warning" | "danger" | "info" {
  switch (opcode) {
    case WS_OPCODE.TEXT:
      return "success";
    case WS_OPCODE.BINARY:
      return "info";
    case WS_OPCODE.CLOSE:
      return "danger";
    case WS_OPCODE.PING:
      return "warning";
    case WS_OPCODE.PONG:
      return "warning";
    default:
      return "default";
  }
}

/** Check if the opcode indicates a control frame. */
function isControlFrame(opcode: string): boolean {
  return (
    opcode === WS_OPCODE.CLOSE ||
    opcode === WS_OPCODE.PING ||
    opcode === WS_OPCODE.PONG
  );
}

// ---------------------------------------------------------------------------
// Close Frame Helpers (RFC 6455 Section 7.4)
// ---------------------------------------------------------------------------

/** Well-known WebSocket close status codes. */
const CLOSE_CODES: Record<number, string> = {
  1000: "Normal Closure",
  1001: "Going Away",
  1002: "Protocol Error",
  1003: "Unsupported Data",
  1005: "No Status Received",
  1006: "Abnormal Closure",
  1007: "Invalid Payload Data",
  1008: "Policy Violation",
  1009: "Message Too Big",
  1010: "Mandatory Extension",
  1011: "Internal Error",
  1012: "Service Restart",
  1013: "Try Again Later",
  1014: "Bad Gateway",
  1015: "TLS Handshake",
};

/** Parse a Close frame body into status code and reason. */
function parseCloseFrame(body: string, encoding: string): { code: number; reason: string; codeDescription: string } | null {
  if (!body) return null;

  let bytes: Uint8Array;
  try {
    if (encoding === "base64") {
      const binary = atob(body);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
    } else {
      // Text-encoded Close frame data -- try interpreting as raw bytes
      const encoder = new TextEncoder();
      bytes = encoder.encode(body);
    }
  } catch {
    return null;
  }

  // Close frame must have at least 2 bytes for the status code.
  if (bytes.length < 2) return null;

  const code = (bytes[0] << 8) | bytes[1];
  const reason =
    bytes.length > 2
      ? new TextDecoder().decode(bytes.slice(2))
      : "";
  const codeDescription = CLOSE_CODES[code] ?? "Unknown";

  return { code, reason, codeDescription };
}

// ---------------------------------------------------------------------------
// Body / Size Helpers
// ---------------------------------------------------------------------------

/** Calculate the byte size of a message body. */
function bodyByteSize(body: string, encoding: string): number {
  if (!body) return 0;
  if (encoding === "base64") {
    // Base64 encodes 3 bytes into 4 chars.
    const padding = (body.match(/=+$/) ?? [""])[0].length;
    return Math.floor((body.length * 3) / 4) - padding;
  }
  return new TextEncoder().encode(body).length;
}

/** Format byte size for display. */
function formatSize(bytes: number): string {
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

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

/** Truncate a string for table display. */
function truncateBody(body: string, maxLen: number = 100): string {
  if (!body) return "(empty)";
  if (body.length <= maxLen) return body;
  return body.slice(0, maxLen) + "...";
}

/** Try to detect if a string is valid JSON. */
function isJsonString(s: string): boolean {
  if (!s) return false;
  const trimmed = s.trim();
  if (
    (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
    (trimmed.startsWith("[") && trimmed.endsWith("]"))
  ) {
    try {
      JSON.parse(trimmed);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

/** Pretty-print JSON. Returns null if not valid JSON. */
function prettyJson(s: string): string | null {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return null;
  }
}

/** Convert a base64 string to a hex dump display. */
function hexDump(base64Str: string): string {
  let bytes: Uint8Array;
  try {
    const binary = atob(base64Str);
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
  } catch {
    return "(Failed to decode base64 content)";
  }

  const lines: string[] = [];
  const maxBytes = Math.min(bytes.length, 4096);

  for (let offset = 0; offset < maxBytes; offset += 16) {
    const hexParts: string[] = [];
    const asciiParts: string[] = [];

    for (let i = 0; i < 16; i++) {
      if (offset + i < maxBytes) {
        const byte = bytes[offset + i];
        hexParts.push(byte.toString(16).padStart(2, "0"));
        asciiParts.push(
          byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".",
        );
      } else {
        hexParts.push("  ");
        asciiParts.push(" ");
      }
    }

    const offsetStr = offset.toString(16).padStart(8, "0");
    const hex =
      hexParts.slice(0, 8).join(" ") + "  " + hexParts.slice(8).join(" ");
    const ascii = asciiParts.join("");
    lines.push(`${offsetStr}  ${hex}  |${ascii}|`);
  }

  if (bytes.length > maxBytes) {
    lines.push(`... (${bytes.length - maxBytes} more bytes truncated)`);
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function WebSocketMessageList({
  messages,
  total,
  offset,
  limit,
  loading,
  onPageChange,
}: WebSocketMessageListProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [binaryMode, setBinaryMode] = useState<BinaryDisplayMode>("hex");
  const [jsonPretty, setJsonPretty] = useState(true);

  // Pagination info
  const totalPages = Math.max(1, Math.ceil(total / limit));
  const currentPage = Math.floor(offset / limit) + 1;

  // Selected message for detail view
  const expandedMessage = useMemo(() => {
    if (!expandedId) return null;
    return messages.find((m) => m.id === expandedId) ?? null;
  }, [expandedId, messages]);

  const handleRowClick = useCallback(
    (id: string) => {
      setExpandedId((prev) => (prev === id ? null : id));
    },
    [],
  );

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
    <div className="sd-messages sd-ws-messages">
      {/* Message list */}
      <div className="sd-ws-message-list">
        {messages.map((msg) => {
          const opcode = msg.metadata?.opcode ?? "";
          const isSend = msg.direction === "send";
          const isExpanded = expandedId === msg.id;
          const size = bodyByteSize(msg.body, msg.body_encoding);
          const isControl = isControlFrame(opcode);
          const closeInfo =
            opcode === WS_OPCODE.CLOSE
              ? parseCloseFrame(msg.body, msg.body_encoding)
              : null;

          // Build content preview
          let preview: string;
          if (opcode === WS_OPCODE.CLOSE && closeInfo) {
            preview = `${closeInfo.code} ${closeInfo.codeDescription}${closeInfo.reason ? ` - ${closeInfo.reason}` : ""}`;
          } else if (msg.body_encoding === "base64") {
            preview = `(binary ${formatSize(size)})`;
          } else if (isControl) {
            preview = msg.body ? truncateBody(msg.body, 60) : "(empty)";
          } else {
            preview = truncateBody(msg.body, 100);
          }

          return (
            <div
              key={msg.id}
              className={[
                "sd-ws-msg-row",
                isSend ? "sd-ws-msg-row--send" : "sd-ws-msg-row--recv",
                isControl ? "sd-ws-msg-row--control" : "",
                isExpanded ? "sd-ws-msg-row--selected" : "",
              ]
                .filter(Boolean)
                .join(" ")}
              onClick={() => handleRowClick(msg.id)}
            >
              <div className="sd-ws-msg-header">
                <span className="sd-ws-msg-seq">#{msg.sequence}</span>
                <span
                  className={`sd-ws-msg-direction ${isSend ? "sd-ws-msg-direction--send" : "sd-ws-msg-direction--recv"}`}
                >
                  {isSend ? "\u2191" : "\u2193"}
                </span>
                <Badge variant={opcodeBadgeVariant(opcode)}>
                  {opcodeLabel(opcode)}
                </Badge>
                <span className="sd-ws-msg-size">{formatSize(size)}</span>
                <span className="sd-ws-msg-time">
                  {formatTime(msg.timestamp)}
                </span>
              </div>
              <div className="sd-ws-msg-preview">{preview}</div>
            </div>
          );
        })}
      </div>

      {/* Expanded message detail */}
      {expandedMessage && (
        <WebSocketMessageDetail
          message={expandedMessage}
          binaryMode={binaryMode}
          onBinaryModeChange={setBinaryMode}
          jsonPretty={jsonPretty}
          onJsonPrettyChange={setJsonPretty}
          onClose={() => setExpandedId(null)}
        />
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

// ---------------------------------------------------------------------------
// Detail Sub-Component
// ---------------------------------------------------------------------------

interface WebSocketMessageDetailProps {
  message: MessageEntry;
  binaryMode: BinaryDisplayMode;
  onBinaryModeChange: (mode: BinaryDisplayMode) => void;
  jsonPretty: boolean;
  onJsonPrettyChange: (pretty: boolean) => void;
  onClose: () => void;
}

function WebSocketMessageDetail({
  message,
  binaryMode,
  onBinaryModeChange,
  jsonPretty,
  onJsonPrettyChange,
  onClose,
}: WebSocketMessageDetailProps) {
  const opcode = message.metadata?.opcode ?? "";
  const isBinary = message.body_encoding === "base64";
  const isClose = opcode === WS_OPCODE.CLOSE;
  const size = bodyByteSize(message.body, message.body_encoding);
  const closeInfo = isClose
    ? parseCloseFrame(message.body, message.body_encoding)
    : null;

  // Detect JSON for text messages.
  const bodyIsJson = !isBinary && isJsonString(message.body);

  // Compute displayed body content.
  const displayContent = useMemo<string>(() => {
    if (!message.body) return "";

    if (isBinary) {
      if (binaryMode === "hex") {
        return hexDump(message.body);
      }
      return message.body; // raw base64
    }

    // Text message.
    if (bodyIsJson && jsonPretty) {
      return prettyJson(message.body) ?? message.body;
    }
    return message.body;
  }, [message.body, isBinary, binaryMode, bodyIsJson, jsonPretty]);

  return (
    <div className="sd-message-detail sd-ws-detail">
      <div className="sd-message-detail-header">
        <div className="sd-ws-detail-title">
          <span className="sd-message-detail-title">
            Message #{message.sequence}
          </span>
          <Badge
            variant={opcodeBadgeVariant(opcode)}
          >
            {opcodeLabel(opcode)}
          </Badge>
          <span
            className={`sd-ws-msg-direction ${message.direction === "send" ? "sd-ws-msg-direction--send" : "sd-ws-msg-direction--recv"}`}
          >
            {message.direction === "send" ? "\u2191 Send" : "\u2193 Receive"}
          </span>
          <span className="sd-ws-detail-size">{formatSize(size)}</span>
        </div>
        <Button variant="ghost" size="sm" onClick={onClose}>
          Close
        </Button>
      </div>

      {/* Close frame info */}
      {isClose && closeInfo && (
        <div className="sd-ws-close-info">
          <div className="sd-meta-item">
            <span className="sd-meta-label">Status Code</span>
            <span className="sd-meta-value">
              {closeInfo.code} ({closeInfo.codeDescription})
            </span>
          </div>
          {closeInfo.reason && (
            <div className="sd-meta-item">
              <span className="sd-meta-label">Reason</span>
              <span className="sd-meta-value">{closeInfo.reason}</span>
            </div>
          )}
        </div>
      )}

      {/* Metadata */}
      {message.metadata &&
        Object.keys(message.metadata).length > 0 && (
          <div className="sd-message-detail-meta">
            {Object.entries(message.metadata).map(([key, value]) => (
              <div key={key} className="sd-meta-item">
                <span className="sd-meta-label">{key}</span>
                <span className="sd-meta-value">{value}</span>
              </div>
            ))}
          </div>
        )}

      {/* Body */}
      {message.body && (
        <div className="sd-message-detail-section">
          <div className="sd-ws-body-header">
            <span className="sd-message-detail-section-title">Body</span>
            {/* Mode toggles */}
            <div className="sd-ws-body-controls">
              {isBinary && (
                <div className="sd-body-mode-selector">
                  <button
                    className={`sd-body-mode-btn ${binaryMode === "hex" ? "sd-body-mode-btn--active" : ""}`}
                    onClick={() => onBinaryModeChange("hex")}
                  >
                    Hex
                  </button>
                  <button
                    className={`sd-body-mode-btn ${binaryMode === "base64" ? "sd-body-mode-btn--active" : ""}`}
                    onClick={() => onBinaryModeChange("base64")}
                  >
                    Base64
                  </button>
                </div>
              )}
              {!isBinary && bodyIsJson && (
                <div className="sd-body-mode-selector">
                  <button
                    className={`sd-body-mode-btn ${jsonPretty ? "sd-body-mode-btn--active" : ""}`}
                    onClick={() => onJsonPrettyChange(true)}
                  >
                    Pretty
                  </button>
                  <button
                    className={`sd-body-mode-btn ${!jsonPretty ? "sd-body-mode-btn--active" : ""}`}
                    onClick={() => onJsonPrettyChange(false)}
                  >
                    Raw
                  </button>
                </div>
              )}
              {!isBinary && (
                <button
                  className="sd-body-mode-btn"
                  onClick={() => {
                    // Toggle hex dump of text
                    if (binaryMode === "hex") {
                      onBinaryModeChange("base64");
                    } else {
                      onBinaryModeChange("hex");
                    }
                  }}
                  title="View as hex dump"
                  style={{ display: "none" }}
                >
                  Hex
                </button>
              )}
            </div>
          </div>
          <pre
            className={`sd-body-content ${binaryMode === "hex" && isBinary ? "sd-body-content--hex" : ""}`}
          >
            {displayContent}
          </pre>
        </div>
      )}

      {!message.body && (
        <div className="sd-empty-section">Empty body</div>
      )}
    </div>
  );
}
