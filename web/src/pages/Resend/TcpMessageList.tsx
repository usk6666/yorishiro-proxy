import type { MessageEntry } from "../../lib/mcp/types.js";
import { Badge } from "../../components/ui/Badge.js";
import "./TcpMessageList.css";

export interface TcpMessageListProps {
  messages: MessageEntry[];
}

/**
 * Read-only list of TCP messages in a flow.
 * Shows sequence, direction, size, and a preview of the data.
 */
export function TcpMessageList({ messages }: TcpMessageListProps) {
  if (messages.length === 0) {
    return (
      <div className="tcp-messages-empty">
        No messages in this flow.
      </div>
    );
  }

  return (
    <div className="tcp-messages">
      <div className="tcp-messages-description">
        Messages in this TCP flow. <code>tcp_replay</code> re-sends all
        client (send) messages in order.
      </div>
      <div className="tcp-messages-list">
        {messages.map((msg) => {
          const isSend = msg.direction === "send";
          const bodySize = msg.body ? msg.body.length : 0;
          const preview = getPreview(msg);

          return (
            <div
              key={msg.id}
              className={`tcp-message-entry ${isSend ? "tcp-message-entry--send" : "tcp-message-entry--receive"}`}
            >
              <span className="tcp-message-seq">#{msg.sequence}</span>
              <Badge variant={isSend ? "info" : "success"}>
                {isSend ? "SEND" : "RECV"}
              </Badge>
              <span className="tcp-message-size">
                {bodySize} {msg.body_encoding === "base64" ? "bytes (b64)" : "bytes"}
              </span>
              <span className="tcp-message-preview" title={preview}>
                {preview}
              </span>
              <span className="tcp-message-time">
                {new Date(msg.timestamp).toLocaleTimeString()}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/** Get a short text preview of a message's body. */
function getPreview(msg: MessageEntry): string {
  if (!msg.body) return "(empty)";

  if (msg.body_encoding === "base64") {
    // Try to decode and show printable chars, or show hex.
    try {
      const decoded = atob(msg.body);
      const printable = decoded.replace(/[^\x20-\x7E]/g, ".");
      return printable.length > 80 ? printable.slice(0, 80) + "..." : printable;
    } catch {
      return msg.body.slice(0, 40) + "...";
    }
  }

  return msg.body.length > 80 ? msg.body.slice(0, 80) + "..." : msg.body;
}
