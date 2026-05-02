/**
 * FlowDetailSSEMessage — Renders the Server-Sent Events panel for a flow.
 *
 * The SSE response body itself isn't fully buffered by the proxy (the body
 * was streamed directly to the client), so the structured view delegates to
 * FlowDetailHTTPMessage for headers and uses the message preview for the
 * per-event timeline when one was recorded.
 */

import type { FlowDetailResult, MessageEntry } from "../../lib/mcp/types.js";
import "./FlowDetailPage.css";
import { MessageList } from "./MessageList.js";

export interface FlowDetailSSEMessageProps {
  flow: FlowDetailResult;
  messages: MessageEntry[];
  total: number;
  offset: number;
  limit: number;
  loading: boolean;
  onPageChange: (offset: number) => void;
}

export function FlowDetailSSEMessage({
  flow,
  messages,
  total,
  offset,
  limit,
  loading,
  onPageChange,
}: FlowDetailSSEMessageProps) {
  const safeMessages = messages ?? [];
  if (safeMessages.length === 0) {
    return (
      <div className="sd-section">
        <h2 className="sd-section-title">SSE Events</h2>
        <div className="sd-no-response">
          No SSE events recorded. The response body was streamed directly to
          the client; only the upgrade headers are available above.
        </div>
      </div>
    );
  }
  return (
    <div className="sd-section">
      <h2 className="sd-section-title">SSE Events</h2>
      <MessageList
        messages={safeMessages}
        total={total ?? 0}
        offset={offset}
        limit={limit}
        loading={loading}
        onPageChange={onPageChange}
        protocol={flow.protocol}
      />
    </div>
  );
}
