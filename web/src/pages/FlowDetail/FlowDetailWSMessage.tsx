/**
 * FlowDetailWSMessage — Renders the WebSocket message panel for a flow.
 *
 * The HTTP/1.x upgrade request/response are still meaningful for inspection,
 * so the parent FlowDetailPage delegates header display to FlowDetailHTTPMessage
 * and this component focuses on the per-frame timeline.
 */

import type { MessageEntry } from "../../lib/mcp/types.js";
import "./FlowDetailPage.css";
import { WebSocketMessageList } from "./WebSocketMessageList.js";

export interface FlowDetailWSMessageProps {
  messages: MessageEntry[];
  total: number;
  offset: number;
  limit: number;
  loading: boolean;
  onPageChange: (offset: number) => void;
}

export function FlowDetailWSMessage({
  messages,
  total,
  offset,
  limit,
  loading,
  onPageChange,
}: FlowDetailWSMessageProps) {
  return (
    <WebSocketMessageList
      messages={messages ?? []}
      total={total ?? 0}
      offset={offset}
      limit={limit}
      loading={loading}
      onPageChange={onPageChange}
    />
  );
}
