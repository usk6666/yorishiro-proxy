/**
 * FlowDetailGRPCMessage — Renders the gRPC structured panel and per-frame
 * message timeline. Covers both gRPC and gRPC-Web flows.
 *
 * Reuses the existing GrpcPanel for the structured Start/Data/End view and
 * the generic MessageList for streaming RPCs.
 */

import type { FlowDetailResult, MessageEntry } from "../../lib/mcp/types.js";
import "./FlowDetailPage.css";
import { GrpcPanel } from "./GrpcPanel.js";
import { MessageList } from "./MessageList.js";

export interface FlowDetailGRPCMessageProps {
  flow: FlowDetailResult;
  messages: MessageEntry[];
  total: number;
  offset: number;
  limit: number;
  loading: boolean;
  onPageChange: (offset: number) => void;
  /** When false, the streaming message list is hidden (e.g. unary RPCs). */
  showMessageTimeline: boolean;
}

export function FlowDetailGRPCMessage({
  flow,
  messages,
  total,
  offset,
  limit,
  loading,
  onPageChange,
  showMessageTimeline,
}: FlowDetailGRPCMessageProps) {
  return (
    <>
      <GrpcPanel flow={flow} />
      {showMessageTimeline && (
        <div className="sd-section">
          <h2 className="sd-section-title">Messages</h2>
          <MessageList
            messages={messages ?? []}
            total={total ?? 0}
            offset={offset}
            limit={limit}
            loading={loading}
            onPageChange={onPageChange}
            protocol={flow.protocol}
          />
        </div>
      )}
    </>
  );
}
