/**
 * FlowDetailRawMessage — Renders the raw byte stream view for TCP / Raw flows.
 *
 * Raw flows have no L7 structured view by design (RFC-001 §"L7-first,
 * L4-capable"); the panel renders the recorded raw_request / raw_response
 * bytes via RawBytesViewer plus the per-direction message list for
 * progressive recording.
 */

import { Badge } from "../../components/ui/Badge.js";
import type { FlowDetailResult, MessageEntry } from "../../lib/mcp/types.js";
import "./FlowDetailPage.css";
import { MessageList } from "./MessageList.js";
import { RawBytesViewer } from "./RawBytesViewer.js";

export interface FlowDetailRawMessageProps {
  flow: FlowDetailResult;
  messages: MessageEntry[];
  total: number;
  offset: number;
  limit: number;
  loading: boolean;
  onPageChange: (offset: number) => void;
  /** When false, the per-message timeline is hidden (only raw bytes are shown). */
  showMessageTimeline: boolean;
}

export function FlowDetailRawMessage({
  flow,
  messages,
  total,
  offset,
  limit,
  loading,
  onPageChange,
  showMessageTimeline,
}: FlowDetailRawMessageProps) {
  const hasRawReq = !!flow.raw_request;
  const hasRawResp = !!flow.raw_response;

  return (
    <>
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

      <div className="sd-panels">
        <div className="sd-panel">
          <div className="sd-panel-header">
            <span className="sd-panel-title">Send (Raw Bytes)</span>
            <Badge variant="default">L4</Badge>
          </div>
          {hasRawReq ? (
            <RawBytesViewer
              rawBytes={flow.raw_request as string}
              label="Raw Request"
            />
          ) : (
            <div className="sd-no-response">
              No raw request bytes recorded for this flow.
            </div>
          )}
        </div>

        <div className="sd-panel">
          <div className="sd-panel-header">
            <span className="sd-panel-title">Receive (Raw Bytes)</span>
            <Badge variant="default">L4</Badge>
          </div>
          {hasRawResp ? (
            <RawBytesViewer
              rawBytes={flow.raw_response as string}
              label="Raw Response"
            />
          ) : (
            <div className="sd-no-response">
              {flow.state === "error"
                ? "This flow ended with an error. No response bytes were received."
                : flow.state === "active"
                  ? "This flow is still active. Response bytes have not been recorded yet."
                  : "No raw response bytes recorded for this flow."}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
