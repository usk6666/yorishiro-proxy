import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { useDialog } from "../../components/ui/Dialog.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { useToast } from "../../components/ui/Toast.js";
import { generateCurl } from "../../lib/export/curl.js";
import { buildHar, downloadHar } from "../../lib/export/har.js";
import {
  isStreamingFlow,
  pickFlowDetailKind,
} from "../../lib/mcp/dispatch.js";
import { useManage, useQuery } from "../../lib/mcp/hooks.js";
import type {
  FlowDetailResult,
  MessageEntry,
} from "../../lib/mcp/types.js";
import { FlowDetailGRPCMessage } from "./FlowDetailGRPCMessage.js";
import { FlowDetailHTTPMessage } from "./FlowDetailHTTPMessage.js";
import "./FlowDetailPage.css";
import { FlowDetailRawMessage } from "./FlowDetailRawMessage.js";
import { FlowDetailSSEMessage } from "./FlowDetailSSEMessage.js";
import { FlowDetailWSMessage } from "./FlowDetailWSMessage.js";
import { Http2Badge, Http2Info, Http2StreamGroups } from "./Http2Info.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Return a shortened flow ID for display (first 8 characters). */
function shortId(id: string): string {
  if (!id) return "";
  return id.length > 8 ? id.slice(0, 8) : id;
}

/** Get the Badge variant for a protocol. */
function protocolVariant(
  protocol: string,
): "default" | "success" | "warning" | "danger" | "info" {
  switch (protocol) {
    case "HTTP/1.x":
      return "default";
    case "HTTPS":
      return "success";
    case "WebSocket":
      return "info";
    case "HTTP/2":
      return "info";
    case "gRPC":
    case "gRPC-Web":
      return "warning";
    case "TCP":
      return "danger";
    default:
      return "default";
  }
}

/** Get the CSS class for a status code. */
function statusCodeClass(code: number): string {
  if (code >= 200 && code < 300) return "sd-status--2xx";
  if (code >= 300 && code < 400) return "sd-status--3xx";
  if (code >= 400 && code < 500) return "sd-status--4xx";
  if (code >= 500 && code < 600) return "sd-status--5xx";
  return "sd-status--other";
}

/** Format duration in milliseconds to a human-readable string. */
function formatDuration(ms: number): string {
  if (ms < 1) return "<1ms";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

/** Format an ISO timestamp to a readable local string. */
function formatTimestamp(ts: string): string {
  if (!ts) return "";
  try {
    const d = new Date(ts);
    return d.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return ts;
  }
}

/** Get the Badge variant for a flow state. */
function stateVariant(
  state: string,
): "default" | "success" | "warning" | "danger" | "info" {
  switch (state) {
    case "complete":
      return "success";
    case "active":
      return "info";
    case "error":
      return "danger";
    default:
      return "default";
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function FlowDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { showDialog } = useDialog();
  const { manage, loading: executeLoading } = useManage();

  // Messages pagination state (for streaming flows)
  const [messagesOffset, setMessagesOffset] = useState(0);
  const messagesLimit = 50;

  // Fetch flow detail
  const {
    data: flowData,
    loading: flowLoading,
    error: flowError,
    refetch: refetchFlow,
  } = useQuery("flow", {
    id: id ?? "",
    enabled: !!id,
  });

  // Fetch messages for streaming flows
  const {
    data: messagesData,
    loading: messagesLoading,
    refetch: refetchMessages,
  } = useQuery("messages", {
    id: id ?? "",
    limit: messagesLimit,
    offset: messagesOffset,
    enabled: !!id && !!flowData && isStreamingFlow(flowData),
  });

  // Refetch messages when offset changes
  const prevOffsetKey = useRef("");
  useEffect(() => {
    const key = JSON.stringify({ offset: messagesOffset });
    if (prevOffsetKey.current && prevOffsetKey.current !== key) {
      refetchMessages();
    }
    prevOffsetKey.current = key;
  }, [messagesOffset, refetchMessages]);

  // Delete flow handler
  const handleDelete = useCallback(async () => {
    if (!id) return;

    const confirmed = await showDialog({
      title: "Delete Flow",
      message:
        "Are you sure you want to delete this flow? This action cannot be undone.",
      variant: "confirm",
      confirmLabel: "Delete",
      confirmVariant: "danger",
    });
    if (!confirmed) return;

    try {
      await manage({
        action: "delete_flows",
        params: { flow_id: id, confirm: true },
      });
      addToast({ type: "success", message: "Flow deleted" });
      navigate("/");
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to delete flow: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [id, showDialog, manage, addToast, navigate]);

  // Navigate to resend view
  const handleResend = useCallback(() => {
    if (!id) return;
    navigate(`/resend/${id}`);
  }, [id, navigate]);

  // Navigate back to flows list
  const handleBack = useCallback(() => {
    navigate("/");
  }, [navigate]);

  // Copy request as cURL command
  const handleCopyCurl = useCallback(async () => {
    if (!flowData) return;
    try {
      const curl = generateCurl(flowData);
      await navigator.clipboard.writeText(curl);
      addToast({
        type: "success",
        message: "cURL command copied to clipboard",
      });
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to copy: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [flowData, addToast]);

  // Export flow as HAR file
  const handleExportHar = useCallback(() => {
    if (!flowData) return;
    try {
      const har = buildHar(flowData);
      const shortFlowId =
        flowData.id.length > 8 ? flowData.id.slice(0, 8) : flowData.id;
      downloadHar(har, `flow-${shortFlowId}.har`);
      addToast({ type: "success", message: "HAR file downloaded" });
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to export HAR: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [flowData, addToast]);

  // Message page navigation
  const handleMessagesPageChange = useCallback((newOffset: number) => {
    setMessagesOffset(newOffset);
  }, []);

  // Loading state
  if (flowLoading && !flowData) {
    return (
      <div className="page flow-detail-page">
        <div className="sd-loading">
          <Spinner size="lg" />
        </div>
      </div>
    );
  }

  // Error state
  if (flowError) {
    return (
      <div className="page flow-detail-page">
        <div className="sd-error">
          Failed to load flow: {flowError.message}
        </div>
        <Button variant="secondary" size="sm" onClick={handleBack}>
          Back to Flows
        </Button>
      </div>
    );
  }

  // No data
  if (!flowData) {
    return (
      <div className="page flow-detail-page">
        <div className="sd-empty">Flow not found.</div>
        <Button variant="secondary" size="sm" onClick={handleBack}>
          Back to Flows
        </Button>
      </div>
    );
  }

  const streaming = isStreamingFlow(flowData);
  const messages: MessageEntry[] =
    messagesData?.messages ?? flowData.message_preview ?? [];
  const totalMessages = messagesData?.total ?? flowData.message_count ?? 0;
  const flowKind = pickFlowDetailKind(flowData.protocol);
  const flowSafe: FlowDetailResult = flowData;
  const responseStatus = flowSafe.response_status_code ?? 0;
  const protoTags = flowSafe.tags ?? {};
  const anomaliesPresent = !!flowSafe.anomalies?.length;

  return (
    <div className="page flow-detail-page">
      {/* Back navigation */}
      <div className="sd-back-row">
        <Button variant="ghost" size="sm" onClick={handleBack}>
          &larr; Flows
        </Button>
      </div>

      {/* Flow summary header */}
      <div className="sd-header">
        <div className="sd-header-top">
          <div className="sd-header-info">
            <div className="sd-header-title-row">
              <h1 className="page-title">Flow Detail</h1>
              <span className="sd-flow-id">{shortId(flowSafe.id ?? "")}</span>
            </div>
            <div className="sd-url-display" title={flowSafe.url}>
              {flowSafe.method && (
                <span className="sd-method">{flowSafe.method}</span>
              )}
              <span className="sd-url">{flowSafe.url}</span>
            </div>
          </div>
          <div className="sd-header-actions">
            <Button variant="primary" size="sm" onClick={handleResend}>
              Resend
            </Button>
            <Button variant="secondary" size="sm" onClick={handleCopyCurl}>
              Copy as cURL
            </Button>
            <Button variant="secondary" size="sm" onClick={handleExportHar}>
              Export HAR
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={handleDelete}
              disabled={executeLoading}
            >
              Delete
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => refetchFlow()}
            >
              Refresh
            </Button>
          </div>
        </div>

        {/* Metadata badges */}
        <div className="sd-meta">
          <div className="sd-meta-item">
            <span className="sd-meta-label">Protocol</span>
            <Badge variant={protocolVariant(flowSafe.protocol ?? "")}>
              {flowSafe.protocol || "unknown"}
            </Badge>
            {flowSafe.protocol === "HTTP/2" && <Http2Badge flow={flowSafe} />}
          </div>
          {responseStatus > 0 && (
            <div className="sd-meta-item">
              <span className="sd-meta-label">Status</span>
              <span className={statusCodeClass(responseStatus)}>
                {responseStatus}
              </span>
            </div>
          )}
          <div className="sd-meta-item">
            <span className="sd-meta-label">Duration</span>
            <span className="sd-meta-value">
              {formatDuration(flowSafe.duration_ms ?? 0)}
            </span>
          </div>
          {(flowSafe.send_ms != null ||
            flowSafe.wait_ms != null ||
            flowSafe.receive_ms != null) && (
            <div className="sd-meta-item">
              <span className="sd-meta-label">Timing</span>
              <span className="sd-meta-value sd-timing-breakdown">
                {flowSafe.send_ms != null && (
                  <span className="sd-timing-part" title="Request send time">
                    Send: {formatDuration(flowSafe.send_ms)}
                  </span>
                )}
                {flowSafe.wait_ms != null && (
                  <span
                    className="sd-timing-part"
                    title="Server processing wait time"
                  >
                    Wait: {formatDuration(flowSafe.wait_ms)}
                  </span>
                )}
                {flowSafe.receive_ms != null && (
                  <span
                    className="sd-timing-part"
                    title="Response receive time"
                  >
                    Recv: {formatDuration(flowSafe.receive_ms)}
                  </span>
                )}
              </span>
            </div>
          )}
          <div className="sd-meta-item">
            <span className="sd-meta-label">Timestamp</span>
            <span className="sd-meta-value">
              {formatTimestamp(flowSafe.timestamp ?? "")}
            </span>
          </div>
          <div className="sd-meta-item">
            <span className="sd-meta-label">Type</span>
            <Badge variant="default">{flowSafe.flow_type || "unknown"}</Badge>
          </div>
          <div className="sd-meta-item">
            <span className="sd-meta-label">State</span>
            <Badge variant={stateVariant(flowSafe.state ?? "")}>
              {flowSafe.state || "unknown"}
            </Badge>
          </div>
          {flowSafe.blocked_by && (
            <div className="sd-meta-item">
              <span className="sd-meta-label">Blocked By</span>
              <Badge variant="warning">{flowSafe.blocked_by}</Badge>
            </div>
          )}
          {(flowSafe.message_count ?? 0) > 0 && (
            <div className="sd-meta-item">
              <span className="sd-meta-label">Messages</span>
              <span className="sd-meta-value">{flowSafe.message_count}</span>
            </div>
          )}
        </div>

        {/* Anomalies */}
        {flowSafe.anomalies && flowSafe.anomalies.length > 0 && (
          <div className="sd-anomalies">
            <span className="sd-anomalies-label">Anomalies</span>
            <div className="sd-anomalies-list">
              {flowSafe.anomalies.map((anomaly, idx) => (
                <div
                  key={`${anomaly.type}-${idx}`}
                  className="sd-anomaly-item"
                >
                  <Badge variant="danger">{anomaly.type}</Badge>
                  {anomaly.detail && (
                    <span className="sd-anomaly-detail">{anomaly.detail}</span>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tags (excluding smuggling:* which are shown as anomalies above, only when anomalies are present) */}
        {Object.keys(protoTags).filter((k) =>
          anomaliesPresent ? !k.startsWith("smuggling:") : true,
        ).length > 0 && (
          <div className="sd-tags">
            {Object.entries(protoTags)
              .filter(([key]) =>
                anomaliesPresent ? !key.startsWith("smuggling:") : true,
              )
              .map(([key, value]) => (
                <Badge key={key} variant="info">
                  {key}: {value}
                </Badge>
              ))}
          </div>
        )}

        {/* Protocol summary */}
        {flowSafe.protocol_summary &&
          Object.keys(flowSafe.protocol_summary).length > 0 && (
            <div className="sd-protocol-summary">
              {Object.entries(flowSafe.protocol_summary).map(
                ([key, value]) => (
                  <div key={key} className="sd-meta-item">
                    <span className="sd-meta-label">{key}</span>
                    <span className="sd-meta-value">{value}</span>
                  </div>
                ),
              )}
            </div>
          )}

        {/* HTTP/2 specific info */}
        {flowSafe.protocol === "HTTP/2" && <Http2Info flow={flowSafe} />}

        {/* Connection info */}
        {flowSafe.conn_info && (
          <div className="sd-conn-info">
            {flowSafe.conn_info.client_addr && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">Client</span>
                <span className="sd-meta-value">
                  {flowSafe.conn_info.client_addr}
                </span>
              </div>
            )}
            {flowSafe.conn_info.server_addr && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">Server</span>
                <span className="sd-meta-value">
                  {flowSafe.conn_info.server_addr}
                </span>
              </div>
            )}
            {flowSafe.conn_info.tls_version && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">TLS</span>
                <span className="sd-meta-value">
                  {flowSafe.conn_info.tls_version}
                </span>
              </div>
            )}
            {flowSafe.conn_info.tls_alpn && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">ALPN</span>
                <span className="sd-meta-value">
                  {flowSafe.conn_info.tls_alpn}
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* HTTP/2 Stream Grouping (for multi-stream message previews) */}
      {flowSafe.protocol === "HTTP/2" && messages.length > 0 && (
        <div className="sd-section">
          <Http2StreamGroups messages={messages} />
        </div>
      )}

      {/* Per-protocol body dispatch */}
      {flowKind === "ws" && (
        <>
          <div className="sd-section">
            <h2 className="sd-section-title">Messages</h2>
            <FlowDetailWSMessage
              messages={messages}
              total={totalMessages}
              offset={messagesOffset}
              limit={messagesLimit}
              loading={messagesLoading}
              onPageChange={handleMessagesPageChange}
            />
          </div>
          <FlowDetailHTTPMessage flow={flowSafe} />
        </>
      )}

      {flowKind === "grpc" && (
        <>
          <FlowDetailGRPCMessage
            flow={flowSafe}
            messages={messages}
            total={totalMessages}
            offset={messagesOffset}
            limit={messagesLimit}
            loading={messagesLoading}
            onPageChange={handleMessagesPageChange}
            showMessageTimeline={streaming}
          />
          <FlowDetailHTTPMessage flow={flowSafe} />
        </>
      )}

      {flowKind === "sse" && (
        <>
          <FlowDetailSSEMessage
            flow={flowSafe}
            messages={messages}
            total={totalMessages}
            offset={messagesOffset}
            limit={messagesLimit}
            loading={messagesLoading}
            onPageChange={handleMessagesPageChange}
          />
          <FlowDetailHTTPMessage flow={flowSafe} />
        </>
      )}

      {flowKind === "raw" && (
        <FlowDetailRawMessage
          flow={flowSafe}
          messages={messages}
          total={totalMessages}
          offset={messagesOffset}
          limit={messagesLimit}
          loading={messagesLoading}
          onPageChange={handleMessagesPageChange}
          showMessageTimeline={streaming}
        />
      )}

      {flowKind === "http" && <FlowDetailHTTPMessage flow={flowSafe} />}
    </div>
  );
}
