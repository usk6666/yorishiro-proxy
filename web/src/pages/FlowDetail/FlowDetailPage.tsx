import { useState, useCallback, useEffect, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useManage } from "../../lib/mcp/hooks.js";
import { useToast } from "../../components/ui/Toast.js";
import { useDialog } from "../../components/ui/Dialog.js";
import type {
  FlowDetailResult,
  MessageEntry,
} from "../../lib/mcp/types.js";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Tabs } from "../../components/ui/Tabs.js";
import { HeadersTable } from "./HeadersTable.js";
import { BodyViewer } from "./BodyViewer.js";
import { MessageList } from "./MessageList.js";
import { generateCurl } from "../../lib/export/curl.js";
import { buildHar, downloadHar } from "../../lib/export/har.js";
import "./FlowDetailPage.css";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REQUEST_TABS = [
  { id: "headers", label: "Headers" },
  { id: "body", label: "Body" },
];

const RESPONSE_TABS = [
  { id: "headers", label: "Headers" },
  { id: "body", label: "Body" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Return a shortened flow ID for display (first 8 characters). */
function shortId(id: string): string {
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
function stateVariant(state: string): "default" | "success" | "warning" | "danger" | "info" {
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

/** Whether a flow is a streaming type (WebSocket, gRPC server/client streaming). */
function isStreamingFlow(flow: FlowDetailResult): boolean {
  return flow.flow_type !== "unary";
}

/** Whether a flow has a response (error/drop flows may not have one). */
function hasResponse(flow: FlowDetailResult): boolean {
  return (
    flow.response_status_code > 0 ||
    (flow.response_headers != null &&
      Object.keys(flow.response_headers).length > 0)
  );
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

  // Tabs state
  const [requestTab, setRequestTab] = useState("headers");
  const [responseTab, setResponseTab] = useState("headers");

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
      message: "Are you sure you want to delete this flow? This action cannot be undone.",
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
      addToast({ type: "success", message: "cURL command copied to clipboard" });
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
      const shortFlowId = flowData.id.length > 8 ? flowData.id.slice(0, 8) : flowData.id;
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
  const messages: MessageEntry[] = messagesData?.messages ?? flowData.message_preview ?? [];
  const totalMessages = messagesData?.total ?? flowData.message_count;

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
              <span className="sd-flow-id">{shortId(flowData.id)}</span>
            </div>
            <div className="sd-url-display" title={flowData.url}>
              {flowData.method && (
                <span className="sd-method">{flowData.method}</span>
              )}
              <span className="sd-url">{flowData.url}</span>
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
            <Button variant="secondary" size="sm" onClick={() => refetchFlow()}>
              Refresh
            </Button>
          </div>
        </div>

        {/* Metadata badges */}
        <div className="sd-meta">
          <div className="sd-meta-item">
            <span className="sd-meta-label">Protocol</span>
            <Badge variant={protocolVariant(flowData.protocol)}>
              {flowData.protocol}
            </Badge>
          </div>
          {flowData.response_status_code > 0 && (
            <div className="sd-meta-item">
              <span className="sd-meta-label">Status</span>
              <span className={statusCodeClass(flowData.response_status_code)}>
                {flowData.response_status_code}
              </span>
            </div>
          )}
          <div className="sd-meta-item">
            <span className="sd-meta-label">Duration</span>
            <span className="sd-meta-value">
              {formatDuration(flowData.duration_ms)}
            </span>
          </div>
          <div className="sd-meta-item">
            <span className="sd-meta-label">Timestamp</span>
            <span className="sd-meta-value">
              {formatTimestamp(flowData.timestamp)}
            </span>
          </div>
          <div className="sd-meta-item">
            <span className="sd-meta-label">Type</span>
            <Badge variant="default">{flowData.flow_type}</Badge>
          </div>
          <div className="sd-meta-item">
            <span className="sd-meta-label">State</span>
            <Badge variant={stateVariant(flowData.state)}>{flowData.state}</Badge>
          </div>
          {flowData.blocked_by && (
            <div className="sd-meta-item">
              <span className="sd-meta-label">Blocked By</span>
              <Badge variant="warning">{flowData.blocked_by}</Badge>
            </div>
          )}
          {flowData.message_count > 0 && (
            <div className="sd-meta-item">
              <span className="sd-meta-label">Messages</span>
              <span className="sd-meta-value">{flowData.message_count}</span>
            </div>
          )}
        </div>

        {/* Tags */}
        {flowData.tags && Object.keys(flowData.tags).length > 0 && (
          <div className="sd-tags">
            {Object.entries(flowData.tags).map(([key, value]) => (
              <Badge key={key} variant="info">
                {key}: {value}
              </Badge>
            ))}
          </div>
        )}

        {/* Protocol summary */}
        {flowData.protocol_summary &&
          Object.keys(flowData.protocol_summary).length > 0 && (
            <div className="sd-protocol-summary">
              {Object.entries(flowData.protocol_summary).map(([key, value]) => (
                <div key={key} className="sd-meta-item">
                  <span className="sd-meta-label">{key}</span>
                  <span className="sd-meta-value">{value}</span>
                </div>
              ))}
            </div>
          )}

        {/* Connection info */}
        {flowData.conn_info && (
          <div className="sd-conn-info">
            {flowData.conn_info.client_addr && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">Client</span>
                <span className="sd-meta-value">
                  {flowData.conn_info.client_addr}
                </span>
              </div>
            )}
            {flowData.conn_info.server_addr && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">Server</span>
                <span className="sd-meta-value">
                  {flowData.conn_info.server_addr}
                </span>
              </div>
            )}
            {flowData.conn_info.tls_version && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">TLS</span>
                <span className="sd-meta-value">
                  {flowData.conn_info.tls_version}
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Streaming flow: Messages list */}
      {streaming && (
        <div className="sd-section">
          <h2 className="sd-section-title">Messages</h2>
          <MessageList
            messages={messages}
            total={totalMessages}
            offset={messagesOffset}
            limit={messagesLimit}
            loading={messagesLoading}
            onPageChange={handleMessagesPageChange}
            protocol={flowData.protocol}
          />
        </div>
      )}

      {/* Variant diff: original vs modified request */}
      {flowData.original_request && (
        <div className="sd-section">
          <h2 className="sd-section-title">Request Modification (Original vs Modified)</h2>
          <div className="sd-panels">
            {/* Original request */}
            <div className="sd-panel">
              <div className="sd-panel-header">
                <span className="sd-panel-title">Original Request</span>
                <Badge variant="default">original</Badge>
              </div>
              <Tabs
                tabs={REQUEST_TABS}
                activeTab={requestTab}
                onTabChange={setRequestTab}
              >
                {requestTab === "headers" && (
                  <HeadersTable headers={flowData.original_request.headers} />
                )}
                {requestTab === "body" && (
                  <BodyViewer
                    body={flowData.original_request.body}
                    encoding={flowData.original_request.body_encoding}
                    truncated={false}
                    headers={flowData.original_request.headers}
                  />
                )}
              </Tabs>
            </div>

            {/* Modified request */}
            <div className="sd-panel">
              <div className="sd-panel-header">
                <span className="sd-panel-title">Modified Request</span>
                <Badge variant="warning">modified</Badge>
              </div>
              <Tabs
                tabs={REQUEST_TABS}
                activeTab={requestTab}
                onTabChange={setRequestTab}
              >
                {requestTab === "headers" && (
                  <HeadersTable headers={flowData.request_headers} />
                )}
                {requestTab === "body" && (
                  <BodyViewer
                    body={flowData.request_body}
                    encoding={flowData.request_body_encoding}
                    truncated={flowData.request_body_truncated}
                    headers={flowData.request_headers}
                  />
                )}
              </Tabs>
            </div>
          </div>
        </div>
      )}

      {/* Request / Response panels */}
      <div className="sd-panels">
        {/* Request panel (shown when no variant diff) */}
        {!flowData.original_request && (
          <div className="sd-panel">
            <div className="sd-panel-header">
              <span className="sd-panel-title">Request</span>
            </div>
            <Tabs
              tabs={REQUEST_TABS}
              activeTab={requestTab}
              onTabChange={setRequestTab}
            >
              {requestTab === "headers" && (
                <HeadersTable headers={flowData.request_headers} />
              )}
              {requestTab === "body" && (
                <BodyViewer
                  body={flowData.request_body}
                  encoding={flowData.request_body_encoding}
                  truncated={flowData.request_body_truncated}
                  headers={flowData.request_headers}
                />
              )}
            </Tabs>
          </div>
        )}

        {/* Response panel */}
        <div className={flowData.original_request ? "sd-panel sd-panel--full-width" : "sd-panel"}>
          <div className="sd-panel-header">
            <span className="sd-panel-title">Response</span>
            {flowData.response_status_code > 0 && (
              <Badge
                variant={
                  flowData.response_status_code < 300
                    ? "success"
                    : flowData.response_status_code < 400
                      ? "info"
                      : flowData.response_status_code < 500
                        ? "warning"
                        : "danger"
                }
              >
                {flowData.response_status_code}
              </Badge>
            )}
            {!hasResponse(flowData) && (
              <Badge variant="danger">No Response</Badge>
            )}
          </div>
          {hasResponse(flowData) ? (
            <Tabs
              tabs={RESPONSE_TABS}
              activeTab={responseTab}
              onTabChange={setResponseTab}
            >
              {responseTab === "headers" && (
                <HeadersTable headers={flowData.response_headers} />
              )}
              {responseTab === "body" && (
                <BodyViewer
                  body={flowData.response_body}
                  encoding={flowData.response_body_encoding}
                  truncated={flowData.response_body_truncated}
                  headers={flowData.response_headers}
                />
              )}
            </Tabs>
          ) : (
            <div className="sd-no-response">
              {flowData.state === "error"
                ? "This flow ended with an error. No response was received from the upstream server."
                : flowData.state === "active"
                  ? "This flow is still active. The response has not been received yet."
                  : flowData.blocked_by === "intercept_drop"
                    ? "This request was dropped by an intercept rule. No response was generated."
                    : "No response data available for this flow."}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
