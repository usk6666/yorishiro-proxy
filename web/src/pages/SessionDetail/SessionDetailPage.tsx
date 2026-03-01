import { useState, useCallback, useEffect, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useExecute } from "../../lib/mcp/hooks.js";
import { useToast } from "../../components/ui/Toast.js";
import type {
  SessionDetailResult,
  MessageEntry,
} from "../../lib/mcp/types.js";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Tabs } from "../../components/ui/Tabs.js";
import { HeadersTable } from "./HeadersTable.js";
import { BodyViewer } from "./BodyViewer.js";
import { MessageList } from "./MessageList.js";
import "./SessionDetailPage.css";

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

/** Return a shortened session ID for display (first 8 characters). */
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

/** Whether a session is a streaming type (WebSocket, gRPC server/client streaming). */
function isStreamingSession(session: SessionDetailResult): boolean {
  return session.session_type !== "unary";
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SessionDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { execute, loading: executeLoading } = useExecute();

  // Tabs state
  const [requestTab, setRequestTab] = useState("headers");
  const [responseTab, setResponseTab] = useState("headers");

  // Messages pagination state (for streaming sessions)
  const [messagesOffset, setMessagesOffset] = useState(0);
  const messagesLimit = 50;

  // Fetch session detail
  const {
    data: session,
    loading: sessionLoading,
    error: sessionError,
    refetch: refetchSession,
  } = useQuery("session", {
    id: id ?? "",
    enabled: !!id,
  });

  // Fetch messages for streaming sessions
  const {
    data: messagesData,
    loading: messagesLoading,
    refetch: refetchMessages,
  } = useQuery("messages", {
    id: id ?? "",
    limit: messagesLimit,
    offset: messagesOffset,
    enabled: !!id && !!session && isStreamingSession(session),
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

  // Delete session handler
  const handleDelete = useCallback(async () => {
    if (!id) return;

    const confirmed = window.confirm(
      "Are you sure you want to delete this session? This action cannot be undone.",
    );
    if (!confirmed) return;

    try {
      await execute({
        action: "delete_sessions",
        params: { session_id: id, confirm: true },
      });
      addToast({ type: "success", message: "Session deleted" });
      navigate("/");
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to delete session: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [id, execute, addToast, navigate]);

  // Navigate to resend view
  const handleResend = useCallback(() => {
    if (!id) return;
    navigate(`/resend/${id}`);
  }, [id, navigate]);

  // Navigate back to sessions list
  const handleBack = useCallback(() => {
    navigate("/");
  }, [navigate]);

  // Message page navigation
  const handleMessagesPageChange = useCallback((newOffset: number) => {
    setMessagesOffset(newOffset);
  }, []);

  // Loading state
  if (sessionLoading && !session) {
    return (
      <div className="page session-detail-page">
        <div className="sd-loading">
          <Spinner size="lg" />
        </div>
      </div>
    );
  }

  // Error state
  if (sessionError) {
    return (
      <div className="page session-detail-page">
        <div className="sd-error">
          Failed to load session: {sessionError.message}
        </div>
        <Button variant="secondary" size="sm" onClick={handleBack}>
          Back to Sessions
        </Button>
      </div>
    );
  }

  // No data
  if (!session) {
    return (
      <div className="page session-detail-page">
        <div className="sd-empty">Session not found.</div>
        <Button variant="secondary" size="sm" onClick={handleBack}>
          Back to Sessions
        </Button>
      </div>
    );
  }

  const streaming = isStreamingSession(session);
  const messages: MessageEntry[] = messagesData?.messages ?? session.message_preview ?? [];
  const totalMessages = messagesData?.total ?? session.message_count;

  return (
    <div className="page session-detail-page">
      {/* Back navigation */}
      <div className="sd-back-row">
        <Button variant="ghost" size="sm" onClick={handleBack}>
          &larr; Sessions
        </Button>
      </div>

      {/* Session summary header */}
      <div className="sd-header">
        <div className="sd-header-top">
          <div className="sd-header-info">
            <div className="sd-header-title-row">
              <h1 className="page-title">Session Detail</h1>
              <span className="sd-session-id">{shortId(session.id)}</span>
            </div>
            <div className="sd-url-display" title={session.url}>
              {session.method && (
                <span className="sd-method">{session.method}</span>
              )}
              <span className="sd-url">{session.url}</span>
            </div>
          </div>
          <div className="sd-header-actions">
            <Button variant="primary" size="sm" onClick={handleResend}>
              Resend
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={handleDelete}
              disabled={executeLoading}
            >
              Delete
            </Button>
            <Button variant="secondary" size="sm" onClick={() => refetchSession()}>
              Refresh
            </Button>
          </div>
        </div>

        {/* Metadata badges */}
        <div className="sd-meta">
          <div className="sd-meta-item">
            <span className="sd-meta-label">Protocol</span>
            <Badge variant={protocolVariant(session.protocol)}>
              {session.protocol}
            </Badge>
          </div>
          {session.response_status_code > 0 && (
            <div className="sd-meta-item">
              <span className="sd-meta-label">Status</span>
              <span className={statusCodeClass(session.response_status_code)}>
                {session.response_status_code}
              </span>
            </div>
          )}
          <div className="sd-meta-item">
            <span className="sd-meta-label">Duration</span>
            <span className="sd-meta-value">
              {formatDuration(session.duration_ms)}
            </span>
          </div>
          <div className="sd-meta-item">
            <span className="sd-meta-label">Timestamp</span>
            <span className="sd-meta-value">
              {formatTimestamp(session.timestamp)}
            </span>
          </div>
          <div className="sd-meta-item">
            <span className="sd-meta-label">Type</span>
            <Badge variant="default">{session.session_type}</Badge>
          </div>
          <div className="sd-meta-item">
            <span className="sd-meta-label">State</span>
            <Badge variant="default">{session.state}</Badge>
          </div>
          {session.message_count > 0 && (
            <div className="sd-meta-item">
              <span className="sd-meta-label">Messages</span>
              <span className="sd-meta-value">{session.message_count}</span>
            </div>
          )}
        </div>

        {/* Tags */}
        {session.tags && Object.keys(session.tags).length > 0 && (
          <div className="sd-tags">
            {Object.entries(session.tags).map(([key, value]) => (
              <Badge key={key} variant="info">
                {key}: {value}
              </Badge>
            ))}
          </div>
        )}

        {/* Protocol summary */}
        {session.protocol_summary &&
          Object.keys(session.protocol_summary).length > 0 && (
            <div className="sd-protocol-summary">
              {Object.entries(session.protocol_summary).map(([key, value]) => (
                <div key={key} className="sd-meta-item">
                  <span className="sd-meta-label">{key}</span>
                  <span className="sd-meta-value">{value}</span>
                </div>
              ))}
            </div>
          )}

        {/* Connection info */}
        {session.conn_info && (
          <div className="sd-conn-info">
            {session.conn_info.client_addr && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">Client</span>
                <span className="sd-meta-value">
                  {session.conn_info.client_addr}
                </span>
              </div>
            )}
            {session.conn_info.server_addr && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">Server</span>
                <span className="sd-meta-value">
                  {session.conn_info.server_addr}
                </span>
              </div>
            )}
            {session.conn_info.tls_version && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">TLS</span>
                <span className="sd-meta-value">
                  {session.conn_info.tls_version}
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Streaming session: Messages list */}
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
            protocol={session.protocol}
          />
        </div>
      )}

      {/* Request / Response panels */}
      <div className="sd-panels">
        {/* Request panel */}
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
              <HeadersTable headers={session.request_headers} />
            )}
            {requestTab === "body" && (
              <BodyViewer
                body={session.request_body}
                encoding={session.request_body_encoding}
                truncated={session.request_body_truncated}
                headers={session.request_headers}
              />
            )}
          </Tabs>
        </div>

        {/* Response panel */}
        <div className="sd-panel">
          <div className="sd-panel-header">
            <span className="sd-panel-title">Response</span>
            {session.response_status_code > 0 && (
              <Badge
                variant={
                  session.response_status_code < 300
                    ? "success"
                    : session.response_status_code < 400
                      ? "info"
                      : session.response_status_code < 500
                        ? "warning"
                        : "danger"
                }
              >
                {session.response_status_code}
              </Badge>
            )}
          </div>
          <Tabs
            tabs={RESPONSE_TABS}
            activeTab={responseTab}
            onTabChange={setResponseTab}
          >
            {responseTab === "headers" && (
              <HeadersTable headers={session.response_headers} />
            )}
            {responseTab === "body" && (
              <BodyViewer
                body={session.response_body}
                encoding={session.response_body_encoding}
                truncated={session.response_body_truncated}
                headers={session.response_headers}
              />
            )}
          </Tabs>
        </div>
      </div>
    </div>
  );
}
