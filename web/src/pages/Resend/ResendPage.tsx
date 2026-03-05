import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Input } from "../../components/ui/Input.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Tabs } from "../../components/ui/Tabs.js";
import { useToast } from "../../components/ui/Toast.js";
import { useResend, useQuery } from "../../lib/mcp/hooks.js";
import type {
  BodyPatch,
  FlowDetailResult,
  MessageEntry,
  MessagesResult,
  RawPatch,
} from "../../lib/mcp/types.js";
import { BodyPatchEditor } from "./BodyPatchEditor.js";
import { HeaderEditor } from "./HeaderEditor.js";
import { RawPatchEditor } from "./RawPatchEditor.js";
import "./ResendPage.css";
import { ResponseViewer } from "./ResponseViewer.js";
import { TcpMessageList } from "./TcpMessageList.js";
import type { TcpResendResult } from "./TcpResponseViewer.js";
import { TcpResponseViewer } from "./TcpResponseViewer.js";

/** HTTP methods available for resend. */
const HTTP_METHODS = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "HEAD",
  "OPTIONS",
] as const;

/** Tabs for the HTTP request editor panel. */
const HTTP_REQUEST_TABS = [
  { id: "headers", label: "Headers" },
  { id: "body", label: "Body" },
  { id: "patches", label: "Body Patches" },
];

/** Tabs for the TCP request editor panel. */
const TCP_REQUEST_TABS = [
  { id: "messages", label: "Messages" },
  { id: "raw_patches", label: "Raw Patches" },
];

/** Protocol mode tabs shown at the top of the editor. */
const TCP_MODE_TABS = [
  { id: "resend_raw", label: "Resend Raw" },
  { id: "tcp_replay", label: "TCP Replay" },
];

/** Resend result from MCP resend tool. */
export interface ResendResult {
  new_flow_id?: string;
  method?: string;
  url?: string;
  request_headers?: Record<string, string[]>;
  request_body?: string;
  response_status_code?: number;
  response_headers?: Record<string, string[]>;
  response_body?: string;
  response_body_encoding?: string;
  duration_ms?: number;
  dry_run?: boolean;
  tag?: string;
}

/** A history entry for resends. */
interface HistoryEntry {
  timestamp: string;
  protocol: "http" | "tcp";
  action: string;
  method: string;
  url: string;
  statusCode?: number;
  responseSize?: number;
  durationMs?: number;
  dryRun: boolean;
  tag: string;
  flowId?: string;
}

/** Detect whether a flow uses TCP/raw protocol. */
function isTcpFlow(flow: FlowDetailResult): boolean {
  const proto = (flow.protocol || "").toLowerCase();
  return proto === "tcp" || proto === "raw";
}

export function ResendPage() {
  const { flowId: routeFlowId } = useParams<{ flowId: string }>();
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { resend, loading: executing } = useResend();

  // Flow ID input state.
  const [flowIdInput, setFlowIdInput] = useState(routeFlowId ?? "");
  const [activeFlowId, setActiveFlowId] = useState(routeFlowId ?? "");

  // HTTP request editor state.
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("");
  const [headers, setHeaders] = useState<Array<{ key: string; value: string }>>([]);
  const [body, setBody] = useState("");
  const [bodyPatches, setBodyPatches] = useState<BodyPatch[]>([]);

  // TCP-specific state.
  const [targetAddr, setTargetAddr] = useState("");
  const [useTls, setUseTls] = useState(false);
  const [rawPatches, setRawPatches] = useState<RawPatch[]>([]);
  const [tcpMode, setTcpMode] = useState<"resend_raw" | "tcp_replay">("resend_raw");

  // Shared state.
  const [tag, setTag] = useState("");
  const [dryRun, setDryRun] = useState(false);

  // UI state.
  const [requestTab, setRequestTab] = useState("headers");
  const [tcpRequestTab, setTcpRequestTab] = useState("messages");
  const [httpResponse, setHttpResponse] = useState<ResendResult | null>(null);
  const [tcpResponse, setTcpResponse] = useState<TcpResendResult | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  // Fetch original flow data when activeFlowId changes.
  const {
    data: flowData,
    loading: flowLoading,
    error: flowError,
  } = useQuery("flow", {
    id: activeFlowId,
    enabled: activeFlowId.length > 0,
  });

  // Determine protocol mode from flow data.
  const flow = flowData as FlowDetailResult | null;
  const isTcp = useMemo(() => flow != null && isTcpFlow(flow), [flow]);

  // Fetch messages for TCP flows.
  const {
    data: messagesData,
  } = useQuery("messages", {
    id: activeFlowId,
    enabled: activeFlowId.length > 0 && isTcp,
  });

  const tcpMessages: MessageEntry[] = useMemo(() => {
    if (!messagesData) return [];
    return (messagesData as MessagesResult).messages ?? [];
  }, [messagesData]);

  // Populate editor with flow data when loaded.
  useEffect(() => {
    if (!flow) return;

    // Reset shared state.
    setTag("");
    setHttpResponse(null);
    setTcpResponse(null);

    if (isTcpFlow(flow)) {
      // TCP flow: populate target address from connection info.
      setTargetAddr(flow.conn_info?.server_addr ?? "");
      setUseTls(!!flow.conn_info?.tls_version);
      setRawPatches([]);
      setTcpMode("resend_raw");
      setTcpRequestTab("messages");
    } else {
      // HTTP flow: populate editor fields.
      setMethod(flow.method || "GET");
      setUrl(flow.url || "");
      setBody(flow.request_body || "");
      setBodyPatches([]);
      setRequestTab("headers");

      // Convert headers from Record<string, string[]> to key-value pairs.
      const headerPairs: Array<{ key: string; value: string }> = [];
      if (flow.request_headers) {
        for (const [key, values] of Object.entries(flow.request_headers)) {
          for (const value of values) {
            headerPairs.push({ key, value });
          }
        }
      }
      setHeaders(headerPairs);
    }
  }, [flow]);

  // Sync route param changes.
  useEffect(() => {
    if (routeFlowId && routeFlowId !== activeFlowId) {
      setFlowIdInput(routeFlowId);
      setActiveFlowId(routeFlowId);
    }
  }, [routeFlowId, activeFlowId]);

  /** Load a flow by ID from the input. */
  const handleLoadFlow = useCallback(() => {
    const trimmed = flowIdInput.trim();
    if (!trimmed) return;
    setActiveFlowId(trimmed);
    if (trimmed !== routeFlowId) {
      navigate(`/resend/${trimmed}`, { replace: true });
    }
  }, [flowIdInput, routeFlowId, navigate]);

  /** Send HTTP resend request. */
  const handleHttpSend = useCallback(
    async (isDryRun: boolean) => {
      if (!activeFlowId) {
        addToast({ type: "warning", message: "No flow selected" });
        return;
      }

      // Build override_headers from the key-value pairs.
      const overrideHeaders: Record<string, string> = {};
      for (const h of headers) {
        const key = h.key.trim();
        if (key) {
          overrideHeaders[key] = key in overrideHeaders
            ? `${overrideHeaders[key]}, ${h.value}`
            : h.value;
        }
      }

      try {
        const result = await resend<ResendResult>({
          action: "resend",
          params: {
            flow_id: activeFlowId,
            override_method: method,
            override_url: url,
            override_headers: Object.keys(overrideHeaders).length > 0 ? overrideHeaders : undefined,
            override_body: body || undefined,
            body_patches: bodyPatches.length > 0 ? bodyPatches : undefined,
            dry_run: isDryRun,
            tag: tag || undefined,
          },
        });

        setHttpResponse(result);

        setHistory((prev) => [
          {
            timestamp: new Date().toISOString(),
            protocol: "http",
            action: "resend",
            method,
            url,
            statusCode: result.response_status_code,
            durationMs: result.duration_ms,
            dryRun: isDryRun,
            tag,
            flowId: result.new_flow_id,
          },
          ...prev,
        ]);

        addToast({
          type: "success",
          message: isDryRun
            ? "Dry-run preview generated"
            : `Request sent (${result.response_status_code ?? "?"})`,
        });
      } catch (err) {
        addToast({
          type: "error",
          message: err instanceof Error ? err.message : "Resend failed",
        });
      }
    },
    [activeFlowId, method, url, headers, body, bodyPatches, tag, resend, addToast],
  );

  /** Send TCP resend_raw request. */
  const handleResendRaw = useCallback(
    async (isDryRun: boolean) => {
      if (!activeFlowId) {
        addToast({ type: "warning", message: "No flow selected" });
        return;
      }
      if (!targetAddr.trim()) {
        addToast({ type: "warning", message: "Target address is required" });
        return;
      }

      try {
        const result = await resend<TcpResendResult>({
          action: "resend_raw",
          params: {
            flow_id: activeFlowId,
            target_addr: targetAddr.trim(),
            use_tls: useTls || undefined,
            patches: rawPatches.length > 0 ? rawPatches : undefined,
            dry_run: isDryRun,
            tag: tag || undefined,
          },
        });

        setTcpResponse(result);

        setHistory((prev) => [
          {
            timestamp: new Date().toISOString(),
            protocol: "tcp",
            action: "resend_raw",
            method: "RAW",
            url: targetAddr.trim(),
            responseSize: result.response_size,
            durationMs: result.duration_ms,
            dryRun: isDryRun,
            tag,
            flowId: result.new_flow_id,
          },
          ...prev,
        ]);

        addToast({
          type: "success",
          message: isDryRun
            ? "Dry-run preview generated"
            : `Raw resend complete (${result.response_size ?? 0} bytes)`,
        });
      } catch (err) {
        addToast({
          type: "error",
          message: err instanceof Error ? err.message : "Resend raw failed",
        });
      }
    },
    [activeFlowId, targetAddr, useTls, rawPatches, tag, resend, addToast],
  );

  /** Send TCP replay request. */
  const handleTcpReplay = useCallback(async () => {
    if (!activeFlowId) {
      addToast({ type: "warning", message: "No flow selected" });
      return;
    }
    if (!targetAddr.trim()) {
      addToast({ type: "warning", message: "Target address is required" });
      return;
    }

    try {
      const result = await resend<TcpResendResult>({
        action: "tcp_replay",
        params: {
          flow_id: activeFlowId,
          target_addr: targetAddr.trim(),
          use_tls: useTls || undefined,
          tag: tag || undefined,
        },
      });

      setTcpResponse(result);

      setHistory((prev) => [
        {
          timestamp: new Date().toISOString(),
          protocol: "tcp",
          action: "tcp_replay",
          method: "REPLAY",
          url: targetAddr.trim(),
          responseSize: result.response_size,
          durationMs: result.duration_ms,
          dryRun: false,
          tag,
          flowId: result.new_flow_id,
        },
        ...prev,
      ]);

      addToast({
        type: "success",
        message: `TCP replay complete (${result.response_size ?? 0} bytes)`,
      });
    } catch (err) {
      addToast({
        type: "error",
        message: err instanceof Error ? err.message : "TCP replay failed",
      });
    }
  }, [activeFlowId, targetAddr, useTls, tag, resend, addToast]);

  /** Whether the editor has a loaded flow. */
  const hasFlow = activeFlowId.length > 0 && flow != null;

  return (
    <div className="page resend-page">
      <div className="resend-header">
        <h1 className="page-title">Resend</h1>
        <p className="page-description">
          Edit and resend captured requests. Supports HTTP resend, raw TCP byte patching, and TCP replay.
        </p>
      </div>

      {/* Flow selector */}
      <div className="resend-flow-selector">
        <div className="resend-flow-input-row">
          <Input
            placeholder="Enter flow ID..."
            value={flowIdInput}
            onChange={(e) => setFlowIdInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleLoadFlow();
            }}
          />
          <Button variant="primary" onClick={handleLoadFlow} disabled={!flowIdInput.trim()}>
            Load
          </Button>
        </div>
        {flowLoading && (
          <div className="resend-loading">
            <Spinner size="sm" />
            <span>Loading flow...</span>
          </div>
        )}
        {flowError && (
          <div className="resend-error">
            Failed to load flow: {flowError.message}
          </div>
        )}
      </div>

      {hasFlow && !isTcp && (
        /* ============================================================
         * HTTP Mode
         * ============================================================ */
        <div className="resend-editor-layout">
          {/* Left: Request editor */}
          <div className="resend-panel resend-request-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">Request</span>
              <Badge variant="info">{activeFlowId.slice(0, 8)}</Badge>
              <Badge variant="default">HTTP</Badge>
            </div>

            {/* Method + URL */}
            <div className="resend-method-url-row">
              <select
                className="resend-method-select"
                value={method}
                onChange={(e) => setMethod(e.target.value)}
              >
                {HTTP_METHODS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
              <input
                className="resend-url-input"
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com/api/endpoint"
              />
            </div>

            {/* Tag input */}
            <div className="resend-tag-row">
              <Input
                placeholder="Tag (optional)"
                value={tag}
                onChange={(e) => setTag(e.target.value)}
              />
            </div>

            {/* Request body tabs */}
            <Tabs
              tabs={HTTP_REQUEST_TABS}
              activeTab={requestTab}
              onTabChange={setRequestTab}
            >
              {requestTab === "headers" && (
                <HeaderEditor headers={headers} onChange={setHeaders} />
              )}
              {requestTab === "body" && (
                <div className="resend-body-editor">
                  <textarea
                    className="resend-body-textarea"
                    value={body}
                    onChange={(e) => setBody(e.target.value)}
                    placeholder="Request body..."
                    spellCheck={false}
                  />
                </div>
              )}
              {requestTab === "patches" && (
                <BodyPatchEditor patches={bodyPatches} onChange={setBodyPatches} />
              )}
            </Tabs>

            {/* Action buttons */}
            <div className="resend-actions">
              <Button
                variant="primary"
                onClick={() => handleHttpSend(dryRun)}
                disabled={executing}
              >
                {executing ? "Sending..." : dryRun ? "Send (Dry Run)" : "Send"}
              </Button>
              <Button
                variant="secondary"
                onClick={() => handleHttpSend(true)}
                disabled={executing}
              >
                Dry Run
              </Button>
              <label className="resend-dryrun-toggle">
                <input
                  type="checkbox"
                  checked={dryRun}
                  onChange={(e) => setDryRun(e.target.checked)}
                />
                <span>Default dry-run</span>
              </label>
            </div>
          </div>

          {/* Right: Response viewer */}
          <div className="resend-panel resend-response-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">Response</span>
              {httpResponse?.dry_run && <Badge variant="warning">DRY RUN</Badge>}
              {httpResponse?.response_status_code != null && (
                <Badge
                  variant={
                    httpResponse.response_status_code < 300
                      ? "success"
                      : httpResponse.response_status_code < 400
                        ? "info"
                        : httpResponse.response_status_code < 500
                          ? "warning"
                          : "danger"
                  }
                >
                  {httpResponse.response_status_code}
                </Badge>
              )}
              {httpResponse?.duration_ms != null && (
                <span className="resend-duration">{httpResponse.duration_ms}ms</span>
              )}
            </div>

            {executing ? (
              <div className="resend-loading">
                <Spinner size="sm" />
                <span>Sending request...</span>
              </div>
            ) : httpResponse ? (
              <ResponseViewer
                response={httpResponse}
                originalFlow={flow}
              />
            ) : (
              <div className="resend-empty-response">
                Send a request to see the response here.
              </div>
            )}
          </div>
        </div>
      )}

      {hasFlow && isTcp && (
        /* ============================================================
         * TCP Mode
         * ============================================================ */
        <div className="resend-editor-layout">
          {/* Left: TCP Request editor */}
          <div className="resend-panel resend-request-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">TCP Request</span>
              <Badge variant="info">{activeFlowId.slice(0, 8)}</Badge>
              <Badge variant="warning">TCP</Badge>
            </div>

            {/* TCP mode selector */}
            <Tabs
              tabs={TCP_MODE_TABS}
              activeTab={tcpMode}
              onTabChange={(id) => setTcpMode(id as "resend_raw" | "tcp_replay")}
              className="resend-tcp-mode-tabs"
            />

            {/* Target address + TLS */}
            <div className="resend-tcp-target-row">
              <input
                className="resend-url-input"
                type="text"
                value={targetAddr}
                onChange={(e) => setTargetAddr(e.target.value)}
                placeholder="host:port (e.g. 192.168.1.10:3306)"
              />
              <label className="resend-tls-toggle">
                <input
                  type="checkbox"
                  checked={useTls}
                  onChange={(e) => setUseTls(e.target.checked)}
                />
                <span>TLS</span>
              </label>
            </div>

            {/* Tag input */}
            <div className="resend-tag-row">
              <Input
                placeholder="Tag (optional)"
                value={tag}
                onChange={(e) => setTag(e.target.value)}
              />
            </div>

            {/* TCP content tabs */}
            {tcpMode === "resend_raw" && (
              <Tabs
                tabs={TCP_REQUEST_TABS}
                activeTab={tcpRequestTab}
                onTabChange={setTcpRequestTab}
              >
                {tcpRequestTab === "messages" && (
                  <TcpMessageList messages={tcpMessages} />
                )}
                {tcpRequestTab === "raw_patches" && (
                  <RawPatchEditor patches={rawPatches} onChange={setRawPatches} />
                )}
              </Tabs>
            )}

            {tcpMode === "tcp_replay" && (
              <div className="resend-tcp-replay-info">
                <TcpMessageList messages={tcpMessages} />
                <div className="resend-tcp-replay-description">
                  TCP Replay re-sends all client (send) messages in sequence
                  to the target address. No patching is applied.
                </div>
              </div>
            )}

            {/* TCP Action buttons */}
            <div className="resend-actions">
              {tcpMode === "resend_raw" ? (
                <>
                  <Button
                    variant="primary"
                    onClick={() => handleResendRaw(dryRun)}
                    disabled={executing || !targetAddr.trim()}
                  >
                    {executing ? "Sending..." : dryRun ? "Send Raw (Dry Run)" : "Send Raw"}
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => handleResendRaw(true)}
                    disabled={executing || !targetAddr.trim()}
                  >
                    Dry Run
                  </Button>
                  <label className="resend-dryrun-toggle">
                    <input
                      type="checkbox"
                      checked={dryRun}
                      onChange={(e) => setDryRun(e.target.checked)}
                    />
                    <span>Default dry-run</span>
                  </label>
                </>
              ) : (
                <Button
                  variant="primary"
                  onClick={handleTcpReplay}
                  disabled={executing || !targetAddr.trim()}
                >
                  {executing ? "Replaying..." : "Replay All"}
                </Button>
              )}
            </div>
          </div>

          {/* Right: TCP Response viewer */}
          <div className="resend-panel resend-response-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">Response</span>
              {tcpResponse?.dry_run && <Badge variant="warning">DRY RUN</Badge>}
              {tcpResponse?.response_size != null && (
                <Badge variant="info">
                  {tcpResponse.response_size} bytes
                </Badge>
              )}
              {tcpResponse?.duration_ms != null && (
                <span className="resend-duration">{tcpResponse.duration_ms}ms</span>
              )}
            </div>

            {executing ? (
              <div className="resend-loading">
                <Spinner size="sm" />
                <span>{tcpMode === "tcp_replay" ? "Replaying..." : "Sending raw data..."}</span>
              </div>
            ) : tcpResponse ? (
              <TcpResponseViewer response={tcpResponse} />
            ) : (
              <div className="resend-empty-response">
                {tcpMode === "tcp_replay"
                  ? "Click Replay All to re-send all TCP messages."
                  : "Send raw data to see the response here."}
              </div>
            )}
          </div>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="resend-history">
          <h3 className="resend-history-title">Send History</h3>
          <div className="resend-history-list">
            {history.map((entry, idx) => (
              <div key={idx} className="resend-history-entry">
                {entry.protocol === "http" ? (
                  <Badge
                    variant={
                      entry.statusCode == null
                        ? "default"
                        : entry.statusCode < 300
                          ? "success"
                          : entry.statusCode < 500
                            ? "warning"
                            : "danger"
                    }
                  >
                    {entry.statusCode ?? "---"}
                  </Badge>
                ) : (
                  <Badge variant="info">
                    {entry.responseSize != null ? `${entry.responseSize}B` : "TCP"}
                  </Badge>
                )}
                <span className="resend-history-method">{entry.method}</span>
                <span className="resend-history-url">{entry.url}</span>
                {entry.protocol === "tcp" && (
                  <Badge variant="warning">{entry.action === "tcp_replay" ? "REPLAY" : "RAW"}</Badge>
                )}
                {entry.dryRun && <Badge variant="warning">DRY</Badge>}
                {entry.tag && <Badge variant="info">{entry.tag}</Badge>}
                {entry.durationMs != null && (
                  <span className="resend-history-duration">
                    {entry.durationMs}ms
                  </span>
                )}
                <span className="resend-history-time">
                  {new Date(entry.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
