import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Spinner, Table, Tabs, useToast } from "../../components/ui/index.js";
import { useInterceptAction, useQuery } from "../../lib/mcp/hooks.js";
import type {
  InterceptQueueEntry,
  InterceptQueueResult,
} from "../../lib/mcp/types.js";
import { BodyEditor } from "./BodyEditor.js";
import type { HeaderRow } from "./HeaderEditor.js";
import { HeaderEditor } from "./HeaderEditor.js";
import "./InterceptPage.css";
import { RawBytesEditor } from "./RawBytesEditor.js";
import { RulesPanel } from "./RulesPanel.js";

const TABS = [
  { id: "queue", label: "Queue" },
  { id: "rules", label: "Rules" },
];

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

const HTTP_STATUS_CODES = [
  200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 405, 500, 502, 503, 504,
];

type DetailViewMode = "structured" | "raw";

/** Resolve the effective phase of an entry, defaulting to "request" for backward compat. */
function resolvePhase(entry: InterceptQueueEntry): string {
  return entry.phase ?? "request";
}

export function InterceptPage() {
  const [activeTab, setActiveTab] = useState("queue");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detailViewMode, setDetailViewMode] = useState<DetailViewMode>("structured");

  // Editable fields for the selected entry (structured mode)
  const [editMethod, setEditMethod] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [editHeaders, setEditHeaders] = useState<HeaderRow[]>([]);
  const [editBody, setEditBody] = useState("");
  const [editStatusCode, setEditStatusCode] = useState(200);

  // Editable raw bytes (raw mode, Base64)
  const [editRawBytes, setEditRawBytes] = useState("");

  const { addToast } = useToast();
  const { interceptAction, loading: executeLoading } = useInterceptAction();

  // Poll intercept queue every second
  const {
    data: queueData,
    loading: queueLoading,
    error: queueError,
    refetch: refetchQueue,
  } = useQuery<"intercept_queue">("intercept_queue", {
    pollInterval: 1000,
  });

  // Fetch config for intercept rules summary
  const {
    data: configData,
    loading: configLoading,
  } = useQuery<"config">("config");

  const queue: InterceptQueueResult = queueData ?? { items: [], count: 0 };

  // Clear selectedId when the selected entry is no longer in the queue
  useEffect(() => {
    if (selectedId && !queue.items.some((item) => item.id === selectedId)) {
      setSelectedId(null);
    }
  }, [selectedId, queue.items]);

  const selectedEntry = selectedId
    ? queue.items.find((item) => item.id === selectedId) ?? null
    : null;

  // Select a queue entry and populate edit fields based on phase
  const handleSelect = useCallback((entry: InterceptQueueEntry) => {
    setSelectedId(entry.id);

    const phase = resolvePhase(entry);

    if (phase === "websocket_frame") {
      // WebSocket frames: only body (payload) is editable
      setEditMethod("");
      setEditUrl("");
      setEditHeaders([]);
      setEditBody(entry.body);
      setEditStatusCode(0);
    } else if (phase === "response") {
      // Response phase: status code, headers, body
      setEditMethod("");
      setEditUrl("");
      setEditStatusCode(entry.status_code ?? 200);
      setEditBody(entry.body);

      const headerRows: HeaderRow[] = [];
      if (entry.headers) {
        for (const [name, values] of Object.entries(entry.headers)) {
          for (const value of values) {
            headerRows.push({ id: crypto.randomUUID(), name, value });
          }
        }
      }
      setEditHeaders(headerRows);
    } else {
      // Request phase (default)
      setEditMethod(entry.method);
      setEditUrl(entry.url);
      setEditBody(entry.body);
      setEditStatusCode(0);

      const headerRows: HeaderRow[] = [];
      if (entry.headers) {
        for (const [name, values] of Object.entries(entry.headers)) {
          for (const value of values) {
            headerRows.push({ id: crypto.randomUUID(), name, value });
          }
        }
      }
      setEditHeaders(headerRows);
    }

    // Populate raw bytes if available
    if (entry.raw_bytes) {
      setEditRawBytes(entry.raw_bytes);
    } else {
      setEditRawBytes("");
    }
  }, []);

  // Release: forward as-is
  const handleRelease = useCallback(async () => {
    if (!selectedId) return;
    const phase = selectedEntry ? resolvePhase(selectedEntry) : "request";
    try {
      await interceptAction({
        action: "release",
        params: {
          intercept_id: selectedId,
          mode: detailViewMode,
        },
      });
      addToast({ type: "success", message: `${phaseLabel(phase)} released` });
      setSelectedId(null);
      refetchQueue();
    } catch (err) {
      addToast({
        type: "error",
        message: `Release failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [selectedId, selectedEntry, detailViewMode, interceptAction, addToast, refetchQueue]);

  // Modify & Forward: apply edits and forward (phase-aware)
  const handleModifyAndForward = useCallback(async () => {
    if (!selectedId || !selectedEntry) return;

    const phase = resolvePhase(selectedEntry);

    if (detailViewMode === "raw") {
      // Raw mode: send raw_override_base64 (same for all phases)
      try {
        await interceptAction({
          action: "modify_and_forward",
          params: {
            intercept_id: selectedId,
            mode: "raw",
            raw_override_base64: editRawBytes,
          },
        });
        addToast({ type: "success", message: `${phaseLabel(phase)} modified (raw) and forwarded` });
        setSelectedId(null);
        refetchQueue();
      } catch (err) {
        addToast({
          type: "error",
          message: `Modify & Forward failed: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
      return;
    }

    // Structured mode: phase-specific parameters
    try {
      if (phase === "websocket_frame") {
        await interceptAction({
          action: "modify_and_forward",
          params: {
            intercept_id: selectedId,
            override_body: editBody,
          },
        });
      } else if (phase === "response") {
        const overrideHeaders: Record<string, string> = {};
        for (const h of editHeaders) {
          const key = h.name.trim();
          if (key) {
            if (key in overrideHeaders) {
              overrideHeaders[key] = overrideHeaders[key] + ", " + h.value;
            } else {
              overrideHeaders[key] = h.value;
            }
          }
        }

        await interceptAction({
          action: "modify_and_forward",
          params: {
            intercept_id: selectedId,
            override_status: editStatusCode,
            override_response_headers: overrideHeaders,
            override_response_body: editBody,
          },
        });
      } else {
        // Request phase
        const overrideHeaders: Record<string, string> = {};
        for (const h of editHeaders) {
          const key = h.name.trim();
          if (key) {
            if (key in overrideHeaders) {
              overrideHeaders[key] = overrideHeaders[key] + ", " + h.value;
            } else {
              overrideHeaders[key] = h.value;
            }
          }
        }

        await interceptAction({
          action: "modify_and_forward",
          params: {
            intercept_id: selectedId,
            override_method: editMethod,
            override_url: editUrl,
            override_headers: overrideHeaders,
            override_body: editBody,
          },
        });
      }

      addToast({ type: "success", message: `${phaseLabel(phase)} modified and forwarded` });
      setSelectedId(null);
      refetchQueue();
    } catch (err) {
      addToast({
        type: "error",
        message: `Modify & Forward failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [selectedId, selectedEntry, detailViewMode, editMethod, editUrl, editHeaders, editBody, editStatusCode, editRawBytes, interceptAction, addToast, refetchQueue]);

  // Drop: discard entry
  const handleDrop = useCallback(async () => {
    if (!selectedId) return;
    const phase = selectedEntry ? resolvePhase(selectedEntry) : "request";
    try {
      await interceptAction({
        action: "drop",
        params: { intercept_id: selectedId },
      });
      addToast({ type: "warning", message: `${phaseLabel(phase)} dropped` });
      setSelectedId(null);
      refetchQueue();
    } catch (err) {
      addToast({
        type: "error",
        message: `Drop failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [selectedId, selectedEntry, interceptAction, addToast, refetchQueue]);

  const hasRawBytes = selectedEntry?.raw_bytes_available ?? false;
  const selectedPhase = selectedEntry ? resolvePhase(selectedEntry) : "request";

  return (
    <div className="page intercept-page">
      <div className="intercept-header">
        <h1 className="page-title">Intercept</h1>
        <Badge variant={queue.count > 0 ? "warning" : "default"}>
          {queue.count}
        </Badge>
      </div>
      <p className="page-description">
        Intercepted requests waiting for review.
      </p>

      <div className="intercept-tabs">
        <Tabs tabs={TABS} activeTab={activeTab} onTabChange={setActiveTab}>
          {activeTab === "queue" && (
            <QueuePanel
              queue={queue}
              loading={queueLoading}
              error={queueError}
              selectedId={selectedId}
              onSelect={handleSelect}
            />
          )}
          {activeTab === "rules" && (
            <RulesPanel
              configData={configData ?? null}
              loading={configLoading}
            />
          )}
        </Tabs>
      </div>

      {activeTab === "queue" && selectedEntry && (
        <div className="intercept-detail">
          <div className="intercept-detail-header">
            <span className="intercept-detail-title">
              <DetailTitle entry={selectedEntry} />
            </span>
            <div className="intercept-detail-actions">
              {/* Structured / Raw toggle */}
              {hasRawBytes && (
                <div className="intercept-view-mode-selector">
                  <button
                    className={`intercept-mode-btn ${detailViewMode === "structured" ? "intercept-mode-btn--active" : ""}`}
                    onClick={() => setDetailViewMode("structured")}
                  >
                    Structured
                  </button>
                  <button
                    className={`intercept-mode-btn ${detailViewMode === "raw" ? "intercept-mode-btn--active" : ""}`}
                    onClick={() => setDetailViewMode("raw")}
                  >
                    Raw
                  </button>
                </div>
              )}
              <Button
                variant="primary"
                size="sm"
                onClick={handleRelease}
                disabled={executeLoading}
              >
                Release
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={handleModifyAndForward}
                disabled={executeLoading}
              >
                Modify & Forward
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={handleDrop}
                disabled={executeLoading}
              >
                Drop
              </Button>
            </div>
          </div>
          <div className="intercept-detail-body">
            {detailViewMode === "structured" ? (
              <>
                {selectedPhase === "request" && (
                  <>
                    {/* Method + URL */}
                    <div className="intercept-request-line">
                      <select
                        className="intercept-method-select"
                        value={editMethod}
                        onChange={(e) => setEditMethod(e.target.value)}
                      >
                        {HTTP_METHODS.map((m) => (
                          <option key={m} value={m}>{m}</option>
                        ))}
                      </select>
                      <input
                        className="input intercept-url-input"
                        value={editUrl}
                        onChange={(e) => setEditUrl(e.target.value)}
                        placeholder="URL"
                      />
                    </div>
                    <HeaderEditor headers={editHeaders} onChange={setEditHeaders} />
                    <BodyEditor body={editBody} onChange={setEditBody} />
                  </>
                )}

                {selectedPhase === "response" && (
                  <>
                    {/* Status Code + URL (read-only) */}
                    <div className="intercept-request-line">
                      <select
                        className="intercept-method-select intercept-status-select"
                        value={editStatusCode}
                        onChange={(e) => setEditStatusCode(Number(e.target.value))}
                      >
                        {HTTP_STATUS_CODES.map((code) => (
                          <option key={code} value={code}>{code}</option>
                        ))}
                        {/* Allow the current status code even if not in the preset list */}
                        {!HTTP_STATUS_CODES.includes(editStatusCode) && (
                          <option value={editStatusCode}>{editStatusCode}</option>
                        )}
                      </select>
                      <input
                        className="input intercept-url-input"
                        value={selectedEntry.url}
                        readOnly
                        title="URL (read-only for response phase)"
                      />
                    </div>
                    <HeaderEditor headers={editHeaders} onChange={setEditHeaders} />
                    <BodyEditor body={editBody} onChange={setEditBody} />
                  </>
                )}

                {selectedPhase === "websocket_frame" && (
                  <>
                    {/* WebSocket frame metadata (read-only) */}
                    <div className="intercept-ws-meta">
                      <div className="intercept-ws-meta-row">
                        <span className="intercept-ws-meta-label">Opcode</span>
                        <Badge variant="info">{selectedEntry.opcode ?? "Unknown"}</Badge>
                      </div>
                      <div className="intercept-ws-meta-row">
                        <span className="intercept-ws-meta-label">Direction</span>
                        <Badge variant={selectedEntry.direction === "client_to_server" ? "success" : "warning"}>
                          {formatDirection(selectedEntry.direction)}
                        </Badge>
                      </div>
                      {selectedEntry.upgrade_url && (
                        <div className="intercept-ws-meta-row">
                          <span className="intercept-ws-meta-label">URL</span>
                          <span className="intercept-ws-meta-value">{selectedEntry.upgrade_url}</span>
                        </div>
                      )}
                      {selectedEntry.sequence != null && (
                        <div className="intercept-ws-meta-row">
                          <span className="intercept-ws-meta-label">Sequence</span>
                          <span className="intercept-ws-meta-value">#{selectedEntry.sequence}</span>
                        </div>
                      )}
                    </div>
                    {/* Payload editor only */}
                    <BodyEditor body={editBody} onChange={setEditBody} />
                  </>
                )}
              </>
            ) : (
              /* Raw bytes editor */
              <RawBytesEditor
                rawBytes={editRawBytes}
                onChange={setEditRawBytes}
                size={selectedEntry.raw_bytes_size}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// DetailTitle -- phase-aware detail header title
// ---------------------------------------------------------------------------

function DetailTitle({ entry }: { entry: InterceptQueueEntry }) {
  const phase = resolvePhase(entry);
  if (phase === "response") {
    return (
      <>
        <Badge variant={statusVariant(entry.status_code ?? 0)} className="intercept-phase-badge">
          {entry.status_code ?? "???"}
        </Badge>
        {" "}
        {extractHost(entry.url)}
      </>
    );
  }
  if (phase === "websocket_frame") {
    return (
      <>
        <Badge variant="info" className="intercept-phase-badge">
          WS {entry.opcode ?? "Frame"}
        </Badge>
        {" "}
        {formatDirection(entry.direction)}
        {entry.upgrade_url ? ` ${extractHost(entry.upgrade_url)}` : ""}
      </>
    );
  }
  // request phase (default)
  return <>{entry.method} {extractHost(entry.url)}</>;
}

// ---------------------------------------------------------------------------
// QueuePanel -- intercept queue table
// ---------------------------------------------------------------------------

interface QueuePanelProps {
  queue: InterceptQueueResult;
  loading: boolean;
  error: Error | null;
  selectedId: string | null;
  onSelect: (entry: InterceptQueueEntry) => void;
}

function QueuePanel({ queue, loading, error, selectedId, onSelect }: QueuePanelProps) {
  if (loading && queue.items.length === 0) {
    return (
      <div className="intercept-loading">
        <Spinner size="md" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="intercept-error">
        Error loading queue: {error.message}
      </div>
    );
  }

  if (queue.items.length === 0) {
    return (
      <div className="intercept-empty">
        <span className="intercept-empty-icon">No intercepted requests</span>
        <span>
          Configure intercept rules to start capturing requests.
        </span>
      </div>
    );
  }

  return (
    <div className="intercept-queue-table">
      <Table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Phase</th>
            <th>Method / Status</th>
            <th>URL</th>
            <th>Host</th>
            <th>Rules</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {queue.items.map((entry) => {
            const phase = resolvePhase(entry);
            return (
              <tr
                key={entry.id}
                className={
                  selectedId === entry.id ? "intercept-row--selected" : ""
                }
                onClick={() => onSelect(entry)}
              >
                <td>
                  <Badge variant="info">{truncateId(entry.id)}</Badge>
                </td>
                <td>
                  <Badge variant={phaseVariant(phase)}>{phaseLabel(phase)}</Badge>
                </td>
                <td>
                  <QueueMethodCell entry={entry} phase={phase} />
                </td>
                <td>
                  <span className="intercept-queue-url" title={phase === "websocket_frame" ? entry.upgrade_url : entry.url}>
                    {extractPath(phase === "websocket_frame" ? (entry.upgrade_url ?? "") : entry.url)}
                  </span>
                </td>
                <td>
                  <span className="intercept-queue-host">
                    {extractHost(phase === "websocket_frame" ? (entry.upgrade_url ?? "") : entry.url)}
                  </span>
                </td>
                <td>
                  <span className="intercept-queue-rules">
                    {entry.matched_rules.map((rule) => (
                      <Badge key={rule} variant="default">{rule}</Badge>
                    ))}
                  </span>
                </td>
                <td>
                  <span className="intercept-queue-time">
                    {formatTime(entry.timestamp)}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </Table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// QueueMethodCell -- phase-aware method/status display in the queue table
// ---------------------------------------------------------------------------

function QueueMethodCell({ entry, phase }: { entry: InterceptQueueEntry; phase: string }) {
  if (phase === "response") {
    return (
      <Badge variant={statusVariant(entry.status_code ?? 0)}>
        {entry.status_code ?? "???"}
      </Badge>
    );
  }
  if (phase === "websocket_frame") {
    return (
      <span className="intercept-ws-info">
        <Badge variant="info">{entry.opcode ?? "Frame"}</Badge>
        {entry.direction && (
          <span className="intercept-ws-direction">
            {entry.direction === "client_to_server" ? "\u2191" : "\u2193"}
          </span>
        )}
      </span>
    );
  }
  // request phase
  return (
    <Badge variant={methodVariant(entry.method)}>
      {entry.method}
    </Badge>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function truncateId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function extractHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function extractPath(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
}

function formatTime(timestamp: string): string {
  try {
    const date = new Date(timestamp);
    return date.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return timestamp;
  }
}

function formatDirection(direction?: string): string {
  if (direction === "client_to_server") return "Client \u2192 Server";
  if (direction === "server_to_client") return "Server \u2192 Client";
  return direction ?? "Unknown";
}

function methodVariant(method: string): "success" | "warning" | "danger" | "info" | "default" {
  switch (method) {
    case "GET":
      return "success";
    case "POST":
      return "info";
    case "PUT":
    case "PATCH":
      return "warning";
    case "DELETE":
      return "danger";
    default:
      return "default";
  }
}

function phaseVariant(phase: string): "success" | "warning" | "danger" | "info" | "default" {
  switch (phase) {
    case "request":
      return "info";
    case "response":
      return "success";
    case "websocket_frame":
      return "warning";
    default:
      return "default";
  }
}

function phaseLabel(phase: string): string {
  switch (phase) {
    case "request":
      return "Request";
    case "response":
      return "Response";
    case "websocket_frame":
      return "WS Frame";
    default:
      return phase;
  }
}

function statusVariant(code: number): "success" | "warning" | "danger" | "info" | "default" {
  if (code >= 200 && code < 300) return "success";
  if (code >= 300 && code < 400) return "info";
  if (code >= 400 && code < 500) return "warning";
  if (code >= 500) return "danger";
  return "default";
}
