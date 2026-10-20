import { useCallback, useEffect, useMemo, useState } from "react";
import { Badge, Button, Spinner, Table, Tabs, useToast } from "../../components/ui/index.js";
import { useInterceptAction, useQuery } from "../../lib/mcp/hooks.js";
import type {
  InterceptQueueEntry,
  InterceptQueueResult,
} from "../../lib/mcp/types.js";
import { BodyEditor } from "./BodyEditor.js";
import { HeaderEditor } from "./HeaderEditor.js";
import "./InterceptPage.css";
import {
  buildModifyAndForwardArgs,
  canModify,
  entryKind,
  entryToEditState,
  type InterceptEditState,
  type InterceptKind,
  maskingWarning,
  rawModeAllowed,
} from "./interceptPayload.js";
import { RawBytesEditor } from "./RawBytesEditor.js";
import { RulesPanel } from "./RulesPanel.js";

const TABS = [
  { id: "queue", label: "Queue" },
  { id: "rules", label: "Rules" },
];

// Adaptive polling thresholds for the intercept queue (USK-974). When the
// queue holds at least one entry, poll aggressively so newly-arriving items
// and post-action queue updates feel responsive. When the queue is empty,
// fall back to 5s to reduce idle load. The Issue body explicitly accepts up
// to 5s latency for the first item to surface in the idle state.
const INTERCEPT_POLL_ACTIVE_MS = 1000;
const INTERCEPT_POLL_IDLE_MS = 5000;

// Suggestions only: the method field is free text so any token the wire
// can carry (WebDAV verbs, custom or malformed methods) can be sent.
const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

const HTTP_STATUS_CODES = [
  200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 405, 500, 502, 503, 504,
];

export function InterceptPage() {
  const [activeTab, setActiveTab] = useState("queue");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Editable state for the selected entry.
  const [edit, setEdit] = useState<InterceptEditState | null>(null);

  // True while a release/drop/modify_and_forward mutation is awaiting its
  // post-mutation refetchQueue. Drives `disabled` on the action buttons so
  // a double-tap before the server-side hold queue updates can not fire a
  // second action against the same (now-released) intercept_id (USK-968).
  const [isActionInFlight, setIsActionInFlight] = useState(false);

  const { addToast } = useToast();
  const { interceptAction, loading: executeLoading } = useInterceptAction();

  // Adaptive polling state derived from the previously-rendered queue
  // depth. Stored as a boolean so the timer is only re-armed on the
  // empty ↔ non-empty transition, not on every poll that mutates queue
  // contents at fixed length. The polling `useEffect` inside `useQuery`
  // re-arms whenever `pollInterval` changes, so once the first non-empty
  // result lands the next render swaps from idle (5s) to active (1s)
  // cadence and back (USK-974). `pauseWhenHidden` additionally suspends
  // the timer entirely while the tab is in the background.
  const [queueHasItems, setQueueHasItems] = useState<boolean>(false);
  const queuePollInterval = queueHasItems
    ? INTERCEPT_POLL_ACTIVE_MS
    : INTERCEPT_POLL_IDLE_MS;

  const {
    data: queueData,
    loading: queueLoading,
    error: queueError,
    refetch: refetchQueue,
  } = useQuery<"intercept_queue">("intercept_queue", {
    pollInterval: queuePollInterval,
    pauseWhenHidden: true,
  });

  // Fetch config for intercept rules summary and the Output Filter rule
  // count that drives the masked-content warning.
  const {
    data: configData,
    loading: configLoading,
  } = useQuery<"config">("config");
  const outputRules = configData?.safety_filter?.output_rules ?? 0;

  const queue: InterceptQueueResult = queueData ?? { items: [], count: 0 };

  // Mirror the live queue's emptiness into state so the adaptive
  // `pollInterval` computed above sees the latest value on the next
  // render. Only the empty ↔ non-empty boolean is tracked so the polling
  // `useEffect` does not tear down and re-arm its timer for fixed-length
  // mutations (e.g., one entry replaced by another) — the interval stays
  // stable in the active cadence until the queue actually drains.
  useEffect(() => {
    const next = queue.items.length > 0;
    setQueueHasItems((prev) => (prev === next ? prev : next));
  }, [queue.items.length]);

  // Clear selectedId when the selected entry is no longer in the queue
  useEffect(() => {
    if (selectedId && !queue.items.some((item) => item.id === selectedId)) {
      setSelectedId(null);
    }
  }, [selectedId, queue.items]);

  const selectedEntry = selectedId
    ? queue.items.find((item) => item.id === selectedId) ?? null
    : null;

  // Select a queue entry and populate the editor from its held view.
  const handleSelect = useCallback((entry: InterceptQueueEntry) => {
    setSelectedId(entry.id);
    setEdit(entryToEditState(entry));
  }, []);

  const updateEdit = useCallback((patch: Partial<InterceptEditState>) => {
    setEdit((prev) => (prev ? { ...prev, ...patch } : prev));
  }, []);

  const modifiable = selectedEntry ? canModify(selectedEntry) : false;

  // The arguments Modify & Forward would send right now; recomputed on
  // every edit so the masked-content warning tracks what is actually sent.
  const pendingArgs = useMemo(
    () => (selectedEntry && edit && modifiable ? buildModifyAndForwardArgs(selectedEntry, edit) : null),
    [selectedEntry, edit, modifiable],
  );
  const showMaskWarning = pendingArgs ? maskingWarning(pendingArgs, outputRules) : false;

  // Release: forward as-is
  const handleRelease = useCallback(async () => {
    if (!selectedId || isActionInFlight) return;
    const kind = selectedEntry ? entryKind(selectedEntry) : "unknown";
    setIsActionInFlight(true);
    try {
      await interceptAction({
        action: "release",
        params: { intercept_id: selectedId },
      });
      addToast({ type: "success", message: `${kindLabel(kind)} released` });
      // Await the refetch BEFORE clearing selectedId so the detail panel
      // does not render a stale (already-released) entry between the
      // mutation completing and the queue polling catching up.
      await refetchQueue();
      setSelectedId(null);
    } catch (err) {
      addToast({
        type: "error",
        message: `Release failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setIsActionInFlight(false);
    }
  }, [selectedId, isActionInFlight, selectedEntry, interceptAction, addToast, refetchQueue]);

  // Modify & Forward: send the typed payload for the held item.
  const handleModifyAndForward = useCallback(async () => {
    if (!selectedId || !selectedEntry || !pendingArgs || isActionInFlight) return;
    const kind = entryKind(selectedEntry);
    setIsActionInFlight(true);
    try {
      await interceptAction(pendingArgs);
      addToast({ type: "success", message: `${kindLabel(kind)} modified and forwarded` });
      // Await the refetch BEFORE clearing selectedId so the detail panel
      // does not render a stale (already-forwarded) entry between the
      // mutation completing and the queue polling catching up.
      await refetchQueue();
      setSelectedId(null);
    } catch (err) {
      addToast({
        type: "error",
        message: `Modify & Forward failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setIsActionInFlight(false);
    }
  }, [selectedId, selectedEntry, pendingArgs, isActionInFlight, interceptAction, addToast, refetchQueue]);

  // Drop: discard entry
  const handleDrop = useCallback(async () => {
    if (!selectedId || isActionInFlight) return;
    const kind = selectedEntry ? entryKind(selectedEntry) : "unknown";
    setIsActionInFlight(true);
    try {
      await interceptAction({
        action: "drop",
        params: { intercept_id: selectedId },
      });
      addToast({ type: "warning", message: `${kindLabel(kind)} dropped` });
      // Await the refetch BEFORE clearing selectedId so the detail panel
      // does not render a stale (already-dropped) entry between the
      // mutation completing and the queue polling catching up.
      await refetchQueue();
      setSelectedId(null);
    } catch (err) {
      addToast({
        type: "error",
        message: `Drop failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setIsActionInFlight(false);
    }
  }, [selectedId, isActionInFlight, selectedEntry, interceptAction, addToast, refetchQueue]);

  const actionDisabled = executeLoading || isActionInFlight;

  return (
    <div className="page intercept-page">
      <div className="intercept-header">
        <h1 className="page-title">Intercept</h1>
        <Badge variant={queue.count > 0 ? "warning" : "default"}>
          {queue.count}
        </Badge>
      </div>
      <p className="page-description">
        Intercepted items waiting for review.
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

      {activeTab === "queue" && selectedEntry && edit && (
        <div className="intercept-detail">
          <div className="intercept-detail-header">
            <span className="intercept-detail-title">
              <DetailTitle entry={selectedEntry} />
            </span>
            <div className="intercept-detail-actions">
              <Button
                variant="primary"
                size="sm"
                onClick={handleRelease}
                disabled={actionDisabled}
              >
                Release
              </Button>
              <Button
                variant="secondary"
                size="sm"
                onClick={handleModifyAndForward}
                disabled={actionDisabled || !modifiable}
                title={modifiable ? undefined : "Modify & Forward is not available for this hold type; use Release or Drop"}
              >
                Modify & Forward
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={handleDrop}
                disabled={actionDisabled}
              >
                Drop
              </Button>
            </div>
          </div>
          <div className="intercept-detail-body">
            {showMaskWarning && (
              <div className="intercept-mask-warning" role="alert">
                The held view was passed through the SafetyFilter Output Filter. Masked
                values (e.g. [MASKED:...]) in the headers or body you send will be
                forwarded to the wire as shown. Check them before forwarding.
              </div>
            )}
            <DetailEditor entry={selectedEntry} edit={edit} onChange={updateEdit} />
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// DetailEditor -- kind-specific editor for the selected entry
// ---------------------------------------------------------------------------

interface DetailEditorProps {
  entry: InterceptQueueEntry;
  edit: InterceptEditState;
  onChange: (patch: Partial<InterceptEditState>) => void;
}

function DetailEditor({ entry, edit, onChange }: DetailEditorProps) {
  if (rawModeAllowed(entry)) {
    return (
      <RawBytesEditor
        rawBytes={edit.rawBytes}
        onChange={(rawBytes) => onChange({ rawBytes })}
        size={entry.raw_bytes_size}
      />
    );
  }

  switch (edit.kind) {
    case "request":
      return (
        <>
          <div className="intercept-request-line">
            <input
              className="input intercept-method-input"
              value={edit.method}
              onChange={(e) => onChange({ method: e.target.value })}
              list="intercept-http-methods"
              placeholder="Method"
              aria-label="Method"
              spellCheck={false}
            />
            <datalist id="intercept-http-methods">
              {HTTP_METHODS.map((m) => (
                <option key={m} value={m} />
              ))}
            </datalist>
            <input
              className="input intercept-scheme-input"
              value={edit.scheme}
              onChange={(e) => onChange({ scheme: e.target.value })}
              placeholder="scheme"
              aria-label="Scheme"
              spellCheck={false}
            />
            <input
              className="input intercept-authority-input"
              value={edit.authority}
              onChange={(e) => onChange({ authority: e.target.value })}
              placeholder="authority"
              aria-label="Authority"
              spellCheck={false}
            />
          </div>
          <div className="intercept-request-line">
            <input
              className="input intercept-url-input"
              value={edit.path}
              onChange={(e) => onChange({ path: e.target.value })}
              placeholder="path"
              aria-label="Path"
              spellCheck={false}
            />
            <span className="intercept-query-separator">?</span>
            <input
              className="input intercept-url-input"
              value={edit.rawQuery}
              onChange={(e) => onChange({ rawQuery: e.target.value })}
              placeholder="raw query (no leading ?)"
              aria-label="Raw query"
              spellCheck={false}
            />
          </div>
          <HeaderEditor headers={edit.headers} onChange={(headers) => onChange({ headers })} />
          <BodyEditor
            body={edit.body}
            encoding={edit.bodyEncoding}
            onChange={(body) => onChange({ body })}
          />
        </>
      );

    case "response":
      return (
        <>
          <div className="intercept-request-line">
            <input
              type="number"
              className="input intercept-status-input"
              value={edit.status}
              min={100}
              max={999}
              onChange={(e) => onChange({ status: Number(e.target.value) })}
              list="http-status-codes"
              aria-label="Status"
            />
            <datalist id="http-status-codes">
              {HTTP_STATUS_CODES.map((code) => (
                <option key={code} value={code} />
              ))}
            </datalist>
            <input
              className="input intercept-url-input"
              value={edit.statusReason}
              onChange={(e) => onChange({ statusReason: e.target.value })}
              placeholder="reason phrase (HTTP/1.x)"
              aria-label="Status reason"
              spellCheck={false}
            />
          </div>
          <HeaderEditor headers={edit.headers} onChange={(headers) => onChange({ headers })} />
          <BodyEditor
            body={edit.body}
            encoding={edit.bodyEncoding}
            onChange={(body) => onChange({ body })}
          />
        </>
      );

    case "websocket_frame":
      return (
        <>
          {/* WebSocket frame metadata (read-only) */}
          <div className="intercept-ws-meta">
            <div className="intercept-ws-meta-row">
              <span className="intercept-ws-meta-label">Opcode</span>
              <Badge variant="info">{entry.ws?.opcode ?? "unknown"}</Badge>
            </div>
            <div className="intercept-ws-meta-row">
              <span className="intercept-ws-meta-label">FIN</span>
              <span className="intercept-ws-meta-value">{entry.ws?.fin ? "1" : "0"}</span>
            </div>
            <div className="intercept-ws-meta-row">
              <span className="intercept-ws-meta-label">Direction</span>
              <Badge variant={entry.direction === "send" ? "success" : "warning"}>
                {formatDirection(entry.direction)}
              </Badge>
            </div>
            {entry.flow_id && (
              <div className="intercept-ws-meta-row">
                <span className="intercept-ws-meta-label">Flow</span>
                <span className="intercept-ws-meta-value">{entry.flow_id}</span>
              </div>
            )}
          </div>
          <BodyEditor
            label="Payload"
            body={edit.body}
            encoding={edit.bodyEncoding}
            onChange={(body) => onChange({ body })}
          />
        </>
      );

    default:
      // gRPC / SSE / unknown holds: read-only view; Release or Drop only.
      return (
        <div className="intercept-section">
          <div className="intercept-section-title">
            Held item (read-only; Modify & Forward is not available for this hold type)
          </div>
          <pre className="intercept-readonly-view">
            {JSON.stringify(entry.grpc_start ?? entry.grpc_data ?? entry.grpc_end ?? entry, null, 2)}
          </pre>
        </div>
      );
  }
}

// ---------------------------------------------------------------------------
// DetailTitle -- kind-aware detail header title
// ---------------------------------------------------------------------------

function DetailTitle({ entry }: { entry: InterceptQueueEntry }) {
  const kind = entryKind(entry);
  return (
    <>
      <Badge variant={kindVariant(kind)} className="intercept-phase-badge">
        {kindLabel(kind)}
      </Badge>
      {" "}
      <QueueMethodCell entry={entry} kind={kind} />
      {" "}
      {queueTarget(entry, kind)}
    </>
  );
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
            <th>Kind</th>
            <th>Method / Status</th>
            <th>Target</th>
            <th>Rules</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {queue.items.map((entry) => {
            const kind = entryKind(entry);
            const target = queueTarget(entry, kind);
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
                  <Badge variant={kindVariant(kind)}>{kindLabel(kind)}</Badge>
                </td>
                <td>
                  <QueueMethodCell entry={entry} kind={kind} />
                </td>
                <td>
                  <span className="intercept-queue-url" title={target}>
                    {target}
                  </span>
                </td>
                <td>
                  <span className="intercept-queue-rules">
                    {(entry.matched_rules ?? []).map((rule) => (
                      <Badge key={rule} variant="default">{rule}</Badge>
                    ))}
                  </span>
                </td>
                <td>
                  <span className="intercept-queue-time">
                    {formatTime(entry.held_at)}
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
// QueueMethodCell -- kind-aware method/status display
// ---------------------------------------------------------------------------

function QueueMethodCell({ entry, kind }: { entry: InterceptQueueEntry; kind: InterceptKind }) {
  switch (kind) {
    case "request":
      return (
        <Badge variant={methodVariant(entry.http?.method ?? "")}>
          {entry.http?.method ?? ""}
        </Badge>
      );
    case "response":
      return (
        <Badge variant={statusVariant(entry.http?.status ?? 0)}>
          {entry.http?.status ?? "???"}
        </Badge>
      );
    case "websocket_frame":
      return (
        <span className="intercept-ws-info">
          <Badge variant="info">{entry.ws?.opcode ?? "frame"}</Badge>
          <span className="intercept-ws-direction">
            {entry.direction === "send" ? "↑" : "↓"}
          </span>
        </span>
      );
    case "grpc_end":
      return <Badge variant="default">{`status ${entry.grpc_end?.status ?? "?"}`}</Badge>;
    default:
      return <span className="intercept-ws-direction">{entry.direction === "send" ? "↑" : "↓"}</span>;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Short target description. Built by concatenating the held parts as-is:
 * no URL parsing, so nothing the wire carried is normalized away.
 */
function queueTarget(entry: InterceptQueueEntry, kind: InterceptKind): string {
  switch (kind) {
    case "request": {
      const h = entry.http ?? {};
      const query = h.raw_query ? `?${h.raw_query}` : "";
      return `${h.authority ?? ""}${h.path ?? ""}${query}`;
    }
    case "grpc_start":
      return `${entry.grpc_start?.service ?? ""}/${entry.grpc_start?.method ?? ""}`;
    case "grpc_data":
      return `${entry.grpc_data?.service ?? ""}/${entry.grpc_data?.method ?? ""}`;
    default:
      return entry.flow_id ? `[Flow ${entry.flow_id.slice(0, 8)}]` : "—";
  }
}

function truncateId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) return timestamp;
  return date.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatDirection(direction: string): string {
  if (direction === "send") return "Client → Server";
  if (direction === "receive") return "Server → Client";
  return direction;
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

function kindVariant(kind: InterceptKind): "success" | "warning" | "danger" | "info" | "default" {
  switch (kind) {
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

function kindLabel(kind: InterceptKind): string {
  switch (kind) {
    case "request":
      return "Request";
    case "response":
      return "Response";
    case "websocket_frame":
      return "WS Frame";
    case "grpc_start":
      return "gRPC Start";
    case "grpc_data":
      return "gRPC Data";
    case "grpc_end":
      return "gRPC End";
    case "sse":
      return "SSE Event";
    case "raw":
      return "Raw";
    default:
      return "Unknown";
  }
}

function statusVariant(code: number): "success" | "warning" | "danger" | "info" | "default" {
  if (code >= 200 && code < 300) return "success";
  if (code >= 300 && code < 400) return "info";
  if (code >= 400 && code < 500) return "warning";
  if (code >= 500) return "danger";
  return "default";
}
