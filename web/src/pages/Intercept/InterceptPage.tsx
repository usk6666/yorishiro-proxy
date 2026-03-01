import { useState, useCallback } from "react";
import { useQuery, useExecute, useConfigure } from "../../lib/mcp/hooks.js";
import type {
  InterceptQueueEntry,
  InterceptQueueResult,
  InterceptRule,
} from "../../lib/mcp/types.js";
import { Badge, Button, Spinner, Table, Tabs, useToast } from "../../components/ui/index.js";
import { HeaderEditor } from "./HeaderEditor.js";
import { BodyEditor } from "./BodyEditor.js";
import { RulesPanel } from "./RulesPanel.js";
import "./InterceptPage.css";

const TABS = [
  { id: "queue", label: "Queue" },
  { id: "rules", label: "Rules" },
];

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

export function InterceptPage() {
  const [activeTab, setActiveTab] = useState("queue");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // Editable fields for the selected request
  const [editMethod, setEditMethod] = useState("");
  const [editUrl, setEditUrl] = useState("");
  const [editHeaders, setEditHeaders] = useState<Array<{ name: string; value: string }>>([]);
  const [editBody, setEditBody] = useState("");

  const { addToast } = useToast();
  const { execute, loading: executeLoading } = useExecute();
  const { configure, loading: configureLoading } = useConfigure();

  // Poll intercept queue every second
  const {
    data: queueData,
    loading: queueLoading,
    error: queueError,
    refetch: refetchQueue,
  } = useQuery<"intercept_queue">("intercept_queue", {
    pollInterval: 1000,
  });

  // Fetch config for intercept rules
  const {
    data: configData,
    loading: configLoading,
    refetch: refetchConfig,
  } = useQuery<"config">("config");

  const queue: InterceptQueueResult = queueData ?? { items: [], count: 0 };

  const selectedEntry = selectedId
    ? queue.items.find((item) => item.id === selectedId) ?? null
    : null;

  // Select a queue entry and populate edit fields
  const handleSelect = useCallback((entry: InterceptQueueEntry) => {
    setSelectedId(entry.id);
    setEditMethod(entry.method);
    setEditUrl(entry.url);
    setEditBody(entry.body);

    // Flatten headers from Record<string, string[]> to editable rows
    const headerRows: Array<{ name: string; value: string }> = [];
    for (const [name, values] of Object.entries(entry.headers)) {
      for (const value of values) {
        headerRows.push({ name, value });
      }
    }
    setEditHeaders(headerRows);
  }, []);

  // Release: forward as-is
  const handleRelease = useCallback(async () => {
    if (!selectedId) return;
    try {
      await execute({
        action: "release",
        params: { intercept_id: selectedId },
      });
      addToast({ type: "success", message: "Request released" });
      setSelectedId(null);
      refetchQueue();
    } catch (err) {
      addToast({
        type: "error",
        message: `Release failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [selectedId, execute, addToast, refetchQueue]);

  // Modify & Forward: apply edits and forward
  const handleModifyAndForward = useCallback(async () => {
    if (!selectedId) return;

    // Build override headers from edit state
    const overrideHeaders: Record<string, string> = {};
    for (const h of editHeaders) {
      if (h.name.trim()) {
        overrideHeaders[h.name.trim()] = h.value;
      }
    }

    try {
      await execute({
        action: "modify_and_forward",
        params: {
          intercept_id: selectedId,
          override_method: editMethod,
          override_url: editUrl,
          override_headers: overrideHeaders,
          override_body: editBody,
        },
      });
      addToast({ type: "success", message: "Request modified and forwarded" });
      setSelectedId(null);
      refetchQueue();
    } catch (err) {
      addToast({
        type: "error",
        message: `Modify & Forward failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [selectedId, editMethod, editUrl, editHeaders, editBody, execute, addToast, refetchQueue]);

  // Drop: discard request
  const handleDrop = useCallback(async () => {
    if (!selectedId) return;
    try {
      await execute({
        action: "drop",
        params: { intercept_id: selectedId },
      });
      addToast({ type: "warning", message: "Request dropped" });
      setSelectedId(null);
      refetchQueue();
    } catch (err) {
      addToast({
        type: "error",
        message: `Drop failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [selectedId, execute, addToast, refetchQueue]);

  // Toggle intercept rule enabled/disabled
  const handleToggleRule = useCallback(
    async (rule: InterceptRule) => {
      try {
        if (rule.enabled) {
          await configure({ intercept_rules: { disable: [rule.id] } });
          addToast({ type: "info", message: `Rule "${rule.id}" disabled` });
        } else {
          await configure({ intercept_rules: { enable: [rule.id] } });
          addToast({ type: "success", message: `Rule "${rule.id}" enabled` });
        }
        refetchConfig();
      } catch (err) {
        addToast({
          type: "error",
          message: `Failed to toggle rule: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    },
    [configure, addToast, refetchConfig],
  );

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
              loading={configLoading || configureLoading}
              onToggleRule={handleToggleRule}
            />
          )}
        </Tabs>
      </div>

      {activeTab === "queue" && selectedEntry && (
        <div className="intercept-detail">
          <div className="intercept-detail-header">
            <span className="intercept-detail-title">
              {selectedEntry.method} {extractHost(selectedEntry.url)}
            </span>
            <div className="intercept-detail-actions">
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

            {/* Headers */}
            <HeaderEditor headers={editHeaders} onChange={setEditHeaders} />

            {/* Body */}
            <BodyEditor body={editBody} onChange={setEditBody} />
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// QueuePanel — intercept queue table
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
            <th>Method</th>
            <th>URL</th>
            <th>Host</th>
            <th>Rules</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {queue.items.map((entry) => (
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
                <Badge variant={methodVariant(entry.method)}>
                  {entry.method}
                </Badge>
              </td>
              <td>
                <span className="intercept-queue-url" title={entry.url}>
                  {extractPath(entry.url)}
                </span>
              </td>
              <td>
                <span className="intercept-queue-host">
                  {extractHost(entry.url)}
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
          ))}
        </tbody>
      </Table>
    </div>
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
