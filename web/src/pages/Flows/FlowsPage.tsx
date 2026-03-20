import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { useDialog } from "../../components/ui/Dialog.js";
import { Input } from "../../components/ui/Input.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Table } from "../../components/ui/Table.js";
import { useToast } from "../../components/ui/Toast.js";
import { buildHarFromList, downloadHar } from "../../lib/export/har.js";
import { useManage, useQuery } from "../../lib/mcp/hooks.js";
import type { FlowEntry, ManageImportFlowsResult, QueryFilter } from "../../lib/mcp/types.js";
import "./FlowsPage.css";

// ---------------------------------------------------------------------------
// useDebounce — returns a debounced copy of `value` that only updates after
// `delay` milliseconds of inactivity.
// ---------------------------------------------------------------------------
function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROTOCOLS = ["HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "TCP", "SOCKS5+HTTPS", "SOCKS5+HTTP"] as const;
const METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] as const;
const FLOW_STATES = ["active", "complete", "error"] as const;
const SCHEMES = ["https", "http", "wss", "ws", "tcp"] as const;
const BLOCKED_BY = ["target_scope", "intercept_drop", "rate_limit", "safety_filter"] as const;
const PAGE_SIZES = [25, 50, 100] as const;
const POLL_INTERVALS = [
  { label: "Off", value: 0 },
  { label: "1s", value: 1000 },
  { label: "2s", value: 2000 },
  { label: "5s", value: 5000 },
  { label: "10s", value: 10000 },
] as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Return a shortened flow ID for display (first 8 characters). */
function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

/** Get the CSS class for a status code. */
function statusCodeClass(code: number): string {
  if (code >= 200 && code < 300) return "status-code--2xx";
  if (code >= 300 && code < 400) return "status-code--3xx";
  if (code >= 400 && code < 500) return "status-code--4xx";
  if (code >= 500 && code < 600) return "status-code--5xx";
  return "status-code--other";
}

/** Get the Badge variant for a protocol. */
function protocolVariant(protocol: string): "default" | "success" | "warning" | "danger" | "info" {
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
    case "SOCKS5+HTTPS":
      return "success";
    case "SOCKS5+HTTP":
      return "default";
    default:
      return "default";
  }
}

/** Format duration in milliseconds to a human-readable string. */
function formatDuration(ms: number): string {
  if (ms < 1) return "<1ms";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60000).toFixed(1)}m`;
}

/** Format an ISO timestamp to a short local time string. */
function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return ts;
  }
}

/** Format a message count for display. */
function formatMessageCount(count: number): string {
  return String(count);
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

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function FlowsPage() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { showDialog } = useDialog();
  const { manage, loading: executeLoading } = useManage();

  // --- Filter state ---
  const [showFilters, setShowFilters] = useState(false);
  const [selectedProtocol, setSelectedProtocol] = useState<string>("");
  const [selectedMethod, setSelectedMethod] = useState<string>("");
  const [statusCodeRange, setStatusCodeRange] = useState<string>("");
  const [urlPattern, setUrlPattern] = useState<string>("");
  const [selectedState, setSelectedState] = useState<string>("");
  const [bodyContains, setBodyContains] = useState<string>("");
  const [tagFilter, setTagFilter] = useState<string>("");
  const [selectedScheme, setSelectedScheme] = useState<string>("");
  const [selectedBlockedBy, setSelectedBlockedBy] = useState<string>("");
  const [hostFilter, setHostFilter] = useState<string>("");

  // Debounce text inputs to avoid firing expensive queries on every keystroke
  const debouncedUrlPattern = useDebounce(urlPattern, 300);
  const debouncedBodyContains = useDebounce(bodyContains, 300);
  const debouncedTagFilter = useDebounce(tagFilter, 300);
  const debouncedHostFilter = useDebounce(hostFilter, 300);

  // --- Pagination state ---
  const [pageSize, setPageSize] = useState<number>(50);
  const [offset, setOffset] = useState(0);

  // --- Sorting state ---
  const [sortBy, setSortBy] = useState<string>("");

  // --- Polling state ---
  const [pollInterval, setPollInterval] = useState<number>(2000);

  // --- Selection state ---
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // --- Import dialog state ---
  const [showImportDialog, setShowImportDialog] = useState(false);
  const [importPath, setImportPath] = useState("");
  const [importConflictPolicy, setImportConflictPolicy] = useState<"skip" | "replace">("skip");
  const [importResult, setImportResult] = useState<ManageImportFlowsResult | null>(null);

  // --- Build query filter ---
  const filter = useMemo<QueryFilter | undefined>(() => {
    const f: QueryFilter = {};
    // Protocol filter: query tool accepts a single protocol string
    if (selectedProtocol) {
      f.protocol = selectedProtocol;
    }
    if (selectedScheme) {
      f.scheme = selectedScheme;
    }
    if (selectedMethod) {
      f.method = selectedMethod;
    }
    if (debouncedUrlPattern.trim()) {
      f.url_pattern = debouncedUrlPattern.trim();
    }
    if (statusCodeRange) {
      const code = parseInt(statusCodeRange, 10);
      if (!isNaN(code)) {
        f.status_code = code;
      }
    }
    if (selectedBlockedBy) {
      f.blocked_by = selectedBlockedBy;
    }
    if (selectedState) {
      f.state = selectedState;
    }
    if (debouncedHostFilter.trim()) {
      f.host = debouncedHostFilter.trim();
    }
    if (debouncedBodyContains.trim()) {
      f.body_contains = debouncedBodyContains.trim();
    }
    if (debouncedTagFilter.trim()) {
      f.tag = debouncedTagFilter.trim();
    }
    return Object.keys(f).length > 0 ? f : undefined;
  }, [selectedProtocol, selectedScheme, selectedMethod, debouncedUrlPattern, statusCodeRange, selectedBlockedBy, selectedState, debouncedHostFilter, debouncedBodyContains, debouncedTagFilter]);

  // --- Query flows ---
  const { data, loading, error, refetch } = useQuery("flows", {
    pollInterval,
    filter,
    sortBy: sortBy || undefined,
    limit: pageSize,
    offset,
  });

  const flows = data?.flows ?? [];
  const total = data?.total ?? 0;

  // Trigger refetch when filter/pagination options change.
  // useQuery stores options in a ref so changing them does not automatically
  // re-execute the query. This effect ensures an explicit refetch fires.
  const prevFilterKey = useRef("");
  useEffect(() => {
    const key = JSON.stringify({ filter, sortBy, limit: pageSize, offset });
    if (prevFilterKey.current && prevFilterKey.current !== key) {
      refetch();
    }
    prevFilterKey.current = key;
  }, [filter, sortBy, pageSize, offset, refetch]);

  // Reset offset and selection when debounced text filters change
  const prevTextFilterKey = useRef("");
  useEffect(() => {
    const key = JSON.stringify({ debouncedUrlPattern, debouncedBodyContains, debouncedTagFilter, debouncedHostFilter });
    if (prevTextFilterKey.current && prevTextFilterKey.current !== key) {
      setOffset(0);
      setSelectedIds(new Set());
    }
    prevTextFilterKey.current = key;
  }, [debouncedUrlPattern, debouncedBodyContains, debouncedTagFilter, debouncedHostFilter]);

  // Reset offset when filter changes (used by non-debounced filter controls)
  const handleFilterChange = useCallback(() => {
    setOffset(0);
    setSelectedIds(new Set());
  }, []);

  // --- Protocol radio select ---
  const selectProtocol = useCallback(
    (protocol: string) => {
      setSelectedProtocol(protocol);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  // --- Method select ---
  const handleMethodChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setSelectedMethod(e.target.value);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  // --- Status code ---
  const handleStatusCodeChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setStatusCodeRange(e.target.value);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  // --- Flow state ---
  const handleStateChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setSelectedState(e.target.value);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  // --- Scheme select ---
  const handleSchemeChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setSelectedScheme(e.target.value);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  // --- Blocked by select ---
  const handleBlockedByChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setSelectedBlockedBy(e.target.value);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  // --- Host filter (debounced — offset/selection reset via effect) ---
  const handleHostFilterChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setHostFilter(e.target.value);
    },
    [],
  );

  // --- URL pattern (debounced — offset/selection reset via effect) ---
  const handleUrlChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setUrlPattern(e.target.value);
    },
    [],
  );

  // --- Body contains (debounced — offset/selection reset via effect) ---
  const handleBodyContainsChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setBodyContains(e.target.value);
    },
    [],
  );

  // --- Tag filter (debounced — offset/selection reset via effect) ---
  const handleTagFilterChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setTagFilter(e.target.value);
    },
    [],
  );

  // --- Row click → navigate to detail ---
  const handleRowClick = useCallback(
    (flow: FlowEntry) => {
      navigate(`/flows/${flow.id}`);
    },
    [navigate],
  );

  // --- Selection ---
  const toggleSelect = useCallback((id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  const toggleSelectAll = useCallback(() => {
    setSelectedIds((prev) => {
      if (prev.size === flows.length && flows.length > 0) {
        return new Set();
      }
      return new Set(flows.map((s) => s.id));
    });
  }, [flows]);

  // --- Delete flows ---
  const handleDeleteSelected = useCallback(async () => {
    if (selectedIds.size === 0) return;

    const count = selectedIds.size;
    const confirmed = await showDialog({
      title: "Delete Flows",
      message: `Are you sure you want to delete ${count} flow(s)? This action cannot be undone.`,
      variant: "confirm",
      confirmLabel: "Delete",
      confirmVariant: "danger",
    });
    if (!confirmed) return;

    try {
      for (const id of selectedIds) {
        await manage({
          action: "delete_flows",
          params: { flow_id: id, confirm: true },
        });
      }
      addToast({ type: "success", message: `Deleted ${count} flow(s)` });
      setSelectedIds(new Set());
      await refetch();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to delete flows: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [selectedIds, showDialog, manage, addToast, refetch]);

  // --- Export flows (JSONL via backend) ---
  const handleExportJsonl = useCallback(async () => {
    try {
      await manage({
        action: "export_flows",
        params: { format: "jsonl" },
      });
      addToast({ type: "success", message: "Flows exported (JSONL)" });
    } catch (err) {
      addToast({
        type: "error",
        message: `Export failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [manage, addToast]);

  // --- Export flows (HAR) ---
  const handleExportHar = useCallback(() => {
    const targetFlows = selectedIds.size > 0
      ? flows.filter((f) => selectedIds.has(f.id))
      : flows;
    if (targetFlows.length === 0) {
      addToast({ type: "warning", message: "No flows to export" });
      return;
    }
    try {
      const har = buildHarFromList(targetFlows);
      const timestamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
      downloadHar(har, `flows-${timestamp}.har`);
      addToast({
        type: "success",
        message: `HAR file downloaded (${targetFlows.length} flow(s))`,
      });
    } catch (err) {
      addToast({
        type: "error",
        message: `HAR export failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [flows, selectedIds, addToast]);

  // --- Import flows ---
  const handleImportOpen = useCallback(() => {
    setImportPath("");
    setImportConflictPolicy("skip");
    setImportResult(null);
    setShowImportDialog(true);
  }, []);

  const handleImportClose = useCallback(() => {
    setShowImportDialog(false);
    setImportPath("");
    setImportConflictPolicy("skip");
    setImportResult(null);
  }, []);

  const handleImportExecute = useCallback(async () => {
    if (!importPath.trim()) return;

    try {
      const result = await manage<ManageImportFlowsResult>({
        action: "import_flows",
        params: {
          input_path: importPath.trim(),
          on_conflict: importConflictPolicy,
        },
      });
      setImportResult(result);
      addToast({
        type: "success",
        message: `Imported ${result.imported} flow(s)`,
      });
      await refetch();
    } catch (err) {
      addToast({
        type: "error",
        message: `Import failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [importPath, importConflictPolicy, manage, addToast, refetch]);

  // --- Pagination ---
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.floor(offset / pageSize) + 1;

  const goToPage = useCallback(
    (page: number) => {
      const newOffset = (page - 1) * pageSize;
      setOffset(newOffset);
      setSelectedIds(new Set());
    },
    [pageSize],
  );

  const handlePageSizeChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      const newSize = parseInt(e.target.value, 10);
      setPageSize(newSize);
      setOffset(0);
      setSelectedIds(new Set());
    },
    [],
  );

  // --- Sorting ---
  const handleSort = useCallback(
    (field: string) => {
      setSortBy((prev) => (prev === field ? "" : field));
      setOffset(0);
      setSelectedIds(new Set());
    },
    [],
  );

  // --- Poll interval ---
  const handlePollChange = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => {
    setPollInterval(parseInt(e.target.value, 10));
  }, []);

  // --- Render ---
  return (
    <div className="page flows-page">
      <div className="flows-header">
        <div className="flows-header-info">
          <h1 className="page-title">Flows</h1>
          <p className="page-description">
            Captured HTTP/HTTPS, WebSocket, gRPC, and TCP flows.
          </p>
          {total > 0 && (
            <span className="flows-total">{total} total flows</span>
          )}
        </div>
      </div>

      {/* Toolbar */}
      <div className="flows-toolbar">
        <div className="flows-toolbar-left">
          <Button
            variant={showFilters ? "primary" : "secondary"}
            size="sm"
            onClick={() => setShowFilters((v) => !v)}
          >
            Filters
          </Button>
          <Button variant="secondary" size="sm" onClick={() => refetch()}>
            Refresh
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleExportJsonl}
            disabled={executeLoading}
          >
            Export JSONL
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleExportHar}
          >
            Export HAR
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleImportOpen}
            disabled={executeLoading}
          >
            Import
          </Button>
        </div>
        <div className="flows-toolbar-right">
          <div className="flows-refresh-control">
            <span>Auto:</span>
            <select value={pollInterval} onChange={handlePollChange}>
              {POLL_INTERVALS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Filters panel */}
      {showFilters && (
        <div className="flows-filters">
          <div className="flows-filter-group">
            <span className="flows-filter-label">Protocol</span>
            <div className="flows-filter-checkboxes">
              <label className="flows-filter-checkbox">
                <input
                  type="radio"
                  name="protocol-filter"
                  checked={selectedProtocol === ""}
                  onChange={() => selectProtocol("")}
                />
                All
              </label>
              {PROTOCOLS.map((proto) => (
                <label key={proto} className="flows-filter-checkbox">
                  <input
                    type="radio"
                    name="protocol-filter"
                    checked={selectedProtocol === proto}
                    onChange={() => selectProtocol(proto)}
                  />
                  {proto}
                </label>
              ))}
            </div>
          </div>

          <div className="flows-filter-group">
            <span className="flows-filter-label">Method</span>
            <select
              className="flows-filter-select"
              value={selectedMethod}
              onChange={handleMethodChange}
            >
              <option value="">All</option>
              {METHODS.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>

          <div className="flows-filter-group">
            <span className="flows-filter-label">Status</span>
            <select
              className="flows-filter-select"
              value={statusCodeRange}
              onChange={handleStatusCodeChange}
            >
              <option value="">All</option>
              <option value="200">200 OK</option>
              <option value="301">301 Redirect</option>
              <option value="400">400 Bad Request</option>
              <option value="500">500 Server Error</option>
            </select>
          </div>

          <div className="flows-filter-group">
            <span className="flows-filter-label">Flow State</span>
            <select
              className="flows-filter-select"
              value={selectedState}
              onChange={handleStateChange}
            >
              <option value="">All</option>
              {FLOW_STATES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          <div className="flows-filter-group">
            <span className="flows-filter-label">Scheme</span>
            <select
              className="flows-filter-select"
              value={selectedScheme}
              onChange={handleSchemeChange}
            >
              <option value="">All</option>
              {SCHEMES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          <div className="flows-filter-group">
            <span className="flows-filter-label">Blocked By</span>
            <select
              className="flows-filter-select"
              value={selectedBlockedBy}
              onChange={handleBlockedByChange}
            >
              <option value="">All</option>
              {BLOCKED_BY.map((b) => (
                <option key={b} value={b}>
                  {b}
                </option>
              ))}
            </select>
          </div>

          <div className="flows-filter-group flows-text-filter">
            <span className="flows-filter-label">Host</span>
            <Input
              placeholder="Filter by host..."
              value={hostFilter}
              onChange={handleHostFilterChange}
            />
          </div>

          <div className="flows-filter-group flows-url-filter">
            <span className="flows-filter-label">URL Pattern</span>
            <Input
              placeholder="Filter by URL..."
              value={urlPattern}
              onChange={handleUrlChange}
            />
          </div>

          <div className="flows-filter-group flows-text-filter">
            <span className="flows-filter-label">Body Contains</span>
            <Input
              placeholder="Search response body..."
              value={bodyContains}
              onChange={handleBodyContainsChange}
            />
          </div>

          <div className="flows-filter-group flows-text-filter">
            <span className="flows-filter-label">Tag</span>
            <Input
              placeholder="Filter by tag..."
              value={tagFilter}
              onChange={handleTagFilterChange}
            />
          </div>
        </div>
      )}

      {/* Bulk actions bar */}
      {selectedIds.size > 0 && (
        <div className="flows-bulk-bar">
          <span className="flows-bulk-count">{selectedIds.size}</span>
          <span>selected</span>
          <Button
            variant="secondary"
            size="sm"
            onClick={handleExportHar}
          >
            Export HAR
          </Button>
          <Button
            variant="danger"
            size="sm"
            onClick={handleDeleteSelected}
            disabled={executeLoading}
          >
            Delete
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSelectedIds(new Set())}
          >
            Clear
          </Button>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="flows-error">
          Error loading flows: {error.message}
        </div>
      )}

      {/* Loading state (initial only) */}
      {loading && !data && (
        <div className="flows-loading">
          <Spinner size="lg" />
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && data && flows.length === 0 && (
        <div className="flows-empty">
          <span>No flows captured yet.</span>
          <span>Start the proxy and send some traffic to see flows here.</span>
        </div>
      )}

      {/* Flow table */}
      {flows.length > 0 && (
        <>
          <div className="flows-table-wrapper">
            <Table className="flows-table">
              <thead>
                <tr>
                  <th className="flows-select-cell">
                    <input
                      type="checkbox"
                      checked={
                        selectedIds.size === flows.length &&
                        flows.length > 0
                      }
                      onChange={toggleSelectAll}
                    />
                  </th>
                  <th>ID</th>
                  <th>Protocol</th>
                  <th>State</th>
                  <th>Method</th>
                  <th>URL</th>
                  <th>Status</th>
                  <th>Messages</th>
                  <th
                    className="flows-sortable-header"
                    onClick={() => handleSort("duration_ms")}
                  >
                    Duration {sortBy === "duration_ms" ? "\u25BC" : ""}
                  </th>
                  <th
                    className="flows-sortable-header"
                    onClick={() => handleSort("timestamp")}
                  >
                    Time {sortBy === "timestamp" ? "\u25BC" : ""}
                  </th>
                </tr>
              </thead>
              <tbody>
                {flows.map((flow) => (
                  <tr
                    key={flow.id}
                    className={
                      selectedIds.has(flow.id)
                        ? "flows-row--selected"
                        : ""
                    }
                    onClick={() => handleRowClick(flow)}
                  >
                    <td className="flows-select-cell">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(flow.id)}
                        onClick={(e) => toggleSelect(flow.id, e)}
                        readOnly
                      />
                    </td>
                    <td className="flows-cell-id">{shortId(flow.id)}</td>
                    <td>
                      <Badge variant={protocolVariant(flow.protocol)}>
                        {flow.protocol}
                      </Badge>
                      {flow.tags?.streaming_type === "sse" && (
                        <Badge variant="warning">SSE</Badge>
                      )}
                    </td>
                    <td>
                      <Badge variant={stateVariant(flow.state)}>
                        {flow.state}
                      </Badge>
                    </td>
                    <td className="flows-cell-method">{flow.method}</td>
                    <td className="flows-cell-url" title={flow.url}>
                      {flow.url}
                    </td>
                    <td>
                      {flow.status_code > 0 ? (
                        <span className={statusCodeClass(flow.status_code)}>
                          {flow.status_code}
                        </span>
                      ) : (
                        <span className="status-code--other">--</span>
                      )}
                    </td>
                    <td className="flows-cell-size">
                      {formatMessageCount(flow.message_count)}
                    </td>
                    <td className="flows-cell-duration">
                      {formatDuration(flow.duration_ms)}
                    </td>
                    <td className="flows-cell-timestamp">
                      {formatTimestamp(flow.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>

          {/* Pagination */}
          <div className="flows-pagination">
            <div className="flows-pagination-info">
              Showing {offset + 1}--{Math.min(offset + pageSize, total)} of{" "}
              {total}
            </div>
            <div className="flows-pagination-controls">
              <div className="flows-page-size">
                <span>Rows:</span>
                <select value={pageSize} onChange={handlePageSizeChange}>
                  {PAGE_SIZES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
              <Button
                variant="ghost"
                size="sm"
                disabled={currentPage <= 1}
                onClick={() => goToPage(currentPage - 1)}
              >
                Prev
              </Button>
              <span className="flows-pagination-info">
                {currentPage} / {totalPages}
              </span>
              <Button
                variant="ghost"
                size="sm"
                disabled={currentPage >= totalPages}
                onClick={() => goToPage(currentPage + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        </>
      )}

      {/* Import dialog */}
      {showImportDialog && (
        <div className="flows-dialog-overlay" onClick={handleImportClose}>
          <div className="flows-dialog" onClick={(e) => e.stopPropagation()}>
            <h3 className="flows-dialog-title">Import Flows</h3>
            <p className="flows-dialog-description">
              Import flows from a JSONL file on the server.
            </p>

            <div className="flows-dialog-field">
              <Input
                label="File path"
                placeholder="/path/to/flows.jsonl"
                value={importPath}
                onChange={(e) => setImportPath(e.target.value)}
              />
              <span className="flows-dialog-hint">
                Server-side path to the JSONL file
              </span>
            </div>

            <div className="flows-dialog-field">
              <label className="flows-dialog-label">Conflict policy</label>
              <select
                className="flows-dialog-select"
                value={importConflictPolicy}
                onChange={(e) =>
                  setImportConflictPolicy(e.target.value as "skip" | "replace")
                }
              >
                <option value="skip">Skip (keep existing)</option>
                <option value="replace">Replace (overwrite existing)</option>
              </select>
            </div>

            {/* Import result summary */}
            {importResult && (
              <div className="flows-import-result">
                <div className="flows-import-result-row">
                  <span className="flows-import-result-label">Imported:</span>
                  <span className="flows-import-result-value flows-import-result-value--success">
                    {importResult.imported}
                  </span>
                </div>
                <div className="flows-import-result-row">
                  <span className="flows-import-result-label">Skipped:</span>
                  <span className="flows-import-result-value">
                    {importResult.skipped}
                  </span>
                </div>
                <div className="flows-import-result-row">
                  <span className="flows-import-result-label">Errors:</span>
                  <span
                    className={`flows-import-result-value${importResult.errors > 0
                        ? " flows-import-result-value--error"
                        : ""
                      }`}
                  >
                    {importResult.errors}
                  </span>
                </div>
                {importResult.error_details &&
                  importResult.error_details.length > 0 && (
                    <div className="flows-import-errors">
                      <span className="flows-import-errors-title">
                        Error details:
                      </span>
                      <ul className="flows-import-errors-list">
                        {importResult.error_details.map((detail) => (
                          <li key={detail.index}>
                            Line {detail.index}: {detail.error}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
              </div>
            )}

            <div className="flows-dialog-actions">
              <Button
                variant="secondary"
                size="sm"
                onClick={handleImportClose}
              >
                {importResult ? "Close" : "Cancel"}
              </Button>
              {!importResult && (
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleImportExecute}
                  disabled={executeLoading || !importPath.trim()}
                >
                  {executeLoading ? "Importing..." : "Import"}
                </Button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
