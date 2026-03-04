import { useState, useCallback, useEffect, useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useManage } from "../../lib/mcp/hooks.js";
import { useToast } from "../../components/ui/Toast.js";
import type { QueryFilter, FlowEntry } from "../../lib/mcp/types.js";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Input } from "../../components/ui/Input.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Table } from "../../components/ui/Table.js";
import "./SessionsPage.css";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PROTOCOLS = ["HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "TCP"] as const;
const METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] as const;
const SESSION_STATES = ["active", "complete", "error"] as const;
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

/** Get the Badge variant for a session state. */
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

export function SessionsPage() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { manage, loading: executeLoading } = useManage();

  // --- Filter state ---
  const [showFilters, setShowFilters] = useState(false);
  const [selectedProtocol, setSelectedProtocol] = useState<string>("");
  const [selectedMethod, setSelectedMethod] = useState<string>("");
  const [statusCodeRange, setStatusCodeRange] = useState<string>("");
  const [urlPattern, setUrlPattern] = useState<string>("");
  const [selectedState, setSelectedState] = useState<string>("");

  // --- Pagination state ---
  const [pageSize, setPageSize] = useState<number>(50);
  const [offset, setOffset] = useState(0);

  // --- Polling state ---
  const [pollInterval, setPollInterval] = useState<number>(2000);

  // --- Selection state ---
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // --- Build query filter ---
  const filter = useMemo<QueryFilter | undefined>(() => {
    const f: QueryFilter = {};
    // Protocol filter: query tool accepts a single protocol string
    if (selectedProtocol) {
      f.protocol = selectedProtocol;
    }
    if (selectedMethod) {
      f.method = selectedMethod;
    }
    if (urlPattern.trim()) {
      f.url_pattern = urlPattern.trim();
    }
    if (statusCodeRange) {
      const code = parseInt(statusCodeRange, 10);
      if (!isNaN(code)) {
        f.status_code = code;
      }
    }
    if (selectedState) {
      f.state = selectedState;
    }
    return Object.keys(f).length > 0 ? f : undefined;
  }, [selectedProtocol, selectedMethod, urlPattern, statusCodeRange, selectedState]);

  // --- Query flows ---
  const { data, loading, error, refetch } = useQuery("flows", {
    pollInterval,
    filter,
    limit: pageSize,
    offset,
  });

  const sessions = data?.flows ?? [];
  const total = data?.total ?? 0;

  // Trigger refetch when filter/pagination options change.
  // useQuery stores options in a ref so changing them does not automatically
  // re-execute the query. This effect ensures an explicit refetch fires.
  const prevFilterKey = useRef("");
  useEffect(() => {
    const key = JSON.stringify({ filter, limit: pageSize, offset });
    if (prevFilterKey.current && prevFilterKey.current !== key) {
      refetch();
    }
    prevFilterKey.current = key;
  }, [filter, pageSize, offset, refetch]);

  // Reset offset when filter changes
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

  // --- Session state ---
  const handleStateChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setSelectedState(e.target.value);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  // --- URL pattern ---
  const handleUrlChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setUrlPattern(e.target.value);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  // --- Row click → navigate to detail ---
  const handleRowClick = useCallback(
    (session: FlowEntry) => {
      navigate(`/flows/${session.id}`);
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
      if (prev.size === sessions.length && sessions.length > 0) {
        return new Set();
      }
      return new Set(sessions.map((s) => s.id));
    });
  }, [sessions]);

  // --- Delete flows ---
  const handleDeleteSelected = useCallback(async () => {
    if (selectedIds.size === 0) return;

    const count = selectedIds.size;
    const confirmed = window.confirm(
      `Are you sure you want to delete ${count} flow(s)? This action cannot be undone.`,
    );
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
  }, [selectedIds, manage, addToast, refetch]);

  // --- Export flows ---
  const handleExport = useCallback(async () => {
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

  // --- Poll interval ---
  const handlePollChange = useCallback((e: React.ChangeEvent<HTMLSelectElement>) => {
    setPollInterval(parseInt(e.target.value, 10));
  }, []);

  // --- Render ---
  return (
    <div className="page sessions-page">
      <div className="sessions-header">
        <div className="sessions-header-info">
          <h1 className="page-title">Flows</h1>
          <p className="page-description">
            Captured HTTP/HTTPS, WebSocket, gRPC, and TCP flows.
          </p>
          {total > 0 && (
            <span className="sessions-total">{total} total flows</span>
          )}
        </div>
      </div>

      {/* Toolbar */}
      <div className="sessions-toolbar">
        <div className="sessions-toolbar-left">
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
            onClick={handleExport}
            disabled={executeLoading}
          >
            Export
          </Button>
        </div>
        <div className="sessions-toolbar-right">
          <div className="sessions-refresh-control">
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
        <div className="sessions-filters">
          <div className="sessions-filter-group">
            <span className="sessions-filter-label">Protocol</span>
            <div className="sessions-filter-checkboxes">
              <label className="sessions-filter-checkbox">
                <input
                  type="radio"
                  name="protocol-filter"
                  checked={selectedProtocol === ""}
                  onChange={() => selectProtocol("")}
                />
                All
              </label>
              {PROTOCOLS.map((proto) => (
                <label key={proto} className="sessions-filter-checkbox">
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

          <div className="sessions-filter-group">
            <span className="sessions-filter-label">Method</span>
            <select
              className="sessions-filter-select"
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

          <div className="sessions-filter-group">
            <span className="sessions-filter-label">Status</span>
            <select
              className="sessions-filter-select"
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

          <div className="sessions-filter-group">
            <span className="sessions-filter-label">Session State</span>
            <select
              className="sessions-filter-select"
              value={selectedState}
              onChange={handleStateChange}
            >
              <option value="">All</option>
              {SESSION_STATES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          <div className="sessions-filter-group sessions-url-filter">
            <span className="sessions-filter-label">URL Pattern</span>
            <Input
              placeholder="Filter by URL..."
              value={urlPattern}
              onChange={handleUrlChange}
            />
          </div>
        </div>
      )}

      {/* Bulk actions bar */}
      {selectedIds.size > 0 && (
        <div className="sessions-bulk-bar">
          <span className="sessions-bulk-count">{selectedIds.size}</span>
          <span>selected</span>
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
        <div className="sessions-error">
          Error loading flows: {error.message}
        </div>
      )}

      {/* Loading state (initial only) */}
      {loading && !data && (
        <div className="sessions-loading">
          <Spinner size="lg" />
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && data && sessions.length === 0 && (
        <div className="sessions-empty">
          <span>No flows captured yet.</span>
          <span>Start the proxy and send some traffic to see flows here.</span>
        </div>
      )}

      {/* Flow table */}
      {sessions.length > 0 && (
        <>
          <div className="sessions-table-wrapper">
            <Table className="sessions-table">
              <thead>
                <tr>
                  <th className="sessions-select-cell">
                    <input
                      type="checkbox"
                      checked={
                        selectedIds.size === sessions.length &&
                        sessions.length > 0
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
                  <th>Duration</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((session) => (
                  <tr
                    key={session.id}
                    className={
                      selectedIds.has(session.id)
                        ? "sessions-row--selected"
                        : ""
                    }
                    onClick={() => handleRowClick(session)}
                  >
                    <td className="sessions-select-cell">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(session.id)}
                        onClick={(e) => toggleSelect(session.id, e)}
                        readOnly
                      />
                    </td>
                    <td className="sessions-cell-id">{shortId(session.id)}</td>
                    <td>
                      <Badge variant={protocolVariant(session.protocol)}>
                        {session.protocol}
                      </Badge>
                    </td>
                    <td>
                      <Badge variant={stateVariant(session.state)}>
                        {session.state}
                      </Badge>
                    </td>
                    <td className="sessions-cell-method">{session.method}</td>
                    <td className="sessions-cell-url" title={session.url}>
                      {session.url}
                    </td>
                    <td>
                      {session.status_code > 0 ? (
                        <span className={statusCodeClass(session.status_code)}>
                          {session.status_code}
                        </span>
                      ) : (
                        <span className="status-code--other">--</span>
                      )}
                    </td>
                    <td className="sessions-cell-size">
                      {formatMessageCount(session.message_count)}
                    </td>
                    <td className="sessions-cell-duration">
                      {formatDuration(session.duration_ms)}
                    </td>
                    <td className="sessions-cell-timestamp">
                      {formatTimestamp(session.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>

          {/* Pagination */}
          <div className="sessions-pagination">
            <div className="sessions-pagination-info">
              Showing {offset + 1}--{Math.min(offset + pageSize, total)} of{" "}
              {total}
            </div>
            <div className="sessions-pagination-controls">
              <div className="sessions-page-size">
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
              <span className="sessions-pagination-info">
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
    </div>
  );
}
