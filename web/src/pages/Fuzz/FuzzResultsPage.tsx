import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { CodeViewer } from "../../components/ui/CodeViewer.js";
import { Input } from "../../components/ui/Input.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Table } from "../../components/ui/Table.js";
import { useToast } from "../../components/ui/Toast.js";
import { useFuzz, useQuery } from "../../lib/mcp/hooks.js";
import type {
  FlowDetailResult,
  FuzzJobEntry,
  FuzzResultEntry,
  QueryFilter,
} from "../../lib/mcp/types.js";
import "./FuzzResultsPage.css";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PAGE_SIZES = [25, 50, 100] as const;

const SORT_OPTIONS = [
  { value: "", label: "Default" },
  { value: "status_code", label: "Status Code" },
  { value: "duration_ms", label: "Duration" },
  { value: "response_length", label: "Body Length" },
] as const;

// Active jobs poll every 2s, completed jobs poll less frequently
const ACTIVE_POLL_MS = 2000;
const COMPLETED_POLL_MS = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

function statusCodeClass(code: number): string {
  if (code >= 200 && code < 300) return "fuzz-status-code--2xx";
  if (code >= 300 && code < 400) return "fuzz-status-code--3xx";
  if (code >= 400 && code < 500) return "fuzz-status-code--4xx";
  if (code >= 500 && code < 600) return "fuzz-status-code--5xx";
  return "fuzz-status-code--other";
}

function statusVariant(
  status: string,
): "default" | "success" | "warning" | "danger" | "info" {
  switch (status) {
    case "running":
      return "info";
    case "completed":
      return "success";
    case "paused":
      return "warning";
    case "cancelled":
    case "error":
      return "danger";
    default:
      return "default";
  }
}

function formatDuration(ms: number): string {
  if (ms < 1) return "<1ms";
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
}

function progressPercent(job: FuzzJobEntry): number {
  if (job.total <= 0) return 0;
  return Math.min(100, Math.round((job.completed_count / job.total) * 100));
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function FuzzResultsPage() {
  const { fuzzId } = useParams<{ fuzzId: string }>();
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { fuzz: fuzzAction, loading: executeLoading } = useFuzz();

  // --- Filter state ---
  const [statusCodeFilter, setStatusCodeFilter] = useState<string>("");
  const [bodyContainsFilter, setBodyContainsFilter] = useState<string>("");
  const [sortBy, setSortBy] = useState<string>("");

  // --- Pagination state ---
  const [pageSize, setPageSize] = useState<number>(50);
  const [offset, setOffset] = useState(0);

  // --- Detail panel ---
  const [selectedResult, setSelectedResult] = useState<FuzzResultEntry | null>(
    null,
  );
  const [detailFlow, setDetailFlow] = useState<FlowDetailResult | null>(
    null,
  );
  const [detailLoading, setDetailLoading] = useState(false);

  // --- Query fuzz job info ---
  const {
    data: jobsData,
    loading: jobLoading,
  } = useQuery("fuzz_jobs", {
    pollInterval: ACTIVE_POLL_MS,
    filter: { status: undefined } as QueryFilter,
    enabled: !!fuzzId,
  });

  // Find this job in the jobs list
  const job = useMemo(() => {
    if (!jobsData?.jobs || !fuzzId) return null;
    return jobsData.jobs.find((j) => j.id === fuzzId) ?? null;
  }, [jobsData, fuzzId]);

  const isActive = job?.status === "running" || job?.status === "paused";
  const resultsPollInterval = isActive ? ACTIVE_POLL_MS : COMPLETED_POLL_MS;

  // --- Build results filter ---
  const resultsFilter = useMemo<QueryFilter | undefined>(() => {
    const f: QueryFilter = {};
    if (statusCodeFilter) {
      const code = parseInt(statusCodeFilter, 10);
      if (!isNaN(code)) f.status_code = code;
    }
    if (bodyContainsFilter.trim()) {
      f.body_contains = bodyContainsFilter.trim();
    }
    return Object.keys(f).length > 0 ? f : undefined;
  }, [statusCodeFilter, bodyContainsFilter]);

  // --- Query fuzz results ---
  const {
    data: resultsData,
    loading: resultsLoading,
    error: resultsError,
    refetch: refetchResults,
  } = useQuery("fuzz_results", {
    fuzzId: fuzzId,
    pollInterval: resultsPollInterval,
    filter: resultsFilter,
    sortBy: sortBy || undefined,
    limit: pageSize,
    offset,
    enabled: !!fuzzId,
  });

  const results = resultsData?.results ?? [];
  const total = resultsData?.total ?? 0;
  const summary = resultsData?.summary;

  // Trigger refetch when filter/pagination/sort changes
  const prevFilterKey = useRef("");
  useEffect(() => {
    const key = JSON.stringify({
      filter: resultsFilter,
      sortBy,
      limit: pageSize,
      offset,
    });
    if (prevFilterKey.current && prevFilterKey.current !== key) {
      refetchResults();
    }
    prevFilterKey.current = key;
  }, [resultsFilter, sortBy, pageSize, offset, refetchResults]);

  // --- Filter change handler ---
  const handleFilterChange = useCallback(() => {
    setOffset(0);
    setSelectedResult(null);
  }, []);

  const handleStatusCodeChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setStatusCodeFilter(e.target.value);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  const handleBodyContainsChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setBodyContainsFilter(e.target.value);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  const handleSortChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setSortBy(e.target.value);
    },
    [],
  );

  // --- Pagination ---
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.floor(offset / pageSize) + 1;

  const goToPage = useCallback(
    (page: number) => {
      setOffset((page - 1) * pageSize);
      setSelectedResult(null);
    },
    [pageSize],
  );

  const handlePageSizeChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setPageSize(parseInt(e.target.value, 10));
      setOffset(0);
      setSelectedResult(null);
    },
    [],
  );

  // --- Select a result row and load detail ---
  const { client, status: mcpStatus } = useMcpContextSafe();
  const handleSelectResult = useCallback(
    async (result: FuzzResultEntry) => {
      setSelectedResult(result);
      if (!result.flow_id) {
        setDetailFlow(null);
        return;
      }

      setDetailLoading(true);
      try {
        if (!client || mcpStatus !== "connected") {
          setDetailFlow(null);
          return;
        }
        const flowDetail = await client.query({
          resource: "flow",
          id: result.flow_id,
        });
        setDetailFlow(flowDetail as FlowDetailResult);
      } catch {
        setDetailFlow(null);
      } finally {
        setDetailLoading(false);
      }
    },
    [client, mcpStatus],
  );

  // --- Job control actions ---
  const handleJobAction = useCallback(
    async (action: "fuzz_pause" | "fuzz_resume" | "fuzz_cancel") => {
      if (!fuzzId) return;
      try {
        await fuzzAction({ action, params: { fuzz_id: fuzzId } });
        addToast({
          type: "success",
          message: `Job ${action.replace("fuzz_", "")}d`,
        });
      } catch (err) {
        addToast({
          type: "error",
          message: `Action failed: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    },
    [fuzzId, fuzzAction, addToast],
  );

  if (!fuzzId) {
    return (
      <div className="page fuzz-results-page">
        <h1 className="page-title">Fuzz Results</h1>
        <div className="fuzz-results-empty">No fuzz ID specified.</div>
      </div>
    );
  }

  return (
    <div className="page fuzz-results-page">
      {/* Header with back button */}
      <div className="fuzz-results-header">
        <div className="fuzz-results-header-left">
          <Button variant="ghost" size="sm" onClick={() => navigate("/fuzz")}>
            Back
          </Button>
          <h1 className="page-title">Fuzz Results</h1>
          <code className="fuzz-results-id">{shortId(fuzzId)}</code>
        </div>
        {job && (
          <div className="fuzz-results-header-right">
            {job.status === "running" && (
              <>
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => handleJobAction("fuzz_pause")}
                  disabled={executeLoading}
                >
                  Pause
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => handleJobAction("fuzz_cancel")}
                  disabled={executeLoading}
                >
                  Cancel
                </Button>
              </>
            )}
            {job.status === "paused" && (
              <>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={() => handleJobAction("fuzz_resume")}
                  disabled={executeLoading}
                >
                  Resume
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => handleJobAction("fuzz_cancel")}
                  disabled={executeLoading}
                >
                  Cancel
                </Button>
              </>
            )}
          </div>
        )}
      </div>

      {/* Job stats */}
      {job && (
        <div className="fuzz-results-stats">
          <div className="fuzz-stat">
            <span className="fuzz-stat-label">Status</span>
            <Badge variant={statusVariant(job.status)}>{job.status}</Badge>
          </div>
          <div className="fuzz-stat">
            <span className="fuzz-stat-label">Progress</span>
            <div className="fuzz-stat-progress">
              <div className="fuzz-stat-progress-bar">
                <div
                  className="fuzz-stat-progress-fill"
                  style={{ width: `${progressPercent(job)}%` }}
                />
              </div>
              <span className="fuzz-stat-value">
                {job.completed_count}/{job.total} ({progressPercent(job)}%)
              </span>
            </div>
          </div>
          <div className="fuzz-stat">
            <span className="fuzz-stat-label">Errors</span>
            <span
              className={
                job.error_count > 0
                  ? "fuzz-stat-value fuzz-stat-value--danger"
                  : "fuzz-stat-value"
              }
            >
              {job.error_count}
            </span>
          </div>
          {summary && (
            <>
              <div className="fuzz-stat">
                <span className="fuzz-stat-label">Avg Duration</span>
                <span className="fuzz-stat-value">
                  {formatDuration(summary.avg_duration_ms)}
                </span>
              </div>
              <div className="fuzz-stat">
                <span className="fuzz-stat-label">Status Distribution</span>
                <div className="fuzz-stat-distribution">
                  {Object.entries(summary.status_distribution ?? {}).map(
                    ([code, count]) => (
                      <span key={code} className="fuzz-stat-dist-item">
                        <span className={statusCodeClass(parseInt(code, 10))}>
                          {code}
                        </span>
                        : {count}
                      </span>
                    ),
                  )}
                </div>
              </div>
            </>
          )}
          {job.tag && (
            <div className="fuzz-stat">
              <span className="fuzz-stat-label">Tag</span>
              <Badge variant="default">{job.tag}</Badge>
            </div>
          )}
        </div>
      )}

      {jobLoading && !job && (
        <div className="fuzz-results-loading">
          <Spinner size="md" />
        </div>
      )}

      {/* Filters toolbar */}
      <div className="fuzz-results-toolbar">
        <div className="fuzz-results-toolbar-left">
          <Input
            placeholder="Status code..."
            value={statusCodeFilter}
            onChange={handleStatusCodeChange}
          />
          <Input
            placeholder="Body contains..."
            value={bodyContainsFilter}
            onChange={handleBodyContainsChange}
          />
          <div className="fuzz-results-sort">
            <span>Sort:</span>
            <select
              className="fuzz-results-sort-select"
              value={sortBy}
              onChange={handleSortChange}
            >
              {SORT_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => refetchResults()}
          >
            Refresh
          </Button>
        </div>
      </div>

      {/* Error */}
      {resultsError && (
        <div className="fuzz-results-error">
          Error loading results: {resultsError.message}
        </div>
      )}

      {/* Loading (initial) */}
      {resultsLoading && !resultsData && (
        <div className="fuzz-results-loading">
          <Spinner size="lg" />
        </div>
      )}

      {/* Empty */}
      {!resultsLoading && !resultsError && resultsData && results.length === 0 && (
        <div className="fuzz-results-empty">
          {isActive
            ? "Results will appear here as the fuzz campaign progresses."
            : "No results match the current filters."}
        </div>
      )}

      {/* Results content */}
      {results.length > 0 && (
        <div className="fuzz-results-content">
          {/* Results table */}
          <div className="fuzz-results-table-wrapper">
            <Table className="fuzz-results-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Status</th>
                  <th>Length</th>
                  <th>Duration</th>
                  <th>Payloads</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {results.map((result) => (
                  <tr
                    key={result.id}
                    className={
                      selectedResult?.id === result.id
                        ? "fuzz-results-row--selected"
                        : ""
                    }
                    onClick={() => handleSelectResult(result)}
                  >
                    <td className="fuzz-results-cell-index">{result.index}</td>
                    <td>
                      {result.status_code > 0 ? (
                        <span className={statusCodeClass(result.status_code)}>
                          {result.status_code}
                        </span>
                      ) : (
                        <span className="fuzz-status-code--other">--</span>
                      )}
                    </td>
                    <td className="fuzz-results-cell-length">
                      {formatBytes(result.response_length)}
                    </td>
                    <td className="fuzz-results-cell-duration">
                      {formatDuration(result.duration_ms)}
                    </td>
                    <td className="fuzz-results-cell-payloads">
                      {Object.entries(result.payloads ?? {}).map(([key, value]) => (
                        <span key={key} className="fuzz-payload-tag">
                          <span className="fuzz-payload-key">{key}:</span>
                          {value}
                        </span>
                      ))}
                    </td>
                    <td className="fuzz-results-cell-error">
                      {result.error && (
                        <span className="fuzz-result-error" title={result.error}>
                          {result.error.length > 40
                            ? result.error.slice(0, 40) + "..."
                            : result.error}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>

            {/* Pagination */}
            <div className="fuzz-results-pagination">
              <div className="fuzz-results-pagination-info">
                Showing {offset + 1}--{Math.min(offset + pageSize, total)} of{" "}
                {total}
              </div>
              <div className="fuzz-results-pagination-controls">
                <div className="fuzz-results-page-size">
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
                <span className="fuzz-results-pagination-info">
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
          </div>

          {/* Detail panel */}
          {selectedResult && (
            <div className="fuzz-results-detail">
              <div className="fuzz-results-detail-header">
                <span className="fuzz-results-detail-title">
                  Result #{selectedResult.index}
                </span>
                {selectedResult.status_code > 0 && (
                  <span
                    className={statusCodeClass(selectedResult.status_code)}
                  >
                    {selectedResult.status_code}
                  </span>
                )}
                <span className="fuzz-results-detail-duration">
                  {formatDuration(selectedResult.duration_ms)}
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelectedResult(null)}
                >
                  Close
                </Button>
              </div>

              {/* Payloads */}
              <div className="fuzz-results-detail-section">
                <h4 className="fuzz-results-detail-section-title">Payloads</h4>
                <div className="fuzz-results-detail-payloads">
                  {Object.entries(selectedResult.payloads ?? {}).map(
                    ([key, value]) => (
                      <div key={key} className="fuzz-results-detail-payload">
                        <span className="fuzz-payload-key">{key}</span>
                        <code className="fuzz-payload-value">{value}</code>
                      </div>
                    ),
                  )}
                </div>
              </div>

              {/* Error */}
              {selectedResult.error && (
                <div className="fuzz-results-detail-section">
                  <h4 className="fuzz-results-detail-section-title">Error</h4>
                  <pre className="fuzz-results-detail-error">
                    {selectedResult.error}
                  </pre>
                </div>
              )}

              {/* Response details */}
              {detailLoading && (
                <div className="fuzz-results-detail-loading">
                  <Spinner size="sm" />
                  <span>Loading response details...</span>
                </div>
              )}

              {detailFlow && !detailLoading && (
                <>
                  {/* Response headers */}
                  <div className="fuzz-results-detail-section">
                    <h4 className="fuzz-results-detail-section-title">
                      Response Headers
                    </h4>
                    <div className="fuzz-results-detail-headers">
                      {Object.entries(detailFlow.response_headers ?? {}).map(
                        ([name, values]) => (
                          <div
                            key={name}
                            className="fuzz-results-detail-header-row"
                          >
                            <span className="fuzz-header-name">{name}:</span>
                            <span className="fuzz-header-value">
                              {(values ?? []).join(", ")}
                            </span>
                          </div>
                        ),
                      )}
                    </div>
                  </div>

                  {/* Response body */}
                  <div className="fuzz-results-detail-section">
                    <h4 className="fuzz-results-detail-section-title">
                      Response Body
                    </h4>
                    {detailFlow.response_body ? (
                      <CodeViewer
                        code={detailFlow.response_body}
                        contentType={
                          (() => {
                            const hdrs = detailFlow.response_headers ?? {};
                            for (const [k, v] of Object.entries(hdrs)) {
                              const sv = v ?? [];
                              if (k.toLowerCase() === "content-type" && sv.length > 0) return sv[0];
                            }
                            return "";
                          })()
                        }
                      />
                    ) : (
                      <div className="fuzz-results-detail-empty">(empty)</div>
                    )}
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Internal helper: access MCP context for direct queries
// ---------------------------------------------------------------------------

import { useMcpContext } from "../../lib/mcp/context.js";

function useMcpContextSafe() {
  const { client, status } = useMcpContext();
  return { client, status };
}
