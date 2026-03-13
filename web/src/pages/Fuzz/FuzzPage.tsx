import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Input } from "../../components/ui/Input.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Table } from "../../components/ui/Table.js";
import { Tabs } from "../../components/ui/Tabs.js";
import { useToast } from "../../components/ui/Toast.js";
import { useFuzz, useQuery } from "../../lib/mcp/hooks.js";
import type {
  FuzzJobEntry,
  FuzzPayloadSet,
  FuzzPosition,
  FuzzStopCondition,
  MacrosEntry,
  QueryFilter,
} from "../../lib/mcp/types.js";
import "./FuzzPage.css";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PAGE_SIZES = [25, 50, 100] as const;
const POLL_INTERVALS = [
  { label: "Off", value: 0 },
  { label: "1s", value: 1000 },
  { label: "2s", value: 2000 },
  { label: "5s", value: 5000 },
] as const;

const STATUS_OPTIONS = ["running", "completed", "paused", "cancelled", "error"] as const;

const TABS = [
  { id: "jobs", label: "Jobs" },
  { id: "create", label: "New Campaign" },
];

const ATTACK_TYPES = [
  { value: "sequential", label: "Sequential" },
  { value: "parallel", label: "Parallel" },
];

const PAYLOAD_TYPES = [
  { value: "wordlist", label: "Wordlist (values)" },
  { value: "range", label: "Range (numeric)" },
  { value: "file", label: "File" },
];

const POSITION_LOCATIONS = [
  { value: "header", label: "Header" },
  { value: "path", label: "Path" },
  { value: "query", label: "Query" },
  { value: "body_regex", label: "Body (Regex)" },
  { value: "body_json", label: "Body (JSON)" },
  { value: "cookie", label: "Cookie" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
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

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleString(undefined, {
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

function progressPercent(job: FuzzJobEntry): number {
  if (job.total <= 0) return 0;
  return Math.min(100, Math.round((job.completed_count / job.total) * 100));
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function FuzzPage() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { fuzz: fuzzAction, loading: executeLoading } = useFuzz();

  const [activeTab, setActiveTab] = useState("jobs");

  // --- Filter state ---
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [tagFilter, setTagFilter] = useState<string>("");

  // --- Pagination state ---
  const [pageSize, setPageSize] = useState<number>(50);
  const [offset, setOffset] = useState(0);

  // --- Polling state ---
  const [pollInterval, setPollInterval] = useState<number>(2000);

  // --- Build query filter ---
  const filter = useMemo<QueryFilter | undefined>(() => {
    const f: QueryFilter = {};
    if (statusFilter) f.status = statusFilter;
    if (tagFilter.trim()) f.tag = tagFilter.trim();
    return Object.keys(f).length > 0 ? f : undefined;
  }, [statusFilter, tagFilter]);

  // --- Query fuzz jobs ---
  const { data, loading, error, refetch } = useQuery("fuzz_jobs", {
    pollInterval,
    filter,
    limit: pageSize,
    offset,
  });

  const jobs = data?.jobs ?? [];
  const total = data?.total ?? 0;

  // Trigger refetch when filter/pagination changes
  const prevFilterKey = useRef("");
  useEffect(() => {
    const key = JSON.stringify({ filter, limit: pageSize, offset });
    if (prevFilterKey.current && prevFilterKey.current !== key) {
      refetch();
    }
    prevFilterKey.current = key;
  }, [filter, pageSize, offset, refetch]);

  // --- Filter change handler ---
  const handleFilterChange = useCallback(() => {
    setOffset(0);
  }, []);

  const handleStatusFilterChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setStatusFilter(e.target.value);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  const handleTagFilterChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setTagFilter(e.target.value);
      handleFilterChange();
    },
    [handleFilterChange],
  );

  // --- Pagination ---
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.floor(offset / pageSize) + 1;

  const goToPage = useCallback(
    (page: number) => {
      setOffset((page - 1) * pageSize);
    },
    [pageSize],
  );

  const handlePageSizeChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setPageSize(parseInt(e.target.value, 10));
      setOffset(0);
    },
    [],
  );

  const handlePollChange = useCallback(
    (e: React.ChangeEvent<HTMLSelectElement>) => {
      setPollInterval(parseInt(e.target.value, 10));
    },
    [],
  );

  // --- Row click → navigate to results ---
  const handleRowClick = useCallback(
    (job: FuzzJobEntry) => {
      navigate(`/fuzz/${job.id}`);
    },
    [navigate],
  );

  // --- Job actions (pause/resume/cancel) ---
  const handleJobAction = useCallback(
    async (
      e: React.MouseEvent,
      action: "fuzz_pause" | "fuzz_resume" | "fuzz_cancel",
      fuzzId: string,
    ) => {
      e.stopPropagation();
      try {
        await fuzzAction({ action, params: { fuzz_id: fuzzId } });
        addToast({
          type: "success",
          message: `Job ${action.replace("fuzz_", "")}d`,
        });
        refetch();
      } catch (err) {
        addToast({
          type: "error",
          message: `Action failed: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    },
    [fuzzAction, addToast, refetch],
  );

  // --- Campaign creation callback ---
  const handleCampaignCreated = useCallback(() => {
    setActiveTab("jobs");
    refetch();
  }, [refetch]);

  return (
    <div className="page fuzz-page">
      <div className="fuzz-header">
        <h1 className="page-title">Fuzz</h1>
        <p className="page-description">
          Fuzz testing jobs and campaigns.
        </p>
      </div>

      <div className="fuzz-tabs">
        <Tabs tabs={TABS} activeTab={activeTab} onTabChange={setActiveTab}>
          {activeTab === "jobs" && (
            <div className="fuzz-jobs-panel">
              {/* Toolbar */}
              <div className="fuzz-toolbar">
                <div className="fuzz-toolbar-left">
                  <select
                    className="fuzz-filter-select"
                    value={statusFilter}
                    onChange={handleStatusFilterChange}
                  >
                    <option value="">All statuses</option>
                    {STATUS_OPTIONS.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                  <Input
                    placeholder="Filter by tag..."
                    value={tagFilter}
                    onChange={handleTagFilterChange}
                  />
                  <Button variant="secondary" size="sm" onClick={() => refetch()}>
                    Refresh
                  </Button>
                </div>
                <div className="fuzz-toolbar-right">
                  <div className="fuzz-refresh-control">
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

              {/* Error state */}
              {error && (
                <div className="fuzz-error">
                  Error loading fuzz jobs: {error.message}
                </div>
              )}

              {/* Loading state (initial) */}
              {loading && !data && (
                <div className="fuzz-loading">
                  <Spinner size="lg" />
                </div>
              )}

              {/* Empty state */}
              {!loading && !error && data && jobs.length === 0 && (
                <div className="fuzz-empty">
                  <span>No fuzz jobs found.</span>
                  <span>
                    Create a new campaign to start fuzzing.
                  </span>
                </div>
              )}

              {/* Jobs table */}
              {jobs.length > 0 && (
                <>
                  <div className="fuzz-table-wrapper">
                    <Table className="fuzz-table">
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Flow</th>
                          <th>Status</th>
                          <th>Progress</th>
                          <th>Errors</th>
                          <th>Tag</th>
                          <th>Created</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {jobs.map((job) => (
                          <tr
                            key={job.id}
                            className="fuzz-row"
                            onClick={() => handleRowClick(job)}
                          >
                            <td className="fuzz-cell-id">{shortId(job.id)}</td>
                            <td className="fuzz-cell-id">
                              {shortId(job.flow_id)}
                            </td>
                            <td>
                              <Badge variant={statusVariant(job.status)}>
                                {job.status}
                              </Badge>
                            </td>
                            <td>
                              <div className="fuzz-progress">
                                <div className="fuzz-progress-bar">
                                  <div
                                    className="fuzz-progress-fill"
                                    style={{
                                      width: `${progressPercent(job)}%`,
                                    }}
                                  />
                                </div>
                                <span className="fuzz-progress-text">
                                  {job.completed_count}/{job.total} (
                                  {progressPercent(job)}%)
                                </span>
                              </div>
                            </td>
                            <td className="fuzz-cell-errors">
                              {job.error_count > 0 ? (
                                <span className="fuzz-error-count">
                                  {job.error_count}
                                </span>
                              ) : (
                                <span className="fuzz-no-errors">0</span>
                              )}
                            </td>
                            <td className="fuzz-cell-tag">
                              {job.tag && (
                                <Badge variant="default">{job.tag}</Badge>
                              )}
                            </td>
                            <td className="fuzz-cell-time">
                              {formatTimestamp(job.created_at)}
                            </td>
                            <td className="fuzz-cell-actions">
                              {job.status === "running" && (
                                <>
                                  <Button
                                    variant="secondary"
                                    size="sm"
                                    onClick={(e) =>
                                      handleJobAction(e, "fuzz_pause", job.id)
                                    }
                                    disabled={executeLoading}
                                  >
                                    Pause
                                  </Button>
                                  <Button
                                    variant="danger"
                                    size="sm"
                                    onClick={(e) =>
                                      handleJobAction(e, "fuzz_cancel", job.id)
                                    }
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
                                    onClick={(e) =>
                                      handleJobAction(e, "fuzz_resume", job.id)
                                    }
                                    disabled={executeLoading}
                                  >
                                    Resume
                                  </Button>
                                  <Button
                                    variant="danger"
                                    size="sm"
                                    onClick={(e) =>
                                      handleJobAction(e, "fuzz_cancel", job.id)
                                    }
                                    disabled={executeLoading}
                                  >
                                    Cancel
                                  </Button>
                                </>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </Table>
                  </div>

                  {/* Pagination */}
                  <div className="fuzz-pagination">
                    <div className="fuzz-pagination-info">
                      Showing {offset + 1}--
                      {Math.min(offset + pageSize, total)} of {total}
                    </div>
                    <div className="fuzz-pagination-controls">
                      <div className="fuzz-page-size">
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
                      <span className="fuzz-pagination-info">
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
          )}

          {activeTab === "create" && (
            <CampaignCreator onCreated={handleCampaignCreated} />
          )}
        </Tabs>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// CampaignCreator — Fuzz campaign creation form
// ---------------------------------------------------------------------------

interface CampaignCreatorProps {
  onCreated: () => void;
}

/** A single position entry in the form. */
interface PositionFormEntry {
  key: string;
  id: string;
  location: string;
  name: string;
  match: string;
  mode: string;
  payloadSet: string;
  jsonPath: string;
}

/** A single payload set entry in the form. */
interface PayloadSetFormEntry {
  key: string;
  name: string;
  type: string;
  values: string;
  path: string;
  start: string;
  end: string;
  step: string;
}

function createEmptyPosition(): PositionFormEntry {
  return {
    key: crypto.randomUUID(),
    id: "",
    location: "header",
    name: "",
    match: "",
    mode: "replace",
    payloadSet: "",
    jsonPath: "",
  };
}

function createEmptyPayloadSet(): PayloadSetFormEntry {
  return {
    key: crypto.randomUUID(),
    name: "",
    type: "wordlist",
    values: "",
    path: "",
    start: "0",
    end: "100",
    step: "1",
  };
}

function CampaignCreator({ onCreated }: CampaignCreatorProps) {
  const { addToast } = useToast();
  const { fuzz: fuzzAction, loading: executing } = useFuzz();

  // Fetch available macros for hook selection
  const { data: macrosData } = useQuery("macros");
  const availableMacros: MacrosEntry[] = macrosData?.macros ?? [];

  // Base flow
  const [flowId, setFlowId] = useState("");

  // Attack type
  const [attackType, setAttackType] = useState("sequential");

  // Tag
  const [tag, setTag] = useState("");

  // Positions
  const [positions, setPositions] = useState<PositionFormEntry[]>([
    createEmptyPosition(),
  ]);

  // Payload sets
  const [payloadSets, setPayloadSets] = useState<PayloadSetFormEntry[]>([
    createEmptyPayloadSet(),
  ]);

  // Execution params
  const [concurrency, setConcurrency] = useState("1");
  const [rateLimit, setRateLimit] = useState("");
  const [delay, setDelay] = useState("");
  const [timeout, setTimeout] = useState("30000");

  // Stop conditions
  const [stopErrorCount, setStopErrorCount] = useState("");
  const [stopStatusCodes, setStopStatusCodes] = useState("");
  const [stopLatencyMs, setStopLatencyMs] = useState("");

  // Hooks
  const [preSendMacro, setPreSendMacro] = useState("");
  const [postReceiveMacro, setPostReceiveMacro] = useState("");

  // --- Position management ---
  const addPosition = useCallback(() => {
    setPositions((prev) => [...prev, createEmptyPosition()]);
  }, []);

  const removePosition = useCallback((key: string) => {
    setPositions((prev) => prev.filter((p) => p.key !== key));
  }, []);

  const updatePosition = useCallback(
    (key: string, field: keyof PositionFormEntry, value: string) => {
      setPositions((prev) =>
        prev.map((p) => (p.key === key ? { ...p, [field]: value } : p)),
      );
    },
    [],
  );

  // --- Payload set management ---
  const addPayloadSet = useCallback(() => {
    setPayloadSets((prev) => [...prev, createEmptyPayloadSet()]);
  }, []);

  const removePayloadSet = useCallback((key: string) => {
    setPayloadSets((prev) => prev.filter((p) => p.key !== key));
  }, []);

  const updatePayloadSet = useCallback(
    (key: string, field: keyof PayloadSetFormEntry, value: string) => {
      setPayloadSets((prev) =>
        prev.map((p) => (p.key === key ? { ...p, [field]: value } : p)),
      );
    },
    [],
  );

  // --- Submit ---
  const handleSubmit = useCallback(async () => {
    if (!flowId.trim()) {
      addToast({ type: "warning", message: "Flow ID is required" });
      return;
    }

    // Build positions
    const builtPositions: FuzzPosition[] = positions
      .filter((p) => p.id.trim())
      .map((p) => {
        const pos: FuzzPosition = {
          id: p.id.trim(),
          location: p.location,
        };
        if (p.name.trim()) pos.name = p.name.trim();
        if (p.match.trim()) pos.match = p.match.trim();
        if (p.mode.trim()) pos.mode = p.mode.trim();
        if (p.payloadSet.trim()) pos.payload_set = p.payloadSet.trim();
        if (p.location === "body_json" && p.jsonPath.trim()) {
          pos.json_path = p.jsonPath.trim();
        }
        return pos;
      });

    if (builtPositions.length === 0) {
      addToast({
        type: "warning",
        message: "At least one position with an ID is required",
      });
      return;
    }

    // Build payload sets
    const builtPayloadSets: Record<string, FuzzPayloadSet> = {};
    for (const ps of payloadSets) {
      if (!ps.name.trim()) continue;
      const set: FuzzPayloadSet = { type: ps.type };
      if (ps.type === "wordlist" && ps.values.trim()) {
        set.values = ps.values
          .split("\n")
          .map((v) => v.trim())
          .filter((v) => v.length > 0);
      }
      if (ps.type === "file" && ps.path.trim()) {
        set.path = ps.path.trim();
      }
      if (ps.type === "range") {
        const start = parseInt(ps.start, 10);
        const end = parseInt(ps.end, 10);
        const step = parseInt(ps.step, 10);
        if (!isNaN(start)) set.start = start;
        if (!isNaN(end)) set.end = end;
        if (!isNaN(step)) set.step = step;
      }
      builtPayloadSets[ps.name.trim()] = set;
    }

    if (Object.keys(builtPayloadSets).length === 0) {
      addToast({
        type: "warning",
        message: "At least one payload set with a name is required",
      });
      return;
    }

    // Build stop conditions
    let stopOn: FuzzStopCondition | undefined;
    const errorCount = parseInt(stopErrorCount, 10);
    const latencyMs = parseInt(stopLatencyMs, 10);
    const statusCodes = stopStatusCodes
      .split(",")
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => !isNaN(n));

    if (!isNaN(errorCount) || !isNaN(latencyMs) || statusCodes.length > 0) {
      stopOn = {};
      if (!isNaN(errorCount)) stopOn.error_count = errorCount;
      if (!isNaN(latencyMs)) stopOn.latency_threshold_ms = latencyMs;
      if (statusCodes.length > 0) stopOn.status_codes = statusCodes;
    }

    // Build hooks
    let hooks: { pre_send?: { macro: string }; post_receive?: { macro: string } } | undefined;
    if (preSendMacro.trim() || postReceiveMacro.trim()) {
      hooks = {};
      if (preSendMacro.trim()) {
        hooks.pre_send = { macro: preSendMacro.trim() };
      }
      if (postReceiveMacro.trim()) {
        hooks.post_receive = { macro: postReceiveMacro.trim() };
      }
    }

    try {
      await fuzzAction({
        action: "fuzz",
        params: {
          flow_id: flowId.trim(),
          positions: builtPositions,
          payload_sets: builtPayloadSets,
          attack_type: attackType,
          concurrency: parseInt(concurrency, 10) || 1,
          rate_limit_rps: rateLimit ? parseFloat(rateLimit) : undefined,
          delay_ms: delay ? parseInt(delay, 10) : undefined,
          timeout_ms: timeout ? parseInt(timeout, 10) : undefined,
          stop_on: stopOn,
          hooks: hooks,
          tag: tag.trim() || undefined,
        },
      });

      addToast({ type: "success", message: "Fuzz campaign started" });
      onCreated();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to start fuzz: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [
    flowId,
    positions,
    payloadSets,
    attackType,
    concurrency,
    rateLimit,
    delay,
    timeout,
    tag,
    stopErrorCount,
    stopStatusCodes,
    stopLatencyMs,
    preSendMacro,
    postReceiveMacro,
    fuzzAction,
    addToast,
    onCreated,
  ]);

  return (
    <div className="fuzz-creator">
      {/* Base flow */}
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Base Flow</h3>
        <div className="fuzz-creator-row">
          <label className="fuzz-creator-label">Flow ID</label>
          <Input
            placeholder="Enter flow ID..."
            value={flowId}
            onChange={(e) => setFlowId(e.target.value)}
          />
        </div>
      </div>

      {/* Attack type & Tag */}
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Campaign Settings</h3>
        <div className="fuzz-creator-row-inline">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Attack Type</label>
            <select
              className="fuzz-filter-select"
              value={attackType}
              onChange={(e) => setAttackType(e.target.value)}
            >
              {ATTACK_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </select>
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Tag (optional)</label>
            <Input
              placeholder="Campaign tag..."
              value={tag}
              onChange={(e) => setTag(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Positions */}
      <div className="fuzz-creator-section">
        <div className="fuzz-creator-section-header">
          <h3 className="fuzz-creator-section-title">Payload Positions</h3>
          <Button variant="secondary" size="sm" onClick={addPosition}>
            Add Position
          </Button>
        </div>
        {positions.map((pos, idx) => (
          <div key={pos.key} className="fuzz-position-entry">
            <div className="fuzz-position-header">
              <span className="fuzz-position-index">#{idx + 1}</span>
              {positions.length > 1 && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => removePosition(pos.key)}
                >
                  Remove
                </Button>
              )}
            </div>
            <div className="fuzz-position-fields">
              <div className="fuzz-creator-field">
                <label className="fuzz-creator-label">ID</label>
                <Input
                  placeholder="pos-1"
                  value={pos.id}
                  onChange={(e) =>
                    updatePosition(pos.key, "id", e.target.value)
                  }
                />
              </div>
              <div className="fuzz-creator-field">
                <label className="fuzz-creator-label">Location</label>
                <select
                  className="fuzz-filter-select"
                  value={pos.location}
                  onChange={(e) =>
                    updatePosition(pos.key, "location", e.target.value)
                  }
                >
                  {POSITION_LOCATIONS.map((l) => (
                    <option key={l.value} value={l.value}>
                      {l.label}
                    </option>
                  ))}
                </select>
              </div>
              <div className="fuzz-creator-field">
                <label className="fuzz-creator-label">Match Pattern</label>
                <Input
                  placeholder="FUZZ"
                  value={pos.match}
                  onChange={(e) =>
                    updatePosition(pos.key, "match", e.target.value)
                  }
                />
              </div>
              <div className="fuzz-creator-field">
                <label className="fuzz-creator-label">Payload Set</label>
                <Input
                  placeholder="set-1"
                  value={pos.payloadSet}
                  onChange={(e) =>
                    updatePosition(pos.key, "payloadSet", e.target.value)
                  }
                />
              </div>
              {pos.location === "body_json" && (
                <div className="fuzz-creator-field">
                  <label className="fuzz-creator-label">JSON Path</label>
                  <Input
                    placeholder="$.key"
                    value={pos.jsonPath}
                    onChange={(e) =>
                      updatePosition(pos.key, "jsonPath", e.target.value)
                    }
                  />
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Payload Sets */}
      <div className="fuzz-creator-section">
        <div className="fuzz-creator-section-header">
          <h3 className="fuzz-creator-section-title">Payload Sets</h3>
          <Button variant="secondary" size="sm" onClick={addPayloadSet}>
            Add Payload Set
          </Button>
        </div>
        {payloadSets.map((ps, idx) => (
          <div key={ps.key} className="fuzz-payloadset-entry">
            <div className="fuzz-position-header">
              <span className="fuzz-position-index">#{idx + 1}</span>
              {payloadSets.length > 1 && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => removePayloadSet(ps.key)}
                >
                  Remove
                </Button>
              )}
            </div>
            <div className="fuzz-position-fields">
              <div className="fuzz-creator-field">
                <label className="fuzz-creator-label">Name</label>
                <Input
                  placeholder="set-1"
                  value={ps.name}
                  onChange={(e) =>
                    updatePayloadSet(ps.key, "name", e.target.value)
                  }
                />
              </div>
              <div className="fuzz-creator-field">
                <label className="fuzz-creator-label">Type</label>
                <select
                  className="fuzz-filter-select"
                  value={ps.type}
                  onChange={(e) =>
                    updatePayloadSet(ps.key, "type", e.target.value)
                  }
                >
                  {PAYLOAD_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            {ps.type === "wordlist" && (
              <div className="fuzz-creator-field fuzz-creator-field-full">
                <label className="fuzz-creator-label">
                  Values (one per line)
                </label>
                <textarea
                  className="fuzz-values-textarea"
                  value={ps.values}
                  onChange={(e) =>
                    updatePayloadSet(ps.key, "values", e.target.value)
                  }
                  placeholder={"admin\ntest\n' OR 1=1 --\n<script>alert(1)</script>"}
                  rows={6}
                  spellCheck={false}
                />
              </div>
            )}
            {ps.type === "file" && (
              <div className="fuzz-creator-field fuzz-creator-field-full">
                <label className="fuzz-creator-label">File Path</label>
                <Input
                  placeholder="/path/to/wordlist.txt"
                  value={ps.path}
                  onChange={(e) =>
                    updatePayloadSet(ps.key, "path", e.target.value)
                  }
                />
              </div>
            )}
            {ps.type === "range" && (
              <div className="fuzz-position-fields">
                <div className="fuzz-creator-field">
                  <label className="fuzz-creator-label">Start</label>
                  <Input
                    type="number"
                    value={ps.start}
                    onChange={(e) =>
                      updatePayloadSet(ps.key, "start", e.target.value)
                    }
                  />
                </div>
                <div className="fuzz-creator-field">
                  <label className="fuzz-creator-label">End</label>
                  <Input
                    type="number"
                    value={ps.end}
                    onChange={(e) =>
                      updatePayloadSet(ps.key, "end", e.target.value)
                    }
                  />
                </div>
                <div className="fuzz-creator-field">
                  <label className="fuzz-creator-label">Step</label>
                  <Input
                    type="number"
                    value={ps.step}
                    onChange={(e) =>
                      updatePayloadSet(ps.key, "step", e.target.value)
                    }
                  />
                </div>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* Execution parameters */}
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Execution Parameters</h3>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Concurrency</label>
            <Input
              type="number"
              value={concurrency}
              onChange={(e) => setConcurrency(e.target.value)}
              placeholder="1"
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Rate Limit (RPS)</label>
            <Input
              type="number"
              value={rateLimit}
              onChange={(e) => setRateLimit(e.target.value)}
              placeholder="Unlimited"
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Delay (ms)</label>
            <Input
              type="number"
              value={delay}
              onChange={(e) => setDelay(e.target.value)}
              placeholder="0"
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Timeout (ms)</label>
            <Input
              type="number"
              value={timeout}
              onChange={(e) => setTimeout(e.target.value)}
              placeholder="30000"
            />
          </div>
        </div>
      </div>

      {/* Stop conditions */}
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Stop Conditions</h3>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Error Count</label>
            <Input
              type="number"
              value={stopErrorCount}
              onChange={(e) => setStopErrorCount(e.target.value)}
              placeholder="No limit"
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">
              Stop Status Codes (comma-separated)
            </label>
            <Input
              value={stopStatusCodes}
              onChange={(e) => setStopStatusCodes(e.target.value)}
              placeholder="e.g. 500,503"
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">
              Latency Threshold (ms)
            </label>
            <Input
              type="number"
              value={stopLatencyMs}
              onChange={(e) => setStopLatencyMs(e.target.value)}
              placeholder="No limit"
            />
          </div>
        </div>
      </div>

      {/* Hooks */}
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Hooks (optional)</h3>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Pre-send Macro</label>
            <select
              className="fuzz-filter-select"
              value={preSendMacro}
              onChange={(e) => setPreSendMacro(e.target.value)}
            >
              <option value="">None</option>
              {availableMacros.map((m) => (
                <option key={m.name} value={m.name}>
                  {m.name}
                </option>
              ))}
            </select>
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Post-receive Macro</label>
            <select
              className="fuzz-filter-select"
              value={postReceiveMacro}
              onChange={(e) => setPostReceiveMacro(e.target.value)}
            >
              <option value="">None</option>
              {availableMacros.map((m) => (
                <option key={m.name} value={m.name}>
                  {m.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Submit */}
      <div className="fuzz-creator-actions">
        <Button
          variant="primary"
          onClick={handleSubmit}
          disabled={executing}
        >
          {executing ? "Starting..." : "Start Fuzz Campaign"}
        </Button>
      </div>
    </div>
  );
}
