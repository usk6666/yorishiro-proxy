import { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Input } from "../../components/ui/Input.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Table } from "../../components/ui/Table.js";
import { Tabs } from "../../components/ui/Tabs.js";
import { useToast } from "../../components/ui/Toast.js";
import { useMcpContext } from "../../lib/mcp/context.js";
import { useQuery } from "../../lib/mcp/hooks.js";
import type {
  FuzzGRPCParams,
  FuzzGRPCPosition,
  FuzzHTTPParams,
  FuzzHTTPPosition,
  FuzzJobEntry,
  FuzzRawParams,
  FuzzRawPosition,
  FuzzWSParams,
  FuzzWSPosition,
  HeaderKV,
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

// "paused" / "cancelled" are valid historical job states even though the
// lifecycle UI was removed (the typed fuzz_* tools are synchronous). Keep
// them in the filter dropdown so analysts can find old rows.
const STATUS_OPTIONS = ["running", "completed", "paused", "cancelled", "error"] as const;

const TABS = [
  { id: "jobs", label: "Jobs" },
  { id: "create", label: "New Campaign" },
];

/** Protocol selector options for the campaign creator form. */
const PROTOCOL_OPTIONS = [
  { value: "http", label: "HTTP / HTTPS / HTTP-2" },
  { value: "ws", label: "WebSocket" },
  { value: "grpc", label: "gRPC" },
  { value: "raw", label: "Raw TCP" },
] as const;

type FuzzProtocol = (typeof PROTOCOL_OPTIONS)[number]["value"];

const ENCODING_OPTIONS = [
  { value: "text", label: "text" },
  { value: "base64", label: "base64" },
] as const;

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

/** Split a textarea string into a non-empty payload array. */
function splitPayloads(values: string): string[] {
  return values
    .split("\n")
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function FuzzPage() {
  const navigate = useNavigate();

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
// CampaignCreator — protocol-typed fuzz_* campaign creation form (USK-937)
//
// The form swaps its body by the selected protocol. Each variant of the
// form builds a typed params object that is sent to the matching
// client.fuzzHttp / fuzzWs / fuzzGrpc / fuzzRaw method.
// ---------------------------------------------------------------------------

interface CampaignCreatorProps {
  onCreated: () => void;
}

/** One position entry rendered inside the per-protocol form. */
interface PositionFormEntry {
  key: string;
  path: string;
  payloadsText: string;
  encoding: string;
}

function createEmptyPosition(): PositionFormEntry {
  return {
    key: crypto.randomUUID(),
    path: "",
    payloadsText: "",
    encoding: "text",
  };
}

/** One header KV entry rendered inside the per-protocol form. */
interface HeaderFormEntry {
  key: string;
  name: string;
  value: string;
}

function createEmptyHeader(): HeaderFormEntry {
  return { key: crypto.randomUUID(), name: "", value: "" };
}

function headerEntriesToKVs(entries: HeaderFormEntry[]): HeaderKV[] {
  return entries
    .filter((h) => h.name.trim().length > 0)
    .map((h) => ({ name: h.name, value: h.value }));
}

function CampaignCreator({ onCreated }: CampaignCreatorProps) {
  const { addToast } = useToast();
  const { client, status: mcpStatus } = useMcpContext();

  // --- Protocol selector ---
  const [protocol, setProtocol] = useState<FuzzProtocol>("http");

  // --- Shared base fields ---
  const [flowId, setFlowId] = useState("");
  const [tag, setTag] = useState("");
  const [timeoutMs, setTimeoutMs] = useState("");

  // --- HTTP-specific fields ---
  const [httpMethod, setHttpMethod] = useState("");
  const [httpScheme, setHttpScheme] = useState("");
  const [httpAuthority, setHttpAuthority] = useState("");
  const [httpPath, setHttpPath] = useState("");
  const [httpRawQuery, setHttpRawQuery] = useState("");
  const [httpHeaders, setHttpHeaders] = useState<HeaderFormEntry[]>([]);
  const [httpBody, setHttpBody] = useState("");
  const [httpBodyEncoding, setHttpBodyEncoding] = useState("text");
  const [httpStopOn5xx, setHttpStopOn5xx] = useState(false);

  // --- WebSocket-specific fields ---
  const [wsTargetAddr, setWsTargetAddr] = useState("");
  const [wsScheme, setWsScheme] = useState("");
  const [wsPath, setWsPath] = useState("");
  const [wsRawQuery, setWsRawQuery] = useState("");
  const [wsOpcode, setWsOpcode] = useState("text");
  const [wsPayload, setWsPayload] = useState("");
  const [wsPayloadEncoding, setWsPayloadEncoding] = useState("text");
  const [wsCloseCode, setWsCloseCode] = useState("");
  const [wsCloseReason, setWsCloseReason] = useState("");
  const [wsStopOnClose, setWsStopOnClose] = useState(false);

  // --- gRPC-specific fields ---
  const [grpcTargetAddr, setGrpcTargetAddr] = useState("");
  const [grpcScheme, setGrpcScheme] = useState("");
  const [grpcService, setGrpcService] = useState("");
  const [grpcMethod, setGrpcMethod] = useState("");
  const [grpcMetadata, setGrpcMetadata] = useState<HeaderFormEntry[]>([]);
  const [grpcEncoding, setGrpcEncoding] = useState("");
  const [grpcMessagePayload, setGrpcMessagePayload] = useState("");
  const [grpcMessageEncoding, setGrpcMessageEncoding] = useState("text");
  const [grpcStopOnNonOk, setGrpcStopOnNonOk] = useState(false);

  // --- Raw-specific fields ---
  const [rawTargetAddr, setRawTargetAddr] = useState("");
  const [rawUseTLS, setRawUseTLS] = useState(false);
  const [rawSNI, setRawSNI] = useState("");
  const [rawOverrideBytes, setRawOverrideBytes] = useState("");
  const [rawOverrideBytesEncoding, setRawOverrideBytesEncoding] =
    useState("text");
  const [rawStopOnError, setRawStopOnError] = useState(false);

  // --- Positions list (shared shape across protocols; .path encoding is
  //     protocol-specific and described inline in the form help text) ---
  const [positions, setPositions] = useState<PositionFormEntry[]>([
    createEmptyPosition(),
  ]);

  const [submitting, setSubmitting] = useState(false);

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

  // --- Header management (HTTP & gRPC metadata) ---
  const addHeader = useCallback(
    (setter: React.Dispatch<React.SetStateAction<HeaderFormEntry[]>>) =>
      setter((prev) => [...prev, createEmptyHeader()]),
    [],
  );
  const removeHeader = useCallback(
    (
      setter: React.Dispatch<React.SetStateAction<HeaderFormEntry[]>>,
      key: string,
    ) => setter((prev) => prev.filter((h) => h.key !== key)),
    [],
  );
  const updateHeader = useCallback(
    (
      setter: React.Dispatch<React.SetStateAction<HeaderFormEntry[]>>,
      key: string,
      field: "name" | "value",
      value: string,
    ) =>
      setter((prev) =>
        prev.map((h) => (h.key === key ? { ...h, [field]: value } : h)),
      ),
    [],
  );

  // --- Build typed positions array from the form. Returns null on
  //     validation failure (and surfaces a toast). ---
  function buildPositions<
    P extends FuzzHTTPPosition | FuzzWSPosition | FuzzGRPCPosition | FuzzRawPosition,
  >(): P[] | null {
    const built: P[] = [];
    for (const p of positions) {
      if (!p.path.trim()) continue; // skip empty rows
      const payloads = splitPayloads(p.payloadsText);
      if (payloads.length === 0) {
        addToast({
          type: "warning",
          message: `Position '${p.path}' must have at least one payload`,
        });
        return null;
      }
      const pos = {
        path: p.path.trim(),
        payloads,
      } as P;
      // Encoding is optional; default "text" matches backend default.
      if (p.encoding && p.encoding !== "text") {
        (pos as { encoding?: string }).encoding = p.encoding;
      }
      built.push(pos);
    }
    if (built.length === 0) {
      addToast({
        type: "warning",
        message: "At least one position with a path and payloads is required",
      });
      return null;
    }
    return built;
  }

  // --- Submit handler ---
  const handleSubmit = useCallback(async () => {
    if (!client || mcpStatus !== "connected") {
      addToast({
        type: "error",
        message: "MCP client is not connected",
      });
      return;
    }

    const timeoutMsNum = timeoutMs.trim() ? parseInt(timeoutMs, 10) : NaN;

    setSubmitting(true);
    try {
      if (protocol === "http") {
        const built = buildPositions<FuzzHTTPPosition>();
        if (!built) return;
        const params: FuzzHTTPParams = {
          positions: built,
        };
        if (flowId.trim()) params.flow_id = flowId.trim();
        if (httpMethod.trim()) params.method = httpMethod.trim();
        if (httpScheme.trim()) params.scheme = httpScheme.trim();
        if (httpAuthority.trim()) params.authority = httpAuthority.trim();
        if (httpPath.trim()) params.path = httpPath.trim();
        if (httpRawQuery.trim()) params.raw_query = httpRawQuery.trim();
        const headerKVs = headerEntriesToKVs(httpHeaders);
        if (headerKVs.length > 0) params.headers = headerKVs;
        if (httpBody.length > 0) {
          params.body = httpBody;
          if (httpBodyEncoding && httpBodyEncoding !== "text") {
            params.body_encoding = httpBodyEncoding;
          }
        }
        if (httpStopOn5xx) params.stop_on_5xx = true;
        if (tag.trim()) params.tag = tag.trim();
        if (!isNaN(timeoutMsNum)) params.timeout_ms = timeoutMsNum;
        const result = await client.fuzzHttp(params);
        addToast({
          type: "success",
          message: `fuzz_http: ${result.completed_variants}/${result.total_variants} variants`,
        });
        onCreated();
        return;
      }

      if (protocol === "ws") {
        const built = buildPositions<FuzzWSPosition>();
        if (!built) return;
        if (!wsOpcode.trim()) {
          addToast({ type: "warning", message: "opcode is required" });
          return;
        }
        const params: FuzzWSParams = {
          opcode: wsOpcode.trim(),
          positions: built,
        };
        if (flowId.trim()) params.flow_id = flowId.trim();
        if (wsTargetAddr.trim()) params.target_addr = wsTargetAddr.trim();
        if (wsScheme.trim()) params.scheme = wsScheme.trim();
        if (wsPath.trim()) params.path = wsPath.trim();
        if (wsRawQuery.trim()) params.raw_query = wsRawQuery.trim();
        if (wsPayload.length > 0) {
          params.payload = wsPayload;
          if (wsPayloadEncoding && wsPayloadEncoding !== "text") {
            params.body_encoding = wsPayloadEncoding;
          }
        }
        if (wsCloseCode.trim()) {
          const code = parseInt(wsCloseCode, 10);
          if (!isNaN(code)) params.close_code = code;
        }
        if (wsCloseReason.trim()) params.close_reason = wsCloseReason.trim();
        if (wsStopOnClose) params.stop_on_close = true;
        if (tag.trim()) params.tag = tag.trim();
        if (!isNaN(timeoutMsNum)) params.timeout_ms = timeoutMsNum;
        const result = await client.fuzzWs(params);
        addToast({
          type: "success",
          message: `fuzz_ws: ${result.completed_variants}/${result.total_variants} variants`,
        });
        onCreated();
        return;
      }

      if (protocol === "grpc") {
        const built = buildPositions<FuzzGRPCPosition>();
        if (!built) return;
        const params: FuzzGRPCParams = {
          positions: built,
        };
        if (flowId.trim()) params.flow_id = flowId.trim();
        if (grpcTargetAddr.trim()) params.target_addr = grpcTargetAddr.trim();
        if (grpcScheme.trim()) params.scheme = grpcScheme.trim();
        if (grpcService.trim()) params.service = grpcService.trim();
        if (grpcMethod.trim()) params.method = grpcMethod.trim();
        const md = headerEntriesToKVs(grpcMetadata);
        if (md.length > 0) params.metadata = md;
        if (grpcEncoding.trim()) params.encoding = grpcEncoding.trim();
        // A single base message is the common case; multi-message campaigns
        // can iterate via positions on messages[N].payload after seeding via
        // flow_id. The form keeps the surface small.
        if (grpcMessagePayload.length > 0) {
          params.messages = [
            {
              payload: grpcMessagePayload,
              body_encoding:
                grpcMessageEncoding && grpcMessageEncoding !== "text"
                  ? grpcMessageEncoding
                  : undefined,
            },
          ];
        }
        if (grpcStopOnNonOk) params.stop_on_non_ok = true;
        if (tag.trim()) params.tag = tag.trim();
        if (!isNaN(timeoutMsNum)) params.timeout_ms = timeoutMsNum;
        const result = await client.fuzzGrpc(params);
        addToast({
          type: "success",
          message: `fuzz_grpc: ${result.completed_variants}/${result.total_variants} variants`,
        });
        onCreated();
        return;
      }

      // raw
      const built = buildPositions<FuzzRawPosition>();
      if (!built) return;
      if (!rawTargetAddr.trim()) {
        addToast({
          type: "warning",
          message: "target_addr is required for fuzz_raw",
        });
        return;
      }
      const params: FuzzRawParams = {
        target_addr: rawTargetAddr.trim(),
        positions: built,
      };
      if (flowId.trim()) params.flow_id = flowId.trim();
      if (rawUseTLS) params.use_tls = true;
      if (rawSNI.trim()) params.sni = rawSNI.trim();
      if (rawOverrideBytes.length > 0) {
        params.override_bytes = rawOverrideBytes;
        if (
          rawOverrideBytesEncoding &&
          rawOverrideBytesEncoding !== "text"
        ) {
          params.override_bytes_encoding = rawOverrideBytesEncoding;
        }
      }
      if (rawStopOnError) params.stop_on_error = true;
      if (tag.trim()) params.tag = tag.trim();
      if (!isNaN(timeoutMsNum)) params.timeout_ms = timeoutMsNum;
      const result = await client.fuzzRaw(params);
      addToast({
        type: "success",
        message: `fuzz_raw: ${result.completed_variants}/${result.total_variants} variants`,
      });
      onCreated();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to start fuzz: ${err instanceof Error ? err.message : String(err)}`,
      });
    } finally {
      setSubmitting(false);
    }
    // buildPositions captures the latest `positions` / `addToast`; including
    // them keeps the linter happy without breaking the closure.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    client,
    mcpStatus,
    protocol,
    flowId,
    tag,
    timeoutMs,
    positions,
    httpMethod,
    httpScheme,
    httpAuthority,
    httpPath,
    httpRawQuery,
    httpHeaders,
    httpBody,
    httpBodyEncoding,
    httpStopOn5xx,
    wsTargetAddr,
    wsScheme,
    wsPath,
    wsRawQuery,
    wsOpcode,
    wsPayload,
    wsPayloadEncoding,
    wsCloseCode,
    wsCloseReason,
    wsStopOnClose,
    grpcTargetAddr,
    grpcScheme,
    grpcService,
    grpcMethod,
    grpcMetadata,
    grpcEncoding,
    grpcMessagePayload,
    grpcMessageEncoding,
    grpcStopOnNonOk,
    rawTargetAddr,
    rawUseTLS,
    rawSNI,
    rawOverrideBytes,
    rawOverrideBytesEncoding,
    rawStopOnError,
    addToast,
    onCreated,
  ]);

  // --- Protocol-specific help text for positions[].path ---
  const positionPathHelp = useMemo(() => {
    switch (protocol) {
      case "http":
        return "method | scheme | authority | path | raw_query | body | headers[N].name | headers[N].value";
      case "ws":
        return "payload | close_reason";
      case "grpc":
        return "service | method | metadata[N].name | metadata[N].value | messages[N].payload | messages[N].payload.<FFFF:OOOO:type> (see gRPC Schemas panel for proto-aware paths)";
      case "raw":
        return "payload | patches[N].data";
    }
  }, [protocol]);

  return (
    <div className="fuzz-creator">
      {/* Protocol selector */}
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Protocol</h3>
        <div className="fuzz-creator-row-inline">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Target Protocol</label>
            <select
              className="fuzz-filter-select"
              value={protocol}
              onChange={(e) => setProtocol(e.target.value as FuzzProtocol)}
            >
              {PROTOCOL_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
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
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Timeout (ms)</label>
            <Input
              type="number"
              placeholder="30000"
              value={timeoutMs}
              onChange={(e) => setTimeoutMs(e.target.value)}
            />
          </div>
        </div>
      </div>

      {/* Base flow */}
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Base Flow (optional)</h3>
        <div className="fuzz-creator-row">
          <label className="fuzz-creator-label">Flow ID</label>
          <Input
            placeholder="Recorded flow ID to seed the base envelope..."
            value={flowId}
            onChange={(e) => setFlowId(e.target.value)}
          />
        </div>
      </div>

      {/* Protocol-specific body */}
      {protocol === "http" && (
        <HttpCampaignFields
          method={httpMethod}
          setMethod={setHttpMethod}
          scheme={httpScheme}
          setScheme={setHttpScheme}
          authority={httpAuthority}
          setAuthority={setHttpAuthority}
          path={httpPath}
          setPath={setHttpPath}
          rawQuery={httpRawQuery}
          setRawQuery={setHttpRawQuery}
          headers={httpHeaders}
          onAddHeader={() => addHeader(setHttpHeaders)}
          onRemoveHeader={(key) => removeHeader(setHttpHeaders, key)}
          onUpdateHeader={(key, field, value) =>
            updateHeader(setHttpHeaders, key, field, value)
          }
          body={httpBody}
          setBody={setHttpBody}
          bodyEncoding={httpBodyEncoding}
          setBodyEncoding={setHttpBodyEncoding}
          stopOn5xx={httpStopOn5xx}
          setStopOn5xx={setHttpStopOn5xx}
        />
      )}
      {protocol === "ws" && (
        <WsCampaignFields
          targetAddr={wsTargetAddr}
          setTargetAddr={setWsTargetAddr}
          scheme={wsScheme}
          setScheme={setWsScheme}
          path={wsPath}
          setPath={setWsPath}
          rawQuery={wsRawQuery}
          setRawQuery={setWsRawQuery}
          opcode={wsOpcode}
          setOpcode={setWsOpcode}
          payload={wsPayload}
          setPayload={setWsPayload}
          payloadEncoding={wsPayloadEncoding}
          setPayloadEncoding={setWsPayloadEncoding}
          closeCode={wsCloseCode}
          setCloseCode={setWsCloseCode}
          closeReason={wsCloseReason}
          setCloseReason={setWsCloseReason}
          stopOnClose={wsStopOnClose}
          setStopOnClose={setWsStopOnClose}
        />
      )}
      {protocol === "grpc" && (
        <GrpcCampaignFields
          targetAddr={grpcTargetAddr}
          setTargetAddr={setGrpcTargetAddr}
          scheme={grpcScheme}
          setScheme={setGrpcScheme}
          service={grpcService}
          setService={setGrpcService}
          method={grpcMethod}
          setMethod={setGrpcMethod}
          metadata={grpcMetadata}
          onAddMetadata={() => addHeader(setGrpcMetadata)}
          onRemoveMetadata={(key) => removeHeader(setGrpcMetadata, key)}
          onUpdateMetadata={(key, field, value) =>
            updateHeader(setGrpcMetadata, key, field, value)
          }
          encoding={grpcEncoding}
          setEncoding={setGrpcEncoding}
          messagePayload={grpcMessagePayload}
          setMessagePayload={setGrpcMessagePayload}
          messageEncoding={grpcMessageEncoding}
          setMessageEncoding={setGrpcMessageEncoding}
          stopOnNonOk={grpcStopOnNonOk}
          setStopOnNonOk={setGrpcStopOnNonOk}
        />
      )}
      {protocol === "raw" && (
        <RawCampaignFields
          targetAddr={rawTargetAddr}
          setTargetAddr={setRawTargetAddr}
          useTLS={rawUseTLS}
          setUseTLS={setRawUseTLS}
          sni={rawSNI}
          setSNI={setRawSNI}
          overrideBytes={rawOverrideBytes}
          setOverrideBytes={setRawOverrideBytes}
          overrideBytesEncoding={rawOverrideBytesEncoding}
          setOverrideBytesEncoding={setRawOverrideBytesEncoding}
          stopOnError={rawStopOnError}
          setStopOnError={setRawStopOnError}
        />
      )}

      {/* Positions */}
      <div className="fuzz-creator-section">
        <div className="fuzz-creator-section-header">
          <h3 className="fuzz-creator-section-title">Payload Positions</h3>
          <Button variant="secondary" size="sm" onClick={addPosition}>
            Add Position
          </Button>
        </div>
        <div className="fuzz-creator-help">
          Path syntax: {positionPathHelp}
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
                <label className="fuzz-creator-label">Path</label>
                <Input
                  placeholder="e.g. path or headers[0].value"
                  value={pos.path}
                  onChange={(e) =>
                    updatePosition(pos.key, "path", e.target.value)
                  }
                />
              </div>
              <div className="fuzz-creator-field">
                <label className="fuzz-creator-label">Encoding</label>
                <select
                  className="fuzz-filter-select"
                  value={pos.encoding}
                  onChange={(e) =>
                    updatePosition(pos.key, "encoding", e.target.value)
                  }
                >
                  {ENCODING_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="fuzz-creator-field fuzz-creator-field-full">
              <label className="fuzz-creator-label">
                Payloads (one per line)
              </label>
              <textarea
                className="fuzz-values-textarea"
                value={pos.payloadsText}
                onChange={(e) =>
                  updatePosition(pos.key, "payloadsText", e.target.value)
                }
                placeholder={"admin\ntest\n' OR 1=1 --"}
                rows={6}
                spellCheck={false}
              />
            </div>
          </div>
        ))}
      </div>

      {/* Submit */}
      <div className="fuzz-creator-actions">
        <Button
          variant="primary"
          onClick={handleSubmit}
          disabled={submitting}
        >
          {submitting ? "Running..." : "Start Fuzz Campaign"}
        </Button>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Per-protocol form fragments
// ---------------------------------------------------------------------------

interface HeaderListProps {
  title: string;
  entries: HeaderFormEntry[];
  onAdd: () => void;
  onRemove: (key: string) => void;
  onUpdate: (key: string, field: "name" | "value", value: string) => void;
}

function HeaderList({
  title,
  entries,
  onAdd,
  onRemove,
  onUpdate,
}: HeaderListProps) {
  return (
    <div className="fuzz-creator-section">
      <div className="fuzz-creator-section-header">
        <h3 className="fuzz-creator-section-title">{title}</h3>
        <Button variant="secondary" size="sm" onClick={onAdd}>
          Add
        </Button>
      </div>
      {entries.map((h) => (
        <div key={h.key} className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Name</label>
            <Input
              value={h.name}
              onChange={(e) => onUpdate(h.key, "name", e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Value</label>
            <Input
              value={h.value}
              onChange={(e) => onUpdate(h.key, "value", e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => onRemove(h.key)}
            >
              Remove
            </Button>
          </div>
        </div>
      ))}
    </div>
  );
}

interface HttpCampaignFieldsProps {
  method: string;
  setMethod: (v: string) => void;
  scheme: string;
  setScheme: (v: string) => void;
  authority: string;
  setAuthority: (v: string) => void;
  path: string;
  setPath: (v: string) => void;
  rawQuery: string;
  setRawQuery: (v: string) => void;
  headers: HeaderFormEntry[];
  onAddHeader: () => void;
  onRemoveHeader: (key: string) => void;
  onUpdateHeader: (key: string, field: "name" | "value", value: string) => void;
  body: string;
  setBody: (v: string) => void;
  bodyEncoding: string;
  setBodyEncoding: (v: string) => void;
  stopOn5xx: boolean;
  setStopOn5xx: (v: boolean) => void;
}

function HttpCampaignFields({
  method,
  setMethod,
  scheme,
  setScheme,
  authority,
  setAuthority,
  path,
  setPath,
  rawQuery,
  setRawQuery,
  headers,
  onAddHeader,
  onRemoveHeader,
  onUpdateHeader,
  body,
  setBody,
  bodyEncoding,
  setBodyEncoding,
  stopOn5xx,
  setStopOn5xx,
}: HttpCampaignFieldsProps) {
  return (
    <>
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">HTTP Base</h3>
        <div className="fuzz-creator-help">
          Required when no Flow ID is supplied. With a Flow ID, omitted fields
          inherit from the recorded request.
        </div>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Method</label>
            <Input
              placeholder="GET"
              value={method}
              onChange={(e) => setMethod(e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Scheme</label>
            <Input
              placeholder="https"
              value={scheme}
              onChange={(e) => setScheme(e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Authority</label>
            <Input
              placeholder="example.com"
              value={authority}
              onChange={(e) => setAuthority(e.target.value)}
            />
          </div>
        </div>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Path</label>
            <Input
              placeholder="/"
              value={path}
              onChange={(e) => setPath(e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Raw Query</label>
            <Input
              placeholder="a=1&b=2"
              value={rawQuery}
              onChange={(e) => setRawQuery(e.target.value)}
            />
          </div>
        </div>
      </div>
      <HeaderList
        title="Headers"
        entries={headers}
        onAdd={onAddHeader}
        onRemove={onRemoveHeader}
        onUpdate={onUpdateHeader}
      />
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Body</h3>
        <div className="fuzz-creator-row-inline">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Body Encoding</label>
            <select
              className="fuzz-filter-select"
              value={bodyEncoding}
              onChange={(e) => setBodyEncoding(e.target.value)}
            >
              {ENCODING_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="fuzz-creator-field fuzz-creator-field-full">
          <textarea
            className="fuzz-values-textarea"
            value={body}
            onChange={(e) => setBody(e.target.value)}
            placeholder="Request body..."
            rows={4}
            spellCheck={false}
          />
        </div>
      </div>
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Stop Condition</h3>
        <label className="fuzz-results-outliers-toggle">
          <input
            type="checkbox"
            checked={stopOn5xx}
            onChange={(e) => setStopOn5xx(e.target.checked)}
          />
          Stop on first 5xx response
        </label>
      </div>
    </>
  );
}

interface WsCampaignFieldsProps {
  targetAddr: string;
  setTargetAddr: (v: string) => void;
  scheme: string;
  setScheme: (v: string) => void;
  path: string;
  setPath: (v: string) => void;
  rawQuery: string;
  setRawQuery: (v: string) => void;
  opcode: string;
  setOpcode: (v: string) => void;
  payload: string;
  setPayload: (v: string) => void;
  payloadEncoding: string;
  setPayloadEncoding: (v: string) => void;
  closeCode: string;
  setCloseCode: (v: string) => void;
  closeReason: string;
  setCloseReason: (v: string) => void;
  stopOnClose: boolean;
  setStopOnClose: (v: boolean) => void;
}

function WsCampaignFields({
  targetAddr,
  setTargetAddr,
  scheme,
  setScheme,
  path,
  setPath,
  rawQuery,
  setRawQuery,
  opcode,
  setOpcode,
  payload,
  setPayload,
  payloadEncoding,
  setPayloadEncoding,
  closeCode,
  setCloseCode,
  closeReason,
  setCloseReason,
  stopOnClose,
  setStopOnClose,
}: WsCampaignFieldsProps) {
  return (
    <>
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">WebSocket Base</h3>
        <div className="fuzz-creator-help">
          target_addr + path are required when no Flow ID is supplied.
        </div>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Target Addr</label>
            <Input
              placeholder="example.com:443"
              value={targetAddr}
              onChange={(e) => setTargetAddr(e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Scheme</label>
            <Input
              placeholder="ws or wss"
              value={scheme}
              onChange={(e) => setScheme(e.target.value)}
            />
          </div>
        </div>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Path</label>
            <Input
              placeholder="/socket"
              value={path}
              onChange={(e) => setPath(e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Raw Query</label>
            <Input
              placeholder="optional"
              value={rawQuery}
              onChange={(e) => setRawQuery(e.target.value)}
            />
          </div>
        </div>
      </div>
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Frame</h3>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Opcode</label>
            <select
              className="fuzz-filter-select"
              value={opcode}
              onChange={(e) => setOpcode(e.target.value)}
            >
              <option value="text">text</option>
              <option value="binary">binary</option>
              <option value="close">close</option>
              <option value="ping">ping</option>
              <option value="pong">pong</option>
            </select>
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Payload Encoding</label>
            <select
              className="fuzz-filter-select"
              value={payloadEncoding}
              onChange={(e) => setPayloadEncoding(e.target.value)}
            >
              {ENCODING_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="fuzz-creator-field fuzz-creator-field-full">
          <label className="fuzz-creator-label">Payload</label>
          <textarea
            className="fuzz-values-textarea"
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            placeholder="Frame payload..."
            rows={4}
            spellCheck={false}
          />
        </div>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Close Code</label>
            <Input
              type="number"
              placeholder="optional"
              value={closeCode}
              onChange={(e) => setCloseCode(e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Close Reason</label>
            <Input
              placeholder="optional"
              value={closeReason}
              onChange={(e) => setCloseReason(e.target.value)}
            />
          </div>
        </div>
      </div>
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Stop Condition</h3>
        <label className="fuzz-results-outliers-toggle">
          <input
            type="checkbox"
            checked={stopOnClose}
            onChange={(e) => setStopOnClose(e.target.checked)}
          />
          Stop on first Close frame from upstream
        </label>
      </div>
    </>
  );
}

interface GrpcCampaignFieldsProps {
  targetAddr: string;
  setTargetAddr: (v: string) => void;
  scheme: string;
  setScheme: (v: string) => void;
  service: string;
  setService: (v: string) => void;
  method: string;
  setMethod: (v: string) => void;
  metadata: HeaderFormEntry[];
  onAddMetadata: () => void;
  onRemoveMetadata: (key: string) => void;
  onUpdateMetadata: (key: string, field: "name" | "value", value: string) => void;
  encoding: string;
  setEncoding: (v: string) => void;
  messagePayload: string;
  setMessagePayload: (v: string) => void;
  messageEncoding: string;
  setMessageEncoding: (v: string) => void;
  stopOnNonOk: boolean;
  setStopOnNonOk: (v: boolean) => void;
}

function GrpcCampaignFields({
  targetAddr,
  setTargetAddr,
  scheme,
  setScheme,
  service,
  setService,
  method,
  setMethod,
  metadata,
  onAddMetadata,
  onRemoveMetadata,
  onUpdateMetadata,
  encoding,
  setEncoding,
  messagePayload,
  setMessagePayload,
  messageEncoding,
  setMessageEncoding,
  stopOnNonOk,
  setStopOnNonOk,
}: GrpcCampaignFieldsProps) {
  return (
    <>
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">gRPC Base</h3>
        <div className="fuzz-creator-help">
          target_addr + service + method are required when no Flow ID is
          supplied. scheme defaults to https; http selects h2c.
        </div>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Target Addr</label>
            <Input
              placeholder="example.com:443"
              value={targetAddr}
              onChange={(e) => setTargetAddr(e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Scheme</label>
            <Input
              placeholder="https"
              value={scheme}
              onChange={(e) => setScheme(e.target.value)}
            />
          </div>
        </div>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Service</label>
            <Input
              placeholder="pkg.Greeter"
              value={service}
              onChange={(e) => setService(e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Method</label>
            <Input
              placeholder="SayHello"
              value={method}
              onChange={(e) => setMethod(e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">grpc-encoding</label>
            <Input
              placeholder="identity"
              value={encoding}
              onChange={(e) => setEncoding(e.target.value)}
            />
          </div>
        </div>
      </div>
      <HeaderList
        title="Metadata"
        entries={metadata}
        onAdd={onAddMetadata}
        onRemove={onRemoveMetadata}
        onUpdate={onUpdateMetadata}
      />
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">
          Request Message (messages[0])
        </h3>
        <div className="fuzz-creator-help">
          Single base message — additional messages must be seeded via Flow
          ID. Positions can target `messages[N].payload` to substitute
          per-variant bytes.
        </div>
        <div className="fuzz-creator-row-inline">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Encoding</label>
            <select
              className="fuzz-filter-select"
              value={messageEncoding}
              onChange={(e) => setMessageEncoding(e.target.value)}
            >
              <option value="text">text</option>
              <option value="base64">base64</option>
              <option value="proto-schemaless-json">
                proto-schemaless-json
              </option>
              <option value="proto-json">proto-json (requires schema)</option>
            </select>
          </div>
        </div>
        <div className="fuzz-creator-field fuzz-creator-field-full">
          <label className="fuzz-creator-label">Payload</label>
          <textarea
            className="fuzz-values-textarea"
            value={messagePayload}
            onChange={(e) => setMessagePayload(e.target.value)}
            placeholder="Message payload..."
            rows={4}
            spellCheck={false}
          />
        </div>
      </div>
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Stop Condition</h3>
        <label className="fuzz-results-outliers-toggle">
          <input
            type="checkbox"
            checked={stopOnNonOk}
            onChange={(e) => setStopOnNonOk(e.target.checked)}
          />
          Stop on first non-OK gRPC status
        </label>
      </div>
    </>
  );
}

interface RawCampaignFieldsProps {
  targetAddr: string;
  setTargetAddr: (v: string) => void;
  useTLS: boolean;
  setUseTLS: (v: boolean) => void;
  sni: string;
  setSNI: (v: string) => void;
  overrideBytes: string;
  setOverrideBytes: (v: string) => void;
  overrideBytesEncoding: string;
  setOverrideBytesEncoding: (v: string) => void;
  stopOnError: boolean;
  setStopOnError: (v: boolean) => void;
}

function RawCampaignFields({
  targetAddr,
  setTargetAddr,
  useTLS,
  setUseTLS,
  sni,
  setSNI,
  overrideBytes,
  setOverrideBytes,
  overrideBytesEncoding,
  setOverrideBytesEncoding,
  stopOnError,
  setStopOnError,
}: RawCampaignFieldsProps) {
  return (
    <>
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Raw TCP Base</h3>
        <div className="fuzz-creator-help">
          target_addr is required. When no Flow ID is supplied, either
          override_bytes or a `payload` position must provide the variant
          bytes.
        </div>
        <div className="fuzz-position-fields">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Target Addr</label>
            <Input
              placeholder="example.com:80"
              value={targetAddr}
              onChange={(e) => setTargetAddr(e.target.value)}
            />
          </div>
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">SNI</label>
            <Input
              placeholder="optional"
              value={sni}
              onChange={(e) => setSNI(e.target.value)}
            />
          </div>
        </div>
        <div className="fuzz-creator-row-inline">
          <label className="fuzz-results-outliers-toggle">
            <input
              type="checkbox"
              checked={useTLS}
              onChange={(e) => setUseTLS(e.target.checked)}
            />
            Use TLS
          </label>
        </div>
      </div>
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Override Bytes</h3>
        <div className="fuzz-creator-row-inline">
          <div className="fuzz-creator-field">
            <label className="fuzz-creator-label">Encoding</label>
            <select
              className="fuzz-filter-select"
              value={overrideBytesEncoding}
              onChange={(e) => setOverrideBytesEncoding(e.target.value)}
            >
              {ENCODING_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="fuzz-creator-field fuzz-creator-field-full">
          <textarea
            className="fuzz-values-textarea"
            value={overrideBytes}
            onChange={(e) => setOverrideBytes(e.target.value)}
            placeholder="Wire bytes (text or base64)..."
            rows={4}
            spellCheck={false}
          />
        </div>
      </div>
      <div className="fuzz-creator-section">
        <h3 className="fuzz-creator-section-title">Stop Condition</h3>
        <label className="fuzz-results-outliers-toggle">
          <input
            type="checkbox"
            checked={stopOnError}
            onChange={(e) => setStopOnError(e.target.checked)}
          />
          Stop on first failure (network error, timeout, or pipeline drop)
        </label>
      </div>
    </>
  );
}
