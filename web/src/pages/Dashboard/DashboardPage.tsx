import { useCallback, useEffect, useRef, useState } from "react";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { useMcpContext } from "../../lib/mcp/context.js";
import { useQuery, useSecurity } from "../../lib/mcp/hooks.js";
import type {
  FlowsResult,
  ListenerStatusEntry,
  SecurityGetBudgetResult,
  SecurityGetRateLimitsResult,
} from "../../lib/mcp/types.js";
import { BudgetWidget } from "./BudgetWidget.js";
import { RateLimitWidget } from "./RateLimitWidget.js";
import { TechnologiesWidget } from "./TechnologiesWidget.js";
import "./DashboardPage.css";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const POLL_INTERVAL = 5000;

const PROTOCOLS = ["HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "TCP"] as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format uptime seconds to a human-readable string. */
function formatUptime(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

/** Format bytes to a human-readable string. */
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

/** Parse "host:port" into display parts for consistent upstream rendering. */
function parseTarget(value: string): { host: string; port: string } {
  const lastColon = value.lastIndexOf(":");
  if (lastColon === -1) return { host: value, port: "" };
  return { host: value.slice(0, lastColon), port: value.slice(lastColon + 1) };
}

/** Get badge variant for protocol. */
function protocolVariant(protocol: string): "default" | "success" | "warning" | "danger" | "info" {
  switch (protocol) {
    case "HTTP/1.x": return "default";
    case "HTTPS": return "success";
    case "WebSocket": return "info";
    case "HTTP/2": return "info";
    case "gRPC": return "warning";
    case "TCP": return "danger";
    default: return "default";
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function DashboardPage() {
  // Fetch proxy status
  const {
    data: statusData,
    loading: statusLoading,
    error: statusError,
    refetch: refetchStatus,
  } = useQuery("status", { pollInterval: POLL_INTERVAL });

  // Fetch flows for statistics (limit: 0 just to get totals)
  const {
    data: flowsData,
    loading: flowsLoading,
    refetch: refetchFlows,
  } = useQuery("flows", { pollInterval: POLL_INTERVAL, limit: 0 });

  // Fetch per-protocol flow counts
  const { data: httpFlows } = useQuery("flows", {
    pollInterval: POLL_INTERVAL,
    limit: 0,
    filter: { protocol: "HTTP/1.x" },
  });
  const { data: httpsFlows } = useQuery("flows", {
    pollInterval: POLL_INTERVAL,
    limit: 0,
    filter: { protocol: "HTTPS" },
  });
  const { data: wsFlows } = useQuery("flows", {
    pollInterval: POLL_INTERVAL,
    limit: 0,
    filter: { protocol: "WebSocket" },
  });
  const { data: h2Flows } = useQuery("flows", {
    pollInterval: POLL_INTERVAL,
    limit: 0,
    filter: { protocol: "HTTP/2" },
  });
  const { data: grpcFlows } = useQuery("flows", {
    pollInterval: POLL_INTERVAL,
    limit: 0,
    filter: { protocol: "gRPC" },
  });
  const { data: tcpFlows } = useQuery("flows", {
    pollInterval: POLL_INTERVAL,
    limit: 0,
    filter: { protocol: "TCP" },
  });

  // Fetch intercept queue count
  const {
    data: interceptData,
    loading: interceptLoading,
    refetch: refetchIntercept,
  } = useQuery("intercept_queue", { pollInterval: POLL_INTERVAL });

  // Fetch running fuzz jobs
  const {
    data: fuzzData,
    loading: fuzzLoading,
    refetch: refetchFuzz,
  } = useQuery("fuzz_jobs", {
    pollInterval: POLL_INTERVAL,
    filter: { status: "running" },
  });

  // Fetch config for TCP forwards
  const {
    data: configData,
    refetch: refetchConfig,
  } = useQuery("config", { pollInterval: POLL_INTERVAL });

  // Fetch technologies
  const {
    data: techData,
    loading: techLoading,
    error: techError,
    refetch: refetchTech,
  } = useQuery("technologies", { pollInterval: POLL_INTERVAL });

  // Fetch budget and rate limits via security tool
  const { status: mcpStatus } = useMcpContext();
  const { security } = useSecurity();

  const [budgetData, setBudgetData] = useState<SecurityGetBudgetResult | null>(null);
  const [budgetLoading, setBudgetLoading] = useState(false);
  const [budgetError, setBudgetError] = useState<Error | null>(null);

  const [rateLimitData, setRateLimitData] = useState<SecurityGetRateLimitsResult | null>(null);
  const [rateLimitLoading, setRateLimitLoading] = useState(false);
  const [rateLimitError, setRateLimitError] = useState<Error | null>(null);

  const fetchBudget = useCallback(async () => {
    if (mcpStatus !== "connected") return;
    setBudgetLoading(true);
    setBudgetError(null);
    try {
      const result = await security<SecurityGetBudgetResult>({
        action: "get_budget",
        params: {},
      });
      setBudgetData(result);
    } catch (err) {
      setBudgetError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setBudgetLoading(false);
    }
  }, [security, mcpStatus]);

  const fetchRateLimits = useCallback(async () => {
    if (mcpStatus !== "connected") return;
    setRateLimitLoading(true);
    setRateLimitError(null);
    try {
      const result = await security<SecurityGetRateLimitsResult>({
        action: "get_rate_limits",
        params: {},
      });
      setRateLimitData(result);
    } catch (err) {
      setRateLimitError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setRateLimitLoading(false);
    }
  }, [security, mcpStatus]);

  // Initial fetch
  useEffect(() => {
    if (mcpStatus === "connected") {
      fetchBudget();
      fetchRateLimits();
    }
  }, [mcpStatus, fetchBudget, fetchRateLimits]);

  // Polling for budget and rate limits
  const fetchBudgetRef = useRef(fetchBudget);
  fetchBudgetRef.current = fetchBudget;
  const fetchRateLimitsRef = useRef(fetchRateLimits);
  fetchRateLimitsRef.current = fetchRateLimits;

  useEffect(() => {
    if (mcpStatus !== "connected") return;
    const timer = setInterval(() => {
      fetchBudgetRef.current();
      fetchRateLimitsRef.current();
    }, POLL_INTERVAL);
    return () => clearInterval(timer);
  }, [mcpStatus]);

  const handleRefreshAll = useCallback(() => {
    refetchStatus();
    refetchFlows();
    refetchIntercept();
    refetchFuzz();
    refetchConfig();
    refetchTech();
    fetchBudget();
    fetchRateLimits();
  }, [refetchStatus, refetchFlows, refetchIntercept, refetchFuzz, refetchConfig, refetchTech, fetchBudget, fetchRateLimits]);

  // Build protocol breakdown
  const protocolCounts: Record<string, number> = {};
  const protocolResults: Record<string, FlowsResult | null> = {
    "HTTP/1.x": httpFlows,
    "HTTPS": httpsFlows,
    "WebSocket": wsFlows,
    "HTTP/2": h2Flows,
    "gRPC": grpcFlows,
    "TCP": tcpFlows,
  };
  for (const proto of PROTOCOLS) {
    const result = protocolResults[proto];
    if (result) {
      protocolCounts[proto] = result.total;
    }
  }

  const totalFlows = flowsData?.total ?? statusData?.total_flows ?? 0;
  const maxProtocolCount = Math.max(1, ...Object.values(protocolCounts));

  return (
    <div className="page dashboard-page">
      <div className="dashboard-header">
        <div className="dashboard-header-info">
          <h1 className="page-title">Dashboard</h1>
          <p className="page-description">
            Proxy status overview and flow statistics.
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={handleRefreshAll}>
          Refresh
        </Button>
      </div>

      {/* Summary cards */}
      <div className="dashboard-cards">
        <SummaryCard
          title="Proxy Status"
          loading={statusLoading && !statusData}
          error={statusError}
        >
          {statusData && (
            <div className="dashboard-status-content">
              <div className="dashboard-status-indicator">
                <span
                  className={`dashboard-status-dot ${statusData.running
                      ? "dashboard-status-dot--running"
                      : "dashboard-status-dot--stopped"
                    }`}
                />
                <span className="dashboard-status-label">
                  {statusData.running ? "Running" : "Stopped"}
                </span>
              </div>
              {statusData.running && (
                <div className="dashboard-status-meta">
                  <span>{statusData.listener_count} listener(s)</span>
                  <span>Uptime: {formatUptime(statusData.uptime_seconds)}</span>
                </div>
              )}
            </div>
          )}
        </SummaryCard>

        <SummaryCard
          title="Active Connections"
          loading={statusLoading && !statusData}
          error={statusError}
        >
          {statusData && (
            <div className="dashboard-metric">
              <span className="dashboard-metric-value">
                {statusData.active_connections}
              </span>
              <span className="dashboard-metric-label">
                / {statusData.max_connections} max
              </span>
            </div>
          )}
        </SummaryCard>

        <SummaryCard
          title="Total Flows"
          loading={flowsLoading && !flowsData}
        >
          {flowsData && (
            <div className="dashboard-metric">
              <span className="dashboard-metric-value">{totalFlows}</span>
            </div>
          )}
        </SummaryCard>

        <SummaryCard
          title="Intercept Queue"
          loading={interceptLoading && !interceptData}
        >
          {interceptData && (
            <div className="dashboard-metric">
              <span className={`dashboard-metric-value ${interceptData.count > 0 ? "dashboard-metric-value--warning" : ""
                }`}>
                {interceptData.count}
              </span>
              <span className="dashboard-metric-label">pending</span>
            </div>
          )}
        </SummaryCard>

        <SummaryCard
          title="Running Fuzz Jobs"
          loading={fuzzLoading && !fuzzData}
        >
          {fuzzData && (
            <div className="dashboard-metric">
              <span className={`dashboard-metric-value ${fuzzData.count > 0 ? "dashboard-metric-value--info" : ""
                }`}>
                {fuzzData.count}
              </span>
              <span className="dashboard-metric-label">active</span>
            </div>
          )}
        </SummaryCard>

        <SummaryCard
          title="Database Size"
          loading={statusLoading && !statusData}
          error={statusError}
        >
          {statusData && (
            <div className="dashboard-metric">
              <span className="dashboard-metric-value">
                {formatBytes(statusData.db_size_bytes)}
              </span>
            </div>
          )}
        </SummaryCard>
      </div>

      {/* Listeners section */}
      {statusData?.listeners && statusData.listeners.length > 0 && (
        <div className="dashboard-section">
          <h2 className="dashboard-section-title">Listeners</h2>
          <div className="dashboard-listeners">
            {statusData.listeners.map((listener: ListenerStatusEntry) => (
              <div key={listener.name} className="dashboard-listener">
                <div className="dashboard-listener-info">
                  <span className="dashboard-status-dot dashboard-status-dot--running" />
                  <span className="dashboard-listener-name">{listener.name}</span>
                  <span className="dashboard-listener-addr">{listener.listen_addr}</span>
                </div>
                <div className="dashboard-listener-stats">
                  <span>{listener.active_connections} conn</span>
                  <span>Uptime: {formatUptime(listener.uptime_seconds)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TCP Forwards section */}
      {configData?.tcp_forwards && Object.keys(configData.tcp_forwards).length > 0 && (
        <div className="dashboard-section">
          <h2 className="dashboard-section-title">TCP Forwards</h2>
          <div className="dashboard-tcp-forwards">
            {Object.entries(configData.tcp_forwards).map(([port, fc]) => {
              const parsed = parseTarget(fc.target);
              const proto = fc.protocol || "auto";
              return (
                <div key={port} className="dashboard-tcp-forward">
                  <div className="dashboard-tcp-forward-info">
                    <Badge variant="info">:{port}</Badge>
                    <span className="dashboard-tcp-forward-arrow">{"->"}</span>
                    <span className="dashboard-tcp-forward-upstream">
                      {parsed.host}:{parsed.port}
                    </span>
                    <Badge variant={proto === "auto" ? "default" : "success"}>
                      {proto}
                    </Badge>
                    {fc.tls && (
                      <Badge variant="warning">TLS</Badge>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Protocol breakdown */}
      <div className="dashboard-section">
        <h2 className="dashboard-section-title">Flows by Protocol</h2>
        {totalFlows === 0 ? (
          <div className="dashboard-empty">No flows captured yet.</div>
        ) : (
          <div className="dashboard-protocol-chart">
            {PROTOCOLS.map((proto) => {
              const count = protocolCounts[proto] ?? 0;
              if (count === 0) return null;
              const pct = Math.round((count / maxProtocolCount) * 100);
              return (
                <div key={proto} className="dashboard-protocol-row">
                  <div className="dashboard-protocol-label">
                    <Badge variant={protocolVariant(proto)}>{proto}</Badge>
                  </div>
                  <div className="dashboard-protocol-bar-container">
                    <div
                      className={`dashboard-protocol-bar dashboard-protocol-bar--${protocolVariant(proto)}`}
                      style={{ width: `${Math.max(pct, 2)}%` }}
                    />
                  </div>
                  <span className="dashboard-protocol-count">{count}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Technologies */}
      <TechnologiesWidget data={techData} loading={techLoading} error={techError} />

      {/* Budget & Rate Limits */}
      <BudgetWidget data={budgetData} loading={budgetLoading} error={budgetError} />
      <RateLimitWidget data={rateLimitData} loading={rateLimitLoading} error={rateLimitError} />

      {/* Connection settings info */}
      {statusData && (
        <div className="dashboard-section">
          <h2 className="dashboard-section-title">Configuration</h2>
          <div className="dashboard-config-grid">
            <div className="dashboard-config-item">
              <span className="dashboard-config-label">Listen Address</span>
              <span className="dashboard-config-value">{statusData.listen_addr || "--"}</span>
            </div>
            <div className="dashboard-config-item">
              <span className="dashboard-config-label">Upstream Proxy</span>
              <span className="dashboard-config-value">{statusData.upstream_proxy || "Direct"}</span>
            </div>
            <div className="dashboard-config-item">
              <span className="dashboard-config-label">Max Connections</span>
              <span className="dashboard-config-value">{statusData.max_connections}</span>
            </div>
            <div className="dashboard-config-item">
              <span className="dashboard-config-label">Peek Timeout</span>
              <span className="dashboard-config-value">{statusData.peek_timeout_ms}ms</span>
            </div>
            <div className="dashboard-config-item">
              <span className="dashboard-config-label">Request Timeout</span>
              <span className="dashboard-config-value">{statusData.request_timeout_ms}ms</span>
            </div>
            <div className="dashboard-config-item">
              <span className="dashboard-config-label">CA Initialized</span>
              <span className="dashboard-config-value">
                {statusData.ca_initialized ? "Yes" : "No"}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SummaryCard sub-component
// ---------------------------------------------------------------------------

interface SummaryCardProps {
  title: string;
  loading?: boolean;
  error?: Error | null;
  children?: React.ReactNode;
}

function SummaryCard({ title, loading, error, children }: SummaryCardProps) {
  return (
    <div className="dashboard-card">
      <div className="dashboard-card-title">{title}</div>
      <div className="dashboard-card-body">
        {loading && <Spinner size="sm" />}
        {error && <span className="dashboard-card-error">Error</span>}
        {!loading && !error && children}
      </div>
    </div>
  );
}
