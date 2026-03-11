import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Input, Spinner, useToast } from "../../components/ui/index.js";
import { useMcpContext } from "../../lib/mcp/context.js";
import { useSecurity } from "../../lib/mcp/hooks.js";
import type {
  SecurityGetRateLimitsResult,
  SecuritySetRateLimitsResult,
} from "../../lib/mcp/types.js";

/**
 * RateLimits -- displays and manages rate limit configuration.
 *
 * Shows Policy Layer (read-only), Agent Layer (editable), and Effective values.
 */
export function RateLimits() {
  const { status } = useMcpContext();
  const { security, loading: actionLoading } = useSecurity();
  const { addToast } = useToast();

  const [data, setData] = useState<SecurityGetRateLimitsResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Agent layer form state.
  const [agentRps, setAgentRps] = useState("");
  const [agentHostRps, setAgentHostRps] = useState("");
  const [editing, setEditing] = useState(false);

  const fetchRateLimits = useCallback(async () => {
    if (status !== "connected") return;
    setLoading(true);
    setError(null);
    try {
      const result = await security<SecurityGetRateLimitsResult>({
        action: "get_rate_limits",
        params: {},
      });
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, [security, status]);

  useEffect(() => {
    if (status === "connected") {
      fetchRateLimits();
    }
  }, [status, fetchRateLimits]);

  // Sync form state when data changes and not editing.
  useEffect(() => {
    if (data && !editing) {
      setAgentRps(data.agent.max_requests_per_second > 0 ? String(data.agent.max_requests_per_second) : "");
      setAgentHostRps(data.agent.max_requests_per_host_per_second > 0 ? String(data.agent.max_requests_per_host_per_second) : "");
    }
  }, [data, editing]);

  const handleSave = useCallback(async () => {
    try {
      const rps = agentRps ? parseFloat(agentRps) : 0;
      const hostRps = agentHostRps ? parseFloat(agentHostRps) : 0;

      if (agentRps && (isNaN(rps) || rps < 0)) {
        addToast({ type: "error", message: "Invalid global RPS value" });
        return;
      }
      if (agentHostRps && (isNaN(hostRps) || hostRps < 0)) {
        addToast({ type: "error", message: "Invalid per-host RPS value" });
        return;
      }

      await security<SecuritySetRateLimitsResult>({
        action: "set_rate_limits",
        params: {
          max_requests_per_second: rps,
          max_requests_per_host_per_second: hostRps,
        },
      });
      addToast({ type: "success", message: "Rate limits updated" });
      setEditing(false);
      fetchRateLimits();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to set rate limits: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [security, agentRps, agentHostRps, addToast, fetchRateLimits]);

  const handleCancel = useCallback(() => {
    setEditing(false);
    if (data) {
      setAgentRps(data.agent.max_requests_per_second > 0 ? String(data.agent.max_requests_per_second) : "");
      setAgentHostRps(data.agent.max_requests_per_host_per_second > 0 ? String(data.agent.max_requests_per_host_per_second) : "");
    }
  }, [data]);

  if (loading && !data) {
    return (
      <div className="security-section">
        <h2 className="security-section-title">Rate Limits</h2>
        <div className="security-loading"><Spinner size="md" /></div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="security-section">
        <h2 className="security-section-title">Rate Limits</h2>
        <div className="security-error">Error loading rate limits: {error.message}</div>
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="security-section">
      <h2 className="security-section-title">Rate Limits</h2>
      <p className="security-section-desc">
        Control request throughput with global and per-host rate limits.
      </p>

      {/* Effective values */}
      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Effective</span>
          <Badge variant="success">Active</Badge>
        </div>
        <div className="security-card-body">
          <div className="security-ratelimit-grid">
            <div className="security-ratelimit-item">
              <span className="security-ratelimit-label">Global RPS</span>
              <span className="security-ratelimit-value">
                {formatRpsValue(data.effective.max_requests_per_second)}
              </span>
            </div>
            <div className="security-ratelimit-item">
              <span className="security-ratelimit-label">Per-Host RPS</span>
              <span className="security-ratelimit-value">
                {formatRpsValue(data.effective.max_requests_per_host_per_second)}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Policy Layer (read-only) */}
      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Policy Layer</span>
          <Badge variant="default">Immutable</Badge>
        </div>
        <div className="security-card-body">
          <div className="security-ratelimit-grid">
            <div className="security-ratelimit-item">
              <span className="security-ratelimit-label">Global RPS</span>
              <span className="security-ratelimit-value">
                {formatRpsValue(data.policy.max_requests_per_second)}
              </span>
            </div>
            <div className="security-ratelimit-item">
              <span className="security-ratelimit-label">Per-Host RPS</span>
              <span className="security-ratelimit-value">
                {formatRpsValue(data.policy.max_requests_per_host_per_second)}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Agent Layer (editable) */}
      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Agent Layer</span>
          {!editing && (
            <Button variant="primary" size="sm" onClick={() => setEditing(true)}>
              Edit
            </Button>
          )}
        </div>
        <div className="security-card-body">
          {editing ? (
            <div className="security-ratelimit-form">
              <div className="security-form-row">
                <Input
                  label="Global RPS"
                  type="number"
                  min="0"
                  step="0.1"
                  placeholder="0 (no limit)"
                  value={agentRps}
                  onChange={(e) => setAgentRps(e.target.value)}
                />
                <Input
                  label="Per-Host RPS"
                  type="number"
                  min="0"
                  step="0.1"
                  placeholder="0 (no limit)"
                  value={agentHostRps}
                  onChange={(e) => setAgentHostRps(e.target.value)}
                />
              </div>
              <div className="security-add-form-actions">
                <Button variant="ghost" size="sm" onClick={handleCancel}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleSave}
                  disabled={actionLoading}
                >
                  Save
                </Button>
              </div>
            </div>
          ) : (
            <div className="security-ratelimit-grid">
              <div className="security-ratelimit-item">
                <span className="security-ratelimit-label">Global RPS</span>
                <span className="security-ratelimit-value">
                  {formatRpsValue(data.agent.max_requests_per_second)}
                </span>
              </div>
              <div className="security-ratelimit-item">
                <span className="security-ratelimit-label">Per-Host RPS</span>
                <span className="security-ratelimit-value">
                  {formatRpsValue(data.agent.max_requests_per_host_per_second)}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** Format an RPS value for display. 0 means "No limit". */
function formatRpsValue(value: number): string {
  if (value <= 0) return "No limit";
  return `${value} req/s`;
}
