import { useCallback, useEffect, useRef, useState } from "react";
import { Badge, Button, Input, Spinner, useToast } from "../../components/ui/index.js";
import { useMcpContext } from "../../lib/mcp/context.js";
import { useSecurity } from "../../lib/mcp/hooks.js";
import type {
  SecurityGetBudgetResult,
  SecuritySetBudgetResult,
} from "../../lib/mcp/types.js";

/** Polling interval for budget usage (5 seconds). */
const BUDGET_POLL_INTERVAL = 5000;

/**
 * Budget -- displays and manages diagnostic budget configuration.
 *
 * Shows Policy Layer (read-only), Agent Layer (editable), Effective values,
 * and current usage with progress bars.
 */
export function Budget() {
  const { status } = useMcpContext();
  const { security, loading: actionLoading } = useSecurity();
  const { addToast } = useToast();

  const [data, setData] = useState<SecurityGetBudgetResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  // Agent layer form state.
  const [agentMaxRequests, setAgentMaxRequests] = useState("");
  const [agentMaxDuration, setAgentMaxDuration] = useState("");
  const [editing, setEditing] = useState(false);

  const fetchBudget = useCallback(async () => {
    if (status !== "connected") return;
    setLoading(true);
    setError(null);
    try {
      const result = await security<SecurityGetBudgetResult>({
        action: "get_budget",
        params: {},
      });
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, [security, status]);

  // Initial fetch.
  useEffect(() => {
    if (status === "connected") {
      fetchBudget();
    }
  }, [status, fetchBudget]);

  // Polling for usage updates.
  const fetchBudgetRef = useRef(fetchBudget);
  fetchBudgetRef.current = fetchBudget;

  useEffect(() => {
    if (status !== "connected") return;
    const timer = setInterval(() => {
      fetchBudgetRef.current();
    }, BUDGET_POLL_INTERVAL);
    return () => clearInterval(timer);
  }, [status]);

  // Sync form state when data changes and not editing.
  useEffect(() => {
    if (data && !editing) {
      setAgentMaxRequests(
        data.agent.max_total_requests > 0 ? String(data.agent.max_total_requests) : "",
      );
      setAgentMaxDuration(
        data.agent.max_duration !== "0s" && data.agent.max_duration !== ""
          ? data.agent.max_duration
          : "",
      );
    }
  }, [data, editing]);

  const handleSave = useCallback(async () => {
    try {
      const maxReqs = agentMaxRequests ? parseInt(agentMaxRequests, 10) : 0;
      if (agentMaxRequests && (isNaN(maxReqs) || maxReqs < 0)) {
        addToast({ type: "error", message: "Invalid max requests value" });
        return;
      }

      // Validate duration format if provided.
      const duration = agentMaxDuration.trim() || undefined;
      if (duration && !/^\d+(\.\d+)?(ns|us|µs|ms|s|m|h)$/.test(duration)) {
        addToast({ type: "error", message: "Invalid duration format (e.g. 30m, 1h, 90s)" });
        return;
      }

      await security<SecuritySetBudgetResult>({
        action: "set_budget",
        params: {
          max_total_requests: maxReqs || undefined,
          max_duration: duration,
        },
      });
      addToast({ type: "success", message: "Budget updated" });
      setEditing(false);
      fetchBudget();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to set budget: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [security, agentMaxRequests, agentMaxDuration, addToast, fetchBudget]);

  const handleCancel = useCallback(() => {
    setEditing(false);
    if (data) {
      setAgentMaxRequests(
        data.agent.max_total_requests > 0 ? String(data.agent.max_total_requests) : "",
      );
      setAgentMaxDuration(
        data.agent.max_duration !== "0s" && data.agent.max_duration !== ""
          ? data.agent.max_duration
          : "",
      );
    }
  }, [data]);

  if (loading && !data) {
    return (
      <div className="security-section">
        <h2 className="security-section-title">Diagnostic Budget</h2>
        <div className="security-loading"><Spinner size="md" /></div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="security-section">
        <h2 className="security-section-title">Diagnostic Budget</h2>
        <div className="security-error">Error loading budget: {error.message}</div>
      </div>
    );
  }

  if (!data) return null;

  const requestsMax = data.effective.max_total_requests;
  const requestsUsed = data.request_count;
  const requestsPct = requestsMax > 0 ? Math.min((requestsUsed / requestsMax) * 100, 100) : 0;

  return (
    <div className="security-section">
      <h2 className="security-section-title">Diagnostic Budget</h2>
      <p className="security-section-desc">
        Limit total requests and session duration for diagnostic sessions.
      </p>

      {/* Current usage */}
      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Current Usage</span>
          {data.stop_reason && <Badge variant="danger">Stopped</Badge>}
        </div>
        <div className="security-card-body">
          <div className="security-budget-usage">
            <div className="security-budget-usage-item">
              <div className="security-budget-usage-header">
                <span className="security-budget-usage-label">Requests</span>
                <span className="security-budget-usage-value">
                  {requestsUsed}{requestsMax > 0 ? ` / ${requestsMax}` : ""}
                </span>
              </div>
              {requestsMax > 0 && (
                <div className="security-budget-progress">
                  <div
                    className={`security-budget-progress-bar ${requestsPct >= 90 ? "security-budget-progress-bar--danger" : requestsPct >= 70 ? "security-budget-progress-bar--warning" : ""}`}
                    style={{ width: `${requestsPct}%` }}
                  />
                </div>
              )}
            </div>
            <div className="security-budget-usage-item">
              <div className="security-budget-usage-header">
                <span className="security-budget-usage-label">Duration Limit</span>
                <span className="security-budget-usage-value">
                  {formatDuration(data.effective.max_duration)}
                </span>
              </div>
            </div>
            {data.stop_reason && (
              <div className="security-budget-stop-reason">
                <span className="security-budget-usage-label">Stop Reason</span>
                <span className="security-budget-usage-value">{data.stop_reason}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Effective values */}
      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Effective</span>
          <Badge variant="success">Active</Badge>
        </div>
        <div className="security-card-body">
          <div className="security-ratelimit-grid">
            <div className="security-ratelimit-item">
              <span className="security-ratelimit-label">Max Requests</span>
              <span className="security-ratelimit-value">
                {formatBudgetRequests(data.effective.max_total_requests)}
              </span>
            </div>
            <div className="security-ratelimit-item">
              <span className="security-ratelimit-label">Max Duration</span>
              <span className="security-ratelimit-value">
                {formatDuration(data.effective.max_duration)}
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
              <span className="security-ratelimit-label">Max Requests</span>
              <span className="security-ratelimit-value">
                {formatBudgetRequests(data.policy.max_total_requests)}
              </span>
            </div>
            <div className="security-ratelimit-item">
              <span className="security-ratelimit-label">Max Duration</span>
              <span className="security-ratelimit-value">
                {formatDuration(data.policy.max_duration)}
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
                  label="Max Total Requests"
                  type="number"
                  min="0"
                  step="1"
                  placeholder="0 (no limit)"
                  value={agentMaxRequests}
                  onChange={(e) => setAgentMaxRequests(e.target.value)}
                />
                <Input
                  label="Max Duration"
                  type="text"
                  placeholder="e.g. 30m, 1h"
                  value={agentMaxDuration}
                  onChange={(e) => setAgentMaxDuration(e.target.value)}
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
                <span className="security-ratelimit-label">Max Requests</span>
                <span className="security-ratelimit-value">
                  {formatBudgetRequests(data.agent.max_total_requests)}
                </span>
              </div>
              <div className="security-ratelimit-item">
                <span className="security-ratelimit-label">Max Duration</span>
                <span className="security-ratelimit-value">
                  {formatDuration(data.agent.max_duration)}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** Format a budget request count for display. 0 means "No limit". */
function formatBudgetRequests(value: number): string {
  if (value <= 0) return "No limit";
  return value.toLocaleString();
}

/** Format a Go duration string for display. "0s" or empty means "No limit". */
function formatDuration(value: string): string {
  if (!value || value === "0s") return "No limit";
  return value;
}
