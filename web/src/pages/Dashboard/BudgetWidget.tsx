import { Spinner } from "../../components/ui/Spinner.js";
import type { SecurityGetBudgetResult } from "../../lib/mcp/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format a Go duration string for display. "0s" or empty means "No limit". */
function formatDuration(value: string): string {
  if (!value || value === "0s") return "No limit";
  return value;
}

/** Get the CSS modifier class for a progress bar based on percentage. */
function progressVariant(pct: number): string {
  if (pct >= 95) return "dashboard-budget-progress-bar--danger";
  if (pct >= 80) return "dashboard-budget-progress-bar--warning";
  return "";
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface BudgetWidgetProps {
  data: SecurityGetBudgetResult | null;
  loading: boolean;
  error: Error | null;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function BudgetWidget({ data, loading, error }: BudgetWidgetProps) {
  if (loading && !data) {
    return (
      <div className="dashboard-section">
        <h2 className="dashboard-section-title">Diagnostic Budget</h2>
        <div className="dashboard-empty">
          <Spinner size="sm" />
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="dashboard-section">
        <h2 className="dashboard-section-title">Diagnostic Budget</h2>
        <div className="dashboard-empty">
          <span className="dashboard-card-error">Failed to load budget</span>
        </div>
      </div>
    );
  }

  if (!data) return null;

  const requestsMax = data.effective.max_total_requests;
  const requestsUsed = data.request_count;
  const requestsPct = requestsMax > 0 ? Math.min((requestsUsed / requestsMax) * 100, 100) : 0;
  const requestsRemaining = requestsMax > 0 ? Math.max(requestsMax - requestsUsed, 0) : null;

  const durationLimit = data.effective.max_duration;
  const hasBudget = requestsMax > 0 || (durationLimit !== "0s" && durationLimit !== "");

  return (
    <div className="dashboard-section">
      <h2 className="dashboard-section-title">Diagnostic Budget</h2>

      {!hasBudget ? (
        <div className="dashboard-empty">No limit</div>
      ) : (
        <div className="dashboard-budget-content">
          {/* Request usage */}
          {requestsMax > 0 && (
            <div className="dashboard-budget-item">
              <div className="dashboard-budget-header">
                <span className="dashboard-budget-label">Requests</span>
                <span className="dashboard-budget-value">
                  {requestsUsed.toLocaleString()} / {requestsMax.toLocaleString()}
                </span>
              </div>
              <div className="dashboard-budget-progress">
                <div
                  className={`dashboard-budget-progress-bar ${progressVariant(requestsPct)}`}
                  style={{ width: `${Math.max(requestsPct, 1)}%` }}
                />
              </div>
              <span className="dashboard-budget-remaining">
                {requestsRemaining!.toLocaleString()} remaining
              </span>
            </div>
          )}

          {/* Duration limit */}
          {durationLimit && durationLimit !== "0s" && (
            <div className="dashboard-budget-item">
              <div className="dashboard-budget-header">
                <span className="dashboard-budget-label">Duration Limit</span>
                <span className="dashboard-budget-value">
                  {formatDuration(durationLimit)}
                </span>
              </div>
            </div>
          )}

          {/* Stop reason */}
          {data.stop_reason && (
            <div className="dashboard-budget-item">
              <div className="dashboard-budget-header">
                <span className="dashboard-budget-label dashboard-budget-label--danger">
                  Stopped
                </span>
                <span className="dashboard-budget-value dashboard-budget-value--danger">
                  {data.stop_reason}
                </span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
