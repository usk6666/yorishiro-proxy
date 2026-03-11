import { Spinner } from "../../components/ui/Spinner.js";
import type { SecurityGetRateLimitsResult } from "../../lib/mcp/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format RPS value for display. 0 means "No limit". */
function formatRps(value: number): string {
  if (value <= 0) return "No limit";
  return `${value} req/s`;
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface RateLimitWidgetProps {
  data: SecurityGetRateLimitsResult | null;
  loading: boolean;
  error: Error | null;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function RateLimitWidget({ data, loading, error }: RateLimitWidgetProps) {
  if (loading && !data) {
    return (
      <div className="dashboard-section">
        <h2 className="dashboard-section-title">Rate Limits</h2>
        <div className="dashboard-empty">
          <Spinner size="sm" />
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="dashboard-section">
        <h2 className="dashboard-section-title">Rate Limits</h2>
        <div className="dashboard-empty">
          <span className="dashboard-card-error">Failed to load rate limits</span>
        </div>
      </div>
    );
  }

  if (!data) return null;

  const globalRps = data.effective.max_requests_per_second;
  const hostRps = data.effective.max_requests_per_host_per_second;
  const hasLimits = globalRps > 0 || hostRps > 0;

  return (
    <div className="dashboard-section">
      <h2 className="dashboard-section-title">Rate Limits</h2>

      {!hasLimits ? (
        <div className="dashboard-empty">No limit</div>
      ) : (
        <div className="dashboard-ratelimit-grid">
          <div className="dashboard-ratelimit-item">
            <span className="dashboard-ratelimit-label">Global RPS</span>
            <span className="dashboard-ratelimit-value">{formatRps(globalRps)}</span>
          </div>
          <div className="dashboard-ratelimit-item">
            <span className="dashboard-ratelimit-label">Per-Host RPS</span>
            <span className="dashboard-ratelimit-value">{formatRps(hostRps)}</span>
          </div>
        </div>
      )}
    </div>
  );
}
