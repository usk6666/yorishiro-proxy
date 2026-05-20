import { Badge } from "../../components/ui/Badge.js";
import "./ComparerView.css";

/**
 * Comparer feature placeholder (USK-938).
 *
 * The backend `compare` resend action was retired in PR #688 / USK-693
 * (2026-05-03). Until a replacement MCP tool lands, the Compare tab
 * renders an informational card. The tab and `?mode=compare`
 * deep-link parity are preserved on purpose so a future revival can
 * restore the feature without churning routing/UI plumbing.
 *
 * Tracked in a follow-up Issue (`feat(mcp): compare tool`).
 */
export function ComparerView() {
  return (
    <div className="comparer-view">
      <div className="comparer-summary">
        <div className="comparer-summary-card">
          <div className="comparer-summary-item">
            <span className="comparer-summary-label">Status</span>
            <Badge variant="warning">Suspended</Badge>
          </div>
        </div>
      </div>

      <div className="comparer-section">
        <h4 className="comparer-section-title">Response Comparison (suspended)</h4>
        <p>
          The structured response-diff feature was removed when the backend{" "}
          <code>compare</code> resend action was retired (PR #688 / USK-693,
          2026-05-03). A replacement MCP tool is planned as a follow-up Issue.
        </p>
        <p>
          The recorded flow data remains accessible: use the{" "}
          <strong>Resend</strong> tab (Send / Send Raw) to re-issue a request
          against the same flow, or open <code>/flows/&lt;id&gt;</code> directly
          to inspect headers, body, and per-message details for each flow ID.
        </p>
      </div>
    </div>
  );
}
