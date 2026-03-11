import { useCallback, useState } from "react";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Input } from "../../components/ui/Input.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { useToast } from "../../components/ui/Toast.js";
import { useResend } from "../../lib/mcp/hooks.js";
import type { CompareResult } from "../../lib/mcp/types.js";
import "./ComparerView.css";

/**
 * ComparerView provides a UI to compare two flow responses
 * using the resend tool's compare action.
 */
export function ComparerView() {
  const { resend, loading } = useResend();
  const { addToast } = useToast();

  const [flowIdA, setFlowIdA] = useState("");
  const [flowIdB, setFlowIdB] = useState("");
  const [result, setResult] = useState<CompareResult | null>(null);

  const handleCompare = useCallback(async () => {
    const a = flowIdA.trim();
    const b = flowIdB.trim();
    if (!a || !b) {
      addToast({ type: "warning", message: "Both Flow IDs are required" });
      return;
    }
    if (a === b) {
      addToast({ type: "warning", message: "Flow IDs must be different" });
      return;
    }

    try {
      const res = await resend<CompareResult>({
        action: "compare",
        params: { flow_id_a: a, flow_id_b: b },
      });
      setResult(res);
      addToast({ type: "success", message: "Comparison complete" });
    } catch (err) {
      addToast({
        type: "error",
        message: err instanceof Error ? err.message : "Compare failed",
      });
    }
  }, [flowIdA, flowIdB, resend, addToast]);

  const canCompare = flowIdA.trim().length > 0 && flowIdB.trim().length > 0;

  return (
    <div className="comparer-view">
      {/* Flow ID inputs */}
      <div className="comparer-inputs">
        <div className="comparer-input-group">
          <label className="comparer-label">Flow A</label>
          <Input
            placeholder="Enter flow ID (A)..."
            value={flowIdA}
            onChange={(e) => setFlowIdA(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && canCompare) handleCompare();
            }}
          />
        </div>
        <div className="comparer-input-group">
          <label className="comparer-label">Flow B</label>
          <Input
            placeholder="Enter flow ID (B)..."
            value={flowIdB}
            onChange={(e) => setFlowIdB(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && canCompare) handleCompare();
            }}
          />
        </div>
        <Button
          variant="primary"
          onClick={handleCompare}
          disabled={!canCompare || loading}
        >
          {loading ? "Comparing..." : "Compare"}
        </Button>
      </div>

      {loading && (
        <div className="comparer-loading">
          <Spinner size="sm" />
          <span>Comparing flows...</span>
        </div>
      )}

      {result && !loading && (
        <div className="comparer-results">
          {/* Summary cards */}
          <div className="comparer-summary">
            <SummaryCard result={result} />
          </div>

          {/* Status code diff */}
          {result.status_code && (
            <CompareSection title="Status Code">
              <div className="comparer-status-row">
                <StatusBadge code={result.status_code.a} label="A" />
                <span className="comparer-arrow">vs</span>
                <StatusBadge code={result.status_code.b} label="B" />
                {result.status_code.changed ? (
                  <Badge variant="danger">Changed</Badge>
                ) : (
                  <Badge variant="success">Match</Badge>
                )}
              </div>
            </CompareSection>
          )}

          {/* Timing diff */}
          {result.timing_ms && (
            <CompareSection title="Timing">
              <div className="comparer-timing-row">
                <span className="comparer-timing-value">
                  A: <strong>{result.timing_ms.a}ms</strong>
                </span>
                <span className="comparer-arrow">vs</span>
                <span className="comparer-timing-value">
                  B: <strong>{result.timing_ms.b}ms</strong>
                </span>
                <span className={`comparer-timing-delta ${result.timing_ms.delta > 0 ? "comparer-delta-positive" : result.timing_ms.delta < 0 ? "comparer-delta-negative" : ""}`}>
                  {result.timing_ms.delta > 0 ? "+" : ""}{result.timing_ms.delta}ms
                </span>
              </div>
            </CompareSection>
          )}

          {/* Body length diff */}
          {result.body_length && (
            <CompareSection title="Body Length">
              <div className="comparer-body-length-row">
                <span>A: <strong>{result.body_length.a}</strong> bytes</span>
                <span className="comparer-arrow">vs</span>
                <span>B: <strong>{result.body_length.b}</strong> bytes</span>
                <span className={`comparer-timing-delta ${result.body_length.delta > 0 ? "comparer-delta-positive" : result.body_length.delta < 0 ? "comparer-delta-negative" : ""}`}>
                  {result.body_length.delta > 0 ? "+" : ""}{result.body_length.delta} bytes
                </span>
              </div>
            </CompareSection>
          )}

          {/* Header diff */}
          <HeaderDiffSection result={result} />

          {/* Body diff */}
          {result.body && (
            <CompareSection title="Body">
              <BodyDiffView body={result.body} />
            </CompareSection>
          )}
        </div>
      )}

      {!result && !loading && (
        <div className="comparer-empty">
          Enter two Flow IDs and click Compare to see a structured diff of their responses.
        </div>
      )}
    </div>
  );
}

/** Summary card showing an overview of the comparison. */
function SummaryCard({ result }: { result: CompareResult }) {
  const statusMatch = result.status_code ? !result.status_code.changed : true;
  const bodyIdentical = result.body?.identical ?? true;
  const headerChanges =
    (result.headers_added?.length ?? 0) +
    (result.headers_removed?.length ?? 0) +
    (result.headers_changed ? Object.keys(result.headers_changed).length : 0);

  return (
    <div className="comparer-summary-card">
      <div className="comparer-summary-item">
        <span className="comparer-summary-label">Status</span>
        <Badge variant={statusMatch ? "success" : "danger"}>
          {statusMatch ? "Match" : "Different"}
        </Badge>
      </div>
      <div className="comparer-summary-item">
        <span className="comparer-summary-label">Headers</span>
        <Badge variant={headerChanges === 0 ? "success" : "warning"}>
          {headerChanges === 0 ? "No changes" : `${headerChanges} change${headerChanges > 1 ? "s" : ""}`}
        </Badge>
      </div>
      <div className="comparer-summary-item">
        <span className="comparer-summary-label">Body</span>
        <Badge variant={bodyIdentical ? "success" : "warning"}>
          {bodyIdentical ? "Identical" : "Different"}
        </Badge>
      </div>
      {result.timing_ms && (
        <div className="comparer-summary-item">
          <span className="comparer-summary-label">Timing</span>
          <span className="comparer-summary-value">
            {result.timing_ms.delta > 0 ? "+" : ""}{result.timing_ms.delta}ms
          </span>
        </div>
      )}
      {result.body_length && (
        <div className="comparer-summary-item">
          <span className="comparer-summary-label">Size</span>
          <span className="comparer-summary-value">
            {result.body_length.delta > 0 ? "+" : ""}{result.body_length.delta} bytes
          </span>
        </div>
      )}
    </div>
  );
}

/** Reusable section wrapper for compare results. */
function CompareSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="comparer-section">
      <h4 className="comparer-section-title">{title}</h4>
      {children}
    </div>
  );
}

/** Status code badge with color coding. */
function StatusBadge({ code, label }: { code: number; label: string }) {
  const variant = code < 300 ? "success" : code < 400 ? "info" : code < 500 ? "warning" : "danger";
  return (
    <span className="comparer-status-badge">
      <span className="comparer-status-label">{label}:</span>
      <Badge variant={variant}>{code}</Badge>
    </span>
  );
}

/** Header diff section showing added/removed/changed headers. */
function HeaderDiffSection({ result }: { result: CompareResult }) {
  const hasAdded = result.headers_added && result.headers_added.length > 0;
  const hasRemoved = result.headers_removed && result.headers_removed.length > 0;
  const hasChanged = result.headers_changed && Object.keys(result.headers_changed).length > 0;

  if (!hasAdded && !hasRemoved && !hasChanged) {
    return null;
  }

  return (
    <CompareSection title="Headers">
      <table className="comparer-headers-table">
        <thead>
          <tr>
            <th>Header</th>
            <th>Change</th>
            <th>Value A</th>
            <th>Value B</th>
          </tr>
        </thead>
        <tbody>
          {result.headers_added?.map((h) => (
            <tr key={`added-${h}`}>
              <td className="comparer-header-name">{h}</td>
              <td><Badge variant="success">Added</Badge></td>
              <td className="comparer-header-value">-</td>
              <td className="comparer-header-value">(present in B)</td>
            </tr>
          ))}
          {result.headers_removed?.map((h) => (
            <tr key={`removed-${h}`}>
              <td className="comparer-header-name">{h}</td>
              <td><Badge variant="danger">Removed</Badge></td>
              <td className="comparer-header-value">(present in A)</td>
              <td className="comparer-header-value">-</td>
            </tr>
          ))}
          {result.headers_changed && Object.entries(result.headers_changed).map(([key, diff]) => (
            <tr key={`changed-${key}`}>
              <td className="comparer-header-name">{key}</td>
              <td><Badge variant="warning">Changed</Badge></td>
              <td className="comparer-header-value">{diff.a}</td>
              <td className="comparer-header-value">{diff.b}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </CompareSection>
  );
}

/** Body diff view with content-type-aware rendering. */
function BodyDiffView({ body }: { body: NonNullable<CompareResult["body"]> }) {
  if (body.identical) {
    return <div className="comparer-body-identical">Response bodies are identical.</div>;
  }

  return (
    <div className="comparer-body-diff">
      <div className="comparer-body-meta">
        <span>Content-Type: <code>{body.content_type || "(unknown)"}</code></span>
        <Badge variant="warning">Different</Badge>
      </div>

      {body.json_diff && (
        <div className="comparer-json-diff">
          <h5 className="comparer-json-diff-title">JSON Key Diff</h5>
          {body.json_diff.keys_added && body.json_diff.keys_added.length > 0 && (
            <div className="comparer-json-diff-group">
              <span className="comparer-json-diff-label">Added keys:</span>
              <div className="comparer-json-diff-keys">
                {body.json_diff.keys_added.map((k) => (
                  <Badge key={k} variant="success">{k}</Badge>
                ))}
              </div>
            </div>
          )}
          {body.json_diff.keys_removed && body.json_diff.keys_removed.length > 0 && (
            <div className="comparer-json-diff-group">
              <span className="comparer-json-diff-label">Removed keys:</span>
              <div className="comparer-json-diff-keys">
                {body.json_diff.keys_removed.map((k) => (
                  <Badge key={k} variant="danger">{k}</Badge>
                ))}
              </div>
            </div>
          )}
          {body.json_diff.keys_changed && body.json_diff.keys_changed.length > 0 && (
            <div className="comparer-json-diff-group">
              <span className="comparer-json-diff-label">Changed keys:</span>
              <div className="comparer-json-diff-keys">
                {body.json_diff.keys_changed.map((k) => (
                  <Badge key={k} variant="warning">{k}</Badge>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {!body.json_diff && (
        <div className="comparer-body-text-diff">
          Bodies differ but no structured diff is available for this content type.
        </div>
      )}
    </div>
  );
}
