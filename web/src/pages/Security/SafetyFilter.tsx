import { useCallback, useEffect, useState } from "react";
import { Badge, Spinner } from "../../components/ui/index.js";
import { useMcpContext } from "../../lib/mcp/context.js";
import { useSecurity } from "../../lib/mcp/hooks.js";
import type { SafetyFilterResult, SafetyFilterRule } from "../../lib/mcp/types.js";

/**
 * SafetyFilterRuleTable -- renders a list of SafetyFilter rules as a table.
 * Used for both Input Filter and Output Filter rule display.
 */
function SafetyFilterRuleTable({ rules, showReplacement }: { rules: SafetyFilterRule[]; showReplacement?: boolean }) {
  if (rules.length === 0) {
    return <div className="security-empty">No rules configured</div>;
  }

  return (
    <div className="security-rule-list">
      {rules.map((rule) => (
        <div key={rule.id} className="security-rule-item">
          <div className="security-rule-content">
            <span className="security-rule-hostname">{rule.name}</span>
            <div className="security-rule-details">
              <span className="security-rule-meta">
                pattern: {rule.pattern}
              </span>
              <span className="security-rule-meta">
                targets: {rule.targets.join(", ")}
              </span>
              <span className="security-rule-meta">
                action: {rule.action}
              </span>
              {showReplacement && rule.replacement && (
                <span className="security-rule-meta">
                  replacement: {rule.replacement}
                </span>
              )}
              <span className="security-rule-meta">
                category: {rule.category}
              </span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * SafetyFilter -- read-only display of SafetyFilter rules (Input Filter + Output Filter).
 * These rules are defined in the configuration file and cannot be modified via the UI.
 */
export function SafetyFilter() {
  const { status } = useMcpContext();
  const { security } = useSecurity();

  const [data, setData] = useState<SafetyFilterResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchSafetyFilter = useCallback(async () => {
    if (status !== "connected") return;

    setLoading(true);
    setError(null);

    try {
      const result = await security<SafetyFilterResult>({
        action: "get_safety_filter",
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
      fetchSafetyFilter();
    }
  }, [status, fetchSafetyFilter]);

  if (loading && !data) {
    return (
      <div className="security-section">
        <div className="security-section-header">
          <h2 className="security-section-title">Safety Filter</h2>
          <Badge variant="default">Policy Layer</Badge>
        </div>
        <div className="security-loading"><Spinner size="md" /></div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <div className="security-section">
        <div className="security-section-header">
          <h2 className="security-section-title">Safety Filter</h2>
          <Badge variant="default">Policy Layer</Badge>
        </div>
        <div className="security-error">Error loading safety filter: {error.message}</div>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  return (
    <div className="security-section">
      <div className="security-section-header">
        <h2 className="security-section-title">Safety Filter</h2>
        <Badge variant={data.enabled ? "success" : "warning"}>
          {data.enabled ? "Enabled" : "Disabled"}
        </Badge>
        {data.immutable && <Badge variant="default">Immutable</Badge>}
      </div>
      <p className="security-section-desc">
        Input and output filter rules defined in the configuration file. Read-only.
      </p>

      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Input Filter Rules</span>
          <Badge variant="info">{data.input_rules.length}</Badge>
        </div>
        <div className="security-card-body">
          <SafetyFilterRuleTable rules={data.input_rules} />
        </div>
      </div>

      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Output Filter Rules</span>
          <Badge variant="info">{data.output_rules.length}</Badge>
        </div>
        <div className="security-card-body">
          <SafetyFilterRuleTable rules={data.output_rules} showReplacement />
        </div>
      </div>
    </div>
  );
}
