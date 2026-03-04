import { Button } from "../../components/ui/index.js";
import type { TargetRule } from "../../lib/mcp/types.js";

interface RuleTableProps {
  rules: TargetRule[];
  onRemove?: (rule: TargetRule) => void;
  loading?: boolean;
}

/**
 * RuleTable -- renders a list of TargetRule entries as styled items.
 * When onRemove is provided, each row includes a remove button (for Agent Layer).
 */
export function RuleTable({ rules, onRemove, loading }: RuleTableProps) {
  return (
    <div className="security-rule-list">
      {rules.map((rule, i) => (
        <div key={i} className="security-rule-item">
          <div className="security-rule-content">
            <span className="security-rule-hostname">{rule.hostname}</span>
            <div className="security-rule-details">
              {rule.ports && rule.ports.length > 0 && (
                <span className="security-rule-meta">
                  ports: {rule.ports.join(", ")}
                </span>
              )}
              {rule.path_prefix && (
                <span className="security-rule-meta">
                  path: {rule.path_prefix}
                </span>
              )}
              {rule.schemes && rule.schemes.length > 0 && (
                <span className="security-rule-meta">
                  schemes: {rule.schemes.join(", ")}
                </span>
              )}
            </div>
          </div>
          {onRemove && (
            <div className="security-rule-actions">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => onRemove(rule)}
                disabled={loading}
              >
                Remove
              </Button>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
