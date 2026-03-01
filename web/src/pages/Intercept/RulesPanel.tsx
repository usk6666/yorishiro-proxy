import type { ConfigResult, InterceptRule } from "../../lib/mcp/types.js";
import { Badge, Spinner } from "../../components/ui/index.js";

interface RulesPanelProps {
  configData: ConfigResult | null;
  loading: boolean;
  onToggleRule: (rule: InterceptRule) => void;
}

export function RulesPanel({ configData, loading, onToggleRule }: RulesPanelProps) {
  if (loading && !configData) {
    return (
      <div className="intercept-loading">
        <Spinner size="md" />
      </div>
    );
  }

  // ConfigResult does not include the full intercept_rules list directly.
  // We need to look at the intercept_rules field from the config query response.
  // The config query returns capture_scope, tls_passthrough, etc., but intercept_rules
  // are managed via the configure tool. We'll display what we know from the config response.
  const interceptRules = extractInterceptRules(configData);

  if (interceptRules.length === 0) {
    return (
      <div className="intercept-rules-empty">
        No intercept rules configured. Use the configure tool to add intercept rules.
      </div>
    );
  }

  return (
    <div className="intercept-rules-list">
      {interceptRules.map((rule) => (
        <div
          key={rule.id}
          className={`intercept-rule ${rule.enabled ? "" : "intercept-rule--disabled"}`}
        >
          <div className="intercept-rule-info">
            <span className="intercept-rule-id">{rule.id}</span>
            <span className="intercept-rule-conditions">
              {formatRuleConditions(rule)}
            </span>
          </div>
          <div className="intercept-rule-actions">
            <Badge variant={rule.enabled ? "success" : "default"}>
              {rule.enabled ? "Enabled" : "Disabled"}
            </Badge>
            <Badge variant="default">{rule.direction}</Badge>
            <label className="intercept-toggle">
              <input
                type="checkbox"
                checked={rule.enabled}
                onChange={() => onToggleRule(rule)}
                disabled={loading}
              />
              <span className="intercept-toggle-slider" />
            </label>
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * Extract intercept rules from the config response.
 * The config query response includes intercept_rules as a nested object
 * with rule details. We need to handle the case where the full rules
 * are available vs only summary counts.
 */
function extractInterceptRules(config: ConfigResult | null): InterceptRule[] {
  if (!config) return [];

  // The config response may include intercept_rules in the full config format.
  // We cast to access possible extended fields that the server may return.
  const extended = config as ConfigResult & {
    intercept_rules?: {
      rules?: InterceptRule[];
      total_rules?: number;
      enabled_rules?: number;
    };
  };

  if (extended.intercept_rules?.rules) {
    return extended.intercept_rules.rules;
  }

  return [];
}

function formatRuleConditions(rule: InterceptRule): string {
  const parts: string[] = [];
  const c = rule.conditions;

  if (c.host_pattern) {
    parts.push(`host: ${c.host_pattern}`);
  }
  if (c.path_pattern) {
    parts.push(`path: ${c.path_pattern}`);
  }
  if (c.methods && c.methods.length > 0) {
    parts.push(`methods: ${c.methods.join(", ")}`);
  }
  if (c.header_match) {
    const entries = Object.entries(c.header_match);
    if (entries.length > 0) {
      parts.push(`headers: ${entries.map(([k, v]) => `${k}=${v}`).join(", ")}`);
    }
  }

  return parts.length > 0 ? parts.join(" | ") : "match all";
}
