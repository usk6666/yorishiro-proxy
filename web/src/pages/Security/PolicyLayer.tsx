import { Badge } from "../../components/ui/index.js";
import type { PolicyLayerResult } from "../../lib/mcp/types.js";
import { RuleTable } from "./RuleTable.js";

interface PolicyLayerProps {
  policy: PolicyLayerResult;
}

/**
 * PolicyLayer -- read-only display of Policy Layer target scope rules.
 * These rules are defined in the configuration file and cannot be modified via the UI.
 */
export function PolicyLayer({ policy }: PolicyLayerProps) {
  return (
    <div className="security-section">
      <div className="security-section-header">
        <h2 className="security-section-title">Policy Layer</h2>
        <Badge variant="default">Immutable</Badge>
      </div>
      <p className="security-section-desc">
        Rules defined in the configuration file (--policy-allow / --policy-deny). Read-only.
      </p>

      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Allow Rules</span>
        </div>
        <div className="security-card-body">
          {policy.allows.length > 0 ? (
            <RuleTable rules={policy.allows} />
          ) : (
            <div className="security-empty">No allow rules</div>
          )}
        </div>
      </div>

      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Deny Rules</span>
        </div>
        <div className="security-card-body">
          {policy.denies.length > 0 ? (
            <RuleTable rules={policy.denies} />
          ) : (
            <div className="security-empty">No deny rules</div>
          )}
        </div>
      </div>
    </div>
  );
}
