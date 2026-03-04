import { Badge } from "../../components/ui/index.js";
import type { SecurityGetScopeResult } from "../../lib/mcp/types.js";

interface EnforcementModeProps {
  scopeData: SecurityGetScopeResult;
}

/**
 * EnforcementMode -- displays the enforcement mode for each layer and the effective mode.
 */
export function EnforcementMode({ scopeData }: EnforcementModeProps) {
  return (
    <div className="security-section">
      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Enforcement Mode</span>
        </div>
        <div className="security-card-body">
          <div className="security-mode-grid">
            <div className="security-mode-item">
              <span className="security-mode-label">Effective Mode</span>
              <ModeBadge mode={scopeData.effective_mode} />
            </div>
            <div className="security-mode-item">
              <span className="security-mode-label">Policy Layer</span>
              <ModeBadge mode={getPolicyMode(scopeData)} />
            </div>
            <div className="security-mode-item">
              <span className="security-mode-label">Agent Layer</span>
              <ModeBadge mode={getAgentMode(scopeData)} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ModeBadge({ mode }: { mode: string }) {
  if (mode === "enforcing") {
    return <Badge variant="warning">{mode}</Badge>;
  }
  return <Badge variant="default">{mode}</Badge>;
}

/**
 * Derive policy mode from the scope data.
 * If policy has any allows or denies, it is enforcing; otherwise open.
 */
function getPolicyMode(data: SecurityGetScopeResult): string {
  const hasRules =
    data.policy.allows.length > 0 || data.policy.denies.length > 0;
  return hasRules ? "enforcing" : "open";
}

/**
 * Derive agent mode from the scope data.
 * If agent has any allows or denies, it is enforcing; otherwise open.
 */
function getAgentMode(data: SecurityGetScopeResult): string {
  const hasRules =
    data.agent.allows.length > 0 || data.agent.denies.length > 0;
  return hasRules ? "enforcing" : "open";
}
