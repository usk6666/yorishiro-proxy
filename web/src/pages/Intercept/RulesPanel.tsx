import type { ConfigResult } from "../../lib/mcp/types.js";
import { Spinner } from "../../components/ui/index.js";

interface RulesPanelProps {
  configData: ConfigResult | null;
  loading: boolean;
}

export function RulesPanel({ configData, loading }: RulesPanelProps) {
  if (loading && !configData) {
    return (
      <div className="intercept-loading">
        <Spinner size="md" />
      </div>
    );
  }

  return (
    <div className="intercept-rules-empty">
      <p>
        Intercept rules are managed via the MCP <code>configure</code> tool.
      </p>
      <p>
        The config query does not return individual rule details.
        Use the configure tool to add, remove, enable, or disable intercept rules.
      </p>
    </div>
  );
}
