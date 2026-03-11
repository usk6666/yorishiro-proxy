import { useCallback, useEffect, useState } from "react";
import { Spinner } from "../../components/ui/index.js";
import { useMcpContext } from "../../lib/mcp/context.js";
import { useSecurity } from "../../lib/mcp/hooks.js";
import type { SecurityGetScopeResult } from "../../lib/mcp/types.js";
import { AgentLayer } from "./AgentLayer.js";
import { Budget } from "./Budget.js";
import { EnforcementMode } from "./EnforcementMode.js";
import { PolicyLayer } from "./PolicyLayer.js";
import { RateLimits } from "./RateLimits.js";
import "./SecurityPage.css";
import { UrlTestTool } from "./UrlTestTool.js";

/**
 * SecurityPage -- Security management page.
 *
 * Displays the two-layer target scope model (Policy Layer + Agent Layer),
 * enforcement mode, URL test tool, rate limits, and diagnostic budget.
 */
export function SecurityPage() {
  const { status } = useMcpContext();
  const { security, loading: actionLoading } = useSecurity();

  const [scopeData, setScopeData] = useState<SecurityGetScopeResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fetchScope = useCallback(async () => {
    if (status !== "connected") return;

    setLoading(true);
    setError(null);

    try {
      const result = await security<SecurityGetScopeResult>({
        action: "get_target_scope",
        params: {},
      });
      setScopeData(result);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, [security, status]);

  // Fetch scope data on mount when connected.
  useEffect(() => {
    if (status === "connected") {
      fetchScope();
    }
  }, [status, fetchScope]);

  if (loading && !scopeData) {
    return (
      <div className="page security-page">
        <h1 className="page-title">Security</h1>
        <p className="page-description">Target scope and access control management.</p>
        <div className="security-loading"><Spinner size="md" /></div>
      </div>
    );
  }

  if (error && !scopeData) {
    return (
      <div className="page security-page">
        <h1 className="page-title">Security</h1>
        <p className="page-description">Target scope and access control management.</p>
        <div className="security-error">Error loading scope: {error.message}</div>
      </div>
    );
  }

  return (
    <div className="page security-page">
      <h1 className="page-title">Security</h1>
      <p className="page-description">Target scope, rate limits, and diagnostic budget management.</p>

      <div className="security-content">
        {scopeData && (
          <EnforcementMode scopeData={scopeData} />
        )}

        {scopeData && (
          <PolicyLayer policy={scopeData.policy} />
        )}

        {scopeData && (
          <AgentLayer
            agent={scopeData.agent}
            onRefresh={fetchScope}
            actionLoading={actionLoading}
          />
        )}

        <UrlTestTool />

        <RateLimits />

        <Budget />
      </div>
    </div>
  );
}
