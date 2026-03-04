import { useState, useCallback } from "react";
import { useSecurity } from "../../lib/mcp/hooks.js";
import { Button, Input, Badge, useToast } from "../../components/ui/index.js";
import type { SecurityTestTargetResult } from "../../lib/mcp/types.js";

/**
 * UrlTestTool -- test a URL against current target scope rules.
 * Displays whether the URL is allowed or denied, the reason, matched rule, and deciding layer.
 */
export function UrlTestTool() {
  const { addToast } = useToast();
  const { security, loading } = useSecurity();

  const [url, setUrl] = useState("");
  const [result, setResult] = useState<SecurityTestTargetResult | null>(null);

  const handleTest = useCallback(async () => {
    const trimmedUrl = url.trim();
    if (!trimmedUrl) {
      addToast({ type: "warning", message: "URL is required" });
      return;
    }

    try {
      const res = await security<SecurityTestTargetResult>({
        action: "test_target",
        params: { url: trimmedUrl },
      });
      setResult(res);
    } catch (err) {
      addToast({
        type: "error",
        message: `Test failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [url, security, addToast]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") {
        handleTest();
      }
    },
    [handleTest],
  );

  return (
    <div className="security-section">
      <div className="security-section-header">
        <h2 className="security-section-title">URL Test</h2>
      </div>
      <p className="security-section-desc">
        Test whether a URL is allowed or denied by the current target scope rules.
      </p>

      <div className="security-card">
        <div className="security-card-body">
          <div className="security-url-test-form">
            <Input
              label="Test URL"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="https://example.com/api/v1/resource"
            />
            <Button
              variant="primary"
              size="sm"
              onClick={handleTest}
              disabled={loading}
            >
              Test
            </Button>
          </div>

          {result && (
            <div className="security-test-result">
              <div className="security-test-result-header">
                <Badge variant={result.allowed ? "success" : "danger"}>
                  {result.allowed ? "Allowed" : "Denied"}
                </Badge>
                <Badge variant="info">{result.layer}</Badge>
              </div>
              <div className="security-test-result-details">
                <div className="security-test-result-row">
                  <span className="security-test-label">Reason</span>
                  <span className="security-test-value">{result.reason}</span>
                </div>
                <div className="security-test-result-row">
                  <span className="security-test-label">Tested Target</span>
                  <span className="security-test-value">
                    {result.tested_target.scheme}://{result.tested_target.hostname}
                    :{result.tested_target.port}{result.tested_target.path}
                  </span>
                </div>
                {result.matched_rule && (
                  <div className="security-test-result-row">
                    <span className="security-test-label">Matched Rule</span>
                    <span className="security-test-value">
                      {result.matched_rule.hostname}
                      {result.matched_rule.ports && result.matched_rule.ports.length > 0
                        ? ` (ports: ${result.matched_rule.ports.join(", ")})`
                        : ""}
                      {result.matched_rule.path_prefix
                        ? ` path: ${result.matched_rule.path_prefix}`
                        : ""}
                      {result.matched_rule.schemes && result.matched_rule.schemes.length > 0
                        ? ` schemes: ${result.matched_rule.schemes.join(", ")}`
                        : ""}
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
