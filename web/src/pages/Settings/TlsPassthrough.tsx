import { useCallback, useState } from "react";
import { Button, Input, useToast } from "../../components/ui/index.js";
import { useConfigure } from "../../lib/mcp/hooks.js";
import type { ConfigResult } from "../../lib/mcp/types.js";

interface TlsPassthroughProps {
  config: ConfigResult;
  onRefresh: () => void;
}

/**
 * TlsPassthrough — manage TLS passthrough patterns (domains that bypass MITM).
 */
export function TlsPassthrough({ config, onRefresh }: TlsPassthroughProps) {
  const { addToast } = useToast();
  const { configure, loading } = useConfigure();

  const [newPattern, setNewPattern] = useState("");

  const patterns = config.tls_passthrough?.patterns ?? [];

  const handleAdd = useCallback(async () => {
    const pattern = newPattern.trim();
    if (!pattern) {
      addToast({ type: "warning", message: "Pattern is required" });
      return;
    }

    try {
      await configure({
        tls_passthrough: { add: [pattern] },
      });
      addToast({ type: "success", message: `Pattern "${pattern}" added` });
      setNewPattern("");
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to add pattern: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [newPattern, configure, addToast, onRefresh]);

  const handleRemove = useCallback(async (pattern: string) => {
    try {
      await configure({
        tls_passthrough: { remove: [pattern] },
      });
      addToast({ type: "success", message: `Pattern "${pattern}" removed` });
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to remove pattern: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [configure, addToast, onRefresh]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      handleAdd();
    }
  }, [handleAdd]);

  return (
    <div className="settings-section">
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">
            TLS Passthrough Patterns ({patterns.length})
          </span>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Domains matching these patterns will bypass TLS interception (no MITM).
          </p>

          {/* Add pattern */}
          <div className="settings-inline-form" style={{ marginBottom: "var(--space-md)" }}>
            <Input
              value={newPattern}
              onChange={(e) => setNewPattern(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="e.g., pinned-service.com or *.googleapis.com"
            />
            <Button
              variant="primary"
              size="sm"
              onClick={handleAdd}
              disabled={loading}
            >
              Add
            </Button>
          </div>

          {/* Pattern list */}
          {patterns.length > 0 ? (
            <div className="settings-item-list">
              {patterns.map((pattern) => (
                <div key={pattern} className="settings-item">
                  <div className="settings-item-content">
                    <span className="settings-item-text">{pattern}</span>
                  </div>
                  <div className="settings-item-actions">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleRemove(pattern)}
                      disabled={loading}
                    >
                      Remove
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="settings-empty">
              No TLS passthrough patterns configured
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
