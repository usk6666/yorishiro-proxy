import { useCallback, useState } from "react";
import { Button, Input, useToast } from "../../components/ui/index.js";
import { useConfigure } from "../../lib/mcp/hooks.js";
import type { ConfigResult, InterceptRule } from "../../lib/mcp/types.js";

interface InterceptRulesProps {
  config: ConfigResult;
  onRefresh: () => void;
}

const DIRECTION_OPTIONS = ["request", "response", "both"] as const;
const TIMEOUT_BEHAVIOR_OPTIONS = ["auto_release", "auto_drop"] as const;

/**
 * InterceptRules — manage intercept rules for request/response interception.
 *
 * Note: The config query does not return individual rule details.
 * We manage rules via the configure tool's intercept_rules section.
 */
export function InterceptRules({ config: _config, onRefresh }: InterceptRulesProps) {
  const { addToast } = useToast();
  const { configure, loading: configureLoading } = useConfigure();

  // We need the full config for intercept rule state;
  // the config result doesn't include individual rules,
  // so we provide a form-based add/remove interface.
  const [showForm, setShowForm] = useState(false);
  const [ruleId, setRuleId] = useState("");
  const [direction, setDirection] = useState<"request" | "response" | "both">("request");
  const [hostPattern, setHostPattern] = useState("");
  const [pathPattern, setPathPattern] = useState("");
  const [methods, setMethods] = useState("");

  // Remove/enable/disable by ID
  const [actionId, setActionId] = useState("");

  // Intercept queue settings
  const [queueTimeoutMs, setQueueTimeoutMs] = useState("");
  const [queueTimeoutBehavior, setQueueTimeoutBehavior] = useState<"auto_release" | "auto_drop">("auto_release");

  const resetForm = () => {
    setRuleId("");
    setDirection("request");
    setHostPattern("");
    setPathPattern("");
    setMethods("");
    setShowForm(false);
  };

  const handleAdd = useCallback(async () => {
    const id = ruleId.trim();
    if (!id) {
      addToast({ type: "warning", message: "Rule ID is required" });
      return;
    }

    const rule: InterceptRule = {
      id,
      enabled: true,
      direction,
      conditions: {},
    };

    if (hostPattern.trim()) rule.conditions.host_pattern = hostPattern.trim();
    if (pathPattern.trim()) rule.conditions.path_pattern = pathPattern.trim();
    if (methods.trim()) {
      rule.conditions.methods = methods
        .split(",")
        .map((m) => m.trim().toUpperCase())
        .filter(Boolean);
    }

    try {
      await configure({
        intercept_rules: { add: [rule] },
      });
      addToast({ type: "success", message: `Rule "${id}" added` });
      resetForm();
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to add rule: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [ruleId, direction, hostPattern, pathPattern, methods, configure, addToast, onRefresh]);

  const handleRemove = useCallback(async () => {
    const id = actionId.trim();
    if (!id) {
      addToast({ type: "warning", message: "Rule ID is required" });
      return;
    }

    try {
      await configure({
        intercept_rules: { remove: [id] },
      });
      addToast({ type: "success", message: `Rule "${id}" removed` });
      setActionId("");
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to remove rule: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [actionId, configure, addToast, onRefresh]);

  const handleEnable = useCallback(async () => {
    const id = actionId.trim();
    if (!id) {
      addToast({ type: "warning", message: "Rule ID is required" });
      return;
    }

    try {
      await configure({
        intercept_rules: { enable: [id] },
      });
      addToast({ type: "success", message: `Rule "${id}" enabled` });
      setActionId("");
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to enable rule: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [actionId, configure, addToast, onRefresh]);

  const handleDisable = useCallback(async () => {
    const id = actionId.trim();
    if (!id) {
      addToast({ type: "warning", message: "Rule ID is required" });
      return;
    }

    try {
      await configure({
        intercept_rules: { disable: [id] },
      });
      addToast({ type: "success", message: `Rule "${id}" disabled` });
      setActionId("");
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to disable rule: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [actionId, configure, addToast, onRefresh]);

  const handleSaveQueueSettings = useCallback(async () => {
    let timeoutMs: number | null = null;
    const trimmed = queueTimeoutMs.trim();
    if (trimmed) {
      const parsed = parseInt(trimmed, 10);
      if (isNaN(parsed) || parsed < 0) {
        addToast({ type: "warning", message: "Timeout must be a non-negative number" });
        return;
      }
      timeoutMs = parsed;
    }

    try {
      await configure({
        intercept_queue: {
          timeout_ms: timeoutMs,
          timeout_behavior: queueTimeoutBehavior,
        },
      });
      addToast({ type: "success", message: "Intercept queue settings updated" });
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to update queue settings: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [queueTimeoutMs, queueTimeoutBehavior, configure, addToast, onRefresh]);

  return (
    <div className="settings-section">
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Intercept Rules</span>
          <Button
            variant="primary"
            size="sm"
            onClick={() => setShowForm(!showForm)}
          >
            {showForm ? "Cancel" : "Add Rule"}
          </Button>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Intercept rules define conditions for holding requests/responses for manual review.
            The config query does not return individual rule details; use the controls below to manage rules by ID.
          </p>

          {/* Manage existing rule by ID */}
          <div className="settings-inline-form" style={{ marginBottom: "var(--space-md)" }}>
            <Input
              value={actionId}
              onChange={(e) => setActionId(e.target.value)}
              placeholder="Rule ID"
            />
            <Button
              variant="secondary"
              size="sm"
              onClick={handleEnable}
              disabled={configureLoading || !actionId.trim()}
            >
              Enable
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleDisable}
              disabled={configureLoading || !actionId.trim()}
            >
              Disable
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={handleRemove}
              disabled={configureLoading || !actionId.trim()}
            >
              Remove
            </Button>
          </div>
        </div>
      </div>

      {/* Add rule form */}
      {showForm && (
        <div className="settings-add-form">
          <div className="settings-add-form-title">Add Intercept Rule</div>
          <div className="settings-form-row">
            <Input
              label="Rule ID"
              value={ruleId}
              onChange={(e) => setRuleId(e.target.value)}
              placeholder="my-rule"
            />
            <div className="input-wrapper">
              <label className="input-label" htmlFor="intercept-direction">Direction</label>
              <select
                id="intercept-direction"
                className="settings-select"
                value={direction}
                onChange={(e) => setDirection(e.target.value as "request" | "response" | "both")}
              >
                {DIRECTION_OPTIONS.map((d) => (
                  <option key={d} value={d}>{d}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="settings-form-row">
            <Input
              label="Host Pattern (regex)"
              value={hostPattern}
              onChange={(e) => setHostPattern(e.target.value)}
              placeholder=".*\\.example\\.com"
            />
            <Input
              label="Path Pattern (regex)"
              value={pathPattern}
              onChange={(e) => setPathPattern(e.target.value)}
              placeholder="/api/.*"
            />
            <Input
              label="Methods (comma-separated)"
              value={methods}
              onChange={(e) => setMethods(e.target.value)}
              placeholder="POST, PUT, DELETE"
            />
          </div>
          <div className="settings-add-form-actions">
            <Button variant="secondary" size="sm" onClick={resetForm}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleAdd}
              disabled={configureLoading}
            >
              Add Rule
            </Button>
          </div>
        </div>
      )}

      {/* Intercept Queue Settings */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Intercept Queue</span>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Configure timeout behavior for intercepted requests waiting in the queue.
            When the timeout expires, the request is automatically released or dropped.
          </p>
          <div className="settings-form-row">
            <Input
              label="Timeout (ms)"
              type="number"
              value={queueTimeoutMs}
              onChange={(e) => setQueueTimeoutMs(e.target.value)}
              placeholder="e.g. 30000 (leave empty for default)"
            />
            <div className="input-wrapper">
              <label className="input-label" htmlFor="queue-timeout-behavior">Timeout Behavior</label>
              <select
                id="queue-timeout-behavior"
                className="settings-select"
                value={queueTimeoutBehavior}
                onChange={(e) => setQueueTimeoutBehavior(e.target.value as "auto_release" | "auto_drop")}
              >
                {TIMEOUT_BEHAVIOR_OPTIONS.map((b) => (
                  <option key={b} value={b}>{b === "auto_release" ? "Auto Release" : "Auto Drop"}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="settings-add-form-actions">
            <Button
              variant="primary"
              size="sm"
              onClick={handleSaveQueueSettings}
              disabled={configureLoading}
            >
              Save Queue Settings
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
