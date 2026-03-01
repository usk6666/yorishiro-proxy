import { useState, useCallback } from "react";
import { useConfigure } from "../../lib/mcp/hooks.js";
import type { ConfigResult, TransformRule } from "../../lib/mcp/types.js";
import { Button, Input, useToast } from "../../components/ui/index.js";

interface AutoTransformRulesProps {
  config: ConfigResult;
  onRefresh: () => void;
}

const DIRECTION_OPTIONS = ["request", "response", "both"] as const;
const ACTION_TYPES = ["add_header", "set_header", "remove_header", "replace_body"] as const;

/**
 * AutoTransformRules — manage auto-transform rules for automatic request/response modification.
 */
export function AutoTransformRules({ config: _config, onRefresh }: AutoTransformRulesProps) {
  const { addToast } = useToast();
  const { configure, loading: configureLoading } = useConfigure();

  const [showForm, setShowForm] = useState(false);

  // Form state
  const [ruleId, setRuleId] = useState("");
  const [priority, setPriority] = useState("0");
  const [direction, setDirection] = useState<"request" | "response" | "both">("request");
  const [urlPattern, setUrlPattern] = useState("");
  const [methods, setMethods] = useState("");
  const [actionType, setActionType] = useState<"add_header" | "set_header" | "remove_header" | "replace_body">("set_header");
  const [headerName, setHeaderName] = useState("");
  const [headerValue, setHeaderValue] = useState("");
  const [bodyPattern, setBodyPattern] = useState("");
  const [bodyReplacement, setBodyReplacement] = useState("");

  // Manage by ID
  const [actionId, setActionId] = useState("");

  const resetForm = () => {
    setRuleId("");
    setPriority("0");
    setDirection("request");
    setUrlPattern("");
    setMethods("");
    setActionType("set_header");
    setHeaderName("");
    setHeaderValue("");
    setBodyPattern("");
    setBodyReplacement("");
    setShowForm(false);
  };

  const handleAdd = useCallback(async () => {
    const id = ruleId.trim();
    if (!id) {
      addToast({ type: "warning", message: "Rule ID is required" });
      return;
    }

    const rule: TransformRule = {
      id,
      enabled: true,
      priority: parseInt(priority, 10) || 0,
      direction,
      conditions: {},
      action: { type: actionType },
    };

    if (urlPattern.trim()) rule.conditions.url_pattern = urlPattern.trim();
    if (methods.trim()) {
      rule.conditions.methods = methods
        .split(",")
        .map((m) => m.trim().toUpperCase())
        .filter(Boolean);
    }

    if (actionType === "add_header" || actionType === "set_header") {
      rule.action.header = headerName.trim();
      rule.action.value = headerValue.trim();
    } else if (actionType === "remove_header") {
      rule.action.header = headerName.trim();
    } else if (actionType === "replace_body") {
      rule.action.pattern = bodyPattern.trim();
      rule.action.value = bodyReplacement.trim();
    }

    try {
      await configure({
        auto_transform: { add: [rule] },
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
  }, [ruleId, priority, direction, urlPattern, methods, actionType, headerName, headerValue, bodyPattern, bodyReplacement, configure, addToast, onRefresh]);

  const handleRemove = useCallback(async () => {
    const id = actionId.trim();
    if (!id) return;

    try {
      await configure({
        auto_transform: { remove: [id] },
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
    if (!id) return;

    try {
      await configure({
        auto_transform: { enable: [id] },
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
    if (!id) return;

    try {
      await configure({
        auto_transform: { disable: [id] },
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

  const showHeaderFields = actionType === "add_header" || actionType === "set_header" || actionType === "remove_header";
  const showBodyFields = actionType === "replace_body";

  return (
    <div className="settings-section">
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Auto-Transform Rules</span>
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
            Auto-transform rules automatically modify matching requests or responses
            (e.g., add headers, replace body patterns).
          </p>

          {/* Manage existing rule by ID */}
          <div className="settings-inline-form">
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
          <div className="settings-add-form-title">Add Auto-Transform Rule</div>

          {/* Basic fields */}
          <div className="settings-form-row">
            <Input
              label="Rule ID"
              value={ruleId}
              onChange={(e) => setRuleId(e.target.value)}
              placeholder="my-transform"
            />
            <Input
              label="Priority"
              value={priority}
              onChange={(e) => setPriority(e.target.value)}
              placeholder="0"
              type="number"
            />
            <div className="input-wrapper">
              <label className="input-label" htmlFor="transform-direction">Direction</label>
              <select
                id="transform-direction"
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

          {/* Conditions */}
          <div className="settings-form-row">
            <Input
              label="URL Pattern (regex)"
              value={urlPattern}
              onChange={(e) => setUrlPattern(e.target.value)}
              placeholder="/api/.*"
            />
            <Input
              label="Methods (comma-separated)"
              value={methods}
              onChange={(e) => setMethods(e.target.value)}
              placeholder="POST, PUT"
            />
          </div>

          {/* Action */}
          <div className="settings-form-row">
            <div className="input-wrapper">
              <label className="input-label" htmlFor="transform-action-type">Action Type</label>
              <select
                id="transform-action-type"
                className="settings-select"
                value={actionType}
                onChange={(e) => setActionType(e.target.value as typeof actionType)}
              >
                {ACTION_TYPES.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Header fields */}
          {showHeaderFields && (
            <div className="settings-form-row">
              <Input
                label="Header Name"
                value={headerName}
                onChange={(e) => setHeaderName(e.target.value)}
                placeholder="X-Custom-Header"
              />
              {actionType !== "remove_header" && (
                <Input
                  label="Header Value"
                  value={headerValue}
                  onChange={(e) => setHeaderValue(e.target.value)}
                  placeholder="value"
                />
              )}
            </div>
          )}

          {/* Body fields */}
          {showBodyFields && (
            <div className="settings-form-row">
              <Input
                label="Search Pattern (regex)"
                value={bodyPattern}
                onChange={(e) => setBodyPattern(e.target.value)}
                placeholder="old-text"
              />
              <Input
                label="Replacement"
                value={bodyReplacement}
                onChange={(e) => setBodyReplacement(e.target.value)}
                placeholder="new-text"
              />
            </div>
          )}

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
    </div>
  );
}
