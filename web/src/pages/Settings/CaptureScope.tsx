import { useCallback, useState } from "react";
import { Button, Input, useToast } from "../../components/ui/index.js";
import { useConfigure } from "../../lib/mcp/hooks.js";
import type { ConfigResult, ScopeRuleOutput } from "../../lib/mcp/types.js";

interface CaptureScopeProps {
  config: ConfigResult;
  onRefresh: () => void;
}

/**
 * CaptureScope — manage include/exclude capture scope rules.
 */
export function CaptureScope({ config, onRefresh }: CaptureScopeProps) {
  const { addToast } = useToast();
  const { configure, loading } = useConfigure();

  // Add rule form
  const [showAddInclude, setShowAddInclude] = useState(false);
  const [showAddExclude, setShowAddExclude] = useState(false);
  const [hostname, setHostname] = useState("");
  const [urlPrefix, setUrlPrefix] = useState("");
  const [method, setMethod] = useState("");

  const resetForm = () => {
    setHostname("");
    setUrlPrefix("");
    setMethod("");
    setShowAddInclude(false);
    setShowAddExclude(false);
  };

  const handleAddRule = useCallback(async (type: "include" | "exclude") => {
    const rule: Record<string, string> = {};
    if (hostname.trim()) rule.hostname = hostname.trim();
    if (urlPrefix.trim()) rule.url_prefix = urlPrefix.trim();
    if (method.trim()) rule.method = method.trim().toUpperCase();

    if (Object.keys(rule).length === 0) {
      addToast({ type: "warning", message: "At least one field is required" });
      return;
    }

    try {
      if (type === "include") {
        await configure({
          capture_scope: { add_includes: [rule] },
        });
      } else {
        await configure({
          capture_scope: { add_excludes: [rule] },
        });
      }
      addToast({ type: "success", message: `${type} rule added` });
      resetForm();
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to add rule: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [hostname, urlPrefix, method, configure, addToast, onRefresh]);

  const handleRemoveRule = useCallback(async (type: "include" | "exclude", rule: ScopeRuleOutput) => {
    try {
      if (type === "include") {
        await configure({
          capture_scope: { remove_includes: [rule] },
        });
      } else {
        await configure({
          capture_scope: { remove_excludes: [rule] },
        });
      }
      addToast({ type: "success", message: `${type} rule removed` });
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to remove rule: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [configure, addToast, onRefresh]);

  const renderRule = (rule: ScopeRuleOutput) => {
    const parts: string[] = [];
    if (rule.hostname) parts.push(`host: ${rule.hostname}`);
    if (rule.url_prefix) parts.push(`prefix: ${rule.url_prefix}`);
    if (rule.method) parts.push(`method: ${rule.method}`);
    return parts.join(" | ");
  };

  return (
    <div className="settings-section">
      {/* Include rules */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Include Rules</span>
          <Button
            variant="primary"
            size="sm"
            onClick={() => { setShowAddInclude(!showAddInclude); setShowAddExclude(false); }}
          >
            Add
          </Button>
        </div>
        <div className="settings-card-body">
          {config.capture_scope.includes.length > 0 ? (
            <div className="settings-item-list">
              {config.capture_scope.includes.map((rule, i) => (
                <div key={i} className="settings-item">
                  <div className="settings-item-content">
                    <span className="settings-item-text">{renderRule(rule)}</span>
                  </div>
                  <div className="settings-item-actions">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleRemoveRule("include", rule)}
                      disabled={loading}
                    >
                      Remove
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="settings-empty">No include rules (all requests captured)</div>
          )}
        </div>
      </div>

      {/* Include add form */}
      {showAddInclude && (
        <AddRuleForm
          title="Add Include Rule"
          hostname={hostname}
          urlPrefix={urlPrefix}
          method={method}
          onHostnameChange={setHostname}
          onUrlPrefixChange={setUrlPrefix}
          onMethodChange={setMethod}
          onSubmit={() => handleAddRule("include")}
          onCancel={resetForm}
          loading={loading}
        />
      )}

      {/* Exclude rules */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Exclude Rules</span>
          <Button
            variant="primary"
            size="sm"
            onClick={() => { setShowAddExclude(!showAddExclude); setShowAddInclude(false); }}
          >
            Add
          </Button>
        </div>
        <div className="settings-card-body">
          {config.capture_scope.excludes.length > 0 ? (
            <div className="settings-item-list">
              {config.capture_scope.excludes.map((rule, i) => (
                <div key={i} className="settings-item">
                  <div className="settings-item-content">
                    <span className="settings-item-text">{renderRule(rule)}</span>
                  </div>
                  <div className="settings-item-actions">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleRemoveRule("exclude", rule)}
                      disabled={loading}
                    >
                      Remove
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="settings-empty">No exclude rules</div>
          )}
        </div>
      </div>

      {/* Exclude add form */}
      {showAddExclude && (
        <AddRuleForm
          title="Add Exclude Rule"
          hostname={hostname}
          urlPrefix={urlPrefix}
          method={method}
          onHostnameChange={setHostname}
          onUrlPrefixChange={setUrlPrefix}
          onMethodChange={setMethod}
          onSubmit={() => handleAddRule("exclude")}
          onCancel={resetForm}
          loading={loading}
        />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// AddRuleForm
// ---------------------------------------------------------------------------

interface AddRuleFormProps {
  title: string;
  hostname: string;
  urlPrefix: string;
  method: string;
  onHostnameChange: (value: string) => void;
  onUrlPrefixChange: (value: string) => void;
  onMethodChange: (value: string) => void;
  onSubmit: () => void;
  onCancel: () => void;
  loading: boolean;
}

function AddRuleForm({
  title,
  hostname,
  urlPrefix,
  method,
  onHostnameChange,
  onUrlPrefixChange,
  onMethodChange,
  onSubmit,
  onCancel,
  loading,
}: AddRuleFormProps) {
  return (
    <div className="settings-add-form">
      <div className="settings-add-form-title">{title}</div>
      <div className="settings-form-row">
        <Input
          label="Hostname"
          value={hostname}
          onChange={(e) => onHostnameChange(e.target.value)}
          placeholder="example.com or *.example.com"
        />
        <Input
          label="URL Prefix"
          value={urlPrefix}
          onChange={(e) => onUrlPrefixChange(e.target.value)}
          placeholder="/api/"
        />
        <Input
          label="Method"
          value={method}
          onChange={(e) => onMethodChange(e.target.value)}
          placeholder="GET, POST, etc."
        />
      </div>
      <div className="settings-add-form-actions">
        <Button variant="secondary" size="sm" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="primary" size="sm" onClick={onSubmit} disabled={loading}>
          Add
        </Button>
      </div>
    </div>
  );
}
