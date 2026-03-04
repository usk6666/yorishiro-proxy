import { useState, useCallback } from "react";
import { useSecurity } from "../../lib/mcp/hooks.js";
import { Button, useToast } from "../../components/ui/index.js";
import type {
  AgentLayerResult,
  TargetRule,
  SecuritySetScopeResult,
} from "../../lib/mcp/types.js";
import { RuleTable } from "./RuleTable.js";
import { AddRuleForm } from "./AddRuleForm.js";

interface AgentLayerProps {
  agent: AgentLayerResult;
  onRefresh: () => void;
  actionLoading: boolean;
}

/**
 * AgentLayer -- editable Agent Layer target scope rules.
 * Supports adding/removing individual rules via update_target_scope.
 */
export function AgentLayer({ agent, onRefresh, actionLoading }: AgentLayerProps) {
  const { addToast } = useToast();
  const { security } = useSecurity();

  const [showAddAllow, setShowAddAllow] = useState(false);
  const [showAddDeny, setShowAddDeny] = useState(false);

  const handleAddRule = useCallback(
    async (type: "allow" | "deny", rule: TargetRule) => {
      try {
        if (type === "allow") {
          await security<SecuritySetScopeResult>({
            action: "update_target_scope",
            params: { add_allows: [rule] },
          });
        } else {
          await security<SecuritySetScopeResult>({
            action: "update_target_scope",
            params: { add_denies: [rule] },
          });
        }
        addToast({ type: "success", message: `${type} rule added` });
        setShowAddAllow(false);
        setShowAddDeny(false);
        onRefresh();
      } catch (err) {
        addToast({
          type: "error",
          message: `Failed to add rule: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    },
    [security, addToast, onRefresh],
  );

  const handleRemoveRule = useCallback(
    async (type: "allow" | "deny", rule: TargetRule) => {
      try {
        if (type === "allow") {
          await security<SecuritySetScopeResult>({
            action: "update_target_scope",
            params: { remove_allows: [rule] },
          });
        } else {
          await security<SecuritySetScopeResult>({
            action: "update_target_scope",
            params: { remove_denies: [rule] },
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
    },
    [security, addToast, onRefresh],
  );

  return (
    <div className="security-section">
      <div className="security-section-header">
        <h2 className="security-section-title">Agent Layer</h2>
      </div>
      <p className="security-section-desc">
        Dynamic rules managed via MCP security tool. Editable from this page.
      </p>

      {/* Allow rules */}
      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Allow Rules</span>
          <Button
            variant="primary"
            size="sm"
            onClick={() => {
              setShowAddAllow(!showAddAllow);
              setShowAddDeny(false);
            }}
          >
            Add
          </Button>
        </div>
        <div className="security-card-body">
          {agent.allows.length > 0 ? (
            <RuleTable
              rules={agent.allows}
              onRemove={(rule) => handleRemoveRule("allow", rule)}
              loading={actionLoading}
            />
          ) : (
            <div className="security-empty">No allow rules</div>
          )}
        </div>
      </div>

      {showAddAllow && (
        <AddRuleForm
          title="Add Allow Rule"
          onSubmit={(rule) => handleAddRule("allow", rule)}
          onCancel={() => setShowAddAllow(false)}
          loading={actionLoading}
        />
      )}

      {/* Deny rules */}
      <div className="security-card">
        <div className="security-card-header">
          <span className="security-card-title">Deny Rules</span>
          <Button
            variant="primary"
            size="sm"
            onClick={() => {
              setShowAddDeny(!showAddDeny);
              setShowAddAllow(false);
            }}
          >
            Add
          </Button>
        </div>
        <div className="security-card-body">
          {agent.denies.length > 0 ? (
            <RuleTable
              rules={agent.denies}
              onRemove={(rule) => handleRemoveRule("deny", rule)}
              loading={actionLoading}
            />
          ) : (
            <div className="security-empty">No deny rules</div>
          )}
        </div>
      </div>

      {showAddDeny && (
        <AddRuleForm
          title="Add Deny Rule"
          onSubmit={(rule) => handleAddRule("deny", rule)}
          onCancel={() => setShowAddDeny(false)}
          loading={actionLoading}
        />
      )}
    </div>
  );
}
