import { useCallback, useEffect, useState } from "react";
import type { HookConfig, HooksInput, MacrosEntry } from "../../lib/mcp/types.js";
import { Button } from "../ui/Button.js";
import { Input } from "../ui/Input.js";
import "./HookConfigEditor.css";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Run interval options for pre_send hooks. */
const PRE_SEND_INTERVALS = [
  { value: "always", label: "Always" },
  { value: "once", label: "Once" },
  { value: "every_n", label: "Every N requests" },
  { value: "on_error", label: "On error" },
] as const;

/** Run interval options for post_receive hooks. */
const POST_RECEIVE_INTERVALS = [
  { value: "always", label: "Always" },
  { value: "on_status", label: "On status code" },
  { value: "on_match", label: "On pattern match" },
] as const;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HookConfigEditorProps {
  /** Available macros for selection. */
  macros: MacrosEntry[];
  /** Current hooks configuration. */
  hooks: HooksInput;
  /** Callback when hooks configuration changes. */
  onChange: (hooks: HooksInput) => void;
}

/** Internal form state for a single hook's key-value vars. */
interface VarEntry {
  key: string;
  id: string;
  value: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createVarEntry(): VarEntry {
  return { key: "", id: crypto.randomUUID(), value: "" };
}

function varsToEntries(vars?: Record<string, string>): VarEntry[] {
  if (!vars || Object.keys(vars).length === 0) return [];
  return Object.entries(vars).map(([key, value]) => ({
    key,
    id: crypto.randomUUID(),
    value,
  }));
}

function entriesToVars(entries: VarEntry[]): Record<string, string> | undefined {
  const filtered = entries.filter((e) => e.key.trim() !== "");
  if (filtered.length === 0) return undefined;
  const result: Record<string, string> = {};
  for (const entry of filtered) {
    result[entry.key.trim()] = entry.value;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function HookConfigEditor({ macros, hooks, onChange }: HookConfigEditorProps) {
  // Track expanded state for detail sections.
  const [preSendExpanded, setPreSendExpanded] = useState(false);
  const [postReceiveExpanded, setPostReceiveExpanded] = useState(false);

  // Track vars as form state (key-value entries).
  const [preSendVars, setPreSendVars] = useState<VarEntry[]>(
    varsToEntries(hooks.pre_send?.vars),
  );
  const [postReceiveVars, setPostReceiveVars] = useState<VarEntry[]>(
    varsToEntries(hooks.post_receive?.vars),
  );

  // Sync internal vars state when the hooks prop changes externally
  // (e.g. when ResendPage resets hooks to {} on flow change).
  useEffect(() => {
    setPreSendVars(varsToEntries(hooks.pre_send?.vars));
    setPostReceiveVars(varsToEntries(hooks.post_receive?.vars));
  }, [hooks.pre_send?.vars, hooks.post_receive?.vars]);

  // --- Pre-send handlers ---

  const handlePreSendMacroChange = useCallback(
    (macroName: string) => {
      if (!macroName) {
        setPreSendExpanded(false);
        setPreSendVars([]);
        onChange({ ...hooks, pre_send: undefined });
      } else {
        const updated: HookConfig = {
          ...(hooks.pre_send ?? { macro: "" }),
          macro: macroName,
        };
        onChange({ ...hooks, pre_send: updated });
      }
    },
    [hooks, onChange],
  );

  const handlePreSendIntervalChange = useCallback(
    (interval: string) => {
      if (!hooks.pre_send) return;
      const updated: HookConfig = { ...hooks.pre_send, run_interval: interval };
      // Clear fields not relevant to the new interval.
      if (interval !== "every_n") {
        delete updated.n;
      }
      onChange({ ...hooks, pre_send: updated });
    },
    [hooks, onChange],
  );

  const handlePreSendNChange = useCallback(
    (n: string) => {
      if (!hooks.pre_send) return;
      const parsed = parseInt(n, 10);
      onChange({
        ...hooks,
        pre_send: { ...hooks.pre_send, n: isNaN(parsed) ? undefined : parsed },
      });
    },
    [hooks, onChange],
  );

  const handlePreSendVarsChange = useCallback(
    (entries: VarEntry[]) => {
      setPreSendVars(entries);
      if (!hooks.pre_send) return;
      onChange({
        ...hooks,
        pre_send: { ...hooks.pre_send, vars: entriesToVars(entries) },
      });
    },
    [hooks, onChange],
  );

  // --- Post-receive handlers ---

  const handlePostReceiveMacroChange = useCallback(
    (macroName: string) => {
      if (!macroName) {
        setPostReceiveExpanded(false);
        setPostReceiveVars([]);
        onChange({ ...hooks, post_receive: undefined });
      } else {
        const updated: HookConfig = {
          ...(hooks.post_receive ?? { macro: "" }),
          macro: macroName,
        };
        onChange({ ...hooks, post_receive: updated });
      }
    },
    [hooks, onChange],
  );

  const handlePostReceiveIntervalChange = useCallback(
    (interval: string) => {
      if (!hooks.post_receive) return;
      const updated: HookConfig = { ...hooks.post_receive, run_interval: interval };
      // Clear fields not relevant to the new interval.
      if (interval !== "on_status") {
        delete updated.status_codes;
      }
      if (interval !== "on_match") {
        delete updated.match_pattern;
      }
      onChange({ ...hooks, post_receive: updated });
    },
    [hooks, onChange],
  );

  const handlePostReceiveStatusCodesChange = useCallback(
    (value: string) => {
      if (!hooks.post_receive) return;
      const codes = value
        .split(",")
        .map((s) => parseInt(s.trim(), 10))
        .filter((n) => !isNaN(n));
      onChange({
        ...hooks,
        post_receive: {
          ...hooks.post_receive,
          status_codes: codes.length > 0 ? codes : undefined,
        },
      });
    },
    [hooks, onChange],
  );

  const handlePostReceiveMatchPatternChange = useCallback(
    (pattern: string) => {
      if (!hooks.post_receive) return;
      onChange({
        ...hooks,
        post_receive: {
          ...hooks.post_receive,
          match_pattern: pattern || undefined,
        },
      });
    },
    [hooks, onChange],
  );

  const handlePostReceivePassResponseChange = useCallback(
    (checked: boolean) => {
      if (!hooks.post_receive) return;
      onChange({
        ...hooks,
        post_receive: {
          ...hooks.post_receive,
          pass_response: checked || undefined,
        },
      });
    },
    [hooks, onChange],
  );

  const handlePostReceiveVarsChange = useCallback(
    (entries: VarEntry[]) => {
      setPostReceiveVars(entries);
      if (!hooks.post_receive) return;
      onChange({
        ...hooks,
        post_receive: { ...hooks.post_receive, vars: entriesToVars(entries) },
      });
    },
    [hooks, onChange],
  );

  return (
    <div className="hook-config-editor">
      {/* Pre-send hook */}
      <div className="hook-config-section">
        <div className="hook-config-header">
          <label className="hook-config-label">Pre-send Macro</label>
          {hooks.pre_send?.macro && (
            <button
              type="button"
              className="hook-config-toggle"
              onClick={() => setPreSendExpanded((v) => !v)}
            >
              {preSendExpanded ? "Hide details" : "Show details"}
            </button>
          )}
        </div>
        <select
          className="hook-config-select"
          value={hooks.pre_send?.macro ?? ""}
          onChange={(e) => handlePreSendMacroChange(e.target.value)}
        >
          <option value="">None</option>
          {macros.map((m) => (
            <option key={m.name} value={m.name}>
              {m.name}
            </option>
          ))}
        </select>

        {hooks.pre_send?.macro && preSendExpanded && (
          <div className="hook-config-details">
            <div className="hook-config-detail-row">
              <label className="hook-config-detail-label">Run Interval</label>
              <select
                className="hook-config-select"
                value={hooks.pre_send.run_interval ?? "always"}
                onChange={(e) => handlePreSendIntervalChange(e.target.value)}
              >
                {PRE_SEND_INTERVALS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {hooks.pre_send.run_interval === "every_n" && (
              <div className="hook-config-detail-row">
                <label className="hook-config-detail-label">N (every N requests)</label>
                <Input
                  type="number"
                  value={hooks.pre_send.n?.toString() ?? ""}
                  onChange={(e) => handlePreSendNChange(e.target.value)}
                  placeholder="e.g. 5"
                />
              </div>
            )}

            <VarsEditor
              entries={preSendVars}
              onChange={handlePreSendVarsChange}
            />
          </div>
        )}
      </div>

      {/* Post-receive hook */}
      <div className="hook-config-section">
        <div className="hook-config-header">
          <label className="hook-config-label">Post-receive Macro</label>
          {hooks.post_receive?.macro && (
            <button
              type="button"
              className="hook-config-toggle"
              onClick={() => setPostReceiveExpanded((v) => !v)}
            >
              {postReceiveExpanded ? "Hide details" : "Show details"}
            </button>
          )}
        </div>
        <select
          className="hook-config-select"
          value={hooks.post_receive?.macro ?? ""}
          onChange={(e) => handlePostReceiveMacroChange(e.target.value)}
        >
          <option value="">None</option>
          {macros.map((m) => (
            <option key={m.name} value={m.name}>
              {m.name}
            </option>
          ))}
        </select>

        {hooks.post_receive?.macro && postReceiveExpanded && (
          <div className="hook-config-details">
            <div className="hook-config-detail-row">
              <label className="hook-config-detail-label">Run Interval</label>
              <select
                className="hook-config-select"
                value={hooks.post_receive.run_interval ?? "always"}
                onChange={(e) => handlePostReceiveIntervalChange(e.target.value)}
              >
                {POST_RECEIVE_INTERVALS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>

            {hooks.post_receive.run_interval === "on_status" && (
              <div className="hook-config-detail-row">
                <label className="hook-config-detail-label">
                  Status Codes (comma-separated)
                </label>
                <Input
                  value={hooks.post_receive.status_codes?.join(", ") ?? ""}
                  onChange={(e) => handlePostReceiveStatusCodesChange(e.target.value)}
                  placeholder="e.g. 401, 403, 500"
                />
              </div>
            )}

            {hooks.post_receive.run_interval === "on_match" && (
              <div className="hook-config-detail-row">
                <label className="hook-config-detail-label">
                  Match Pattern (regex)
                </label>
                <Input
                  value={hooks.post_receive.match_pattern ?? ""}
                  onChange={(e) => handlePostReceiveMatchPatternChange(e.target.value)}
                  placeholder="e.g. error|fail"
                />
              </div>
            )}

            <div className="hook-config-detail-row">
              <label className="hook-config-checkbox-label">
                <input
                  type="checkbox"
                  checked={hooks.post_receive.pass_response ?? false}
                  onChange={(e) => handlePostReceivePassResponseChange(e.target.checked)}
                />
                <span>Pass response to macro</span>
              </label>
            </div>

            <VarsEditor
              entries={postReceiveVars}
              onChange={handlePostReceiveVarsChange}
            />
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// VarsEditor — key-value editor for runtime variable overrides
// ---------------------------------------------------------------------------

interface VarsEditorProps {
  entries: VarEntry[];
  onChange: (entries: VarEntry[]) => void;
}

function VarsEditor({ entries, onChange }: VarsEditorProps) {
  const handleAdd = useCallback(() => {
    onChange([...entries, createVarEntry()]);
  }, [entries, onChange]);

  const handleRemove = useCallback(
    (id: string) => {
      onChange(entries.filter((e) => e.id !== id));
    },
    [entries, onChange],
  );

  const handleUpdate = useCallback(
    (id: string, field: "key" | "value", val: string) => {
      onChange(
        entries.map((e) => (e.id === id ? { ...e, [field]: val } : e)),
      );
    },
    [entries, onChange],
  );

  return (
    <div className="hook-vars-editor">
      <div className="hook-vars-header">
        <label className="hook-config-detail-label">Variables</label>
        <Button variant="ghost" size="sm" onClick={handleAdd}>
          Add
        </Button>
      </div>
      {entries.map((entry) => (
        <div key={entry.id} className="hook-var-row">
          <Input
            placeholder="key"
            value={entry.key}
            onChange={(e) => handleUpdate(entry.id, "key", e.target.value)}
          />
          <Input
            placeholder="value"
            value={entry.value}
            onChange={(e) => handleUpdate(entry.id, "value", e.target.value)}
          />
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleRemove(entry.id)}
          >
            X
          </Button>
        </div>
      ))}
    </div>
  );
}
