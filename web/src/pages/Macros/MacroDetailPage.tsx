import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Input } from "../../components/ui/Input.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Table } from "../../components/ui/Table.js";
import { Tabs } from "../../components/ui/Tabs.js";
import { useToast } from "../../components/ui/Toast.js";
import { useMacro, useQuery } from "../../lib/mcp/hooks.js";
import type {
  ExtractionRule,
  GuardCondition,
  MacroDefineResult,
  MacroRunResult,
  MacroStep,
  MacroStepResult,
} from "../../lib/mcp/types.js";
import "./MacroDetailPage.css";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const TABS = [
  { id: "editor", label: "Editor" },
  { id: "run", label: "Run & Results" },
];

const ON_ERROR_OPTIONS = [
  { value: "abort", label: "Abort" },
  { value: "skip", label: "Skip" },
  { value: "retry", label: "Retry" },
];

const EXTRACTION_FROM_OPTIONS = [
  { value: "request", label: "Request" },
  { value: "response", label: "Response" },
];

const EXTRACTION_SOURCE_OPTIONS = [
  { value: "header", label: "Header" },
  { value: "body", label: "Body (regex)" },
  { value: "body_json", label: "Body (JSON Path)" },
  { value: "status", label: "Status Code" },
  { value: "url", label: "URL" },
];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Form representation of a key-value pair. */
interface KVEntry {
  key: string;
  id: string;
  value: string;
}

/** Form representation of a step. */
interface StepFormEntry {
  key: string;
  id: string;
  flowId: string;
  overrideMethod: string;
  overrideUrl: string;
  overrideHeaders: KVEntry[];
  overrideBody: string;
  onError: string;
  retryCount: string;
  retryDelayMs: string;
  timeoutMs: string;
  extract: ExtractionFormEntry[];
  guardEnabled: boolean;
  guard: GuardFormEntry;
}

/** Form representation of an extraction rule. */
interface ExtractionFormEntry {
  key: string;
  name: string;
  from: string;
  source: string;
  headerName: string;
  regex: string;
  group: string;
  jsonPath: string;
  defaultValue: string;
  required: boolean;
}

/** Form representation of a guard condition. */
interface GuardFormEntry {
  step: string;
  statusCode: string;
  statusCodeRangeMin: string;
  statusCodeRangeMax: string;
  headerMatchEntries: KVEntry[];
  bodyMatch: string;
  extractedVar: string;
  negate: boolean;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function uid(): string {
  return crypto.randomUUID();
}

function createEmptyKV(): KVEntry {
  return { key: "", id: uid(), value: "" };
}

function createEmptyExtraction(): ExtractionFormEntry {
  return {
    key: uid(),
    name: "",
    from: "response",
    source: "body",
    headerName: "",
    regex: "",
    group: "0",
    jsonPath: "",
    defaultValue: "",
    required: false,
  };
}

function createEmptyGuard(): GuardFormEntry {
  return {
    step: "",
    statusCode: "",
    statusCodeRangeMin: "",
    statusCodeRangeMax: "",
    headerMatchEntries: [],
    bodyMatch: "",
    extractedVar: "",
    negate: false,
  };
}

function createEmptyStep(): StepFormEntry {
  return {
    key: uid(),
    id: "",
    flowId: "",
    overrideMethod: "",
    overrideUrl: "",
    overrideHeaders: [],
    overrideBody: "",
    onError: "abort",
    retryCount: "3",
    retryDelayMs: "1000",
    timeoutMs: "",
    extract: [],
    guardEnabled: false,
    guard: createEmptyGuard(),
  };
}

function stepFromData(step: MacroStep): StepFormEntry {
  return {
    key: uid(),
    id: step.id,
    flowId: step.flow_id,
    overrideMethod: step.override_method ?? "",
    overrideUrl: step.override_url ?? "",
    overrideHeaders: step.override_headers
      ? Object.entries(step.override_headers).map(([k, v]) => ({
        key: k,
        id: uid(),
        value: v,
      }))
      : [],
    overrideBody: step.override_body ?? "",
    onError: step.on_error ?? "abort",
    retryCount: String(step.retry_count ?? 3),
    retryDelayMs: String(step.retry_delay_ms ?? 1000),
    timeoutMs: step.timeout_ms ? String(step.timeout_ms) : "",
    extract: (step.extract ?? []).map((e) => ({
      key: uid(),
      name: e.name,
      from: e.from,
      source: e.source,
      headerName: e.header_name ?? "",
      regex: e.regex ?? "",
      group: String(e.group ?? 0),
      jsonPath: e.json_path ?? "",
      defaultValue: e.default ?? "",
      required: e.required ?? false,
    })),
    guardEnabled: step.when != null,
    guard: step.when
      ? {
        step: step.when.step ?? "",
        statusCode:
          step.when.status_code != null ? String(step.when.status_code) : "",
        statusCodeRangeMin:
          step.when.status_code_range
            ? String(step.when.status_code_range[0])
            : "",
        statusCodeRangeMax:
          step.when.status_code_range
            ? String(step.when.status_code_range[1])
            : "",
        headerMatchEntries: step.when.header_match
          ? Object.entries(step.when.header_match).map(([k, v]) => ({
            key: k,
            id: uid(),
            value: v,
          }))
          : [],
        bodyMatch: step.when.body_match ?? "",
        extractedVar: step.when.extracted_var ?? "",
        negate: step.when.negate ?? false,
      }
      : createEmptyGuard(),
  };
}

function buildStepForApi(step: StepFormEntry): MacroStep {
  const s: MacroStep = {
    id: step.id,
    flow_id: step.flowId,
  };

  if (step.overrideMethod.trim()) s.override_method = step.overrideMethod.trim();
  if (step.overrideUrl.trim()) s.override_url = step.overrideUrl.trim();

  const headers: Record<string, string> = {};
  for (const h of step.overrideHeaders) {
    if (h.key.trim()) headers[h.key.trim()] = h.value;
  }
  if (Object.keys(headers).length > 0) s.override_headers = headers;

  if (step.overrideBody.trim()) s.override_body = step.overrideBody.trim();

  if (step.onError) s.on_error = step.onError;
  const retryCount = parseInt(step.retryCount, 10);
  if (!isNaN(retryCount)) s.retry_count = retryCount;
  const retryDelay = parseInt(step.retryDelayMs, 10);
  if (!isNaN(retryDelay)) s.retry_delay_ms = retryDelay;
  const timeout = parseInt(step.timeoutMs, 10);
  if (!isNaN(timeout)) s.timeout_ms = timeout;

  // Extraction rules
  const extractRules: ExtractionRule[] = [];
  for (const e of step.extract) {
    if (!e.name.trim()) continue;
    const rule: ExtractionRule = {
      name: e.name.trim(),
      from: e.from,
      source: e.source,
    };
    if (e.headerName.trim()) rule.header_name = e.headerName.trim();
    if (e.regex.trim()) rule.regex = e.regex.trim();
    const group = parseInt(e.group, 10);
    if (!isNaN(group)) rule.group = group;
    if (e.jsonPath.trim()) rule.json_path = e.jsonPath.trim();
    if (e.defaultValue.trim()) rule.default = e.defaultValue.trim();
    if (e.required) rule.required = true;
    extractRules.push(rule);
  }
  if (extractRules.length > 0) s.extract = extractRules;

  // Guard
  if (step.guardEnabled) {
    const g: GuardCondition = {};
    if (step.guard.step.trim()) g.step = step.guard.step.trim();
    const statusCode = parseInt(step.guard.statusCode, 10);
    if (!isNaN(statusCode)) g.status_code = statusCode;
    const rangeMin = parseInt(step.guard.statusCodeRangeMin, 10);
    const rangeMax = parseInt(step.guard.statusCodeRangeMax, 10);
    if (!isNaN(rangeMin) && !isNaN(rangeMax)) {
      g.status_code_range = [rangeMin, rangeMax];
    }
    const headerMatch: Record<string, string> = {};
    for (const h of step.guard.headerMatchEntries) {
      if (h.key.trim()) headerMatch[h.key.trim()] = h.value;
    }
    if (Object.keys(headerMatch).length > 0) g.header_match = headerMatch;
    if (step.guard.bodyMatch.trim()) g.body_match = step.guard.bodyMatch.trim();
    if (step.guard.extractedVar.trim())
      g.extracted_var = step.guard.extractedVar.trim();
    if (step.guard.negate) g.negate = true;
    s.when = g;
  }

  return s;
}

function statusVariant(
  status: string,
): "default" | "success" | "warning" | "danger" | "info" {
  switch (status) {
    case "completed":
      return "success";
    case "skipped":
      return "warning";
    case "error":
      return "danger";
    default:
      return "default";
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function MacroDetailPage() {
  const { name: routeName } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { macro: macroAction, loading: actionLoading } = useMacro();

  const isNew = routeName === "new";
  const macroName = isNew ? "" : decodeURIComponent(routeName ?? "");

  const [activeTab, setActiveTab] = useState("editor");

  // --- Form state ---
  const [name, setName] = useState(macroName);
  const [description, setDescription] = useState("");
  const [timeoutMs, setTimeoutMs] = useState("");
  const [initialVars, setInitialVars] = useState<KVEntry[]>([]);
  const [steps, setSteps] = useState<StepFormEntry[]>([createEmptyStep()]);
  const [formLoaded, setFormLoaded] = useState(isNew);

  // --- Run result state ---
  const [runResult, setRunResult] = useState<MacroRunResult | null>(null);
  const [runVars, setRunVars] = useState<KVEntry[]>([]);

  // --- Query macro detail (for edit mode) ---
  const { data, loading, error } = useQuery("macro", {
    id: macroName,
    enabled: !isNew && !!macroName,
  });

  // Populate form from loaded data
  useEffect(() => {
    if (!data || formLoaded) return;
    setName(data.name);
    setDescription(data.description ?? "");
    setTimeoutMs(data.timeout_ms ? String(data.timeout_ms) : "");
    setInitialVars(
      data.initial_vars
        ? Object.entries(data.initial_vars).map(([k, v]) => ({
          key: k,
          id: uid(),
          value: v,
        }))
        : [],
    );
    setSteps(
      data.steps && data.steps.length > 0
        ? data.steps.map(stepFromData)
        : [createEmptyStep()],
    );
    setFormLoaded(true);
  }, [data, formLoaded]);

  // --- Initial vars management ---
  const addInitialVar = useCallback(() => {
    setInitialVars((prev) => [...prev, createEmptyKV()]);
  }, []);

  const removeInitialVar = useCallback((id: string) => {
    setInitialVars((prev) => prev.filter((v) => v.id !== id));
  }, []);

  const updateInitialVar = useCallback(
    (id: string, field: "key" | "value", val: string) => {
      setInitialVars((prev) =>
        prev.map((v) => (v.id === id ? { ...v, [field]: val } : v)),
      );
    },
    [],
  );

  // --- Step management ---
  const addStep = useCallback(() => {
    setSteps((prev) => [...prev, createEmptyStep()]);
  }, []);

  const removeStep = useCallback((key: string) => {
    setSteps((prev) => prev.filter((s) => s.key !== key));
  }, []);

  const updateStep = useCallback(
    (key: string, updates: Partial<StepFormEntry>) => {
      setSteps((prev) =>
        prev.map((s) => (s.key === key ? { ...s, ...updates } : s)),
      );
    },
    [],
  );

  const moveStep = useCallback((fromIdx: number, toIdx: number) => {
    setSteps((prev) => {
      const arr = [...prev];
      const [item] = arr.splice(fromIdx, 1);
      arr.splice(toIdx, 0, item);
      return arr;
    });
  }, []);

  // --- Run vars management ---
  const addRunVar = useCallback(() => {
    setRunVars((prev) => [...prev, createEmptyKV()]);
  }, []);

  const removeRunVar = useCallback((id: string) => {
    setRunVars((prev) => prev.filter((v) => v.id !== id));
  }, []);

  const updateRunVar = useCallback(
    (id: string, field: "key" | "value", val: string) => {
      setRunVars((prev) =>
        prev.map((v) => (v.id === id ? { ...v, [field]: val } : v)),
      );
    },
    [],
  );

  // --- Save macro ---
  const handleSave = useCallback(async () => {
    if (!name.trim()) {
      addToast({ type: "warning", message: "Macro name is required" });
      return;
    }

    const validSteps = steps.filter((s) => s.id.trim() && s.flowId.trim());
    if (validSteps.length === 0) {
      addToast({
        type: "warning",
        message: "At least one step with ID and Flow ID is required",
      });
      return;
    }

    const builtSteps = validSteps.map(buildStepForApi);

    const vars: Record<string, string> = {};
    for (const v of initialVars) {
      if (v.key.trim()) vars[v.key.trim()] = v.value;
    }

    try {
      await macroAction<MacroDefineResult>({
        action: "define_macro",
        params: {
          name: name.trim(),
          description: description.trim() || undefined,
          steps: builtSteps,
          initial_vars: Object.keys(vars).length > 0 ? vars : undefined,
          macro_timeout_ms: timeoutMs ? parseInt(timeoutMs, 10) : undefined,
        },
      });
      addToast({ type: "success", message: `Macro "${name}" saved` });

      // If creating new, navigate to the edit page
      if (isNew) {
        navigate(`/macros/${encodeURIComponent(name.trim())}`, { replace: true });
      }
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to save macro: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [name, description, timeoutMs, initialVars, steps, macroAction, addToast, isNew, navigate]);

  // --- Run macro ---
  const handleRun = useCallback(async () => {
    const macroNameToRun = name.trim();
    if (!macroNameToRun) {
      addToast({ type: "warning", message: "Save the macro first before running" });
      return;
    }

    const vars: Record<string, string> = {};
    for (const v of runVars) {
      if (v.key.trim()) vars[v.key.trim()] = v.value;
    }

    try {
      const result = await macroAction<MacroRunResult>({
        action: "run_macro",
        params: {
          name: macroNameToRun,
          vars: Object.keys(vars).length > 0 ? vars : undefined,
        },
      });
      setRunResult(result);
      addToast({
        type: result.status === "completed" ? "success" : "warning",
        message: `Macro "${macroNameToRun}" ${result.status}: ${result.steps_executed} steps executed`,
      });
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to run macro: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [name, runVars, macroAction, addToast]);

  // --- Loading state for edit mode ---
  if (!isNew && loading && !formLoaded) {
    return (
      <div className="page macro-detail-page">
        <div className="macros-loading">
          <Spinner size="lg" />
        </div>
      </div>
    );
  }

  if (!isNew && error) {
    return (
      <div className="page macro-detail-page">
        <div className="macros-error">
          Error loading macro: {error.message}
        </div>
      </div>
    );
  }

  return (
    <div className="page macro-detail-page">
      <div className="macro-detail-header">
        <Button variant="ghost" size="sm" onClick={() => navigate("/macros")}>
          &larr; Back to Macros
        </Button>
        <h1 className="page-title">
          {isNew ? "New Macro" : `Macro: ${macroName}`}
        </h1>
      </div>

      <div className="macro-detail-tabs">
        <Tabs tabs={TABS} activeTab={activeTab} onTabChange={setActiveTab}>
          {activeTab === "editor" && (
            <div className="macro-editor">
              {/* Basic info */}
              <div className="macro-section">
                <h3 className="macro-section-title">Basic Information</h3>
                <div className="macro-fields-row">
                  <div className="macro-field">
                    <label className="macro-field-label">Name</label>
                    <Input
                      placeholder="my-macro"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      disabled={!isNew}
                    />
                  </div>
                  <div className="macro-field macro-field-grow">
                    <label className="macro-field-label">Description</label>
                    <Input
                      placeholder="What this macro does..."
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                    />
                  </div>
                  <div className="macro-field">
                    <label className="macro-field-label">Timeout (ms)</label>
                    <Input
                      type="number"
                      placeholder="300000"
                      value={timeoutMs}
                      onChange={(e) => setTimeoutMs(e.target.value)}
                    />
                  </div>
                </div>
              </div>

              {/* Initial Variables */}
              <div className="macro-section">
                <div className="macro-section-header">
                  <h3 className="macro-section-title">Initial Variables</h3>
                  <Button variant="secondary" size="sm" onClick={addInitialVar}>
                    Add Variable
                  </Button>
                </div>
                {initialVars.length === 0 && (
                  <p className="macro-hint">
                    No initial variables. These pre-populate the KV Store before execution.
                  </p>
                )}
                {initialVars.map((v) => (
                  <div key={v.id} className="macro-kv-row">
                    <Input
                      placeholder="Key"
                      value={v.key}
                      onChange={(e) => updateInitialVar(v.id, "key", e.target.value)}
                    />
                    <Input
                      placeholder="Value"
                      value={v.value}
                      onChange={(e) => updateInitialVar(v.id, "value", e.target.value)}
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => removeInitialVar(v.id)}
                    >
                      Remove
                    </Button>
                  </div>
                ))}
              </div>

              {/* Steps */}
              <div className="macro-section">
                <div className="macro-section-header">
                  <h3 className="macro-section-title">Steps</h3>
                  <Button variant="secondary" size="sm" onClick={addStep}>
                    Add Step
                  </Button>
                </div>
                {steps.map((step, idx) => (
                  <StepEditor
                    key={step.key}
                    step={step}
                    index={idx}
                    totalSteps={steps.length}
                    onUpdate={(updates) => updateStep(step.key, updates)}
                    onRemove={() => removeStep(step.key)}
                    onMoveUp={() => moveStep(idx, idx - 1)}
                    onMoveDown={() => moveStep(idx, idx + 1)}
                  />
                ))}
              </div>

              {/* Save */}
              <div className="macro-actions">
                <Button
                  variant="primary"
                  onClick={handleSave}
                  disabled={actionLoading}
                >
                  {actionLoading ? "Saving..." : "Save Macro"}
                </Button>
                <Button variant="secondary" onClick={() => navigate("/macros")}>
                  Cancel
                </Button>
              </div>
            </div>
          )}

          {activeTab === "run" && (
            <div className="macro-run-panel">
              {/* Runtime variables */}
              <div className="macro-section">
                <div className="macro-section-header">
                  <h3 className="macro-section-title">Runtime Variables</h3>
                  <Button variant="secondary" size="sm" onClick={addRunVar}>
                    Add Variable
                  </Button>
                </div>
                <p className="macro-hint">
                  Override or add variables before running the macro.
                </p>
                {runVars.map((v) => (
                  <div key={v.id} className="macro-kv-row">
                    <Input
                      placeholder="Key"
                      value={v.key}
                      onChange={(e) => updateRunVar(v.id, "key", e.target.value)}
                    />
                    <Input
                      placeholder="Value"
                      value={v.value}
                      onChange={(e) => updateRunVar(v.id, "value", e.target.value)}
                    />
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => removeRunVar(v.id)}
                    >
                      Remove
                    </Button>
                  </div>
                ))}
              </div>

              {/* Run button */}
              <div className="macro-actions">
                <Button
                  variant="primary"
                  onClick={handleRun}
                  disabled={actionLoading || isNew}
                >
                  {actionLoading ? "Running..." : "Run Macro"}
                </Button>
              </div>

              {/* Run results */}
              {runResult && (
                <RunResultView result={runResult} />
              )}
            </div>
          )}
        </Tabs>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// StepEditor component
// ---------------------------------------------------------------------------

interface StepEditorProps {
  step: StepFormEntry;
  index: number;
  totalSteps: number;
  onUpdate: (updates: Partial<StepFormEntry>) => void;
  onRemove: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
}

function StepEditor({
  step,
  index,
  totalSteps,
  onUpdate,
  onRemove,
  onMoveUp,
  onMoveDown,
}: StepEditorProps) {
  const [expanded, setExpanded] = useState(true);

  // --- Override headers management ---
  const addOverrideHeader = useCallback(() => {
    onUpdate({
      overrideHeaders: [...step.overrideHeaders, createEmptyKV()],
    });
  }, [step.overrideHeaders, onUpdate]);

  const removeOverrideHeader = useCallback(
    (id: string) => {
      onUpdate({
        overrideHeaders: step.overrideHeaders.filter((h) => h.id !== id),
      });
    },
    [step.overrideHeaders, onUpdate],
  );

  const updateOverrideHeader = useCallback(
    (id: string, field: "key" | "value", val: string) => {
      onUpdate({
        overrideHeaders: step.overrideHeaders.map((h) =>
          h.id === id ? { ...h, [field]: val } : h,
        ),
      });
    },
    [step.overrideHeaders, onUpdate],
  );

  // --- Extraction rules management ---
  const addExtraction = useCallback(() => {
    onUpdate({
      extract: [...step.extract, createEmptyExtraction()],
    });
  }, [step.extract, onUpdate]);

  const removeExtraction = useCallback(
    (key: string) => {
      onUpdate({
        extract: step.extract.filter((e) => e.key !== key),
      });
    },
    [step.extract, onUpdate],
  );

  const updateExtraction = useCallback(
    (key: string, updates: Partial<ExtractionFormEntry>) => {
      onUpdate({
        extract: step.extract.map((e) =>
          e.key === key ? { ...e, ...updates } : e,
        ),
      });
    },
    [step.extract, onUpdate],
  );

  // --- Guard header match management ---
  const addGuardHeaderMatch = useCallback(() => {
    onUpdate({
      guard: {
        ...step.guard,
        headerMatchEntries: [...step.guard.headerMatchEntries, createEmptyKV()],
      },
    });
  }, [step.guard, onUpdate]);

  const removeGuardHeaderMatch = useCallback(
    (id: string) => {
      onUpdate({
        guard: {
          ...step.guard,
          headerMatchEntries: step.guard.headerMatchEntries.filter(
            (h) => h.id !== id,
          ),
        },
      });
    },
    [step.guard, onUpdate],
  );

  const updateGuardHeaderMatch = useCallback(
    (id: string, field: "key" | "value", val: string) => {
      onUpdate({
        guard: {
          ...step.guard,
          headerMatchEntries: step.guard.headerMatchEntries.map((h) =>
            h.id === id ? { ...h, [field]: val } : h,
          ),
        },
      });
    },
    [step.guard, onUpdate],
  );

  return (
    <div className="macro-step-entry">
      <div className="macro-step-header">
        <div className="macro-step-header-left">
          <div className="macro-step-reorder">
            <Button
              variant="ghost"
              size="sm"
              disabled={index === 0}
              onClick={onMoveUp}
              title="Move up"
            >
              &uarr;
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={index === totalSteps - 1}
              onClick={onMoveDown}
              title="Move down"
            >
              &darr;
            </Button>
          </div>
          <span className="macro-step-index">Step #{index + 1}</span>
          {step.id && (
            <span className="macro-step-id-label">{step.id}</span>
          )}
        </div>
        <div className="macro-step-header-right">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? "Collapse" : "Expand"}
          </Button>
          {totalSteps > 1 && (
            <Button variant="ghost" size="sm" onClick={onRemove}>
              Remove
            </Button>
          )}
        </div>
      </div>

      {expanded && (
        <div className="macro-step-body">
          {/* Basic step info */}
          <div className="macro-fields-row">
            <div className="macro-field">
              <label className="macro-field-label">Step ID</label>
              <Input
                placeholder="step-1"
                value={step.id}
                onChange={(e) => onUpdate({ id: e.target.value })}
              />
            </div>
            <div className="macro-field">
              <label className="macro-field-label">Flow ID</label>
              <Input
                placeholder="Flow ID to use as template"
                value={step.flowId}
                onChange={(e) => onUpdate({ flowId: e.target.value })}
              />
            </div>
          </div>

          {/* Overrides */}
          <div className="macro-substep-section">
            <h4 className="macro-substep-title">Overrides</h4>
            <div className="macro-fields-row">
              <div className="macro-field">
                <label className="macro-field-label">Method</label>
                <Input
                  placeholder="Original"
                  value={step.overrideMethod}
                  onChange={(e) =>
                    onUpdate({ overrideMethod: e.target.value })
                  }
                />
              </div>
              <div className="macro-field macro-field-grow">
                <label className="macro-field-label">URL</label>
                <Input
                  placeholder="Original"
                  value={step.overrideUrl}
                  onChange={(e) => onUpdate({ overrideUrl: e.target.value })}
                />
              </div>
            </div>
            <div className="macro-substep-section">
              <div className="macro-subsection-header">
                <span className="macro-field-label">Override Headers</span>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={addOverrideHeader}
                >
                  Add
                </Button>
              </div>
              {step.overrideHeaders.map((h) => (
                <div key={h.id} className="macro-kv-row">
                  <Input
                    placeholder="Header name"
                    value={h.key}
                    onChange={(e) =>
                      updateOverrideHeader(h.id, "key", e.target.value)
                    }
                  />
                  <Input
                    placeholder="Value"
                    value={h.value}
                    onChange={(e) =>
                      updateOverrideHeader(h.id, "value", e.target.value)
                    }
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => removeOverrideHeader(h.id)}
                  >
                    Remove
                  </Button>
                </div>
              ))}
            </div>
            <div className="macro-field">
              <label className="macro-field-label">Override Body</label>
              <textarea
                className="macro-textarea"
                placeholder="Leave empty to use original body. Supports {{variable}} templates."
                value={step.overrideBody}
                onChange={(e) => onUpdate({ overrideBody: e.target.value })}
                rows={3}
                spellCheck={false}
              />
            </div>
          </div>

          {/* Error handling */}
          <div className="macro-substep-section">
            <h4 className="macro-substep-title">Error Handling</h4>
            <div className="macro-fields-row">
              <div className="macro-field">
                <label className="macro-field-label">On Error</label>
                <select
                  className="macro-select"
                  value={step.onError}
                  onChange={(e) => onUpdate({ onError: e.target.value })}
                >
                  {ON_ERROR_OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </div>
              {step.onError === "retry" && (
                <>
                  <div className="macro-field">
                    <label className="macro-field-label">Retry Count</label>
                    <Input
                      type="number"
                      value={step.retryCount}
                      onChange={(e) =>
                        onUpdate({ retryCount: e.target.value })
                      }
                    />
                  </div>
                  <div className="macro-field">
                    <label className="macro-field-label">Retry Delay (ms)</label>
                    <Input
                      type="number"
                      value={step.retryDelayMs}
                      onChange={(e) =>
                        onUpdate({ retryDelayMs: e.target.value })
                      }
                    />
                  </div>
                </>
              )}
              <div className="macro-field">
                <label className="macro-field-label">Step Timeout (ms)</label>
                <Input
                  type="number"
                  placeholder="60000"
                  value={step.timeoutMs}
                  onChange={(e) => onUpdate({ timeoutMs: e.target.value })}
                />
              </div>
            </div>
          </div>

          {/* Extraction rules */}
          <div className="macro-substep-section">
            <div className="macro-subsection-header">
              <h4 className="macro-substep-title">Extraction Rules</h4>
              <Button variant="ghost" size="sm" onClick={addExtraction}>
                Add Rule
              </Button>
            </div>
            {step.extract.length === 0 && (
              <p className="macro-hint">
                No extraction rules. Add rules to extract values into the KV Store.
              </p>
            )}
            {step.extract.map((ext) => (
              <div key={ext.key} className="macro-extraction-entry">
                <div className="macro-fields-row">
                  <div className="macro-field">
                    <label className="macro-field-label">Variable Name</label>
                    <Input
                      placeholder="token"
                      value={ext.name}
                      onChange={(e) =>
                        updateExtraction(ext.key, { name: e.target.value })
                      }
                    />
                  </div>
                  <div className="macro-field">
                    <label className="macro-field-label">From</label>
                    <select
                      className="macro-select"
                      value={ext.from}
                      onChange={(e) =>
                        updateExtraction(ext.key, { from: e.target.value })
                      }
                    >
                      {EXTRACTION_FROM_OPTIONS.map((o) => (
                        <option key={o.value} value={o.value}>
                          {o.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="macro-field">
                    <label className="macro-field-label">Source</label>
                    <select
                      className="macro-select"
                      value={ext.source}
                      onChange={(e) =>
                        updateExtraction(ext.key, { source: e.target.value })
                      }
                    >
                      {EXTRACTION_SOURCE_OPTIONS.map((o) => (
                        <option key={o.value} value={o.value}>
                          {o.label}
                        </option>
                      ))}
                    </select>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => removeExtraction(ext.key)}
                  >
                    Remove
                  </Button>
                </div>
                <div className="macro-fields-row">
                  {ext.source === "header" && (
                    <div className="macro-field">
                      <label className="macro-field-label">Header Name</label>
                      <Input
                        placeholder="Authorization"
                        value={ext.headerName}
                        onChange={(e) =>
                          updateExtraction(ext.key, {
                            headerName: e.target.value,
                          })
                        }
                      />
                    </div>
                  )}
                  {(ext.source === "body" ||
                    ext.source === "header" ||
                    ext.source === "url") && (
                      <>
                        <div className="macro-field">
                          <label className="macro-field-label">Regex</label>
                          <Input
                            placeholder="token=(\\w+)"
                            value={ext.regex}
                            onChange={(e) =>
                              updateExtraction(ext.key, {
                                regex: e.target.value,
                              })
                            }
                          />
                        </div>
                        <div className="macro-field">
                          <label className="macro-field-label">Group</label>
                          <Input
                            type="number"
                            value={ext.group}
                            onChange={(e) =>
                              updateExtraction(ext.key, {
                                group: e.target.value,
                              })
                            }
                          />
                        </div>
                      </>
                    )}
                  {ext.source === "body_json" && (
                    <div className="macro-field macro-field-grow">
                      <label className="macro-field-label">JSON Path</label>
                      <Input
                        placeholder="$.data.token"
                        value={ext.jsonPath}
                        onChange={(e) =>
                          updateExtraction(ext.key, {
                            jsonPath: e.target.value,
                          })
                        }
                      />
                    </div>
                  )}
                  <div className="macro-field">
                    <label className="macro-field-label">Default</label>
                    <Input
                      placeholder="Fallback"
                      value={ext.defaultValue}
                      onChange={(e) =>
                        updateExtraction(ext.key, {
                          defaultValue: e.target.value,
                        })
                      }
                    />
                  </div>
                  <div className="macro-field macro-field-checkbox">
                    <label className="macro-checkbox-label">
                      <input
                        type="checkbox"
                        checked={ext.required}
                        onChange={(e) =>
                          updateExtraction(ext.key, {
                            required: e.target.checked,
                          })
                        }
                      />
                      Required
                    </label>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Guard */}
          <div className="macro-substep-section">
            <div className="macro-subsection-header">
              <h4 className="macro-substep-title">Guard Condition</h4>
              <label className="macro-checkbox-label">
                <input
                  type="checkbox"
                  checked={step.guardEnabled}
                  onChange={(e) =>
                    onUpdate({ guardEnabled: e.target.checked })
                  }
                />
                Enabled
              </label>
            </div>
            {step.guardEnabled && (
              <div className="macro-guard-body">
                <div className="macro-fields-row">
                  <div className="macro-field">
                    <label className="macro-field-label">Reference Step</label>
                    <Input
                      placeholder="step-1"
                      value={step.guard.step}
                      onChange={(e) =>
                        onUpdate({
                          guard: { ...step.guard, step: e.target.value },
                        })
                      }
                    />
                  </div>
                  <div className="macro-field">
                    <label className="macro-field-label">Status Code</label>
                    <Input
                      type="number"
                      placeholder="200"
                      value={step.guard.statusCode}
                      onChange={(e) =>
                        onUpdate({
                          guard: {
                            ...step.guard,
                            statusCode: e.target.value,
                          },
                        })
                      }
                    />
                  </div>
                  <div className="macro-field">
                    <label className="macro-field-label">
                      Status Range Min
                    </label>
                    <Input
                      type="number"
                      placeholder="200"
                      value={step.guard.statusCodeRangeMin}
                      onChange={(e) =>
                        onUpdate({
                          guard: {
                            ...step.guard,
                            statusCodeRangeMin: e.target.value,
                          },
                        })
                      }
                    />
                  </div>
                  <div className="macro-field">
                    <label className="macro-field-label">
                      Status Range Max
                    </label>
                    <Input
                      type="number"
                      placeholder="299"
                      value={step.guard.statusCodeRangeMax}
                      onChange={(e) =>
                        onUpdate({
                          guard: {
                            ...step.guard,
                            statusCodeRangeMax: e.target.value,
                          },
                        })
                      }
                    />
                  </div>
                </div>
                <div className="macro-fields-row">
                  <div className="macro-field macro-field-grow">
                    <label className="macro-field-label">Body Match (regex)</label>
                    <Input
                      placeholder="success"
                      value={step.guard.bodyMatch}
                      onChange={(e) =>
                        onUpdate({
                          guard: {
                            ...step.guard,
                            bodyMatch: e.target.value,
                          },
                        })
                      }
                    />
                  </div>
                  <div className="macro-field">
                    <label className="macro-field-label">Extracted Var</label>
                    <Input
                      placeholder="token"
                      value={step.guard.extractedVar}
                      onChange={(e) =>
                        onUpdate({
                          guard: {
                            ...step.guard,
                            extractedVar: e.target.value,
                          },
                        })
                      }
                    />
                  </div>
                  <div className="macro-field macro-field-checkbox">
                    <label className="macro-checkbox-label">
                      <input
                        type="checkbox"
                        checked={step.guard.negate}
                        onChange={(e) =>
                          onUpdate({
                            guard: {
                              ...step.guard,
                              negate: e.target.checked,
                            },
                          })
                        }
                      />
                      Negate
                    </label>
                  </div>
                </div>
                {/* Guard header match */}
                <div className="macro-substep-section">
                  <div className="macro-subsection-header">
                    <span className="macro-field-label">Header Match</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={addGuardHeaderMatch}
                    >
                      Add
                    </Button>
                  </div>
                  {step.guard.headerMatchEntries.map((h) => (
                    <div key={h.id} className="macro-kv-row">
                      <Input
                        placeholder="Header name"
                        value={h.key}
                        onChange={(e) =>
                          updateGuardHeaderMatch(h.id, "key", e.target.value)
                        }
                      />
                      <Input
                        placeholder="Regex pattern"
                        value={h.value}
                        onChange={(e) =>
                          updateGuardHeaderMatch(h.id, "value", e.target.value)
                        }
                      />
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => removeGuardHeaderMatch(h.id)}
                      >
                        Remove
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// RunResultView component
// ---------------------------------------------------------------------------

interface RunResultViewProps {
  result: MacroRunResult;
}

function RunResultView({ result }: RunResultViewProps) {
  const kvEntries = useMemo(
    () => Object.entries(result.kv_store ?? {}),
    [result.kv_store],
  );

  return (
    <div className="macro-run-result">
      <div className="macro-section">
        <h3 className="macro-section-title">Execution Result</h3>
        <div className="macro-result-summary">
          <div className="macro-result-item">
            <span className="macro-result-label">Status</span>
            <Badge variant={statusVariant(result.status)}>{result.status}</Badge>
          </div>
          <div className="macro-result-item">
            <span className="macro-result-label">Macro</span>
            <span className="macro-result-value">{result.macro_name}</span>
          </div>
          <div className="macro-result-item">
            <span className="macro-result-label">Steps Executed</span>
            <span className="macro-result-value">{result.steps_executed}</span>
          </div>
          {result.error && (
            <div className="macro-result-item macro-result-error">
              <span className="macro-result-label">Error</span>
              <span className="macro-result-value">{result.error}</span>
            </div>
          )}
        </div>
      </div>

      {/* Step results table */}
      {result.step_results && result.step_results.length > 0 && (
        <div className="macro-section">
          <h3 className="macro-section-title">Step Results</h3>
          <Table>
            <thead>
              <tr>
                <th>Step</th>
                <th>Status</th>
                <th>Status Code</th>
                <th>Duration</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {result.step_results.map((sr: MacroStepResult) => (
                <tr key={sr.id}>
                  <td className="macro-cell-mono">{sr.id}</td>
                  <td>
                    <Badge variant={statusVariant(sr.status)}>
                      {sr.status}
                    </Badge>
                  </td>
                  <td className="macro-cell-mono">
                    {sr.status_code ?? "--"}
                  </td>
                  <td className="macro-cell-mono">
                    {sr.duration_ms != null ? `${sr.duration_ms}ms` : "--"}
                  </td>
                  <td className="macro-cell-error">
                    {sr.error || "--"}
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}

      {/* KV Store */}
      {kvEntries.length > 0 && (
        <div className="macro-section">
          <h3 className="macro-section-title">KV Store</h3>
          <Table>
            <thead>
              <tr>
                <th>Key</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {kvEntries.map(([key, value]) => (
                <tr key={key}>
                  <td className="macro-cell-mono">{key}</td>
                  <td className="macro-cell-value">{value}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}
    </div>
  );
}
