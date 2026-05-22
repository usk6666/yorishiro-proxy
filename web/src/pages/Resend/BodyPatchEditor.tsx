import { useCallback, useEffect } from "react";
import { Button } from "../../components/ui/Button.js";
import type { BodyPatch } from "../../lib/mcp/types.js";
import "./BodyPatchEditor.css";

export interface BodyPatchEditorProps {
  patches: BodyPatch[];
  onChange: (patches: BodyPatch[]) => void;
  /**
   * Called when the editor's validity changes. A patch is valid only when
   * exactly one mode is populated (json_path xor regex). The backend
   * `validateBodyPatch` (`internal/mcp/body_patch.go`) rejects the
   * both-modes-set and neither-mode-set shapes with a hard error; parents
   * use this signal to disable the submit button so the conflicting input
   * is caught before the server round-trip (USK-973).
   */
  onValidityChange?: (valid: boolean) => void;
}

/** Patch mode for the editor entry. */
export type BodyPatchMode = "json_path" | "regex";

/**
 * Infer which mode an existing BodyPatch entry uses.
 *
 * Priority: regex wins when both pattern fields are present. The
 * editor's own write path never produces this shape (mode switching
 * clears the other-mode fields), so the only way to reach it is
 * legacy data or a flow-load before USK-973. The flow-load reset in
 * `ResendPage` clears `bodyPatches` to `[]`, so this is defense-only.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function detectBodyPatchMode(patch: BodyPatch): BodyPatchMode {
  if (patch.regex != null || patch.replace != null) return "regex";
  return "json_path";
}

/**
 * Determine whether a single BodyPatch is submittable.
 *
 * Mirrors the backend `validateBodyPatch` exactly-one-of contract:
 * the patch must have a non-empty `json_path` xor a non-empty `regex`.
 * Empty rows (both modes blank) and conflicting rows (both modes
 * populated) are rejected here so the parent's submit button is
 * disabled before the server round-trip.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function isBodyPatchValid(patch: BodyPatch): boolean {
  const hasJSON = (patch.json_path ?? "").trim() !== "";
  const hasRegex = (patch.regex ?? "").trim() !== "";
  return hasJSON !== hasRegex;
}

/**
 * Editor for body patches (JSON path or regex-based partial body modification).
 * Each patch selects exactly one mode (json_path xor regex); mode switching
 * clears the other-mode fields to keep the wire shape unambiguous.
 */
export function BodyPatchEditor({
  patches,
  onChange,
  onValidityChange,
}: BodyPatchEditorProps) {
  const isValid = patches.every(isBodyPatchValid);

  // Notify parent of validity transitions so the submit button can be
  // disabled while any patch row is empty or has both modes populated
  // (USK-973).
  useEffect(() => {
    onValidityChange?.(isValid);
  }, [isValid, onValidityChange]);

  const handleModeChange = useCallback(
    (index: number, mode: BodyPatchMode) => {
      const updated = [...patches];
      // Reset all fields and set relevant ones for the new mode.
      updated[index] = mode === "json_path" ? { json_path: "" } : { regex: "", replace: "" };
      onChange(updated);
    },
    [patches, onChange],
  );

  const handleJSONPathChange = useCallback(
    (index: number, val: string) => {
      const updated = [...patches];
      const patch = { ...updated[index] };
      patch.json_path = val;
      updated[index] = patch;
      onChange(updated);
    },
    [patches, onChange],
  );

  const handleValueChange = useCallback(
    (index: number, val: string) => {
      const updated = [...patches];
      const patch = { ...updated[index] };
      // Try to parse as JSON, fall back to string.
      try {
        patch.value = JSON.parse(val);
      } catch {
        patch.value = val;
      }
      updated[index] = patch;
      onChange(updated);
    },
    [patches, onChange],
  );

  const handleRegexFieldChange = useCallback(
    (index: number, field: "regex" | "replace", val: string) => {
      const updated = [...patches];
      const patch = { ...updated[index] };
      patch[field] = val;
      updated[index] = patch;
      onChange(updated);
    },
    [patches, onChange],
  );

  const handleAdd = useCallback(() => {
    onChange([...patches, { json_path: "" }]);
  }, [patches, onChange]);

  const handleRemove = useCallback(
    (index: number) => {
      const updated = patches.filter((_, i) => i !== index);
      onChange(updated);
    },
    [patches, onChange],
  );

  return (
    <div className="patch-editor">
      <div className="patch-editor-description">
        Modify parts of the request body using JSON path or regex patterns.
        Choose a patch mode for each entry.
      </div>
      {patches.length === 0 && (
        <div className="patch-editor-empty">
          No body patches. Click "Add Patch" to add one.
        </div>
      )}
      {patches.map((patch, index) => {
        const mode = detectBodyPatchMode(patch);
        const valid = isBodyPatchValid(patch);
        return (
          <div key={index} className="patch-editor-entry">
            <div className="patch-editor-mode-row">
              <select
                className="patch-editor-mode-select"
                value={mode}
                onChange={(e) =>
                  handleModeChange(index, e.target.value as BodyPatchMode)
                }
              >
                <option value="json_path">JSON path + value</option>
                <option value="regex">Regex + replace</option>
              </select>
              <button
                className="patch-editor-remove"
                onClick={() => handleRemove(index)}
                title="Remove patch"
                aria-label={`Remove patch ${index}`}
              >
                x
              </button>
            </div>
            {mode === "json_path" && (
              <div className="patch-editor-row">
                <input
                  className="patch-editor-field"
                  type="text"
                  value={patch.json_path ?? ""}
                  onChange={(e) => handleJSONPathChange(index, e.target.value)}
                  placeholder="$.path.to.field"
                  spellCheck={false}
                  aria-invalid={!valid}
                />
                <input
                  className="patch-editor-field"
                  type="text"
                  value={
                    typeof patch.value === "string"
                      ? patch.value
                      : patch.value != null
                        ? JSON.stringify(patch.value)
                        : ""
                  }
                  onChange={(e) => handleValueChange(index, e.target.value)}
                  placeholder="New value (JSON)"
                  spellCheck={false}
                />
              </div>
            )}
            {mode === "regex" && (
              <div className="patch-editor-row">
                <input
                  className="patch-editor-field"
                  type="text"
                  value={patch.regex ?? ""}
                  onChange={(e) =>
                    handleRegexFieldChange(index, "regex", e.target.value)
                  }
                  placeholder="Regex pattern"
                  spellCheck={false}
                  aria-invalid={!valid}
                />
                <input
                  className="patch-editor-field"
                  type="text"
                  value={patch.replace ?? ""}
                  onChange={(e) =>
                    handleRegexFieldChange(index, "replace", e.target.value)
                  }
                  placeholder="Replace string"
                  spellCheck={false}
                />
              </div>
            )}
            {!valid && (
              <div
                className="patch-editor-error"
                role="alert"
                aria-label={`Validation error for patch ${index}`}
              >
                {mode === "json_path"
                  ? "json_path is required"
                  : "regex is required"}
              </div>
            )}
          </div>
        );
      })}
      <Button variant="ghost" size="sm" onClick={handleAdd}>
        + Add Patch
      </Button>
    </div>
  );
}
