import { useCallback, useEffect, useState } from "react";
import { Button } from "../../components/ui/Button.js";
import type { RawPatch } from "../../lib/mcp/types.js";
import "./RawPatchEditor.css";

export interface RawPatchEditorProps {
  patches: RawPatch[];
  onChange: (patches: RawPatch[]) => void;
  /**
   * Called when the editor's validity changes. Validity is computed from
   * the offset field of every `mode === "offset"` patch — non-numeric,
   * empty, negative, or fractional offsets are invalid. Parent components
   * use this to disable the submit button, preventing the prior silent
   * NaN→0 coercion at submit time (USK-967).
   */
  onValidityChange?: (valid: boolean) => void;
}

/**
 * Validate a raw offset string entry.
 *
 * Returns `null` when the input parses as a finite non-negative integer.
 * Returns an error message otherwise. Empty strings, "abc", "-1", and
 * "1.5" all surface as errors so the caller can render inline feedback
 * and disable submit — silent coercion to 0 (the prior behaviour) would
 * write the patch at a wholly different offset than the user intended,
 * exactly the failure mode the byte-level fuzz workflow exists to avoid.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function validateRawPatchOffset(raw: string): string | null {
  if (raw.trim() === "") return "offset is required";
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return "offset must be a number";
  if (!Number.isInteger(parsed)) return "offset must be an integer";
  if (parsed < 0) return "offset must be non-negative";
  return null;
}

/** Patch mode for the editor entry. */
type PatchMode = "offset" | "find_replace_hex" | "find_replace_text";

/** Determine which mode a RawPatch entry uses. */
function detectMode(patch: RawPatch): PatchMode {
  if (patch.find_text != null || patch.replace_text != null) return "find_replace_text";
  if (patch.find_base64 != null || patch.replace_base64 != null) return "find_replace_hex";
  return "offset";
}

/**
 * Editor for raw byte-level patches used by resend_raw.
 *
 * Supports three patch modes:
 * - Offset: apply data at a specific byte offset (offset + data_base64)
 * - Find/Replace (hex): find and replace by base64-encoded bytes
 * - Find/Replace (text): find and replace by plain text
 */
export function RawPatchEditor({
  patches,
  onChange,
  onValidityChange,
}: RawPatchEditorProps) {
  // Per-row raw offset input string (USK-967). Stored alongside the parsed
  // patches so that an in-flight "abc" never silently coerces to 0 — the
  // user's keystrokes are kept verbatim and the parent's submit gate
  // observes the validation state.
  const [offsetInputs, setOffsetInputs] = useState<Record<number, string>>({});

  // Compute the per-row validation error for offset-mode patches. Other
  // modes are unconditionally valid here (find/replace doesn't have the
  // NaN→0 problem since the backend treats those fields as opaque strings).
  const offsetErrors: Record<number, string | null> = {};
  patches.forEach((patch, index) => {
    const mode = detectMode(patch);
    if (mode !== "offset") {
      offsetErrors[index] = null;
      return;
    }
    const raw = offsetInputs[index];
    if (raw === undefined) {
      // No edit yet — trust the parsed offset (typically 0 from "Add Patch").
      offsetErrors[index] = patch.offset == null ? "offset is required" : null;
      return;
    }
    offsetErrors[index] = validateRawPatchOffset(raw);
  });

  const isValid = Object.values(offsetErrors).every((e) => e == null);

  // Notify parent of validity transitions so the submit button can be
  // disabled while any offset row is invalid (USK-967).
  useEffect(() => {
    onValidityChange?.(isValid);
  }, [isValid, onValidityChange]);

  const handleModeChange = useCallback(
    (index: number, mode: PatchMode) => {
      const updated = [...patches];
      // Reset all fields and set relevant ones for the new mode.
      const blank: RawPatch = {};
      if (mode === "offset") {
        blank.offset = 0;
        blank.data_base64 = "";
      } else if (mode === "find_replace_hex") {
        blank.find_base64 = "";
        blank.replace_base64 = "";
      } else {
        blank.find_text = "";
        blank.replace_text = "";
      }
      updated[index] = blank;
      onChange(updated);
      // Reset the per-row offset input string when leaving offset mode so
      // a previously stored "abc" doesn't shadow a later switch back.
      setOffsetInputs((prev) => {
        const next = { ...prev };
        delete next[index];
        return next;
      });
    },
    [patches, onChange],
  );

  const handleOffsetChange = useCallback(
    (index: number, val: string) => {
      setOffsetInputs((prev) => ({ ...prev, [index]: val }));
      const updated = [...patches];
      const patch = { ...updated[index] };
      const err = validateRawPatchOffset(val);
      if (err == null) {
        patch.offset = Number(val);
      } else {
        // Mark the patch offset as null so the parent's submit-gate (which
        // additionally disables when isValid is false) cannot accidentally
        // see a stale numeric offset from a prior keystroke.
        patch.offset = null;
      }
      updated[index] = patch;
      onChange(updated);
    },
    [patches, onChange],
  );

  const handleFieldChange = useCallback(
    (index: number, field: keyof RawPatch, val: string) => {
      const updated = [...patches];
      const patch = { ...updated[index] };
      (patch as Record<string, unknown>)[field] = val || undefined;
      updated[index] = patch;
      onChange(updated);
    },
    [patches, onChange],
  );

  const handleAdd = useCallback(() => {
    onChange([...patches, { offset: 0, data_base64: "" }]);
  }, [patches, onChange]);

  const handleRemove = useCallback(
    (index: number) => {
      const updated = patches.filter((_, i) => i !== index);
      onChange(updated);
      // Compact the offsetInputs keys so later entries don't inherit a
      // stale validation state from a removed row.
      setOffsetInputs((prev) => {
        const next: Record<number, string> = {};
        for (const [k, v] of Object.entries(prev)) {
          const idx = Number(k);
          if (idx < index) next[idx] = v;
          else if (idx > index) next[idx - 1] = v;
        }
        return next;
      });
    },
    [patches, onChange],
  );

  return (
    <div className="raw-patch-editor">
      <div className="raw-patch-editor-description">
        Modify raw bytes of the TCP payload. Choose a patch mode for each entry.
      </div>
      {patches.length === 0 && (
        <div className="raw-patch-editor-empty">
          No raw patches. Click "Add Patch" to add one.
        </div>
      )}
      {patches.map((patch, index) => {
        const mode = detectMode(patch);
        return (
          <div key={index} className="raw-patch-editor-entry">
            <div className="raw-patch-editor-mode-row">
              <select
                className="raw-patch-editor-mode-select"
                value={mode}
                onChange={(e) => handleModeChange(index, e.target.value as PatchMode)}
              >
                <option value="offset">Offset + Data (base64)</option>
                <option value="find_replace_hex">Find/Replace (base64)</option>
                <option value="find_replace_text">Find/Replace (text)</option>
              </select>
              <button
                className="raw-patch-editor-remove"
                onClick={() => handleRemove(index)}
                title="Remove patch"
                aria-label={`Remove patch ${index}`}
              >
                x
              </button>
            </div>
            {mode === "offset" && (
              <>
                <div className="raw-patch-editor-row">
                  <input
                    className="raw-patch-editor-field raw-patch-editor-field--offset"
                    type="text"
                    inputMode="numeric"
                    value={
                      offsetInputs[index] !== undefined
                        ? offsetInputs[index]
                        : patch.offset != null
                          ? String(patch.offset)
                          : ""
                    }
                    onChange={(e) => handleOffsetChange(index, e.target.value)}
                    placeholder="Byte offset"
                    title="Byte offset (non-negative integer)"
                    aria-invalid={offsetErrors[index] != null}
                  />
                  <input
                    className="raw-patch-editor-field"
                    type="text"
                    value={patch.data_base64 ?? ""}
                    onChange={(e) => handleFieldChange(index, "data_base64", e.target.value)}
                    placeholder="Base64-encoded data"
                    spellCheck={false}
                  />
                </div>
                {offsetErrors[index] != null && (
                  <div
                    className="raw-patch-editor-error"
                    role="alert"
                    aria-label={`Offset error for patch ${index}`}
                  >
                    {offsetErrors[index]}
                  </div>
                )}
              </>
            )}
            {mode === "find_replace_hex" && (
              <div className="raw-patch-editor-row">
                <input
                  className="raw-patch-editor-field"
                  type="text"
                  value={patch.find_base64 ?? ""}
                  onChange={(e) => handleFieldChange(index, "find_base64", e.target.value)}
                  placeholder="Find (base64)"
                  spellCheck={false}
                />
                <input
                  className="raw-patch-editor-field"
                  type="text"
                  value={patch.replace_base64 ?? ""}
                  onChange={(e) => handleFieldChange(index, "replace_base64", e.target.value)}
                  placeholder="Replace (base64)"
                  spellCheck={false}
                />
              </div>
            )}
            {mode === "find_replace_text" && (
              <div className="raw-patch-editor-row">
                <input
                  className="raw-patch-editor-field"
                  type="text"
                  value={patch.find_text ?? ""}
                  onChange={(e) => handleFieldChange(index, "find_text", e.target.value)}
                  placeholder="Find text"
                  spellCheck={false}
                />
                <input
                  className="raw-patch-editor-field"
                  type="text"
                  value={patch.replace_text ?? ""}
                  onChange={(e) => handleFieldChange(index, "replace_text", e.target.value)}
                  placeholder="Replace text"
                  spellCheck={false}
                />
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
