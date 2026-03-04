import { useCallback } from "react";
import { Button } from "../../components/ui/Button.js";
import type { RawPatch } from "../../lib/mcp/types.js";
import "./RawPatchEditor.css";

export interface RawPatchEditorProps {
  patches: RawPatch[];
  onChange: (patches: RawPatch[]) => void;
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
export function RawPatchEditor({ patches, onChange }: RawPatchEditorProps) {
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
    },
    [patches, onChange],
  );

  const handleFieldChange = useCallback(
    (index: number, field: keyof RawPatch, val: string) => {
      const updated = [...patches];
      const patch = { ...updated[index] };
      if (field === "offset") {
        const num = parseInt(val, 10);
        patch.offset = isNaN(num) ? null : num;
      } else {
        (patch as Record<string, unknown>)[field] = val || undefined;
      }
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
              <div className="raw-patch-editor-row">
                <input
                  className="raw-patch-editor-field raw-patch-editor-field--offset"
                  type="number"
                  value={patch.offset ?? 0}
                  onChange={(e) => handleFieldChange(index, "offset", e.target.value)}
                  placeholder="Byte offset"
                  title="Byte offset"
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
