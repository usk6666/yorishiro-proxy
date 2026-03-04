import { useCallback } from "react";
import { Button } from "../../components/ui/Button.js";
import type { BodyPatch } from "../../lib/mcp/types.js";
import "./BodyPatchEditor.css";

export interface BodyPatchEditorProps {
  patches: BodyPatch[];
  onChange: (patches: BodyPatch[]) => void;
}

/**
 * Editor for body patches (JSON path or regex-based partial body modification).
 * Each patch can specify a json_path + value or a regex + replace string.
 */
export function BodyPatchEditor({ patches, onChange }: BodyPatchEditorProps) {
  const handleFieldChange = useCallback(
    (index: number, field: keyof BodyPatch, val: string) => {
      const updated = [...patches];
      const patch = { ...updated[index] };
      if (field === "value") {
        // Try to parse as JSON, fall back to string.
        try {
          patch.value = JSON.parse(val);
        } catch {
          patch.value = val;
        }
      } else {
        (patch as Record<string, unknown>)[field] = val || undefined;
      }
      updated[index] = patch;
      onChange(updated);
    },
    [patches, onChange],
  );

  const handleAdd = useCallback(() => {
    onChange([...patches, { json_path: "", replace: "" }]);
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
      </div>
      {patches.length === 0 && (
        <div className="patch-editor-empty">
          No body patches. Click "Add Patch" to add one.
        </div>
      )}
      {patches.map((patch, index) => (
        <div key={index} className="patch-editor-entry">
          <div className="patch-editor-row">
            <input
              className="patch-editor-field"
              type="text"
              value={patch.json_path ?? ""}
              onChange={(e) => handleFieldChange(index, "json_path", e.target.value)}
              placeholder="$.path.to.field"
              spellCheck={false}
            />
            <input
              className="patch-editor-field"
              type="text"
              value={typeof patch.value === "string" ? patch.value : patch.value != null ? JSON.stringify(patch.value) : ""}
              onChange={(e) => handleFieldChange(index, "value", e.target.value)}
              placeholder="New value (JSON)"
              spellCheck={false}
            />
            <button
              className="patch-editor-remove"
              onClick={() => handleRemove(index)}
              title="Remove patch"
              aria-label={`Remove patch ${index}`}
            >
              x
            </button>
          </div>
          <div className="patch-editor-row">
            <input
              className="patch-editor-field"
              type="text"
              value={patch.regex ?? ""}
              onChange={(e) => handleFieldChange(index, "regex", e.target.value)}
              placeholder="Regex pattern (optional)"
              spellCheck={false}
            />
            <input
              className="patch-editor-field"
              type="text"
              value={patch.replace ?? ""}
              onChange={(e) => handleFieldChange(index, "replace", e.target.value)}
              placeholder="Replace string (optional)"
              spellCheck={false}
            />
            <div className="patch-editor-spacer" />
          </div>
        </div>
      ))}
      <Button variant="ghost" size="sm" onClick={handleAdd}>
        + Add Patch
      </Button>
    </div>
  );
}
