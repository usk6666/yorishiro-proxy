import { useCallback } from "react";
import { Button } from "../../components/ui/Button.js";
import "./HeaderEditor.css";

export interface HeaderEntry {
  key: string;
  value: string;
}

export interface HeaderEditorProps {
  headers: HeaderEntry[];
  onChange: (headers: HeaderEntry[]) => void;
}

/**
 * Key-value editor for HTTP headers.
 * Supports adding, removing, and editing individual header entries.
 */
export function HeaderEditor({ headers, onChange }: HeaderEditorProps) {
  const handleKeyChange = useCallback(
    (index: number, key: string) => {
      const updated = [...headers];
      updated[index] = { ...updated[index], key };
      onChange(updated);
    },
    [headers, onChange],
  );

  const handleValueChange = useCallback(
    (index: number, value: string) => {
      const updated = [...headers];
      updated[index] = { ...updated[index], value };
      onChange(updated);
    },
    [headers, onChange],
  );

  const handleAdd = useCallback(() => {
    onChange([...headers, { key: "", value: "" }]);
  }, [headers, onChange]);

  const handleRemove = useCallback(
    (index: number) => {
      const updated = headers.filter((_, i) => i !== index);
      onChange(updated);
    },
    [headers, onChange],
  );

  return (
    <div className="header-editor">
      {headers.length === 0 && (
        <div className="header-editor-empty">
          No headers. Click "Add Header" to add one.
        </div>
      )}
      {headers.map((header, index) => (
        <div key={index} className="header-editor-row">
          <input
            className="header-editor-key"
            type="text"
            value={header.key}
            onChange={(e) => handleKeyChange(index, e.target.value)}
            placeholder="Header name"
            spellCheck={false}
          />
          <input
            className="header-editor-value"
            type="text"
            value={header.value}
            onChange={(e) => handleValueChange(index, e.target.value)}
            placeholder="Value"
            spellCheck={false}
          />
          <button
            className="header-editor-remove"
            onClick={() => handleRemove(index)}
            title="Remove header"
            aria-label={`Remove header ${header.key || index}`}
          >
            x
          </button>
        </div>
      ))}
      <Button variant="ghost" size="sm" onClick={handleAdd}>
        + Add Header
      </Button>
    </div>
  );
}
