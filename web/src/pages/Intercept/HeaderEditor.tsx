import { useCallback } from "react";
import { Button } from "../../components/ui/index.js";

export interface HeaderRow {
  id: string;
  name: string;
  value: string;
}

interface HeaderEditorProps {
  headers: HeaderRow[];
  onChange: (headers: HeaderRow[]) => void;
}

export function HeaderEditor({ headers, onChange }: HeaderEditorProps) {
  const handleNameChange = useCallback(
    (index: number, name: string) => {
      const next = [...headers];
      next[index] = { ...next[index], name };
      onChange(next);
    },
    [headers, onChange],
  );

  const handleValueChange = useCallback(
    (index: number, value: string) => {
      const next = [...headers];
      next[index] = { ...next[index], value };
      onChange(next);
    },
    [headers, onChange],
  );

  const handleRemove = useCallback(
    (index: number) => {
      const next = headers.filter((_, i) => i !== index);
      onChange(next);
    },
    [headers, onChange],
  );

  const handleAdd = useCallback(() => {
    onChange([...headers, { id: crypto.randomUUID(), name: "", value: "" }]);
  }, [headers, onChange]);

  return (
    <div className="intercept-section">
      <div className="intercept-section-title">Headers</div>
      {headers.map((header, index) => (
        <div key={header.id} className="intercept-header-row">
          <input
            className="input intercept-header-name"
            value={header.name}
            onChange={(e) => handleNameChange(index, e.target.value)}
            placeholder="Header name"
          />
          <input
            className="input intercept-header-value"
            value={header.value}
            onChange={(e) => handleValueChange(index, e.target.value)}
            placeholder="Header value"
          />
          <Button
            variant="ghost"
            size="sm"
            className="intercept-header-remove"
            onClick={() => handleRemove(index)}
            title="Remove header"
          >
            x
          </Button>
        </div>
      ))}
      <Button
        variant="ghost"
        size="sm"
        className="intercept-add-header"
        onClick={handleAdd}
      >
        + Add Header
      </Button>
    </div>
  );
}
