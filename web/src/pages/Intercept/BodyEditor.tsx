interface BodyEditorProps {
  body: string;
  onChange: (body: string) => void;
}

export function BodyEditor({ body, onChange }: BodyEditorProps) {
  return (
    <div className="intercept-section">
      <div className="intercept-section-title">Body</div>
      <textarea
        className="intercept-body-editor"
        value={body}
        onChange={(e) => onChange(e.target.value)}
        placeholder="Request body (empty)"
        spellCheck={false}
      />
    </div>
  );
}
