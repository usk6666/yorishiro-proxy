interface BodyEditorProps {
  body: string;
  onChange: (body: string) => void;
  /** Section title. Defaults to "Body". */
  label?: string;
  /** Encoding of `body` as held by the server; base64 is shown in the title. */
  encoding?: "text" | "base64";
}

export function BodyEditor({ body, onChange, label = "Body", encoding = "text" }: BodyEditorProps) {
  return (
    <div className="intercept-section">
      <div className="intercept-section-title">
        {label}
        {encoding === "base64" ? " (base64)" : ""}
      </div>
      <textarea
        className="intercept-body-editor"
        value={body}
        onChange={(e) => onChange(e.target.value)}
        placeholder={`${label} (empty)`}
        spellCheck={false}
      />
    </div>
  );
}
