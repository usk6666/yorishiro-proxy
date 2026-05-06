import { useId, type InputHTMLAttributes } from "react";
import "./Input.css";

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
}

export function Input({ label, error, className, id, ...props }: InputProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const errorId = error ? `${inputId}-error` : undefined;
  const classes = ["input", error ? "input--error" : "", className]
    .filter(Boolean)
    .join(" ");

  return (
    <div className="input-wrapper">
      {label && (
        <label className="input-label" htmlFor={inputId}>
          {label}
        </label>
      )}
      <input
        id={inputId}
        className={classes}
        aria-invalid={error ? true : undefined}
        aria-describedby={errorId}
        {...props}
      />
      {error && (
        <span id={errorId} className="input-error">
          {error}
        </span>
      )}
    </div>
  );
}
