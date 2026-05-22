import { useCallback, useEffect, useState } from "react";
import { Input } from "../../components/ui/index.js";
import type {
  UpstreamProxyPolicy,
  UpstreamProxyRotationInput,
} from "../../lib/mcp/types.js";
import { isRotationUpstream } from "../../lib/mcp/types.js";

/**
 * Shape emitted by the editor's `onChange`. Mirrors the wire shape that
 * `configure` / `proxy_start` accept on the `upstream_proxy` field — a
 * plain string (literal URL or `""` to disable) or the USK-959 rotation
 * object. The editor never emits an empty `{}` (backend rejects it).
 */
export type UpstreamProxyEditorValue = string | UpstreamProxyRotationInput;

type Mode = "simple" | "rotation";

/** Policy options surfaced in the rotation select; order matches backend doc. */
const POLICY_OPTIONS: readonly { value: UpstreamProxyPolicy; label: string }[] = [
  { value: "per_request", label: "Per request" },
  { value: "per_connection", label: "Per connection" },
  { value: "per_target_host", label: "Per target host" },
  { value: "sticky", label: "Sticky" },
] as const;

/** Macro that the live data path expands to a fresh UUID per resolution. */
const NONCE_MACRO = "§__nonce§";

/** Generic macro pattern (any §var§). */
const ANY_MACRO_RE = /§[^§]+§/;

const PROXY_SCHEME_RE = /^(?:https?|socks5):\/\//;

/**
 * Pure helper used by the editor (and exercised by tests) to translate
 * the local component state into the polymorphic wire value. Kept
 * stand-alone so unit tests can exercise it without rendering React.
 */
export function buildUpstreamProxyPayload(
  mode: Mode,
  simpleUrl: string,
  templateUrl: string,
  policy: UpstreamProxyPolicy,
): UpstreamProxyEditorValue {
  if (mode === "rotation") {
    return {
      url_template: templateUrl.trim(),
      rotation: { policy },
    };
  }
  // Simple mode: emit a bare string (legacy literal URL) — backend
  // accepts both the bare string and `{ url: ... }` but the string form
  // is the most compact and matches USK-826 prior art.
  return simpleUrl.trim();
}

/**
 * Pre-save validation returning warning strings the parent can surface
 * via toast. Empty array means "no warnings" — does NOT mean "valid";
 * the backend remains the source of truth on connectivity / scheme /
 * CR-LF guards (CWE-93).
 */
export function validateUpstreamProxyPayload(
  value: UpstreamProxyEditorValue,
): string[] {
  const warnings: string[] = [];

  if (typeof value === "string") {
    if (value !== "" && !PROXY_SCHEME_RE.test(value)) {
      warnings.push(
        "Upstream proxy URL should start with http://, https://, or socks5://",
      );
    }
    return warnings;
  }

  // Rotation form
  if (isRotationUpstream(value)) {
    const tpl = value.url_template;
    if (!PROXY_SCHEME_RE.test(tpl)) {
      warnings.push(
        "Rotation template should start with http://, https://, or socks5://",
      );
    }
    if (!ANY_MACRO_RE.test(tpl)) {
      warnings.push(
        `Rotation template has no §var§ macro (e.g. ${NONCE_MACRO}); each resolution will return the same URL`,
      );
    }
  }

  return warnings;
}

interface UpstreamProxyEditorProps {
  /** Current value. `null`/`undefined` is treated as the empty-string literal form. */
  value: UpstreamProxyEditorValue | null | undefined;
  /** Called with the newly-typed value as the user edits. */
  onChange: (next: UpstreamProxyEditorValue) => void;
  /** Disable all inputs (e.g. while a configure call is in-flight). */
  disabled?: boolean;
  /** Optional label prefix; defaults to "Upstream Proxy". */
  idPrefix?: string;
}

/**
 * Initial-mode inference from an incoming value. Used on mount and when
 * the externally-supplied value transitions between forms (e.g. the
 * Settings page receives a fresh status snapshot).
 */
function inferMode(v: UpstreamProxyEditorValue | null | undefined): Mode {
  if (v && typeof v === "object" && isRotationUpstream(v)) {
    return "rotation";
  }
  return "simple";
}

/**
 * Two-mode editor for the polymorphic `upstream_proxy` field. Local
 * state preserves the *other* mode's draft so toggling does not destroy
 * user input. Only the active mode's value is sent on save (the parent
 * calls `onChange` for every keystroke; the active payload variant is
 * already what the backend expects).
 *
 * NOTE (USK-976): when the listener is currently using rotation, the
 * `status` query does not yet expose `upstream_proxy_template` /
 * `upstream_proxy_rotation_policy`, so on page reload the editor will
 * default to Simple mode with an empty field even if rotation is
 * actually live. This pre-population gap is tracked separately.
 */
export function UpstreamProxyEditor({
  value,
  onChange,
  disabled,
  idPrefix = "upstream-proxy",
}: UpstreamProxyEditorProps) {
  const [mode, setMode] = useState<Mode>(() => inferMode(value));
  const [simpleUrl, setSimpleUrl] = useState<string>(() =>
    typeof value === "string" ? value : "",
  );
  const [templateUrl, setTemplateUrl] = useState<string>(() =>
    value && typeof value === "object" && isRotationUpstream(value)
      ? value.url_template
      : "",
  );
  const [policy, setPolicy] = useState<UpstreamProxyPolicy>(() =>
    value && typeof value === "object" && isRotationUpstream(value)
      ? value.rotation.policy
      : "per_request",
  );

  // Re-sync local state if the externally-supplied value changes shape
  // (e.g. parent receives a new status snapshot). Mode-preserving sync.
  useEffect(() => {
    if (value === undefined || value === null) {
      return;
    }
    if (typeof value === "string") {
      setSimpleUrl(value);
      // Only flip to simple if the parent moved us; preserve current
      // mode otherwise so a user mid-edit isn't yanked away.
    } else if (isRotationUpstream(value)) {
      setTemplateUrl(value.url_template);
      setPolicy(value.rotation.policy);
    }
  }, [value]);

  const emit = useCallback(
    (nextMode: Mode, nextSimple: string, nextTemplate: string, nextPolicy: UpstreamProxyPolicy) => {
      onChange(buildUpstreamProxyPayload(nextMode, nextSimple, nextTemplate, nextPolicy));
    },
    [onChange],
  );

  const handleModeChange = useCallback(
    (next: Mode) => {
      setMode(next);
      emit(next, simpleUrl, templateUrl, policy);
    },
    [simpleUrl, templateUrl, policy, emit],
  );

  const handleSimpleChange = useCallback(
    (next: string) => {
      setSimpleUrl(next);
      if (mode === "simple") {
        emit(mode, next, templateUrl, policy);
      }
    },
    [mode, templateUrl, policy, emit],
  );

  const handleTemplateChange = useCallback(
    (next: string) => {
      setTemplateUrl(next);
      if (mode === "rotation") {
        emit(mode, simpleUrl, next, policy);
      }
    },
    [mode, simpleUrl, policy, emit],
  );

  const handlePolicyChange = useCallback(
    (next: UpstreamProxyPolicy) => {
      setPolicy(next);
      if (mode === "rotation") {
        emit(mode, simpleUrl, templateUrl, next);
      }
    },
    [mode, simpleUrl, templateUrl, emit],
  );

  const simpleId = `${idPrefix}-simple-url`;
  const templateId = `${idPrefix}-template-url`;
  const policyId = `${idPrefix}-policy`;
  const radioGroupName = `${idPrefix}-mode`;

  return (
    <div className="upstream-proxy-editor">
      <div className="settings-form-row upstream-proxy-mode-row" role="radiogroup" aria-label="Upstream proxy mode">
        <label className="upstream-proxy-mode-option">
          <input
            type="radio"
            name={radioGroupName}
            value="simple"
            checked={mode === "simple"}
            onChange={() => handleModeChange("simple")}
            disabled={disabled}
          />
          <span>Simple URL</span>
        </label>
        <label className="upstream-proxy-mode-option">
          <input
            type="radio"
            name={radioGroupName}
            value="rotation"
            checked={mode === "rotation"}
            onChange={() => handleModeChange("rotation")}
            disabled={disabled}
          />
          <span>Rotation template</span>
        </label>
      </div>

      {mode === "simple" ? (
        <div className="settings-form-row">
          <Input
            id={simpleId}
            label="Upstream Proxy URL"
            value={simpleUrl}
            onChange={(e) => handleSimpleChange(e.target.value)}
            placeholder="http://host:port or socks5://host:port"
            disabled={disabled}
          />
        </div>
      ) : (
        <>
          <div className="settings-form-row">
            <Input
              id={templateId}
              label="Rotation URL Template"
              value={templateUrl}
              onChange={(e) => handleTemplateChange(e.target.value)}
              placeholder={`http://session-${NONCE_MACRO}:pass@proxy:8080`}
              disabled={disabled}
            />
          </div>
          <div className="settings-form-row">
            <div className="input-wrapper">
              <label className="input-label" htmlFor={policyId}>
                Rotation Policy
              </label>
              <select
                id={policyId}
                className="settings-select"
                value={policy}
                onChange={(e) => handlePolicyChange(e.target.value as UpstreamProxyPolicy)}
                disabled={disabled}
              >
                {POLICY_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
