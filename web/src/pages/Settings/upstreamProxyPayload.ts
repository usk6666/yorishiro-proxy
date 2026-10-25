/**
 * upstreamProxyPayload -- pure helpers behind UpstreamProxyEditor: the wire
 * value shape, payload construction, pre-save validation and URL redaction.
 *
 * Split out of UpstreamProxyEditor.tsx so that file exports only components
 * (React Fast Refresh). The code below is unchanged apart from exporting
 * NONCE_MACRO (still used by the editor's placeholder) and naming the mode
 * type `UpstreamProxyEditorMode`.
 */

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

export type UpstreamProxyEditorMode = "simple" | "rotation";

/** Macro that the live data path expands to a fresh UUID per resolution. */
export const NONCE_MACRO = "§__nonce§";

/** Generic macro pattern (any §var§). */
const ANY_MACRO_RE = /§[^§]+§/;

const PROXY_SCHEME_RE = /^(?:https?|socks5):\/\//;

/**
 * Mask the credential portion of userinfo in a proxy URL when surfacing
 * the URL in UI toasts / status text. Mirrors the backend
 * `connector.RedactProxyURL` semantics (CWE-200): a `user:password`
 * userinfo keeps the username visible and masks the password; a single
 * bare token in userinfo (often a session key) is masked entirely.
 * Falls back to lexical substitution when the URL is not parsable by
 * `URL` (e.g., when it contains `§macro§` characters).
 */
export function redactUpstreamProxyURL(raw: string): string {
  if (raw === "") {
    return raw;
  }
  // Macro-bearing template URLs (§…§) bypass the structured URL parser
  // path: the WHATWG URL parser percent-encodes the section sign,
  // mutating the template shape. The lexical path preserves the
  // template bytes exactly while masking the userinfo region.
  if (!raw.includes("§")) {
    try {
      const u = new URL(raw);
      if (!u.username && !u.password) {
        return raw;
      }
      if (u.password) {
        u.password = "xxxxx";
        return u.toString();
      }
      // Single-token userinfo (no `:password` colon) — mask the whole
      // thing. URL.toString preserves the no-password shape.
      u.username = "xxxxx";
      return u.toString();
    } catch {
      // Fall through to lexical path.
    }
  }
  // Lexical fallback. Mirrors the Go fallback path: scan from the
  // scheme separator to the first `@`, masking the password half
  // when a `:` exists inside the userinfo region.
  const schemeIdx = raw.indexOf("://");
  if (schemeIdx < 0) {
    return raw;
  }
  const userinfoStart = schemeIdx + 3;
  const atIdx = raw.indexOf("@", userinfoStart);
  if (atIdx < 0) {
    return raw;
  }
  const colonIdx = raw.indexOf(":", userinfoStart);
  if (colonIdx < 0 || colonIdx >= atIdx) {
    return raw.slice(0, userinfoStart) + "xxxxx" + raw.slice(atIdx);
  }
  return raw.slice(0, colonIdx + 1) + "xxxxx" + raw.slice(atIdx);
}

/**
 * Pure helper used by the editor (and exercised by tests) to translate
 * the local component state into the polymorphic wire value. Kept
 * stand-alone so unit tests can exercise it without rendering React.
 */
export function buildUpstreamProxyPayload(
  mode: UpstreamProxyEditorMode,
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
    return warnings;
  }

  // Rotation-shape object with an empty url_template. `isRotationUpstream`
  // requires `url_template.length > 0`, so the editor's rotation-mode
  // emit-with-empty-template case lands here. Backend will reject with
  // "one of url or url_template is required", but warn-on-save should
  // surface the issue before the round-trip.
  if (
    typeof value === "object" &&
    value !== null &&
    "url_template" in value &&
    typeof (value as { url_template?: unknown }).url_template === "string" &&
    (value as { url_template: string }).url_template.length === 0
  ) {
    warnings.push("Rotation template is empty; backend will reject this save");
  }

  return warnings;
}
