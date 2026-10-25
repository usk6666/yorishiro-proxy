/**
 * bodyViewerHelpers -- pure helpers for BodyViewer.
 *
 * Split out of BodyViewer.tsx so that file exports only components (React
 * Fast Refresh). The code below is unchanged.
 */

import type { DecodeAnomaly } from "../../lib/mcp/types.js";

export type BodySource = "decoded" | "original";

export interface BodySourceState {
  /** Whether the source toggle should be shown at all. */
  showToggle: boolean;
  /** Whether the "Decoded" toggle button should be selectable. */
  decodedAvailable: boolean;
  /** Default source to select on first render. */
  defaultSource: BodySource;
}

/**
 * MIME types that are safe to render via `<img src="data:...">`.
 *
 * `image/svg+xml` is intentionally excluded: SVG can carry inline `<script>`
 * which executes in the `data:` origin, and the WebUI renders attacker-
 * controlled MITM-observed bodies. With no CSP yet (USK-743), this allowlist
 * is the sole barrier against SVG-based XSS through the body preview.
 */
const PREVIEWABLE_IMAGE_TYPES = new Set<string>([
  "image/png",
  "image/jpeg",
  "image/jpg",
  "image/gif",
  "image/webp",
  "image/avif",
]);

/**
 * Check if Content-Type is an image format that is safe to inline as a
 * `data:` URL. Strips parameters (e.g. `; charset=...`), trims whitespace,
 * and lowercases the main type before matching against `PREVIEWABLE_IMAGE_TYPES`.
 */
export function isPreviewableImage(ct: string | null | undefined): boolean {
  if (!ct) return false;
  const main = ct.split(";")[0].trim().toLowerCase();
  return PREVIEWABLE_IMAGE_TYPES.has(main);
}

/**
 * Resolve which body source toggle state should be shown for a body.
 *
 * - If a codec was applied AND a decoded body is present, the toggle is
 *   shown and "decoded" is the default (this is the user's main reason for
 *   visiting the panel: read the body content).
 * - If decode was attempted but produced an anomaly, the toggle is still
 *   shown (so the operator can see the warning + Original) but the Decoded
 *   button is disabled.
 * - If neither happened (no Content-Encoding, identity, or server-side decode
 *   disabled), the toggle is hidden and the original body is shown — exactly
 *   the pre-USK-738 behavior.
 */
export function resolveBodySourceState(
  bodyDecoded: string | undefined,
  bodyEncodingApplied: string | undefined,
  bodyDecodeAnomaly: DecodeAnomaly | undefined,
): BodySourceState {
  const decodedAvailable =
    !!bodyEncodingApplied && bodyEncodingApplied !== "" && !!bodyDecoded && bodyDecoded.length > 0;
  const showToggle = decodedAvailable || !!bodyDecodeAnomaly;
  return {
    showToggle,
    decodedAvailable,
    defaultSource: decodedAvailable ? "decoded" : "original",
  };
}

/** Render-friendly label for an anomaly type. */
export function anomalyLabel(type: string): string {
  switch (type) {
    case "unknown_encoding":
      return "Unknown Content-Encoding";
    case "malformed":
      return "Malformed compressed body";
    case "size_exceeded":
      return "Decoded body exceeds size cap";
    case "chain_rejected":
      return "Chained Content-Encoding not supported";
    case "truncated_decode":
      return "Body was truncated at storage time";
    default:
      return type;
  }
}
