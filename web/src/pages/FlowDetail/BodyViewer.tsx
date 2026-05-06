/**
 * BodyViewer -- Displays request/response body with Raw/Pretty/Hex modes.
 *
 * Content-Type detection for pretty-printing:
 * - JSON: formatted with indentation
 * - HTML/XML: displayed as-is with syntax highlighting
 * - Binary (base64): hex dump display
 * - Images: inline preview for image/* content types
 *
 * When the server reports a Content-Encoding decode (gzip / br / deflate /
 * zstd) via `bodyEncodingApplied` (USK-731), an additional source toggle is
 * shown so the operator can view the decoded plaintext (default) or fall back
 * to the original compressed bytes. CLAUDE.md MITM principle #1 is preserved
 * because the original wire bytes remain accessible via the toggle.
 *
 * Text modes (raw / pretty) delegate rendering to CodeViewer for
 * syntax highlighting, line numbers, copy, and word-wrap support.
 */

import { useMemo, useState } from "react";
import { CodeViewer } from "../../components/ui/CodeViewer.js";
import type { DecodeAnomaly } from "../../lib/mcp/types.js";
import "./FlowDetailPage.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BodyViewerProps {
  body: string;
  encoding: string;
  truncated: boolean;
  headers?: Record<string, string[]> | null;
  /**
   * Body after Content-Encoding decode (USK-731). When non-empty and
   * `bodyEncodingApplied` is set, the decoded form is shown by default.
   */
  bodyDecoded?: string;
  /** "text" | "base64" — transport encoding of `bodyDecoded`. */
  bodyDecodedEncoding?: string;
  /** Codec that was applied ("gzip" | "br" | "deflate" | "zstd"). */
  bodyEncodingApplied?: string;
  /** Anomaly detail when decode was attempted but rejected or failed. */
  bodyDecodeAnomaly?: DecodeAnomaly;
}

type ViewMode = "raw" | "pretty" | "hex" | "preview";
export type BodySource = "decoded" | "original";

export interface BodySourceState {
  /** Whether the source toggle should be shown at all. */
  showToggle: boolean;
  /** Whether the "Decoded" toggle button should be selectable. */
  decodedAvailable: boolean;
  /** Default source to select on first render. */
  defaultSource: BodySource;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Extract Content-Type from headers (case-insensitive). */
function getContentType(headers?: Record<string, string[]> | null): string {
  if (!headers) return "";
  for (const [key, values] of Object.entries(headers)) {
    const sv = values ?? [];
    if (key.toLowerCase() === "content-type" && sv.length > 0) {
      return sv[0];
    }
  }
  return "";
}

/** Check if Content-Type indicates JSON. */
function isJsonContentType(ct: string): boolean {
  return ct.includes("application/json") || ct.includes("+json");
}

/** Check if Content-Type indicates HTML. */
function isHtmlContentType(ct: string): boolean {
  return ct.includes("text/html");
}

/** Check if Content-Type indicates XML. */
function isXmlContentType(ct: string): boolean {
  return ct.includes("text/xml") || ct.includes("application/xml") || ct.includes("+xml");
}

/** Check if Content-Type indicates an image. */
function isImageContentType(ct: string): boolean {
  return ct.startsWith("image/");
}

/** Try to pretty-print JSON. Returns null if not valid JSON. */
function tryPrettyJson(body: string): string | null {
  try {
    const parsed = JSON.parse(body);
    return JSON.stringify(parsed, null, 2);
  } catch {
    return null;
  }
}

/** Convert a base64 string to a hex dump display. */
function hexDump(base64: string): string {
  let bytes: Uint8Array;
  try {
    const binary = atob(base64);
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
  } catch {
    return "(Failed to decode base64 content)";
  }

  const lines: string[] = [];
  const maxBytes = Math.min(bytes.length, 4096); // Limit display to 4KB

  for (let offset = 0; offset < maxBytes; offset += 16) {
    const hexParts: string[] = [];
    const asciiParts: string[] = [];

    for (let i = 0; i < 16; i++) {
      if (offset + i < maxBytes) {
        const byte = bytes[offset + i];
        hexParts.push(byte.toString(16).padStart(2, "0"));
        asciiParts.push(byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".");
      } else {
        hexParts.push("  ");
        asciiParts.push(" ");
      }
    }

    const offsetStr = offset.toString(16).padStart(8, "0");
    const hex = hexParts.slice(0, 8).join(" ") + "  " + hexParts.slice(8).join(" ");
    const ascii = asciiParts.join("");
    lines.push(`${offsetStr}  ${hex}  |${ascii}|`);
  }

  if (bytes.length > maxBytes) {
    lines.push(`... (${bytes.length - maxBytes} more bytes truncated)`);
  }

  return lines.join("\n");
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

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function BodyViewer({
  body,
  encoding,
  truncated,
  headers,
  bodyDecoded,
  bodyDecodedEncoding,
  bodyEncodingApplied,
  bodyDecodeAnomaly,
}: BodyViewerProps) {
  const sourceState = useMemo(
    () => resolveBodySourceState(bodyDecoded, bodyEncodingApplied, bodyDecodeAnomaly),
    [bodyDecoded, bodyEncodingApplied, bodyDecodeAnomaly],
  );
  const [source, setSource] = useState<BodySource>(sourceState.defaultSource);

  const effectiveSource: BodySource = sourceState.decodedAvailable ? source : "original";
  const useDecoded = effectiveSource === "decoded";

  const activeBody = useDecoded ? (bodyDecoded ?? "") : body;
  const activeEncoding = useDecoded ? (bodyDecodedEncoding ?? "text") : encoding;

  const contentType = getContentType(headers);
  const isBinary = activeEncoding === "base64";
  const isImage = isImageContentType(contentType);

  // Determine available view modes based on the *active* body, so that a
  // gzip-decoded JSON body offers Pretty mode even though the wire encoding
  // is base64.
  const availableModes = useMemo<ViewMode[]>(() => {
    if (isBinary) {
      const modes: ViewMode[] = ["hex"];
      if (isImage) {
        modes.push("preview");
      }
      return modes;
    }
    const modes: ViewMode[] = ["raw"];
    if (isJsonContentType(contentType) || isHtmlContentType(contentType) || isXmlContentType(contentType)) {
      modes.push("pretty");
    }
    modes.push("hex");
    return modes;
  }, [isBinary, isImage, contentType]);

  // Default mode (recomputed when source changes so a Decoded JSON body opens
  // in Pretty by default, while flipping to Original drops back to Hex).
  const defaultMode = useMemo<ViewMode>(() => {
    if (isBinary && isImage) return "preview";
    if (isBinary) return "hex";
    if (isJsonContentType(contentType)) return "pretty";
    return "raw";
  }, [isBinary, isImage, contentType]);

  const [viewMode, setViewMode] = useState<ViewMode>(defaultMode);

  // Clamp the user-selected mode to one that is available for the active
  // body. When the source toggles (e.g. Decoded JSON ⇄ Original base64), the
  // set of available modes can change, and the previous selection may no
  // longer be valid; fall back to the default for the new body.
  const effectiveViewMode: ViewMode = availableModes.includes(viewMode)
    ? viewMode
    : defaultMode;

  // Formatted content for text modes
  const displayContent = useMemo<string>(() => {
    if (!activeBody) return "";

    if (effectiveViewMode === "hex") {
      if (isBinary) {
        return hexDump(activeBody);
      }
      const encoded = btoa(
        Array.from(new TextEncoder().encode(activeBody))
          .map((b) => String.fromCharCode(b))
          .join(""),
      );
      return hexDump(encoded);
    }

    if (effectiveViewMode === "pretty") {
      if (isJsonContentType(contentType)) {
        const pretty = tryPrettyJson(activeBody);
        if (pretty) return pretty;
      }
      return activeBody;
    }

    // raw or preview fallback
    if (isBinary) {
      return "(Binary content, base64 encoded)";
    }

    return activeBody;
  }, [activeBody, effectiveViewMode, isBinary, contentType]);

  // Whether to use CodeViewer (text-based modes, not hex or preview)
  const useCodeViewer = effectiveViewMode === "raw" || effectiveViewMode === "pretty";

  if (!body && !bodyDecoded) {
    return <div className="sd-empty-section">Empty body</div>;
  }

  return (
    <div className="sd-body-viewer">
      {/* Source toggle (Decoded / Original) — shown only when Content-Encoding
          decode applied or produced an anomaly. */}
      {sourceState.showToggle && (
        <div className="sd-body-controls">
          <div className="sd-body-mode-selector">
            <button
              className={`sd-body-mode-btn ${effectiveSource === "decoded" ? "sd-body-mode-btn--active" : ""}`}
              onClick={() => setSource("decoded")}
              disabled={!sourceState.decodedAvailable}
              title={
                sourceState.decodedAvailable
                  ? `Decoded (${bodyEncodingApplied})`
                  : "Decoded view unavailable due to decode anomaly"
              }
            >
              {bodyEncodingApplied
                ? `Decoded (${bodyEncodingApplied})`
                : "Decoded"}
            </button>
            <button
              className={`sd-body-mode-btn ${effectiveSource === "original" ? "sd-body-mode-btn--active" : ""}`}
              onClick={() => setSource("original")}
              title="Original wire bytes (compressed)"
            >
              Original
            </button>
          </div>
        </div>
      )}

      {/* Decode anomaly warning (always shown when present, regardless of
          which source is currently active). */}
      {bodyDecodeAnomaly && (
        <div className="sd-body-truncated">
          {anomalyLabel(bodyDecodeAnomaly.type)}
          {bodyDecodeAnomaly.detail ? `: ${bodyDecodeAnomaly.detail}` : ""}
        </div>
      )}

      {/* View mode selector (Raw / Pretty / Hex / Preview). */}
      <div className="sd-body-controls">
        <div className="sd-body-mode-selector">
          {availableModes.map((mode) => (
            <button
              key={mode}
              className={`sd-body-mode-btn ${effectiveViewMode === mode ? "sd-body-mode-btn--active" : ""}`}
              onClick={() => setViewMode(mode)}
            >
              {mode.charAt(0).toUpperCase() + mode.slice(1)}
            </button>
          ))}
        </div>
        {contentType && (
          <span className="sd-body-content-type">{contentType}</span>
        )}
      </div>

      {/* Truncation warning */}
      {truncated && (
        <div className="sd-body-truncated">
          Body was truncated. The full content may not be shown.
        </div>
      )}

      {/* Image preview */}
      {effectiveViewMode === "preview" && isBinary && isImage && (
        <div className="sd-body-image-preview">
          <img
            src={`data:${contentType};base64,${activeBody}`}
            alt="Response body"
            className="sd-body-image"
          />
        </div>
      )}

      {/* Syntax-highlighted text content (raw / pretty modes) */}
      {useCodeViewer && (
        <CodeViewer
          code={displayContent}
          contentType={contentType}
        />
      )}

      {/* Hex dump (not highlighted, uses existing monospace style) */}
      {effectiveViewMode === "hex" && (
        <pre className="sd-body-content sd-body-content--hex">
          {displayContent}
        </pre>
      )}
    </div>
  );
}
