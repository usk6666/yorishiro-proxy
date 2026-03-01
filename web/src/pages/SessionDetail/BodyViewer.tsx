/**
 * BodyViewer — Displays request/response body with Raw/Pretty/Hex modes.
 *
 * Content-Type detection for pretty-printing:
 * - JSON: formatted with indentation
 * - HTML/XML: displayed as-is in monospace (no dangerouslySetInnerHTML)
 * - Binary (base64): hex dump display
 * - Images: inline preview for image/* content types
 */

import { useState, useMemo } from "react";
import "./SessionDetailPage.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BodyViewerProps {
  body: string;
  encoding: string;
  truncated: boolean;
  headers?: Record<string, string[]>;
}

type ViewMode = "raw" | "pretty" | "hex" | "preview";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Extract Content-Type from headers (case-insensitive). */
function getContentType(headers?: Record<string, string[]>): string {
  if (!headers) return "";
  for (const [key, values] of Object.entries(headers)) {
    if (key.toLowerCase() === "content-type" && values.length > 0) {
      return values[0];
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

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function BodyViewer({ body, encoding, truncated, headers }: BodyViewerProps) {
  const contentType = getContentType(headers);
  const isBinary = encoding === "base64";
  const isImage = isImageContentType(contentType);

  // Determine available view modes
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

  // Default mode
  const defaultMode = useMemo<ViewMode>(() => {
    if (isBinary && isImage) return "preview";
    if (isBinary) return "hex";
    if (isJsonContentType(contentType)) return "pretty";
    return "raw";
  }, [isBinary, isImage, contentType]);

  const [viewMode, setViewMode] = useState<ViewMode>(defaultMode);

  // Formatted content
  const displayContent = useMemo<string>(() => {
    if (!body) return "";

    if (viewMode === "hex") {
      if (isBinary) {
        return hexDump(body);
      }
      // For text content, encode to base64 first then hex dump
      const encoded = btoa(
        Array.from(new TextEncoder().encode(body))
          .map((b) => String.fromCharCode(b))
          .join(""),
      );
      return hexDump(encoded);
    }

    if (viewMode === "pretty") {
      if (isJsonContentType(contentType)) {
        const pretty = tryPrettyJson(body);
        if (pretty) return pretty;
      }
      // For HTML/XML, return as-is (displayed in monospace <pre>)
      return body;
    }

    // raw or preview fallback
    if (isBinary) {
      return "(Binary content, base64 encoded)";
    }

    return body;
  }, [body, viewMode, isBinary, contentType]);

  if (!body) {
    return <div className="sd-empty-section">Empty body</div>;
  }

  return (
    <div className="sd-body-viewer">
      {/* View mode selector */}
      <div className="sd-body-controls">
        <div className="sd-body-mode-selector">
          {availableModes.map((mode) => (
            <button
              key={mode}
              className={`sd-body-mode-btn ${viewMode === mode ? "sd-body-mode-btn--active" : ""}`}
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
      {viewMode === "preview" && isBinary && isImage && (
        <div className="sd-body-image-preview">
          <img
            src={`data:${contentType};base64,${body}`}
            alt="Response body"
            className="sd-body-image"
          />
        </div>
      )}

      {/* Text content */}
      {viewMode !== "preview" && (
        <pre className={`sd-body-content ${viewMode === "hex" ? "sd-body-content--hex" : ""}`}>
          {displayContent}
        </pre>
      )}
    </div>
  );
}
