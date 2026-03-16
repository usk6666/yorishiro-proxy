/**
 * RawBytesViewer -- Read-only hex dump + text view for raw bytes in flow detail.
 *
 * Displays the raw_request / raw_response fields from flow detail as
 * hex dump or plain text.
 */

import { useMemo, useState } from "react";
import "./FlowDetailPage.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RawBytesViewerProps {
  /** Base64-encoded raw bytes. */
  rawBytes: string;
  /** Label to display (e.g., "Raw Request", "Raw Response"). */
  label: string;
}

type RawViewMode = "hex" | "text";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Decode Base64 to Uint8Array. */
function decodeBase64(b64: string): Uint8Array {
  try {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return new Uint8Array(0);
  }
}

/** Format bytes as hex dump string. */
function formatHexDump(bytes: Uint8Array): string {
  const lines: string[] = [];
  const maxBytes = Math.min(bytes.length, 8192); // Limit display to 8KB

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

/** Decode bytes to text (UTF-8 with replacement for invalid chars). */
function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function RawBytesViewer({ rawBytes, label }: RawBytesViewerProps) {
  const [viewMode, setViewMode] = useState<RawViewMode>("hex");

  const bytes = useMemo(() => decodeBase64(rawBytes), [rawBytes]);
  const hexDump = useMemo(() => formatHexDump(bytes), [bytes]);
  const textContent = useMemo(() => bytesToText(bytes), [bytes]);

  if (!rawBytes) {
    return (
      <div className="sd-empty-section">
        No {label.toLowerCase()} data available
      </div>
    );
  }

  return (
    <div className="sd-raw-bytes-viewer">
      <div className="sd-body-controls">
        <div className="sd-body-mode-selector">
          <button
            className={`sd-body-mode-btn ${viewMode === "hex" ? "sd-body-mode-btn--active" : ""}`}
            onClick={() => setViewMode("hex")}
          >
            Hex
          </button>
          <button
            className={`sd-body-mode-btn ${viewMode === "text" ? "sd-body-mode-btn--active" : ""}`}
            onClick={() => setViewMode("text")}
          >
            Text
          </button>
        </div>
        <span className="sd-body-content-type">{bytes.length} bytes</span>
      </div>

      <pre className={`sd-body-content ${viewMode === "hex" ? "sd-body-content--hex" : ""}`}>
        {viewMode === "hex" ? hexDump : textContent}
      </pre>
    </div>
  );
}
