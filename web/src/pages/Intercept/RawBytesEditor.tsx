/**
 * RawBytesEditor -- Editable hex dump + text view for raw bytes in intercept.
 *
 * Supports two sub-modes:
 * - Hex: traditional hex dump with byte-level editing
 * - Text: plain text editing of the raw bytes
 *
 * Input/output is Base64-encoded raw bytes.
 */

import { useCallback, useMemo, useState } from "react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RawBytesEditorProps {
  /** Base64-encoded raw bytes. */
  rawBytes: string;
  /** Called when bytes are modified. Value is Base64. */
  onChange: (base64: string) => void;
  /** Size hint for display. */
  size?: number;
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

/** Encode Uint8Array to Base64. */
function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/** Format bytes as hex dump string. */
function formatHexDump(bytes: Uint8Array): string {
  const lines: string[] = [];

  for (let offset = 0; offset < bytes.length; offset += 16) {
    const hexParts: string[] = [];
    const asciiParts: string[] = [];

    for (let i = 0; i < 16; i++) {
      if (offset + i < bytes.length) {
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

  return lines.join("\n");
}

/** Parse hex dump back to bytes. Extracts hex values from the middle column. */
function parseHexDump(text: string): Uint8Array | null {
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  const byteValues: number[] = [];

  for (const line of lines) {
    // Match the offset and hex portion: "00000000  xx xx xx ..."
    const match = line.match(/^[0-9a-fA-F]{8}\s{2}(.+?)\s{2}\|/);
    if (!match) continue;

    const hexPart = match[1];
    const hexTokens = hexPart.split(/\s+/).filter((t) => t.length > 0);

    for (const token of hexTokens) {
      if (token.length === 2 && /^[0-9a-fA-F]{2}$/.test(token)) {
        byteValues.push(parseInt(token, 16));
      }
    }
  }

  if (byteValues.length === 0 && lines.length > 0) {
    return null; // Parse error
  }

  return new Uint8Array(byteValues);
}

/** Decode bytes to text (UTF-8 with replacement for invalid chars). */
function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

/** Encode text to bytes (UTF-8). */
function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function RawBytesEditor({ rawBytes, onChange, size }: RawBytesEditorProps) {
  const [viewMode, setViewMode] = useState<RawViewMode>("hex");
  const [parseError, setParseError] = useState<string | null>(null);

  const bytes = useMemo(() => decodeBase64(rawBytes), [rawBytes]);
  const hexDump = useMemo(() => formatHexDump(bytes), [bytes]);
  const textContent = useMemo(() => bytesToText(bytes), [bytes]);

  const handleHexChange = useCallback(
    (value: string) => {
      const parsed = parseHexDump(value);
      if (parsed) {
        setParseError(null);
        onChange(encodeBase64(parsed));
      } else {
        setParseError("Invalid hex dump format");
      }
    },
    [onChange],
  );

  const handleTextChange = useCallback(
    (value: string) => {
      setParseError(null);
      const newBytes = textToBytes(value);
      onChange(encodeBase64(newBytes));
    },
    [onChange],
  );

  return (
    <div className="intercept-section">
      <div className="intercept-section-title">
        Raw Bytes
        {size != null && (
          <span className="intercept-raw-size"> ({size} bytes)</span>
        )}
      </div>

      {/* Sub-mode selector */}
      <div className="intercept-raw-mode-selector">
        <button
          className={`intercept-raw-mode-btn ${viewMode === "hex" ? "intercept-raw-mode-btn--active" : ""}`}
          onClick={() => setViewMode("hex")}
        >
          Hex
        </button>
        <button
          className={`intercept-raw-mode-btn ${viewMode === "text" ? "intercept-raw-mode-btn--active" : ""}`}
          onClick={() => setViewMode("text")}
        >
          Text
        </button>
      </div>

      {parseError && (
        <div className="intercept-raw-error">{parseError}</div>
      )}

      {viewMode === "hex" ? (
        <textarea
          className="intercept-body-editor intercept-raw-hex-editor"
          value={hexDump}
          onChange={(e) => handleHexChange(e.target.value)}
          spellCheck={false}
          placeholder="No raw bytes available"
        />
      ) : (
        <textarea
          className="intercept-body-editor"
          value={textContent}
          onChange={(e) => handleTextChange(e.target.value)}
          spellCheck={false}
          placeholder="No raw bytes available"
        />
      )}
    </div>
  );
}
