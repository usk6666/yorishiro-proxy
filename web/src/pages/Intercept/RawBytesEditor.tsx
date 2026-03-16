/**
 * RawBytesEditor -- Editable hex dump + text view for raw bytes in intercept.
 *
 * Supports two sub-modes:
 * - Hex: traditional hex dump with byte-level editing
 * - Text: plain text editing of the raw bytes
 *
 * Input/output is Base64-encoded raw bytes.
 *
 * Editing uses a "draft" pattern: the textarea value is local state that is
 * only synchronised back to the parent on blur. This avoids cursor-jump and
 * mid-edit reformatting issues that occur with fully-controlled hex input.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  type RawViewMode,
  bytesToText,
  decodeBase64,
  encodeBase64,
  formatHexDump,
  HEX_DUMP_EDITOR_MAX,
  HEX_DUMP_EDITOR_WARN,
} from "../../lib/rawBytes";

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

// ---------------------------------------------------------------------------
// Helpers (editor-only)
// ---------------------------------------------------------------------------

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

  // Draft state -- local textarea values that are NOT re-derived on every keystroke.
  const [draftHex, setDraftHex] = useState("");
  const [draftText, setDraftText] = useState("");

  // Track the last rawBytes value we synchronised FROM so we can detect
  // external changes (e.g. switching to a different intercept item).
  const lastSyncedRef = useRef(rawBytes);

  const bytes = useMemo(() => decodeBase64(rawBytes), [rawBytes]);

  // Derive whether hex mode should be limited / disabled based on byte length.
  const hexDisabled = bytes.length > HEX_DUMP_EDITOR_MAX;
  const hexWarning =
    bytes.length > HEX_DUMP_EDITOR_WARN && bytes.length <= HEX_DUMP_EDITOR_MAX;

  // Synchronise drafts when rawBytes changes externally.
  useEffect(() => {
    if (rawBytes !== lastSyncedRef.current) {
      lastSyncedRef.current = rawBytes;
      const newBytes = decodeBase64(rawBytes);
      setDraftHex(formatHexDump(newBytes));
      setDraftText(bytesToText(newBytes));
      setParseError(null);
    }
  }, [rawBytes]);

  // Initial population of drafts on mount.
  useEffect(() => {
    const initBytes = decodeBase64(rawBytes);
    setDraftHex(formatHexDump(initBytes));
    setDraftText(bytesToText(initBytes));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // --- Hex mode handlers ---

  const handleHexInput = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setDraftHex(e.target.value);
  }, []);

  const handleHexBlur = useCallback(() => {
    const parsed = parseHexDump(draftHex);
    if (parsed) {
      setParseError(null);
      const newBase64 = encodeBase64(parsed);
      lastSyncedRef.current = newBase64;
      onChange(newBase64);
      // Re-format the draft to a clean hex dump so it looks tidy after blur.
      setDraftHex(formatHexDump(parsed));
      setDraftText(bytesToText(parsed));
    } else {
      setParseError("Invalid hex dump format");
    }
  }, [draftHex, onChange]);

  // --- Text mode handlers ---

  const handleTextInput = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setDraftText(e.target.value);
  }, []);

  const handleTextBlur = useCallback(() => {
    setParseError(null);
    const newBytes = textToBytes(draftText);
    const newBase64 = encodeBase64(newBytes);
    lastSyncedRef.current = newBase64;
    onChange(newBase64);
    // Keep hex draft in sync so switching modes shows the latest data.
    setDraftHex(formatHexDump(newBytes));
  }, [draftText, onChange]);

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
          className={`intercept-mode-btn ${viewMode === "hex" ? "intercept-mode-btn--active" : ""}`}
          onClick={() => setViewMode("hex")}
        >
          Hex
        </button>
        <button
          className={`intercept-mode-btn ${viewMode === "text" ? "intercept-mode-btn--active" : ""}`}
          onClick={() => setViewMode("text")}
        >
          Text
        </button>
      </div>

      {parseError && (
        <div className="intercept-raw-error">{parseError}</div>
      )}

      {hexWarning && viewMode === "hex" && (
        <div className="intercept-raw-error">
          Large payload ({Math.round(bytes.length / 1024)} KB). Hex editing may be slow.
        </div>
      )}

      {hexDisabled && viewMode === "hex" ? (
        <div className="intercept-raw-error">
          Payload too large for hex editing ({Math.round(bytes.length / 1024)} KB &gt; {Math.round(HEX_DUMP_EDITOR_MAX / 1024)} KB).
          Please use Text mode instead.
        </div>
      ) : viewMode === "hex" ? (
        <textarea
          className="intercept-body-editor intercept-raw-hex-editor"
          value={draftHex}
          onChange={handleHexInput}
          onBlur={handleHexBlur}
          spellCheck={false}
          placeholder="No raw bytes available"
        />
      ) : (
        <textarea
          className="intercept-body-editor"
          value={draftText}
          onChange={handleTextInput}
          onBlur={handleTextBlur}
          spellCheck={false}
          placeholder="No raw bytes available"
        />
      )}
    </div>
  );
}
