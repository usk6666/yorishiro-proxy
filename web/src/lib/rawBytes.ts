/**
 * Shared utilities for raw bytes display and editing.
 *
 * Used by both RawBytesViewer (read-only) and RawBytesEditor (editable).
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type RawViewMode = "hex" | "text";

// ---------------------------------------------------------------------------
// Size limits
// ---------------------------------------------------------------------------

/** Default max bytes for hex dump in the read-only viewer (8 KB). */
export const HEX_DUMP_VIEWER_MAX = 8192;

/** Max bytes for hex dump in the editor (64 KB). Beyond this a warning is shown. */
export const HEX_DUMP_EDITOR_WARN = 64 * 1024;

/** Absolute max for hex editor (1 MB). Beyond this hex mode is disabled. */
export const HEX_DUMP_EDITOR_MAX = 1024 * 1024;

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

/** Decode Base64 to Uint8Array. */
export function decodeBase64(b64: string): Uint8Array {
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
export function encodeBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// ---------------------------------------------------------------------------
// Hex dump
// ---------------------------------------------------------------------------

/**
 * Format bytes as hex dump string.
 *
 * @param bytes - The raw bytes to format.
 * @param maxSize - Optional limit on number of bytes to display.
 *                  When set, a truncation notice is appended if exceeded.
 */
export function formatHexDump(bytes: Uint8Array, maxSize?: number): string {
  const lines: string[] = [];
  const limit = maxSize != null ? Math.min(bytes.length, maxSize) : bytes.length;

  for (let offset = 0; offset < limit; offset += 16) {
    const hexParts: string[] = [];
    const asciiParts: string[] = [];

    for (let i = 0; i < 16; i++) {
      if (offset + i < limit) {
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

  if (maxSize != null && bytes.length > limit) {
    lines.push(`... (${bytes.length - limit} more bytes truncated)`);
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

/** Decode bytes to text (UTF-8 with replacement for invalid chars). */
export function bytesToText(bytes: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}
