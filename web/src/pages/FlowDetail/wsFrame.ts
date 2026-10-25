/**
 * wsFrame -- WebSocket frame classification for WebSocketMessageList.
 *
 * Split out of WebSocketMessageList.tsx so that file exports only components
 * (React Fast Refresh). The code below is unchanged apart from exporting
 * WS_OPCODE, which the component file still uses for badge styling.
 */

import type { MessageEntry } from "../../lib/mcp/types.js";

// ---------------------------------------------------------------------------
// WebSocket Opcode Helpers
// ---------------------------------------------------------------------------

/** WebSocket opcode constants (RFC 6455 Section 11.8). */
export const WS_OPCODE = {
  CONTINUATION: 0,
  TEXT: 1,
  BINARY: 2,
  CLOSE: 8,
  PING: 9,
  PONG: 10,
} as const;

/** Map an opcode to a human-readable label. */
function opcodeLabel(opcode: number): string {
  switch (opcode) {
    case WS_OPCODE.CONTINUATION:
      return "Continuation";
    case WS_OPCODE.TEXT:
      return "Text";
    case WS_OPCODE.BINARY:
      return "Binary";
    case WS_OPCODE.CLOSE:
      return "Close";
    case WS_OPCODE.PING:
      return "Ping";
    case WS_OPCODE.PONG:
      return "Pong";
    default:
      return `0x${opcode.toString(16)}`;
  }
}

/**
 * Parse a recorded decimal metadata value (e.g. ws_opcode, ws_close_code).
 * Returns null for a missing or non-decimal value so that `Number("")`
 * (= 0) cannot fabricate a Continuation opcode or a status code.
 */
function parseDecimal(value: string | undefined): number | null {
  if (value === undefined || !/^[0-9]{1,6}$/.test(value)) return null;
  return Number(value);
}

// ---------------------------------------------------------------------------
// Close Frame Helpers (RFC 6455 Section 7.4)
// ---------------------------------------------------------------------------

/** Well-known WebSocket close status codes. */
const CLOSE_CODES: Record<number, string> = {
  1000: "Normal Closure",
  1001: "Going Away",
  1002: "Protocol Error",
  1003: "Unsupported Data",
  1005: "No Status Received",
  1006: "Abnormal Closure",
  1007: "Invalid Payload Data",
  1008: "Policy Violation",
  1009: "Message Too Big",
  1010: "Mandatory Extension",
  1011: "Internal Error",
  1012: "Service Restart",
  1013: "Try Again Later",
  1014: "Bad Gateway",
  1015: "TLS Handshake",
};

/** Parse a Close frame body into status code and reason. */
function parseCloseFrame(body: string, encoding: string): WSCloseInfo | null {
  if (!body) return null;

  let bytes: Uint8Array;
  try {
    if (encoding === "base64") {
      const binary = atob(body);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
    } else {
      // Text-encoded Close frame data -- try interpreting as raw bytes
      const encoder = new TextEncoder();
      bytes = encoder.encode(body);
    }
  } catch {
    return null;
  }

  // Close frame must have at least 2 bytes for the status code.
  if (bytes.length < 2) return null;

  const code = (bytes[0] << 8) | bytes[1];
  const reason =
    bytes.length > 2
      ? new TextDecoder().decode(bytes.slice(2))
      : "";
  const codeDescription = CLOSE_CODES[code] ?? "Unknown";

  return { code, reason, codeDescription };
}

// ---------------------------------------------------------------------------
// Frame classification (recorded Metadata keys)
// ---------------------------------------------------------------------------

/** Close frame status as recorded by the proxy. */
export interface WSCloseInfo {
  /** Close status code; null when the frame carried none (recorded as "0"). */
  code: number | null;
  /** Human-readable description of code ("no status code" when null). */
  codeDescription: string;
  /** Close reason; "" when the frame carried none. */
  reason: string;
}

/** Display classification for one message row of a WS stream. */
export interface WSFrameInfo {
  /** WS opcode from metadata.ws_opcode; null for non-frame rows. */
  opcode: number | null;
  /** Badge label (Text / Binary / Close / ... / HTTP / ?). */
  label: string;
  /** Close status; non-null only for Close frames. */
  close: WSCloseInfo | null;
}

/**
 * Classify a message entry of a WS stream for display.
 *
 * Reads the Metadata keys the proxy's RecordStep writes: ws_opcode for
 * every frame, ws_close_code / ws_close_reason for Close frames. The Close
 * body is parsed only when those keys are absent. Rows without ws_opcode
 * (the HTTP upgrade request / 101 response in the same stream) get a
 * neutral label instead of an opcode.
 */
export function wsFrameInfo(msg: MessageEntry): WSFrameInfo {
  const opcode = parseDecimal(msg.metadata?.ws_opcode);
  if (opcode === null) {
    const isHttp = Boolean(msg.method) || Boolean(msg.status_code);
    return { opcode: null, label: isHttp ? "HTTP" : "?", close: null };
  }
  let close: WSCloseInfo | null = null;
  if (opcode === WS_OPCODE.CLOSE) {
    close = closeFromMetadata(msg) ?? parseCloseFrame(msg.body, msg.body_encoding);
  }
  return { opcode, label: opcodeLabel(opcode), close };
}

/** Close status from ws_close_code / ws_close_reason; null when absent. */
function closeFromMetadata(msg: MessageEntry): WSCloseInfo | null {
  const code = parseDecimal(msg.metadata?.ws_close_code);
  if (code === null) return null;
  const reason = msg.metadata?.ws_close_reason ?? "";
  // RFC 6455 §7.4: a Close frame without a status code is recorded as "0".
  if (code === 0) {
    return { code: null, codeDescription: "no status code", reason };
  }
  return { code, codeDescription: CLOSE_CODES[code] ?? "Unknown", reason };
}
