/**
 * Pure helpers that turn an intercept queue entry into editor state and
 * editor state into `intercept` tool arguments. Kept free of React so the
 * payload shape can be tested against the server's real InputSchema.
 *
 * Wire fidelity (MITM Principles 1 / 3): headers stay an ordered
 * [{name, value}] list with the wire casing and duplicates; the URL is
 * edited as the scheme / authority / path / raw_query parts the server
 * holds, never re-parsed or normalized.
 */

import { decodeBase64, encodeBase64 } from "../../lib/rawBytes.js";
import type {
  HeaderKV,
  InterceptActionParams,
  InterceptBodyEncoding,
  InterceptHTTPModify,
  InterceptQueueEntry,
} from "../../lib/mcp/types.js";
import type { HeaderRow } from "./HeaderEditor.js";

/**
 * What a held entry is, for display and editing. HTTP holds split by
 * direction into request / response; every other protocol maps 1:1.
 */
export type InterceptKind =
  | "request"
  | "response"
  | "websocket_frame"
  | "grpc_start"
  | "grpc_data"
  | "grpc_end"
  | "sse"
  | "raw"
  | "unknown";

/** Editable state for the selected queue entry. */
export interface InterceptEditState {
  kind: InterceptKind;
  // HTTP request side
  method: string;
  scheme: string;
  authority: string;
  path: string;
  /** Raw query string, without a leading "?". */
  rawQuery: string;
  // HTTP response side
  /**
   * Status code as typed into the editor. Kept as a string so a cleared
   * or non-integer field reads as "unchanged" rather than as status 0.
   */
  status: string;
  statusReason: string;
  // HTTP headers (both sides)
  headers: HeaderRow[];
  /** HTTP body or WebSocket payload, in `bodyEncoding`. */
  body: string;
  bodyEncoding: InterceptBodyEncoding;
  /** Raw holds only: the chunk bytes, base64-encoded. */
  rawBytes: string;
}

/** Token prefix the built-in Output Filter presets substitute for masked values. */
const MASK_TOKEN = "[MASKED:";

/** Classify a queue entry. */
export function entryKind(entry: InterceptQueueEntry): InterceptKind {
  switch (entry.protocol) {
    case "http":
      return entry.direction === "receive" ? "response" : "request";
    case "websocket":
      return "websocket_frame";
    case "grpc_start":
      return "grpc_start";
    case "grpc_data":
      return "grpc_data";
    case "grpc_end":
      return "grpc_end";
    case "sse":
      return "sse";
    case "raw":
      return "raw";
    default:
      return "unknown";
  }
}

/** Populate editor state from a queue entry. */
export function entryToEditState(
  entry: InterceptQueueEntry,
  newId: () => string = () => crypto.randomUUID(),
): InterceptEditState {
  const kind = entryKind(entry);
  const http = entry.http ?? {};
  const state: InterceptEditState = {
    kind,
    method: http.method ?? "",
    scheme: http.scheme ?? "",
    authority: http.authority ?? "",
    path: http.path ?? "",
    rawQuery: http.raw_query ?? "",
    status: http.status !== undefined ? String(http.status) : "",
    statusReason: http.status_reason ?? "",
    headers: (http.headers ?? []).map((h) => ({ id: newId(), name: h.name, value: h.value })),
    body: http.body ?? "",
    bodyEncoding: http.body_encoding ?? "text",
    rawBytes: "",
  };
  if (kind === "websocket_frame") {
    state.body = entry.ws?.payload ?? "";
    state.bodyEncoding = entry.ws?.payload_encoding ?? "text";
  }
  if (kind === "raw") {
    state.rawBytes = toBase64(entry.raw?.bytes ?? "", entry.raw?.bytes_encoding);
  }
  return state;
}

/**
 * Build the `intercept` tool arguments for a modify_and_forward action.
 * Only fields that differ from the held entry are sent (an omitted field
 * keeps the held value); a changed header list is sent in full because
 * the server treats `headers` as a full replacement.
 */
export function buildModifyAndForwardArgs(
  entry: InterceptQueueEntry,
  edit: InterceptEditState,
): InterceptActionParams {
  const base: InterceptActionParams = {
    action: "modify_and_forward",
    params: { intercept_id: entry.id },
  };
  switch (entryKind(entry)) {
    case "request":
    case "response":
      return { ...base, http: buildHTTPModify(entry, edit) };
    case "websocket_frame": {
      const ws = entry.ws ?? {};
      if (edit.body === (ws.payload ?? "")) return { ...base, ws: {} };
      return { ...base, ws: { payload: edit.body, body_encoding: edit.bodyEncoding } };
    }
    case "raw": {
      const held = toBase64(entry.raw?.bytes ?? "", entry.raw?.bytes_encoding);
      if (edit.rawBytes === held) return { ...base, raw: {} };
      return { ...base, raw: { bytes_override: edit.rawBytes, bytes_encoding: "base64" } };
    }
    default:
      throw new Error(`Modify & Forward is not supported for ${entry.protocol} holds`);
  }
}

function buildHTTPModify(entry: InterceptQueueEntry, edit: InterceptEditState): InterceptHTTPModify {
  const held = entry.http ?? {};
  const out: InterceptHTTPModify = {};
  if (edit.kind === "request") {
    if (edit.method !== (held.method ?? "")) out.method = edit.method;
    if (edit.scheme !== (held.scheme ?? "")) out.scheme = edit.scheme;
    if (edit.authority !== (held.authority ?? "")) out.authority = edit.authority;
    if (edit.path !== (held.path ?? "")) out.path = edit.path;
    if (edit.rawQuery !== (held.raw_query ?? "")) out.raw_query = edit.rawQuery;
  } else {
    const status = parseStatus(edit.status);
    if (status !== undefined && status !== held.status) out.status = status;
    if (edit.statusReason !== (held.status_reason ?? "")) out.status_reason = edit.statusReason;
  }
  const headers = headerRowsToKVs(edit.headers);
  if (!sameHeaders(headers, held.headers ?? [])) out.headers = headers;
  if (edit.body !== (held.body ?? "")) {
    out.body = edit.body;
    out.body_encoding = edit.bodyEncoding;
  }
  return out;
}

/**
 * Editor status field to a status code. Empty or non-integer input yields
 * undefined (leave the held status unchanged) so a cleared field never
 * becomes status 0. Out-of-range integers are passed through deliberately:
 * the intercept tool stays permissive for pentest use.
 */
function parseStatus(value: string): number | undefined {
  if (!/^\d+$/.test(value)) return undefined;
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : undefined;
}

/** Whether Modify & Forward is offered for the entry. */
export function canModify(entry: InterceptQueueEntry): boolean {
  const kind = entryKind(entry);
  return kind === "request" || kind === "response" || kind === "websocket_frame" || kind === "raw";
}

/**
 * Whether the raw bytes editor is offered for the entry. Only raw holds
 * are edited as bytes: on other holds the server's raw override path
 * replaces the L7 message with a RawMessage and breaks the connection.
 */
export function rawModeAllowed(entry: InterceptQueueEntry): boolean {
  return entry.protocol === "raw";
}

/**
 * Whether the outgoing arguments may echo Output-Filter-masked content
 * back onto the wire. The queue view is masked by the Output Filter but
 * carries no per-entry flag, so this warns when Output Filter rules are
 * active (config `safety_filter.output_rules`) and the arguments send
 * headers or a body / payload / bytes, or when the sent content contains
 * the `[MASKED:` token the built-in presets substitute.
 *
 * `outputRules > 0` is the authoritative trigger. The token scan is only a
 * secondary signal (e.g. while the config is still loading); base64
 * content is decoded before scanning, and content that is not valid
 * base64 is skipped. This only warns, it never blocks.
 */
export function maskingWarning(args: InterceptActionParams, outputRules: number): boolean {
  const content: string[] = [];
  if (args.http?.headers) {
    for (const h of args.http.headers) content.push(h.name, h.value);
  }
  if (args.http?.body !== undefined) {
    content.push(scanText(args.http.body, args.http.body_encoding));
  }
  if (args.ws?.payload !== undefined) {
    content.push(scanText(args.ws.payload, args.ws.body_encoding));
  }
  if (args.raw?.bytes_override !== undefined) {
    content.push(scanText(args.raw.bytes_override, args.raw.bytes_encoding));
  }
  if (content.length === 0) return false;
  if (outputRules > 0) return true;
  return content.some((c) => c.includes(MASK_TOKEN));
}

/**
 * Content as text for the mask-token scan. Base64 is decoded (lossy
 * UTF-8 is fine: the token is ASCII); invalid base64 scans as "".
 */
function scanText(data: string, encoding: string | undefined): string {
  if (encoding !== "base64") return data;
  // decodeBase64 wraps atob in try/catch and yields no bytes on bad input.
  return new TextDecoder().decode(decodeBase64(data));
}

/**
 * Editor rows to the wire list. Rows left completely blank (an added row
 * nobody filled in) are dropped; everything else is sent verbatim, so the
 * server rejects a nameless header instead of the UI silently fixing it.
 */
function headerRowsToKVs(rows: HeaderRow[]): HeaderKV[] {
  return rows
    .filter((r) => r.name !== "" || r.value !== "")
    .map((r) => ({ name: r.name, value: r.value }));
}

function sameHeaders(a: HeaderKV[], b: HeaderKV[]): boolean {
  return a.length === b.length && a.every((h, i) => h.name === b[i].name && h.value === b[i].value);
}

function toBase64(data: string, encoding: InterceptBodyEncoding | undefined): string {
  if (encoding === "base64") return data;
  return encodeBase64(new TextEncoder().encode(data));
}

