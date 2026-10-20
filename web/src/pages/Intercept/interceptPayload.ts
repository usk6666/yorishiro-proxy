/**
 * Pure helpers that turn an intercept queue entry into editor state and
 * editor state into `intercept` tool arguments. Kept free of React so the
 * payload shape can be tested against the server's real InputSchema.
 */

import type {
  InterceptActionParams,
  InterceptPhase,
  InterceptQueueEntry,
} from "../../lib/mcp/types.js";
import type { HeaderRow } from "./HeaderEditor.js";

/** Detail-panel mode: structured L7 editors or the raw bytes editor. */
export type DetailViewMode = "structured" | "raw";

/** Editable state for the selected queue entry. */
export interface InterceptEditState {
  phase: InterceptPhase;
  method: string;
  url: string;
  headers: HeaderRow[];
  body: string;
  statusCode: number;
  rawBytes: string;
}

/** Resolve the effective phase of an entry, defaulting to "request" for backward compat. */
export function resolvePhase(entry: InterceptQueueEntry): InterceptPhase {
  return entry.phase ?? "request";
}

/** Populate editor state from a queue entry. */
export function entryToEditState(entry: InterceptQueueEntry): InterceptEditState {
  const phase = resolvePhase(entry);
  const rawBytes = entry.raw_bytes ? entry.raw_bytes : "";
  if (phase === "websocket_frame") {
    return { phase, method: "", url: "", headers: [], body: entry.body, statusCode: 0, rawBytes };
  }
  if (phase === "response") {
    return {
      phase,
      method: "",
      url: "",
      statusCode: entry.status_code ?? 200,
      body: entry.body,
      headers: flattenHeaders(entry.headers),
      rawBytes,
    };
  }
  return {
    phase,
    method: entry.method ?? "",
    url: entry.url ?? "",
    body: entry.body,
    statusCode: 0,
    headers: flattenHeaders(entry.headers),
    rawBytes,
  };
}

/** Build the `intercept` tool arguments for a modify_and_forward action. */
export function buildModifyAndForwardArgs(
  entry: InterceptQueueEntry,
  edit: InterceptEditState,
  mode: DetailViewMode = "structured",
): InterceptActionParams {
  const phase = resolvePhase(entry);
  if (mode === "raw") {
    return {
      action: "modify_and_forward",
      params: {
        intercept_id: entry.id,
        mode: "raw",
        raw_override_base64: edit.rawBytes,
      },
    };
  }
  if (phase === "websocket_frame") {
    return {
      action: "modify_and_forward",
      params: {
        intercept_id: entry.id,
        override_body: edit.body,
      },
    };
  }
  if (phase === "response") {
    return {
      action: "modify_and_forward",
      params: {
        intercept_id: entry.id,
        override_status: edit.statusCode,
        override_response_headers: mergeHeaders(edit.headers),
        override_response_body: edit.body,
      },
    };
  }
  return {
    action: "modify_and_forward",
    params: {
      intercept_id: entry.id,
      override_method: edit.method,
      override_url: edit.url,
      override_headers: mergeHeaders(edit.headers),
      override_body: edit.body,
    },
  };
}

/** Whether Modify & Forward is offered for the entry. */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function canModify(_entry: InterceptQueueEntry): boolean {
  return true;
}

/** Whether the raw bytes editor is offered for the entry. */
export function rawModeAllowed(entry: InterceptQueueEntry): boolean {
  return entry.raw_bytes_available ?? false;
}

/**
 * Whether the outgoing arguments may echo Output-Filter-masked content
 * back onto the wire.
 */
/* eslint-disable @typescript-eslint/no-unused-vars */
export function maskingWarning(
  _args: InterceptActionParams,
  _outputRules: number,
): boolean {
/* eslint-enable @typescript-eslint/no-unused-vars */
  return false;
}

/** Flatten headers Record to editable HeaderRow array. */
function flattenHeaders(headers: Record<string, string[]> | undefined): HeaderRow[] {
  if (!headers) return [];
  const rows: HeaderRow[] = [];
  for (const [name, values] of Object.entries(headers)) {
    for (const value of values) {
      rows.push({ id: crypto.randomUUID(), name, value });
    }
  }
  return rows;
}

/** Merge HeaderRow array to Record with comma concatenation (RFC 7230). */
function mergeHeaders(rows: HeaderRow[]): Record<string, string> {
  const merged: Record<string, string> = {};
  for (const h of rows) {
    const key = h.name.trim();
    if (key) {
      if (key in merged) {
        merged[key] = merged[key] + ", " + h.value;
      } else {
        merged[key] = h.value;
      }
    }
  }
  return merged;
}
