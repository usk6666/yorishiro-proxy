/**
 * gRPC payload helpers for the flow-detail and resend views.
 *
 * Not implemented yet (USK-1343 red-phase scaffolding).
 */

import type { MessageEntry } from "./mcp/types.js";

export function firstGrpcDataMessage(
  _messages: readonly MessageEntry[] | null | undefined,
  _direction: "send" | "receive",
): MessageEntry | undefined {
  return undefined;
}

export function firstGrpcDataPayload(
  _messages: readonly MessageEntry[] | null | undefined,
  _direction: "send" | "receive",
): string {
  return "";
}
