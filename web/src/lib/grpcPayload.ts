/**
 * gRPC payload helpers for the flow-detail and resend views.
 *
 * The top level of a gRPC flow detail (`request_body` / `response_body`,
 * `url`, headers) is the Start message of each direction, which carries no
 * payload. The protobuf payload lives on the Data messages, which reach the
 * WebUI through `message_preview` / `query resource=messages` tagged with
 * `metadata.grpc_event === "data"`.
 */

import type { MessageEntry } from "./mcp/types.js";

/**
 * Returns the first gRPC Data message of the given direction, or undefined
 * when there is none.
 */
export function firstGrpcDataMessage(
  messages: readonly MessageEntry[] | null | undefined,
  direction: "send" | "receive",
): MessageEntry | undefined {
  if (!messages) return undefined;
  return messages.find(
    (m) => m.direction === direction && m.metadata?.grpc_event === "data",
  );
}

/**
 * Returns the body of the first gRPC Data message of the given direction,
 * or "" when there is none.
 */
export function firstGrpcDataPayload(
  messages: readonly MessageEntry[] | null | undefined,
  direction: "send" | "receive",
): string {
  return firstGrpcDataMessage(messages, direction)?.body ?? "";
}
