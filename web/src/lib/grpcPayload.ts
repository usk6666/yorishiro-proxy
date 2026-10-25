/**
 * gRPC payload helpers for the flow-detail and resend views.
 *
 * The top level of a gRPC flow detail (`request_body` / `response_body`,
 * `url`, headers) is the Start message of each direction, which carries no
 * payload. The protobuf payload lives on the Data messages, which reach the
 * WebUI through `message_preview` / `query resource=messages` tagged with
 * `metadata.grpc_event === "data"`.
 *
 * The server only emits `message_preview` for flows with more than two
 * messages, so a gRPC flow that stopped early (send Start + Data, no
 * receive rows) has no preview: callers must fall back to the messages
 * list (`grpcDataPayloadWithFallback`).
 */

import type { MessageEntry } from "./mcp/types.js";

/**
 * Returns the first gRPC Data message of the given direction, or undefined
 * when there is none.
 *
 * When that Data message was modified by intercept / transform, both the
 * variant=original and variant=modified rows share its (sequence,
 * direction); the original is recorded first. The modified row is the
 * effective one (same rule as pickVariantAtSequence in
 * internal/mcp/query_tool.go), so it is preferred.
 */
export function firstGrpcDataMessage(
  messages: readonly MessageEntry[] | null | undefined,
  direction: "send" | "receive",
): MessageEntry | undefined {
  if (!messages) return undefined;
  const isData = (m: MessageEntry) =>
    m.direction === direction && m.metadata?.grpc_event === "data";
  const first = messages.find(isData);
  if (!first) return undefined;
  const modified = messages.find(
    (m) =>
      isData(m) &&
      m.sequence === first.sequence &&
      m.metadata?.variant === "modified",
  );
  return modified ?? first;
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

/**
 * Like firstGrpcDataPayload, but looks in `message_preview` first and falls
 * back to the separately fetched messages list (`query resource=messages`)
 * when the preview is absent or carries no Data message of that direction.
 */
export function grpcDataPayloadWithFallback(
  preview: readonly MessageEntry[] | null | undefined,
  messages: readonly MessageEntry[] | null | undefined,
  direction: "send" | "receive",
): string {
  return (
    firstGrpcDataMessage(preview, direction) ??
    firstGrpcDataMessage(messages, direction)
  )?.body ?? "";
}
