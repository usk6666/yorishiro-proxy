/**
 * Pure helpers for the protocol-typed resend_* dispatch in ResendPage.
 *
 * Extracted so the (typed param construction, protocol detection)
 * surface can be unit-tested without rendering React — the component
 * itself is heavyweight enough that a render-based assertion would
 * pull in jsdom / RTL. Keeping the helpers pure lets vitest exercise
 * them directly.
 *
 * The bug fixed by USK-936 was a dispatch routing problem: gRPC / WS
 * flows fell through to the legacy `resend` tool that the backend no
 * longer registers. These helpers anchor the typed routing on
 * `pickResendTool(flow.protocol)` and translate editor state into the
 * `ResendGRPCParams` / `ResendWSParams` shapes the backend expects.
 */

import { pickResendTool } from "../../lib/mcp/dispatch.js";
import type { HeaderKV, ResendGRPCData, ResendGRPCParams, ResendWSParams } from "../../lib/mcp/types.js";
import type { GrpcRequestEditorState } from "./GrpcRequestEditor.js";
import type { WsRequestEditorState } from "./WsRequestEditor.js";

/**
 * The typed resend tool that should serve a given flow protocol.
 * Wraps `pickResendTool` so callers don't have to deal with the
 * legacy "resend" fallback string when they only care about typed
 * routing.
 */
export function typedResendToolForProtocol(
  protocol: string | null | undefined,
): "resend_http" | "resend_ws" | "resend_grpc" | "resend_raw" | null {
  const tool = pickResendTool(protocol);
  if (tool === "resend") return null;
  return tool;
}

/**
 * Build a `ResendGRPCParams` payload from the editor state. Empty
 * metadata rows are filtered out so blank slots in the editor don't
 * propagate as wire metadata. Backend expects at least one message,
 * so the single editor payload is always emitted as a text-mode
 * `ResendGRPCData` entry.
 */
export function buildResendGrpcParams(
  flowId: string,
  state: GrpcRequestEditorState,
  tag: string | undefined,
): ResendGRPCParams {
  const metadata: HeaderKV[] = state.metadata
    .filter((h) => h.key.trim() !== "")
    .map((h) => ({ name: h.key, value: h.value }));

  const message: ResendGRPCData = {
    payload: state.messagePayload,
    body_encoding: "text",
  };

  return {
    flow_id: flowId,
    target_addr: state.targetAddr.trim() || undefined,
    scheme: state.scheme || undefined,
    service: state.service.trim() || undefined,
    method: state.method.trim() || undefined,
    metadata: metadata.length > 0 ? metadata : undefined,
    messages: [message],
    tag: tag && tag !== "" ? tag : undefined,
  };
}

/**
 * Build a `ResendWSParams` payload from the editor state. Mirrors the
 * single-frame semantics of the backend `resend_ws` tool: payload
 * fields are dropped on control frames that don't carry them
 * (`close`), compression toggles are only forwarded on data frames
 * (`text` / `binary`), and close-frame metadata only attaches on the
 * `close` opcode. Empty string fields are normalised to `undefined`
 * so the wire payload doesn't carry empty placeholders.
 */
export function buildResendWsParams(
  flowId: string,
  state: WsRequestEditorState,
  tag: string | undefined,
): ResendWSParams {
  const isCloseFrame = state.opcode === "close";
  const hasPayload =
    state.opcode === "text" ||
    state.opcode === "binary" ||
    state.opcode === "ping" ||
    state.opcode === "pong";

  let closeCode: number | undefined;
  if (isCloseFrame) {
    const trimmed = state.closeCode.trim();
    // Reject inputs that aren't strictly an unsigned integer.
    // `Number.parseInt("1000abc", 10)` would otherwise silently truncate to
    // 1000; the backend re-validates the WebSocket close-code range
    // (1000-4999) but we want client-side hygiene to surface obvious
    // typos before the round trip.
    if (trimmed !== "" && /^\d+$/.test(trimmed)) {
      const parsed = Number.parseInt(trimmed, 10);
      if (Number.isFinite(parsed)) closeCode = parsed;
    }
  }

  return {
    flow_id: flowId,
    target_addr: state.targetAddr.trim() || undefined,
    scheme: state.scheme || undefined,
    path: state.path || undefined,
    opcode: state.opcode,
    fin: state.fin,
    payload: hasPayload ? state.payload : undefined,
    body_encoding: hasPayload ? state.bodyEncoding : undefined,
    compressed:
      (state.opcode === "text" || state.opcode === "binary") &&
      state.compressed
        ? true
        : undefined,
    close_code: isCloseFrame ? closeCode : undefined,
    close_reason:
      isCloseFrame && state.closeReason ? state.closeReason : undefined,
    tag: tag && tag !== "" ? tag : undefined,
  };
}
