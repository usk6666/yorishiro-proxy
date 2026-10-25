import { describe, expect, it } from "vitest";
import { firstGrpcDataMessage, firstGrpcDataPayload } from "./grpcPayload.js";
import type { MessageEntry } from "./mcp/types.js";

// Literal MessageEntry rows shaped like `query resource=messages` /
// `message_preview` for a gRPC unary RPC: Send Start + Data, Receive
// Start + Data + End (metadata.grpc_event is set by RecordStep).
function entry(
  sequence: number,
  direction: string,
  grpcEvent: string,
  body: string,
  bodyEncoding = "text",
): MessageEntry {
  return {
    id: `${direction}-${sequence}-${grpcEvent}`,
    sequence,
    direction,
    body,
    body_encoding: bodyEncoding,
    metadata: { protocol: "grpc", grpc_event: grpcEvent },
    timestamp: "2026-10-25T00:00:00Z",
  };
}

const unary: MessageEntry[] = [
  entry(0, "send", "start", ""),
  entry(1, "send", "data", "CgVoZWxsbw==", "base64"),
  entry(2, "send", "data", "second"),
  entry(0, "receive", "start", ""),
  entry(1, "receive", "data", "reply"),
  entry(2, "receive", "end", ""),
];

describe("firstGrpcDataPayload", () => {
  it("returns the first send-direction data body", () => {
    expect(firstGrpcDataPayload(unary, "send")).toBe("CgVoZWxsbw==");
  });

  it("returns the first receive-direction data body", () => {
    expect(firstGrpcDataPayload(unary, "receive")).toBe("reply");
  });

  it("ignores Start / End rows and rows without grpc_event", () => {
    const rows: MessageEntry[] = [
      entry(0, "receive", "start", "not-a-payload"),
      { ...entry(1, "receive", "data", "untagged"), metadata: {} },
      entry(2, "receive", "end", "trailer"),
    ];
    expect(firstGrpcDataPayload(rows, "receive")).toBe("");
  });

  it("returns an empty string when there is no data message", () => {
    expect(firstGrpcDataPayload([], "send")).toBe("");
    expect(firstGrpcDataPayload(undefined, "send")).toBe("");
    expect(firstGrpcDataPayload(null, "receive")).toBe("");
  });
});

describe("firstGrpcDataMessage", () => {
  it("returns the whole entry so the caller keeps body_encoding", () => {
    const m = firstGrpcDataMessage(unary, "send");
    expect(m?.body).toBe("CgVoZWxsbw==");
    expect(m?.body_encoding).toBe("base64");
  });

  it("returns undefined when there is no data message", () => {
    expect(firstGrpcDataMessage(unary.slice(0, 1), "send")).toBeUndefined();
  });
});
