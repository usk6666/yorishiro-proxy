import { describe, expect, it } from "vitest";
import {
  firstGrpcDataMessage,
  firstGrpcDataPayload,
  grpcDataPayloadWithFallback,
} from "./grpcPayload.js";
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

describe("firstGrpcDataMessage variant selection", () => {
  // RecordStep saves variant=original before variant=modified at the same
  // (sequence, direction), and GetFlows orders by timestamp, so the original
  // row comes first. The modified row is the effective one.
  function variantEntry(variant: string, body: string): MessageEntry {
    const e = entry(1, "send", "data", body);
    return {
      ...e,
      id: `${e.id}-${variant}`,
      metadata: { ...e.metadata, variant },
    };
  }

  it("prefers the modified variant at the first data sequence", () => {
    const rows: MessageEntry[] = [
      entry(0, "send", "start", ""),
      variantEntry("original", "before"),
      variantEntry("modified", "after"),
      entry(2, "send", "data", "later"),
    ];
    expect(firstGrpcDataPayload(rows, "send")).toBe("after");
  });

  it("does not pick a modified row from a later sequence", () => {
    const later = {
      ...entry(2, "send", "data", "later-modified"),
      metadata: { protocol: "grpc", grpc_event: "data", variant: "modified" },
    };
    const rows: MessageEntry[] = [entry(1, "send", "data", "first"), later];
    expect(firstGrpcDataPayload(rows, "send")).toBe("first");
  });

  it("does not pick a modified row from the other direction", () => {
    const recv = {
      ...entry(1, "receive", "data", "recv-modified"),
      metadata: { protocol: "grpc", grpc_event: "data", variant: "modified" },
    };
    const rows: MessageEntry[] = [entry(1, "send", "data", "send-body"), recv];
    expect(firstGrpcDataPayload(rows, "send")).toBe("send-body");
  });
});

describe("grpcDataPayloadWithFallback", () => {
  // A gRPC flow that stopped early (send Start + Data, no receive rows) has
  // only two messages, so the server omits message_preview; the payload must
  // then come from the separately fetched messages list.
  const twoRow: MessageEntry[] = [
    entry(0, "send", "start", ""),
    entry(1, "send", "data", "early-payload"),
  ];

  it("uses the messages list when message_preview is absent", () => {
    expect(grpcDataPayloadWithFallback(undefined, twoRow, "send")).toBe(
      "early-payload",
    );
  });

  it("prefers message_preview when it carries a data message", () => {
    expect(grpcDataPayloadWithFallback(unary, twoRow, "send")).toBe(
      "CgVoZWxsbw==",
    );
  });

  it("returns an empty string when neither source has a data message", () => {
    expect(grpcDataPayloadWithFallback(null, undefined, "send")).toBe("");
  });
});
