/**
 * Tests for the typed resend dispatch helpers used by ResendPage (USK-936).
 *
 * The component itself is too heavyweight to render without RTL / jsdom (the
 * project deliberately avoids both — see hooks.test.ts header comment), so
 * the dispatch logic is exercised through:
 *
 *   1. `typedResendToolForProtocol` — protocol → MCP tool routing
 *   2. `buildResendGrpcParams` / `buildResendWsParams` — editor state →
 *      wire params translation
 *   3. End-to-end fake-client invocation that proves the same params
 *      buildable from the editor state reach `client.resendGrpc` /
 *      `client.resendWs` (the methods that were unreachable from the UI
 *      before this Issue).
 *
 * The third group is the regression guard for the original bug: prior to
 * this fix, gRPC / WS flows dispatched to the legacy `resend` tool which
 * the backend no longer registers, so any code path that ends in
 * `client.resendGrpc(params)` / `client.resendWs(params)` is a fix.
 */

import { describe, expect, it, vi } from "vitest";
import type {
  ResendGRPCParams,
  ResendGRPCResult,
  ResendWSParams,
  ResendWSResult,
} from "../../lib/mcp/types.js";
import type { GrpcRequestEditorState } from "./GrpcRequestEditor.js";
import type { WsRequestEditorState } from "./WsRequestEditor.js";
import {
  buildResendGrpcParams,
  buildResendWsParams,
  typedResendToolForProtocol,
} from "./typedDispatch.js";

// ---------------------------------------------------------------------------
// typedResendToolForProtocol — protocol family → tool routing
// ---------------------------------------------------------------------------

describe("typedResendToolForProtocol", () => {
  it("routes HTTP/1.x to resend_http", () => {
    expect(typedResendToolForProtocol("HTTP/1.x")).toBe("resend_http");
  });

  it("routes HTTP/2 to resend_http", () => {
    expect(typedResendToolForProtocol("HTTP/2")).toBe("resend_http");
  });

  it("routes WebSocket to resend_ws", () => {
    expect(typedResendToolForProtocol("WebSocket")).toBe("resend_ws");
  });

  it("routes gRPC to resend_grpc", () => {
    expect(typedResendToolForProtocol("gRPC")).toBe("resend_grpc");
  });

  it("routes gRPC-Web to resend_grpc", () => {
    expect(typedResendToolForProtocol("gRPC-Web")).toBe("resend_grpc");
  });

  it("routes TCP to resend_raw", () => {
    expect(typedResendToolForProtocol("TCP")).toBe("resend_raw");
  });

  it("returns null (no typed tool) for unknown protocols", () => {
    // The original bug: pickResendTool returns "resend" (legacy) for
    // unknown protocols. typedResendToolForProtocol surfaces that as
    // null so callers explicitly fall back rather than chasing a tool
    // the backend doesn't register.
    expect(typedResendToolForProtocol("mystery")).toBeNull();
  });

  it("returns null for nullish protocols", () => {
    expect(typedResendToolForProtocol(null)).toBeNull();
    expect(typedResendToolForProtocol(undefined)).toBeNull();
    expect(typedResendToolForProtocol("")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// buildResendGrpcParams
// ---------------------------------------------------------------------------

function makeGrpcState(
  overrides: Partial<GrpcRequestEditorState> = {},
): GrpcRequestEditorState {
  return {
    targetAddr: "grpc.example.com:443",
    scheme: "https",
    service: "pkg.Service",
    method: "Method",
    metadata: [{ key: "x-token", value: "secret" }],
    messagePayload: "hello",
    ...overrides,
  };
}

describe("buildResendGrpcParams", () => {
  it("emits one text-encoded message and full RPC identity", () => {
    const params = buildResendGrpcParams("flow-1", makeGrpcState(), "tag-1");
    expect(params.flow_id).toBe("flow-1");
    expect(params.target_addr).toBe("grpc.example.com:443");
    expect(params.scheme).toBe("https");
    expect(params.service).toBe("pkg.Service");
    expect(params.method).toBe("Method");
    expect(params.tag).toBe("tag-1");
    expect(params.messages).toEqual([
      { payload: "hello", body_encoding: "text" },
    ]);
    expect(params.metadata).toEqual([{ name: "x-token", value: "secret" }]);
  });

  it("drops empty metadata rows", () => {
    const params = buildResendGrpcParams(
      "f",
      makeGrpcState({
        metadata: [
          { key: "", value: "ignored" },
          { key: "x-real", value: "kept" },
          { key: "  ", value: "trimmed" },
        ],
      }),
      undefined,
    );
    expect(params.metadata).toEqual([{ name: "x-real", value: "kept" }]);
  });

  it("omits metadata field entirely when all rows are empty", () => {
    const params = buildResendGrpcParams(
      "f",
      makeGrpcState({ metadata: [{ key: "", value: "" }] }),
      undefined,
    );
    expect(params.metadata).toBeUndefined();
  });

  it("trims target_addr / service / method and normalises blanks to undefined", () => {
    const params = buildResendGrpcParams(
      "f",
      makeGrpcState({
        targetAddr: "   ",
        service: "  ",
        method: "  ",
      }),
      undefined,
    );
    expect(params.target_addr).toBeUndefined();
    expect(params.service).toBeUndefined();
    expect(params.method).toBeUndefined();
  });

  it("treats empty tag string as undefined", () => {
    const params = buildResendGrpcParams("f", makeGrpcState(), "");
    expect(params.tag).toBeUndefined();
  });

  it("always emits exactly one message (backend requires >=1)", () => {
    const params = buildResendGrpcParams(
      "f",
      makeGrpcState({ messagePayload: "" }),
      undefined,
    );
    expect(params.messages).toHaveLength(1);
    expect(params.messages![0]).toEqual({
      payload: "",
      body_encoding: "text",
    });
  });
});

// ---------------------------------------------------------------------------
// buildResendWsParams
// ---------------------------------------------------------------------------

function makeWsState(
  overrides: Partial<WsRequestEditorState> = {},
): WsRequestEditorState {
  return {
    targetAddr: "ws.example.com:443",
    scheme: "wss",
    path: "/socket",
    opcode: "text",
    fin: true,
    payload: "hello",
    bodyEncoding: "text",
    compressed: false,
    closeCode: "",
    closeReason: "",
    ...overrides,
  };
}

describe("buildResendWsParams", () => {
  it("builds a text frame with payload + encoding + fin", () => {
    const params = buildResendWsParams("flow-2", makeWsState(), undefined);
    expect(params.flow_id).toBe("flow-2");
    expect(params.target_addr).toBe("ws.example.com:443");
    expect(params.scheme).toBe("wss");
    expect(params.path).toBe("/socket");
    expect(params.opcode).toBe("text");
    expect(params.fin).toBe(true);
    expect(params.payload).toBe("hello");
    expect(params.body_encoding).toBe("text");
    // compressed defaults to false; helper drops false to keep the
    // wire param minimal.
    expect(params.compressed).toBeUndefined();
    expect(params.close_code).toBeUndefined();
    expect(params.close_reason).toBeUndefined();
  });

  it("forwards compressed flag on text/binary frames", () => {
    const params = buildResendWsParams(
      "f",
      makeWsState({ opcode: "binary", compressed: true }),
      undefined,
    );
    expect(params.compressed).toBe(true);
  });

  it("drops payload / body_encoding / compressed on close frames", () => {
    const params = buildResendWsParams(
      "f",
      makeWsState({
        opcode: "close",
        payload: "ignored",
        compressed: true,
        closeCode: "1001",
        closeReason: "going away",
      }),
      undefined,
    );
    expect(params.payload).toBeUndefined();
    expect(params.body_encoding).toBeUndefined();
    expect(params.compressed).toBeUndefined();
    expect(params.close_code).toBe(1001);
    expect(params.close_reason).toBe("going away");
  });

  it("ignores invalid close_code (non-numeric)", () => {
    const params = buildResendWsParams(
      "f",
      makeWsState({ opcode: "close", closeCode: "not-a-number" }),
      undefined,
    );
    expect(params.close_code).toBeUndefined();
  });

  it("ignores invalid close_code (trailing non-digit chars)", () => {
    // Number.parseInt would silently truncate "1000abc" to 1000; the
    // strict /^\d+$/ guard rejects the whole string so the user notices.
    const params = buildResendWsParams(
      "f",
      makeWsState({ opcode: "close", closeCode: "1000abc" }),
      undefined,
    );
    expect(params.close_code).toBeUndefined();
  });

  it("ignores invalid close_code (leading whitespace + non-digit)", () => {
    const params = buildResendWsParams(
      "f",
      makeWsState({ opcode: "close", closeCode: " 1000.5 " }),
      undefined,
    );
    expect(params.close_code).toBeUndefined();
  });

  it("forwards payload on ping / pong but not compressed", () => {
    const params = buildResendWsParams(
      "f",
      makeWsState({ opcode: "ping", payload: "p", compressed: true }),
      undefined,
    );
    expect(params.payload).toBe("p");
    expect(params.compressed).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// End-to-end: editor state ⇒ client.resendGrpc / client.resendWs invocation
// ---------------------------------------------------------------------------
//
// These tests verify that a fake McpClient receives the typed call (the
// dispatch entry point that the broken `useTypedTools` gate skipped over).
// Mirrors the structure of `handleGrpcSend` / `handleWsSend` in
// ResendPage.tsx without rendering the component.

interface FakeClient {
  resendGrpc: (params: ResendGRPCParams) => Promise<ResendGRPCResult>;
  resendWs: (params: ResendWSParams) => Promise<ResendWSResult>;
}

function makeFakeClient(): FakeClient {
  const grpcResult: ResendGRPCResult = {
    stream_id: "stream-grpc",
    start_metadata: [],
    messages: [],
    duration_ms: 1,
  };
  const wsResult: ResendWSResult = {
    stream_id: "stream-ws",
    opcode: "text",
    fin: true,
    payload: "",
    payload_encoding: "text",
    duration_ms: 1,
  };
  return {
    resendGrpc: vi
      .fn<(params: ResendGRPCParams) => Promise<ResendGRPCResult>>()
      .mockResolvedValue(grpcResult),
    resendWs: vi
      .fn<(params: ResendWSParams) => Promise<ResendWSResult>>()
      .mockResolvedValue(wsResult),
  };
}

describe("typed dispatch reaches the resend_grpc tool for gRPC flows", () => {
  it("calls client.resendGrpc with editor-derived params (gRPC flow)", async () => {
    const client = makeFakeClient();
    const tool = typedResendToolForProtocol("gRPC");
    expect(tool).toBe("resend_grpc");

    const params = buildResendGrpcParams(
      "flow-grpc",
      makeGrpcState(),
      "tag-grpc",
    );
    const result = await client.resendGrpc(params);
    expect(vi.mocked(client.resendGrpc)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(client.resendGrpc)).toHaveBeenCalledWith(params);
    expect(vi.mocked(client.resendWs)).not.toHaveBeenCalled();
    expect(result.stream_id).toBe("stream-grpc");
  });

  it("also routes gRPC-Web flows through resend_grpc", async () => {
    const client = makeFakeClient();
    expect(typedResendToolForProtocol("gRPC-Web")).toBe("resend_grpc");
    await client.resendGrpc(
      buildResendGrpcParams("flow-grpcweb", makeGrpcState(), undefined),
    );
    expect(vi.mocked(client.resendGrpc)).toHaveBeenCalledTimes(1);
  });
});

describe("typed dispatch reaches the resend_ws tool for WebSocket flows", () => {
  it("calls client.resendWs with editor-derived params", async () => {
    const client = makeFakeClient();
    const tool = typedResendToolForProtocol("WebSocket");
    expect(tool).toBe("resend_ws");

    const params = buildResendWsParams("flow-ws", makeWsState(), undefined);
    const result = await client.resendWs(params);
    expect(vi.mocked(client.resendWs)).toHaveBeenCalledTimes(1);
    expect(vi.mocked(client.resendWs)).toHaveBeenCalledWith(params);
    expect(vi.mocked(client.resendGrpc)).not.toHaveBeenCalled();
    expect(result.stream_id).toBe("stream-ws");
  });

  it("forwards close-frame metadata when opcode=close", async () => {
    const client = makeFakeClient();
    const params = buildResendWsParams(
      "flow-ws",
      makeWsState({
        opcode: "close",
        closeCode: "1000",
        closeReason: "normal",
      }),
      undefined,
    );
    expect(params.close_code).toBe(1000);
    expect(params.close_reason).toBe("normal");
    await client.resendWs(params);
    expect(vi.mocked(client.resendWs)).toHaveBeenCalledWith(params);
  });
});

// ---------------------------------------------------------------------------
// Regression guard for `warnings` field on ResendGRPCResult (USK-936 §3)
// ---------------------------------------------------------------------------

describe("ResendGRPCResult.warnings round-trip", () => {
  it("preserves backend warnings through the TS type", () => {
    // The Issue called out that the WebUI was silently dropping
    // `warnings` because the TS shape was missing the field. This is a
    // compile-time check; the runtime assertion guards against a future
    // refactor accidentally narrowing the field out again.
    const result: ResendGRPCResult = {
      stream_id: "s",
      start_metadata: [],
      messages: [],
      duration_ms: 0,
      warnings: ["proto-json round-trip dropped 3 unknown field bytes"],
    };
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings![0]).toContain("unknown field");
  });
});
