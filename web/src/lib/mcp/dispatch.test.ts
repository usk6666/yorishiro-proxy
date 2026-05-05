/**
 * Tests for the pure dispatcher helpers in dispatch.ts.
 *
 * Verifies:
 * - protocol -> FlowDetail component kind dispatch (pickFlowDetailKind)
 * - protocol -> resend_* MCP tool dispatch (pickResendTool)
 * - null-guard regression: helpers do not throw when fed sparse FlowDetailResult
 * - plugin_introspect sort + redact-key passthrough smoke test
 */

import { describe, expect, it } from "vitest";
import {
  formatVarsValue,
  hasResponse,
  isStreamingFlow,
  pickFlowDetailKind,
  pickResendTool,
  sortIntrospectedPlugins,
} from "./dispatch.js";
import type {
  FlowDetailResult,
  PluginIntrospectResult,
} from "./types.js";

// ---------------------------------------------------------------------------
// pickFlowDetailKind
// ---------------------------------------------------------------------------

describe("pickFlowDetailKind", () => {
  it("returns 'http' for HTTP/1.x", () => {
    expect(pickFlowDetailKind("HTTP/1.x")).toBe("http");
  });

  it("returns 'http' for HTTPS", () => {
    expect(pickFlowDetailKind("HTTPS")).toBe("http");
  });

  it("returns 'http' for HTTP/2", () => {
    expect(pickFlowDetailKind("HTTP/2")).toBe("http");
  });

  it("returns 'http' for lowercase 'h2'", () => {
    expect(pickFlowDetailKind("h2")).toBe("http");
  });

  it("returns 'ws' for WebSocket", () => {
    expect(pickFlowDetailKind("WebSocket")).toBe("ws");
  });

  it("returns 'ws' for ws", () => {
    expect(pickFlowDetailKind("ws")).toBe("ws");
  });

  it("returns 'grpc' for gRPC", () => {
    expect(pickFlowDetailKind("gRPC")).toBe("grpc");
  });

  it("returns 'grpc' for gRPC-Web", () => {
    expect(pickFlowDetailKind("gRPC-Web")).toBe("grpc");
  });

  it("returns 'sse' for SSE", () => {
    expect(pickFlowDetailKind("SSE")).toBe("sse");
  });

  it("returns 'raw' for TCP", () => {
    expect(pickFlowDetailKind("TCP")).toBe("raw");
  });

  it("returns 'raw' for unknown protocol (no throw)", () => {
    expect(pickFlowDetailKind("mystery-protocol")).toBe("raw");
  });

  it("returns 'raw' for null protocol (no throw)", () => {
    expect(pickFlowDetailKind(null)).toBe("raw");
  });

  it("returns 'raw' for undefined protocol (no throw)", () => {
    expect(pickFlowDetailKind(undefined)).toBe("raw");
  });

  it("returns 'raw' for empty string (no throw)", () => {
    expect(pickFlowDetailKind("")).toBe("raw");
  });
});

// ---------------------------------------------------------------------------
// pickResendTool
// ---------------------------------------------------------------------------

describe("pickResendTool", () => {
  it("returns 'resend_http' for HTTP/1.x", () => {
    expect(pickResendTool("HTTP/1.x")).toBe("resend_http");
  });

  it("returns 'resend_http' for HTTPS", () => {
    expect(pickResendTool("HTTPS")).toBe("resend_http");
  });

  it("returns 'resend_http' for HTTP/2", () => {
    expect(pickResendTool("HTTP/2")).toBe("resend_http");
  });

  it("returns 'resend_ws' for WebSocket", () => {
    expect(pickResendTool("WebSocket")).toBe("resend_ws");
  });

  it("returns 'resend_grpc' for gRPC", () => {
    expect(pickResendTool("gRPC")).toBe("resend_grpc");
  });

  it("returns 'resend_grpc' for gRPC-Web", () => {
    expect(pickResendTool("gRPC-Web")).toBe("resend_grpc");
  });

  it("returns 'resend_raw' for TCP", () => {
    expect(pickResendTool("TCP")).toBe("resend_raw");
  });

  it("returns 'resend_raw' for raw", () => {
    expect(pickResendTool("raw")).toBe("resend_raw");
  });

  it("returns legacy 'resend' for unknown protocol", () => {
    expect(pickResendTool("mystery-protocol")).toBe("resend");
  });

  it("returns legacy 'resend' for null protocol", () => {
    expect(pickResendTool(null)).toBe("resend");
  });

  it("returns legacy 'resend' for undefined protocol", () => {
    expect(pickResendTool(undefined)).toBe("resend");
  });
});

// ---------------------------------------------------------------------------
// Null-guard regression: minimal/sparse FlowDetailResult must not crash
// ---------------------------------------------------------------------------

/**
 * Construct a FlowDetailResult with only the strictly required wire fields
 * present. Optional fields are deliberately omitted to exercise the null
 * guards in helpers that consume the shape.
 */
function makeMinimalFlow(
  overrides: Partial<FlowDetailResult> = {},
): FlowDetailResult {
  return {
    id: "minimal",
    conn_id: "",
    protocol: "",
    flow_type: "unary",
    state: "active",
    method: "",
    url: "",
    request_headers: null,
    request_body: "",
    request_body_encoding: "",
    response_status_code: 0,
    response_headers: null,
    response_body: "",
    response_body_encoding: "",
    request_body_truncated: false,
    response_body_truncated: false,
    timestamp: "",
    duration_ms: 0,
    message_count: 0,
    ...overrides,
  };
}

describe("null-guard regression", () => {
  it("isStreamingFlow tolerates null", () => {
    expect(isStreamingFlow(null)).toBe(false);
  });

  it("isStreamingFlow tolerates undefined", () => {
    expect(isStreamingFlow(undefined)).toBe(false);
  });

  it("isStreamingFlow returns false for unary flow", () => {
    expect(isStreamingFlow(makeMinimalFlow())).toBe(false);
  });

  it("isStreamingFlow returns true for ws_stream flow", () => {
    expect(
      isStreamingFlow(makeMinimalFlow({ flow_type: "ws_stream" })),
    ).toBe(true);
  });

  it("isStreamingFlow does not throw on missing flow_type", () => {
    // flow_type cast to undefined to simulate a sparse server response.
    // The helper coerces missing to "" which is != "unary", so it returns
    // true (the conservative choice: render the streaming UI rather than
    // hiding messages on a malformed response).
    const sparse = { flow_type: undefined } as unknown as Pick<
      FlowDetailResult,
      "flow_type"
    >;
    expect(() => isStreamingFlow(sparse)).not.toThrow();
  });

  it("hasResponse tolerates null flow", () => {
    expect(hasResponse(null)).toBe(false);
  });

  it("hasResponse tolerates undefined flow", () => {
    expect(hasResponse(undefined)).toBe(false);
  });

  it("hasResponse returns false for minimal flow with no response data", () => {
    expect(hasResponse(makeMinimalFlow())).toBe(false);
  });

  it("hasResponse returns true when status_code is set", () => {
    expect(
      hasResponse(makeMinimalFlow({ response_status_code: 200 })),
    ).toBe(true);
  });

  it("hasResponse returns true when response_headers has entries", () => {
    expect(
      hasResponse(
        makeMinimalFlow({
          response_headers: { "content-type": ["text/plain"] },
        }),
      ),
    ).toBe(true);
  });

  it("hasResponse tolerates undefined response_status_code on a sparse object", () => {
    const sparse = {
      ...makeMinimalFlow(),
      response_status_code: undefined,
    } as unknown as FlowDetailResult;
    expect(hasResponse(sparse)).toBe(false);
  });

  it("pickFlowDetailKind on a minimal flow returns 'raw' (empty protocol)", () => {
    expect(pickFlowDetailKind(makeMinimalFlow().protocol)).toBe("raw");
  });

  it("pickResendTool on a minimal flow returns legacy 'resend' (empty protocol)", () => {
    expect(pickResendTool(makeMinimalFlow().protocol)).toBe("resend");
  });
});

// ---------------------------------------------------------------------------
// sortIntrospectedPlugins + formatVarsValue (Plugins page helpers)
// ---------------------------------------------------------------------------

describe("sortIntrospectedPlugins", () => {
  it("returns empty list for null", () => {
    expect(sortIntrospectedPlugins(null)).toEqual([]);
  });

  it("returns empty list for undefined", () => {
    expect(sortIntrospectedPlugins(undefined)).toEqual([]);
  });

  it("returns empty list for malformed result", () => {
    const bad = { plugins: "not-an-array" } as unknown as PluginIntrospectResult;
    expect(sortIntrospectedPlugins(bad)).toEqual([]);
  });

  it("sorts enabled plugins before disabled", () => {
    const result: PluginIntrospectResult = {
      plugins: [
        { name: "z-disabled", path: "/z", enabled: false, registrations: [] },
        { name: "a-enabled", path: "/a", enabled: true, registrations: [] },
      ],
    };
    const sorted = sortIntrospectedPlugins(result);
    expect(sorted.map((p) => p.name)).toEqual(["a-enabled", "z-disabled"]);
  });

  it("sorts alphabetically within enabled group", () => {
    const result: PluginIntrospectResult = {
      plugins: [
        { name: "b", path: "/b", enabled: true, registrations: [] },
        { name: "a", path: "/a", enabled: true, registrations: [] },
        { name: "c", path: "/c", enabled: true, registrations: [] },
      ],
    };
    const sorted = sortIntrospectedPlugins(result);
    expect(sorted.map((p) => p.name)).toEqual(["a", "b", "c"]);
  });

  it("never mutates the input array", () => {
    const original: PluginIntrospectResult = {
      plugins: [
        { name: "z", path: "/z", enabled: false, registrations: [] },
        { name: "a", path: "/a", enabled: true, registrations: [] },
      ],
    };
    const before = original.plugins.map((p) => p.name).join(",");
    sortIntrospectedPlugins(original);
    const after = original.plugins.map((p) => p.name).join(",");
    expect(after).toBe(before);
  });
});

describe("formatVarsValue (redact passthrough)", () => {
  it("preserves the literal '<redacted>' string verbatim", () => {
    expect(formatVarsValue("<redacted>")).toBe("<redacted>");
  });

  it("does not unescape HTML/angle-bracket characters", () => {
    expect(formatVarsValue("<script>alert(1)</script>")).toBe(
      "<script>alert(1)</script>",
    );
  });

  it("renders numbers as strings", () => {
    expect(formatVarsValue(42)).toBe("42");
  });

  it("renders booleans as strings", () => {
    expect(formatVarsValue(true)).toBe("true");
    expect(formatVarsValue(false)).toBe("false");
  });

  it("renders null as empty string", () => {
    expect(formatVarsValue(null)).toBe("");
  });

  it("renders undefined as empty string", () => {
    expect(formatVarsValue(undefined)).toBe("");
  });

  it("renders objects as compact JSON", () => {
    expect(formatVarsValue({ a: 1, b: "x" })).toBe('{"a":1,"b":"x"}');
  });

  it("renders arrays as compact JSON", () => {
    expect(formatVarsValue([1, 2, 3])).toBe("[1,2,3]");
  });

  it("preserves <redacted> embedded inside an object", () => {
    expect(formatVarsValue({ token: "<redacted>" })).toBe(
      '{"token":"<redacted>"}',
    );
  });
});
