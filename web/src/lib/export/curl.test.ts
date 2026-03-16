import { describe, expect, it } from "vitest";
import { generateCurl } from "./curl";
import type { FlowDetailResult } from "../mcp/types";

/**
 * Helper to create a minimal FlowDetailResult for testing.
 * Only the fields used by generateCurl are required.
 */
function makeFlow(
  overrides: Partial<FlowDetailResult> = {}
): FlowDetailResult {
  return {
    id: "test-id",
    conn_id: "conn-1",
    protocol: "http",
    flow_type: "http",
    state: "complete",
    method: "GET",
    url: "http://example.com/",
    request_headers: null,
    request_body: "",
    request_body_encoding: "",
    response_status_code: 200,
    response_headers: null,
    response_body: "",
    response_body_encoding: "",
    request_body_truncated: false,
    response_body_truncated: false,
    timestamp: "2025-01-01T00:00:00Z",
    duration_ms: 100,
    message_count: 0,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Basic generation
// ---------------------------------------------------------------------------

describe("generateCurl", () => {
  it("generates a simple GET request", () => {
    const result = generateCurl(makeFlow());
    expect(result).toBe("curl 'http://example.com/'");
  });

  it("omits -X for GET without body", () => {
    const result = generateCurl(makeFlow({ method: "GET" }));
    expect(result).not.toContain("-X");
  });

  it("emits -X for non-GET methods without body", () => {
    const result = generateCurl(makeFlow({ method: "DELETE" }));
    expect(result).toContain("-X 'DELETE'");
  });

  it("omits -X for POST with body (implied)", () => {
    const result = generateCurl(
      makeFlow({
        method: "POST",
        request_body: "data",
        request_headers: {
          "Content-Type": ["application/x-www-form-urlencoded"],
        },
      })
    );
    expect(result).not.toContain("-X");
    expect(result).toContain("-d 'data'");
  });

  it("emits -X for PUT with body", () => {
    const result = generateCurl(
      makeFlow({
        method: "PUT",
        request_body: '{"key":"value"}',
        request_headers: { "Content-Type": ["application/json"] },
      })
    );
    expect(result).toContain("-X 'PUT'");
    expect(result).toContain("-d '{\"key\":\"value\"}'");
  });

  // ---------------------------------------------------------------------------
  // Headers
  // ---------------------------------------------------------------------------

  it("includes request headers", () => {
    const result = generateCurl(
      makeFlow({
        request_headers: {
          "X-Custom": ["value1"],
          Accept: ["application/json"],
        },
      })
    );
    expect(result).toContain("-H 'X-Custom: value1'");
    expect(result).toContain("-H 'Accept: application/json'");
  });

  it("emits multiple values for the same header", () => {
    const result = generateCurl(
      makeFlow({
        request_headers: { Cookie: ["a=1", "b=2"] },
      })
    );
    expect(result).toContain("-H 'Cookie: a=1'");
    expect(result).toContain("-H 'Cookie: b=2'");
  });

  it("omits Content-Length header", () => {
    const result = generateCurl(
      makeFlow({
        request_headers: { "Content-Length": ["42"] },
      })
    );
    expect(result).not.toContain("Content-Length");
  });

  // ---------------------------------------------------------------------------
  // Body
  // ---------------------------------------------------------------------------

  it("uses --data-binary for binary content types", () => {
    const result = generateCurl(
      makeFlow({
        method: "POST",
        request_body: "binarydata",
        request_headers: {
          "Content-Type": ["application/octet-stream"],
        },
      })
    );
    expect(result).toContain("--data-binary");
  });

  it("uses -d for JSON content type", () => {
    const result = generateCurl(
      makeFlow({
        method: "POST",
        request_body: '{"a":1}',
        request_headers: { "Content-Type": ["application/json"] },
      })
    );
    expect(result).toContain("-d");
    expect(result).not.toContain("--data-binary");
  });

  it("uses -d for XML content type", () => {
    const result = generateCurl(
      makeFlow({
        method: "POST",
        request_body: "<root/>",
        request_headers: { "Content-Type": ["application/xml"] },
      })
    );
    expect(result).toContain("-d");
  });

  it("uses placeholder for base64-encoded body", () => {
    const result = generateCurl(
      makeFlow({
        method: "POST",
        request_body: "AAEC",
        request_body_encoding: "base64",
      })
    );
    expect(result).toContain("<base64-encoded body omitted>");
  });

  // ---------------------------------------------------------------------------
  // Shell escaping
  // ---------------------------------------------------------------------------

  it("escapes single quotes in URL", () => {
    const result = generateCurl(
      makeFlow({ url: "http://example.com/path?q=it's" })
    );
    expect(result).toContain("'http://example.com/path?q=it'\\''s'");
  });

  it("escapes single quotes in header values", () => {
    const result = generateCurl(
      makeFlow({
        request_headers: { "X-Val": ["it's a test"] },
      })
    );
    expect(result).toContain("'X-Val: it'\\''s a test'");
  });

  it("escapes single quotes in body", () => {
    const result = generateCurl(
      makeFlow({
        method: "POST",
        request_body: "value='test'",
        request_headers: {
          "Content-Type": ["application/x-www-form-urlencoded"],
        },
      })
    );
    expect(result).toContain("'value='\\''test'\\'''");
  });

  // ---------------------------------------------------------------------------
  // Formatting
  // ---------------------------------------------------------------------------

  it("uses line-continuation for commands with more than 2 parts", () => {
    const result = generateCurl(
      makeFlow({
        request_headers: { Accept: ["text/html"] },
      })
    );
    expect(result).toContain(" \\\n  ");
  });

  it("does not use line-continuation for simple commands", () => {
    const result = generateCurl(makeFlow());
    expect(result).not.toContain("\\");
  });

  // ---------------------------------------------------------------------------
  // Null / missing fields
  // ---------------------------------------------------------------------------

  it("handles null request_headers", () => {
    const result = generateCurl(makeFlow({ request_headers: null }));
    expect(result).toBe("curl 'http://example.com/'");
  });

  it("handles missing method (defaults to GET)", () => {
    const result = generateCurl(
      makeFlow({ method: undefined as unknown as string })
    );
    expect(result).toContain("curl");
    expect(result).not.toContain("-X");
  });
});
