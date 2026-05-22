import { describe, expect, it } from "vitest";
import { buildHar } from "./har";
import type { FlowDetailResult } from "../mcp/types";

/**
 * Helper to create a minimal FlowDetailResult for testing.
 * Only the fields used by buildHar are required.
 */
function makeFlow(
  overrides: Partial<FlowDetailResult> = {},
): FlowDetailResult {
  return {
    id: "test-id",
    conn_id: "conn-1",
    protocol: "HTTP/1.x",
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
// Baseline HTTP/1.x
// ---------------------------------------------------------------------------

describe("buildHar", () => {
  it("builds a minimal HAR for a GET / 200 flow", () => {
    const har = buildHar(makeFlow());
    expect(har.log.version).toBe("1.2");
    expect(har.log.entries).toHaveLength(1);

    const entry = har.log.entries[0];
    expect(entry.request.method).toBe("GET");
    expect(entry.request.url).toBe("http://example.com/");
    expect(entry.request.httpVersion).toBe("HTTP/1.1");
    expect(entry.response.status).toBe(200);
    expect(entry.response.httpVersion).toBe("HTTP/1.1");
  });

  it("emits regular HTTP/1.x request headers", () => {
    const har = buildHar(
      makeFlow({
        request_headers: {
          Accept: ["application/json"],
          "X-Custom": ["a", "b"],
        },
      }),
    );
    const headers = har.log.entries[0].request.headers;
    expect(headers).toEqual([
      { name: "Accept", value: "application/json" },
      { name: "X-Custom", value: "a" },
      { name: "X-Custom", value: "b" },
    ]);
  });

  it("emits regular HTTP/1.x response headers", () => {
    const har = buildHar(
      makeFlow({
        response_headers: {
          "Content-Type": ["text/html"],
          "Set-Cookie": ["a=1", "b=2"],
        },
      }),
    );
    const headers = har.log.entries[0].response.headers;
    expect(headers).toEqual([
      { name: "Content-Type", value: "text/html" },
      { name: "Set-Cookie", value: "a=1" },
      { name: "Set-Cookie", value: "b=2" },
    ]);
  });

  // -------------------------------------------------------------------------
  // HTTP/2 pseudo-headers
  //
  // HAR 1.2 §6.2.4 / §6.2.6 forbid pseudo-headers from request.headers[] and
  // response.headers[]. Strict HAR validators reject entries containing them.
  // The semantic content is already represented in request.method /
  // request.url / response.status.
  // -------------------------------------------------------------------------

  it("strips request pseudo-headers from HTTP/2 request.headers[]", () => {
    const har = buildHar(
      makeFlow({
        protocol: "HTTP/2",
        method: "POST",
        url: "https://example.com/api",
        request_headers: {
          ":method": ["POST"],
          ":path": ["/api"],
          ":authority": ["example.com"],
          ":scheme": ["https"],
          "content-type": ["application/json"],
          "user-agent": ["test-agent/1.0"],
        },
      }),
    );
    const headers = har.log.entries[0].request.headers;
    const names = headers.map((h) => h.name);
    expect(names).not.toContain(":method");
    expect(names).not.toContain(":path");
    expect(names).not.toContain(":authority");
    expect(names).not.toContain(":scheme");
    expect(names).toContain("content-type");
    expect(names).toContain("user-agent");
  });

  it("strips :status from HTTP/2 response.headers[]", () => {
    const har = buildHar(
      makeFlow({
        protocol: "HTTP/2",
        response_status_code: 200,
        response_headers: {
          ":status": ["200"],
          "content-type": ["application/json"],
          "content-length": ["42"],
        },
      }),
    );
    const headers = har.log.entries[0].response.headers;
    const names = headers.map((h) => h.name);
    expect(names).not.toContain(":status");
    expect(names).toContain("content-type");
    expect(names).toContain("content-length");
  });

  it("strips pseudo-headers regardless of casing", () => {
    const har = buildHar(
      makeFlow({
        protocol: "HTTP/2",
        request_headers: {
          ":METHOD": ["GET"],
          ":Path": ["/api"],
        },
        response_headers: {
          ":STATUS": ["200"],
        },
      }),
    );
    expect(har.log.entries[0].request.headers).toEqual([]);
    expect(har.log.entries[0].response.headers).toEqual([]);
  });

  it("populates request.method / request.url / response.status from top-level fields even when pseudo-headers are filtered", () => {
    const har = buildHar(
      makeFlow({
        protocol: "HTTP/2",
        method: "DELETE",
        url: "https://example.com/items/42",
        response_status_code: 204,
        request_headers: {
          ":method": ["DELETE"],
          ":path": ["/items/42"],
          ":authority": ["example.com"],
          ":scheme": ["https"],
        },
        response_headers: {
          ":status": ["204"],
        },
      }),
    );
    const entry = har.log.entries[0];
    expect(entry.request.method).toBe("DELETE");
    expect(entry.request.url).toBe("https://example.com/items/42");
    expect(entry.request.httpVersion).toBe("h2");
    expect(entry.response.status).toBe(204);
    expect(entry.response.httpVersion).toBe("h2");
  });

  // -------------------------------------------------------------------------
  // Bodies / postData / content
  // -------------------------------------------------------------------------

  it("includes request body in postData", () => {
    const har = buildHar(
      makeFlow({
        method: "POST",
        request_body: '{"a":1}',
        request_headers: { "Content-Type": ["application/json"] },
      }),
    );
    const req = har.log.entries[0].request;
    expect(req.postData).toEqual({
      mimeType: "application/json",
      text: '{"a":1}',
    });
    expect(req.bodySize).toBe('{"a":1}'.length);
  });

  it("preserves base64 request body verbatim", () => {
    const har = buildHar(
      makeFlow({
        method: "POST",
        request_body: "AAEC",
        request_body_encoding: "base64",
      }),
    );
    expect(har.log.entries[0].request.postData?.text).toBe("AAEC");
  });

  it("marks base64 response body with encoding", () => {
    const har = buildHar(
      makeFlow({
        response_body: "AAEC",
        response_body_encoding: "base64",
      }),
    );
    const content = har.log.entries[0].response.content;
    expect(content.text).toBe("AAEC");
    expect(content.encoding).toBe("base64");
  });

  // -------------------------------------------------------------------------
  // Query string + redirect URL
  // -------------------------------------------------------------------------

  it("extracts query string from the URL", () => {
    const har = buildHar(makeFlow({ url: "http://example.com/?a=1&b=two" }));
    expect(har.log.entries[0].request.queryString).toEqual([
      { name: "a", value: "1" },
      { name: "b", value: "two" },
    ]);
  });

  it("populates redirectURL from Location header", () => {
    const har = buildHar(
      makeFlow({
        response_status_code: 302,
        response_headers: { Location: ["https://example.com/next"] },
      }),
    );
    expect(har.log.entries[0].response.redirectURL).toBe(
      "https://example.com/next",
    );
  });

  // -------------------------------------------------------------------------
  // Null guards
  // -------------------------------------------------------------------------

  it("handles null request_headers and response_headers", () => {
    const har = buildHar(
      makeFlow({ request_headers: null, response_headers: null }),
    );
    expect(har.log.entries[0].request.headers).toEqual([]);
    expect(har.log.entries[0].response.headers).toEqual([]);
  });
});
