/**
 * Initial text for the ResendPage raw HTTP editor. Kept free of React so
 * it can be tested against recorded `query resource=flow` fixtures.
 */

import type { FlowDetailResult } from "../../lib/mcp/types.js";

/** Check if a flow is HTTP/2, gRPC, or gRPC-Web (no raw bytes stored). */
function isHttp2Flow(flow: FlowDetailResult): boolean {
  const proto = (flow.protocol || "").toLowerCase();
  return proto === "http/2" || proto === "h2" || proto === "grpc" || proto === "grpc-web";
}

/**
 * Decode base64-encoded raw request bytes to a text string.
 * Returns null if decoding fails or the data is empty.
 */
function decodeRawRequest(base64Data: string): string | null {
  if (!base64Data) return null;
  try {
    return atob(base64Data);
  } catch {
    return null;
  }
}

/**
 * Reconstruct an HTTP/1.1 raw message from parsed flow data.
 * Used for HTTP/2, gRPC, and gRPC-Web flows that don't store raw bytes.
 *
 * Format:
 *   {Method} {RequestURI} HTTP/1.1\r\n
 *   Host: {host}\r\n
 *   {Headers}\r\n
 *   \r\n
 *   {Body}
 */
export function reconstructHttp11(flow: FlowDetailResult): string {
  const method = flow.method || "GET";
  const urlStr = flow.url || "/";

  // Extract request URI (path + query) and host from the URL.
  let requestUri = "/";
  let host = "";
  try {
    const parsed = new URL(urlStr);
    requestUri = parsed.pathname + parsed.search;
    host = parsed.host;
  } catch {
    // If URL parsing fails, use the raw URL as-is.
    requestUri = urlStr;
  }

  const lines: string[] = [];
  lines.push(`${method} ${requestUri} HTTP/1.1`);

  // Add Host header first if not already in request_headers.
  const hasHostHeader = flow.request_headers
    ? Object.keys(flow.request_headers).some((k) => k.toLowerCase() === "host")
    : false;

  if (!hasHostHeader && host) {
    lines.push(`Host: ${host}`);
  }

  // Add all recorded headers.
  if (flow.request_headers) {
    for (const [key, values] of Object.entries(flow.request_headers)) {
      for (const value of values) {
        lines.push(`${key}: ${value}`);
      }
    }
  }

  // Empty line to separate headers from body.
  lines.push("");

  // Join with \r\n (HTTP line endings).
  let raw = lines.join("\r\n");

  // Append body if present.
  const bodyText = flow.request_body || "";
  if (bodyText) {
    raw += "\r\n" + bodyText;
  }

  return raw;
}

/**
 * Text the raw HTTP editor starts with for a recorded flow: the recorded
 * HTTP/1.x request bytes when they are text, otherwise an HTTP/1.1
 * reconstruction from the parsed fields.
 */
export function initialRawHttpText(flow: FlowDetailResult): string {
  if (!isHttp2Flow(flow) && flow.raw_request) {
    // HTTP/1.x: decode the recorded raw bytes.
    const decoded = decodeRawRequest(flow.raw_request);
    return decoded ?? reconstructHttp11(flow);
  }
  // HTTP/2 or no raw bytes: reconstruct HTTP/1.1 from parsed data.
  return reconstructHttp11(flow);
}
