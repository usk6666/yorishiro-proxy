/**
 * Generate a cURL command string from flow request data.
 *
 * The generated command reproduces the captured HTTP request for use in
 * terminals, scripts, or other tooling common in vulnerability assessments.
 */

import type { FlowDetailResult } from "../mcp/types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Escape a string for use inside single quotes in a shell command.
 * The standard technique is to end the current single-quoted segment,
 * insert an escaped single quote, and re-open the single-quoted segment.
 */
function shellEscape(value: string): string {
  return value.replace(/'/g, "'\\''");
}

/**
 * Headers that curl sends automatically and should generally be omitted
 * from the explicit -H flags to keep the output readable.
 */
const IMPLICIT_HEADERS = new Set(["content-length"]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Build a cURL command string from a FlowDetailResult.
 *
 * Design choices:
 * - Uses single-quote escaping (POSIX sh compatible).
 * - -X is only emitted when the method is not GET (or not POST when a
 *   body is present, since -d / --data-binary implies POST).
 * - Body is emitted via -d for text content types, --data-binary otherwise.
 * - Each flag is placed on its own line with a trailing backslash for
 *   readability.
 */
export function generateCurl(flow: FlowDetailResult): string {
  const parts: string[] = ["curl"];

  const method = (flow.method ?? "GET").toUpperCase();
  const url = flow.url ?? "";

  // Method flag: curl defaults to GET, or POST when a body is present.
  const hasBody = !!flow.request_body;
  const impliedMethod = hasBody ? "POST" : "GET";
  if (method !== impliedMethod) {
    parts.push("-X '" + shellEscape(method) + "'");
  }

  // URL
  parts.push("'" + shellEscape(url) + "'");

  // Headers
  const headers = flow.request_headers ?? {};
  for (const [name, values] of Object.entries(headers)) {
    if (IMPLICIT_HEADERS.has(name.toLowerCase())) continue;

    for (const v of values) {
      parts.push("-H '" + shellEscape(name + ": " + v) + "'");
    }
  }

  // Body
  if (hasBody) {
    const contentType = getContentType(headers);
    const isText = isTextContentType(contentType);
    const flag = isText ? "-d" : "--data-binary";

    // If the body encoding is base64, we cannot include it verbatim.
    // Provide a placeholder comment instead.
    if (flow.request_body_encoding === "base64") {
      parts.push(flag + " '<base64-encoded body omitted>'");
    } else {
      parts.push(flag + " '" + shellEscape(flow.request_body) + "'");
    }
  }

  // Format with line-continuation backslashes for readability.
  if (parts.length <= 2) {
    return parts.join(" ");
  }
  return parts.join(" \\\n  ");
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Extract the Content-Type value from a headers map (case-insensitive). */
function getContentType(headers: Record<string, string[]>): string {
  for (const [name, values] of Object.entries(headers)) {
    if (name.toLowerCase() === "content-type" && values.length > 0) {
      return values[0];
    }
  }
  return "";
}

/** Decide whether the content type is textual (use -d) or binary. */
function isTextContentType(ct: string): boolean {
  const lower = ct.toLowerCase();
  return (
    lower.startsWith("text/") ||
    lower.includes("json") ||
    lower.includes("xml") ||
    lower.includes("x-www-form-urlencoded")
  );
}
