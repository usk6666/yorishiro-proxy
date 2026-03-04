/**
 * Build an HTTP Archive (HAR) 1.2 JSON object from flow data.
 *
 * Specification reference: http://www.softwareishard.com/blog/har-12-spec/
 *
 * The HAR is constructed entirely on the frontend from the data already
 * available via the MCP query tool — no backend changes are required.
 */

import type { FlowDetailResult, FlowEntry } from "../mcp/types.js";

// ---------------------------------------------------------------------------
// HAR type subset (only what we emit)
// ---------------------------------------------------------------------------

interface HarLog {
  log: {
    version: string;
    creator: { name: string; version: string };
    entries: HarEntry[];
  };
}

interface HarEntry {
  startedDateTime: string;
  time: number;
  request: HarRequest;
  response: HarResponse;
  cache: Record<string, never>;
  timings: { send: number; wait: number; receive: number };
}

interface HarRequest {
  method: string;
  url: string;
  httpVersion: string;
  headers: HarHeader[];
  queryString: HarQueryParam[];
  bodySize: number;
  headersSize: number;
  postData?: HarPostData;
}

interface HarResponse {
  status: number;
  statusText: string;
  httpVersion: string;
  headers: HarHeader[];
  content: HarContent;
  redirectURL: string;
  bodySize: number;
  headersSize: number;
}

interface HarHeader {
  name: string;
  value: string;
}

interface HarQueryParam {
  name: string;
  value: string;
}

interface HarPostData {
  mimeType: string;
  text: string;
}

interface HarContent {
  size: number;
  mimeType: string;
  text?: string;
  encoding?: string;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

const CREATOR = { name: "yorishiro-proxy", version: "1.0" };

/**
 * Build a complete HAR object from a single flow detail.
 */
export function buildHar(flow: FlowDetailResult): HarLog {
  return {
    log: {
      version: "1.2",
      creator: CREATOR,
      entries: [buildEntry(flow)],
    },
  };
}

/**
 * Build a HAR object from multiple flow entries.
 *
 * Because the list view ({@link FlowEntry}) contains less data than the
 * detail view, the generated entries will have fewer fields populated
 * (e.g. no bodies or full headers). This is still spec-compliant.
 */
export function buildHarFromList(flows: FlowEntry[]): HarLog {
  return {
    log: {
      version: "1.2",
      creator: CREATOR,
      entries: flows.map(buildEntryFromListItem),
    },
  };
}

/**
 * Trigger a file download of the HAR JSON in the browser.
 */
export function downloadHar(har: HarLog, filename: string): void {
  const json = JSON.stringify(har, null, 2);
  const blob = new Blob([json], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  } finally {
    URL.revokeObjectURL(url);
  }
}

// ---------------------------------------------------------------------------
// Entry builders
// ---------------------------------------------------------------------------

function buildEntry(flow: FlowDetailResult): HarEntry {
  const httpVersion = mapHttpVersion(flow.protocol);

  return {
    startedDateTime: flow.timestamp,
    time: flow.duration_ms,
    request: buildRequest(flow, httpVersion),
    response: buildResponse(flow, httpVersion),
    cache: {},
    timings: { send: -1, wait: flow.duration_ms, receive: -1 },
  };
}

function buildEntryFromListItem(flow: FlowEntry): HarEntry {
  const httpVersion = mapHttpVersion(flow.protocol);

  return {
    startedDateTime: flow.timestamp,
    time: flow.duration_ms,
    request: {
      method: flow.method ?? "GET",
      url: flow.url ?? "",
      httpVersion,
      headers: [],
      queryString: parseQueryString(flow.url),
      headersSize: -1,
      bodySize: -1,
    },
    response: {
      status: flow.status_code ?? 0,
      statusText: "",
      httpVersion,
      headers: [],
      content: { size: -1, mimeType: "" },
      redirectURL: "",
      headersSize: -1,
      bodySize: -1,
    },
    cache: {},
    timings: { send: -1, wait: flow.duration_ms, receive: -1 },
  };
}

// ---------------------------------------------------------------------------
// Request / Response helpers
// ---------------------------------------------------------------------------

function buildRequest(
  flow: FlowDetailResult,
  httpVersion: string,
): HarRequest {
  const headers = flattenHeaders(flow.request_headers);
  const contentType = getContentType(flow.request_headers);

  const req: HarRequest = {
    method: flow.method ?? "GET",
    url: flow.url ?? "",
    httpVersion,
    headers,
    queryString: parseQueryString(flow.url),
    headersSize: -1,
    bodySize: flow.request_body ? flow.request_body.length : 0,
  };

  if (flow.request_body) {
    req.postData = {
      mimeType: contentType,
      text: flow.request_body_encoding === "base64"
        ? flow.request_body  // Keep the base64 as-is; HAR supports encoding field
        : flow.request_body,
    };
  }

  return req;
}

function buildResponse(
  flow: FlowDetailResult,
  httpVersion: string,
): HarResponse {
  const headers = flattenHeaders(flow.response_headers);
  const contentType = getContentType(flow.response_headers);

  const content: HarContent = {
    size: flow.response_body ? flow.response_body.length : 0,
    mimeType: contentType,
  };

  if (flow.response_body) {
    if (flow.response_body_encoding === "base64") {
      content.text = flow.response_body;
      content.encoding = "base64";
    } else {
      content.text = flow.response_body;
    }
  }

  return {
    status: flow.response_status_code ?? 0,
    statusText: "",
    httpVersion,
    headers,
    content,
    redirectURL: getRedirectURL(flow.response_headers),
    headersSize: -1,
    bodySize: flow.response_body ? flow.response_body.length : 0,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function mapHttpVersion(protocol: string): string {
  switch (protocol) {
    case "HTTP/1.x":
      return "HTTP/1.1";
    case "HTTPS":
      return "HTTP/1.1";
    case "HTTP/2":
      return "h2";
    default:
      return "HTTP/1.1";
  }
}

/**
 * Flatten the multi-value headers map into a flat array of {name, value} pairs.
 */
function flattenHeaders(
  headers?: Record<string, string[]>,
): HarHeader[] {
  if (!headers) return [];
  const result: HarHeader[] = [];
  for (const [name, values] of Object.entries(headers)) {
    for (const value of values) {
      result.push({ name, value });
    }
  }
  return result;
}

/** Extract query string parameters from a URL. */
function parseQueryString(url?: string): HarQueryParam[] {
  if (!url) return [];
  try {
    const parsed = new URL(url);
    const params: HarQueryParam[] = [];
    parsed.searchParams.forEach((value, name) => {
      params.push({ name, value });
    });
    return params;
  } catch {
    return [];
  }
}

/** Extract the Content-Type value from a headers map. */
function getContentType(headers?: Record<string, string[]>): string {
  if (!headers) return "";
  for (const [name, values] of Object.entries(headers)) {
    if (name.toLowerCase() === "content-type" && values.length > 0) {
      return values[0];
    }
  }
  return "";
}

/** Extract the Location header for redirect URL. */
function getRedirectURL(headers?: Record<string, string[]>): string {
  if (!headers) return "";
  for (const [name, values] of Object.entries(headers)) {
    if (name.toLowerCase() === "location" && values.length > 0) {
      return values[0];
    }
  }
  return "";
}
