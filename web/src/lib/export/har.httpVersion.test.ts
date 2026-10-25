/**
 * The WebUI HAR export's httpVersion must agree with the server-side HAR
 * export (Go `harHTTPVersion` in internal/flow/har.go), which keys on the
 * flow's wire HTTP version — not on `protocol`, which is "http" for both
 * HTTP/1.x and HTTP/2. Fixtures are real `query resource=flow` responses.
 */

import { describe, expect, it } from "vitest";
import type { FlowDetailResult } from "../mcp/types.js";
import h1Text from "../../pages/FlowDetail/__fixtures__/h1-flow.response.json?raw";
import h2Text from "../../pages/FlowDetail/__fixtures__/h2-flow.response.json?raw";
import h2cText from "../../pages/FlowDetail/__fixtures__/h2c-flow.response.json?raw";
import { buildHar } from "./har.js";

const h1 = JSON.parse(h1Text) as FlowDetailResult;
const h2 = JSON.parse(h2Text) as FlowDetailResult;
const h2c = JSON.parse(h2cText) as FlowDetailResult;

function versions(flow: FlowDetailResult): [string, string] {
  const entry = buildHar(flow).log.entries[0];
  return [entry.request.httpVersion, entry.response.httpVersion];
}

describe("buildHar httpVersion", () => {
  it("writes h2 for a recorded HTTP/2 flow", () => {
    expect(versions(h2)).toEqual(["h2", "h2"]);
  });

  it("writes h2c for a recorded cleartext HTTP/2 flow", () => {
    expect(versions(h2c)).toEqual(["h2c", "h2c"]);
  });

  it("writes HTTP/1.1 for a recorded HTTP/1.1 flow", () => {
    expect(versions(h1)).toEqual(["HTTP/1.1", "HTTP/1.1"]);
  });

  it("mirrors harHTTPVersion for http/1.0 and an empty version", () => {
    expect(versions({ ...h1, http_version: "http/1.0" })).toEqual(["HTTP/1.0", "HTTP/1.0"]);
    expect(versions({ ...h1, http_version: undefined })).toEqual(["HTTP/1.1", "HTTP/1.1"]);
  });
});
