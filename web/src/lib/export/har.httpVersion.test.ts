/**
 * The WebUI HAR export's httpVersion must agree with the server-side HAR
 * export (Go `harHTTPVersion` in internal/flow/har.go), which keys on the
 * flow's wire HTTP version — not on `protocol`, which is "http" for both
 * HTTP/1.x and HTTP/2. Fixtures are real `query resource=flow` responses.
 */

import { describe, expect, it } from "vitest";
import type { FlowDetailResult, FlowEntry, FlowsResult } from "../mcp/types.js";
import h1Text from "../../pages/FlowDetail/__fixtures__/h1-flow.response.json?raw";
import h2Text from "../../pages/FlowDetail/__fixtures__/h2-flow.response.json?raw";
import h2cText from "../../pages/FlowDetail/__fixtures__/h2c-flow.response.json?raw";
import flowsText from "../../pages/Flows/__fixtures__/flows-all-protocols.response.json?raw";
import { buildHar, buildHarFromList } from "./har.js";

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

describe("buildHarFromList httpVersion", () => {
  const list = JSON.parse(flowsText) as FlowsResult;

  function row(id: string): FlowEntry {
    const f = list.flows.find((e) => e.id === id);
    if (!f) throw new Error(`fixture has no row ${id}`);
    return f;
  }

  function listVersions(flow: FlowEntry): [string, string] {
    const entry = buildHarFromList([flow]).log.entries[0];
    return [entry.request.httpVersion, entry.response.httpVersion];
  }

  it("list rows carry the recorded http_version", () => {
    expect(row("stream-http-h2").http_version).toBe("h2");
    expect(row("stream-http-h2c").http_version).toBe("h2c");
    expect(row("stream-http-h1").http_version).toBe("http/1.1");
  });

  it("writes h2 / h2c / HTTP/1.1 for recorded list rows", () => {
    expect(listVersions(row("stream-http-h2"))).toEqual(["h2", "h2"]);
    expect(listVersions(row("stream-http-h2c"))).toEqual(["h2c", "h2c"]);
    expect(listVersions(row("stream-http-h1"))).toEqual(["HTTP/1.1", "HTTP/1.1"]);
  });

  it("keys on http_version, falling back to HTTP/1.1 when absent", () => {
    const h1Row = row("stream-http-h1");
    expect(listVersions({ ...h1Row, http_version: "h2" })).toEqual(["h2", "h2"]);
    expect(listVersions({ ...h1Row, http_version: undefined })).toEqual(["HTTP/1.1", "HTTP/1.1"]);
  });
});
