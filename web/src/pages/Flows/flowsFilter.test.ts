/**
 * The Flows page builds the `filter` it sends to `query resource=flows`.
 * The server applies filter.tag on flows (exact match on
 * Stream.Tags["tag"]) but rejects body_contains there — it only applies to
 * fuzz_results — so the page must never send it (USK-1357).
 */

import { describe, expect, it } from "vitest";
import flowsPageSrc from "./FlowsPage.tsx?raw";
import { buildFlowsFilter, type FlowsFilterInputs } from "./flowsFilter.js";

const empty: FlowsFilterInputs = {
  protocol: "",
  httpVersion: "",
  scheme: "",
  method: "",
  urlPattern: "",
  statusCode: "",
  blockedBy: "",
  state: "",
  host: "",
  tag: "",
  connId: "",
};

describe("buildFlowsFilter", () => {
  it("returns undefined when no input is set", () => {
    expect(buildFlowsFilter(empty)).toBeUndefined();
  });

  it("sends the tag as filter.tag", () => {
    expect(buildFlowsFilter({ ...empty, tag: "probe-1" })).toEqual({ tag: "probe-1" });
  });

  it("sends the tag verbatim, since the server matches it exactly", () => {
    expect(buildFlowsFilter({ ...empty, tag: " probe-1 " })).toEqual({ tag: " probe-1 " });
  });

  it("maps every input to its server filter field", () => {
    expect(
      buildFlowsFilter({
        protocol: "http",
        httpVersion: "h2",
        scheme: "https",
        method: "POST",
        urlPattern: " /api ",
        statusCode: "404",
        blockedBy: "target_scope",
        state: "complete",
        host: " example.com ",
        tag: "scratch",
        connId: "conn-1",
      }),
    ).toEqual({
      protocol: "http",
      http_version: "h2",
      scheme: "https",
      method: "POST",
      url_pattern: "/api",
      status_code: 404,
      blocked_by: "target_scope",
      state: "complete",
      host: "example.com",
      tag: "scratch",
      conn_id: "conn-1",
    });
  });

  it("sends the connection ID as filter.conn_id", () => {
    expect(buildFlowsFilter({ ...empty, connId: "conn-h2-multiplexed" })).toEqual({
      conn_id: "conn-h2-multiplexed",
    });
  });

  it("sends the connection ID verbatim, since the server matches it exactly", () => {
    expect(buildFlowsFilter({ ...empty, connId: " Conn-A " })).toEqual({ conn_id: " Conn-A " });
  });

  it("ANDs the connection ID with the other filters", () => {
    expect(buildFlowsFilter({ ...empty, connId: "conn-1", method: "GET" })).toEqual({
      conn_id: "conn-1",
      method: "GET",
    });
  });
});

describe("FlowsPage filter wiring", () => {
  it("never sends body_contains to resource=flows", () => {
    expect(flowsPageSrc).not.toMatch(/body_contains|bodyContains|Body Contains/);
  });

  it("builds its filter with buildFlowsFilter", () => {
    expect(flowsPageSrc).toMatch(/buildFlowsFilter\(/);
  });

  it("labels the tag input as an exact resend/fuzz tag", () => {
    expect(flowsPageSrc).toContain('placeholder="resend/fuzz tag (exact)"');
  });
});
