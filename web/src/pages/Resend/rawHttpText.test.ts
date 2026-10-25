/**
 * The raw HTTP editor's initial text for recorded flows. An HTTP/2 flow's
 * raw_request is the binary HEADERS frame block, so decoding it as text
 * yields garbage; the editor must reconstruct HTTP/1.1 from the parsed
 * fields instead. HTTP/1.x flows keep their recorded bytes verbatim.
 */

import { describe, expect, it } from "vitest";
import type { FlowDetailResult } from "../../lib/mcp/types.js";
import h1Text from "../FlowDetail/__fixtures__/h1-flow.response.json?raw";
import h2Text from "../FlowDetail/__fixtures__/h2-flow.response.json?raw";
import h2cText from "../FlowDetail/__fixtures__/h2c-flow.response.json?raw";
import { initialRawHttpText } from "./rawHttpText.js";

const h1 = JSON.parse(h1Text) as FlowDetailResult;
const h2 = JSON.parse(h2Text) as FlowDetailResult;
const h2c = JSON.parse(h2cText) as FlowDetailResult;

describe("initialRawHttpText", () => {
  it.each([
    ["h2", h2],
    ["h2c", h2c],
  ])("reconstructs HTTP/1.1 text for a recorded %s flow instead of decoding the frame block", (_name, flow) => {
    const text = initialRawHttpText(flow);
    expect(text.startsWith("GET /api/items HTTP/1.1\r\n")).toBe(true);
    expect(text).toContain("Host: h2.example.com\r\n");
    expect(text).toContain("user-agent: fixture/1.0\r\n");
    expect(text).not.toBe(atob(flow.raw_request ?? ""));
  });

  it("keeps the recorded request bytes for an HTTP/1.1 flow", () => {
    expect(initialRawHttpText(h1)).toBe(atob(h1.raw_request ?? ""));
  });
});
