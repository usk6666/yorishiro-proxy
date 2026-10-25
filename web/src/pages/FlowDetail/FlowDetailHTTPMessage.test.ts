/**
 * A recorded HTTP/2 flow's headers never contain pseudo-headers (the h2
 * Layer moves :method / :path / :authority / :scheme / :status into the
 * message fields), so the request/response panels show the regular
 * Headers tab only — no "Pseudo-Headers" tab that would either be empty
 * or show values reconstructed in an order the wire never had.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { FlowDetailResult } from "../../lib/mcp/types.js";
import { FlowDetailHTTPMessage } from "./FlowDetailHTTPMessage.js";
import h2Text from "./__fixtures__/h2-flow.response.json?raw";

const h2 = JSON.parse(h2Text) as FlowDetailResult;

function render(flow: FlowDetailResult): string {
  return renderToStaticMarkup(createElement(FlowDetailHTTPMessage, { flow }));
}

describe("FlowDetailHTTPMessage with a recorded h2 flow", () => {
  it("fixture headers carry no pseudo-headers", () => {
    const names = [
      ...Object.keys(h2.request_headers ?? {}),
      ...Object.keys(h2.response_headers ?? {}),
    ];
    expect(names.length).toBeGreaterThan(0);
    expect(names.filter((n) => n.startsWith(":"))).toEqual([]);
  });

  it("does not render a Pseudo-Headers tab", () => {
    expect(render(h2)).not.toContain("Pseudo-Headers");
  });

  it("renders the recorded regular headers on the default Headers tab", () => {
    const html = render(h2);
    expect(html).toContain("user-agent");
    expect(html).toContain("fixture/1.0");
    expect(html).toContain("content-type");
  });
});
