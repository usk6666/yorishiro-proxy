/**
 * Tests for GrpcPanel protocol-dependent title.
 *
 * The backend reports gRPC-Web flows with the canonical lowercase protocol
 * name "grpc-web"; older recordings may carry the legacy "gRPC-Web" spelling.
 * Both must render the gRPC-Web panel, while plain gRPC must not.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { FlowDetailResult } from "../../lib/mcp/types.js";
import { GrpcPanel } from "./GrpcPanel.js";

function flowWithProtocol(protocol: string): FlowDetailResult {
  return {
    id: "f1",
    conn_id: "c1",
    protocol,
    flow_type: "unary",
    state: "complete",
    method: "POST",
    url: "https://example.com/pkg.Svc/Method",
    request_headers: null,
    request_body: "",
    request_body_encoding: "base64",
    response_status_code: 200,
    response_headers: null,
    response_body: "",
    response_body_encoding: "base64",
    request_body_truncated: false,
    response_body_truncated: false,
    timestamp: "2026-10-25T00:00:00Z",
    duration_ms: 0,
    protocol_summary: { service: "pkg.Svc", method: "Method" },
  } as unknown as FlowDetailResult;
}

function renderTitle(protocol: string): string {
  const html = renderToStaticMarkup(
    createElement(GrpcPanel, { flow: flowWithProtocol(protocol) }),
  );
  const m = html.match(/<h2 class="sd-section-title">([^<]*)<\/h2>/);
  if (!m) throw new Error(`no panel title in markup: ${html}`);
  return m[1];
}

describe("GrpcPanel title", () => {
  it.each(["grpc-web", "gRPC-Web"])(
    "renders gRPC-Web Details for protocol %s",
    (protocol) => {
      expect(renderTitle(protocol)).toBe("gRPC-Web Details");
    },
  );

  it.each(["grpc", "gRPC"])(
    "renders gRPC Details for protocol %s",
    (protocol) => {
      expect(renderTitle(protocol)).toBe("gRPC Details");
    },
  );
});
