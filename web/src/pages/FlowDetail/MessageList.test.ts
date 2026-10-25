/**
 * Tests for MessageList's gRPC columns.
 *
 * The metadata keys below are copied verbatim from what the pipeline
 * RecordStep writes (internal/pipeline/record_step.go projectGRPCStart /
 * projectGRPCData: grpc_event, grpc_service, grpc_method; projectGRPCEnd:
 * grpc_event, grpc_status). The Stream protocol is the canonical
 * Envelope.Protocol value ("grpc" / "grpc-web", internal/envelope/envelope.go).
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { MessageEntry } from "../../lib/mcp/types.js";
import { MessageList } from "./MessageList.js";

const grpcMessages: MessageEntry[] = [
  {
    id: "m0",
    sequence: 0,
    direction: "send",
    body: "",
    body_encoding: "text",
    metadata: {
      protocol: "grpc",
      grpc_event: "start",
      grpc_service: "pkg.Svc",
      grpc_method: "Do",
      grpc_content_type: "application/grpc",
    },
    timestamp: "2026-01-01T00:00:00Z",
  },
  {
    id: "m1",
    sequence: 1,
    direction: "receive",
    body: "",
    body_encoding: "text",
    metadata: { protocol: "grpc", grpc_event: "end", grpc_status: "5" },
    timestamp: "2026-01-01T00:00:00Z",
  },
];

function render(protocol: string): string {
  return renderToStaticMarkup(
    createElement(MessageList, {
      messages: grpcMessages,
      total: grpcMessages.length,
      offset: 0,
      limit: 100,
      loading: false,
      onPageChange: () => {},
      protocol,
    }),
  );
}

/** Cells of the gRPC metadata columns, in render order. */
function metaCells(html: string): string[] {
  return [...html.matchAll(/<td class="sd-message-meta">([^<]*)<\/td>/g)].map(
    (m) => m[1],
  );
}

describe("MessageList gRPC columns", () => {
  for (const protocol of ["grpc", "grpc-web", "gRPC", "gRPC-Web"]) {
    it(`shows Service / Method / Status for protocol=${protocol}`, () => {
      const html = render(protocol);
      expect(html).toContain("<th>Service</th>");
      expect(html).toContain("<th>Method</th>");
      expect(html).toContain("<th>Status</th>");
      // Row 0: service, method, status; row 1: service, method, status.
      expect(metaCells(html)).toEqual(["pkg.Svc", "Do", "--", "--", "--", "5"]);
    });
  }

  it("omits gRPC columns for other protocols", () => {
    const html = render("sse");
    expect(html).not.toContain("<th>Service</th>");
  });
});
