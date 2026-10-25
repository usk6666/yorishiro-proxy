/**
 * Tests for WebSocketMessageList frame display.
 *
 * The fixture is the real `query resource=messages` response for a stream
 * recorded by the pipeline RecordStep (upgrade GET, 101, Send Text "hello",
 * Receive Binary 00 01 02 ff, Receive Close 1000 "bye"), generated and kept
 * in sync by internal/mcp/ws_metadata_keys_test.go
 * TestQueryMessages_WSMatchesWebUIFixture. RecordStep writes the opcode as
 * metadata.ws_opcode and Close status as ws_close_code / ws_close_reason.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { MessageEntry } from "../../lib/mcp/types.js";
import fixtureText from "./__fixtures__/ws-messages.response.json?raw";
import {
  WebSocketMessageDetail,
  WebSocketMessageList,
} from "./WebSocketMessageList.js";
import { wsFrameInfo } from "./wsFrame.js";

const fixture = JSON.parse(fixtureText) as {
  messages: MessageEntry[];
  total: number;
};

function bySeq(seq: number): MessageEntry {
  const m = fixture.messages.find((e) => e.sequence === seq);
  if (!m) throw new Error(`fixture has no sequence ${seq}`);
  return m;
}

/** Clone a fixture entry with metadata overrides (flagged edited variant). */
function withMetadata(
  seq: number,
  overrides: Record<string, string>,
  body?: string,
): MessageEntry {
  const base = bySeq(seq);
  return {
    ...base,
    body: body ?? base.body,
    metadata: { ...(base.metadata ?? {}), ...overrides },
  };
}

function renderList(messages: MessageEntry[]): string {
  return renderToStaticMarkup(
    createElement(WebSocketMessageList, {
      messages,
      total: messages.length,
      offset: 0,
      limit: 100,
      loading: false,
      onPageChange: () => {},
    }),
  );
}

function renderDetail(message: MessageEntry): string {
  return renderToStaticMarkup(
    createElement(WebSocketMessageDetail, {
      message,
      binaryMode: "hex",
      onBinaryModeChange: () => {},
      jsonPretty: true,
      onJsonPrettyChange: () => {},
      onClose: () => {},
    }),
  );
}

/** Badge labels in render order. */
function badges(html: string): string[] {
  return [...html.matchAll(/<span class="badge[^"]*">([^<]*)<\/span>/g)].map(
    (m) => m[1],
  );
}

/** Row previews in render order. */
function previews(html: string): string[] {
  return [...html.matchAll(/<div class="sd-ws-msg-preview">([^<]*)<\/div>/g)].map(
    (m) => m[1],
  );
}

describe("WebSocketMessageList with a RecordStep-recorded stream", () => {
  it("fixture carries ws_opcode, not a legacy opcode key", () => {
    // Guard against a vacuous pass if the fixture shape changes.
    expect(bySeq(2).metadata?.ws_opcode).toBe("1");
    expect(bySeq(4).metadata?.ws_close_code).toBe("1000");
    expect(fixture.messages.some((m) => m.metadata?.opcode !== undefined)).toBe(false);
  });

  it("labels Text / Binary / Close frames and never fabricates 0x0", () => {
    const html = renderList(fixture.messages);
    expect(badges(html)).toEqual(["HTTP", "HTTP", "Text", "Binary", "Close"]);
    expect(html).not.toContain("0x0");
  });

  it("shows Close code and reason instead of a binary size", () => {
    const html = renderList(fixture.messages);
    const closePreview = previews(html)[4];
    expect(closePreview).toContain("1000");
    expect(closePreview).toContain("Normal Closure");
    expect(closePreview).toContain("bye");
    expect(closePreview).not.toContain("(binary");
  });
});

describe("wsFrameInfo", () => {
  it("maps ws_opcode to RFC 6455 labels", () => {
    const cases: Array<[string, string]> = [
      ["0", "Continuation"],
      ["1", "Text"],
      ["2", "Binary"],
      ["8", "Close"],
      ["9", "Ping"],
      ["10", "Pong"],
      ["3", "0x3"],
    ];
    for (const [op, label] of cases) {
      const info = wsFrameInfo(withMetadata(3, { ws_opcode: op }));
      expect(info.label, `ws_opcode=${op}`).toBe(label);
      expect(info.opcode, `ws_opcode=${op}`).toBe(Number(op));
    }
  });

  it("gives non-frame rows a neutral label, not an opcode", () => {
    expect(wsFrameInfo(bySeq(0))).toMatchObject({ opcode: null, label: "HTTP", close: null });
    expect(wsFrameInfo(bySeq(1))).toMatchObject({ opcode: null, label: "HTTP", close: null });
    const bare: MessageEntry = { ...bySeq(3), metadata: { protocol: "ws" } };
    expect(wsFrameInfo(bare)).toMatchObject({ opcode: null, label: "?" });
    const garbage = withMetadata(3, { ws_opcode: "x1" });
    expect(wsFrameInfo(garbage).opcode).toBeNull();
    expect(wsFrameInfo(garbage).label).not.toBe("0x0");
  });

  it("reads Close status from ws_close_code / ws_close_reason", () => {
    // Edited variant: empty body, metadata carries the status.
    const msg = withMetadata(4, { ws_close_code: "1001", ws_close_reason: "going" }, "");
    expect(wsFrameInfo(msg).close).toEqual({
      code: 1001,
      codeDescription: "Going Away",
      reason: "going",
    });
    const html = renderList([msg]);
    expect(previews(html)[0]).toContain("1001 Going Away");
    expect(previews(html)[0]).toContain("going");
    const detail = renderDetail(msg);
    expect(detail).toContain("1001 (Going Away)");
    expect(detail).toContain("going");
  });

  it("shows ws_close_code=0 as no status code", () => {
    const msg = withMetadata(4, { ws_close_code: "0", ws_close_reason: "" }, "");
    const info = wsFrameInfo(msg);
    expect(info.close?.code).toBeNull();
    expect(info.close?.codeDescription).toBe("no status code");
    expect(info.close?.reason).toBe("");
    const preview = previews(renderList([msg]))[0];
    expect(preview).toContain("no status code");
    expect(preview).not.toContain("0 Unknown");
  });

  it("falls back to the Close body when status keys are absent", () => {
    const base = bySeq(4);
    const msg: MessageEntry = {
      ...base,
      metadata: { protocol: "ws", ws_opcode: "8" },
    };
    expect(wsFrameInfo(msg).close).toEqual({
      code: 1000,
      codeDescription: "Normal Closure",
      reason: "bye",
    });
  });
});
