/**
 * Tests for the Intercept page's pure payload helpers (USK-1261).
 *
 * The page used to send `params.override_*` fields that the server's
 * `intercept` InputSchema rejects (additionalProperties:false), so Modify &
 * Forward never worked. These tests validate the builder output against
 * the real InputSchema (exported from tools/list into a checked-in fixture
 * by internal/mcp/intercept_webui_schema_test.go) rather than against the
 * TypeScript types, and pin the generated arguments as goldens that the Go
 * e2e test internal/mcp/intercept_webui_golden_integration_test.go replays
 * against the real intercept tool.
 */

import { AjvJsonSchemaValidator } from "@modelcontextprotocol/sdk/validation/ajv";
import { describe, expect, it } from "vitest";
import schemaText from "../../lib/mcp/__fixtures__/intercept.input-schema.json?raw";
import type { InterceptActionParams, InterceptQueueEntry } from "../../lib/mcp/types.js";
import rawEntryText from "./__fixtures__/queue-entry.raw.json?raw";
import requestEntryText from "./__fixtures__/queue-entry.request.json?raw";
import responseEntryText from "./__fixtures__/queue-entry.response.json?raw";
import wsEntryText from "./__fixtures__/queue-entry.ws.json?raw";
import type { HeaderRow } from "./HeaderEditor.js";
import {
  buildModifyAndForwardArgs,
  canModify,
  entryToEditState,
  type InterceptEditState,
  maskingWarning,
  rawModeAllowed,
} from "./interceptPayload.js";

const schema = JSON.parse(schemaText);
const validate = new AjvJsonSchemaValidator().getValidator<unknown>(schema);

function loadEntry(text: string): InterceptQueueEntry {
  return JSON.parse(text) as InterceptQueueEntry;
}

function row(name: string, value: string): HeaderRow {
  return { id: `${name}:${value}`, name, value };
}

function headerPairs(rows: HeaderRow[]): [string, string][] {
  return rows.map((r) => [r.name, r.value]);
}

function expectSchemaValid(args: unknown): void {
  const result = validate(args);
  expect(result.errorMessage ?? "").toBe("");
  expect(result.valid).toBe(true);
}

// ---------------------------------------------------------------------------
// Golden scenarios: one per editable hold kind. The Go e2e test replays the
// resulting goldens against the real intercept tool.
// ---------------------------------------------------------------------------

interface Scenario {
  name: string;
  entry: InterceptQueueEntry;
  edit: (state: InterceptEditState) => InterceptEditState;
}

const SCENARIOS: Scenario[] = [
  {
    name: "request",
    entry: loadEntry(requestEntryText),
    edit: (s) => ({
      ...s,
      path: "/admin",
      rawQuery: "a=2",
      headers: [
        ...s.headers
          .filter((h) => h.name !== "X-Remove")
          .map((h) => (h.name === "x-dup" ? { ...h, value: "3" } : h)),
        row("X-Added", "yes"),
      ],
      body: "hello world",
    }),
  },
  {
    name: "response",
    entry: loadEntry(responseEntryText),
    edit: (s) => ({
      ...s,
      status: 403,
      headers: [...s.headers, row("Set-Cookie", "c=3")],
      body: "/wACAw==",
    }),
  },
  {
    name: "ws",
    entry: loadEntry(wsEntryText),
    edit: (s) => ({ ...s, body: "pong" }),
  },
  {
    name: "raw",
    entry: loadEntry(rawEntryText),
    edit: (s) => ({ ...s, rawBytes: "QllFDQo=" }),
  },
];

describe("buildModifyAndForwardArgs against the real intercept InputSchema", () => {
  it("the schema fixture rejects the legacy params.override_* shape (negative control)", () => {
    const result = validate({
      action: "modify_and_forward",
      params: { intercept_id: "x", override_body: "y" },
    });
    expect(result.valid).toBe(false);
  });

  for (const sc of SCENARIOS) {
    it(`${sc.name} hold: generated arguments pass the InputSchema`, async () => {
      const args = buildModifyAndForwardArgs(sc.entry, sc.edit(entryToEditState(sc.entry)));
      // Golden first: the Go e2e test replays it against the real tool.
      await expect(JSON.stringify(args, null, 2) + "\n").toMatchFileSnapshot(
        `./__fixtures__/modify-args.${sc.name}.json`,
      );
      expectSchemaValid(args);
    });
  }
});

// ---------------------------------------------------------------------------
// Read side: queue entry -> editor state
// ---------------------------------------------------------------------------

describe("entryToEditState", () => {
  it("maps http + send to a request and keeps header order, casing and duplicates", () => {
    const s = entryToEditState(loadEntry(requestEntryText));
    expect(s.kind).toBe("request");
    expect(s.method).toBe("POST");
    expect(s.scheme).toBe("https");
    expect(s.authority).toBe("example.com");
    expect(s.path).toBe("/orig");
    expect(s.rawQuery).toBe("a=1");
    expect(headerPairs(s.headers)).toEqual([
      ["Host", "example.com"],
      ["X-Dup", "1"],
      ["x-dup", "2"],
      ["X-Remove", "gone"],
    ]);
    expect(s.body).toBe("hello");
    expect(s.bodyEncoding).toBe("text");
  });

  it("maps http + receive to a response with status, reason and base64 body", () => {
    const s = entryToEditState(loadEntry(responseEntryText));
    expect(s.kind).toBe("response");
    expect(s.status).toBe(200);
    expect(s.statusReason).toBe("OK");
    expect(headerPairs(s.headers)).toEqual([
      ["Content-Type", "application/octet-stream"],
      ["Set-Cookie", "a=1"],
      ["set-cookie", "b=2"],
    ]);
    expect(s.body).toBe("/wAB");
    expect(s.bodyEncoding).toBe("base64");
  });

  it("maps websocket to a WS frame with payload and payload_encoding", () => {
    const s = entryToEditState(loadEntry(wsEntryText));
    expect(s.kind).toBe("websocket_frame");
    expect(s.body).toBe("ping");
    expect(s.bodyEncoding).toBe("text");
  });

  it("maps raw to base64 bytes even when the view is text-encoded", () => {
    const s = entryToEditState(loadEntry(rawEntryText));
    expect(s.kind).toBe("raw");
    expect(s.rawBytes).toBe("SEVMTE8NCg==");
  });

  it("defaults an omitted (empty) body to text", () => {
    const entry = loadEntry(requestEntryText);
    delete entry.http!.body;
    delete entry.http!.body_encoding;
    const s = entryToEditState(entry);
    expect(s.body).toBe("");
    expect(s.bodyEncoding).toBe("text");
  });

  it("classifies gRPC, SSE and unknown holds by protocol", () => {
    const base = loadEntry(requestEntryText);
    for (const protocol of ["grpc_start", "grpc_data", "grpc_end", "sse"] as const) {
      const s = entryToEditState({ ...base, http: undefined, protocol });
      expect(s.kind).toBe(protocol);
    }
  });
});

// ---------------------------------------------------------------------------
// Write side: only changed fields are sent
// ---------------------------------------------------------------------------

describe("buildModifyAndForwardArgs partial updates", () => {
  const req = loadEntry(requestEntryText);
  const resp = loadEntry(responseEntryText);
  const ws = loadEntry(wsEntryText);

  it("sends an empty http payload when nothing changed", () => {
    const args = buildModifyAndForwardArgs(req, entryToEditState(req));
    expect(args).toEqual({
      action: "modify_and_forward",
      params: { intercept_id: "INTERCEPT_ID" },
      http: {},
    });
  });

  it("sends only the changed URL parts, raw_query without a leading ?", () => {
    const s = entryToEditState(req);
    const args = buildModifyAndForwardArgs(req, { ...s, path: "/x", rawQuery: "q=1" });
    expect(args.http).toEqual({ path: "/x", raw_query: "q=1" });
  });

  it("sends a free-text method only when changed", () => {
    const s = entryToEditState(req);
    const args = buildModifyAndForwardArgs(req, { ...s, method: "PURGE" });
    expect(args.http).toEqual({ method: "PURGE" });
  });

  it("sends scheme and authority when edited", () => {
    const s = entryToEditState(req);
    const args = buildModifyAndForwardArgs(req, { ...s, scheme: "http", authority: "evil.test:8080" });
    expect(args.http).toEqual({ scheme: "http", authority: "evil.test:8080" });
  });

  it("sends the full ordered header list, duplicates and casing intact, when one value changes", () => {
    const s = entryToEditState(resp);
    const headers = s.headers.map((h) => (h.name === "set-cookie" ? { ...h, value: "b=9" } : h));
    const args = buildModifyAndForwardArgs(resp, { ...s, headers });
    expect(args.http).toEqual({
      headers: [
        { name: "Content-Type", value: "application/octet-stream" },
        { name: "Set-Cookie", value: "a=1" },
        { name: "set-cookie", value: "b=9" },
      ],
    });
  });

  it("treats a blank added header row as no change", () => {
    const s = entryToEditState(req);
    const args = buildModifyAndForwardArgs(req, { ...s, headers: [...s.headers, row("", "")] });
    expect(args.http).toEqual({});
  });

  it("sends a reordered header list", () => {
    const s = entryToEditState(req);
    const headers = [...s.headers].reverse();
    const args = buildModifyAndForwardArgs(req, { ...s, headers });
    expect(args.http?.headers?.map((h) => h.name)).toEqual(["X-Remove", "x-dup", "X-Dup", "Host"]);
  });

  it("carries base64 body_encoding with a changed response body and sends status as a number", () => {
    const s = entryToEditState(resp);
    const args = buildModifyAndForwardArgs(resp, { ...s, status: 500, body: "AAAA" });
    expect(args.http).toEqual({ status: 500, body: "AAAA", body_encoding: "base64" });
  });

  it("treats a cleared status field as unchanged instead of sending status 0", () => {
    const s = entryToEditState(resp);
    const args = buildModifyAndForwardArgs(resp, { ...s, status: "" });
    expect(args.http).toEqual({});
  });

  it("treats a non-integer status field as unchanged", () => {
    const s = entryToEditState(resp);
    for (const status of ["abc", "12.5", " ", "-1"]) {
      const args = buildModifyAndForwardArgs(resp, { ...s, status });
      expect(args.http).toEqual({});
    }
  });

  it("still sends a deliberately out-of-range integer status", () => {
    const s = entryToEditState(resp);
    const args = buildModifyAndForwardArgs(resp, { ...s, status: "42" });
    expect(args.http).toEqual({ status: 42 });
  });

  it("sends status_reason only when changed", () => {
    const s = entryToEditState(resp);
    const args = buildModifyAndForwardArgs(resp, { ...s, statusReason: "Nope" });
    expect(args.http).toEqual({ status_reason: "Nope" });
  });

  it("maps WS payload_encoding to body_encoding and omits opcode / fin", () => {
    const s = entryToEditState(ws);
    const args = buildModifyAndForwardArgs(ws, { ...s, body: "pong" });
    expect(args).toEqual({
      action: "modify_and_forward",
      params: { intercept_id: "INTERCEPT_ID" },
      ws: { payload: "pong", body_encoding: "text" },
    });
  });

  it("never puts modifications under params", () => {
    for (const sc of SCENARIOS) {
      const args = buildModifyAndForwardArgs(sc.entry, sc.edit(entryToEditState(sc.entry)));
      expect(Object.keys(args.params)).toEqual(["intercept_id"]);
    }
  });
});

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

describe("canModify / rawModeAllowed / maskingWarning", () => {
  const req = loadEntry(requestEntryText);
  const resp = loadEntry(responseEntryText);
  const ws = loadEntry(wsEntryText);
  const raw = loadEntry(rawEntryText);

  it("offers Modify & Forward for HTTP, WS and raw holds only", () => {
    expect(canModify(req)).toBe(true);
    expect(canModify(resp)).toBe(true);
    expect(canModify(ws)).toBe(true);
    expect(canModify(raw)).toBe(true);
    for (const protocol of ["grpc_start", "grpc_data", "grpc_end", "sse", "unknown"]) {
      expect(canModify({ ...req, http: undefined, protocol })).toBe(false);
    }
  });

  it("offers the raw editor only for raw holds, even when wire bytes are available", () => {
    expect(rawModeAllowed(raw)).toBe(true);
    expect(rawModeAllowed({ ...req, raw_bytes_available: true, raw_bytes: "eA==" })).toBe(false);
    expect(rawModeAllowed({ ...ws, raw_bytes_available: true, raw_bytes: "eA==" })).toBe(false);
  });

  const withHeaderChange = (): InterceptActionParams => {
    const s = entryToEditState(req);
    return buildModifyAndForwardArgs(req, { ...s, headers: [...s.headers, row("X-New", "1")] });
  };

  it("warns when Output Filter rules are active and headers or body are echoed", () => {
    expect(maskingWarning(withHeaderChange(), 1)).toBe(true);
    const s = entryToEditState(ws);
    expect(maskingWarning(buildModifyAndForwardArgs(ws, { ...s, body: "x" }), 2)).toBe(true);
  });

  it("does not warn when only scalar fields are sent", () => {
    const s = entryToEditState(req);
    expect(maskingWarning(buildModifyAndForwardArgs(req, { ...s, path: "/x" }), 3)).toBe(false);
  });

  it("does not warn without Output Filter rules and without mask tokens", () => {
    expect(maskingWarning(withHeaderChange(), 0)).toBe(false);
  });

  it("finds a [MASKED:...] token inside a base64 HTTP body", () => {
    const s = entryToEditState(resp);
    const body = btoa("mail=[MASKED:email]");
    const args = buildModifyAndForwardArgs(resp, { ...s, body });
    expect(args.http?.body_encoding).toBe("base64");
    expect(maskingWarning(args, 0)).toBe(true);
  });

  it("finds a [MASKED:...] token inside a base64 WS payload", () => {
    const s = entryToEditState(ws);
    const args = buildModifyAndForwardArgs(ws, {
      ...s,
      body: btoa("[MASKED:credit-card]"),
      bodyEncoding: "base64",
    });
    expect(maskingWarning(args, 0)).toBe(true);
  });

  it("finds a [MASKED:...] token inside raw bytes_override", () => {
    const s = entryToEditState(raw);
    const args = buildModifyAndForwardArgs(raw, { ...s, rawBytes: btoa("x=[MASKED:email]\r\n") });
    expect(maskingWarning(args, 0)).toBe(true);
  });

  it("does not throw on invalid base64 content and skips the scan for it", () => {
    const s = entryToEditState(raw);
    const args = buildModifyAndForwardArgs(raw, { ...s, rawBytes: "!!not-base64!!" });
    expect(maskingWarning(args, 0)).toBe(false);
    expect(maskingWarning(args, 1)).toBe(true);
  });

  it("warns when the outgoing content carries a [MASKED:...] token", () => {
    const s = entryToEditState(req);
    const args = buildModifyAndForwardArgs(req, { ...s, body: "mail=[MASKED:email]" });
    expect(maskingWarning(args, 0)).toBe(true);
  });
});
