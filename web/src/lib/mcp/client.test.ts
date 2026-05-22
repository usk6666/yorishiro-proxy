/**
 * Tests for McpClient.callTool's content-block parsing contract (USK-966).
 *
 * yorishiro-proxy's MCP tools return a single JSON-text ContentBlock. If the
 * server returns no content, an empty content array, or a non-text first
 * block, that is a contract violation. callTool MUST throw an explicit error
 * with the tool name — the previous behaviour silently cast the raw
 * `ToolResult` to `T`, which propagated to callers and triggered
 * `JSON.parse("")` crashes or property-undefined surprises downstream.
 */

import { describe, expect, it } from "vitest";
import { McpClient } from "./client.js";

/**
 * Build an McpClient and inject a fake underlying MCP SDK client that
 * returns the supplied `ToolResult` payload from `callTool`. Bypasses the
 * real transport / handshake — we only exercise the result-parsing path.
 */
function clientReturning(result: unknown): McpClient {
  const c = new McpClient({ url: "/mcp" });
  // Cast to a record so we can poke at the private fields exercised by
  // callTool's guard. `callTool` only checks `this.client` truthiness and
  // `this._status === "connected"`; nothing else from the SDK is touched in
  // the parsing path.
  const internal = c as unknown as {
    client: { callTool: (req: unknown) => Promise<unknown> } | null;
    _status: string;
  };
  internal.client = {
    callTool: async () => result,
  };
  internal._status = "connected";
  return c;
}

describe("McpClient.callTool", () => {
  it("parses a single JSON-text content block", async () => {
    const c = clientReturning({
      content: [{ type: "text", text: JSON.stringify({ ok: true }) }],
    });
    const out = await c.callTool<{ ok: boolean }>("some_tool", {});
    expect(out).toEqual({ ok: true });
  });

  it("throws when content array is missing", async () => {
    const c = clientReturning({});
    await expect(c.callTool("some_tool", {})).rejects.toThrow(
      "MCP tool 'some_tool' returned no parseable content",
    );
  });

  it("throws when content array is empty", async () => {
    const c = clientReturning({ content: [] });
    await expect(c.callTool("some_tool", {})).rejects.toThrow(
      "MCP tool 'some_tool' returned no parseable content",
    );
  });

  it("throws when first content block is not a text block", async () => {
    const c = clientReturning({
      content: [{ type: "image", data: "...", mimeType: "image/png" }],
    });
    await expect(c.callTool("some_tool", {})).rejects.toThrow(
      "MCP tool 'some_tool' returned no parseable content",
    );
  });

  it("propagates isError content text as the error message", async () => {
    const c = clientReturning({
      isError: true,
      content: [{ type: "text", text: "tool blew up" }],
    });
    await expect(c.callTool("some_tool", {})).rejects.toThrow("tool blew up");
  });
});
