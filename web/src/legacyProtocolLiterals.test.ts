/**
 * Recorded Stream.Protocol values are canonical (http, ws, grpc, grpc-web,
 * sse, raw, tls-handshake; HTTP/2 is "http" + http_version). The display
 * spellings used before that ("HTTP/1.x", "HTTPS", "HTTP/2", "WebSocket",
 * "gRPC", "gRPC-Web", "TCP", "SOCKS5+...") never come from the server, so
 * comparing against them, sending them as filters, or using them as
 * defaults silently breaks the UI.
 *
 * This scans non-test sources for those literals. Allowed:
 *   - lib/mcp/dispatch.ts: the tolerant helpers that read a recorded
 *     `protocol`. Old DBs / JSONL imports may still hold legacy values
 *     (no migration rewrites Stream.Protocol), and the file documents why.
 *   - MessageList.tsx / GrpcPanel.tsx: being fixed in PR 251; they move
 *     onto the shared helpers once it merges.
 *   - UI labels (`label: "..."`), which name a protocol for a human and
 *     are never compared or sent.
 */

import { describe, expect, it } from "vitest";

const sources = import.meta.glob("/src/**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const ALLOWED_FILES = new Set([
  "/src/lib/mcp/dispatch.ts",
  // PR 251 changes these; consolidate onto the shared helpers after it merges.
  "/src/pages/FlowDetail/MessageList.tsx",
  "/src/pages/FlowDetail/GrpcPanel.tsx",
]);

const LEGACY_LITERAL =
  /(["'`])(HTTP\/1\.x|HTTPS|HTTP\/2|WebSocket|gRPC|gRPC-Web|TCP|SOCKS5\+[A-Za-z]*|http\/1\.x|http\/2)\1/;

const LABEL_SITE = /\blabel:\s*["'`]/;

function isTestFile(path: string): boolean {
  return /\.test\.tsx?$/.test(path);
}

/** Drop // line comments and /* block comments *\/ so prose may name protocols. */
function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
}

describe("legacy protocol literals", () => {
  it("scans a non-trivial set of sources", () => {
    expect(Object.keys(sources).length).toBeGreaterThan(50);
    expect(sources["/src/pages/Flows/FlowsPage.tsx"]).toBeTruthy();
  });

  it("are not used outside the documented tolerant helpers", () => {
    const hits: string[] = [];
    for (const [path, src] of Object.entries(sources)) {
      if (isTestFile(path) || ALLOWED_FILES.has(path)) continue;
      stripComments(src)
        .split("\n")
        .forEach((line, i) => {
          if (LEGACY_LITERAL.test(line) && !LABEL_SITE.test(line)) {
            hits.push(`${path}:${i + 1}: ${line.trim()}`);
          }
        });
    }
    expect(hits).toEqual([]);
  });

  it("dispatch.ts documents why it still accepts legacy spellings", () => {
    const src = sources["/src/lib/mcp/dispatch.ts"];
    expect(src).toMatch(/no migration/i);
  });
});
