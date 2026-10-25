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
 *   - UI labels (`label: "..."`), which name a protocol for a human and
 *     are never compared or sent.
 */

import { describe, expect, it } from "vitest";

const sources = import.meta.glob("/src/**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const ALLOWED_FILES = new Set(["/src/lib/mcp/dispatch.ts"]);

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

// ---------------------------------------------------------------------------
// "SSE" / "Raw"
//
// The canonical values are "sse" / "raw". "SSE" and "Raw" are also ordinary
// UI labels ("Raw" names many body-view tabs and toggles), so a line regex
// cannot tell a label from a value. These are classified on the TypeScript
// AST instead: a literal is flagged only where it acts as a value —
// compared, defaulted, switched on, passed, stored, or typed.
// ---------------------------------------------------------------------------

/**
 * Return "line: text" for every "SSE" / "Raw" string literal in `src` that
 * is used as a value rather than as a label. Not implemented yet.
 */
function findProtocolValueLiterals(_src: string, _fileName: string): string[] {
  return [];
}

describe("legacy SSE / Raw protocol literals", () => {
  const flagged: [string, string][] = [
    ["strict equality", `if (p === "Raw") {}`],
    ["nullish default", `const x = flow?.protocol ?? "SSE";`],
    ["case clause", `switch (p) { case "Raw": break; }`],
    ["property value", `f({ protocol: "SSE" });`],
    ["array member", `["SSE", "raw"].includes(p);`],
    ["strict inequality, single quotes", `const b = p !== 'Raw';`],
    ["template call argument", "x.has(`SSE`);"],
    ["logical-or default", `const p = q || "Raw";`],
    ["variable initializer", `const p = "Raw";`],
    ["literal type", `type P = "SSE" | "sse";`],
    ["comparison through parens and a cast", `if (p === ("SSE" as string)) {}`],
    ["ternary branch stored as a value", `const p = c ? "sse" : "SSE";`],
    ["JSX value attribute", `const o = <option value="Raw" />;`],
    ["JSX protocol attribute expression", `const b = <Badge protocol={"SSE"} />;`],
  ];

  it.each(flagged)("flags a value use: %s", (_name, snippet) => {
    expect(findProtocolValueLiterals(snippet, "snippet.tsx")).toHaveLength(1);
  });

  const passed: [string, string][] = [
    ["label property", `const tabs = [{ id: "raw", label: "Raw" }];`],
    ["JSX text", `const e = <b>SSE</b>;`],
    ["ternary inside JSX", `const e = <span>{c ? "Highlighted" : "Raw"}</span>;`],
    ["return from a label function", `function kindLabel() { return "Raw"; }`],
    ["title attribute", `const z = <Tab title="Raw" />;`],
  ];

  it.each(passed)("does not flag a label: %s", (_name, snippet) => {
    expect(findProtocolValueLiterals(snippet, "snippet.tsx")).toEqual([]);
  });

  it("are not used as values outside the documented tolerant helpers", () => {
    const hits: string[] = [];
    for (const [path, src] of Object.entries(sources)) {
      if (isTestFile(path) || ALLOWED_FILES.has(path)) continue;
      for (const hit of findProtocolValueLiterals(src, path)) {
        hits.push(`${path}:${hit}`);
      }
    }
    expect(hits).toEqual([]);
  });
});
