/**
 * The server dropped the flow_type column (a MITM proxy cannot tell a
 * unary RPC from a streaming one without the proto schema), so no
 * `query` response carries it. Reading it made every flow look like a
 * streaming flow and the Type badges render "unknown" / empty.
 *
 * This scans every source under src/, tests included, so neither code
 * nor fixtures-by-hand can reintroduce the field. Comments are stripped
 * so prose may still explain its absence. This file is the only
 * exemption, since it has to spell the name it looks for.
 */

import { describe, expect, it } from "vitest";

const sources = import.meta.glob("/src/**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
}) as Record<string, string>;

const SELF = "/src/flowTypeField.test.ts";

const FIELD = /flow_type/;

/** Drop // line comments and /* block comments *\/. */
function stripComments(src: string): string {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:"'`])\/\/.*$/gm, "$1");
}

describe("dropped flow_type field", () => {
  it("scans a non-trivial set of sources, tests included", () => {
    expect(Object.keys(sources).length).toBeGreaterThan(50);
    expect(sources["/src/lib/mcp/dispatch.ts"]).toBeTruthy();
    expect(sources["/src/lib/mcp/dispatch.test.ts"]).toBeTruthy();
  });

  it("is not read, declared, or set anywhere in src/", () => {
    const hits: string[] = [];
    for (const [path, src] of Object.entries(sources)) {
      if (path === SELF) continue;
      stripComments(src)
        .split("\n")
        .forEach((line, i) => {
          if (FIELD.test(line)) hits.push(`${path}:${i + 1}: ${line.trim()}`);
        });
    }
    expect(hits).toEqual([]);
  });
});
