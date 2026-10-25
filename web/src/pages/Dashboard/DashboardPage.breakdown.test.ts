/**
 * DashboardPage issues one `flows` count query per PROTOCOL_BREAKDOWN row
 * by index (hooks cannot run in a loop). Guard that the explicit list
 * covers every row, so adding a row cannot silently drop its count.
 */

import { describe, expect, it } from "vitest";
import { PROTOCOL_BREAKDOWN } from "../../lib/mcp/protocols.js";
import dashboardSrc from "./DashboardPage.tsx?raw";

describe("DashboardPage protocol breakdown queries", () => {
  it("query every PROTOCOL_BREAKDOWN row exactly once, in order", () => {
    const indices = [...dashboardSrc.matchAll(/useQuery\("flows", breakdownQuery\((\d+)\)\)/g)].map(
      (m) => Number(m[1]),
    );
    expect(indices).toEqual(PROTOCOL_BREAKDOWN.map((_, i) => i));
  });
});
