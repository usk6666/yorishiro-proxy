/**
 * fetchBreakdownCounts derives one `flows` count query per breakdown row
 * from the rows themselves, so adding a PROTOCOL_BREAKDOWN row cannot
 * leave it without a query (the per-index useQuery list it replaces could).
 */

import { describe, expect, it, vi } from "vitest";
import type { QueryParams } from "../../lib/mcp/types.js";
import {
  PROTOCOL_BREAKDOWN,
  type ProtocolBreakdownEntry,
} from "../../lib/mcp/protocols.js";
import { type BreakdownQueryClient, fetchBreakdownCounts } from "./breakdownCounts.js";

/** A fake client whose `query` answers with `answer(params)`. */
function fakeClient(answer: (params: QueryParams) => Promise<{ total: number }>) {
  const query = vi.fn(answer);
  return { query, client: { query } as unknown as BreakdownQueryClient };
}

/** Total 100 + row index, keyed by the filter the row sends. */
function totalsByFilter(rows: readonly ProtocolBreakdownEntry[]) {
  return (params: QueryParams) => {
    const i = rows.findIndex((r) => JSON.stringify(r.filter) === JSON.stringify(params.filter));
    return i < 0
      ? Promise.reject(new Error(`unexpected filter ${JSON.stringify(params.filter)}`))
      : Promise.resolve({ total: 100 + i });
  };
}

/** Like totalsByFilter, but the plain "sse" row's query rejects. */
function failingSse(rows: readonly ProtocolBreakdownEntry[]) {
  const ok = totalsByFilter(rows);
  return (params: QueryParams) =>
    params.filter?.protocol === "sse" && !params.filter.http_version
      ? Promise.reject(new Error("boom"))
      : ok(params);
}

const sseIndex = PROTOCOL_BREAKDOWN.findIndex((r) => r.label === "sse");

describe("fetchBreakdownCounts", () => {
  it("issues exactly one flows count query per row, in row order", async () => {
    const { query, client } = fakeClient(totalsByFilter(PROTOCOL_BREAKDOWN));
    await fetchBreakdownCounts(client, PROTOCOL_BREAKDOWN);
    expect(query.mock.calls.map(([params]) => params)).toEqual(
      PROTOCOL_BREAKDOWN.map((row) => ({ resource: "flows", limit: 0, filter: row.filter })),
    );
  });

  it("returns each row's total at the row's index", async () => {
    const { client } = fakeClient(totalsByFilter(PROTOCOL_BREAKDOWN));
    const counts = await fetchBreakdownCounts(client, PROTOCOL_BREAKDOWN);
    expect(counts).toEqual(PROTOCOL_BREAKDOWN.map((_, i) => 100 + i));
  });

  it("yields null for a failed row that never loaded, and still fills the others", async () => {
    expect(sseIndex).toBeGreaterThanOrEqual(0);
    const { client } = fakeClient(failingSse(PROTOCOL_BREAKDOWN));
    const counts = await fetchBreakdownCounts(client, PROTOCOL_BREAKDOWN);
    expect(counts).toEqual(PROTOCOL_BREAKDOWN.map((_, i) => (i === sseIndex ? null : 100 + i)));
  });

  it("keeps a failed row's previous count", async () => {
    const { client } = fakeClient(failingSse(PROTOCOL_BREAKDOWN));
    const previous = PROTOCOL_BREAKDOWN.map(() => 7);
    const counts = await fetchBreakdownCounts(client, PROTOCOL_BREAKDOWN, previous);
    expect(counts).toEqual(PROTOCOL_BREAKDOWN.map((_, i) => (i === sseIndex ? 7 : 100 + i)));
  });

  it("covers an added row without any per-row code", async () => {
    const rows: ProtocolBreakdownEntry[] = [
      ...PROTOCOL_BREAKDOWN,
      { label: "x", filter: { protocol: "raw", scheme: "tcp" } },
    ];
    const { query, client } = fakeClient(totalsByFilter(rows));
    const counts = await fetchBreakdownCounts(client, rows);
    expect(query).toHaveBeenCalledTimes(rows.length);
    expect(query).toHaveBeenLastCalledWith({
      resource: "flows",
      limit: 0,
      filter: rows[rows.length - 1].filter,
    });
    expect(counts).toEqual(rows.map((_, i) => 100 + i));
  });
});
