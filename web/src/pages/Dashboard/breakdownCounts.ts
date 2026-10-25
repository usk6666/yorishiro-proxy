/**
 * Per-row flow counts for the Dashboard "Flows by Protocol" breakdown.
 *
 * The queries are derived from the rows (`rows.map`), and the counts come
 * back aligned with them, so a new PROTOCOL_BREAKDOWN row gets its count
 * query without any per-row code. There is no server-side per-protocol
 * aggregate, so this is one `flows` query with `limit: 0` per row.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { McpClient } from "../../lib/mcp/client.js";
import { useMcpContext } from "../../lib/mcp/context.js";
import type { ProtocolBreakdownEntry } from "../../lib/mcp/protocols.js";

/** The part of McpClient the breakdown needs. */
export type BreakdownQueryClient = Pick<McpClient, "query">;

/** Count of flows per breakdown row, aligned with `rows`. Null = unknown. */
export type BreakdownCounts = (number | null)[];

/**
 * Fetch the flow count of every row, in row order.
 *
 * A row whose query fails keeps its `previous` count (null if it never
 * loaded); the other rows still update.
 */
export async function fetchBreakdownCounts(
  client: BreakdownQueryClient,
  rows: readonly ProtocolBreakdownEntry[],
  previous: readonly (number | null)[] = [],
): Promise<BreakdownCounts> {
  const results = await Promise.allSettled(
    rows.map((row) => client.query({ resource: "flows", limit: 0, filter: row.filter })),
  );
  return results.map((r, i) =>
    r.status === "fulfilled" ? r.value.total : (previous[i] ?? null),
  );
}

/** Return type of useBreakdownCounts. */
export interface UseBreakdownCountsResult {
  /** Count per row, aligned with `rows`. */
  counts: BreakdownCounts;
  /** Re-fetch every row now. */
  refetch: () => Promise<void>;
}

/**
 * Poll the flow count of every breakdown row while connected.
 *
 * `rows` must be stable across renders (a module constant such as
 * PROTOCOL_BREAKDOWN); a new array identity restarts polling.
 */
export function useBreakdownCounts(
  rows: readonly ProtocolBreakdownEntry[],
  pollInterval: number,
): UseBreakdownCountsResult {
  const { client, status } = useMcpContext();
  const [counts, setCounts] = useState<BreakdownCounts>(() => rows.map(() => null));
  const countsRef = useRef(counts);
  countsRef.current = counts;

  const load = useCallback(
    async (isLive: () => boolean) => {
      if (!client || status !== "connected") return;
      const next = await fetchBreakdownCounts(client, rows, countsRef.current);
      if (isLive()) setCounts(next);
    },
    [client, status, rows],
  );

  // Liveness of the current polling effect. A fetch started under an
  // effect that has since been cleaned up (status / client / rows change,
  // or unmount) is dropped instead of setting state.
  const isLiveRef = useRef<() => boolean>(() => false);

  useEffect(() => {
    if (status !== "connected") return;
    let cancelled = false;
    const isLive = () => !cancelled;
    isLiveRef.current = isLive;
    load(isLive);
    const timer = setInterval(() => {
      load(isLive);
    }, pollInterval);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [status, load, pollInterval]);

  const refetch = useCallback(() => load(isLiveRef.current), [load]);

  return { counts, refetch };
}
