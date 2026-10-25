/**
 * Per-row flow counts for the Dashboard "Flows by Protocol" breakdown.
 */

import type { McpClient } from "../../lib/mcp/client.js";
import type { ProtocolBreakdownEntry } from "../../lib/mcp/protocols.js";

/** The part of McpClient the breakdown needs. */
export type BreakdownQueryClient = Pick<McpClient, "query">;

/** Count of flows per breakdown row, aligned with `rows`. Null = unknown. */
export type BreakdownCounts = (number | null)[];

/**
 * Fetch the flow count of every row. Not implemented yet.
 */
export async function fetchBreakdownCounts(
  _client: BreakdownQueryClient,
  _rows: readonly ProtocolBreakdownEntry[],
  _previous: readonly (number | null)[] = [],
): Promise<BreakdownCounts> {
  return [];
}
