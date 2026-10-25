import type { QueryFilter } from "../../lib/mcp/types.js";

/** Raw Flows-page filter inputs (text inputs already debounced). */
export interface FlowsFilterInputs {
  protocol: string;
  httpVersion: string;
  scheme: string;
  method: string;
  urlPattern: string;
  statusCode: string;
  blockedBy: string;
  state: string;
  host: string;
  tag: string;
}

/** Stub — implemented in the green commit. */
export function buildFlowsFilter(_inputs: FlowsFilterInputs): QueryFilter | undefined {
  return undefined;
}
