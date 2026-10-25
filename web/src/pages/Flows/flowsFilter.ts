import type { QueryFilter } from "../../lib/mcp/types.js";

/** Raw Flows-page filter inputs (text inputs already debounced). */
export interface FlowsFilterInputs {
  protocol: string;
  httpVersion: string;
  scheme: string;
  method: string;
  urlPattern: string;
  /** Status code text; ignored unless it parses as an integer. */
  statusCode: string;
  blockedBy: string;
  state: string;
  host: string;
  /** resend_* / fuzz_* tag; sent verbatim (the server matches exactly). */
  tag: string;
  /**
   * Client connection ID (`?conn_id=` on the Flows route); sent verbatim
   * as filter.conn_id (the server matches exactly).
   */
  connId: string;
}

/**
 * Builds the `filter` for `query resource=flows` from the Flows page inputs.
 * Only fields the server applies to resource=flows are emitted: the server
 * rejects the fuzz-only body_contains / outliers_only / status there.
 * Returns undefined when no filter is set.
 */
export function buildFlowsFilter(inputs: FlowsFilterInputs): QueryFilter | undefined {
  const f: QueryFilter = {};
  if (inputs.protocol) {
    f.protocol = inputs.protocol;
  }
  if (inputs.httpVersion) {
    f.http_version = inputs.httpVersion;
  }
  if (inputs.scheme) {
    f.scheme = inputs.scheme;
  }
  if (inputs.method) {
    f.method = inputs.method;
  }
  if (inputs.urlPattern.trim()) {
    f.url_pattern = inputs.urlPattern.trim();
  }
  if (inputs.statusCode) {
    const code = parseInt(inputs.statusCode, 10);
    if (!isNaN(code)) {
      f.status_code = code;
    }
  }
  if (inputs.blockedBy) {
    f.blocked_by = inputs.blockedBy;
  }
  if (inputs.state) {
    f.state = inputs.state;
  }
  if (inputs.host.trim()) {
    f.host = inputs.host.trim();
  }
  if (inputs.tag) {
    f.tag = inputs.tag;
  }
  return Object.keys(f).length > 0 ? f : undefined;
}
