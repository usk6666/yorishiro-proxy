/**
 * ConnectionMeta -- the "Connection" item in the FlowDetail header.
 *
 * Shows the flow's client connection ID (`conn_id`, unique per accepted
 * client TCP connection) and links to the Flows list filtered to it, so the
 * other h2 streams multiplexed on that connection — or the other HTTP/1.x
 * keep-alive requests — are one click away. It is the same *client*
 * connection; flows on it may still have used different upstream legs.
 *
 * Renders nothing for an empty conn_id: streams recorded by resend_* /
 * fuzz_* carry none, and an empty filter.conn_id would list every flow.
 */

import { Link } from "react-router-dom";
import type { FlowDetailResult } from "../../lib/mcp/types.js";

export interface ConnectionMetaProps {
  flow: Pick<FlowDetailResult, "conn_id">;
}

export function ConnectionMeta({ flow }: ConnectionMetaProps) {
  const connId = flow.conn_id ?? "";
  if (connId === "") return null;

  return (
    <div className="sd-meta-item">
      <span className="sd-meta-label">Connection</span>
      <span className="sd-meta-value sd-conn-id" title={connId}>
        {connId}
      </span>
      <Link
        className="sd-conn-link"
        to={{ pathname: "/", search: new URLSearchParams({ conn_id: connId }).toString() }}
        title="Flows recorded on the same client connection"
      >
        Flows on this connection
      </Link>
    </div>
  );
}
