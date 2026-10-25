/**
 * FlowProtocolCell -- contents of the Flows list's Protocol cell: the
 * protocol badge, the wire `http_version` badge (the only thing telling an
 * h2 / h2c row from HTTP/1.x, since HTTP/2 is recorded as `protocol:
 * "http"`), and the SSE marker. Split out of FlowsPage so the cell can be
 * render-tested without mounting the page.
 */

import { HttpVersionBadge } from "../../components/flow/HttpVersionBadge.js";
import { Badge } from "../../components/ui/Badge.js";
import { protocolVariant } from "../../lib/mcp/dispatch.js";
import type { FlowEntry } from "../../lib/mcp/types.js";

export interface FlowProtocolCellProps {
  flow: Pick<FlowEntry, "protocol" | "http_version" | "tags">;
}

export function FlowProtocolCell({ flow }: FlowProtocolCellProps) {
  return (
    <>
      <Badge variant={protocolVariant(flow.protocol)}>{flow.protocol}</Badge>
      <HttpVersionBadge flow={flow} />
      {flow.tags?.streaming_type === "sse" && (
        <Badge variant="warning">SSE</Badge>
      )}
    </>
  );
}
