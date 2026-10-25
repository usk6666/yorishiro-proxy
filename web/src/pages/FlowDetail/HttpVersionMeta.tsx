/**
 * HttpVersionMeta -- the "HTTP version" item in the FlowDetail header.
 *
 * Wraps HttpVersionBadge (shared with the Flows list) in a labelled meta
 * item. Renders nothing when the flow has no recorded version (non-HTTP
 * streams, rows predating the field).
 */

import { HttpVersionBadge } from "../../components/flow/HttpVersionBadge.js";
import type { HttpVersionedFlow } from "../../lib/mcp/dispatch.js";

export interface HttpVersionMetaProps {
  flow: HttpVersionedFlow;
}

export function HttpVersionMeta({ flow }: HttpVersionMetaProps) {
  if ((flow.http_version ?? "") === "") return null;

  return (
    <div className="sd-meta-item">
      <span className="sd-meta-label">HTTP version</span>
      <HttpVersionBadge flow={flow} />
    </div>
  );
}
