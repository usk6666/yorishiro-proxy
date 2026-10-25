/**
 * HttpVersionMeta -- the "HTTP version" item in the FlowDetail header.
 *
 * Shows the flow's wire `http_version` verbatim (http/1.0, http/1.1, h2,
 * h2c, ...). HTTP/2 streams are recorded as `protocol: "http"`, so this is
 * what keeps h2 distinguishable from HTTP/1.x; h2 / h2c are highlighted.
 * Renders nothing when the flow has no recorded version (non-HTTP streams,
 * rows predating the field).
 */

import { Badge } from "../../components/ui/Badge.js";
import { isHttp2 } from "../../lib/mcp/dispatch.js";
import type { FlowDetailResult } from "../../lib/mcp/types.js";

export interface HttpVersionMetaProps {
  flow: Pick<FlowDetailResult, "protocol" | "http_version">;
}

export function HttpVersionMeta({ flow }: HttpVersionMetaProps) {
  const version = flow.http_version ?? "";
  if (version === "") return null;

  return (
    <div className="sd-meta-item">
      <span className="sd-meta-label">HTTP version</span>
      <Badge variant={isHttp2(flow) ? "info" : "default"}>{version}</Badge>
    </div>
  );
}
