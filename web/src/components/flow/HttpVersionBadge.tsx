/**
 * HttpVersionBadge -- a flow's wire `http_version` as a badge.
 *
 * Shows the version verbatim (http/1.0, http/1.1, h2, h2c, ...). HTTP/2
 * streams are recorded as `protocol: "http"`, so this is what keeps h2
 * distinguishable from HTTP/1.x; h2 / h2c are highlighted. Renders nothing
 * when the flow has no recorded version (non-HTTP streams, rows predating
 * the field). Shared by the FlowDetail header and the Flows list.
 */

import { Badge } from "../ui/Badge.js";
import { isHttp2, type HttpVersionedFlow } from "../../lib/mcp/dispatch.js";

export interface HttpVersionBadgeProps {
  flow: HttpVersionedFlow;
}

export function HttpVersionBadge({ flow }: HttpVersionBadgeProps) {
  const version = flow.http_version ?? "";
  if (version === "") return null;

  return <Badge variant={isHttp2(flow) ? "info" : "default"}>{version}</Badge>;
}
