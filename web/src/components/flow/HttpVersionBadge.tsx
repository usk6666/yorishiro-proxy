import type { FlowEntry } from "../../lib/mcp/types.js";

export interface HttpVersionBadgeProps {
  flow: Pick<FlowEntry, "protocol" | "http_version">;
}

// Red-phase stub.
export function HttpVersionBadge(_props: HttpVersionBadgeProps) {
  return null;
}
