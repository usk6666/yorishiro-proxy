/**
 * React Context for the MCP client.
 *
 * McpProvider (./McpProvider.tsx) supplies the McpClient instance to the
 * component tree. Components access the client through the useMcpContext hook.
 */

import { createContext, useContext } from "react";
import type { McpClient } from "./client.js";
import type { ConnectionStatus } from "./types.js";

/** Values exposed by the MCP context. */
export interface McpContextValue {
  /** The MCP client instance. Null before connection is established. */
  client: McpClient | null;
  /** Current connection status. */
  status: ConnectionStatus;
  /** Last connection error, if any. */
  error: Error | null;
  /** Manually reconnect to the MCP server. */
  reconnect: () => Promise<void>;
}

export const McpContext = createContext<McpContextValue | null>(null);

/**
 * Hook to access the MCP context.
 * Must be used within a McpProvider.
 * @throws Error if used outside of McpProvider.
 */
export function useMcpContext(): McpContextValue {
  const context = useContext(McpContext);
  if (!context) {
    throw new Error("useMcpContext must be used within a McpProvider");
  }
  return context;
}
