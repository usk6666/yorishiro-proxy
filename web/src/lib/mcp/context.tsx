/**
 * React Context for the MCP client.
 *
 * Provides the McpClient instance to the component tree via McpProvider.
 * Components access the client through the useMcpContext hook.
 */

import {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  useCallback,
  type ReactNode,
} from "react";
import { McpClient, type McpClientConfig } from "./client.js";
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

const McpContext = createContext<McpContextValue | null>(null);

/** Props for the McpProvider component. */
export interface McpProviderProps {
  /** MCP client configuration. */
  config: McpClientConfig;
  /** Child components. */
  children: ReactNode;
}

/**
 * McpProvider manages the MCP client lifecycle and provides it to the component tree.
 *
 * It connects on mount and disconnects on unmount. Connection status and errors
 * are tracked in React state.
 */
export function McpProvider({ config, children }: McpProviderProps) {
  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [error, setError] = useState<Error | null>(null);
  const clientRef = useRef<McpClient | null>(null);
  // Track current config to detect changes.
  const configRef = useRef(config);
  configRef.current = config;

  const connect = useCallback(async () => {
    // Disconnect existing client if any.
    if (clientRef.current) {
      await clientRef.current.disconnect();
    }

    const client = new McpClient(configRef.current);

    // Subscribe to status events.
    client.on((event) => {
      if (event.type === "status") {
        setStatus(event.status);
        setError(event.error ?? null);
      } else if (event.type === "error") {
        setError(event.error);
      }
    });

    clientRef.current = client;

    try {
      await client.connect();
    } catch {
      // Error is already set via the event listener.
    }
  }, []);

  const reconnect = useCallback(async () => {
    await connect();
  }, [connect]);

  useEffect(() => {
    connect();

    return () => {
      clientRef.current?.disconnect();
      clientRef.current = null;
    };
  }, [connect]);

  const value: McpContextValue = {
    client: clientRef.current,
    status,
    error,
    reconnect,
  };

  return <McpContext.Provider value={value}>{children}</McpContext.Provider>;
}

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
