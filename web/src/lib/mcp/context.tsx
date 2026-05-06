/**
 * React Context for the MCP client.
 *
 * Provides the McpClient instance to the component tree via McpProvider.
 * Components access the client through the useMcpContext hook.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { clearStoredToken } from "../auth.js";
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
 * It connects on mount and disconnects on unmount. Connection status, errors,
 * and the McpClient instance itself are tracked in React state so that
 * consumers re-render reliably when the client is replaced (e.g., on reconnect).
 */
export function McpProvider({ config, children }: McpProviderProps) {
  const [client, setClient] = useState<McpClient | null>(null);
  const [status, setStatus] = useState<ConnectionStatus>("disconnected");
  const [error, setError] = useState<Error | null>(null);

  // Track the latest config so connect() picks up updates without
  // re-running on every config object identity change.
  const configRef = useRef(config);
  configRef.current = config;

  // Hold the active client outside React state for cleanup; the same
  // instance is mirrored into `client` state above so consumers
  // re-render when it is replaced (e.g., on reconnect).
  const activeClientRef = useRef<McpClient | null>(null);

  const connect = useCallback(async () => {
    // Disconnect any prior client. Fire-and-forget; the new client
    // does not need to wait for the old one's teardown.
    const previous = activeClientRef.current;
    if (previous) {
      void previous.disconnect();
    }

    const newClient = new McpClient(configRef.current);
    activeClientRef.current = newClient;

    // Subscribe to status events.
    newClient.on((event) => {
      // Drop late events from a client that has already been replaced.
      if (activeClientRef.current !== newClient) return;
      if (event.type === "status") {
        setStatus(event.status);
        setError(event.error ?? null);
      } else if (event.type === "error") {
        setError(event.error);
      }
    });

    setClient(newClient);

    try {
      await newClient.connect();
    } catch (err) {
      if (isAuthError(err)) {
        clearStoredToken();
      }
      // Error is already set via the event listener.
    }
  }, []);

  const reconnect = useCallback(async () => {
    await connect();
  }, [connect]);

  useEffect(() => {
    connect();

    return () => {
      const previous = activeClientRef.current;
      activeClientRef.current = null;
      if (previous) {
        void previous.disconnect();
      }
      setClient(null);
    };
  }, [connect]);

  const value = useMemo<McpContextValue>(
    () => ({ client, status, error, reconnect }),
    [client, status, error, reconnect],
  );

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

/**
 * Check if an error is an HTTP 401 authentication error.
 * StreamableHTTPClientTransport throws StreamableHTTPError with code 401.
 */
function isAuthError(err: unknown): boolean {
  return (
    err != null &&
    typeof err === "object" &&
    "code" in err &&
    (err as { code: unknown }).code === 401
  );
}
