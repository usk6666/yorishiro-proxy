/**
 * MCP Streamable HTTP client wrapper.
 *
 * Uses the official MCP TypeScript SDK's Client and StreamableHTTPClientTransport
 * to connect to yorishiro-proxy's /mcp endpoint via Streamable HTTP.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  ConnectionStatus,
  ConfigureParams,
  ConfigureResult,
  ExecuteParams,
  ProxyStartParams,
  ProxyStartResult,
  ProxyStopParams,
  ProxyStopResult,
  QueryParams,
  QueryResource,
  QueryResultMap,
} from "./types.js";

/** Configuration for the MCP client. */
export interface McpClientConfig {
  /** The base URL for the MCP endpoint (e.g., "/mcp" or "http://localhost:8943/mcp"). */
  url: string;
  /** Optional Bearer token for authentication. */
  token?: string;
}

/** Event types emitted by the MCP client. */
export type McpClientEvent =
  | { type: "status"; status: ConnectionStatus; error?: Error }
  | { type: "error"; error: Error };

/** Listener callback for MCP client events. */
export type McpClientEventListener = (event: McpClientEvent) => void;

/**
 * McpClient wraps the MCP SDK Client to provide typed access
 * to yorishiro-proxy's 5 MCP tools.
 */
export class McpClient {
  private client: Client | null = null;
  private transport: StreamableHTTPClientTransport | null = null;
  private _status: ConnectionStatus = "disconnected";
  private _error: Error | null = null;
  private listeners = new Set<McpClientEventListener>();
  private config: McpClientConfig;

  constructor(config: McpClientConfig) {
    this.config = config;
  }

  /** Current connection status. */
  get status(): ConnectionStatus {
    return this._status;
  }

  /** Last error, if any. */
  get error(): Error | null {
    return this._error;
  }

  /** Subscribe to client events. Returns an unsubscribe function. */
  on(listener: McpClientEventListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private emit(event: McpClientEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // Swallow listener errors to prevent cascading failures.
      }
    }
  }

  private setStatus(status: ConnectionStatus, error?: Error): void {
    this._status = status;
    this._error = error ?? null;
    this.emit({ type: "status", status, error });
  }

  /**
   * Connect to the MCP server.
   * Performs the MCP initialize handshake and transitions to "connected" status.
   */
  async connect(): Promise<void> {
    if (this._status === "connected" || this._status === "connecting") {
      return;
    }

    this.setStatus("connecting");

    try {
      // Build URL - resolve relative paths against the current origin.
      const resolvedUrl = new URL(this.config.url, window.location.origin);

      // Build request headers for authentication.
      const headers: Record<string, string> = {};
      if (this.config.token) {
        headers["Authorization"] = `Bearer ${this.config.token}`;
      }

      this.transport = new StreamableHTTPClientTransport(resolvedUrl, {
        requestInit: {
          headers,
        },
      });

      this.client = new Client({
        name: "yorishiro-proxy-webui",
        version: "0.0.0",
      });

      await this.client.connect(this.transport);
      this.setStatus("connected");
    } catch (err) {
      const error =
        err instanceof Error ? err : new Error(String(err));
      this.setStatus("error", error);
      throw error;
    }
  }

  /**
   * Disconnect from the MCP server.
   */
  async disconnect(): Promise<void> {
    try {
      if (this.client) {
        await this.client.close();
      }
    } catch {
      // Ignore disconnect errors.
    } finally {
      this.client = null;
      this.transport = null;
      this.setStatus("disconnected");
    }
  }

  /**
   * Call an MCP tool and return the parsed result.
   * @throws Error if not connected or the tool call fails.
   */
  async callTool<T>(
    name: string,
    args: Record<string, unknown>,
  ): Promise<T> {
    if (!this.client || this._status !== "connected") {
      throw new Error("MCP client is not connected");
    }

    const result = await this.client.callTool({ name, arguments: args });

    if (result.isError) {
      // Extract error message from the MCP tool result.
      const errorText =
        result.content &&
        Array.isArray(result.content) &&
        result.content.length > 0 &&
        typeof result.content[0] === "object" &&
        "text" in result.content[0]
          ? (result.content[0] as { text: string }).text
          : "Tool call failed";
      throw new Error(errorText);
    }

    // Parse the structured result from the content.
    if (
      result.content &&
      Array.isArray(result.content) &&
      result.content.length > 0
    ) {
      const first = result.content[0];
      if (typeof first === "object" && "text" in first) {
        return JSON.parse((first as { text: string }).text) as T;
      }
    }

    return result as unknown as T;
  }

  // -----------------------------------------------------------------------
  // Typed tool methods
  // -----------------------------------------------------------------------

  /** Start a proxy listener. */
  async proxyStart(
    params: ProxyStartParams = {},
  ): Promise<ProxyStartResult> {
    return this.callTool<ProxyStartResult>("proxy_start", params as Record<string, unknown>);
  }

  /** Stop proxy listener(s). */
  async proxyStop(
    params: ProxyStopParams = {},
  ): Promise<ProxyStopResult> {
    return this.callTool<ProxyStopResult>("proxy_stop", params as Record<string, unknown>);
  }

  /** Configure runtime proxy settings. */
  async configure(
    params: ConfigureParams,
  ): Promise<ConfigureResult> {
    return this.callTool<ConfigureResult>("configure", params as unknown as Record<string, unknown>);
  }

  /** Query proxy data (sessions, status, config, etc.). */
  async query<R extends QueryResource>(
    params: QueryParams & { resource: R },
  ): Promise<QueryResultMap[R]> {
    return this.callTool<QueryResultMap[R]>("query", params as unknown as Record<string, unknown>);
  }

  /** Execute an action (resend, delete, fuzz, etc.). */
  async execute<T = unknown>(
    params: ExecuteParams,
  ): Promise<T> {
    return this.callTool<T>("execute", params as unknown as Record<string, unknown>);
  }
}
