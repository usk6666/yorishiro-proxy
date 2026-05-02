/**
 * MCP Streamable HTTP client wrapper.
 *
 * Uses the official MCP TypeScript SDK's Client and StreamableHTTPClientTransport
 * to connect to yorishiro-proxy's /mcp endpoint via Streamable HTTP.
 *
 * Provides typed access to yorishiro-proxy's 10 MCP tools:
 * proxy_start, proxy_stop, configure, query, resend,
 * manage, fuzz, macro, intercept, security
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type {
  ConfigureParams,
  ConfigureResult,
  ConnectionStatus,
  ExecuteParams,
  FuzzToolParams,
  InterceptActionParams,
  MacroToolParams,
  ManageParams,
  PluginIntrospectResult,
  PluginToolParams,
  ProxyStartParams,
  ProxyStartResult,
  ProxyStopParams,
  ProxyStopResult,
  QueryParams,
  QueryResource,
  QueryResultMap,
  ResendGRPCParams,
  ResendGRPCResult,
  ResendHTTPParams,
  ResendHTTPResult,
  ResendRawParams,
  ResendRawTypedResult,
  ResendWSParams,
  ResendWSResult,
  SecurityParams,
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
 * to yorishiro-proxy's 10 MCP tools.
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

  /** Query proxy data (flows, status, config, etc.). */
  async query<R extends QueryResource>(
    params: QueryParams & { resource: R },
  ): Promise<QueryResultMap[R]> {
    return this.callTool<QueryResultMap[R]>("query", params as unknown as Record<string, unknown>);
  }

  /** Execute a resend action (resend, resend_raw, tcp_replay). */
  async resend<T = unknown>(
    params: ExecuteParams,
  ): Promise<T> {
    return this.callTool<T>("resend", params as unknown as Record<string, unknown>);
  }

  /** Manage flow data and CA certificates (delete_flows, export_flows, import_flows, regenerate_ca_cert). */
  async manage<T = unknown>(
    params: ManageParams,
  ): Promise<T> {
    return this.callTool<T>("manage", params as unknown as Record<string, unknown>);
  }

  /** Execute fuzz testing campaigns (fuzz, fuzz_pause, fuzz_resume, fuzz_cancel). */
  async fuzz<T = unknown>(
    params: FuzzToolParams,
  ): Promise<T> {
    return this.callTool<T>("fuzz", params as unknown as Record<string, unknown>);
  }

  /** Define and execute macro workflows (define_macro, run_macro, delete_macro). */
  async macro<T = unknown>(
    params: MacroToolParams,
  ): Promise<T> {
    return this.callTool<T>("macro", params as unknown as Record<string, unknown>);
  }

  /** Act on intercepted requests (release, modify_and_forward, drop). */
  async interceptAction<T = unknown>(
    params: InterceptActionParams,
  ): Promise<T> {
    return this.callTool<T>("intercept", params as unknown as Record<string, unknown>);
  }

  /** Configure security settings and target scope rules. */
  async security<T = unknown>(
    params: SecurityParams,
  ): Promise<T> {
    return this.callTool<T>("security", params as unknown as Record<string, unknown>);
  }

  /** Manage Starlark plugins (list, reload, enable, disable). */
  async plugin<T = unknown>(
    params: PluginToolParams,
  ): Promise<T> {
    return this.callTool<T>("plugin", params as unknown as Record<string, unknown>);
  }

  // -----------------------------------------------------------------------
  // RFC-001 N8 protocol-typed helpers (resend_*, plugin_introspect)
  // -----------------------------------------------------------------------

  /** Introspect loaded pluginv2 plugins. Returns an empty list when pluginv2 is not configured. */
  async pluginIntrospect(): Promise<PluginIntrospectResult> {
    return this.callTool<PluginIntrospectResult>("plugin_introspect", {});
  }

  /** Resend an HTTP/1.x or HTTP/2 flow via the protocol-typed resend_http tool. */
  async resendHttp(params: ResendHTTPParams): Promise<ResendHTTPResult> {
    return this.callTool<ResendHTTPResult>(
      "resend_http",
      params as unknown as Record<string, unknown>,
    );
  }

  /** Resend a single WebSocket frame via the protocol-typed resend_ws tool. */
  async resendWs(params: ResendWSParams): Promise<ResendWSResult> {
    return this.callTool<ResendWSResult>(
      "resend_ws",
      params as unknown as Record<string, unknown>,
    );
  }

  /** Resend a gRPC RPC via the protocol-typed resend_grpc tool. */
  async resendGrpc(params: ResendGRPCParams): Promise<ResendGRPCResult> {
    return this.callTool<ResendGRPCResult>(
      "resend_grpc",
      params as unknown as Record<string, unknown>,
    );
  }

  /** Resend a recorded raw byte payload via the protocol-typed resend_raw tool. */
  async resendRaw(params: ResendRawParams): Promise<ResendRawTypedResult> {
    return this.callTool<ResendRawTypedResult>(
      "resend_raw",
      params as unknown as Record<string, unknown>,
    );
  }
}
