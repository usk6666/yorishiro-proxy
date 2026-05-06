/**
 * React hooks for interacting with yorishiro-proxy's 10 MCP tools.
 *
 * These hooks provide a convenient, type-safe API for React components
 * to query data, execute actions, manage flows, run fuzz campaigns,
 * define macros, act on intercepted requests, configure security,
 * configure the proxy, and control proxy listeners.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useMcpContext } from "./context.js";
import type { McpClient } from "./client.js";
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
  ProxyStartParams,
  ProxyStartResult,
  ProxyStopParams,
  ProxyStopResult,
  QueryFilter,
  QueryResource,
  QueryResultMap,
  SecurityParams,
} from "./types.js";

// ---------------------------------------------------------------------------
// useMcpClient — connection management
// ---------------------------------------------------------------------------

/** Return type for useMcpClient. */
export interface UseMcpClientResult {
  /** Current connection status. */
  status: ConnectionStatus;
  /** Last connection error, if any. */
  error: Error | null;
  /** Whether the client is connected. */
  connected: boolean;
  /** Reconnect to the MCP server. */
  reconnect: () => Promise<void>;
}

/**
 * Hook to access the MCP client connection state.
 * The client is managed by McpProvider; this hook provides status observation.
 */
export function useMcpClient(): UseMcpClientResult {
  const { status, error, reconnect } = useMcpContext();

  return {
    status,
    error,
    connected: status === "connected",
    reconnect,
  };
}

// ---------------------------------------------------------------------------
// useMcpAction — shared action hook foundation
// ---------------------------------------------------------------------------

/** Return shape shared by every MCP action hook. */
export interface UseMcpActionResult<P, R> {
  /** Execute the action with the given params. Throws if disconnected. */
  execute: (params: P) => Promise<R>;
  /** Whether an execution is in progress. */
  loading: boolean;
  /** Last execution error, if any. */
  error: Error | null;
}

/**
 * Sentinel error message thrown when an action is invoked while the MCP
 * client is not connected. Exported so unit tests can match on it.
 */
export const MCP_NOT_CONNECTED_MESSAGE = "MCP client is not connected";

/**
 * Pure runner for MCP actions. Encapsulates the loading/error state
 * machine shared by every action hook so the logic is unit-testable in
 * isolation (without React). The wrapper hook below threads React state
 * setters through this function.
 *
 * @param call    The protocol method to invoke (`(client, params) => Promise<R>`).
 * @param client  The connected MCP client, or null when disconnected.
 * @param status  The connection status from McpContext.
 * @param params  The arguments to pass through to `call`.
 * @param sinks   Hooks for state mutation. Tests pass plain mutators;
 *                the React hook below passes its `setLoading`/`setError`.
 * @throws Error("MCP client is not connected") when `client` is null
 *         or `status !== "connected"`.
 * @throws The original error from `call`, after recording it via `setError`.
 */
export async function runMcpAction<P, R>(
  call: (client: McpClient, params: P) => Promise<R>,
  client: McpClient | null,
  status: ConnectionStatus,
  params: P,
  sinks: {
    setLoading: (v: boolean) => void;
    setError: (e: Error | null) => void;
  },
): Promise<R> {
  if (!client || status !== "connected") {
    throw new Error(MCP_NOT_CONNECTED_MESSAGE);
  }

  sinks.setLoading(true);
  sinks.setError(null);

  try {
    return await call(client, params);
  } catch (err) {
    const e = err instanceof Error ? err : new Error(String(err));
    sinks.setError(e);
    throw e;
  } finally {
    sinks.setLoading(false);
  }
}

/**
 * Generic foundation hook for the MCP action tools.
 *
 * Wraps a `(client, params) => Promise<result>` call in the standard
 * loading/error state machine used by every action hook below. The 8
 * concrete action hooks (`useResend`, `useManage`, ...) are thin
 * re-exports of this hook with the matching `client.<method>` plumbed in.
 */
export function useMcpAction<P, R>(
  call: (client: McpClient, params: P) => Promise<R>,
): UseMcpActionResult<P, R> {
  const { client, status } = useMcpContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const execute = useCallback(
    (params: P): Promise<R> =>
      runMcpAction(call, client, status, params, { setLoading, setError }),
    [client, status, call],
  );

  return { execute, loading, error };
}

// ---------------------------------------------------------------------------
// useQuery — query tool
// ---------------------------------------------------------------------------

/** Options for the useQuery hook. */
export interface UseQueryOptions {
  /** Polling interval in milliseconds. Set to 0 or undefined to disable. */
  pollInterval?: number;
  /** When false, the query is not executed. Defaults to true. */
  enabled?: boolean;
  /** Additional filter parameters. */
  filter?: QueryFilter;
  /** Flow or macro ID (for resource="flow", "messages", "macro"). */
  id?: string;
  /** Fuzz job ID (for resource="fuzz_results"). */
  fuzzId?: string;
  /** Fields to include in the response. */
  fields?: string[];
  /** Sort field (for fuzz_results). */
  sortBy?: string;
  /** Page size limit. */
  limit?: number;
  /** Pagination offset. */
  offset?: number;
}

/** Return type for useQuery. */
export interface UseQueryResult<T> {
  /** Query result data. Null if not yet loaded or on error. */
  data: T | null;
  /** Whether a query is in progress. */
  loading: boolean;
  /** Last query error, if any. */
  error: Error | null;
  /** Manually re-execute the query. */
  refetch: () => Promise<void>;
}

/**
 * Hook to call the MCP query tool with typed results.
 *
 * Supports automatic polling and conditional execution. The query
 * automatically re-fetches when filter / fields / sortBy / limit /
 * offset / id / fuzzId change — a stable JSON cache key is derived
 * from those fields and used as the fetch callback dependency.
 *
 * @example
 * ```tsx
 * const { data, loading, error } = useQuery("flows", {
 *   pollInterval: 2000,
 *   limit: 50,
 * });
 * ```
 */
export function useQuery<R extends QueryResource>(
  resource: R,
  options: UseQueryOptions = {},
): UseQueryResult<QueryResultMap[R]> {
  const { client, status } = useMcpContext();
  const [data, setData] = useState<QueryResultMap[R] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const enabled = options.enabled !== false;
  const pollInterval = options.pollInterval;

  // Stable JSON key over the request-shaping fields. Order matters and
  // must stay in lock-step with the query call below so consumers get
  // a deterministic cache hit when option identity changes between
  // renders but the values themselves are equal.
  const optionsKey = useMemo(
    () =>
      JSON.stringify({
        filter: options.filter ?? null,
        fields: options.fields ?? null,
        sort_by: options.sortBy ?? null,
        limit: options.limit ?? null,
        offset: options.offset ?? null,
        id: options.id ?? null,
        fuzzId: options.fuzzId ?? null,
      }),
    [
      options.filter,
      options.fields,
      options.sortBy,
      options.limit,
      options.offset,
      options.id,
      options.fuzzId,
    ],
  );

  const fetchData = useCallback(async () => {
    if (!client || status !== "connected") return;

    // Re-parse the stable key rather than capturing the raw options
    // object, so the callback identity tracks `optionsKey` exactly.
    const opts = JSON.parse(optionsKey) as {
      filter: QueryFilter | null;
      fields: string[] | null;
      sort_by: string | null;
      limit: number | null;
      offset: number | null;
      id: string | null;
      fuzzId: string | null;
    };

    setLoading(true);
    setError(null);

    try {
      const result = await client.query({
        resource,
        id: opts.id ?? undefined,
        fuzz_id: opts.fuzzId ?? undefined,
        filter: opts.filter ?? undefined,
        fields: opts.fields ?? undefined,
        sort_by: opts.sort_by ?? undefined,
        limit: opts.limit ?? undefined,
        offset: opts.offset ?? undefined,
      });
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, [client, status, resource, optionsKey]);

  // Execute query when connected and enabled.
  useEffect(() => {
    if (!enabled || status !== "connected") return;
    fetchData();
  }, [enabled, status, fetchData]);

  // Polling.
  useEffect(() => {
    if (!enabled || !pollInterval || pollInterval <= 0 || status !== "connected") {
      return;
    }

    const timer = setInterval(() => {
      fetchData();
    }, pollInterval);

    return () => clearInterval(timer);
  }, [enabled, status, fetchData, pollInterval]);

  return { data, loading, error, refetch: fetchData };
}

// ---------------------------------------------------------------------------
// useResend — resend tool (resend, resend_raw, tcp_replay)
// ---------------------------------------------------------------------------

/** Return type for useResend. */
export interface UseResendResult {
  /** Execute a resend action (resend, resend_raw, tcp_replay). Returns the tool result. */
  resend: <T = unknown>(params: ExecuteParams) => Promise<T>;
  /** Whether an execution is in progress. */
  loading: boolean;
  /** Last execution error, if any. */
  error: Error | null;
}

/**
 * Hook to call the MCP resend tool (resend, resend_raw, tcp_replay).
 *
 * @example
 * ```tsx
 * const { resend, loading, error } = useResend();
 * await resend({
 *   action: "resend",
 *   params: { flow_id: "abc123" },
 * });
 * ```
 */
export function useResend(): UseResendResult {
  const { execute, loading, error } = useMcpAction(
    (client: McpClient, params: ExecuteParams) => client.resend(params),
  );
  return {
    resend: execute as <T = unknown>(params: ExecuteParams) => Promise<T>,
    loading,
    error,
  };
}

/** @deprecated Use useResend instead. */
export const useExecute = useResend;
/** @deprecated Use UseResendResult instead. */
export type UseExecuteResult = UseResendResult;

// ---------------------------------------------------------------------------
// useManage — manage tool (delete_flows, export_flows, import_flows, regenerate_ca_cert)
// ---------------------------------------------------------------------------

/** Return type for useManage. */
export interface UseManageResult {
  /** Execute a manage action. Returns the tool result. */
  manage: <T = unknown>(params: ManageParams) => Promise<T>;
  /** Whether a manage operation is in progress. */
  loading: boolean;
  /** Last manage error, if any. */
  error: Error | null;
}

/**
 * Hook to call the MCP manage tool (delete_flows, export_flows, import_flows, regenerate_ca_cert).
 *
 * @example
 * ```tsx
 * const { manage, loading, error } = useManage();
 * await manage({
 *   action: "delete_flows",
 *   params: { flow_id: "abc123", confirm: true },
 * });
 * ```
 */
export function useManage(): UseManageResult {
  const { execute, loading, error } = useMcpAction(
    (client: McpClient, params: ManageParams) => client.manage(params),
  );
  return {
    manage: execute as <T = unknown>(params: ManageParams) => Promise<T>,
    loading,
    error,
  };
}

// ---------------------------------------------------------------------------
// useFuzz — fuzz tool (fuzz, fuzz_pause, fuzz_resume, fuzz_cancel)
// ---------------------------------------------------------------------------

/** Return type for useFuzz. */
export interface UseFuzzResult {
  /** Execute a fuzz action. Returns the tool result. */
  fuzz: <T = unknown>(params: FuzzToolParams) => Promise<T>;
  /** Whether a fuzz operation is in progress. */
  loading: boolean;
  /** Last fuzz error, if any. */
  error: Error | null;
}

/**
 * Hook to call the MCP fuzz tool (fuzz, fuzz_pause, fuzz_resume, fuzz_cancel).
 *
 * @example
 * ```tsx
 * const { fuzz, loading, error } = useFuzz();
 * await fuzz({
 *   action: "fuzz",
 *   params: { flow_id: "abc123", attack_type: "sequential", positions: [...] },
 * });
 * ```
 */
export function useFuzz(): UseFuzzResult {
  const { execute, loading, error } = useMcpAction(
    (client: McpClient, params: FuzzToolParams) => client.fuzz(params),
  );
  return {
    fuzz: execute as <T = unknown>(params: FuzzToolParams) => Promise<T>,
    loading,
    error,
  };
}

// ---------------------------------------------------------------------------
// useMacro — macro tool (define_macro, run_macro, delete_macro)
// ---------------------------------------------------------------------------

/** Return type for useMacro. */
export interface UseMacroResult {
  /** Execute a macro action. Returns the tool result. */
  macro: <T = unknown>(params: MacroToolParams) => Promise<T>;
  /** Whether a macro operation is in progress. */
  loading: boolean;
  /** Last macro error, if any. */
  error: Error | null;
}

/**
 * Hook to call the MCP macro tool (define_macro, run_macro, delete_macro).
 *
 * @example
 * ```tsx
 * const { macro, loading, error } = useMacro();
 * await macro({
 *   action: "run_macro",
 *   params: { name: "my-macro" },
 * });
 * ```
 */
export function useMacro(): UseMacroResult {
  const { execute, loading, error } = useMcpAction(
    (client: McpClient, params: MacroToolParams) => client.macro(params),
  );
  return {
    macro: execute as <T = unknown>(params: MacroToolParams) => Promise<T>,
    loading,
    error,
  };
}

// ---------------------------------------------------------------------------
// useInterceptAction — intercept tool (release, modify_and_forward, drop)
// ---------------------------------------------------------------------------

/** Return type for useInterceptAction. */
export interface UseInterceptActionResult {
  /** Execute an intercept queue action. Returns the tool result. */
  interceptAction: <T = unknown>(params: InterceptActionParams) => Promise<T>;
  /** Whether an intercept action is in progress. */
  loading: boolean;
  /** Last intercept action error, if any. */
  error: Error | null;
}

/**
 * Hook to call the MCP intercept tool (release, modify_and_forward, drop).
 *
 * @example
 * ```tsx
 * const { interceptAction, loading, error } = useInterceptAction();
 * await interceptAction({
 *   action: "release",
 *   params: { intercept_id: "abc123" },
 * });
 * ```
 */
export function useInterceptAction(): UseInterceptActionResult {
  const { execute, loading, error } = useMcpAction(
    (client: McpClient, params: InterceptActionParams) =>
      client.interceptAction(params),
  );
  return {
    interceptAction: execute as <T = unknown>(
      params: InterceptActionParams,
    ) => Promise<T>,
    loading,
    error,
  };
}

// ---------------------------------------------------------------------------
// useSecurity — security tool (set_target_scope, update_target_scope, get_target_scope, test_target)
// ---------------------------------------------------------------------------

/** Return type for useSecurity. */
export interface UseSecurityResult {
  /** Execute a security action. Returns the tool result. */
  security: <T = unknown>(params: SecurityParams) => Promise<T>;
  /** Whether a security operation is in progress. */
  loading: boolean;
  /** Last security error, if any. */
  error: Error | null;
}

/**
 * Hook to call the MCP security tool (set_target_scope, update_target_scope, get_target_scope, test_target).
 *
 * @example
 * ```tsx
 * const { security, loading, error } = useSecurity();
 * const result = await security({
 *   action: "get_target_scope",
 *   params: {},
 * });
 * ```
 */
export function useSecurity(): UseSecurityResult {
  const { execute, loading, error } = useMcpAction(
    (client: McpClient, params: SecurityParams) => client.security(params),
  );
  return {
    security: execute as <T = unknown>(params: SecurityParams) => Promise<T>,
    loading,
    error,
  };
}

// ---------------------------------------------------------------------------
// useConfigure — configure tool
// ---------------------------------------------------------------------------

/** Return type for useConfigure. */
export interface UseConfigureResult {
  /** Apply configuration changes. Returns the configure result. */
  configure: (params: ConfigureParams) => Promise<ConfigureResult>;
  /** Whether a configuration change is in progress. */
  loading: boolean;
  /** Last configuration error, if any. */
  error: Error | null;
}

/**
 * Hook to call the MCP configure tool.
 *
 * @example
 * ```tsx
 * const { configure, loading } = useConfigure();
 * await configure({
 *   capture_scope: {
 *     add_includes: [{ hostname: "example.com" }],
 *   },
 * });
 * ```
 */
export function useConfigure(): UseConfigureResult {
  const { execute, loading, error } = useMcpAction(
    (client: McpClient, params: ConfigureParams) => client.configure(params),
  );
  return { configure: execute, loading, error };
}

// ---------------------------------------------------------------------------
// useProxyControl — proxy_start / proxy_stop
// ---------------------------------------------------------------------------

/** Return type for useProxyControl. */
export interface UseProxyControlResult {
  /** Start a proxy listener. */
  start: (params?: ProxyStartParams) => Promise<ProxyStartResult>;
  /** Stop proxy listener(s). */
  stop: (params?: ProxyStopParams) => Promise<ProxyStopResult>;
  /** Whether a proxy control operation is in progress. */
  loading: boolean;
  /** Last proxy control error, if any. */
  error: Error | null;
}

/**
 * Hook to control proxy listeners (start/stop).
 *
 * @example
 * ```tsx
 * const { start, stop, loading } = useProxyControl();
 * await start({ listen_addr: "127.0.0.1:8080" });
 * await stop();
 * ```
 */
export function useProxyControl(): UseProxyControlResult {
  const startAction = useMcpAction(
    (client: McpClient, params: ProxyStartParams) => client.proxyStart(params),
  );
  const stopAction = useMcpAction(
    (client: McpClient, params: ProxyStopParams) => client.proxyStop(params),
  );

  const start = useCallback(
    (params: ProxyStartParams = {}) => startAction.execute(params),
    [startAction],
  );
  const stop = useCallback(
    (params: ProxyStopParams = {}) => stopAction.execute(params),
    [stopAction],
  );

  // Surface either action's pending state / latest error.
  return {
    start,
    stop,
    loading: startAction.loading || stopAction.loading,
    error: startAction.error ?? stopAction.error,
  };
}

// ---------------------------------------------------------------------------
// usePluginIntrospect — plugin_introspect tool (RFC-001 N8 pluginv2)
// ---------------------------------------------------------------------------

/** Return type for usePluginIntrospect. */
export interface UsePluginIntrospectResult {
  /** Latest introspect snapshot. Null while the first fetch is in flight. */
  data: PluginIntrospectResult | null;
  /** Whether a fetch is currently in progress. */
  loading: boolean;
  /** Last fetch error, if any. */
  error: Error | null;
  /** Manually re-fetch the introspect snapshot. */
  refetch: () => Promise<void>;
}

/**
 * Hook that auto-fetches the plugin_introspect MCP tool when the client
 * connects. Modelled on useQuery's enabled+refetch pattern but for the
 * parameterless plugin_introspect tool.
 */
export function usePluginIntrospect(): UsePluginIntrospectResult {
  const { client, status } = useMcpContext();
  const [data, setData] = useState<PluginIntrospectResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const refetch = useCallback(async () => {
    if (!client || status !== "connected") return;
    setLoading(true);
    setError(null);
    try {
      const result = await client.pluginIntrospect();
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, [client, status]);

  useEffect(() => {
    if (status !== "connected") return;
    refetch();
  }, [status, refetch]);

  return { data, loading, error, refetch };
}
