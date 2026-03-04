/**
 * React hooks for interacting with yorishiro-proxy's 10 MCP tools.
 *
 * These hooks provide a convenient, type-safe API for React components
 * to query data, execute actions, manage flows, run fuzz campaigns,
 * define macros, act on intercepted requests, configure security,
 * configure the proxy, and control proxy listeners.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { useMcpContext } from "./context.js";
import type {
  ConnectionStatus,
  ConfigureParams,
  ConfigureResult,
  ExecuteParams,
  FuzzToolParams,
  InterceptActionParams,
  MacroToolParams,
  ManageParams,
  ProxyStartParams,
  ProxyStartResult,
  ProxyStopParams,
  ProxyStopResult,
  QueryResource,
  QueryResultMap,
  QueryFilter,
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
 * Supports automatic polling and conditional execution.
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

  // Use a ref for the options to avoid re-creating the fetch callback on every render,
  // while still using the latest options when the callback is invoked.
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const enabled = options.enabled !== false;

  const fetchData = useCallback(async () => {
    if (!client || status !== "connected") return;

    const opts = optionsRef.current;
    setLoading(true);
    setError(null);

    try {
      const result = await client.query({
        resource,
        id: opts.id,
        fuzz_id: opts.fuzzId,
        filter: opts.filter,
        fields: opts.fields,
        sort_by: opts.sortBy,
        limit: opts.limit,
        offset: opts.offset,
      });
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setLoading(false);
    }
  }, [client, status, resource]);

  // Execute query when connected and enabled.
  useEffect(() => {
    if (!enabled || status !== "connected") return;
    fetchData();
  }, [enabled, status, fetchData]);

  // Polling.
  useEffect(() => {
    const pollInterval = optionsRef.current.pollInterval;
    if (!enabled || !pollInterval || pollInterval <= 0 || status !== "connected") {
      return;
    }

    const timer = setInterval(() => {
      fetchData();
    }, pollInterval);

    return () => clearInterval(timer);
  }, [enabled, status, fetchData, options.pollInterval]);

  return { data, loading, error, refetch: fetchData };
}

// ---------------------------------------------------------------------------
// useExecute — execute tool (resend, resend_raw, tcp_replay)
// ---------------------------------------------------------------------------

/** Return type for useExecute. */
export interface UseExecuteResult {
  /** Execute a resend action (resend, resend_raw, tcp_replay). Returns the tool result. */
  execute: <T = unknown>(params: ExecuteParams) => Promise<T>;
  /** Whether an execution is in progress. */
  loading: boolean;
  /** Last execution error, if any. */
  error: Error | null;
}

/**
 * Hook to call the MCP execute tool (resend, resend_raw, tcp_replay).
 *
 * @example
 * ```tsx
 * const { execute, loading, error } = useExecute();
 * await execute({
 *   action: "resend",
 *   params: { flow_id: "abc123" },
 * });
 * ```
 */
export function useExecute(): UseExecuteResult {
  const { client, status } = useMcpContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const execute = useCallback(
    async <T = unknown>(params: ExecuteParams): Promise<T> => {
      if (!client || status !== "connected") {
        throw new Error("MCP client is not connected");
      }

      setLoading(true);
      setError(null);

      try {
        const result = await client.execute<T>(params);
        return result;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [client, status],
  );

  return { execute, loading, error };
}

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
  const { client, status } = useMcpContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const manage = useCallback(
    async <T = unknown>(params: ManageParams): Promise<T> => {
      if (!client || status !== "connected") {
        throw new Error("MCP client is not connected");
      }

      setLoading(true);
      setError(null);

      try {
        const result = await client.manage<T>(params);
        return result;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [client, status],
  );

  return { manage, loading, error };
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
  const { client, status } = useMcpContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const fuzz = useCallback(
    async <T = unknown>(params: FuzzToolParams): Promise<T> => {
      if (!client || status !== "connected") {
        throw new Error("MCP client is not connected");
      }

      setLoading(true);
      setError(null);

      try {
        const result = await client.fuzz<T>(params);
        return result;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [client, status],
  );

  return { fuzz, loading, error };
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
  const { client, status } = useMcpContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const macro = useCallback(
    async <T = unknown>(params: MacroToolParams): Promise<T> => {
      if (!client || status !== "connected") {
        throw new Error("MCP client is not connected");
      }

      setLoading(true);
      setError(null);

      try {
        const result = await client.macro<T>(params);
        return result;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [client, status],
  );

  return { macro, loading, error };
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
  const { client, status } = useMcpContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const interceptAction = useCallback(
    async <T = unknown>(params: InterceptActionParams): Promise<T> => {
      if (!client || status !== "connected") {
        throw new Error("MCP client is not connected");
      }

      setLoading(true);
      setError(null);

      try {
        const result = await client.interceptAction<T>(params);
        return result;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [client, status],
  );

  return { interceptAction, loading, error };
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
  const { client, status } = useMcpContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const security = useCallback(
    async <T = unknown>(params: SecurityParams): Promise<T> => {
      if (!client || status !== "connected") {
        throw new Error("MCP client is not connected");
      }

      setLoading(true);
      setError(null);

      try {
        const result = await client.security<T>(params);
        return result;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [client, status],
  );

  return { security, loading, error };
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
  const { client, status } = useMcpContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const configure = useCallback(
    async (params: ConfigureParams): Promise<ConfigureResult> => {
      if (!client || status !== "connected") {
        throw new Error("MCP client is not connected");
      }

      setLoading(true);
      setError(null);

      try {
        const result = await client.configure(params);
        return result;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [client, status],
  );

  return { configure, loading, error };
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
  const { client, status } = useMcpContext();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const start = useCallback(
    async (params: ProxyStartParams = {}): Promise<ProxyStartResult> => {
      if (!client || status !== "connected") {
        throw new Error("MCP client is not connected");
      }

      setLoading(true);
      setError(null);

      try {
        const result = await client.proxyStart(params);
        return result;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [client, status],
  );

  const stop = useCallback(
    async (params: ProxyStopParams = {}): Promise<ProxyStopResult> => {
      if (!client || status !== "connected") {
        throw new Error("MCP client is not connected");
      }

      setLoading(true);
      setError(null);

      try {
        const result = await client.proxyStop(params);
        return result;
      } catch (err) {
        const e = err instanceof Error ? err : new Error(String(err));
        setError(e);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [client, status],
  );

  return { start, stop, loading, error };
}
