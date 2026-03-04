/**
 * MCP Client SDK for yorishiro-proxy Web UI.
 *
 * Provides typed access to yorishiro-proxy's 5 MCP tools:
 * - proxy_start: Start proxy listeners
 * - proxy_stop: Stop proxy listeners
 * - configure: Configure runtime proxy settings
 * - query: Query flows, status, config, and other resources
 * - execute: Execute actions (resend, fuzz, delete, etc.)
 */

// Client
export { McpClient } from "./client.js";
export type { McpClientConfig, McpClientEvent, McpClientEventListener } from "./client.js";

// Context & Provider
export { McpProvider, useMcpContext } from "./context.js";
export type { McpContextValue, McpProviderProps } from "./context.js";

// Hooks
export {
  useMcpClient,
  useQuery,
  useExecute,
  useConfigure,
  useProxyControl,
} from "./hooks.js";
export type {
  UseMcpClientResult,
  UseQueryOptions,
  UseQueryResult,
  UseExecuteResult,
  UseConfigureResult,
  UseProxyControlResult,
} from "./hooks.js";

// Types
export type {
  // Shared types
  ScopeRule,
  InterceptConditions,
  InterceptRule,
  TransformConditions,
  TransformAction,
  TransformRule,
  ConnInfo,

  // proxy_start
  CaptureScope,
  ProxyStartParams,
  ProxyStartResult,

  // proxy_stop
  ProxyStopParams,
  ProxyStopResult,

  // configure
  ConfigureCaptureScope,
  ConfigureTLSPassthrough,
  ConfigureInterceptRules,
  ConfigureInterceptQueue,
  ConfigureAutoTransform,
  ConfigureParams,
  ConfigureResult,

  // query
  QueryResource,
  QueryFilter,
  QueryParams,
  FlowEntry,
  FlowsResult,
  MessageEntry,
  FlowDetailResult,
  MessagesResult,
  ListenerStatusEntry,
  StatusResult,
  ScopeRuleOutput,
  ConfigResult,
  CACertResult,
  InterceptQueueEntry,
  InterceptQueueResult,
  MacrosEntry,
  MacrosResult,
  ExtractionRule,
  GuardCondition,
  MacroStep,
  MacroDetailResult,
  FuzzJobEntry,
  FuzzJobsResult,
  FuzzResultEntry,
  FuzzResultsSummary,
  FuzzResultsResult,
  QueryResultMap,

  // execute
  ExecuteAction,
  BodyPatch,
  RawPatch,
  FuzzPosition,
  FuzzPayloadSet,
  FuzzStopCondition,
  HookConfig,
  HooksInput,
  ExportFilter,
  ExecuteParams,

  // Connection
  ConnectionStatus,
} from "./types.js";
