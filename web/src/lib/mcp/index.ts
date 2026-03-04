/**
 * MCP Client SDK for yorishiro-proxy Web UI.
 *
 * Provides typed access to yorishiro-proxy's 10 MCP tools:
 * - proxy_start: Start proxy listeners
 * - proxy_stop: Stop proxy listeners
 * - configure: Configure runtime proxy settings
 * - query: Query flows, status, config, and other resources
 * - execute: Resend and replay recorded requests (resend, resend_raw, tcp_replay)
 * - manage: Manage flow data and CA certificates (delete_flows, export_flows, import_flows, regenerate_ca_cert)
 * - fuzz: Execute fuzz testing campaigns (fuzz, fuzz_pause, fuzz_resume, fuzz_cancel)
 * - macro: Define and execute macro workflows (define_macro, run_macro, delete_macro)
 * - intercept: Act on intercepted requests (release, modify_and_forward, drop)
 * - security: Configure target scope and security settings
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
  useManage,
  useFuzz,
  useMacro,
  useInterceptAction,
  useSecurity,
  useConfigure,
  useProxyControl,
} from "./hooks.js";
export type {
  UseMcpClientResult,
  UseQueryOptions,
  UseQueryResult,
  UseExecuteResult,
  UseManageResult,
  UseFuzzResult,
  UseMacroResult,
  UseInterceptActionResult,
  UseSecurityResult,
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
  VariantRequest,
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

  // Shared execute/fuzz types
  BodyPatch,
  RawPatch,
  FuzzPosition,
  FuzzPayloadSet,
  FuzzStopCondition,
  HookConfig,
  HooksInput,
  ExportFilter,

  // execute
  ExecuteAction,
  ExecuteParams,
  ExecuteResendResult,
  ExecuteDryRunResult,
  ExecuteResendRawResult,
  ExecuteRawDryRunResult,

  // manage
  ManageAction,
  ManageParams,
  ManageDeleteFlowsResult,
  ManageRegenerateCACertResult,
  ManageExportFlowsResult,
  ImportErrorDetail,
  ManageImportFlowsResult,

  // fuzz
  FuzzAction,
  FuzzToolParams,
  FuzzStartResult,
  FuzzControlResult,

  // macro
  MacroAction,
  MacroToolParams,
  MacroDefineResult,
  MacroStepResult,
  MacroRunResult,
  MacroDeleteResult,

  // intercept
  InterceptAction,
  InterceptActionParams,
  InterceptActionResult,

  // security
  SecurityAction,
  TargetRule,
  SecurityParams,
  SecuritySetScopeResult,
  PolicyLayerResult,
  AgentLayerResult,
  SecurityGetScopeResult,
  TestedTarget,
  SecurityTestTargetResult,

  // Connection
  ConnectionStatus,
} from "./types.js";
