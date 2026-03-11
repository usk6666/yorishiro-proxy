/**
 * MCP Client SDK for yorishiro-proxy Web UI.
 *
 * Provides typed access to yorishiro-proxy's 10 MCP tools:
 * - proxy_start: Start proxy listeners
 * - proxy_stop: Stop proxy listeners
 * - configure: Configure runtime proxy settings
 * - query: Query flows, status, config, and other resources
 * - resend: Resend and replay recorded requests (resend, resend_raw, tcp_replay)
 * - manage: Manage flow data and CA certificates (delete_flows, export_flows, import_flows, regenerate_ca_cert)
 * - fuzz: Execute fuzz testing campaigns (fuzz, fuzz_pause, fuzz_resume, fuzz_cancel)
 * - macro: Define and run macro workflows (define_macro, run_macro, delete_macro)
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
  useConfigure, useExecute, useFuzz, useInterceptAction, useMacro, useManage, useMcpClient, useProxyControl, useQuery, useResend, useSecurity
} from "./hooks.js";
export type {
  UseConfigureResult, UseExecuteResult, UseFuzzResult, UseInterceptActionResult, UseMacroResult, UseManageResult, UseMcpClientResult, UseProxyControlResult, UseQueryOptions,
  UseQueryResult, UseResendResult, UseSecurityResult
} from "./hooks.js";

// Types
export type {
  AgentLayerResult,
  // Shared resend/fuzz types
  BodyPatch, CACertResult,
  // proxy_start
  CaptureScope, ConfigResult, ConfigureAutoTransform,
  // configure
  ConfigureCaptureScope, ConfigureInterceptQueue, ConfigureInterceptRules, ConfigureParams,
  ConfigureResult, ConfigureTLSPassthrough,
  // Connection
  ConnectionStatus, ConnInfo,
  // resend
  CompareBodyDiff, CompareBodyLengthDiff, CompareHeaderDiff, CompareJsonDiff, CompareResult, CompareStatusCodeDiff, CompareTimingDiff,
  ExecuteAction, ExecuteDryRunResult, ExecuteParams, ExecuteRawDryRunResult, ExecuteResendRawResult, ExecuteResendResult, ExportFilter, ExtractionRule, FlowDetailResult, FlowEntry,
  FlowsResult,
  // fuzz
  FuzzAction, FuzzControlResult, FuzzJobEntry,
  FuzzJobsResult, FuzzPayloadSet, FuzzPosition, FuzzResultEntry, FuzzResultsResult, FuzzResultsSummary, FuzzStartResult, FuzzStopCondition, FuzzToolParams, GuardCondition, HookConfig,
  HooksInput, ImportErrorDetail,
  // intercept
  InterceptAction,
  InterceptActionParams,
  InterceptActionResult, InterceptConditions, InterceptQueueEntry,
  InterceptQueueResult, InterceptRule, ListenerStatusEntry,
  // macro
  MacroAction, MacroDefineResult, MacroDeleteResult, MacroDetailResult, MacroRunResult, MacrosEntry,
  MacrosResult, MacroStep, MacroStepResult, MacroToolParams,
  // manage
  ManageAction, ManageDeleteFlowsResult, ManageExportFlowsResult, ManageImportFlowsResult, ManageParams, ManageRegenerateCACertResult, MessageEntry, MessagesResult, PolicyLayerResult, ProxyStartParams,
  ProxyStartResult,

  // proxy_stop
  ProxyStopParams,
  ProxyStopResult, QueryFilter,
  QueryParams,
  // query
  QueryResource, QueryResultMap, RawPatch,
  // Shared types
  ScopeRule, ScopeRuleOutput,
  // security
  SecurityAction, SecurityGetScopeResult, SecurityParams,
  SecuritySetScopeResult, SecurityTestTargetResult, StatusResult, TargetRule, TestedTarget, TransformAction, TransformConditions, TransformRule, VariantRequest
} from "./types.js";
