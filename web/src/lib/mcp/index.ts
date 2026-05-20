/**
 * MCP Client SDK for yorishiro-proxy Web UI.
 *
 * Provides typed access to yorishiro-proxy's MCP tools:
 * - proxy_start: Start proxy listeners
 * - proxy_stop: Stop proxy listeners
 * - configure: Configure runtime proxy settings
 * - query: Query flows, status, config, and other resources
 * - resend_{http,ws,grpc,raw}: Protocol-typed synchronous resend tools
 *           (RFC-001 N8). The legacy `resend` MCP tool was removed at the
 *           backend; pages call client.resendHttp / resendWs / resendGrpc /
 *           resendRaw directly via useMcpContext. See
 *           pages/Resend/typedDispatch.ts (typedResendToolForProtocol)
 *           for routing helpers.
 * - manage: Manage flow data and CA certificates (delete_flows, export_flows, import_flows, regenerate_ca_cert)
 * - fuzz_{http,ws,grpc,raw}: Protocol-typed synchronous fuzz tools (RFC-001 N8).
 *           The legacy `fuzz` MCP tool was removed at the backend; see
 *           dispatch.ts pickFuzzTool() to route by flow.protocol.
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
  useConfigure, useInterceptAction, useMacro, useManage, useMcpClient, useProxyControl, useQuery, useSecurity
} from "./hooks.js";
export type {
  UseConfigureResult, UseInterceptActionResult, UseMacroResult, UseManageResult, UseMcpClientResult, UseProxyControlResult, UseQueryOptions,
  UseQueryResult, UseSecurityResult
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
  // resend (typed quartet — legacy ExecuteAction / ExecuteParams /
  // ExecuteResendResult / ExecuteDryRunResult / ExecuteResendRawResult /
  // ExecuteRawDryRunResult and the Compare* family were removed alongside
  // the backend `resend` tool — USK-938).
  ExportFilter, ExtractionRule, FlowDetailResult, FlowEntry,
  FlowsResult,
  // fuzz (typed quartet — legacy FuzzAction / FuzzToolParams / FuzzStartResult /
  // FuzzControlResult / FuzzPosition / FuzzPayloadSet / FuzzStopCondition
  // were removed alongside the backend `fuzz` tool — USK-937).
  FuzzGRPCParams, FuzzGRPCPosition, FuzzGRPCResult, FuzzGRPCVariantRow,
  FuzzHTTPParams, FuzzHTTPPosition, FuzzHTTPResult, FuzzHTTPVariantRow,
  FuzzJobEntry,
  FuzzJobsResult,
  FuzzRawParams, FuzzRawPosition, FuzzRawResult, FuzzRawVariantRow,
  FuzzResultEntry, FuzzResultsResult, FuzzResultsSummary,
  FuzzWSParams, FuzzWSPosition, FuzzWSResult, FuzzWSVariantRow,
  GuardCondition, HookConfig,
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
