/**
 * TypeScript type definitions for yorishiro-proxy's 10 MCP tools.
 * These types mirror the Go structs in internal/mcp/.
 *
 * Tools: proxy_start, proxy_stop, configure, query, resend,
 *        manage, fuzz, macro, intercept, security
 */

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/** Capture scope rule (include/exclude). */
export interface ScopeRule {
  hostname?: string;
  url_prefix?: string;
  method?: string;
}

/** Intercept rule conditions. */
export interface InterceptConditions {
  host_pattern?: string;
  path_pattern?: string;
  methods?: string[] | null;
  header_match?: Record<string, string>;
}

/** Intercept rule definition. */
export interface InterceptRule {
  id: string;
  enabled: boolean;
  direction: "request" | "response" | "both";
  conditions: InterceptConditions;
}

/** Auto-transform rule conditions. */
export interface TransformConditions {
  url_pattern?: string;
  methods?: string[] | null;
  header_match?: Record<string, string>;
}

/** Auto-transform action. */
export interface TransformAction {
  type: "add_header" | "set_header" | "remove_header" | "replace_body";
  header?: string;
  value?: string;
  pattern?: string;
}

/** Auto-transform rule definition. */
export interface TransformRule {
  id: string;
  enabled: boolean;
  priority: number;
  direction: "request" | "response" | "both";
  conditions: TransformConditions;
  action: TransformAction;
}

/** Connection info for a flow. */
export interface ConnInfo {
  client_addr?: string;
  server_addr?: string;
  tls_version?: string;
  tls_cipher?: string;
  tls_alpn?: string;
  tls_server_cert_subject?: string;
}

// ---------------------------------------------------------------------------
// proxy_start tool
// ---------------------------------------------------------------------------

/** Capture scope configuration for proxy_start. */
export interface CaptureScope {
  includes?: ScopeRule[];
  excludes?: ScopeRule[];
}

/** Parameters for the proxy_start tool. */
export interface ProxyStartParams {
  name?: string;
  listen_addr?: string;
  upstream_proxy?: string;
  capture_scope?: CaptureScope;
  tls_passthrough?: string[];
  intercept_rules?: InterceptRule[];
  auto_transform?: TransformRule[];
  tcp_forwards?: Record<string, string>;
  protocols?: string[];
  max_connections?: number | null;
  peek_timeout_ms?: number | null;
  request_timeout_ms?: number | null;
}

/** Response from the proxy_start tool. */
export interface ProxyStartResult {
  name: string;
  listen_addr: string;
  status: string;
  tcp_forwards?: Record<string, string>;
  protocols?: string[];
}

// ---------------------------------------------------------------------------
// proxy_stop tool
// ---------------------------------------------------------------------------

/** Parameters for the proxy_stop tool. */
export interface ProxyStopParams {
  name?: string;
}

/** Response from the proxy_stop tool. */
export interface ProxyStopResult {
  status: string;
  stopped?: string[];
}

// ---------------------------------------------------------------------------
// configure tool
// ---------------------------------------------------------------------------

/** Capture scope configuration for merge operations. */
export interface ConfigureCaptureScope {
  add_includes?: ScopeRule[];
  remove_includes?: ScopeRule[];
  add_excludes?: ScopeRule[];
  remove_excludes?: ScopeRule[];
  includes?: ScopeRule[];
  excludes?: ScopeRule[];
}

/** TLS passthrough configuration. */
export interface ConfigureTLSPassthrough {
  add?: string[];
  remove?: string[];
  patterns?: string[];
}

/** Intercept rules configuration. */
export interface ConfigureInterceptRules {
  add?: InterceptRule[];
  remove?: string[];
  enable?: string[];
  disable?: string[];
  rules?: InterceptRule[];
}

/** Intercept queue configuration. */
export interface ConfigureInterceptQueue {
  timeout_ms?: number | null;
  timeout_behavior?: "auto_release" | "auto_drop";
}

/** Auto-transform rules configuration. */
export interface ConfigureAutoTransform {
  add?: TransformRule[];
  remove?: string[];
  enable?: string[];
  disable?: string[];
  rules?: TransformRule[];
}

/** Parameters for the configure tool. */
export interface ConfigureParams {
  operation?: "merge" | "replace";
  upstream_proxy?: string | null;
  capture_scope?: ConfigureCaptureScope;
  tls_passthrough?: ConfigureTLSPassthrough;
  intercept_rules?: ConfigureInterceptRules;
  intercept_queue?: ConfigureInterceptQueue;
  auto_transform?: ConfigureAutoTransform;
  max_connections?: number | null;
  peek_timeout_ms?: number | null;
  request_timeout_ms?: number | null;
}

/** Response from the configure tool. */
export interface ConfigureResult {
  status: string;
  upstream_proxy?: string;
  capture_scope?: {
    include_count: number;
    exclude_count: number;
  };
  tls_passthrough?: {
    total_patterns: number;
  };
  intercept_rules?: {
    total_rules: number;
    enabled_rules: number;
  };
  intercept_queue?: {
    timeout_ms: number;
    timeout_behavior: string;
    queued_items: number;
  };
  auto_transform?: {
    total_rules: number;
    enabled_rules: number;
  };
  max_connections?: number;
  peek_timeout_ms?: number;
  request_timeout_ms?: number;
}

// ---------------------------------------------------------------------------
// query tool
// ---------------------------------------------------------------------------

/** Resource types for the query tool. */
export type QueryResource =
  | "flows"
  | "flow"
  | "messages"
  | "status"
  | "config"
  | "ca_cert"
  | "intercept_queue"
  | "macros"
  | "macro"
  | "fuzz_jobs"
  | "fuzz_results";

/** Filter options for the query tool. */
export interface QueryFilter {
  protocol?: string;
  method?: string;
  url_pattern?: string;
  status_code?: number;
  blocked_by?: string;
  state?: string;
  direction?: "send" | "receive";
  body_contains?: string;
  status?: string;
  tag?: string;
}

/** Parameters for the query tool. */
export interface QueryParams {
  resource: QueryResource;
  id?: string;
  fuzz_id?: string;
  filter?: QueryFilter;
  fields?: string[];
  sort_by?: string;
  limit?: number;
  offset?: number;
}

// --- Query response types ---

/** Flow entry in the flows list. */
export interface FlowEntry {
  id: string;
  protocol: string;
  flow_type: string;
  state: string;
  method: string;
  url: string;
  status_code: number;
  message_count: number;
  blocked_by?: string;
  protocol_summary?: Record<string, string>;
  timestamp: string;
  duration_ms: number;
}

/** Response for query resource="flows". */
export interface FlowsResult {
  flows: FlowEntry[];
  count: number;
  total: number;
}

/** Message entry in the messages list and flow preview. */
export interface MessageEntry {
  id: string;
  sequence: number;
  direction: string;
  method?: string;
  url?: string;
  status_code?: number;
  headers?: Record<string, string[]>;
  body: string;
  body_encoding: string;
  metadata?: Record<string, string>;
  timestamp: string;
}

/** Original request data before intercept/transform modification. */
export interface VariantRequest {
  method: string;
  url: string;
  headers: Record<string, string[]>;
  body: string;
  body_encoding: string;
}

/** Response for query resource="flow". */
export interface FlowDetailResult {
  id: string;
  conn_id: string;
  protocol: string;
  flow_type: string;
  state: string;
  method: string;
  url: string;
  request_headers: Record<string, string[]>;
  request_body: string;
  request_body_encoding: string;
  response_status_code: number;
  response_headers: Record<string, string[]>;
  response_body: string;
  response_body_encoding: string;
  request_body_truncated: boolean;
  response_body_truncated: boolean;
  timestamp: string;
  duration_ms: number;
  tags?: Record<string, string>;
  blocked_by?: string;
  raw_request?: string;
  raw_response?: string;
  conn_info?: ConnInfo;
  message_count: number;
  protocol_summary?: Record<string, string>;
  message_preview?: MessageEntry[];
  original_request?: VariantRequest;
}

/** Response for query resource="messages". */
export interface MessagesResult {
  messages: MessageEntry[];
  count: number;
  total: number;
}

/** Listener status entry. */
export interface ListenerStatusEntry {
  name: string;
  listen_addr: string;
  active_connections: number;
  uptime_seconds: number;
}

/** Response for query resource="status". */
export interface StatusResult {
  running: boolean;
  listen_addr: string;
  listeners?: ListenerStatusEntry[];
  listener_count: number;
  upstream_proxy: string;
  active_connections: number;
  max_connections: number;
  peek_timeout_ms: number;
  request_timeout_ms: number;
  total_flows: number;
  db_size_bytes: number;
  uptime_seconds: number;
  ca_initialized: boolean;
}

/** Scope rule in config output. */
export interface ScopeRuleOutput {
  hostname?: string;
  url_prefix?: string;
  method?: string;
}

/** Response for query resource="config". */
export interface ConfigResult {
  upstream_proxy: string;
  capture_scope: {
    includes: ScopeRuleOutput[];
    excludes: ScopeRuleOutput[];
  };
  tls_passthrough: {
    patterns: string[];
    count: number;
  };
  tcp_forwards?: Record<string, string>;
  enabled_protocols?: string[];
}

/** Response for query resource="ca_cert". */
export interface CACertResult {
  pem: string;
  fingerprint: string;
  subject: string;
  not_after: string;
  persisted: boolean;
  cert_path?: string;
  install_hint?: string;
}

/** Intercept queue entry. */
export interface InterceptQueueEntry {
  id: string;
  method: string;
  url: string;
  headers: Record<string, string[]>;
  body_encoding: string;
  body: string;
  timestamp: string;
  matched_rules: string[];
}

/** Response for query resource="intercept_queue". */
export interface InterceptQueueResult {
  items: InterceptQueueEntry[];
  count: number;
}

/** Macro entry in the macros list. */
export interface MacrosEntry {
  name: string;
  description: string;
  step_count: number;
  created_at: string;
  updated_at: string;
}

/** Response for query resource="macros". */
export interface MacrosResult {
  macros: MacrosEntry[];
  count: number;
}

/** Extraction rule in a macro step. */
export interface ExtractionRule {
  name: string;
  from: string;
  source: string;
  header_name?: string;
  regex?: string;
  group?: number;
  json_path?: string;
  default?: string;
  required?: boolean;
}

/** Guard condition for a macro step. */
export interface GuardCondition {
  step?: string;
  status_code?: number | null;
  status_code_range?: [number, number];
  header_match?: Record<string, string>;
  body_match?: string;
  extracted_var?: string;
  negate?: boolean;
}

/** Macro step definition. */
export interface MacroStep {
  id: string;
  flow_id: string;
  override_method?: string;
  override_url?: string;
  override_headers?: Record<string, string>;
  override_body?: string | null;
  on_error?: string;
  retry_count?: number;
  retry_delay_ms?: number;
  timeout_ms?: number;
  extract?: ExtractionRule[];
  when?: GuardCondition | null;
}

/** Response for query resource="macro". */
export interface MacroDetailResult {
  name: string;
  description: string;
  steps: MacroStep[];
  initial_vars?: Record<string, string>;
  timeout_ms?: number;
  created_at: string;
  updated_at: string;
}

/** Fuzz job entry. */
export interface FuzzJobEntry {
  id: string;
  flow_id: string;
  status: string;
  tag: string;
  total: number;
  completed_count: number;
  error_count: number;
  created_at: string;
  completed_at?: string;
}

/** Response for query resource="fuzz_jobs". */
export interface FuzzJobsResult {
  jobs: FuzzJobEntry[];
  count: number;
  total: number;
}

/** Fuzz result entry. */
export interface FuzzResultEntry {
  id: string;
  fuzz_id: string;
  index: number;
  flow_id: string;
  payloads: Record<string, string>;
  status_code: number;
  response_length: number;
  duration_ms: number;
  error?: string;
}

/** Fuzz results summary. */
export interface FuzzResultsSummary {
  status_distribution: Record<string, number>;
  avg_duration_ms: number;
  total_duration_ms: number;
}

/** Response for query resource="fuzz_results". */
export interface FuzzResultsResult {
  results: FuzzResultEntry[];
  count: number;
  total: number;
  summary: FuzzResultsSummary;
}

/** Map of query resource to its result type. */
export interface QueryResultMap {
  flows: FlowsResult;
  flow: FlowDetailResult;
  messages: MessagesResult;
  status: StatusResult;
  config: ConfigResult;
  ca_cert: CACertResult;
  intercept_queue: InterceptQueueResult;
  macros: MacrosResult;
  macro: MacroDetailResult;
  fuzz_jobs: FuzzJobsResult;
  fuzz_results: FuzzResultsResult;
}

// ---------------------------------------------------------------------------
// Shared resend/fuzz types
// ---------------------------------------------------------------------------

/** Body patch for resend. */
export interface BodyPatch {
  json_path?: string;
  regex?: string;
  replace?: string;
  value?: unknown;
}

/** Raw byte-level patch for resend_raw. */
export interface RawPatch {
  offset?: number | null;
  data_base64?: string;
  find_base64?: string;
  replace_base64?: string;
  find_text?: string;
  replace_text?: string;
}

/** Fuzz payload position. */
export interface FuzzPosition {
  id: string;
  location: string;
  name?: string;
  match?: string;
  mode?: string;
  payload_set?: string;
  json_path?: string;
}

/** Fuzz payload set. */
export interface FuzzPayloadSet {
  type: string;
  values?: string[] | null;
  path?: string;
  format?: string;
  start?: number | null;
  end?: number | null;
  step?: number | null;
}

/** Fuzz stop conditions. */
export interface FuzzStopCondition {
  status_codes?: number[] | null;
  error_count?: number;
  latency_threshold_ms?: number;
  latency_baseline_multiplier?: number;
  latency_window?: number;
}

/** Hook configuration for resend/fuzz. */
export interface HookConfig {
  macro: string;
  vars?: Record<string, string>;
  run_interval?: string;
  n?: number;
  status_codes?: number[] | null;
  match_pattern?: string;
  pass_response?: boolean;
}

/** Hooks input for resend/fuzz. */
export interface HooksInput {
  pre_send?: HookConfig | null;
  post_receive?: HookConfig | null;
}

/** Export filter for manage tool. */
export interface ExportFilter {
  protocol?: string;
  url_pattern?: string;
  time_after?: string;
  time_before?: string;
}

// ---------------------------------------------------------------------------
// resend tool — resend, resend_raw, tcp_replay
// ---------------------------------------------------------------------------

/** Available resend actions. */
export type ExecuteAction = "resend" | "resend_raw" | "tcp_replay";

/** A single header key-value pair, allowing duplicate keys. */
export interface ExecuteHeaderEntry {
  key: string;
  value: string;
}

/** Parameters for the resend tool (resend / resend_raw / tcp_replay). */
export interface ExecuteParams {
  action: ExecuteAction;
  params: {
    // Flow targeting
    flow_id?: string;
    message_sequence?: number | null;

    // Resend overrides
    override_method?: string;
    override_url?: string;
    override_headers?: ExecuteHeaderEntry[];
    override_body?: string | null;
    add_headers?: ExecuteHeaderEntry[];
    remove_headers?: string[];
    override_body_base64?: string | null;
    body_patches?: BodyPatch[];
    override_host?: string;
    follow_redirects?: boolean | null;
    timeout_ms?: number | null;
    dry_run?: boolean;
    tag?: string;

    // Resend raw
    target_addr?: string;
    use_tls?: boolean | null;
    override_raw_base64?: string;
    patches?: RawPatch[];

    // Hooks
    hooks?: HooksInput | null;
  };
}

/** Result of a resend action. */
export interface ExecuteResendResult {
  new_flow_id: string;
  status_code: number;
  response_headers: Record<string, string[]>;
  response_body: string;
  response_body_encoding: string;
  duration_ms: number;
  tag?: string;
}

/** Result of a dry-run resend action. */
export interface ExecuteDryRunResult {
  dry_run: true;
  request_preview: {
    method: string;
    url: string;
    headers: Record<string, string[]>;
    body: string;
    body_encoding: string;
  };
}

/** Result of a resend_raw action. */
export interface ExecuteResendRawResult {
  new_flow_id: string;
  response_data: string;
  response_size: number;
  duration_ms: number;
  tag?: string;
}

/** Result of a raw dry-run action. */
export interface ExecuteRawDryRunResult {
  dry_run: true;
  raw_preview: {
    data_base64: string;
    data_size: number;
    patches_applied: number;
  };
}

// ---------------------------------------------------------------------------
// manage tool — delete_flows, export_flows, import_flows, regenerate_ca_cert
// ---------------------------------------------------------------------------

/** Available manage actions. */
export type ManageAction =
  | "delete_flows"
  | "export_flows"
  | "import_flows"
  | "regenerate_ca_cert";

/** Parameters for the manage tool. */
export interface ManageParams {
  action: ManageAction;
  params: {
    // delete_flows
    flow_id?: string;
    older_than_days?: number | null;
    confirm?: boolean;
    protocol?: string;

    // export_flows
    format?: string;
    filter?: ExportFilter | null;
    include_bodies?: boolean | null;
    output_path?: string;

    // import_flows
    input_path?: string;
    on_conflict?: string;
  };
}

/** Result of delete_flows action. */
export interface ManageDeleteFlowsResult {
  deleted_count: number;
  cutoff_time?: string;
}

/** Result of regenerate_ca_cert action. */
export interface ManageRegenerateCACertResult {
  fingerprint: string;
  subject: string;
  not_after: string;
  persisted: boolean;
  cert_path?: string;
  install_hint?: string;
}

/** Result of export_flows action. */
export interface ManageExportFlowsResult {
  exported_count: number;
  format: string;
  output_path?: string;
  data?: string;
}

/** Import error detail. */
export interface ImportErrorDetail {
  index: number;
  error: string;
}

/** Result of import_flows action. */
export interface ManageImportFlowsResult {
  imported: number;
  skipped: number;
  errors: number;
  source: string;
  error_details?: ImportErrorDetail[];
}

// ---------------------------------------------------------------------------
// fuzz tool — fuzz, fuzz_pause, fuzz_resume, fuzz_cancel
// ---------------------------------------------------------------------------

/** Available fuzz actions. */
export type FuzzAction = "fuzz" | "fuzz_pause" | "fuzz_resume" | "fuzz_cancel";

/** Parameters for the fuzz tool. */
export interface FuzzToolParams {
  action: FuzzAction;
  params: {
    // fuzz start
    flow_id?: string;
    attack_type?: string;
    positions?: FuzzPosition[];
    payload_sets?: Record<string, FuzzPayloadSet>;
    tag?: string;
    concurrency?: number | null;
    rate_limit_rps?: number | null;
    delay_ms?: number | null;
    max_retries?: number | null;
    timeout_ms?: number | null;
    stop_on?: FuzzStopCondition | null;

    // fuzz control (pause/resume/cancel)
    fuzz_id?: string;

    // hooks
    hooks?: HooksInput | null;
  };
}

/** Result of fuzz start action. */
export interface FuzzStartResult {
  fuzz_id: string;
  flow_id: string;
  status: string;
  total: number;
  tag: string;
}

/** Result of fuzz control actions (pause/resume/cancel). */
export interface FuzzControlResult {
  fuzz_id: string;
  action: string;
  status: string;
}

// ---------------------------------------------------------------------------
// macro tool — define_macro, run_macro, delete_macro
// ---------------------------------------------------------------------------

/** Available macro actions. */
export type MacroAction = "define_macro" | "run_macro" | "delete_macro";

/** Parameters for the macro tool. */
export interface MacroToolParams {
  action: MacroAction;
  params: {
    name?: string;
    description?: string;
    steps?: MacroStep[];
    initial_vars?: Record<string, string>;
    macro_timeout_ms?: number;
    vars?: Record<string, string>;
  };
}

/** Result of define_macro action. */
export interface MacroDefineResult {
  name: string;
  step_count: number;
  created: boolean;
}

/** Step result entry for run_macro. */
export interface MacroStepResult {
  id: string;
  status: string;
  status_code?: number;
  duration_ms?: number;
  error?: string;
}

/** Result of run_macro action. */
export interface MacroRunResult {
  macro_name: string;
  status: string;
  steps_executed: number;
  kv_store: Record<string, string>;
  step_results: MacroStepResult[];
  error?: string;
}

/** Result of delete_macro action. */
export interface MacroDeleteResult {
  name: string;
  deleted: boolean;
}

// ---------------------------------------------------------------------------
// intercept tool — release, modify_and_forward, drop
// ---------------------------------------------------------------------------

/** Available intercept actions. */
export type InterceptAction = "release" | "modify_and_forward" | "drop";

/** Parameters for the intercept tool. */
export interface InterceptActionParams {
  action: InterceptAction;
  params: {
    intercept_id?: string;

    // modify_and_forward mutation parameters
    override_method?: string;
    override_url?: string;
    override_headers?: Record<string, string>;
    add_headers?: Record<string, string>;
    remove_headers?: string[];
    override_body?: string | null;
  };
}

/** Result of intercept actions. */
export interface InterceptActionResult {
  intercept_id: string;
  action: string;
  status: string;
}

// ---------------------------------------------------------------------------
// security tool — set_target_scope, update_target_scope, get_target_scope, test_target
// ---------------------------------------------------------------------------

/** Available security actions. */
export type SecurityAction =
  | "set_target_scope"
  | "update_target_scope"
  | "get_target_scope"
  | "test_target";

/** Target rule for security tool. */
export interface TargetRule {
  hostname: string;
  ports?: number[];
  path_prefix?: string;
  schemes?: string[];
}

/** Parameters for the security tool. */
export interface SecurityParams {
  action: SecurityAction;
  params: {
    // set_target_scope
    allows?: TargetRule[];
    denies?: TargetRule[];

    // update_target_scope
    add_allows?: TargetRule[];
    remove_allows?: TargetRule[];
    add_denies?: TargetRule[];
    remove_denies?: TargetRule[];

    // test_target
    url?: string;
  };
}

/** Result of set_target_scope / update_target_scope actions. */
export interface SecuritySetScopeResult {
  status: string;
  allows: TargetRule[];
  denies: TargetRule[];
  mode: string;
}

/** Policy layer result for get_target_scope. */
export interface PolicyLayerResult {
  allows: TargetRule[];
  denies: TargetRule[];
  source: string;
  immutable: boolean;
}

/** Agent layer result for get_target_scope. */
export interface AgentLayerResult {
  allows: TargetRule[];
  denies: TargetRule[];
}

/** Result of get_target_scope action. */
export interface SecurityGetScopeResult {
  policy: PolicyLayerResult;
  agent: AgentLayerResult;
  effective_mode: string;
}

/** Tested target info in test_target result. */
export interface TestedTarget {
  hostname: string;
  port: number;
  scheme: string;
  path: string;
}

/** Result of test_target action. */
export interface SecurityTestTargetResult {
  allowed: boolean;
  reason: string;
  layer: string;
  matched_rule?: TargetRule | null;
  tested_target: TestedTarget;
}

// ---------------------------------------------------------------------------
// MCP client connection state
// ---------------------------------------------------------------------------

/** MCP client connection status. */
export type ConnectionStatus =
  | "connecting"
  | "connected"
  | "disconnected"
  | "error";
