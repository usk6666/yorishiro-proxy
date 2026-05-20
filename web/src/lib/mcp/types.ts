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

/** Allowed protocols for TCP forwarding. */
export type ForwardProtocol = "auto" | "raw" | "http" | "http2" | "grpc" | "websocket" | "sse";

/** TCP forward configuration for a single port. */
export interface ForwardConfig {
  target: string;
  protocol?: ForwardProtocol;
  /** Client-side TLS MITM termination on the forwarded listen port. */
  tls?: boolean;
  /** Upstream-dial TLS encryption to target (independent of `tls`). */
  upstream_tls?: boolean;
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
  tcp_forwards?: Record<string, string | ForwardConfig>;
  max_connections?: number | null;
  peek_timeout_ms?: number | null;
  request_timeout_ms?: number | null;
}

/** Response from the proxy_start tool. */
export interface ProxyStartResult {
  name: string;
  listen_addr: string;
  status: string;
  tcp_forwards?: Record<string, ForwardConfig>;
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

/** SOCKS5 authentication configuration. */
export interface ConfigureSOCKS5Auth {
  method: "none" | "password";
  username?: string;
  password?: string;
  listener_name?: string;
}

/** mTLS client certificate configuration. */
export interface ConfigureClientCert {
  cert_path: string;
  key_path: string;
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
  socks5_auth?: ConfigureSOCKS5Auth;
  tls_fingerprint?: string;
  max_connections?: number | null;
  peek_timeout_ms?: number | null;
  request_timeout_ms?: number | null;
  client_cert?: ConfigureClientCert;
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
  socks5_auth?: {
    method: string;
  };
  tls_fingerprint?: string;
  max_connections?: number;
  peek_timeout_ms?: number;
  request_timeout_ms?: number;
  client_cert?: {
    cert_path?: string;
    key_path?: string;
    status: string;
  };
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
  scheme?: string;
  method?: string;
  url_pattern?: string;
  status_code?: number;
  blocked_by?: string;
  state?: string;
  direction?: "send" | "receive";
  conn_id?: string;
  host?: string;
  body_contains?: string;
  outliers_only?: boolean;
  status?: string;
  tag?: string;
  /**
   * Stream origin classification (USK-786 server filter).
   * - "proxy": live MITM-recorded traffic
   * - "resend": streams created by the resend_* MCP tools
   * - "fuzz":  reserved for fuzz campaigns
   */
  origin?: "proxy" | "resend" | "fuzz";
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

/** A structured anomaly entry detected during HTTP parsing. */
export interface AnomalyEntry {
  /** Anomaly classification (e.g., "CLTE", "DuplicateCL", "HeaderInjection"). */
  type: string;
  /** Human-readable description of the anomaly. */
  detail: string;
}

/**
 * Structured anomaly surfaced when Content-Encoding decode is rejected or
 * fails. Mirrors `queryDecodeAnomaly` in internal/mcp/query_tool.go (USK-731).
 * Wire-form bytes are always preserved in the sibling *_body field.
 */
export interface DecodeAnomaly {
  /**
   * "unknown_encoding" | "malformed" | "size_exceeded" | "chain_rejected"
   * | "truncated_decode"
   */
  type: string;
  detail?: string;
}

/** Flow entry in the flows list. */
export interface FlowEntry {
  id: string;
  protocol: string;
  scheme?: string;
  flow_type: string;
  state: string;
  method: string;
  url: string;
  status_code: number;
  message_count: number;
  blocked_by?: string;
  protocol_summary?: Record<string, string>;
  tags?: Record<string, string>;
  anomalies?: AnomalyEntry[];
  timestamp: string;
  duration_ms: number;
  send_ms?: number;
  wait_ms?: number;
  receive_ms?: number;
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
  /** Body after Content-Encoding decode (USK-731). Empty when no codec applied. */
  body_decoded?: string;
  /** "text" | "base64" — transport encoding of body_decoded. */
  body_decoded_encoding?: string;
  /** Codec applied to produce body_decoded ("gzip" | "br" | "deflate" | "zstd"). */
  body_encoding_applied?: string;
  /** Anomaly detail when decode was attempted but rejected or failed. */
  body_decode_anomaly?: DecodeAnomaly;
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
  /** Body after Content-Encoding decode (USK-731). Empty when no codec applied. */
  body_decoded?: string;
  /** "text" | "base64" — transport encoding of body_decoded. */
  body_decoded_encoding?: string;
  /** Codec applied to produce body_decoded ("gzip" | "br" | "deflate" | "zstd"). */
  body_encoding_applied?: string;
  /** Anomaly detail when decode was attempted but rejected or failed. */
  body_decode_anomaly?: DecodeAnomaly;
}

/** Original response data before intercept modification. */
export interface VariantResponse {
  status_code: number;
  headers: Record<string, string[]>;
  body: string;
  body_encoding: string;
  body_truncated: boolean;
  /** Body after Content-Encoding decode (USK-731). Empty when no codec applied. */
  body_decoded?: string;
  /** "text" | "base64" — transport encoding of body_decoded. */
  body_decoded_encoding?: string;
  /** Codec applied to produce body_decoded ("gzip" | "br" | "deflate" | "zstd"). */
  body_encoding_applied?: string;
  /** Anomaly detail when decode was attempted but rejected or failed. */
  body_decode_anomaly?: DecodeAnomaly;
}

/** Response for query resource="flow". */
export interface FlowDetailResult {
  id: string;
  conn_id: string;
  protocol: string;
  scheme?: string;
  flow_type: string;
  state: string;
  method: string;
  url: string;
  request_headers: Record<string, string[]> | null;
  request_body: string;
  request_body_encoding: string;
  /** Request body after Content-Encoding decode (USK-731). Empty when no codec applied. */
  request_body_decoded?: string;
  /** "text" | "base64" — transport encoding of request_body_decoded. */
  request_body_decoded_encoding?: string;
  /** Codec applied to produce request_body_decoded ("gzip" | "br" | "deflate" | "zstd"). */
  request_body_encoding_applied?: string;
  /** Anomaly detail when request body decode was attempted but rejected or failed. */
  request_body_decode_anomaly?: DecodeAnomaly;
  response_status_code: number;
  response_headers: Record<string, string[]> | null;
  response_body: string;
  response_body_encoding: string;
  /** Response body after Content-Encoding decode (USK-731). Empty when no codec applied. */
  response_body_decoded?: string;
  /** "text" | "base64" — transport encoding of response_body_decoded. */
  response_body_decoded_encoding?: string;
  /** Codec applied to produce response_body_decoded ("gzip" | "br" | "deflate" | "zstd"). */
  response_body_encoding_applied?: string;
  /** Anomaly detail when response body decode was attempted but rejected or failed. */
  response_body_decode_anomaly?: DecodeAnomaly;
  request_body_truncated: boolean;
  response_body_truncated: boolean;
  timestamp: string;
  duration_ms: number;
  send_ms?: number;
  wait_ms?: number;
  receive_ms?: number;
  tags?: Record<string, string>;
  anomalies?: AnomalyEntry[];
  blocked_by?: string;
  raw_request?: string;
  raw_response?: string;
  conn_info?: ConnInfo;
  message_count: number;
  protocol_summary?: Record<string, string>;
  message_preview?: MessageEntry[];
  original_request?: VariantRequest;
  original_response?: VariantResponse;
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

/** Rate limit status in the status response. */
export interface RateLimitStatus {
  effective: RateLimitConfig;
  enabled: boolean;
}

/** Budget status in the status response. */
export interface BudgetStatus {
  effective: BudgetConfig;
  enabled: boolean;
  request_count: number;
  stop_reason?: string;
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
  socks5_enabled: boolean;
  socks5_auth?: string;
  tls_fingerprint: string;
  rate_limits?: RateLimitStatus;
  budget?: BudgetStatus;
}

/** Scope rule in config output. */
export interface ScopeRuleOutput {
  hostname?: string;
  url_prefix?: string;
  method?: string;
}

/** Safety filter status in the config response. */
export interface SafetyFilterStatus {
  enabled: boolean;
  input_rules: number;
  output_rules: number;
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
  tcp_forwards?: Record<string, ForwardConfig>;
  socks5_enabled?: boolean;
  socks5_auth?: {
    method: string;
    username?: string;
  };
  client_cert?: {
    cert_path: string;
    key_path: string;
  };
  safety_filter: SafetyFilterStatus;
  max_connections: number;
  peek_timeout_ms: number;
  request_timeout_ms: number;
  tls_fingerprint: string;
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

/** Intercept phase: request (pre-send), response (post-receive), or websocket_frame. */
export type InterceptPhase = "request" | "response" | "websocket_frame";

/** Intercept protocol type. Expanded by RFC-001 N8 to cover all Message families. */
export type InterceptProtocol =
  | "http"
  | "websocket"
  | "grpc"
  | "grpc-web"
  | "sse"
  | "raw";

// ---------------------------------------------------------------------------
// Per-protocol Message-typed flow shapes (light-touch discriminated union).
//
// These types layer over the existing FlowDetailResult wire shape for callers
// that want to narrow on `flow.protocol`. The MCP wire format is unchanged;
// these types provide compile-time discrimination and explicit field maps for
// per-protocol UI components.
// ---------------------------------------------------------------------------

/** Ordered header pair preserving wire case/order/duplicates. */
export interface HeaderKV {
  name: string;
  value: string;
}

/** HTTP/1.x or HTTP/2 (and HTTPS) Message-typed flow shape. */
export interface HTTPMessageFlow extends FlowDetailResult {
  protocol: "HTTP/1.x" | "HTTP/2" | "HTTPS";
}

/** WebSocket Message-typed flow shape. */
export interface WSMessageFlow extends FlowDetailResult {
  protocol: "WebSocket";
}

/** gRPC / gRPC-Web Message-typed flow shape (covers Start / Data / End frames). */
export interface GRPCMessageFlow extends FlowDetailResult {
  protocol: "gRPC" | "gRPC-Web";
}

/** SSE (Server-Sent Events) Message-typed flow shape. */
export interface SSEMessageFlow extends FlowDetailResult {
  protocol: "SSE";
}

/** Raw / TCP Message-typed flow shape. */
export interface RawMessageFlow extends FlowDetailResult {
  protocol: "TCP" | "Raw";
}

/** Discriminated Message-typed flow union. */
export type MessageFlow =
  | HTTPMessageFlow
  | WSMessageFlow
  | GRPCMessageFlow
  | SSEMessageFlow
  | RawMessageFlow;

/** Intercept queue entry. */
export interface InterceptQueueEntry {
  id: string;
  phase?: InterceptPhase;
  protocol?: InterceptProtocol;
  method?: string; // HTTP-only (omitempty in backend)
  url?: string; // HTTP-only (omitempty in backend)
  status_code?: number; // response phase: HTTP status code
  headers?: Record<string, string[]>; // HTTP-only (omitempty in backend)
  body_encoding: string;
  body: string;
  timestamp: string;
  matched_rules: string[];
  metadata?: Record<string, string>; // protocol-specific metadata (e.g. gRPC encoding)
  // WebSocket frame fields (phase=websocket_frame only)
  opcode?: string; // e.g. "Text", "Binary"
  direction?: "client_to_server" | "server_to_client";
  flow_id?: string;
  upgrade_url?: string;
  sequence?: number;
  raw_bytes_available?: boolean;
  raw_bytes_size?: number;
  raw_bytes?: string;
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
// (Legacy resend tool types removed — the untyped `resend` MCP tool was
// retired at the backend in favour of the protocol-typed quartet
// resend_{http,ws,grpc,raw}. See ResendHTTPParams / ResendWSParams /
// ResendGRPCParams / ResendRawParams below for the replacement schemas.
// The retired `compare` resend action no longer has a TS shape; revival
// is tracked as a follow-up Issue alongside USK-938.)
// ---------------------------------------------------------------------------

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
// fuzz tools — protocol-typed fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw
// (RFC-001 N8; the legacy `fuzz` MCP tool was removed at the backend in
// favour of these four — see USK-937)
//
// Schemas mirror the Go input/output structs in internal/mcp/fuzz_*.go.
// Lifecycle controls (pause/resume/cancel) intentionally have no
// corresponding tool — the typed fuzz_* tools are synchronous and run to
// completion (or the per-tool stop_on_* flag). See PR USK-937 for the
// follow-up `feat(mcp): fuzz job lifecycle control` Issue.
// ---------------------------------------------------------------------------

/** One position into the HTTPMessage envelope for fuzz_http. */
export interface FuzzHTTPPosition {
  path: string;
  payloads: string[];
  encoding?: string;
}

/** Parameters for the fuzz_http MCP tool. */
export interface FuzzHTTPParams {
  flow_id?: string;
  method?: string;
  scheme?: string;
  authority?: string;
  path?: string;
  raw_query?: string;
  headers?: HeaderKV[];
  body?: string;
  body_encoding?: string;
  body_set?: boolean;
  body_patches?: BodyPatch[];
  override_host?: string;
  tls_fingerprint?: string;
  timeout_ms?: number;
  tag?: string;
  positions: FuzzHTTPPosition[];
  stop_on_5xx?: boolean;
}

/** One variant result row from fuzz_http. */
export interface FuzzHTTPVariantRow {
  index: number;
  stream_id: string;
  status_code?: number;
  body_size?: number;
  payloads: Record<string, string>;
  error?: string;
  duration_ms: number;
}

/** Result of the fuzz_http MCP tool. */
export interface FuzzHTTPResult {
  fuzz_id: string;
  total_variants: number;
  completed_variants: number;
  stopped_reason?: string;
  variants: FuzzHTTPVariantRow[];
  duration_ms: number;
  tag?: string;
}

/** One position into the WSMessage envelope for fuzz_ws. */
export interface FuzzWSPosition {
  path: string;
  payloads: string[];
  encoding?: string;
}

/** Parameters for the fuzz_ws MCP tool. */
export interface FuzzWSParams {
  flow_id?: string;
  target_addr?: string;
  scheme?: string;
  path?: string;
  raw_query?: string;
  opcode: string;
  fin?: boolean;
  payload?: string;
  body_encoding?: string;
  payload_set?: boolean;
  masked?: boolean;
  mask?: string;
  close_code?: number;
  close_reason?: string;
  compressed?: boolean;
  timeout_ms?: number;
  tls_fingerprint?: string;
  tag?: string;
  positions: FuzzWSPosition[];
  stop_on_close?: boolean;
}

/** One variant result row from fuzz_ws. */
export interface FuzzWSVariantRow {
  index: number;
  stream_id: string;
  opcode?: string;
  fin?: boolean;
  payload_size?: number;
  compressed?: boolean;
  close_code?: number;
  close_reason?: string;
  payloads: Record<string, string>;
  error?: string;
  duration_ms: number;
}

/** Result of the fuzz_ws MCP tool. */
export interface FuzzWSResult {
  fuzz_id: string;
  total_variants: number;
  completed_variants: number;
  stopped_reason?: string;
  variants: FuzzWSVariantRow[];
  duration_ms: number;
  tag?: string;
}

/** One position into the GRPCStart/GRPCData envelope for fuzz_grpc. */
export interface FuzzGRPCPosition {
  path: string;
  payloads: string[];
  encoding?: string;
}

/** Parameters for the fuzz_grpc MCP tool. */
export interface FuzzGRPCParams {
  flow_id?: string;
  target_addr?: string;
  scheme?: string;
  service?: string;
  method?: string;
  metadata?: HeaderKV[];
  encoding?: string;
  accept_encoding?: string[];
  messages?: ResendGRPCData[];
  trailer_metadata?: HeaderKV[];
  timeout_ms?: number;
  tls_fingerprint?: string;
  tag?: string;
  positions: FuzzGRPCPosition[];
  stop_on_non_ok?: boolean;
}

/** One variant result row from fuzz_grpc. */
export interface FuzzGRPCVariantRow {
  index: number;
  stream_id: string;
  status: number;
  status_message?: string;
  response_message_count?: number;
  response_total_bytes?: number;
  payloads: Record<string, string>;
  error?: string;
  duration_ms: number;
}

/** Result of the fuzz_grpc MCP tool. */
export interface FuzzGRPCResult {
  fuzz_id: string;
  total_variants: number;
  completed_variants: number;
  stopped_reason?: string;
  variants: FuzzGRPCVariantRow[];
  duration_ms: number;
  tag?: string;
}

/** One position into the RawMessage payload for fuzz_raw. */
export interface FuzzRawPosition {
  path: string;
  payloads: string[];
  encoding?: string;
}

/** Parameters for the fuzz_raw MCP tool. */
export interface FuzzRawParams {
  flow_id?: string;
  target_addr: string;
  use_tls?: boolean;
  sni?: string;
  override_bytes?: string;
  override_bytes_encoding?: string;
  override_bytes_set?: boolean;
  patches?: ResendRawBytePatch[];
  insecure_skip_verify?: boolean;
  tls_fingerprint?: string;
  timeout_ms?: number;
  tag?: string;
  positions: FuzzRawPosition[];
  stop_on_error?: boolean;
}

/** One variant result row from fuzz_raw. */
export interface FuzzRawVariantRow {
  index: number;
  stream_id: string;
  response_size?: number;
  response_chunks?: number;
  truncated?: boolean;
  payloads: Record<string, string>;
  error?: string;
  duration_ms: number;
}

/** Result of the fuzz_raw MCP tool. */
export interface FuzzRawResult {
  fuzz_id: string;
  total_variants: number;
  completed_variants: number;
  stopped_reason?: string;
  variants: FuzzRawVariantRow[];
  duration_ms: number;
  tag?: string;
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

    // Mode: "structured" (default) or "raw"
    mode?: "structured" | "raw";

    // modify_and_forward mutation parameters — request phase (structured mode)
    override_method?: string;
    override_url?: string;
    override_headers?: Record<string, string>;
    add_headers?: Record<string, string>;
    remove_headers?: string[];
    override_body?: string | null;

    // modify_and_forward mutation parameters — response phase (structured mode)
    override_status?: number;
    override_response_headers?: Record<string, string>;
    add_response_headers?: Record<string, string>;
    remove_response_headers?: string[];
    override_response_body?: string | null;

    // modify_and_forward mutation parameters (raw mode)
    raw_override_base64?: string;
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
  | "test_target"
  | "set_rate_limits"
  | "get_rate_limits"
  | "set_budget"
  | "get_budget"
  | "get_safety_filter";

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

    // set_rate_limits
    max_requests_per_second?: number;
    max_requests_per_host_per_second?: number;

    // set_budget
    max_total_requests?: number;
    max_duration?: string;
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

/** Rate limit configuration (mirrors Go proxy.RateLimitConfig). */
export interface RateLimitConfig {
  max_requests_per_second: number;
  max_requests_per_host_per_second: number;
}

/** Result of set_rate_limits action. */
export interface SecuritySetRateLimitsResult {
  status: string;
  effective: RateLimitConfig;
  agent: RateLimitConfig;
}

/** Result of get_rate_limits action. */
export interface SecurityGetRateLimitsResult {
  policy: RateLimitConfig;
  agent: RateLimitConfig;
  effective: RateLimitConfig;
}

/** Budget configuration (mirrors Go proxy.BudgetConfig). */
export interface BudgetConfig {
  max_total_requests: number;
  max_duration: string;
}

/** Result of set_budget action. */
export interface SecuritySetBudgetResult {
  status: string;
  effective: BudgetConfig;
  agent: BudgetConfig;
}

/** Result of get_budget action. */
export interface SecurityGetBudgetResult {
  policy: BudgetConfig;
  agent: BudgetConfig;
  effective: BudgetConfig;
  request_count: number;
  stop_reason?: string;
}

// ---------------------------------------------------------------------------
// security tool — get_safety_filter
// ---------------------------------------------------------------------------

/** A single SafetyFilter rule (input or output). */
export interface SafetyFilterRule {
  id: string;
  name: string;
  pattern: string;
  targets: string[];
  action: string;
  replacement?: string;
  category: string;
}

/** Result of get_safety_filter action. */
export interface SafetyFilterResult {
  enabled: boolean;
  input_rules: SafetyFilterRule[];
  output_rules: SafetyFilterRule[];
  immutable: boolean;
}

// ---------------------------------------------------------------------------
// plugin_introspect tool — RFC-001 N8 pluginv2 introspection
// ---------------------------------------------------------------------------

/** Single (protocol, event, phase) registration as recorded by pluginv2.register_hook. */
export interface PluginHookRegistration {
  protocol: string;
  event: string;
  phase: string;
}

/** Per-plugin info entry returned by plugin_introspect. */
export interface PluginIntrospectInfo {
  /** Plugin's stable identifier. */
  name: string;
  /** Filesystem location of the plugin script. */
  path: string;
  /** Whether the engine considers the plugin live. */
  enabled: boolean;
  /** Each register_hook call the plugin made, in script order. */
  registrations: PluginHookRegistration[];
  /** PluginConfig.Vars after redact_keys is applied (server-side). */
  vars?: Record<string, unknown>;
}

/** Result of the plugin_introspect MCP tool. */
export interface PluginIntrospectResult {
  plugins: PluginIntrospectInfo[];
}

// ---------------------------------------------------------------------------
// resend_* protocol-typed tools (RFC-001 N8) — schemas mirror the Go types
// ---------------------------------------------------------------------------

/** Parameters for the resend_http MCP tool. */
export interface ResendHTTPParams {
  flow_id?: string;
  method?: string;
  scheme?: string;
  authority?: string;
  path?: string;
  raw_query?: string;
  headers?: HeaderKV[];
  body?: string;
  body_encoding?: string;
  body_set?: boolean;
  body_patches?: BodyPatch[];
  override_host?: string;
  follow_redirects?: boolean;
  timeout_ms?: number;
  tls_fingerprint?: string;
  tag?: string;
}

/** Result of the resend_http MCP tool. */
export interface ResendHTTPResult {
  stream_id: string;
  status_code: number;
  headers: HeaderKV[];
  body: string;
  body_encoding: string;
  duration_ms: number;
  tag?: string;
}

/** Parameters for the resend_ws MCP tool. */
export interface ResendWSParams {
  flow_id?: string;
  target_addr?: string;
  scheme?: string;
  path?: string;
  raw_query?: string;
  opcode: string;
  fin?: boolean;
  payload?: string;
  body_encoding?: string;
  payload_set?: boolean;
  masked?: boolean;
  mask?: string;
  close_code?: number;
  close_reason?: string;
  compressed?: boolean;
  timeout_ms?: number;
  tls_fingerprint?: string;
  tag?: string;
}

/** Result of the resend_ws MCP tool. */
export interface ResendWSResult {
  stream_id: string;
  opcode: string;
  fin: boolean;
  payload: string;
  payload_encoding: string;
  compressed?: boolean;
  close_code?: number;
  close_reason?: string;
  duration_ms: number;
  tag?: string;
}

/** A single gRPC LPM in the resend_grpc request. */
export interface ResendGRPCData {
  payload: string;
  body_encoding?: string;
  compressed?: boolean;
}

/** Parameters for the resend_grpc MCP tool. */
export interface ResendGRPCParams {
  flow_id?: string;
  target_addr?: string;
  scheme?: string;
  service?: string;
  method?: string;
  metadata?: HeaderKV[];
  encoding?: string;
  accept_encoding?: string[];
  messages?: ResendGRPCData[];
  trailer_metadata?: HeaderKV[];
  timeout_ms?: number;
  tls_fingerprint?: string;
  tag?: string;
}

/** Decoded response-side LPM in the resend_grpc result. */
export interface ResendGRPCDataResult {
  payload: string;
  payload_encoding: string;
  compressed?: boolean;
}

/** Trailer summary in the resend_grpc result. */
export interface ResendGRPCEndResult {
  status: number;
  message?: string;
  trailers?: HeaderKV[];
}

/** Result of the resend_grpc MCP tool. */
export interface ResendGRPCResult {
  stream_id: string;
  start_metadata: HeaderKV[];
  messages: ResendGRPCDataResult[];
  end?: ResendGRPCEndResult;
  duration_ms: number;
  tag?: string;
  /**
   * Non-fatal warnings surfaced by the backend (e.g. proto-json round-trip
   * dropping unknown fields when a registered schema is applied). Emitted by
   * `internal/mcp/resend_grpc.go:121`; absent on success without warnings.
   */
  warnings?: string[];
}

/** Offset-based byte patch for resend_raw. */
export interface ResendRawBytePatch {
  offset: number;
  data: string;
  data_encoding?: string;
}

/** Parameters for the resend_raw MCP tool. */
export interface ResendRawParams {
  flow_id: string;
  target_addr: string;
  use_tls?: boolean;
  sni?: string;
  override_bytes?: string;
  override_bytes_encoding?: string;
  override_bytes_set?: boolean;
  patches?: ResendRawBytePatch[];
  insecure_skip_verify?: boolean;
  tls_fingerprint?: string;
  timeout_ms?: number;
  tag?: string;
}

/** Result of the resend_raw MCP tool. */
export interface ResendRawTypedResult {
  stream_id: string;
  response_bytes: string;
  response_size: number;
  response_chunks?: number;
  truncated?: boolean;
  duration_ms: number;
  tag?: string;
}

// ---------------------------------------------------------------------------
// grpc_schema tool — schema-aware gRPC .proto management (USK-923 / USK-926)
// ---------------------------------------------------------------------------

/** Available grpc_schema actions. */
export type GrpcSchemaAction =
  | "register"
  | "list"
  | "unregister"
  | "clear"
  | "discover";

/** Descriptor input shape for action=register. */
export type GrpcSchemaSource = "descriptor_set" | "file";

/** Transport scheme for action=discover. */
export type GrpcSchemaDiscoverScheme = "https" | "http";

/** Action-specific parameters for the grpc_schema tool. */
export interface GrpcSchemaToolParams {
  /** Source mode (register only). */
  source?: GrpcSchemaSource;
  /** Base64-encoded FileDescriptorSet payload (register, source=descriptor_set). Max 16 MiB decoded. */
  descriptor_set_b64?: string;
  /** Optional service-name allowlist applied during register / discover. */
  service_filter?: string[];
  /** Free-form diagnostic label preserved in list output. */
  source_label?: string;
  /** Fully-qualified service name (unregister only). */
  service?: string;
  /** Absolute .proto paths (register, source=file). */
  proto_paths?: string[];
  /** Optional -I roots for protoc (register, source=file). */
  import_paths?: string[];
  /** Upstream `host:port` exposing the gRPC reflection endpoint (discover only). */
  target_addr?: string;
  /** Transport scheme (discover only). Defaults to `https`. */
  scheme?: GrpcSchemaDiscoverScheme;
  /** Optional ordered gRPC metadata forwarded on the reflection stream (discover only). */
  metadata?: HeaderKV[];
  /** Per-call timeout in milliseconds (discover only). Default 30000, server caps at 300000. */
  timeout_ms?: number;
}

/** Parameters for the grpc_schema MCP tool. */
export interface GrpcSchemaParams {
  action: GrpcSchemaAction;
  params?: GrpcSchemaToolParams;
}

/** One method entry inside a registered gRPC service. */
export interface GrpcSchemaMethodEntry {
  name: string;
  input: string;
  output: string;
}

/** One service entry returned by register / list. */
export interface GrpcSchemaServiceEntry {
  service: string;
  methods: GrpcSchemaMethodEntry[];
  source_label?: string;
  registered_at?: string;
}

/** Result of grpc_schema action=register. */
export interface GrpcSchemaRegisterResult {
  registered: GrpcSchemaServiceEntry[];
}

/** Result of grpc_schema action=list. */
export interface GrpcSchemaListResult {
  schemas: GrpcSchemaServiceEntry[];
}

/** Result of grpc_schema action=unregister. */
export interface GrpcSchemaUnregisterResult {
  service: string;
  unregistered: boolean;
}

/** Result of grpc_schema action=clear. */
export interface GrpcSchemaClearResult {
  cleared: number;
}

/** Result of grpc_schema action=discover (USK-928). */
export interface GrpcSchemaDiscoverResult {
  discovered: GrpcSchemaServiceEntry[];
  target: string;
  reflection_version?: string;
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
