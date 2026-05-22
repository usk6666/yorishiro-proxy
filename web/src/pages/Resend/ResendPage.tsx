import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Input } from "../../components/ui/Input.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Tabs } from "../../components/ui/Tabs.js";
import { useToast } from "../../components/ui/Toast.js";
import { useMcpContext } from "../../lib/mcp/context.js";
import { useQuery } from "../../lib/mcp/hooks.js";
import type {
  BodyPatch,
  FlowDetailResult,
  FlowEntry,
  FlowsResult,
  HeaderKV,
  HooksInput,
  MacrosEntry,
  MessageEntry,
  MessagesResult,
  RawPatch,
  ResendGRPCResult,
  ResendHTTPParams,
  ResendHTTPResult,
  ResendRawBytePatch,
  ResendRawParams,
  ResendRawTypedResult,
  ResendWSResult,
} from "../../lib/mcp/types.js";
import { HookConfigEditor } from "../../components/hooks/HookConfigEditor.js";
import { BodyPatchEditor } from "./BodyPatchEditor.js";
import { ComparerView } from "./ComparerView.js";
import { GrpcRequestEditor, type GrpcRequestEditorState } from "./GrpcRequestEditor.js";
import { GrpcResponseViewer } from "./GrpcResponseViewer.js";
import { HeaderEditor } from "./HeaderEditor.js";
import { RawPatchEditor } from "./RawPatchEditor.js";
import "./ResendPage.css";
import { ResponseViewer } from "./ResponseViewer.js";
import { TcpMessageList } from "./TcpMessageList.js";
import type { TcpResendResult } from "./TcpResponseViewer.js";
import { TcpResponseViewer } from "./TcpResponseViewer.js";
import {
  buildResendGrpcParams,
  buildResendHTTPRawParams,
  buildResendWsParams,
  buildTcpReplayResendRawParams,
  typedResendToolForProtocol,
} from "./typedDispatch.js";
import { WsRequestEditor, type WsRequestEditorState } from "./WsRequestEditor.js";
import { WsResponseViewer } from "./WsResponseViewer.js";

/**
 * Tooltip text shown next to the hooks editors and dry-run toggles that
 * the typed `resend_http` / `resend_raw` MCP tools don't accept (USK-938).
 * Tracked as deferred follow-ups (resend_http hooks + dry_run support) so
 * the UI stays discoverable even though the inputs are inert.
 */
const SUSPENDED_FIELD_TOOLTIP =
  "Unsupported on typed resend tools. Tracked as a follow-up Issue.";

/** HTTP methods available for resend. */
const HTTP_METHODS = [
  "GET",
  "POST",
  "PUT",
  "DELETE",
  "PATCH",
  "HEAD",
  "OPTIONS",
] as const;

/** Tabs for the HTTP request editor panel (structured mode). */
const HTTP_REQUEST_TABS = [
  { id: "headers", label: "Headers" },
  { id: "body", label: "Body" },
  { id: "patches", label: "Body Patches" },
];

/** Tabs for the TCP request editor panel. */
const TCP_REQUEST_TABS = [
  { id: "messages", label: "Messages" },
  { id: "raw_patches", label: "Raw Patches" },
];

/** Protocol mode tabs shown at the top of the editor. */
const TCP_MODE_TABS = [
  { id: "resend_raw", label: "Resend Raw" },
  { id: "tcp_replay", label: "TCP Replay" },
];

/** HTTP editor mode tabs: structured vs raw. */
const HTTP_MODE_TABS = [
  { id: "structured", label: "Structured" },
  { id: "raw", label: "Raw" },
];

/** Top-level page mode tabs: Resend vs Compare. */
const PAGE_MODE_TABS = [
  { id: "resend", label: "Resend" },
  { id: "compare", label: "Compare" },
];

/**
 * Display shape adapted from `ResendHTTPResult` so the existing
 * `ResponseViewer` keeps rendering recorded responses unchanged.
 *
 * USK-938 dropped the `dry_run` field — the typed `resend_http` MCP tool
 * has no dry-run path, and the legacy `resend` tool that did is gone.
 */
export interface ResendResult {
  new_flow_id?: string;
  method?: string;
  url?: string;
  request_headers?: Record<string, string[]>;
  request_body?: string;
  response_status_code?: number;
  response_headers?: Record<string, string[]>;
  response_body?: string;
  response_body_encoding?: string;
  duration_ms?: number;
  tag?: string;
}

/**
 * A Stream-derived history entry for resends (USK-787).
 *
 * Backed by server-side Stream Store rows pre-filtered by `origin = "resend"`.
 * The optimistic-prepend buffer also produces values of this shape so the
 * "fresh resend just landed" row appears before the server fetch resolves.
 */
interface HistoryEntry {
  /** FlowEntry.id — used for row key + navigation to /flows/:id. */
  id: string;
  protocol: string;
  method: string;
  url: string;
  statusCode?: number;
  durationMs?: number;
  tag?: string;
  /** ISO 8601 timestamp from the server (or `new Date().toISOString()` for optimistic rows). */
  timestamp: string;
}

/** Page size for the server-driven Send History pager (USK-787). */
const HISTORY_PAGE_SIZE = 50;

/**
 * Map a `FlowEntry` returned by the `flows` MCP query (already pre-filtered
 * by `origin = "resend"`) to the `HistoryEntry` render shape.
 *
 * `FlowEntry.tags` is server-side metadata (e.g. user-supplied resend `tag`
 * argument); we surface a single representative value when present so the
 * existing tag badge keeps working.
 */
function flowEntryToHistoryEntry(entry: FlowEntry): HistoryEntry {
  let tag: string | undefined;
  if (entry.tags) {
    // Prefer a "tag" key when the server stored the resend tag under that
    // name; otherwise pick the first defined value so the badge still
    // surfaces useful metadata. Drop empty strings.
    if (typeof entry.tags.tag === "string" && entry.tags.tag !== "") {
      tag = entry.tags.tag;
    } else {
      for (const v of Object.values(entry.tags)) {
        if (typeof v === "string" && v !== "") {
          tag = v;
          break;
        }
      }
    }
  }
  return {
    id: entry.id,
    protocol: entry.protocol,
    method: entry.method,
    url: entry.url,
    statusCode: entry.status_code,
    durationMs: entry.duration_ms,
    tag,
    timestamp: entry.timestamp,
  };
}

/** Get the Badge variant for an HTTP status code. */
function statusBadgeVariant(
  code: number | undefined,
): "default" | "success" | "warning" | "danger" | "info" {
  if (code == null || code === 0) return "default";
  if (code < 300) return "success";
  if (code < 400) return "info";
  if (code < 500) return "warning";
  return "danger";
}

/** Detect whether a flow uses TCP/raw protocol. */
function isTcpFlow(flow: FlowDetailResult): boolean {
  const proto = (flow.protocol || "").toLowerCase();
  return proto === "tcp" || proto === "raw";
}

/** Check if a flow is HTTP/2, gRPC, or gRPC-Web (no raw bytes stored). */
function isHttp2Flow(flow: FlowDetailResult): boolean {
  const proto = (flow.protocol || "").toLowerCase();
  return proto === "http/2" || proto === "h2" || proto === "grpc" || proto === "grpc-web";
}

/** Detect whether a flow is gRPC / gRPC-Web (uses resend_grpc dispatch). */
function isGrpcFlow(flow: FlowDetailResult): boolean {
  const proto = (flow.protocol || "").toLowerCase();
  return proto === "grpc" || proto === "grpc-web";
}

/** Detect whether a flow is a WebSocket flow (uses resend_ws dispatch). */
function isWsFlow(flow: FlowDetailResult): boolean {
  const proto = (flow.protocol || "").toLowerCase();
  return proto === "ws" || proto === "websocket";
}

/**
 * Split a fully-qualified gRPC URL path of the form
 * "/package.Service/Method" into its `(service, method)` components.
 *
 * The recorded `flow.url` for gRPC flows uses the standard gRPC HTTP/2
 * path encoding; we slice it back out so the editor pre-populates with
 * the source flow's RPC by default. Returns empty strings when the URL
 * doesn't match the expected shape so the user can fill them manually.
 */
function splitGrpcServiceMethod(urlStr: string): {
  service: string;
  method: string;
} {
  if (!urlStr) return { service: "", method: "" };
  let pathname: string;
  try {
    pathname = new URL(urlStr).pathname;
  } catch {
    pathname = urlStr;
  }
  const trimmed = pathname.startsWith("/") ? pathname.slice(1) : pathname;
  const slash = trimmed.indexOf("/");
  if (slash <= 0 || slash === trimmed.length - 1) {
    return { service: "", method: "" };
  }
  return {
    service: trimmed.slice(0, slash),
    method: trimmed.slice(slash + 1),
  };
}

/**
 * Extract the path component of a flow URL, defaulting to "/" when the
 * URL doesn't parse. Used to pre-populate the WebSocket editor's path
 * field from the recorded handshake URL.
 */
function extractFlowPath(urlStr: string): string {
  if (!urlStr) return "/";
  try {
    const parsed = new URL(urlStr);
    return (parsed.pathname || "/") + (parsed.search || "");
  } catch {
    return urlStr;
  }
}

/**
 * Extract the FIN bit from the first send-direction frame in a loaded
 * WebSocket flow (USK-967).
 *
 * Frames are projected into `message_preview` with `metadata["ws_fin"]`
 * (see `internal/pipeline/record_step.go:1231`). Returns `true` when the
 * flow has no message_preview, no send-direction frame, or the metadata
 * value is missing/unparseable — matching the historical default but
 * preserving the wire-observed FIN=0 when one is recorded. Without this,
 * a frame loaded with FIN=0 silently default-resends with FIN=1, which
 * is a wire-faithfulness violation.
 */
function extractFlowFin(flow: FlowDetailResult): boolean {
  const preview = flow.message_preview;
  if (!preview || preview.length === 0) return true;
  for (const msg of preview) {
    if (msg.direction === "send") {
      const raw = msg.metadata?.ws_fin;
      if (raw === "true") return true;
      if (raw === "false") return false;
      return true;
    }
  }
  return true;
}

/**
 * Map a `Record<string, string[]>` headers map (the FlowDetailResult
 * wire shape) to the ordered `{key,value}` rows the HeaderEditor consumes.
 * Mirrors the inline conversion in the HTTP populate path.
 */
function headersRecordToRows(
  headers: Record<string, string[]> | null | undefined,
): Array<{ key: string; value: string }> {
  if (!headers) return [];
  const rows: Array<{ key: string; value: string }> = [];
  for (const [key, values] of Object.entries(headers)) {
    for (const value of values) {
      rows.push({ key, value });
    }
  }
  return rows;
}

/**
 * Decode base64-encoded raw request bytes to a text string.
 * Returns null if decoding fails or the data is empty.
 */
function decodeRawRequest(base64Data: string): string | null {
  if (!base64Data) return null;
  try {
    return atob(base64Data);
  } catch {
    return null;
  }
}

/**
 * Reconstruct an HTTP/1.1 raw message from parsed flow data.
 * Used for HTTP/2, gRPC, and gRPC-Web flows that don't store raw bytes.
 *
 * Format:
 *   {Method} {RequestURI} HTTP/1.1\r\n
 *   Host: {host}\r\n
 *   {Headers}\r\n
 *   \r\n
 *   {Body}
 */
function reconstructHttp11(flow: FlowDetailResult): string {
  const method = flow.method || "GET";
  const urlStr = flow.url || "/";

  // Extract request URI (path + query) and host from the URL.
  let requestUri = "/";
  let host = "";
  try {
    const parsed = new URL(urlStr);
    requestUri = parsed.pathname + parsed.search;
    host = parsed.host;
  } catch {
    // If URL parsing fails, use the raw URL as-is.
    requestUri = urlStr;
  }

  const lines: string[] = [];
  lines.push(`${method} ${requestUri} HTTP/1.1`);

  // Track which headers have been added to avoid duplicating Host.
  const addedHeaders = new Set<string>();

  // Add Host header first if not already in request_headers.
  const hasHostHeader = flow.request_headers
    ? Object.keys(flow.request_headers).some((k) => k.toLowerCase() === "host")
    : false;

  if (!hasHostHeader && host) {
    lines.push(`Host: ${host}`);
  }

  // Add all recorded headers.
  if (flow.request_headers) {
    for (const [key, values] of Object.entries(flow.request_headers)) {
      for (const value of values) {
        lines.push(`${key}: ${value}`);
      }
      addedHeaders.add(key.toLowerCase());
    }
  }

  // Empty line to separate headers from body.
  lines.push("");

  // Join with \r\n (HTTP line endings).
  let raw = lines.join("\r\n");

  // Append body if present.
  const bodyText = flow.request_body || "";
  if (bodyText) {
    raw += "\r\n" + bodyText;
  }

  return raw;
}

/**
 * Extract target address (host:port) from a flow URL.
 * Returns host:port suitable for raw TCP connection.
 */
function extractTargetAddr(flow: FlowDetailResult): string {
  // Prefer server_addr from connection info.
  if (flow.conn_info?.server_addr) {
    return flow.conn_info.server_addr;
  }

  // Fall back to parsing URL.
  const urlStr = flow.url || "";
  try {
    const parsed = new URL(urlStr);
    const host = parsed.hostname;
    const port = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
    return `${host}:${port}`;
  } catch {
    return "";
  }
}

/**
 * Determine if TLS should be used from a flow's connection info or URL.
 */
function extractUseTls(flow: FlowDetailResult): boolean {
  if (flow.conn_info?.tls_version) {
    return true;
  }
  const urlStr = flow.url || "";
  try {
    return new URL(urlStr).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Split a request URL into the scheme/authority/path/raw_query tuple expected
 * by the resend_http MCP tool. Falls back to a path-only override when URL
 * parsing fails so unusual flow URLs don't block the protocol-typed dispatch.
 */
function splitUrlForResendHTTP(urlStr: string): {
  scheme?: string;
  authority?: string;
  path?: string;
  rawQuery?: string;
} {
  if (!urlStr) return {};
  try {
    const parsed = new URL(urlStr);
    const scheme = parsed.protocol.replace(/:$/, "");
    const authority = parsed.host;
    const path = parsed.pathname || "/";
    const rawQuery = parsed.search.replace(/^\?/, "");
    return {
      scheme: scheme || undefined,
      authority: authority || undefined,
      path,
      rawQuery: rawQuery || undefined,
    };
  } catch {
    return { path: urlStr };
  }
}

/**
 * Encode a string to base64 (handles binary content).
 */
function stringToBase64(str: string): string {
  // Use btoa for ASCII-safe encoding. For raw HTTP messages,
  // content is typically ASCII/Latin-1 compatible.
  try {
    return btoa(str);
  } catch {
    // For strings with characters outside Latin-1, use TextEncoder.
    const encoder = new TextEncoder();
    const bytes = encoder.encode(str);
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary);
  }
}

export function ResendPage() {
  const { flowId: routeFlowId } = useParams<{ flowId: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { client } = useMcpContext();

  // Page mode: derived from URL searchParams for reactivity to URL changes.
  const pageMode: "resend" | "compare" = searchParams.get("mode") === "compare" ? "compare" : "resend";
  const setPageMode = useCallback(
    (mode: "resend" | "compare") => {
      const params = new URLSearchParams(searchParams);
      if (mode === "compare") {
        params.set("mode", "compare");
      } else {
        params.delete("mode");
      }
      navigate({ search: params.toString() }, { replace: true });
    },
    [searchParams, navigate],
  );

  // Flow ID input state.
  const [flowIdInput, setFlowIdInput] = useState(routeFlowId ?? "");
  const [activeFlowId, setActiveFlowId] = useState(routeFlowId ?? "");

  // HTTP request editor state (structured mode).
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("");
  const [headers, setHeaders] = useState<Array<{ key: string; value: string }>>([]);
  const [body, setBody] = useState("");
  const [bodyPatches, setBodyPatches] = useState<BodyPatch[]>([]);

  // HTTP raw editor state.
  const [httpEditorMode, setHttpEditorMode] = useState<"structured" | "raw">("structured");
  const [rawHttpText, setRawHttpText] = useState("");
  const [rawTargetAddr, setRawTargetAddr] = useState("");
  const [rawUseTls, setRawUseTls] = useState(false);

  // TCP-specific state.
  const [targetAddr, setTargetAddr] = useState("");
  const [useTls, setUseTls] = useState(false);
  const [rawPatches, setRawPatches] = useState<RawPatch[]>([]);
  // RawPatchEditor validity gate (USK-967). The editor surfaces invalid
  // offset entries (non-numeric / empty / negative / fractional) inline
  // and toggles this flag via onValidityChange so the Send button is
  // disabled before the prior silent NaN→0 coercion path is reached.
  const [rawPatchesValid, setRawPatchesValid] = useState(true);
  const [tcpMode, setTcpMode] = useState<"resend_raw" | "tcp_replay">("resend_raw");

  // gRPC editor state — USK-936. Minimum-viable MVP exposes service /
  // method / target / scheme / ordered metadata / a single text payload.
  const [grpcState, setGrpcState] = useState<GrpcRequestEditorState>({
    targetAddr: "",
    scheme: "https",
    service: "",
    method: "",
    metadata: [],
    messagePayload: "",
  });

  // WebSocket editor state — USK-936. resend_ws is single-frame on the
  // backend; multi-frame replay is out of scope.
  const [wsState, setWsState] = useState<WsRequestEditorState>({
    targetAddr: "",
    scheme: "wss",
    path: "/",
    opcode: "text",
    fin: true,
    payload: "",
    bodyEncoding: "text",
    compressed: false,
    closeCode: "",
    closeReason: "",
  });

  // Shared state.
  const [tag, setTag] = useState("");
  // `dryRun` / `setDryRun` are intentionally preserved across the USK-938
  // suspension: the dry-run checkboxes are rendered disabled (the typed
  // `resend_http` / `resend_raw` MCP tools have no dry-run path), so the
  // setter is presently unreachable. Kept so the follow-up Issue
  // (`feat(mcp): resend_http hooks + dry_run support`) can re-enable the
  // inputs without re-introducing the state shape.
  const [dryRun, setDryRun] = useState(false);

  // Hooks state. Same suspension rationale as `dryRun` above — the
  // `HookConfigEditor` is wrapped in a pointer-events:none overlay, so
  // `setHooks` is presently unreachable. Retained so the follow-up Issue
  // can re-wire it without re-introducing the state shape.
  const [hooks, setHooks] = useState<HooksInput>({});

  // Fetch available macros for hook selection.
  const { data: macrosData } = useQuery("macros");
  const availableMacros: MacrosEntry[] = useMemo(
    () => (macrosData as { macros?: MacrosEntry[] } | null)?.macros ?? [],
    [macrosData],
  );

  // UI state.
  const [requestTab, setRequestTab] = useState("headers");
  const [tcpRequestTab, setTcpRequestTab] = useState("messages");
  const [httpResponse, setHttpResponse] = useState<ResendResult | null>(null);
  const [tcpResponse, setTcpResponse] = useState<TcpResendResult | null>(null);
  const [rawResponse, setRawResponse] = useState<TcpResendResult | null>(null);
  // gRPC / WebSocket typed responses (USK-936).
  const [grpcResponse, setGrpcResponse] = useState<ResendGRPCResult | null>(null);
  const [wsResponse, setWsResponse] = useState<ResendWSResult | null>(null);
  // Per-handler in-flight flags (USK-938). Previously the page shared a
  // single `executing` flag from `useResend.loading`; that flag never
  // flipped on the typed fast-paths, so the HTTP "Send" button stayed
  // active during a typed call. After removing the legacy hook each
  // handler tracks its own pending state — see also `grpcSending` and
  // `wsSending` which already followed this pattern in USK-936.
  const [grpcSending, setGrpcSending] = useState(false);
  const [wsSending, setWsSending] = useState(false);
  const [httpSending, setHttpSending] = useState(false);
  const [rawSending, setRawSending] = useState(false);
  const [tcpResendRawSending, setTcpResendRawSending] = useState(false);
  const [tcpReplaySending, setTcpReplaySending] = useState(false);

  // -------------------------------------------------------------------------
  // Send History (USK-787)
  // -------------------------------------------------------------------------
  //
  // Server-driven. `useQuery("flows", { filter: { origin: "resend" }, ... })`
  // returns the most recent resend Streams from the server-side Stream Store,
  // so reload preserves the list. `optimisticEntries` is a transient buffer
  // that prepends a freshly-resent row before the next refetch resolves; it
  // is cleared on page change and trimmed when entries land in the server
  // response (de-duplicated by id below at render time).
  // -------------------------------------------------------------------------
  const [historyOffset, setHistoryOffset] = useState(0);
  const [optimisticEntries, setOptimisticEntries] = useState<HistoryEntry[]>([]);

  const {
    data: historyData,
    loading: historyLoading,
    error: historyError,
    refetch: refetchHistory,
  } = useQuery("flows", {
    filter: { origin: "resend" },
    limit: HISTORY_PAGE_SIZE,
    offset: historyOffset,
    // The server's `flows` resource sorts by timestamp descending by default,
    // matching FlowsPage's pattern of omitting `sortBy`. Schema's `sort_by`
    // exposes `timestamp` / `duration_ms` for flows but the implicit default
    // is the most-recent-first order we want here.
  });

  /** Composed display rows: optimistic prepend + server entries, de-duped by id. */
  const displayedHistory = useMemo<HistoryEntry[]>(() => {
    const serverRows: HistoryEntry[] = (historyData as FlowsResult | null)?.flows
      ? (historyData as FlowsResult).flows.map(flowEntryToHistoryEntry)
      : [];
    const seen = new Set<string>();
    const out: HistoryEntry[] = [];
    for (const e of optimisticEntries) {
      if (e.id && !seen.has(e.id)) {
        seen.add(e.id);
        out.push(e);
      } else if (!e.id) {
        // Defensive: optimistic rows should always have an id (we only push
        // after we have a stream_id from the resend result), but allow
        // through to avoid silently swallowing rows.
        out.push(e);
      }
    }
    for (const e of serverRows) {
      if (!seen.has(e.id)) {
        seen.add(e.id);
        out.push(e);
      }
    }
    return out.slice(0, HISTORY_PAGE_SIZE);
  }, [optimisticEntries, historyData]);

  // When the server response includes an optimistic row's id, drop it from
  // the optimistic buffer to avoid retaining stale client-side state.
  useEffect(() => {
    if (optimisticEntries.length === 0) return;
    const flows = (historyData as FlowsResult | null)?.flows;
    if (!flows || flows.length === 0) return;
    const serverIds = new Set(flows.map((f) => f.id));
    if (optimisticEntries.some((e) => serverIds.has(e.id))) {
      setOptimisticEntries((prev) => prev.filter((e) => !serverIds.has(e.id)));
    }
  }, [historyData, optimisticEntries]);

  const historyTotal = (historyData as FlowsResult | null)?.total ?? 0;
  const historyHasNext = historyOffset + HISTORY_PAGE_SIZE < historyTotal;
  const historyHasPrev = historyOffset > 0;

  /** Pump a freshly-completed resend into the optimistic buffer + trigger a refetch. */
  const recordResendSuccess = useCallback(
    (entry: HistoryEntry | null) => {
      if (entry && entry.id) {
        setOptimisticEntries((prev) => {
          const next = [entry, ...prev.filter((e) => e.id !== entry.id)];
          return next.slice(0, HISTORY_PAGE_SIZE);
        });
      }
      // Re-sync the visible page with the server. Failure to refetch (e.g.
      // transient network issue) is non-fatal — the optimistic row stays
      // until a later refetch succeeds. We deliberately do NOT await the
      // promise so the calling resend handler doesn't block on it.
      void refetchHistory();
    },
    [refetchHistory],
  );

  /** Reset optimistic buffer when paging away (it only covers the current page). */
  const goToHistoryPage = useCallback((nextOffset: number) => {
    setOptimisticEntries([]);
    setHistoryOffset(Math.max(0, nextOffset));
  }, []);

  // Fetch original flow data when activeFlowId changes.
  const {
    data: flowData,
    loading: flowLoading,
    error: flowError,
  } = useQuery("flow", {
    id: activeFlowId,
    enabled: activeFlowId.length > 0,
  });

  // Determine protocol mode from flow data.
  const flow = flowData as FlowDetailResult | null;
  const isTcp = useMemo(() => flow != null && isTcpFlow(flow), [flow]);
  const isH2 = useMemo(() => flow != null && isHttp2Flow(flow), [flow]);
  const isGrpc = useMemo(() => flow != null && isGrpcFlow(flow), [flow]);
  const isWs = useMemo(() => flow != null && isWsFlow(flow), [flow]);

  // Fetch messages for TCP flows.
  const {
    data: messagesData,
  } = useQuery("messages", {
    id: activeFlowId,
    enabled: activeFlowId.length > 0 && isTcp,
  });

  const tcpMessages: MessageEntry[] = useMemo(() => {
    if (!messagesData) return [];
    return (messagesData as MessagesResult).messages ?? [];
  }, [messagesData]);

  // Populate editor with flow data when loaded.
  useEffect(() => {
    if (!flow) return;

    // Reset shared state.
    setTag("");
    setHooks({});
    setHttpResponse(null);
    setTcpResponse(null);
    setRawResponse(null);
    setGrpcResponse(null);
    setWsResponse(null);

    if (isGrpcFlow(flow)) {
      // gRPC / gRPC-Web flow: populate the typed editor from the source flow.
      //
      // NOTE (USK-936 MVP scope): `flow.request_body` may carry a
      // base64-encoded protobuf payload (when `flow.request_body_encoding ===
      // "base64"`), but the editor only emits `body_encoding: "text"`. That
      // means binary-protobuf payloads pre-populate as base64 text and round-
      // trip incorrectly on send. Proto-schema-aware editing + base64 mode
      // are deferred to the follow-up Issue (see Issue body "out of scope")
      // — the current populate path is intentionally text-first so the
      // editor is at least usable for schemaless / debug RPCs.
      const { service, method } = splitGrpcServiceMethod(flow.url || "");
      const metadataRows = headersRecordToRows(flow.request_headers);
      setGrpcState({
        targetAddr: flow.conn_info?.server_addr ?? "",
        scheme: extractUseTls(flow) ? "https" : "http",
        service,
        method,
        metadata: metadataRows,
        messagePayload: flow.request_body || "",
      });
    } else if (isWsFlow(flow)) {
      // WebSocket flow: populate single-frame editor from the handshake URL
      // and (USK-967) honour the first send-direction frame's FIN bit
      // so a loaded FIN=0 frame doesn't silently default-resend with FIN=1.
      const path = extractFlowPath(flow.url || "");
      setWsState({
        targetAddr: flow.conn_info?.server_addr ?? "",
        scheme: extractUseTls(flow) ? "wss" : "ws",
        path,
        opcode: "text",
        fin: extractFlowFin(flow),
        payload: "",
        bodyEncoding: "text",
        compressed: false,
        closeCode: "",
        closeReason: "",
      });
    }

    if (isTcpFlow(flow)) {
      // TCP flow: populate target address from connection info.
      setTargetAddr(flow.conn_info?.server_addr ?? "");
      setUseTls(!!flow.conn_info?.tls_version);
      setRawPatches([]);
      // Reset to valid for the empty-patches default; the editor will
      // re-notify after the first edit (USK-967).
      setRawPatchesValid(true);
      setTcpMode("resend_raw");
      setTcpRequestTab("messages");
    } else {
      // HTTP flow: populate structured editor fields.
      setMethod(flow.method || "GET");
      setUrl(flow.url || "");
      setBody(flow.request_body || "");
      setBodyPatches([]);
      setRequestTab("headers");
      setHttpEditorMode("structured");

      // Convert headers from Record<string, string[]> to key-value pairs.
      const headerPairs: Array<{ key: string; value: string }> = [];
      if (flow.request_headers) {
        for (const [key, values] of Object.entries(flow.request_headers)) {
          for (const value of values) {
            headerPairs.push({ key, value });
          }
        }
      }

      // Fallback: if Host header is missing, extract from flow.url
      // (mirrors reconstructHttp11() logic for raw mode).
      const hasHost = headerPairs.some(
        (h) => h.key.toLowerCase() === "host",
      );
      if (!hasHost && flow.url) {
        try {
          const host = new URL(flow.url).host;
          if (host) {
            headerPairs.unshift({ key: "Host", value: host });
          }
        } catch {
          // URL parse failure — skip.
        }
      }

      setHeaders(headerPairs);

      // Populate raw editor fields.
      const isH2Flow = isHttp2Flow(flow);
      if (!isH2Flow && flow.raw_request) {
        // HTTP/1.x: decode the recorded raw bytes.
        const decoded = decodeRawRequest(flow.raw_request);
        setRawHttpText(decoded ?? reconstructHttp11(flow));
      } else {
        // HTTP/2 or no raw bytes: reconstruct HTTP/1.1 from parsed data.
        setRawHttpText(reconstructHttp11(flow));
      }

      // Set target address for raw mode.
      setRawTargetAddr(extractTargetAddr(flow));
      setRawUseTls(extractUseTls(flow));
    }
    // re-fetch must not overwrite in-flight edits; trigger only on flow id change
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flow?.id]);

  // Sync route param changes.
  useEffect(() => {
    if (routeFlowId && routeFlowId !== activeFlowId) {
      setFlowIdInput(routeFlowId);
      setActiveFlowId(routeFlowId);
    }
  }, [routeFlowId, activeFlowId]);

  /** Load a flow by ID from the input. */
  const handleLoadFlow = useCallback(() => {
    const trimmed = flowIdInput.trim();
    if (!trimmed) return;
    setActiveFlowId(trimmed);
    if (trimmed !== routeFlowId) {
      navigate(`/resend/${trimmed}`, { replace: true });
    }
  }, [flowIdInput, routeFlowId, navigate]);

  /**
   * Send HTTP resend request (structured mode) via the typed `resend_http`
   * MCP tool.
   *
   * USK-938: the legacy `resend` fallback (used pre-USK-936 for hooks /
   * dry-run / unknown-protocol flows) was removed because the backend
   * retired the `resend` tool in PR #688 (USK-693). The hooks editor and
   * dry-run row are still rendered for discoverability but disabled with
   * a tooltip pointing at the follow-up Issues.
   */
  const handleHttpSend = useCallback(async () => {
    if (!activeFlowId) {
      addToast({ type: "warning", message: "No flow selected" });
      return;
    }
    if (client == null) {
      addToast({ type: "error", message: "MCP client is not connected" });
      return;
    }
    if (flow == null) {
      addToast({ type: "warning", message: "Flow has not loaded yet" });
      return;
    }
    if (typedResendToolForProtocol(flow.protocol) !== "resend_http") {
      addToast({
        type: "error",
        message: `Unsupported protocol for HTTP resend: ${flow.protocol || "(unknown)"}`,
      });
      return;
    }

    // Build override_headers from the key-value pairs as array format.
    // Array format supports duplicate keys (e.g., multiple Host headers).
    const overrideHeaders = headers
      .filter((h) => h.key.trim() !== "")
      .map((h) => ({ key: h.key.trim(), value: h.value }));

    const split = splitUrlForResendHTTP(url);
    const headerKVs: HeaderKV[] = overrideHeaders.map((h) => ({
      name: h.key,
      value: h.value,
    }));
    const params: ResendHTTPParams = {
      flow_id: activeFlowId,
      method: method || undefined,
      scheme: split.scheme,
      authority: split.authority,
      path: split.path,
      raw_query: split.rawQuery,
      headers: headerKVs.length > 0 ? headerKVs : undefined,
      body: body || undefined,
      body_patches: bodyPatches.length > 0 ? bodyPatches : undefined,
      tag: tag || undefined,
    };

    setHttpSending(true);
    try {
      const typedResult: ResendHTTPResult = await client.resendHttp(params);

      // Map the typed result back to the legacy ResendResult shape so
      // ResponseViewer keeps working unchanged.
      const responseHeaders: Record<string, string[]> = {};
      for (const h of typedResult.headers ?? []) {
        const list = responseHeaders[h.name] ?? [];
        list.push(h.value);
        responseHeaders[h.name] = list;
      }
      const adaptedResult: ResendResult = {
        new_flow_id: typedResult.stream_id,
        response_status_code: typedResult.status_code,
        response_headers: responseHeaders,
        response_body: typedResult.body,
        response_body_encoding: typedResult.body_encoding,
        duration_ms: typedResult.duration_ms,
        tag: typedResult.tag,
      };
      setHttpResponse(adaptedResult);
      recordResendSuccess({
        id: typedResult.stream_id,
        protocol: flow.protocol ?? "HTTP",
        method,
        url,
        statusCode: typedResult.status_code,
        durationMs: typedResult.duration_ms,
        tag: tag || undefined,
        timestamp: new Date().toISOString(),
      });
      addToast({
        type: "success",
        message: `Request sent (${typedResult.status_code ?? "?"})`,
      });
    } catch (err) {
      addToast({
        type: "error",
        message: err instanceof Error ? err.message : "Resend failed",
      });
    } finally {
      setHttpSending(false);
    }
  }, [
    activeFlowId,
    method,
    url,
    headers,
    body,
    bodyPatches,
    tag,
    addToast,
    flow,
    client,
    recordResendSuccess,
  ]);

  /**
   * Send HTTP raw resend request (raw mode) via the typed `resend_raw`
   * MCP tool.
   *
   * USK-938: the legacy `resend{action:"resend_raw"}` path with
   * `override_raw_base64` was retired in PR #688 (USK-693). The typed
   * tool uses `override_bytes` + `override_bytes_encoding: "base64"` —
   * see `buildResendHTTPRawParams` for the field rename in one place.
   * Hooks and dry-run are not supported by the typed schema; the UI
   * controls are disabled with a tooltip.
   */
  const handleHttpRawSend = useCallback(async () => {
    if (!activeFlowId) {
      addToast({ type: "warning", message: "No flow selected" });
      return;
    }
    if (client == null) {
      addToast({ type: "error", message: "MCP client is not connected" });
      return;
    }
    if (!rawTargetAddr.trim()) {
      addToast({ type: "warning", message: "Target address is required for raw mode" });
      return;
    }
    if (!rawHttpText.trim()) {
      addToast({ type: "warning", message: "Raw HTTP message cannot be empty" });
      return;
    }

    const params = buildResendHTTPRawParams({
      flowId: activeFlowId,
      targetAddr: rawTargetAddr.trim(),
      useTls: rawUseTls,
      rawBase64: stringToBase64(rawHttpText),
      tag: tag || undefined,
    });

    setRawSending(true);
    try {
      const typedResult: ResendRawTypedResult = await client.resendRaw(params);
      const adapted: TcpResendResult = {
        new_flow_id: typedResult.stream_id,
        response_data: typedResult.response_bytes,
        response_size: typedResult.response_size,
        duration_ms: typedResult.duration_ms,
        tag: typedResult.tag,
      };
      setRawResponse(adapted);

      recordResendSuccess({
        id: typedResult.stream_id,
        protocol: flow?.protocol ?? "Raw",
        method: "RAW",
        url: rawTargetAddr.trim(),
        durationMs: typedResult.duration_ms,
        tag: tag || undefined,
        timestamp: new Date().toISOString(),
      });
      addToast({
        type: "success",
        message: `Raw resend complete (${typedResult.response_size ?? 0} bytes)`,
      });
    } catch (err) {
      addToast({
        type: "error",
        message: err instanceof Error ? err.message : "Raw resend failed",
      });
    } finally {
      setRawSending(false);
    }
  }, [
    activeFlowId,
    rawTargetAddr,
    rawUseTls,
    rawHttpText,
    tag,
    addToast,
    flow,
    client,
    recordResendSuccess,
  ]);

  /**
   * Send TCP resend_raw request via the typed `resend_raw` MCP tool.
   *
   * USK-938: the legacy fallback for dry-run / non-offset patches was
   * removed because the backend retired the `resend` action in PR #688
   * (USK-693). The typed tool only accepts offset-based patches with
   * byte-level base64 data; non-offset patches in the editor will be
   * coerced to `offset=0` (the same coercion the prior fast-path used).
   */
  const handleResendRaw = useCallback(async () => {
    if (!activeFlowId) {
      addToast({ type: "warning", message: "No flow selected" });
      return;
    }
    if (client == null) {
      addToast({ type: "error", message: "MCP client is not connected" });
      return;
    }
    if (!targetAddr.trim()) {
      addToast({ type: "warning", message: "Target address is required" });
      return;
    }

    setTcpResendRawSending(true);
    try {
      // USK-967: the previous `p.offset ?? 0` fallback silently coerced an
      // invalid offset (typically a NaN from a non-numeric editor input)
      // to 0, which writes the patch at a wholly different position than
      // the user intended — exactly the byte-level fuzz failure mode we
      // exist to avoid. The submit button is gated on `rawPatchesValid`,
      // so this path is unreachable when an offset row is invalid; the
      // throw acts as a defense-in-depth assertion against a future
      // regression in the validity wiring.
      const offsetPatches: ResendRawBytePatch[] = [];
      for (const p of rawPatches) {
        const mode =
          p.find_text != null || p.replace_text != null
            ? "find_replace_text"
            : p.find_base64 != null || p.replace_base64 != null
              ? "find_replace_hex"
              : "offset";
        if (mode === "offset") {
          if (
            p.offset == null ||
            !Number.isInteger(p.offset) ||
            p.offset < 0
          ) {
            throw new Error(
              "resend_raw: invalid offset reached submit; RawPatchEditor validity gate failed",
            );
          }
          offsetPatches.push({
            offset: p.offset,
            data: p.data_base64 ?? "",
            data_encoding: "base64",
          });
        }
        // Note: find/replace modes are not part of ResendRawParams.patches
        // (the typed schema is offset-only). They are preserved in state
        // for future use but skipped here — matching the prior behaviour.
      }
      const params: ResendRawParams = {
        flow_id: activeFlowId,
        target_addr: targetAddr.trim(),
        use_tls: useTls || undefined,
        patches: offsetPatches.length > 0 ? offsetPatches : undefined,
        tag: tag || undefined,
      };

      const typedResult: ResendRawTypedResult = await client.resendRaw(params);
      const adapted: TcpResendResult = {
        new_flow_id: typedResult.stream_id,
        response_data: typedResult.response_bytes,
        response_size: typedResult.response_size,
        duration_ms: typedResult.duration_ms,
        tag: typedResult.tag,
      };
      setTcpResponse(adapted);
      recordResendSuccess({
        id: typedResult.stream_id,
        protocol: flow?.protocol ?? "TCP",
        method: "RAW",
        url: targetAddr.trim(),
        durationMs: typedResult.duration_ms,
        tag: tag || undefined,
        timestamp: new Date().toISOString(),
      });
      addToast({
        type: "success",
        message: `Raw resend complete (${typedResult.response_size ?? 0} bytes)`,
      });
    } catch (err) {
      addToast({
        type: "error",
        message: err instanceof Error ? err.message : "Resend raw failed",
      });
    } finally {
      setTcpResendRawSending(false);
    }
  }, [
    activeFlowId,
    targetAddr,
    useTls,
    rawPatches,
    tag,
    addToast,
    flow,
    client,
    recordResendSuccess,
  ]);

  /**
   * Send a gRPC resend via the protocol-typed `resend_grpc` MCP tool.
   *
   * Builds a minimum-viable `ResendGRPCParams` from the editor state:
   * one text-mode request LPM, ordered metadata, and the target/scheme
   * pair. Proto-schemaless JSON edit, trailer_metadata edit, and
   * multi-message requests are deferred (see Issue body).
   */
  const handleGrpcSend = useCallback(async () => {
    if (!activeFlowId) {
      addToast({ type: "warning", message: "No flow selected" });
      return;
    }
    if (client == null) {
      addToast({
        type: "error",
        message: "MCP client is not connected",
      });
      return;
    }

    const params = buildResendGrpcParams(
      activeFlowId,
      grpcState,
      tag || undefined,
    );

    setGrpcSending(true);
    try {
      const result = await client.resendGrpc(params);
      setGrpcResponse(result);
      recordResendSuccess({
        id: result.stream_id,
        protocol: flow?.protocol ?? "gRPC",
        method: flow?.method ?? "POST",
        url: flow?.url ?? `${grpcState.service}/${grpcState.method}`,
        statusCode: result.end?.status,
        durationMs: result.duration_ms,
        tag: tag || undefined,
        timestamp: new Date().toISOString(),
      });
      const warnings = result.warnings ?? [];
      if (warnings.length > 0) {
        addToast({
          type: "warning",
          message: `Resend completed with ${warnings.length} warning${warnings.length === 1 ? "" : "s"}`,
        });
      } else {
        addToast({
          type: "success",
          message: `gRPC resend complete (status ${result.end?.status ?? "?"})`,
        });
      }
    } catch (err) {
      addToast({
        type: "error",
        message: err instanceof Error ? err.message : "gRPC resend failed",
      });
    } finally {
      setGrpcSending(false);
    }
  }, [
    activeFlowId,
    client,
    grpcState,
    tag,
    flow,
    addToast,
    recordResendSuccess,
  ]);

  /**
   * Send a WebSocket resend via the protocol-typed `resend_ws` MCP tool.
   *
   * `resend_ws` is single-frame by design — opcode + payload + fin (+
   * close metadata when applicable). Multi-frame replay is deferred.
   */
  const handleWsSend = useCallback(async () => {
    if (!activeFlowId) {
      addToast({ type: "warning", message: "No flow selected" });
      return;
    }
    if (client == null) {
      addToast({
        type: "error",
        message: "MCP client is not connected",
      });
      return;
    }

    const params = buildResendWsParams(
      activeFlowId,
      wsState,
      tag || undefined,
    );

    setWsSending(true);
    try {
      const result = await client.resendWs(params);
      setWsResponse(result);
      recordResendSuccess({
        id: result.stream_id,
        protocol: flow?.protocol ?? "WebSocket",
        method: result.opcode.toUpperCase(),
        url: flow?.url ?? wsState.path,
        durationMs: result.duration_ms,
        tag: tag || undefined,
        timestamp: new Date().toISOString(),
      });
      addToast({
        type: "success",
        message: `WebSocket resend complete (${result.opcode})`,
      });
    } catch (err) {
      addToast({
        type: "error",
        message: err instanceof Error ? err.message : "WebSocket resend failed",
      });
    } finally {
      setWsSending(false);
    }
  }, [
    activeFlowId,
    client,
    wsState,
    tag,
    flow,
    addToast,
    recordResendSuccess,
  ]);

  /**
   * Send TCP replay request via the typed `resend_raw` MCP tool.
   *
   * USK-938: the backend retired the `tcp_replay` resend action in
   * PR #688 (USK-693). The typed `resend_raw` tool with no
   * `override_bytes` / `patches` replays the recorded send-direction
   * bytes verbatim (see `internal/mcp/resend_raw.go:46-48`), which is
   * the exact semantic Replay All needs.
   *
   * UX narrowing (USK-938 D1): legacy `tcp_replay` was documented as
   * "all client (send) messages in sequence"; the typed tool is
   * single-payload verbatim replay. The Replay description copy in
   * the UI reflects this.
   */
  const handleTcpReplay = useCallback(async () => {
    if (!activeFlowId) {
      addToast({ type: "warning", message: "No flow selected" });
      return;
    }
    if (client == null) {
      addToast({ type: "error", message: "MCP client is not connected" });
      return;
    }
    if (!targetAddr.trim()) {
      addToast({ type: "warning", message: "Target address is required" });
      return;
    }

    const params = buildTcpReplayResendRawParams({
      flowId: activeFlowId,
      targetAddr: targetAddr.trim(),
      useTls,
      tag: tag || undefined,
    });

    setTcpReplaySending(true);
    try {
      const typedResult: ResendRawTypedResult = await client.resendRaw(params);
      const adapted: TcpResendResult = {
        new_flow_id: typedResult.stream_id,
        response_data: typedResult.response_bytes,
        response_size: typedResult.response_size,
        duration_ms: typedResult.duration_ms,
        tag: typedResult.tag,
      };
      setTcpResponse(adapted);

      recordResendSuccess({
        id: typedResult.stream_id,
        protocol: flow?.protocol ?? "TCP",
        method: "REPLAY",
        url: targetAddr.trim(),
        durationMs: typedResult.duration_ms,
        tag: tag || undefined,
        timestamp: new Date().toISOString(),
      });
      addToast({
        type: "success",
        message: `TCP replay complete (${typedResult.response_size ?? 0} bytes)`,
      });
    } catch (err) {
      addToast({
        type: "error",
        message: err instanceof Error ? err.message : "TCP replay failed",
      });
    } finally {
      setTcpReplaySending(false);
    }
  }, [
    activeFlowId,
    targetAddr,
    useTls,
    tag,
    addToast,
    flow,
    client,
    recordResendSuccess,
  ]);

  /** Whether the editor has a loaded flow. */
  const hasFlow = activeFlowId.length > 0 && flow != null;

  return (
    <div className="page resend-page">
      <div className="resend-header">
        <h1 className="page-title">Resend</h1>
        <p className="page-description">
          Edit and resend captured requests. Supports HTTP resend, raw HTTP editing, raw TCP byte patching, and TCP replay. Response comparison is suspended pending a backend follow-up.
        </p>
      </div>

      {/* Page mode tabs: Resend / Compare */}
      <Tabs
        tabs={PAGE_MODE_TABS}
        activeTab={pageMode}
        onTabChange={(id) => setPageMode(id as "resend" | "compare")}
        className="resend-page-mode-tabs"
      />

      {pageMode === "compare" && <ComparerView />}

      {pageMode === "resend" && (
        <>
          {/* Flow selector */}
      <div className="resend-flow-selector">
        <div className="resend-flow-input-row">
          <Input
            placeholder="Enter flow ID..."
            value={flowIdInput}
            onChange={(e) => setFlowIdInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleLoadFlow();
            }}
          />
          <Button variant="primary" onClick={handleLoadFlow} disabled={!flowIdInput.trim()}>
            Load
          </Button>
        </div>
        {flowLoading && (
          <div className="resend-loading">
            <Spinner size="sm" />
            <span>Loading flow...</span>
          </div>
        )}
        {flowError && (
          <div className="resend-error">
            Failed to load flow: {flowError.message}
          </div>
        )}
      </div>

      {hasFlow && !isTcp && !isGrpc && !isWs && (
        /* ============================================================
         * HTTP Mode
         * ============================================================ */
        <div className="resend-editor-layout">
          {/* Left: Request editor */}
          <div className="resend-panel resend-request-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">Request</span>
              <Badge variant="info">{activeFlowId.slice(0, 8)}</Badge>
              <Badge variant="default">{isH2 ? "HTTP/2" : "HTTP"}</Badge>
              {httpEditorMode === "raw" && (
                <Badge variant="warning">RAW</Badge>
              )}
            </div>

            {/* HTTP editor mode tabs: Structured / Raw */}
            <Tabs
              tabs={HTTP_MODE_TABS}
              activeTab={httpEditorMode}
              onTabChange={(id) => setHttpEditorMode(id as "structured" | "raw")}
              className="resend-http-mode-tabs"
            />

            {httpEditorMode === "structured" && (
              <>
                {/* Method + URL */}
                <div className="resend-method-url-row">
                  <select
                    className="resend-method-select"
                    value={method}
                    onChange={(e) => setMethod(e.target.value)}
                  >
                    {HTTP_METHODS.map((m) => (
                      <option key={m} value={m}>
                        {m}
                      </option>
                    ))}
                  </select>
                  <input
                    className="resend-url-input"
                    type="text"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    placeholder="https://example.com/api/endpoint"
                  />
                </div>

                {/* Tag input */}
                <div className="resend-tag-row">
                  <Input
                    placeholder="Tag (optional)"
                    value={tag}
                    onChange={(e) => setTag(e.target.value)}
                  />
                </div>

                {/* Request body tabs */}
                <Tabs
                  tabs={HTTP_REQUEST_TABS}
                  activeTab={requestTab}
                  onTabChange={setRequestTab}
                >
                  {requestTab === "headers" && (
                    <HeaderEditor headers={headers} onChange={setHeaders} />
                  )}
                  {requestTab === "body" && (
                    <div className="resend-body-editor">
                      <textarea
                        className="resend-body-textarea"
                        value={body}
                        onChange={(e) => setBody(e.target.value)}
                        placeholder="Request body..."
                        spellCheck={false}
                      />
                    </div>
                  )}
                  {requestTab === "patches" && (
                    <BodyPatchEditor patches={bodyPatches} onChange={setBodyPatches} />
                  )}
                </Tabs>

                {/* Hooks configuration (suspended — typed resend_http has no hooks support).
                  * Inputs visibly inert via pointer-events:none + opacity to keep the
                  * feature discoverable without sending unsupported fields. */}
                {availableMacros.length > 0 && (
                  <div className="resend-hooks-section">
                    <h4 className="resend-hooks-title">
                      Hooks (optional){" "}
                      <span
                        className="resend-suspended-note"
                        title={SUSPENDED_FIELD_TOOLTIP}
                      >
                        (suspended — follow-up planned)
                      </span>
                    </h4>
                    <div
                      style={{ pointerEvents: "none", opacity: 0.5 }}
                      title={SUSPENDED_FIELD_TOOLTIP}
                    >
                      <HookConfigEditor
                        macros={availableMacros}
                        hooks={hooks}
                        onChange={setHooks}
                      />
                    </div>
                  </div>
                )}

                {/* Action buttons */}
                <div className="resend-actions">
                  <Button
                    variant="primary"
                    onClick={() => handleHttpSend()}
                    disabled={httpSending}
                  >
                    {httpSending ? "Sending..." : "Send"}
                  </Button>
                  <label
                    className="resend-dryrun-toggle"
                    title={SUSPENDED_FIELD_TOOLTIP}
                  >
                    <input
                      type="checkbox"
                      checked={dryRun}
                      onChange={(e) => setDryRun(e.target.checked)}
                      disabled
                    />
                    <span>Default dry-run (suspended)</span>
                  </label>
                </div>
              </>
            )}

            {httpEditorMode === "raw" && (
              <>
                {/* Downgrade notice for HTTP/2 */}
                {isH2 && (
                  <div className="resend-raw-downgrade-notice">
                    This HTTP/2 request has been reconstructed as HTTP/1.1 for raw editing.
                    Header casing and order may differ from the original HTTP/2 pseudo-headers.
                  </div>
                )}

                {/* Target address + TLS for raw mode */}
                <div className="resend-tcp-target-row">
                  <input
                    className="resend-url-input"
                    type="text"
                    value={rawTargetAddr}
                    onChange={(e) => setRawTargetAddr(e.target.value)}
                    placeholder="host:port (e.g. example.com:443)"
                  />
                  <label className="resend-tls-toggle">
                    <input
                      type="checkbox"
                      checked={rawUseTls}
                      onChange={(e) => setRawUseTls(e.target.checked)}
                    />
                    <span>TLS</span>
                  </label>
                </div>

                {/* Tag input */}
                <div className="resend-tag-row">
                  <Input
                    placeholder="Tag (optional)"
                    value={tag}
                    onChange={(e) => setTag(e.target.value)}
                  />
                </div>

                {/* Raw HTTP text editor */}
                <div className="resend-raw-editor">
                  <textarea
                    className="resend-raw-textarea"
                    value={rawHttpText}
                    onChange={(e) => setRawHttpText(e.target.value)}
                    placeholder={"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"}
                    spellCheck={false}
                  />
                </div>

                {/* Hooks configuration (suspended — typed resend_raw has no hooks support). */}
                {availableMacros.length > 0 && (
                  <div className="resend-hooks-section">
                    <h4 className="resend-hooks-title">
                      Hooks (optional){" "}
                      <span
                        className="resend-suspended-note"
                        title={SUSPENDED_FIELD_TOOLTIP}
                      >
                        (suspended — follow-up planned)
                      </span>
                    </h4>
                    <div
                      style={{ pointerEvents: "none", opacity: 0.5 }}
                      title={SUSPENDED_FIELD_TOOLTIP}
                    >
                      <HookConfigEditor
                        macros={availableMacros}
                        hooks={hooks}
                        onChange={setHooks}
                      />
                    </div>
                  </div>
                )}

                {/* Raw mode action buttons */}
                <div className="resend-actions">
                  <Button
                    variant="primary"
                    onClick={() => handleHttpRawSend()}
                    disabled={rawSending || !rawTargetAddr.trim()}
                  >
                    {rawSending ? "Sending..." : "Send Raw"}
                  </Button>
                  <label
                    className="resend-dryrun-toggle"
                    title={SUSPENDED_FIELD_TOOLTIP}
                  >
                    <input
                      type="checkbox"
                      checked={dryRun}
                      onChange={(e) => setDryRun(e.target.checked)}
                      disabled
                    />
                    <span>Default dry-run (suspended)</span>
                  </label>
                </div>
              </>
            )}
          </div>

          {/* Right: Response viewer */}
          <div className="resend-panel resend-response-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">Response</span>
              {httpEditorMode === "structured" && (
                <>
                  {httpResponse?.response_status_code != null && (
                    <Badge
                      variant={
                        httpResponse.response_status_code < 300
                          ? "success"
                          : httpResponse.response_status_code < 400
                            ? "info"
                            : httpResponse.response_status_code < 500
                              ? "warning"
                              : "danger"
                      }
                    >
                      {httpResponse.response_status_code}
                    </Badge>
                  )}
                  {httpResponse?.duration_ms != null && (
                    <span className="resend-duration">{httpResponse.duration_ms}ms</span>
                  )}
                </>
              )}
              {httpEditorMode === "raw" && (
                <>
                  {rawResponse?.response_size != null && (
                    <Badge variant="info">
                      {rawResponse.response_size} bytes
                    </Badge>
                  )}
                  {rawResponse?.duration_ms != null && (
                    <span className="resend-duration">{rawResponse.duration_ms}ms</span>
                  )}
                </>
              )}
            </div>

            {(httpEditorMode === "structured" ? httpSending : rawSending) ? (
              <div className="resend-loading">
                <Spinner size="sm" />
                <span>Sending request...</span>
              </div>
            ) : httpEditorMode === "structured" ? (
              httpResponse ? (
                <ResponseViewer
                  response={httpResponse}
                  originalFlow={flow}
                />
              ) : (
                <div className="resend-empty-response">
                  Send a request to see the response here.
                </div>
              )
            ) : rawResponse ? (
              <TcpResponseViewer response={rawResponse} />
            ) : (
              <div className="resend-empty-response">
                Send a raw request to see the response here.
              </div>
            )}
          </div>
        </div>
      )}

      {hasFlow && isGrpc && (
        /* ============================================================
         * gRPC Mode (USK-936)
         * ============================================================ */
        <div className="resend-editor-layout">
          {/* Left: gRPC Request editor */}
          <div className="resend-panel resend-request-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">gRPC Request</span>
              <Badge variant="info">{activeFlowId.slice(0, 8)}</Badge>
              <Badge variant="default">{flow?.protocol ?? "gRPC"}</Badge>
            </div>

            <div className="resend-tag-row">
              <Input
                placeholder="Tag (optional)"
                value={tag}
                onChange={(e) => setTag(e.target.value)}
              />
            </div>

            <GrpcRequestEditor state={grpcState} onChange={setGrpcState} />

            <div className="resend-actions">
              <Button
                variant="primary"
                onClick={handleGrpcSend}
                disabled={grpcSending}
              >
                {grpcSending ? "Sending..." : "Send"}
              </Button>
            </div>
          </div>

          {/* Right: gRPC Response viewer */}
          <div className="resend-panel resend-response-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">Response</span>
              {grpcResponse?.end?.status != null && (
                <Badge
                  variant={
                    grpcResponse.end.status === 0 ? "success" : "danger"
                  }
                >
                  status {grpcResponse.end.status}
                </Badge>
              )}
              {grpcResponse?.warnings && grpcResponse.warnings.length > 0 && (
                <Badge variant="warning">
                  {grpcResponse.warnings.length} warning
                  {grpcResponse.warnings.length === 1 ? "" : "s"}
                </Badge>
              )}
              {grpcResponse?.duration_ms != null && (
                <span className="resend-duration">
                  {grpcResponse.duration_ms}ms
                </span>
              )}
            </div>

            {grpcSending ? (
              <div className="resend-loading">
                <Spinner size="sm" />
                <span>Sending request...</span>
              </div>
            ) : grpcResponse ? (
              <GrpcResponseViewer response={grpcResponse} />
            ) : (
              <div className="resend-empty-response">
                Send a request to see the response here.
              </div>
            )}
          </div>
        </div>
      )}

      {hasFlow && isWs && (
        /* ============================================================
         * WebSocket Mode (USK-936)
         * ============================================================ */
        <div className="resend-editor-layout">
          {/* Left: WebSocket Request editor */}
          <div className="resend-panel resend-request-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">WebSocket Frame</span>
              <Badge variant="info">{activeFlowId.slice(0, 8)}</Badge>
              <Badge variant="default">WebSocket</Badge>
            </div>

            <div className="resend-tag-row">
              <Input
                placeholder="Tag (optional)"
                value={tag}
                onChange={(e) => setTag(e.target.value)}
              />
            </div>

            <WsRequestEditor state={wsState} onChange={setWsState} />

            <div className="resend-actions">
              <Button
                variant="primary"
                onClick={handleWsSend}
                disabled={wsSending}
              >
                {wsSending ? "Sending..." : "Send"}
              </Button>
            </div>
          </div>

          {/* Right: WebSocket Response viewer */}
          <div className="resend-panel resend-response-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">Response</span>
              {wsResponse?.opcode && (
                <Badge variant="info">{wsResponse.opcode}</Badge>
              )}
              {wsResponse?.duration_ms != null && (
                <span className="resend-duration">
                  {wsResponse.duration_ms}ms
                </span>
              )}
            </div>

            {wsSending ? (
              <div className="resend-loading">
                <Spinner size="sm" />
                <span>Sending frame...</span>
              </div>
            ) : wsResponse ? (
              <WsResponseViewer response={wsResponse} />
            ) : (
              <div className="resend-empty-response">
                Send a frame to see the response here.
              </div>
            )}
          </div>
        </div>
      )}

      {hasFlow && isTcp && (
        /* ============================================================
         * TCP Mode
         * ============================================================ */
        <div className="resend-editor-layout">
          {/* Left: TCP Request editor */}
          <div className="resend-panel resend-request-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">TCP Request</span>
              <Badge variant="info">{activeFlowId.slice(0, 8)}</Badge>
              <Badge variant="warning">TCP</Badge>
            </div>

            {/* TCP mode selector */}
            <Tabs
              tabs={TCP_MODE_TABS}
              activeTab={tcpMode}
              onTabChange={(id) => setTcpMode(id as "resend_raw" | "tcp_replay")}
              className="resend-tcp-mode-tabs"
            />

            {/* Target address + TLS */}
            <div className="resend-tcp-target-row">
              <input
                className="resend-url-input"
                type="text"
                value={targetAddr}
                onChange={(e) => setTargetAddr(e.target.value)}
                placeholder="host:port (e.g. 192.168.1.10:3306)"
              />
              <label className="resend-tls-toggle">
                <input
                  type="checkbox"
                  checked={useTls}
                  onChange={(e) => setUseTls(e.target.checked)}
                />
                <span>TLS</span>
              </label>
            </div>

            {/* Tag input */}
            <div className="resend-tag-row">
              <Input
                placeholder="Tag (optional)"
                value={tag}
                onChange={(e) => setTag(e.target.value)}
              />
            </div>

            {/* TCP content tabs */}
            {tcpMode === "resend_raw" && (
              <Tabs
                tabs={TCP_REQUEST_TABS}
                activeTab={tcpRequestTab}
                onTabChange={setTcpRequestTab}
              >
                {tcpRequestTab === "messages" && (
                  <TcpMessageList messages={tcpMessages} />
                )}
                {tcpRequestTab === "raw_patches" && (
                  <RawPatchEditor
                    patches={rawPatches}
                    onChange={setRawPatches}
                    onValidityChange={setRawPatchesValid}
                  />
                )}
              </Tabs>
            )}

            {tcpMode === "tcp_replay" && (
              <div className="resend-tcp-replay-info">
                <TcpMessageList messages={tcpMessages} />
                <div className="resend-tcp-replay-description">
                  Resends the recorded send-direction bytes verbatim to the
                  target address. Single-payload (the typed{" "}
                  <code>resend_raw</code> tool is not multi-frame); see the
                  follow-up Issue for multi-message replay.
                </div>
              </div>
            )}

            {/* TCP Action buttons */}
            <div className="resend-actions">
              {tcpMode === "resend_raw" ? (
                <>
                  <Button
                    variant="primary"
                    onClick={() => handleResendRaw()}
                    disabled={
                      tcpResendRawSending ||
                      !targetAddr.trim() ||
                      !rawPatchesValid
                    }
                    title={
                      !rawPatchesValid
                        ? "Fix raw patch validation errors before sending"
                        : undefined
                    }
                  >
                    {tcpResendRawSending ? "Sending..." : "Send Raw"}
                  </Button>
                  <label
                    className="resend-dryrun-toggle"
                    title={SUSPENDED_FIELD_TOOLTIP}
                  >
                    <input
                      type="checkbox"
                      checked={dryRun}
                      onChange={(e) => setDryRun(e.target.checked)}
                      disabled
                    />
                    <span>Default dry-run (suspended)</span>
                  </label>
                </>
              ) : (
                <Button
                  variant="primary"
                  onClick={handleTcpReplay}
                  disabled={tcpReplaySending || !targetAddr.trim()}
                >
                  {tcpReplaySending ? "Replaying..." : "Replay All"}
                </Button>
              )}
            </div>
          </div>

          {/* Right: TCP Response viewer */}
          <div className="resend-panel resend-response-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">Response</span>
              {tcpResponse?.response_size != null && (
                <Badge variant="info">
                  {tcpResponse.response_size} bytes
                </Badge>
              )}
              {tcpResponse?.duration_ms != null && (
                <span className="resend-duration">{tcpResponse.duration_ms}ms</span>
              )}
            </div>

            {(tcpMode === "tcp_replay" ? tcpReplaySending : tcpResendRawSending) ? (
              <div className="resend-loading">
                <Spinner size="sm" />
                <span>{tcpMode === "tcp_replay" ? "Replaying..." : "Sending raw data..."}</span>
              </div>
            ) : tcpResponse ? (
              <TcpResponseViewer response={tcpResponse} />
            ) : (
              <div className="resend-empty-response">
                {tcpMode === "tcp_replay"
                  ? "Click Replay All to re-send all TCP messages."
                  : "Send raw data to see the response here."}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Send History — server-driven (USK-787).
        *
        * Backed by `query("flows", { filter: { origin: "resend" }, limit, offset })`
        * so the list survives browser reload. Optimistic prepend covers the
        * gap between resend completion and the next refetch. Each row navigates
        * to the corresponding Stream detail page (`/flows/:id`).
        */}
      <div className="resend-history">
        <div className="resend-history-header-row">
          <h3 className="resend-history-title">Send History</h3>
          {historyLoading && historyOffset === 0 && (
            <Spinner size="sm" />
          )}
        </div>
        {historyError && (
          <div className="resend-error">
            Failed to load history: {historyError.message}
          </div>
        )}
        {displayedHistory.length === 0 && !historyLoading && !historyError && (
          <div className="resend-empty-response">
            No resend history yet. Submit a resend to see it appear here.
          </div>
        )}
        {displayedHistory.length > 0 && (
          <div className="resend-history-list">
            {displayedHistory.map((entry) => (
              <button
                key={entry.id}
                type="button"
                className="resend-history-entry resend-history-entry--clickable"
                onClick={() => navigate(`/flows/${entry.id}`)}
                title={`Open Stream ${entry.id}`}
              >
                <Badge variant={statusBadgeVariant(entry.statusCode)}>
                  {entry.statusCode != null && entry.statusCode > 0
                    ? entry.statusCode
                    : "---"}
                </Badge>
                <Badge variant="default">{entry.protocol}</Badge>
                <span className="resend-history-method">{entry.method}</span>
                <span className="resend-history-url">{entry.url}</span>
                {entry.tag && <Badge variant="info">{entry.tag}</Badge>}
                {entry.durationMs != null && (
                  <span className="resend-history-duration">
                    {entry.durationMs}ms
                  </span>
                )}
                <span className="resend-history-time">
                  {new Date(entry.timestamp).toLocaleTimeString()}
                </span>
              </button>
            ))}
          </div>
        )}
        {(historyHasPrev || historyHasNext) && (
          <div className="resend-history-pagination">
            <Button
              variant="ghost"
              size="sm"
              disabled={!historyHasPrev}
              onClick={() => goToHistoryPage(historyOffset - HISTORY_PAGE_SIZE)}
            >
              Prev
            </Button>
            <span className="resend-history-pagination-info">
              {historyTotal > 0
                ? `${historyOffset + 1}–${Math.min(
                    historyOffset + HISTORY_PAGE_SIZE,
                    historyTotal,
                  )} of ${historyTotal}`
                : "0"}
            </span>
            <Button
              variant="ghost"
              size="sm"
              disabled={!historyHasNext}
              onClick={() => goToHistoryPage(historyOffset + HISTORY_PAGE_SIZE)}
            >
              Next
            </Button>
          </div>
        )}
      </div>
        </>
      )}
    </div>
  );
}
