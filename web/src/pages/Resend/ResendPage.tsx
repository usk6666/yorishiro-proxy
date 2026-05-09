import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Input } from "../../components/ui/Input.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Tabs } from "../../components/ui/Tabs.js";
import { useToast } from "../../components/ui/Toast.js";
import { useMcpContext } from "../../lib/mcp/context.js";
import { pickResendTool } from "../../lib/mcp/dispatch.js";
import { useResend, useQuery } from "../../lib/mcp/hooks.js";
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
  ResendHTTPParams,
  ResendHTTPResult,
  ResendRawParams,
  ResendRawTypedResult,
} from "../../lib/mcp/types.js";
import { HookConfigEditor } from "../../components/hooks/HookConfigEditor.js";
import { BodyPatchEditor } from "./BodyPatchEditor.js";
import { ComparerView } from "./ComparerView.js";
import { HeaderEditor } from "./HeaderEditor.js";
import { RawPatchEditor } from "./RawPatchEditor.js";
import "./ResendPage.css";
import { ResponseViewer } from "./ResponseViewer.js";
import { TcpMessageList } from "./TcpMessageList.js";
import type { TcpResendResult } from "./TcpResponseViewer.js";
import { TcpResponseViewer } from "./TcpResponseViewer.js";

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

/** Resend result from MCP resend tool. */
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
  dry_run?: boolean;
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
  const { resend, loading: executing } = useResend();
  const { client } = useMcpContext();

  // Use the RFC-001 N8 protocol-typed resend tools (resend_http / resend_ws /
  // resend_grpc / resend_raw) when the flow protocol is recognized. Defaults
  // to true; users can flip to "force legacy" via the toggle in the action bar.
  const [useTypedTools, setUseTypedTools] = useState(true);

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
  const [tcpMode, setTcpMode] = useState<"resend_raw" | "tcp_replay">("resend_raw");

  // Shared state.
  const [tag, setTag] = useState("");
  const [dryRun, setDryRun] = useState(false);

  // Hooks state.
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

    if (isTcpFlow(flow)) {
      // TCP flow: populate target address from connection info.
      setTargetAddr(flow.conn_info?.server_addr ?? "");
      setUseTls(!!flow.conn_info?.tls_version);
      setRawPatches([]);
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

  /** Send HTTP resend request (structured mode). */
  const handleHttpSend = useCallback(
    async (isDryRun: boolean) => {
      if (!activeFlowId) {
        addToast({ type: "warning", message: "No flow selected" });
        return;
      }

      // Build override_headers from the key-value pairs as array format.
      // Array format supports duplicate keys (e.g., multiple Host headers).
      const overrideHeaders = headers
        .filter((h) => h.key.trim() !== "")
        .map((h) => ({ key: h.key.trim(), value: h.value }));

      // Build hooks param if any hook is configured.
      const hooksParam =
        hooks.pre_send || hooks.post_receive ? hooks : undefined;

      // Decide the dispatch: protocol-typed resend_http when (a) the toggle is
      // on, (b) the flow protocol resolves to resend_http, (c) no hooks are
      // configured (the new tool ignores them; legacy still honours hooks),
      // and (d) we're not in dry-run mode (the new tool has no dry_run flag).
      const toolName =
        flow != null ? pickResendTool(flow.protocol) : "resend";
      const canUseTyped =
        useTypedTools &&
        toolName === "resend_http" &&
        client != null &&
        !isDryRun &&
        !hooksParam;

      try {
        if (canUseTyped) {
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
          const typedResult: ResendHTTPResult = await client!.resendHttp(
            params,
          );

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
            protocol: flow?.protocol ?? "HTTP",
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
          return;
        }

        const result = await resend<ResendResult>({
          action: "resend",
          params: {
            flow_id: activeFlowId,
            override_method: method,
            override_url: url,
            override_headers: overrideHeaders.length > 0 ? overrideHeaders : undefined,
            override_body: body || undefined,
            body_patches: bodyPatches.length > 0 ? bodyPatches : undefined,
            dry_run: isDryRun,
            tag: tag || undefined,
            hooks: hooksParam,
          },
        });

        setHttpResponse(result);

        // Dry-run requests don't create a server-side Stream record, so the
        // optimistic row would never reconcile with a server entry. Skip
        // recording in dry-run mode (USK-787 explicitly drops dry-run from
        // history; the response panel still shows the preview).
        if (!isDryRun && result.new_flow_id) {
          recordResendSuccess({
            id: result.new_flow_id,
            protocol: flow?.protocol ?? "HTTP",
            method,
            url,
            statusCode: result.response_status_code,
            durationMs: result.duration_ms,
            tag: tag || undefined,
            timestamp: new Date().toISOString(),
          });
        }

        addToast({
          type: "success",
          message: isDryRun
            ? "Dry-run preview generated"
            : `Request sent (${result.response_status_code ?? "?"})`,
        });
      } catch (err) {
        addToast({
          type: "error",
          message: err instanceof Error ? err.message : "Resend failed",
        });
      }
    },
    [
      activeFlowId,
      method,
      url,
      headers,
      body,
      bodyPatches,
      tag,
      hooks,
      resend,
      addToast,
      flow,
      client,
      useTypedTools,
      recordResendSuccess,
    ],
  );

  /** Send HTTP raw resend request (raw mode). */
  const handleHttpRawSend = useCallback(
    async (isDryRun: boolean) => {
      if (!activeFlowId) {
        addToast({ type: "warning", message: "No flow selected" });
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

      try {
        const rawBase64 = stringToBase64(rawHttpText);

        // Build hooks param if any hook is configured.
        const hooksParam =
          hooks.pre_send || hooks.post_receive ? hooks : undefined;

        const result = await resend<TcpResendResult>({
          action: "resend_raw",
          params: {
            flow_id: activeFlowId,
            target_addr: rawTargetAddr.trim(),
            use_tls: rawUseTls || undefined,
            override_raw_base64: rawBase64,
            dry_run: isDryRun,
            tag: tag || undefined,
            hooks: hooksParam,
          },
        });

        setRawResponse(result);

        if (!isDryRun && result.new_flow_id) {
          recordResendSuccess({
            id: result.new_flow_id,
            protocol: flow?.protocol ?? "Raw",
            method: "RAW",
            url: rawTargetAddr.trim(),
            durationMs: result.duration_ms,
            tag: tag || undefined,
            timestamp: new Date().toISOString(),
          });
        }

        addToast({
          type: "success",
          message: isDryRun
            ? "Dry-run preview generated"
            : `Raw resend complete (${result.response_size ?? 0} bytes)`,
        });
      } catch (err) {
        addToast({
          type: "error",
          message: err instanceof Error ? err.message : "Raw resend failed",
        });
      }
    },
    [
      activeFlowId,
      rawTargetAddr,
      rawUseTls,
      rawHttpText,
      tag,
      hooks,
      resend,
      addToast,
      flow,
      recordResendSuccess,
    ],
  );

  /** Send TCP resend_raw request. */
  const handleResendRaw = useCallback(
    async (isDryRun: boolean) => {
      if (!activeFlowId) {
        addToast({ type: "warning", message: "No flow selected" });
        return;
      }
      if (!targetAddr.trim()) {
        addToast({ type: "warning", message: "Target address is required" });
        return;
      }

      // Dispatch to the protocol-typed resend_raw tool when applicable.
      // The typed tool only supports offset-based patches with byte-level data
      // (no regex/find-replace), so legacy stays the path for those modes
      // and for dry-run / hooks (the typed tool exposes neither).
      const toolName =
        flow != null ? pickResendTool(flow.protocol) : "resend";
      const patchesAreOffsetOnly = rawPatches.every(
        (p) => p.offset != null && p.data_base64 != null,
      );
      const canUseTyped =
        useTypedTools &&
        toolName === "resend_raw" &&
        client != null &&
        !isDryRun &&
        patchesAreOffsetOnly;

      try {
        if (canUseTyped) {
          const params: ResendRawParams = {
            flow_id: activeFlowId,
            target_addr: targetAddr.trim(),
            use_tls: useTls || undefined,
            patches:
              rawPatches.length > 0
                ? rawPatches.map((p) => ({
                    offset: p.offset ?? 0,
                    data: p.data_base64 ?? "",
                    data_encoding: "base64",
                  }))
                : undefined,
            tag: tag || undefined,
          };
          const typedResult: ResendRawTypedResult = await client!.resendRaw(
            params,
          );
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
          return;
        }

        const result = await resend<TcpResendResult>({
          action: "resend_raw",
          params: {
            flow_id: activeFlowId,
            target_addr: targetAddr.trim(),
            use_tls: useTls || undefined,
            patches: rawPatches.length > 0 ? rawPatches : undefined,
            dry_run: isDryRun,
            tag: tag || undefined,
          },
        });

        setTcpResponse(result);

        if (!isDryRun && result.new_flow_id) {
          recordResendSuccess({
            id: result.new_flow_id,
            protocol: flow?.protocol ?? "TCP",
            method: "RAW",
            url: targetAddr.trim(),
            durationMs: result.duration_ms,
            tag: tag || undefined,
            timestamp: new Date().toISOString(),
          });
        }

        addToast({
          type: "success",
          message: isDryRun
            ? "Dry-run preview generated"
            : `Raw resend complete (${result.response_size ?? 0} bytes)`,
        });
      } catch (err) {
        addToast({
          type: "error",
          message: err instanceof Error ? err.message : "Resend raw failed",
        });
      }
    },
    [
      activeFlowId,
      targetAddr,
      useTls,
      rawPatches,
      tag,
      resend,
      addToast,
      flow,
      client,
      useTypedTools,
      recordResendSuccess,
    ],
  );

  /** Send TCP replay request. */
  const handleTcpReplay = useCallback(async () => {
    if (!activeFlowId) {
      addToast({ type: "warning", message: "No flow selected" });
      return;
    }
    if (!targetAddr.trim()) {
      addToast({ type: "warning", message: "Target address is required" });
      return;
    }

    try {
      const result = await resend<TcpResendResult>({
        action: "tcp_replay",
        params: {
          flow_id: activeFlowId,
          target_addr: targetAddr.trim(),
          use_tls: useTls || undefined,
          tag: tag || undefined,
        },
      });

      setTcpResponse(result);

      if (result.new_flow_id) {
        recordResendSuccess({
          id: result.new_flow_id,
          protocol: flow?.protocol ?? "TCP",
          method: "REPLAY",
          url: targetAddr.trim(),
          durationMs: result.duration_ms,
          tag: tag || undefined,
          timestamp: new Date().toISOString(),
        });
      }

      addToast({
        type: "success",
        message: `TCP replay complete (${result.response_size ?? 0} bytes)`,
      });
    } catch (err) {
      addToast({
        type: "error",
        message: err instanceof Error ? err.message : "TCP replay failed",
      });
    }
  }, [
    activeFlowId,
    targetAddr,
    useTls,
    tag,
    resend,
    addToast,
    flow,
    recordResendSuccess,
  ]);

  /** Whether the editor has a loaded flow. */
  const hasFlow = activeFlowId.length > 0 && flow != null;

  return (
    <div className="page resend-page">
      <div className="resend-header">
        <h1 className="page-title">Resend</h1>
        <p className="page-description">
          Edit and resend captured requests. Supports HTTP resend, raw HTTP editing, raw TCP byte patching, TCP replay, and response comparison.
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

      {hasFlow && !isTcp && (
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

                {/* Hooks configuration */}
                {availableMacros.length > 0 && (
                  <div className="resend-hooks-section">
                    <h4 className="resend-hooks-title">Hooks (optional)</h4>
                    <HookConfigEditor
                      macros={availableMacros}
                      hooks={hooks}
                      onChange={setHooks}
                    />
                    {hooks.pre_send?.macro && (
                      <p className="resend-hooks-help">
                        Use <code>{"\u00A7key\u00A7"}</code> syntax in URL, headers, and body fields to reference KV Store values set by the pre-send macro.
                        Encoder chains are supported: <code>{"\u00A7key | url_encode\u00A7"}</code>, <code>{"\u00A7key | base64\u00A7"}</code>.
                      </p>
                    )}
                  </div>
                )}

                {/* Action buttons */}
                <div className="resend-actions">
                  <Button
                    variant="primary"
                    onClick={() => handleHttpSend(dryRun)}
                    disabled={executing}
                  >
                    {executing ? "Sending..." : dryRun ? "Send (Dry Run)" : "Send"}
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => handleHttpSend(true)}
                    disabled={executing}
                  >
                    Dry Run
                  </Button>
                  <label className="resend-dryrun-toggle">
                    <input
                      type="checkbox"
                      checked={dryRun}
                      onChange={(e) => setDryRun(e.target.checked)}
                    />
                    <span>Default dry-run</span>
                  </label>
                  <label
                    className="resend-dryrun-toggle"
                    title="When on, recognized protocols dispatch to resend_http / resend_ws / resend_grpc / resend_raw. Disable to force the legacy 'resend' tool."
                  >
                    <input
                      type="checkbox"
                      checked={useTypedTools}
                      onChange={(e) => setUseTypedTools(e.target.checked)}
                    />
                    <span>Use typed tools</span>
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

                {/* Hooks configuration */}
                {availableMacros.length > 0 && (
                  <div className="resend-hooks-section">
                    <h4 className="resend-hooks-title">Hooks (optional)</h4>
                    <HookConfigEditor
                      macros={availableMacros}
                      hooks={hooks}
                      onChange={setHooks}
                    />
                    {hooks.pre_send?.macro && (
                      <p className="resend-hooks-help">
                        Note: In Raw mode, <code>{"\u00A7key\u00A7"}</code> template expansion is not applied to raw bytes. Use Structured mode for template-based value injection. Hooks (pre-send / post-receive) are still executed.
                      </p>
                    )}
                  </div>
                )}

                {/* Raw mode action buttons */}
                <div className="resend-actions">
                  <Button
                    variant="primary"
                    onClick={() => handleHttpRawSend(dryRun)}
                    disabled={executing || !rawTargetAddr.trim()}
                  >
                    {executing ? "Sending..." : dryRun ? "Send Raw (Dry Run)" : "Send Raw"}
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => handleHttpRawSend(true)}
                    disabled={executing || !rawTargetAddr.trim()}
                  >
                    Dry Run
                  </Button>
                  <label className="resend-dryrun-toggle">
                    <input
                      type="checkbox"
                      checked={dryRun}
                      onChange={(e) => setDryRun(e.target.checked)}
                    />
                    <span>Default dry-run</span>
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
                  {httpResponse?.dry_run && <Badge variant="warning">DRY RUN</Badge>}
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
                  {rawResponse?.dry_run && <Badge variant="warning">DRY RUN</Badge>}
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

            {executing ? (
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
                  <RawPatchEditor patches={rawPatches} onChange={setRawPatches} />
                )}
              </Tabs>
            )}

            {tcpMode === "tcp_replay" && (
              <div className="resend-tcp-replay-info">
                <TcpMessageList messages={tcpMessages} />
                <div className="resend-tcp-replay-description">
                  TCP Replay re-sends all client (send) messages in sequence
                  to the target address. No patching is applied.
                </div>
              </div>
            )}

            {/* TCP Action buttons */}
            <div className="resend-actions">
              {tcpMode === "resend_raw" ? (
                <>
                  <Button
                    variant="primary"
                    onClick={() => handleResendRaw(dryRun)}
                    disabled={executing || !targetAddr.trim()}
                  >
                    {executing ? "Sending..." : dryRun ? "Send Raw (Dry Run)" : "Send Raw"}
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() => handleResendRaw(true)}
                    disabled={executing || !targetAddr.trim()}
                  >
                    Dry Run
                  </Button>
                  <label className="resend-dryrun-toggle">
                    <input
                      type="checkbox"
                      checked={dryRun}
                      onChange={(e) => setDryRun(e.target.checked)}
                    />
                    <span>Default dry-run</span>
                  </label>
                  <label
                    className="resend-dryrun-toggle"
                    title="When on, recognized protocols dispatch to resend_http / resend_ws / resend_grpc / resend_raw. Disable to force the legacy 'resend' tool."
                  >
                    <input
                      type="checkbox"
                      checked={useTypedTools}
                      onChange={(e) => setUseTypedTools(e.target.checked)}
                    />
                    <span>Use typed tools</span>
                  </label>
                </>
              ) : (
                <Button
                  variant="primary"
                  onClick={handleTcpReplay}
                  disabled={executing || !targetAddr.trim()}
                >
                  {executing ? "Replaying..." : "Replay All"}
                </Button>
              )}
            </div>
          </div>

          {/* Right: TCP Response viewer */}
          <div className="resend-panel resend-response-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">Response</span>
              {tcpResponse?.dry_run && <Badge variant="warning">DRY RUN</Badge>}
              {tcpResponse?.response_size != null && (
                <Badge variant="info">
                  {tcpResponse.response_size} bytes
                </Badge>
              )}
              {tcpResponse?.duration_ms != null && (
                <span className="resend-duration">{tcpResponse.duration_ms}ms</span>
              )}
            </div>

            {executing ? (
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
