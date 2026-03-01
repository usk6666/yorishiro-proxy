import { useState, useCallback, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useExecute } from "../../lib/mcp/hooks.js";
import type {
  SessionDetailResult,
  BodyPatch,
} from "../../lib/mcp/types.js";
import { Button } from "../../components/ui/Button.js";
import { Input } from "../../components/ui/Input.js";
import { Badge } from "../../components/ui/Badge.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Tabs } from "../../components/ui/Tabs.js";
import { useToast } from "../../components/ui/Toast.js";
import { HeaderEditor } from "./HeaderEditor.js";
import { BodyPatchEditor } from "./BodyPatchEditor.js";
import { ResponseViewer } from "./ResponseViewer.js";
import "./ResendPage.css";

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

/** Tabs for the request editor panel. */
const REQUEST_TABS = [
  { id: "headers", label: "Headers" },
  { id: "body", label: "Body" },
  { id: "patches", label: "Body Patches" },
];

/** Resend result from MCP execute. */
export interface ResendResult {
  session_id?: string;
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

/** A history entry for resends. */
interface HistoryEntry {
  timestamp: string;
  method: string;
  url: string;
  statusCode?: number;
  durationMs?: number;
  dryRun: boolean;
  tag: string;
  sessionId?: string;
}

export function ResendPage() {
  const { sessionId: routeSessionId } = useParams<{ sessionId: string }>();
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { execute, loading: executing } = useExecute();

  // Session ID input state.
  const [sessionIdInput, setSessionIdInput] = useState(routeSessionId ?? "");
  const [activeSessionId, setActiveSessionId] = useState(routeSessionId ?? "");

  // Request editor state.
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("");
  const [headers, setHeaders] = useState<Array<{ key: string; value: string }>>([]);
  const [body, setBody] = useState("");
  const [bodyPatches, setBodyPatches] = useState<BodyPatch[]>([]);
  const [tag, setTag] = useState("");
  const [dryRun, setDryRun] = useState(false);

  // UI state.
  const [requestTab, setRequestTab] = useState("headers");
  const [response, setResponse] = useState<ResendResult | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  // Fetch original session data when activeSessionId changes.
  const {
    data: sessionData,
    loading: sessionLoading,
    error: sessionError,
  } = useQuery("session", {
    id: activeSessionId,
    enabled: activeSessionId.length > 0,
  });

  // Populate editor with session data when loaded.
  useEffect(() => {
    if (!sessionData) return;
    const session = sessionData as SessionDetailResult;
    setMethod(session.method || "GET");
    setUrl(session.url || "");
    setBody(session.request_body || "");
    setBodyPatches([]);
    setTag("");
    setResponse(null);

    // Convert headers from Record<string, string[]> to key-value pairs.
    const headerPairs: Array<{ key: string; value: string }> = [];
    if (session.request_headers) {
      for (const [key, values] of Object.entries(session.request_headers)) {
        for (const value of values) {
          headerPairs.push({ key, value });
        }
      }
    }
    setHeaders(headerPairs);
  }, [sessionData]);

  // Sync route param changes.
  useEffect(() => {
    if (routeSessionId && routeSessionId !== activeSessionId) {
      setSessionIdInput(routeSessionId);
      setActiveSessionId(routeSessionId);
    }
  }, [routeSessionId, activeSessionId]);

  /** Load a session by ID from the input. */
  const handleLoadSession = useCallback(() => {
    const trimmed = sessionIdInput.trim();
    if (!trimmed) return;
    setActiveSessionId(trimmed);
    if (trimmed !== routeSessionId) {
      navigate(`/resend/${trimmed}`, { replace: true });
    }
  }, [sessionIdInput, routeSessionId, navigate]);

  /** Send the resend request. */
  const handleSend = useCallback(
    async (isDryRun: boolean) => {
      if (!activeSessionId) {
        addToast({ type: "warning", message: "No session selected" });
        return;
      }

      // Build override_headers from the key-value pairs.
      // Merge duplicate header names by joining values with ", ".
      const overrideHeaders: Record<string, string> = {};
      for (const h of headers) {
        const key = h.key.trim();
        if (key) {
          overrideHeaders[key] = key in overrideHeaders
            ? `${overrideHeaders[key]}, ${h.value}`
            : h.value;
        }
      }

      try {
        const result = await execute<ResendResult>({
          action: "resend",
          params: {
            session_id: activeSessionId,
            override_method: method,
            override_url: url,
            override_headers: Object.keys(overrideHeaders).length > 0 ? overrideHeaders : undefined,
            override_body: body || undefined,
            body_patches: bodyPatches.length > 0 ? bodyPatches : undefined,
            dry_run: isDryRun,
            tag: tag || undefined,
          },
        });

        setResponse(result);

        // Add to history.
        setHistory((prev) => [
          {
            timestamp: new Date().toISOString(),
            method,
            url,
            statusCode: result.response_status_code,
            durationMs: result.duration_ms,
            dryRun: isDryRun,
            tag,
            sessionId: result.session_id,
          },
          ...prev,
        ]);

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
    [activeSessionId, method, url, headers, body, bodyPatches, tag, execute, addToast],
  );

  /** Whether the editor has a loaded session. */
  const hasSession = activeSessionId.length > 0 && sessionData != null;

  return (
    <div className="page resend-page">
      <div className="resend-header">
        <h1 className="page-title">Resend</h1>
        <p className="page-description">
          Edit and resend captured HTTP requests.
        </p>
      </div>

      {/* Session selector */}
      <div className="resend-session-selector">
        <div className="resend-session-input-row">
          <Input
            placeholder="Enter session ID..."
            value={sessionIdInput}
            onChange={(e) => setSessionIdInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleLoadSession();
            }}
          />
          <Button variant="primary" onClick={handleLoadSession} disabled={!sessionIdInput.trim()}>
            Load
          </Button>
        </div>
        {sessionLoading && (
          <div className="resend-loading">
            <Spinner size="sm" />
            <span>Loading session...</span>
          </div>
        )}
        {sessionError && (
          <div className="resend-error">
            Failed to load session: {sessionError.message}
          </div>
        )}
      </div>

      {hasSession && (
        <div className="resend-editor-layout">
          {/* Left: Request editor */}
          <div className="resend-panel resend-request-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">Request</span>
              <Badge variant="info">{activeSessionId.slice(0, 8)}</Badge>
            </div>

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
              tabs={REQUEST_TABS}
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

            {/* Action buttons */}
            <div className="resend-actions">
              <Button
                variant="primary"
                onClick={() => handleSend(dryRun)}
                disabled={executing}
              >
                {executing ? "Sending..." : dryRun ? "Send (Dry Run)" : "Send"}
              </Button>
              <Button
                variant="secondary"
                onClick={() => handleSend(true)}
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
            </div>
          </div>

          {/* Right: Response viewer */}
          <div className="resend-panel resend-response-panel">
            <div className="resend-panel-header">
              <span className="resend-panel-title">Response</span>
              {response?.dry_run && <Badge variant="warning">DRY RUN</Badge>}
              {response?.response_status_code != null && (
                <Badge
                  variant={
                    response.response_status_code < 300
                      ? "success"
                      : response.response_status_code < 400
                        ? "info"
                        : response.response_status_code < 500
                          ? "warning"
                          : "danger"
                  }
                >
                  {response.response_status_code}
                </Badge>
              )}
              {response?.duration_ms != null && (
                <span className="resend-duration">{response.duration_ms}ms</span>
              )}
            </div>

            {executing ? (
              <div className="resend-loading">
                <Spinner size="sm" />
                <span>Sending request...</span>
              </div>
            ) : response ? (
              <ResponseViewer
                response={response}
                originalSession={sessionData as SessionDetailResult}
              />
            ) : (
              <div className="resend-empty-response">
                Send a request to see the response here.
              </div>
            )}
          </div>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="resend-history">
          <h3 className="resend-history-title">Send History</h3>
          <div className="resend-history-list">
            {history.map((entry, idx) => (
              <div key={idx} className="resend-history-entry">
                <Badge
                  variant={
                    entry.statusCode == null
                      ? "default"
                      : entry.statusCode < 300
                        ? "success"
                        : entry.statusCode < 500
                          ? "warning"
                          : "danger"
                  }
                >
                  {entry.statusCode ?? "---"}
                </Badge>
                <span className="resend-history-method">{entry.method}</span>
                <span className="resend-history-url">{entry.url}</span>
                {entry.dryRun && <Badge variant="warning">DRY</Badge>}
                {entry.tag && <Badge variant="info">{entry.tag}</Badge>}
                {entry.durationMs != null && (
                  <span className="resend-history-duration">
                    {entry.durationMs}ms
                  </span>
                )}
                <span className="resend-history-time">
                  {new Date(entry.timestamp).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
