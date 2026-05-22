import { useCallback, useEffect, useMemo, useState } from "react";
import { Button, Input, useToast } from "../../components/ui/index.js";
import { useConfigure } from "../../lib/mcp/hooks.js";
import type { StatusResult } from "../../lib/mcp/types.js";
import {
  UpstreamProxyEditor,
  type UpstreamProxyEditorValue,
  redactUpstreamProxyURL,
  validateUpstreamProxyPayload,
} from "./UpstreamProxyEditor.js";

interface ConnectionSettingsProps {
  status: StatusResult;
  onRefresh: () => void;
}

const DEFAULT_LISTENER = "default";

/**
 * ConnectionSettings — manage connection limits, timeouts, and upstream proxy.
 *
 * Intercept queue configuration (timeout / behavior) lives on the Intercept
 * Rules tab as the single source of truth (USK-969). A small pointer note is
 * retained here for discoverability.
 */
export function ConnectionSettings({ status, onRefresh }: ConnectionSettingsProps) {
  const { addToast } = useToast();
  const { configure, loading } = useConfigure();

  // Connection & timeout fields
  const [maxConnections, setMaxConnections] = useState(String(status.max_connections));
  const [peekTimeout, setPeekTimeout] = useState(String(status.peek_timeout_ms));
  const [requestTimeout, setRequestTimeout] = useState(String(status.request_timeout_ms));

  // Upstream proxy. Backend follow-up USK-976 will expose rotation
  // template/policy in the status query; until then, the editor cannot
  // pre-populate the rotation form after page reload — it falls back to
  // the (status.upstream_proxy) literal URL, which is "" when rotation
  // is live.
  const [upstreamProxy, setUpstreamProxy] = useState<UpstreamProxyEditorValue>(
    status.upstream_proxy || "",
  );

  // Listener scope for the Upstream Proxy card (USK-826/USK-959).
  // `configure({ name })` currently scopes only the upstream_proxy
  // section; other cards remain process-global, so the selector lives
  // here and not on the parent container.
  const listenerNames = useMemo(
    () => (status.listeners ?? []).map((l) => l.name),
    [status.listeners],
  );
  const [selectedListener, setSelectedListener] = useState<string>(DEFAULT_LISTENER);

  // Sync state when status changes
  useEffect(() => {
    setMaxConnections(String(status.max_connections));
    setPeekTimeout(String(status.peek_timeout_ms));
    setRequestTimeout(String(status.request_timeout_ms));
    setUpstreamProxy(status.upstream_proxy || "");
  }, [status]);

  // If the selected listener disappears (stopped externally), fall back
  // to the default listener so the next save targets a running scope.
  useEffect(() => {
    if (selectedListener !== DEFAULT_LISTENER && !listenerNames.includes(selectedListener)) {
      setSelectedListener(DEFAULT_LISTENER);
    }
  }, [listenerNames, selectedListener]);

  const handleSaveConnection = useCallback(async () => {
    const maxConn = parseInt(maxConnections, 10);
    const peekMs = parseInt(peekTimeout, 10);
    const reqMs = parseInt(requestTimeout, 10);

    if (isNaN(maxConn) || maxConn < 1) {
      addToast({ type: "warning", message: "Max connections must be a positive number" });
      return;
    }
    if (isNaN(peekMs) || peekMs < 100) {
      addToast({ type: "warning", message: "Peek timeout must be at least 100ms" });
      return;
    }
    if (isNaN(reqMs) || reqMs < 100) {
      addToast({ type: "warning", message: "Request timeout must be at least 100ms" });
      return;
    }

    try {
      await configure({
        max_connections: maxConn,
        peek_timeout_ms: peekMs,
        request_timeout_ms: reqMs,
      });
      addToast({ type: "success", message: "Connection settings updated" });
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to update: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [maxConnections, peekTimeout, requestTimeout, configure, addToast, onRefresh]);

  const handleSaveUpstreamProxy = useCallback(async () => {
    // Trim string form before send; the editor already builds a
    // trimmed payload but a literal-URL paste with leading whitespace
    // can still slip through component-local state.
    const payload =
      typeof upstreamProxy === "string" ? upstreamProxy.trim() : upstreamProxy;

    for (const warning of validateUpstreamProxyPayload(payload)) {
      addToast({ type: "warning", message: warning });
    }

    try {
      await configure({
        name: selectedListener,
        upstream_proxy: payload || "",
      });

      // Redact the URL before echoing in the toast to avoid leaking
      // userinfo credentials to the UI surface (CWE-200). Mirrors the
      // backend `connector.RedactProxyURL` behaviour for the read-back
      // path. The rotation summary deliberately does not echo the
      // template (which may also embed secrets).
      const summary =
        typeof payload === "string"
          ? payload
            ? `Upstream proxy set to ${redactUpstreamProxyURL(payload)}`
            : "Upstream proxy disabled"
          : `Rotation enabled (${"url_template" in payload && payload.url_template ? "template set" : "no template"})`;

      addToast({
        type: "success",
        message: `${summary} (listener: ${selectedListener})`,
      });
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to update: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [upstreamProxy, selectedListener, configure, addToast, onRefresh]);

  const listenerSelectorDisabled = loading || listenerNames.length === 0;

  return (
    <div className="settings-section">
      {/* Connection & Timeouts */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Connection & Timeouts</span>
          <Button
            variant="primary"
            size="sm"
            onClick={handleSaveConnection}
            disabled={loading}
          >
            Save
          </Button>
        </div>
        <div className="settings-card-body">
          <div className="settings-form-row">
            <Input
              label="Max Connections"
              value={maxConnections}
              onChange={(e) => setMaxConnections(e.target.value)}
              type="number"
              placeholder="1024"
            />
            <Input
              label="Peek Timeout (ms)"
              value={peekTimeout}
              onChange={(e) => setPeekTimeout(e.target.value)}
              type="number"
              placeholder="30000"
            />
            <Input
              label="Request Timeout (ms)"
              value={requestTimeout}
              onChange={(e) => setRequestTimeout(e.target.value)}
              type="number"
              placeholder="60000"
            />
          </div>
        </div>
      </div>

      {/* Upstream Proxy */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Upstream Proxy</span>
          <Button
            variant="primary"
            size="sm"
            onClick={handleSaveUpstreamProxy}
            disabled={loading}
          >
            Save
          </Button>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Route outgoing traffic through an upstream HTTP/SOCKS5 proxy. Use rotation mode to expand a
            template per request / connection / target host. Leave the URL empty to disable.
          </p>
          <div className="settings-form-row">
            <div className="input-wrapper">
              <label className="input-label" htmlFor="upstream-proxy-listener">Listener (scope)</label>
              <select
                id="upstream-proxy-listener"
                className="settings-select"
                value={selectedListener}
                onChange={(e) => setSelectedListener(e.target.value)}
                disabled={listenerSelectorDisabled}
              >
                <option value={DEFAULT_LISTENER}>{DEFAULT_LISTENER}</option>
                {listenerNames
                  .filter((name) => name !== DEFAULT_LISTENER)
                  .map((name) => (
                    <option key={name} value={name}>
                      {name}
                    </option>
                  ))}
              </select>
            </div>
          </div>
          <UpstreamProxyEditor
            value={upstreamProxy}
            onChange={setUpstreamProxy}
            disabled={loading}
          />
        </div>
      </div>

      {/* Intercept Queue — moved to the Intercept Rules tab (USK-969). */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Intercept Queue</span>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Intercept queue timeout and behavior are now configured on the Intercept Rules tab.
          </p>
        </div>
      </div>
    </div>
  );
}
