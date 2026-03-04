import { useCallback, useEffect, useState } from "react";
import { Button, Input, useToast } from "../../components/ui/index.js";
import { useConfigure } from "../../lib/mcp/hooks.js";
import type { StatusResult } from "../../lib/mcp/types.js";

interface ConnectionSettingsProps {
  status: StatusResult;
  onRefresh: () => void;
}

/**
 * ConnectionSettings — manage connection limits, timeouts, upstream proxy, and intercept queue.
 */
export function ConnectionSettings({ status, onRefresh }: ConnectionSettingsProps) {
  const { addToast } = useToast();
  const { configure, loading } = useConfigure();

  // Connection & timeout fields
  const [maxConnections, setMaxConnections] = useState(String(status.max_connections));
  const [peekTimeout, setPeekTimeout] = useState(String(status.peek_timeout_ms));
  const [requestTimeout, setRequestTimeout] = useState(String(status.request_timeout_ms));

  // Upstream proxy
  const [upstreamProxy, setUpstreamProxy] = useState(status.upstream_proxy || "");

  // Intercept queue
  const [queueTimeout, setQueueTimeout] = useState("");
  const [queueBehavior, setQueueBehavior] = useState<"auto_release" | "auto_drop">("auto_release");

  // Sync state when status changes
  useEffect(() => {
    setMaxConnections(String(status.max_connections));
    setPeekTimeout(String(status.peek_timeout_ms));
    setRequestTimeout(String(status.request_timeout_ms));
    setUpstreamProxy(status.upstream_proxy || "");
  }, [status]);

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
    try {
      await configure({
        upstream_proxy: upstreamProxy.trim() || "",
      });
      addToast({
        type: "success",
        message: upstreamProxy.trim()
          ? `Upstream proxy set to ${upstreamProxy.trim()}`
          : "Upstream proxy disabled",
      });
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to update: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [upstreamProxy, configure, addToast, onRefresh]);

  const handleSaveInterceptQueue = useCallback(async () => {
    const timeoutMs = queueTimeout.trim() ? parseInt(queueTimeout, 10) : null;

    if (queueTimeout.trim() && (isNaN(timeoutMs as number) || (timeoutMs as number) < 0)) {
      addToast({ type: "warning", message: "Timeout must be a non-negative number" });
      return;
    }

    try {
      await configure({
        intercept_queue: {
          timeout_ms: timeoutMs,
          timeout_behavior: queueBehavior,
        },
      });
      addToast({ type: "success", message: "Intercept queue settings updated" });
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to update: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [queueTimeout, queueBehavior, configure, addToast, onRefresh]);

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
            Route all outgoing traffic through an upstream HTTP or SOCKS5 proxy. Leave empty to connect directly.
          </p>
          <div className="settings-form-row">
            <Input
              label="Upstream Proxy URL"
              value={upstreamProxy}
              onChange={(e) => setUpstreamProxy(e.target.value)}
              placeholder="http://host:port or socks5://host:port"
            />
          </div>
        </div>
      </div>

      {/* Intercept Queue */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Intercept Queue</span>
          <Button
            variant="primary"
            size="sm"
            onClick={handleSaveInterceptQueue}
            disabled={loading}
          >
            Save
          </Button>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Configure timeout and behavior for intercepted requests waiting in the queue.
          </p>
          <div className="settings-form-row">
            <Input
              label="Queue Timeout (ms)"
              value={queueTimeout}
              onChange={(e) => setQueueTimeout(e.target.value)}
              type="number"
              placeholder="Leave empty for no timeout"
            />
            <div className="input-wrapper">
              <label className="input-label" htmlFor="queue-behavior">Timeout Behavior</label>
              <select
                id="queue-behavior"
                className="settings-select"
                value={queueBehavior}
                onChange={(e) => setQueueBehavior(e.target.value as "auto_release" | "auto_drop")}
              >
                <option value="auto_release">Auto Release</option>
                <option value="auto_drop">Auto Drop</option>
              </select>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
