import { useState, useCallback } from "react";
import { useQuery, useProxyControl } from "../../lib/mcp/hooks.js";
import type { StatusResult } from "../../lib/mcp/types.js";
import { Badge, Button, Input, Spinner, useToast } from "../../components/ui/index.js";

/**
 * ProxyControl — manage proxy listeners (start/stop).
 */
export function ProxyControl() {
  const { addToast } = useToast();
  const { start, stop, loading: controlLoading } = useProxyControl();

  const {
    data: statusData,
    loading: statusLoading,
    error: statusError,
    refetch: refetchStatus,
  } = useQuery("status", { pollInterval: 3000 });

  // New listener form state
  const [showForm, setShowForm] = useState(false);
  const [name, setName] = useState("");
  const [listenAddr, setListenAddr] = useState("127.0.0.1:8080");
  const [upstreamProxy, setUpstreamProxy] = useState("");

  // Stop confirmation
  const [confirmStop, setConfirmStop] = useState<string | null>(null);

  const handleStart = useCallback(async () => {
    try {
      const params: Record<string, unknown> = {};
      if (name.trim()) params.name = name.trim();
      if (listenAddr.trim()) params.listen_addr = listenAddr.trim();
      if (upstreamProxy.trim()) params.upstream_proxy = upstreamProxy.trim();

      await start(params);
      addToast({ type: "success", message: `Listener started on ${listenAddr}` });
      setShowForm(false);
      setName("");
      setListenAddr("127.0.0.1:8080");
      setUpstreamProxy("");
      refetchStatus();
    } catch (err) {
      addToast({
        type: "error",
        message: `Start failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [name, listenAddr, upstreamProxy, start, addToast, refetchStatus]);

  const handleStop = useCallback(async (listenerName?: string) => {
    try {
      await stop(listenerName ? { name: listenerName } : {});
      addToast({
        type: "success",
        message: listenerName ? `Listener "${listenerName}" stopped` : "All listeners stopped",
      });
      setConfirmStop(null);
      refetchStatus();
    } catch (err) {
      addToast({
        type: "error",
        message: `Stop failed: ${err instanceof Error ? err.message : String(err)}`,
      });
      setConfirmStop(null);
    }
  }, [stop, addToast, refetchStatus]);

  if (statusLoading && !statusData) {
    return (
      <div className="settings-loading">
        <Spinner size="md" />
      </div>
    );
  }

  if (statusError) {
    return (
      <div className="settings-error">
        Error loading status: {statusError.message}
      </div>
    );
  }

  const status: StatusResult | null = statusData ?? null;

  return (
    <div className="settings-section">
      {/* Status overview */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Proxy Status</span>
          <div className="settings-card-actions">
            <Button
              variant="primary"
              size="sm"
              onClick={() => setShowForm(!showForm)}
            >
              {showForm ? "Cancel" : "New Listener"}
            </Button>
            {status?.running && (
              <Button
                variant="danger"
                size="sm"
                onClick={() => setConfirmStop("__all__")}
                disabled={controlLoading}
              >
                Stop All
              </Button>
            )}
          </div>
        </div>
        <div className="settings-card-body">
          <div style={{ display: "flex", alignItems: "center", gap: "var(--space-sm)", marginBottom: "var(--space-md)" }}>
            <span className={`settings-status-dot ${status?.running ? "settings-status-dot--running" : "settings-status-dot--stopped"}`} />
            <Badge variant={status?.running ? "success" : "default"}>
              {status?.running ? "Running" : "Stopped"}
            </Badge>
            {status && (
              <span style={{ fontSize: "var(--font-size-xs)", color: "var(--text-muted)" }}>
                {status.listener_count} listener{status.listener_count !== 1 ? "s" : ""}
                {" | "}
                {status.active_connections} connection{status.active_connections !== 1 ? "s" : ""}
                {" | "}
                {status.total_flows} flow{status.total_flows !== 1 ? "s" : ""}
              </span>
            )}
          </div>

          {/* Active listeners */}
          {status?.listeners && status.listeners.length > 0 ? (
            <div className="settings-listeners">
              {status.listeners.map((listener) => (
                <div key={listener.name} className="settings-listener">
                  <div className="settings-listener-info">
                    <span className="settings-listener-name">{listener.name}</span>
                    <span className="settings-listener-addr">{listener.listen_addr}</span>
                    <div className="settings-listener-stats">
                      <span>{listener.active_connections} conn</span>
                      <span>{formatUptime(listener.uptime_seconds)}</span>
                    </div>
                  </div>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => setConfirmStop(listener.name)}
                    disabled={controlLoading}
                  >
                    Stop
                  </Button>
                </div>
              ))}
            </div>
          ) : (
            <div className="settings-empty">
              No active listeners
            </div>
          )}
        </div>
      </div>

      {/* New listener form */}
      {showForm && (
        <div className="settings-add-form">
          <div className="settings-add-form-title">Start New Listener</div>
          <div className="settings-form-row">
            <Input
              label="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="default"
            />
            <Input
              label="Listen Address"
              value={listenAddr}
              onChange={(e) => setListenAddr(e.target.value)}
              placeholder="127.0.0.1:8080"
            />
          </div>
          <div className="settings-form-row">
            <Input
              label="Upstream Proxy"
              value={upstreamProxy}
              onChange={(e) => setUpstreamProxy(e.target.value)}
              placeholder="http://host:port or socks5://host:port"
            />
          </div>
          <div className="settings-add-form-actions">
            <Button variant="secondary" size="sm" onClick={() => setShowForm(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleStart}
              disabled={controlLoading}
            >
              Start
            </Button>
          </div>
        </div>
      )}

      {/* Stop confirmation dialog */}
      {confirmStop && (
        <div className="settings-confirm-overlay" onClick={() => setConfirmStop(null)}>
          <div className="settings-confirm-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="settings-confirm-title">Stop Listener</div>
            <div className="settings-confirm-message">
              {confirmStop === "__all__"
                ? "Are you sure you want to stop all listeners?"
                : `Are you sure you want to stop listener "${confirmStop}"?`}
            </div>
            <div className="settings-confirm-actions">
              <Button variant="secondary" size="sm" onClick={() => setConfirmStop(null)}>
                Cancel
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={() => handleStop(confirmStop === "__all__" ? undefined : confirmStop)}
                disabled={controlLoading}
              >
                Stop
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}
