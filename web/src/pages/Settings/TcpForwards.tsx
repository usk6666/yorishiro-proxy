import { useState, useCallback } from "react";
import { useProxyControl } from "../../lib/mcp/hooks.js";
import type { ConfigResult } from "../../lib/mcp/types.js";
import { Badge, Button, Input, useToast } from "../../components/ui/index.js";

interface TcpForwardsProps {
  config: ConfigResult;
  onRefresh: () => void;
}

/**
 * TcpForwards — manage TCP forward mappings (local port -> upstream host:port).
 *
 * TCP forwards are configured at proxy_start time. This component displays
 * the currently active mappings and provides a form to start new TCP forward
 * listeners via proxy_start.
 */
export function TcpForwards({ config, onRefresh }: TcpForwardsProps) {
  const { addToast } = useToast();
  const { start, loading } = useProxyControl();

  // Form state for adding a new mapping
  const [localPort, setLocalPort] = useState("");
  const [upstreamHost, setUpstreamHost] = useState("");
  const [upstreamPort, setUpstreamPort] = useState("");
  const [showForm, setShowForm] = useState(false);

  const forwards = config.tcp_forwards ?? {};
  const entries = Object.entries(forwards);

  const handleAdd = useCallback(async () => {
    const port = localPort.trim();
    const host = upstreamHost.trim();
    const uPort = upstreamPort.trim();

    if (!port) {
      addToast({ type: "warning", message: "Local port is required" });
      return;
    }
    const portNum = parseInt(port, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      addToast({ type: "warning", message: "Local port must be between 1 and 65535" });
      return;
    }
    if (!host) {
      addToast({ type: "warning", message: "Upstream host is required" });
      return;
    }
    if (!uPort) {
      addToast({ type: "warning", message: "Upstream port is required" });
      return;
    }
    const uPortNum = parseInt(uPort, 10);
    if (isNaN(uPortNum) || uPortNum < 1 || uPortNum > 65535) {
      addToast({ type: "warning", message: "Upstream port must be between 1 and 65535" });
      return;
    }

    if (forwards[port]) {
      addToast({ type: "warning", message: `Port ${port} is already mapped` });
      return;
    }

    const upstream = `${host}:${uPort}`;

    // Build new forwards map: existing + new entry
    const newForwards: Record<string, string> = { ...forwards, [port]: upstream };

    try {
      await start({
        tcp_forwards: newForwards,
      });
      addToast({
        type: "success",
        message: `TCP forward added: port ${port} -> ${upstream}`,
      });
      setLocalPort("");
      setUpstreamHost("");
      setUpstreamPort("");
      setShowForm(false);
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to add TCP forward: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [localPort, upstreamHost, upstreamPort, forwards, start, addToast, onRefresh]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") {
        handleAdd();
      }
    },
    [handleAdd],
  );

  /** Parse "host:port" into display parts. */
  function parseUpstream(value: string): { host: string; port: string } {
    const lastColon = value.lastIndexOf(":");
    if (lastColon === -1) return { host: value, port: "" };
    return { host: value.slice(0, lastColon), port: value.slice(lastColon + 1) };
  }

  return (
    <div className="settings-section">
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">
            TCP Forward Mappings ({entries.length})
          </span>
          <div className="settings-card-actions">
            <Button
              variant="primary"
              size="sm"
              onClick={() => setShowForm(!showForm)}
            >
              {showForm ? "Cancel" : "Add Forward"}
            </Button>
          </div>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Map local ports to upstream TCP addresses. Incoming connections on a mapped port
            are forwarded to the specified upstream host:port via the Raw TCP handler.
            Changes require a proxy restart to take effect.
          </p>

          {/* Add mapping form */}
          {showForm && (
            <div className="settings-add-form" style={{ marginBottom: "var(--space-md)" }}>
              <div className="settings-add-form-title">New TCP Forward</div>
              <div className="settings-form-row">
                <Input
                  label="Local Port"
                  value={localPort}
                  onChange={(e) => setLocalPort(e.target.value)}
                  onKeyDown={handleKeyDown}
                  type="number"
                  placeholder="e.g., 3306"
                />
                <Input
                  label="Upstream Host"
                  value={upstreamHost}
                  onChange={(e) => setUpstreamHost(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="e.g., db.example.com"
                />
                <Input
                  label="Upstream Port"
                  value={upstreamPort}
                  onChange={(e) => setUpstreamPort(e.target.value)}
                  onKeyDown={handleKeyDown}
                  type="number"
                  placeholder="e.g., 3306"
                />
              </div>
              <div className="settings-add-form-actions">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => setShowForm(false)}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleAdd}
                  disabled={loading}
                >
                  Add
                </Button>
              </div>
            </div>
          )}

          {/* Mapping list */}
          {entries.length > 0 ? (
            <div className="settings-item-list">
              {entries.map(([port, upstream]) => {
                const parsed = parseUpstream(upstream);
                return (
                  <div key={port} className="settings-item">
                    <div className="settings-item-content">
                      <Badge variant="info">:{port}</Badge>
                      <span className="settings-item-meta" style={{ margin: "0 var(--space-xs)" }}>
                        -&gt;
                      </span>
                      <span className="settings-item-text">
                        {parsed.host}:{parsed.port}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="settings-empty">
              No TCP forward mappings configured
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
