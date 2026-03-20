import { useCallback, useState } from "react";
import { Badge, Button, Input, useToast } from "../../components/ui/index.js";
import { useProxyControl } from "../../lib/mcp/hooks.js";
import type { ConfigResult, ForwardConfig } from "../../lib/mcp/types.js";

interface TcpForwardsProps {
  config: ConfigResult;
  onRefresh: () => void;
}

/** Valid protocol values for ForwardConfig. */
const PROTOCOL_OPTIONS = ["auto", "raw", "http", "http2", "grpc", "websocket"] as const;

/**
 * TcpForwards — manage TCP forward mappings (local port -> ForwardConfig).
 *
 * TCP forwards are start-time configuration: they are applied when starting a
 * new listener via proxy_start. Adding a forward triggers a proxy restart.
 * Individual removal is not supported at runtime — the proxy must be restarted
 * with the updated mapping set.
 */
export function TcpForwards({ config, onRefresh }: TcpForwardsProps) {
  const { addToast } = useToast();
  const { start, loading } = useProxyControl();

  // Form state for adding a new mapping
  const [localPort, setLocalPort] = useState("");
  const [upstreamHost, setUpstreamHost] = useState("");
  const [upstreamPort, setUpstreamPort] = useState("");
  const [protocol, setProtocol] = useState("auto");
  const [tlsEnabled, setTlsEnabled] = useState(false);
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
    const newEntry: ForwardConfig = { target: upstream };
    if (protocol && protocol !== "auto") {
      newEntry.protocol = protocol;
    }
    if (tlsEnabled) {
      newEntry.tls = true;
    }

    // Build new forwards map: existing + new entry
    const newForwards: Record<string, ForwardConfig> = { ...forwards, [port]: newEntry };

    try {
      await start({
        tcp_forwards: newForwards,
      });
      addToast({
        type: "success",
        message: `TCP forward added: port ${port} -> ${upstream}${protocol !== "auto" ? ` (${protocol})` : ""}${tlsEnabled ? " [TLS]" : ""}`,
      });
      setLocalPort("");
      setUpstreamHost("");
      setUpstreamPort("");
      setProtocol("auto");
      setTlsEnabled(false);
      setShowForm(false);
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to add TCP forward: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [localPort, upstreamHost, upstreamPort, protocol, tlsEnabled, forwards, start, addToast, onRefresh]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") {
        handleAdd();
      }
    },
    [handleAdd],
  );

  /** Parse "host:port" target into display parts. */
  function parseTarget(value: string): { host: string; port: string } {
    const lastColon = value.lastIndexOf(":");
    if (lastColon === -1) return { host: value, port: "" };
    return { host: value.slice(0, lastColon), port: value.slice(lastColon + 1) };
  }

  /** Get display label for protocol. */
  function protocolLabel(proto?: string): string {
    if (!proto || proto === "auto") return "auto";
    return proto;
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
            Map local ports to upstream TCP addresses with optional protocol detection and TLS termination.
            Incoming connections on a mapped port are forwarded to the specified upstream, with L7 protocol
            parsing applied based on the configured protocol hint.
          </p>
          <p className="settings-section-desc">
            TCP forwards are configured when starting a new listener. Adding a forward
            restarts the proxy with the updated mappings. To remove a forward, restart
            the proxy with the desired configuration.
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
              <div className="settings-form-row">
                <div className="input-wrapper">
                  <label className="input-label">Protocol</label>
                  <select
                    className="input"
                    value={protocol}
                    onChange={(e) => setProtocol(e.target.value)}
                  >
                    {PROTOCOL_OPTIONS.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="input-wrapper">
                  <label className="input-label">TLS Termination</label>
                  <label style={{ display: "flex", alignItems: "center", gap: "var(--space-xs)", cursor: "pointer", padding: "var(--space-xs) 0" }}>
                    <input
                      type="checkbox"
                      checked={tlsEnabled}
                      onChange={(e) => setTlsEnabled(e.target.checked)}
                    />
                    <span>Enable TLS MITM</span>
                  </label>
                </div>
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
              {entries.map(([port, fc]) => {
                const parsed = parseTarget(fc.target);
                const proto = protocolLabel(fc.protocol);
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
                      <span style={{ marginLeft: "var(--space-xs)" }}>
                        <Badge variant={proto === "auto" ? "default" : "success"}>
                          {proto}
                        </Badge>
                      </span>
                      {fc.tls && (
                        <span style={{ marginLeft: "var(--space-xs)" }}>
                          <Badge variant="warning">
                            TLS
                          </Badge>
                        </span>
                      )}
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
