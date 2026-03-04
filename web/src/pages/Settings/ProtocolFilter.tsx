import { Badge } from "../../components/ui/index.js";
import type { ConfigResult } from "../../lib/mcp/types.js";

/**
 * All supported protocol names, matching the validProtocols set in the Go backend
 * (internal/mcp/proxy_start_tool.go).
 */
const ALL_PROTOCOLS = [
  "HTTP/1.x",
  "HTTPS",
  "WebSocket",
  "HTTP/2",
  "gRPC",
  "TCP",
] as const;

interface ProtocolFilterProps {
  config: ConfigResult;
}

/**
 * ProtocolFilter — displays the currently enabled protocols from the proxy config.
 *
 * This is a read-only status display. To change which protocols are enabled,
 * users select protocols when starting a new listener in the ProxyControl form.
 */
export function ProtocolFilter({ config }: ProtocolFilterProps) {
  const enabledProtocols = config.enabled_protocols ?? [];

  return (
    <div className="settings-card">
      <div className="settings-card-header">
        <span className="settings-card-title">Enabled Protocols</span>
      </div>
      <div className="settings-card-body">
        <p className="settings-section-desc">
          Protocols currently enabled on the running proxy.
          Configure protocol selection when starting a new listener.
        </p>

        {enabledProtocols.length > 0 ? (
          <div className="settings-protocol-list">
            {ALL_PROTOCOLS.map((proto) => {
              const enabled = enabledProtocols.includes(proto);
              return (
                <div
                  key={proto}
                  className={`settings-protocol-item ${enabled ? "settings-protocol-item--enabled" : "settings-protocol-item--disabled"}`}
                >
                  <span className={`settings-protocol-dot ${enabled ? "settings-protocol-dot--on" : "settings-protocol-dot--off"}`} />
                  <span className="settings-protocol-name">{proto}</span>
                  <Badge variant={enabled ? "success" : "default"}>
                    {enabled ? "Enabled" : "Disabled"}
                  </Badge>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="settings-empty">
            No protocols configured. Start a listener to enable protocols.
          </div>
        )}
      </div>
    </div>
  );
}
