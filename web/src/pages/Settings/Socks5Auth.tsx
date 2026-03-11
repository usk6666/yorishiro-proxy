import { useCallback, useEffect, useState } from "react";
import { Button, Input, useToast } from "../../components/ui/index.js";
import { useConfigure } from "../../lib/mcp/hooks.js";
import type { ConfigResult } from "../../lib/mcp/types.js";

interface Socks5AuthProps {
  config: ConfigResult;
  onRefresh: () => void;
}

/**
 * Socks5Auth — manage SOCKS5 proxy authentication settings.
 *
 * Allows enabling/disabling SOCKS5 password authentication and
 * configuring the username and password via the configure tool's
 * socks5_auth section.
 */
export function Socks5Auth({ config, onRefresh }: Socks5AuthProps) {
  const { addToast } = useToast();
  const { configure, loading } = useConfigure();

  const socks5Available = config.socks5_enabled ?? false;
  const currentAuth = config.socks5_auth;

  const [authEnabled, setAuthEnabled] = useState(currentAuth?.method === "password");
  const [username, setUsername] = useState(currentAuth?.username ?? "");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  // Sync state when config changes (e.g. after navigation or refresh)
  useEffect(() => {
    setAuthEnabled(currentAuth?.method === "password");
    setUsername(currentAuth?.username ?? "");
    // Password is intentionally not synced from server for security
    setPassword("");
  }, [currentAuth]);

  const handleSave = useCallback(async () => {
    if (authEnabled) {
      if (!username.trim()) {
        addToast({ type: "warning", message: "Username is required for password authentication" });
        return;
      }
      if (!password) {
        addToast({ type: "warning", message: "Password is required for password authentication" });
        return;
      }
    }

    try {
      await configure({
        socks5_auth: authEnabled
          ? { method: "password", username: username.trim(), password }
          : { method: "none" },
      });
      addToast({
        type: "success",
        message: authEnabled
          ? "SOCKS5 authentication enabled"
          : "SOCKS5 authentication disabled",
      });
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to update SOCKS5 auth: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [authEnabled, username, password, configure, addToast, onRefresh]);

  if (!socks5Available) {
    return (
      <div className="settings-section">
        <div className="settings-card">
          <div className="settings-card-header">
            <span className="settings-card-title">SOCKS5 Authentication</span>
          </div>
          <div className="settings-card-body">
            <div className="settings-empty">
              SOCKS5 is not available. Start the proxy to configure SOCKS5 authentication.
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="settings-section">
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">SOCKS5 Authentication</span>
          <Button
            variant="primary"
            size="sm"
            onClick={handleSave}
            disabled={loading}
          >
            Save
          </Button>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Configure SOCKS5 proxy authentication. When enabled, clients must provide credentials to use the proxy.
          </p>

          {/* Auth toggle */}
          <div className="settings-form-row">
            <div className="input-wrapper">
              <label className="input-label" htmlFor="socks5-auth-toggle">Authentication</label>
              <select
                id="socks5-auth-toggle"
                className="settings-select"
                value={authEnabled ? "password" : "none"}
                onChange={(e) => setAuthEnabled(e.target.value === "password")}
              >
                <option value="none">Disabled (no authentication)</option>
                <option value="password">Enabled (username/password)</option>
              </select>
            </div>
          </div>

          {/* Credentials (shown only when auth is enabled) */}
          {authEnabled && (
            <div className="settings-form-row">
              <Input
                label="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username"
              />
              <div className="input-wrapper">
                <label className="input-label" htmlFor="socks5-password">Password</label>
                <div className="settings-inline-form">
                  <input
                    id="socks5-password"
                    className="input"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter password"
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setShowPassword((prev) => !prev)}
                  >
                    {showPassword ? "Hide" : "Show"}
                  </Button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
