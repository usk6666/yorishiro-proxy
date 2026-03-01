import { useState, useCallback } from "react";
import { useQuery } from "../../lib/mcp/hooks.js";
import { Spinner, Tabs } from "../../components/ui/index.js";
import { ProxyControl } from "./ProxyControl.js";
import { CaptureScope } from "./CaptureScope.js";
import { TlsPassthrough } from "./TlsPassthrough.js";
import { InterceptRules } from "./InterceptRules.js";
import { AutoTransformRules } from "./AutoTransformRules.js";
import { ConnectionSettings } from "./ConnectionSettings.js";
import "./SettingsPage.css";

const TABS = [
  { id: "proxy", label: "Proxy" },
  { id: "capture", label: "Capture Scope" },
  { id: "tls", label: "TLS Passthrough" },
  { id: "intercept", label: "Intercept Rules" },
  { id: "transform", label: "Auto-Transform" },
  { id: "connection", label: "Connection" },
];

/**
 * SettingsPage — main settings panel with tabbed navigation for proxy configuration.
 *
 * Uses the MCP query tool (resource: "config" and "status") to fetch current settings,
 * and the configure / proxy_start / proxy_stop tools to apply changes.
 */
export function SettingsPage() {
  const [activeTab, setActiveTab] = useState("proxy");

  // Fetch config for most tabs
  const {
    data: configData,
    loading: configLoading,
    error: configError,
    refetch: refetchConfig,
  } = useQuery("config");

  // Fetch status for connection settings and proxy control
  const {
    data: statusData,
    loading: statusLoading,
    error: statusError,
    refetch: refetchStatus,
  } = useQuery("status");

  const handleRefresh = useCallback(() => {
    refetchConfig();
    refetchStatus();
  }, [refetchConfig, refetchStatus]);

  const renderContent = () => {
    switch (activeTab) {
      case "proxy":
        return <ProxyControl />;

      case "capture":
        if (configLoading && !configData) {
          return <div className="settings-loading"><Spinner size="md" /></div>;
        }
        if (configError) {
          return <div className="settings-error">Error loading config: {configError.message}</div>;
        }
        if (!configData) return null;
        return <CaptureScope config={configData} onRefresh={handleRefresh} />;

      case "tls":
        if (configLoading && !configData) {
          return <div className="settings-loading"><Spinner size="md" /></div>;
        }
        if (configError) {
          return <div className="settings-error">Error loading config: {configError.message}</div>;
        }
        if (!configData) return null;
        return <TlsPassthrough config={configData} onRefresh={handleRefresh} />;

      case "intercept":
        if (configLoading && !configData) {
          return <div className="settings-loading"><Spinner size="md" /></div>;
        }
        if (configError) {
          return <div className="settings-error">Error loading config: {configError.message}</div>;
        }
        if (!configData) return null;
        return <InterceptRules config={configData} onRefresh={handleRefresh} />;

      case "transform":
        if (configLoading && !configData) {
          return <div className="settings-loading"><Spinner size="md" /></div>;
        }
        if (configError) {
          return <div className="settings-error">Error loading config: {configError.message}</div>;
        }
        if (!configData) return null;
        return <AutoTransformRules config={configData} onRefresh={handleRefresh} />;

      case "connection":
        if (statusLoading && !statusData) {
          return <div className="settings-loading"><Spinner size="md" /></div>;
        }
        if (statusError) {
          return <div className="settings-error">Error loading status: {statusError.message}</div>;
        }
        if (!statusData) return null;
        return <ConnectionSettings status={statusData} onRefresh={handleRefresh} />;

      default:
        return null;
    }
  };

  return (
    <div className="page settings-page">
      <h1 className="page-title">Settings</h1>
      <p className="page-description">
        Proxy configuration and listener management.
      </p>

      <div className="settings-tabs">
        <Tabs tabs={TABS} activeTab={activeTab} onTabChange={setActiveTab}>
          {renderContent()}
        </Tabs>
      </div>
    </div>
  );
}
