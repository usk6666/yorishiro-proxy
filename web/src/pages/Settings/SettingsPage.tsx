import { type ReactNode, useCallback, useState } from "react";
import { Badge, Spinner, Tabs } from "../../components/ui/index.js";
import { useQuery } from "../../lib/mcp/hooks.js";
import { AutoTransformRules } from "./AutoTransformRules.js";
import { CACertPanel } from "./CACertPanel.js";
import { CaptureScope } from "./CaptureScope.js";
import { ClientCertificate } from "./ClientCertificate.js";
import { ConnectionSettings } from "./ConnectionSettings.js";
import { InterceptRules } from "./InterceptRules.js";
import { ProxyControl } from "./ProxyControl.js";
import "./SettingsPage.css";
import { Socks5Auth } from "./Socks5Auth.js";
import { TcpForwards } from "./TcpForwards.js";
import { TlsFingerprint } from "./TlsFingerprint.js";
import { TlsPassthrough } from "./TlsPassthrough.js";

const TABS = [
  { id: "proxy", label: "Proxy" },
  { id: "capture", label: "Capture Scope" },
  { id: "tls", label: "TLS Passthrough" },
  { id: "tcp-forwards", label: "TCP Forwards" },
  { id: "intercept", label: "Intercept Rules" },
  { id: "transform", label: "Auto-Transform" },
  { id: "socks5-auth", label: "SOCKS5 Auth" },
  { id: "tls-fingerprint", label: "TLS Fingerprint" },
  { id: "client-cert", label: "Client Certificate" },
  { id: "connection", label: "Connection" },
  { id: "ca-cert", label: "CA Certificate" },
];

interface TabContentProps<T> {
  loading: boolean;
  error: Error | null;
  data: T | null;
  resourceLabel: string;
  children: (data: T) => ReactNode;
}

/**
 * TabContent — file-local helper that absorbs the shared loading / error /
 * empty guards used by most Settings tabs. Renders a spinner while loading,
 * an error banner on failure, nothing while data is absent, and otherwise
 * delegates to the render-prop child with the non-null data.
 */
function TabContent<T>({ loading, error, data, resourceLabel, children }: TabContentProps<T>): ReactNode {
  if (loading && !data) {
    return <div className="settings-loading"><Spinner size="md" /></div>;
  }
  if (error) {
    return <div className="settings-error">Error loading {resourceLabel}: {error.message}</div>;
  }
  if (!data) return null;
  return children(data);
}

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
        return (
          <div className="settings-section">
            <ProxyControl />
            {configData?.safety_filter && (
              <div className="settings-card">
                <div className="settings-card-header">
                  <span className="settings-card-title">Safety Filter</span>
                </div>
                <div className="settings-card-body">
                  <div className="settings-form-row">
                    <div className="settings-info-item">
                      <span className="settings-info-label">Status</span>
                      <Badge variant={configData.safety_filter.enabled ? "success" : "default"}>
                        {configData.safety_filter.enabled ? "Enabled" : "Disabled"}
                      </Badge>
                    </div>
                    <div className="settings-info-item">
                      <span className="settings-info-label">Input Rules</span>
                      <span className="settings-info-value">{configData.safety_filter.input_rules}</span>
                    </div>
                    <div className="settings-info-item">
                      <span className="settings-info-label">Output Rules</span>
                      <span className="settings-info-value">{configData.safety_filter.output_rules}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        );

      case "capture":
        return (
          <TabContent loading={configLoading} error={configError} data={configData} resourceLabel="config">
            {(c) => <CaptureScope config={c} onRefresh={handleRefresh} />}
          </TabContent>
        );

      case "tls":
        return (
          <TabContent loading={configLoading} error={configError} data={configData} resourceLabel="config">
            {(c) => <TlsPassthrough config={c} onRefresh={handleRefresh} />}
          </TabContent>
        );

      case "tcp-forwards":
        return (
          <TabContent loading={configLoading} error={configError} data={configData} resourceLabel="config">
            {(c) => <TcpForwards config={c} onRefresh={handleRefresh} />}
          </TabContent>
        );

      case "intercept":
        return (
          <TabContent loading={configLoading} error={configError} data={configData} resourceLabel="config">
            {(c) => <InterceptRules config={c} onRefresh={handleRefresh} />}
          </TabContent>
        );

      case "transform":
        return (
          <TabContent loading={configLoading} error={configError} data={configData} resourceLabel="config">
            {(c) => <AutoTransformRules config={c} onRefresh={handleRefresh} />}
          </TabContent>
        );

      case "socks5-auth":
        return (
          <TabContent loading={configLoading} error={configError} data={configData} resourceLabel="config">
            {(c) => <Socks5Auth config={c} onRefresh={handleRefresh} />}
          </TabContent>
        );

      case "tls-fingerprint":
        return (
          <TabContent loading={statusLoading} error={statusError} data={statusData} resourceLabel="status">
            {(s) => <TlsFingerprint status={s} onRefresh={handleRefresh} />}
          </TabContent>
        );

      case "client-cert":
        return (
          <TabContent loading={configLoading} error={configError} data={configData} resourceLabel="config">
            {(c) => <ClientCertificate config={c} onRefresh={handleRefresh} />}
          </TabContent>
        );

      case "connection":
        return (
          <TabContent loading={statusLoading} error={statusError} data={statusData} resourceLabel="status">
            {(s) => <ConnectionSettings status={s} onRefresh={handleRefresh} />}
          </TabContent>
        );

      case "ca-cert":
        return <CACertPanel onRefresh={handleRefresh} />;

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
