import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Input, useToast } from "../../components/ui/index.js";
import { useConfigure } from "../../lib/mcp/hooks.js";
import type { ConfigResult } from "../../lib/mcp/types.js";

interface ClientCertificateProps {
  config: ConfigResult;
  onRefresh: () => void;
}

/**
 * ClientCertificate — manage mTLS client certificate settings for upstream connections.
 *
 * Allows configuring the PEM certificate and private key file paths
 * used for mTLS authentication with upstream servers, via the configure
 * tool's client_cert section.
 */
export function ClientCertificate({ config, onRefresh }: ClientCertificateProps) {
  const { addToast } = useToast();
  const { configure, loading } = useConfigure();

  const currentCert = config.client_cert;
  const isConfigured = !!currentCert;

  const [certPath, setCertPath] = useState(currentCert?.cert_path ?? "");
  const [keyPath, setKeyPath] = useState(currentCert?.key_path ?? "");

  // Sync state when config changes (e.g. after navigation or refresh)
  useEffect(() => {
    setCertPath(currentCert?.cert_path ?? "");
    setKeyPath(currentCert?.key_path ?? "");
  }, [currentCert]);

  const handleApply = useCallback(async () => {
    if (!certPath.trim()) {
      addToast({ type: "warning", message: "Certificate path is required" });
      return;
    }
    if (!keyPath.trim()) {
      addToast({ type: "warning", message: "Private key path is required" });
      return;
    }

    try {
      await configure({
        client_cert: {
          cert_path: certPath.trim(),
          key_path: keyPath.trim(),
        },
      });
      addToast({
        type: "success",
        message: "Client certificate configured successfully",
      });
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to configure client certificate: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [certPath, keyPath, configure, addToast, onRefresh]);

  const handleClear = useCallback(async () => {
    try {
      await configure({
        client_cert: {
          cert_path: "",
          key_path: "",
        },
      });
      setCertPath("");
      setKeyPath("");
      addToast({
        type: "success",
        message: "Client certificate removed",
      });
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to remove client certificate: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [configure, addToast, onRefresh]);

  return (
    <div className="settings-section">
      {/* Current status */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Current Status</span>
          <Badge variant={isConfigured ? "info" : "default"}>
            {isConfigured ? "Configured" : "Not Configured"}
          </Badge>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            mTLS client certificates are used for mutual TLS authentication with upstream servers.
            The proxy presents this certificate when connecting to backends that require client certificate verification.
          </p>
          {isConfigured && (
            <div className="settings-item-list">
              <div className="settings-rule">
                <div className="settings-rule-info">
                  <span className="settings-rule-id">Certificate</span>
                  <span className="settings-rule-detail">{currentCert.cert_path}</span>
                </div>
              </div>
              <div className="settings-rule">
                <div className="settings-rule-info">
                  <span className="settings-rule-id">Private Key</span>
                  <span className="settings-rule-detail">{currentCert.key_path}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Configuration form */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Configure Client Certificate</span>
          {isConfigured && (
            <Button
              variant="secondary"
              size="sm"
              onClick={handleClear}
              disabled={loading}
            >
              Clear
            </Button>
          )}
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Specify the file paths on the server for the PEM-encoded client certificate and private key.
          </p>

          <div className="settings-form-row">
            <Input
              label="Certificate Path"
              value={certPath}
              onChange={(e) => setCertPath(e.target.value)}
              placeholder="/path/to/client.crt"
            />
          </div>

          <div className="settings-form-row">
            <Input
              label="Private Key Path"
              value={keyPath}
              onChange={(e) => setKeyPath(e.target.value)}
              placeholder="/path/to/client.key"
            />
          </div>

          <div className="settings-add-form-actions" style={{ marginTop: "var(--space-lg)" }}>
            <Button
              variant="primary"
              size="sm"
              onClick={handleApply}
              disabled={loading || (!certPath.trim() && !keyPath.trim())}
            >
              {loading ? "Applying..." : "Apply"}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
