import { useState, useCallback } from "react";
import { useQuery, useExecute } from "../../lib/mcp/hooks.js";
import { useToast } from "../../components/ui/Toast.js";
import { Button } from "../../components/ui/Button.js";
import { Spinner } from "../../components/ui/Spinner.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Format an ISO date string to a human-readable date. */
function formatDate(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

/** Check if a certificate is expiring within the given number of days. */
function isExpiringSoon(notAfter: string, daysThreshold: number): boolean {
  try {
    const expiry = new Date(notAfter).getTime();
    const now = Date.now();
    const thresholdMs = daysThreshold * 24 * 60 * 60 * 1000;
    return expiry - now < thresholdMs;
  } catch {
    return false;
  }
}

/** Trigger a file download in the browser. */
function downloadPem(pem: string, filename: string): void {
  const blob = new Blob([pem], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Install instructions
// ---------------------------------------------------------------------------

const INSTALL_INSTRUCTIONS = [
  {
    platform: "macOS",
    steps: [
      "1. Download the CA certificate (PEM) using the button above",
      '2. Open Keychain Access (Applications > Utilities > Keychain Access)',
      '3. Drag the .pem file into the "System" keychain',
      '4. Double-click the imported certificate',
      '5. Expand "Trust" and set "When using this certificate" to "Always Trust"',
      "6. Close the dialog and enter your password to confirm",
    ],
  },
  {
    platform: "Windows",
    steps: [
      "1. Download the CA certificate (PEM) using the button above",
      "2. Rename the file extension from .pem to .crt",
      "3. Double-click the .crt file",
      '4. Click "Install Certificate..."',
      '5. Select "Local Machine" and click Next',
      '6. Select "Place all certificates in the following store"',
      '7. Click Browse and select "Trusted Root Certification Authorities"',
      "8. Click Next, then Finish",
    ],
  },
  {
    platform: "Linux (Ubuntu/Debian)",
    steps: [
      "1. Download the CA certificate (PEM) using the button above",
      "2. Copy to the CA certificates directory:",
      "   sudo cp yorishiro-ca.pem /usr/share/ca-certificates/yorishiro-ca.crt",
      "3. Register the certificate in the configuration:",
      '   echo "yorishiro-ca.crt" | sudo tee -a /etc/ca-certificates.conf',
      "4. Update the CA certificate store:",
      "   sudo update-ca-certificates",
    ],
  },
  {
    platform: "Firefox",
    steps: [
      "1. Download the CA certificate (PEM) using the button above",
      "2. Open Firefox Settings > Privacy & Security",
      '3. Scroll to "Certificates" and click "View Certificates..."',
      '4. Go to the "Authorities" tab',
      '5. Click "Import..." and select the .pem file',
      '6. Check "Trust this CA to identify websites"',
      "7. Click OK",
    ],
  },
  {
    platform: "Chrome / Edge (uses OS store)",
    steps: [
      "Chrome and Edge use the operating system's certificate store.",
      "Follow the instructions for your OS above (macOS, Windows, or Linux).",
      "After installing, restart the browser for changes to take effect.",
    ],
  },
  {
    platform: "curl / CLI tools",
    steps: [
      "Use the --cacert flag to specify the CA certificate:",
      "  curl --cacert yorishiro-ca.pem --proxy http://127.0.0.1:8080 https://example.com",
      "",
      "Or set the environment variable:",
      "  export SSL_CERT_FILE=/path/to/yorishiro-ca.pem",
      "  export REQUESTS_CA_BUNDLE=/path/to/yorishiro-ca.pem  # for Python requests",
      "  export NODE_EXTRA_CA_CERTS=/path/to/yorishiro-ca.pem  # for Node.js",
    ],
  },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

interface CACertPanelProps {
  onRefresh: () => void;
}

export function CACertPanel({ onRefresh }: CACertPanelProps) {
  const { addToast } = useToast();
  const { execute, loading: executing } = useExecute();
  const [showConfirm, setShowConfirm] = useState(false);
  const [expandedPlatform, setExpandedPlatform] = useState<string | null>(null);

  const {
    data: certData,
    loading,
    error,
    refetch,
  } = useQuery("ca_cert");

  const handleDownload = useCallback(() => {
    if (!certData?.pem) return;
    downloadPem(certData.pem, "yorishiro-ca.pem");
    addToast({ type: "success", message: "CA certificate downloaded" });
  }, [certData, addToast]);

  const handleRegenerate = useCallback(async () => {
    setShowConfirm(false);
    try {
      await execute({
        action: "regenerate_ca_cert",
        params: {},
      });
      addToast({
        type: "success",
        message: "CA certificate regenerated. Re-install the new certificate in your OS/browser.",
      });
      refetch();
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to regenerate CA: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [execute, addToast, refetch, onRefresh]);

  const togglePlatform = useCallback((platform: string) => {
    setExpandedPlatform((prev) => (prev === platform ? null : platform));
  }, []);

  if (loading && !certData) {
    return (
      <div className="settings-loading">
        <Spinner size="md" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="settings-error">
        Error loading CA certificate: {error.message}
      </div>
    );
  }

  if (!certData) return null;

  const expiringSoon = isExpiringSoon(certData.not_after, 30);

  return (
    <div className="settings-section">
      {/* Certificate info card */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">CA Certificate</span>
          <div className="settings-card-actions">
            <Button variant="primary" size="sm" onClick={handleDownload}>
              Download PEM
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={() => setShowConfirm(true)}
              disabled={executing}
            >
              Regenerate
            </Button>
          </div>
        </div>
        <div className="settings-card-body">
          <div className="ca-cert-details">
            <div className="ca-cert-row">
              <span className="ca-cert-label">Subject</span>
              <span className="ca-cert-value">{certData.subject}</span>
            </div>
            <div className="ca-cert-row">
              <span className="ca-cert-label">Fingerprint (SHA-256)</span>
              <span className="ca-cert-value ca-cert-fingerprint">
                {certData.fingerprint}
              </span>
            </div>
            <div className="ca-cert-row">
              <span className="ca-cert-label">Valid Until</span>
              <span className={`ca-cert-value ${expiringSoon ? "ca-cert-expiring" : ""}`}>
                {formatDate(certData.not_after)}
                {expiringSoon && " (expiring soon)"}
              </span>
            </div>
            <div className="ca-cert-row">
              <span className="ca-cert-label">Persisted</span>
              <span className="ca-cert-value">
                {certData.persisted ? "Yes" : "No (ephemeral)"}
              </span>
            </div>
            {certData.cert_path && (
              <div className="ca-cert-row">
                <span className="ca-cert-label">File Path</span>
                <span className="ca-cert-value ca-cert-path">{certData.cert_path}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Installation instructions */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Installation Instructions</span>
        </div>
        <div className="settings-card-body">
          <div className="ca-cert-install">
            {INSTALL_INSTRUCTIONS.map((inst) => (
              <div key={inst.platform} className="ca-cert-install-section">
                <button
                  className="ca-cert-install-toggle"
                  onClick={() => togglePlatform(inst.platform)}
                  type="button"
                >
                  <span className="ca-cert-install-arrow">
                    {expandedPlatform === inst.platform ? "\u25BC" : "\u25B6"}
                  </span>
                  <span className="ca-cert-install-platform">{inst.platform}</span>
                </button>
                {expandedPlatform === inst.platform && (
                  <div className="ca-cert-install-steps">
                    {inst.steps.map((step, i) => (
                      <div key={i} className="ca-cert-install-step">
                        {step}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Regenerate confirmation dialog */}
      {showConfirm && (
        <div className="settings-confirm-overlay" onClick={() => setShowConfirm(false)}>
          <div className="settings-confirm-dialog" onClick={(e) => e.stopPropagation()}>
            <h3 className="settings-confirm-title">Regenerate CA Certificate?</h3>
            <p className="settings-confirm-message">
              This will generate a new CA certificate and invalidate the current one.
              All previously issued server certificates will no longer be trusted.
              You will need to re-install the new CA certificate in your OS and/or browser.
            </p>
            <div className="settings-confirm-actions">
              <Button variant="secondary" size="sm" onClick={() => setShowConfirm(false)}>
                Cancel
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={handleRegenerate}
                disabled={executing}
              >
                {executing ? "Regenerating..." : "Regenerate"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
