import { useCallback, useState } from "react";
import { Badge, Button, useDialog, useToast } from "../../components/ui/index.js";
import { useConfigure } from "../../lib/mcp/hooks.js";
import type { StatusResult } from "../../lib/mcp/types.js";

/** Available TLS fingerprint presets. */
const PRESETS = [
  { value: "none", label: "None (Default Go TLS)", description: "Standard Go crypto/tls stack without fingerprint spoofing" },
  { value: "chrome", label: "Chrome (Latest)", description: "Mimics Chrome's TLS ClientHello fingerprint" },
  { value: "firefox", label: "Firefox (Latest)", description: "Mimics Firefox's TLS ClientHello fingerprint" },
  { value: "safari", label: "Safari (Latest)", description: "Mimics Safari's TLS ClientHello fingerprint" },
  { value: "edge", label: "Edge", description: "Mimics Microsoft Edge's TLS ClientHello fingerprint" },
  { value: "random", label: "Random", description: "Randomly selects a browser fingerprint for each connection" },
] as const;

interface TlsFingerprintProps {
  status: StatusResult;
  onRefresh: () => void;
}

/**
 * TlsFingerprint — configure TLS ClientHello fingerprint profile for upstream connections.
 *
 * Uses the status resource to read the current fingerprint profile,
 * and the configure tool to apply changes.
 */
export function TlsFingerprint({ status, onRefresh }: TlsFingerprintProps) {
  const { addToast } = useToast();
  const { showDialog } = useDialog();
  const { configure, loading } = useConfigure();

  const currentProfile = status.tls_fingerprint || "none";
  const [selectedProfile, setSelectedProfile] = useState(currentProfile);

  const currentPreset = PRESETS.find((p) => p.value === currentProfile);
  const selectedPreset = PRESETS.find((p) => p.value === selectedProfile);

  const hasChanges = selectedProfile !== currentProfile;

  const handleApply = useCallback(async () => {
    if (!hasChanges) return;

    const isRunning = status.running;
    if (isRunning) {
      const confirmed = await showDialog({
        title: "Change TLS Fingerprint",
        message:
          "Changing the TLS fingerprint profile will affect new connections. " +
          "Existing connections will not be interrupted. Continue?",
        variant: "confirm",
        confirmLabel: "Apply",
      });
      if (!confirmed) return;
    }

    try {
      await configure({
        tls_fingerprint: selectedProfile,
      });
      addToast({
        type: "success",
        message: `TLS fingerprint changed to "${selectedPreset?.label ?? selectedProfile}"`,
      });
      if (isRunning) {
        addToast({
          type: "info",
          message: "New fingerprint will apply to new connections. Active listeners are not affected.",
        });
      }
      onRefresh();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to change TLS fingerprint: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [hasChanges, selectedProfile, selectedPreset, status.running, configure, addToast, showDialog, onRefresh]);

  const handleReset = useCallback(() => {
    setSelectedProfile(currentProfile);
  }, [currentProfile]);

  return (
    <div className="settings-section">
      {/* Current profile display */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Current Profile</span>
          <Badge variant={currentProfile === "none" ? "default" : "info"}>
            {currentPreset?.label ?? currentProfile}
          </Badge>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            {currentPreset?.description ?? "Unknown profile"}
          </p>
          <p className="settings-section-desc" style={{ marginBottom: 0 }}>
            TLS fingerprint spoofing uses uTLS to mimic a browser&apos;s TLS ClientHello,
            evading JA3/JA4-based bot detection on upstream HTTPS connections.
          </p>
        </div>
      </div>

      {/* Preset selection */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Preset Selection</span>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Select a browser profile to mimic, or choose &quot;None&quot; to use the default Go TLS stack.
          </p>

          <div className="settings-item-list">
            {PRESETS.map((preset) => (
              <label
                key={preset.value}
                className={`settings-rule${selectedProfile === preset.value ? "" : " settings-rule--disabled"}`}
                style={{ cursor: "pointer" }}
              >
                <div className="settings-rule-info">
                  <span className="settings-rule-id">{preset.label}</span>
                  <span className="settings-rule-detail">{preset.description}</span>
                </div>
                <div className="settings-rule-actions">
                  <input
                    type="radio"
                    name="tls-fingerprint-preset"
                    value={preset.value}
                    checked={selectedProfile === preset.value}
                    onChange={() => setSelectedProfile(preset.value)}
                    disabled={loading}
                    style={{ accentColor: "var(--accent-primary)" }}
                  />
                </div>
              </label>
            ))}
          </div>

          {/* Apply / Reset buttons */}
          <div className="settings-add-form-actions" style={{ marginTop: "var(--space-lg)" }}>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleReset}
              disabled={!hasChanges || loading}
            >
              Reset
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleApply}
              disabled={!hasChanges || loading}
            >
              {loading ? "Applying..." : "Apply"}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
