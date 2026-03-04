import { useCallback, useState } from "react";
import { Button, Input, useToast } from "../../components/ui/index.js";
import type { TargetRule } from "../../lib/mcp/types.js";

interface AddRuleFormProps {
  title: string;
  onSubmit: (rule: TargetRule) => void;
  onCancel: () => void;
  loading: boolean;
}

/**
 * AddRuleForm -- form for adding a new TargetRule.
 *
 * Fields:
 * - hostname (required)
 * - ports (comma-separated numbers)
 * - path_prefix
 * - schemes (checkboxes: http, https)
 */
export function AddRuleForm({ title, onSubmit, onCancel, loading }: AddRuleFormProps) {
  const { addToast } = useToast();

  const [hostname, setHostname] = useState("");
  const [ports, setPorts] = useState("");
  const [pathPrefix, setPathPrefix] = useState("");
  const [httpChecked, setHttpChecked] = useState(false);
  const [httpsChecked, setHttpsChecked] = useState(false);

  const handleSubmit = useCallback(() => {
    const trimmedHostname = hostname.trim();
    if (!trimmedHostname) {
      addToast({ type: "warning", message: "Hostname is required" });
      return;
    }

    const rule: TargetRule = { hostname: trimmedHostname };

    // Parse ports
    const trimmedPorts = ports.trim();
    if (trimmedPorts) {
      const portNumbers = trimmedPorts
        .split(",")
        .map((p) => p.trim())
        .filter((p) => p !== "")
        .map((p) => parseInt(p, 10));

      if (portNumbers.some((p) => isNaN(p) || p < 1 || p > 65535)) {
        addToast({ type: "warning", message: "Invalid port number (must be 1-65535)" });
        return;
      }
      if (portNumbers.length > 0) {
        rule.ports = portNumbers;
      }
    }

    // Path prefix
    const trimmedPath = pathPrefix.trim();
    if (trimmedPath) {
      rule.path_prefix = trimmedPath;
    }

    // Schemes
    const schemes: string[] = [];
    if (httpChecked) schemes.push("http");
    if (httpsChecked) schemes.push("https");
    if (schemes.length > 0) {
      rule.schemes = schemes;
    }

    onSubmit(rule);
  }, [hostname, ports, pathPrefix, httpChecked, httpsChecked, onSubmit, addToast]);

  return (
    <div className="security-add-form">
      <div className="security-add-form-title">{title}</div>
      <div className="security-form-row">
        <Input
          label="Hostname"
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          placeholder="example.com or *.example.com"
        />
        <Input
          label="Ports"
          value={ports}
          onChange={(e) => setPorts(e.target.value)}
          placeholder="443, 8080"
        />
        <Input
          label="Path Prefix"
          value={pathPrefix}
          onChange={(e) => setPathPrefix(e.target.value)}
          placeholder="/api/"
        />
      </div>
      <div className="security-form-row">
        <div className="security-schemes-group">
          <span className="security-schemes-label">Schemes</span>
          <div className="security-schemes-options">
            <label className="security-checkbox">
              <input
                type="checkbox"
                checked={httpChecked}
                onChange={(e) => setHttpChecked(e.target.checked)}
              />
              <span>http</span>
            </label>
            <label className="security-checkbox">
              <input
                type="checkbox"
                checked={httpsChecked}
                onChange={(e) => setHttpsChecked(e.target.checked)}
              />
              <span>https</span>
            </label>
          </div>
        </div>
      </div>
      <div className="security-add-form-actions">
        <Button variant="secondary" size="sm" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="primary" size="sm" onClick={handleSubmit} disabled={loading}>
          Add
        </Button>
      </div>
    </div>
  );
}
