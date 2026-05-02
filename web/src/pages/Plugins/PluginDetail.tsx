/**
 * PluginDetail — Per-plugin view showing the (protocol, event, phase)
 * registrations table plus the Vars map.
 *
 * Vars values are rendered verbatim. Server-side redaction (the literal
 * "<redacted>" string applied per redact_keys) flows through unchanged so
 * analysts know which fields were withheld.
 */

import { useMemo } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Table } from "../../components/ui/Table.js";
import { formatVarsValue } from "../../lib/mcp/dispatch.js";
import { usePluginIntrospect } from "../../lib/mcp/hooks.js";
import "./Plugins.css";

export function PluginDetail() {
  const { name: rawName } = useParams<{ name: string }>();
  const navigate = useNavigate();
  const decodedName = rawName ? decodeURIComponent(rawName) : "";

  const { data, loading, error, refetch } = usePluginIntrospect();

  const plugin = useMemo(() => {
    const list = data?.plugins ?? [];
    return list.find((p) => p?.name === decodedName) ?? null;
  }, [data, decodedName]);

  const handleBack = () => navigate("/plugins");

  if (loading && !data) {
    return (
      <div className="page plugins-page">
        <div className="plugins-loading">
          <Spinner size="md" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page plugins-page">
        <div className="plugins-error">
          Failed to load plugins: {error.message}
        </div>
        <Button variant="secondary" size="sm" onClick={handleBack}>
          Back to Plugins
        </Button>
      </div>
    );
  }

  if (!plugin) {
    return (
      <div className="page plugins-page">
        <div className="plugins-empty">
          Plugin "{decodedName}" not found.
        </div>
        <Button variant="secondary" size="sm" onClick={handleBack}>
          Back to Plugins
        </Button>
      </div>
    );
  }

  const registrations = plugin.registrations ?? [];
  const varsEntries = plugin.vars ? Object.entries(plugin.vars) : [];

  return (
    <div className="page plugins-page">
      <div className="plugins-back-row">
        <Button variant="ghost" size="sm" onClick={handleBack}>
          &larr; Plugins
        </Button>
      </div>

      <div className="plugins-header">
        <div className="plugins-header-top">
          <div>
            <h1 className="page-title">{plugin.name}</h1>
            <div className="plugins-detail-meta">
              <Badge variant={plugin.enabled ? "success" : "default"}>
                {plugin.enabled ? "enabled" : "disabled"}
              </Badge>
              {plugin.path && (
                <span className="plugins-detail-path">{plugin.path}</span>
              )}
            </div>
          </div>
          <Button variant="secondary" size="sm" onClick={() => refetch()}>
            Refresh
          </Button>
        </div>
      </div>

      <section className="plugins-section">
        <h2 className="plugins-section-title">Registrations</h2>
        {registrations.length === 0 ? (
          <div className="plugins-empty-section">
            No register_hook calls recorded for this plugin.
          </div>
        ) : (
          <div className="plugins-table-wrapper">
            <Table className="plugins-table">
              <thead>
                <tr>
                  <th>Protocol</th>
                  <th>Event</th>
                  <th>Phase</th>
                </tr>
              </thead>
              <tbody>
                {registrations.map((reg, idx) => (
                  <tr key={`${reg.protocol}-${reg.event}-${reg.phase}-${idx}`}>
                    <td className="plugins-cell-mono">
                      {reg.protocol || "-"}
                    </td>
                    <td className="plugins-cell-mono">{reg.event || "-"}</td>
                    <td>
                      <Badge variant="info">{reg.phase || "-"}</Badge>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </section>

      <section className="plugins-section">
        <h2 className="plugins-section-title">Vars</h2>
        {varsEntries.length === 0 ? (
          <div className="plugins-empty-section">
            No PluginConfig.Vars set for this plugin.
          </div>
        ) : (
          <div className="plugins-table-wrapper">
            <Table className="plugins-table">
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {varsEntries.map(([key, value]) => (
                  <tr key={key}>
                    <td className="plugins-cell-mono">{key}</td>
                    <td className="plugins-cell-value">
                      {formatVarsValue(value)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
            <p className="plugins-vars-note">
              Values shown verbatim. Server-side redaction (per redact_keys)
              is rendered as the literal string{" "}
              <code>&lt;redacted&gt;</code>.
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
