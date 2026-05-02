/**
 * PluginsPage — Lists pluginv2 plugins from the plugin_introspect MCP tool.
 *
 * Each row shows the plugin name, enabled flag, registration count, and a
 * link into PluginDetail. Server-side redaction applied via redact_keys is
 * displayed verbatim (the literal "<redacted>" string).
 */

import { useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Table } from "../../components/ui/Table.js";
import { sortIntrospectedPlugins } from "../../lib/mcp/dispatch.js";
import { usePluginIntrospect } from "../../lib/mcp/hooks.js";
import type { PluginIntrospectInfo } from "../../lib/mcp/types.js";
import "./Plugins.css";

export function PluginsPage() {
  const navigate = useNavigate();
  const { data, loading, error, refetch } = usePluginIntrospect();

  const plugins = useMemo(() => sortIntrospectedPlugins(data), [data]);

  const handleRowClick = useCallback(
    (plugin: PluginIntrospectInfo) => {
      navigate(`/plugins/${encodeURIComponent(plugin.name)}`);
    },
    [navigate],
  );

  return (
    <div className="page plugins-page">
      <div className="plugins-header">
        <div className="plugins-header-top">
          <div>
            <h1 className="page-title">Plugins</h1>
            <p className="page-description">
              Loaded pluginv2 plugins and their (protocol, event, phase)
              register_hook registrations.
            </p>
          </div>
          <Button variant="secondary" size="sm" onClick={() => refetch()}>
            Refresh
          </Button>
        </div>
      </div>

      {loading && plugins.length === 0 && (
        <div className="plugins-loading">
          <Spinner size="md" />
        </div>
      )}

      {error && (
        <div className="plugins-error">
          Failed to load plugins: {error.message}
        </div>
      )}

      {!loading && !error && plugins.length === 0 && (
        <div className="plugins-empty">
          No pluginv2 plugins are loaded. Add Starlark scripts to the
          configured plugins directory and reload to see them here.
        </div>
      )}

      {plugins.length > 0 && (
        <div className="plugins-table-wrapper">
          <Table className="plugins-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Enabled</th>
                <th>Registrations</th>
                <th>Path</th>
              </tr>
            </thead>
            <tbody>
              {plugins.map((plugin) => {
                const regCount = plugin.registrations?.length ?? 0;
                return (
                  <tr
                    key={plugin.name}
                    className="plugins-row"
                    onClick={() => handleRowClick(plugin)}
                  >
                    <td className="plugins-cell-name">{plugin.name}</td>
                    <td>
                      <Badge variant={plugin.enabled ? "success" : "default"}>
                        {plugin.enabled ? "enabled" : "disabled"}
                      </Badge>
                    </td>
                    <td className="plugins-cell-count">{regCount}</td>
                    <td className="plugins-cell-path">{plugin.path ?? ""}</td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        </div>
      )}
    </div>
  );
}
