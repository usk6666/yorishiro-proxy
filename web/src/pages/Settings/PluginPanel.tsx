import { useCallback, useEffect, useState } from "react";
import { Button, Spinner, useToast } from "../../components/ui/index.js";
import { usePlugin } from "../../lib/mcp/hooks.js";
import type {
  PluginInfo,
  PluginListResult,
  PluginReloadResult,
  PluginToggleResult,
} from "../../lib/mcp/types.js";

/**
 * PluginPanel — manage Starlark plugins (list, enable/disable, reload).
 *
 * Standalone panel that fetches plugin data directly via the plugin MCP tool
 * (not dependent on the config/status queries used by other Settings tabs).
 */
export function PluginPanel() {
  const { addToast } = useToast();
  const { plugin, loading } = usePlugin();

  const [plugins, setPlugins] = useState<PluginInfo[]>([]);
  const [initialLoading, setInitialLoading] = useState(true);
  const [fetchError, setFetchError] = useState<Error | null>(null);

  const fetchPlugins = useCallback(async () => {
    try {
      const result = await plugin<PluginListResult>({ action: "list" });
      setPlugins(result.plugins ?? []);
      setFetchError(null);
    } catch (err) {
      setFetchError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      setInitialLoading(false);
    }
  }, [plugin]);

  useEffect(() => {
    fetchPlugins();
  }, [fetchPlugins]);

  const handleToggle = useCallback(
    async (name: string, currentEnabled: boolean) => {
      const action = currentEnabled ? "disable" : "enable";
      try {
        const result = await plugin<PluginToggleResult>({
          action,
          params: { name },
        });
        addToast({
          type: "success",
          message: `Plugin "${result.name}" ${result.enabled ? "enabled" : "disabled"}`,
        });
        fetchPlugins();
      } catch (err) {
        addToast({
          type: "error",
          message: `Failed to ${action} plugin: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    },
    [plugin, addToast, fetchPlugins],
  );

  const handleReload = useCallback(
    async (name: string) => {
      try {
        const result = await plugin<PluginReloadResult>({
          action: "reload",
          params: { name },
        });
        addToast({
          type: "success",
          message: result.message,
        });
        fetchPlugins();
      } catch (err) {
        addToast({
          type: "error",
          message: `Failed to reload plugin: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    },
    [plugin, addToast, fetchPlugins],
  );

  const handleReloadAll = useCallback(async () => {
    try {
      const result = await plugin<PluginReloadResult>({
        action: "reload",
        params: {},
      });
      addToast({
        type: "success",
        message: result.message,
      });
      fetchPlugins();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to reload plugins: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [plugin, addToast, fetchPlugins]);

  if (initialLoading) {
    return (
      <div className="settings-loading">
        <Spinner size="md" />
      </div>
    );
  }

  if (fetchError) {
    return (
      <div className="settings-error">
        Error loading plugins: {fetchError.message}
      </div>
    );
  }

  return (
    <div className="settings-section">
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">
            Plugins ({plugins.length})
          </span>
          <div className="settings-card-actions">
            <Button
              variant="secondary"
              size="sm"
              onClick={handleReloadAll}
              disabled={loading || plugins.length === 0}
            >
              Reload All
            </Button>
          </div>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Starlark plugins extend proxy behavior via lifecycle hooks.
            Plugin registration and removal is managed through the configuration file.
          </p>

          {plugins.length > 0 ? (
            <div className="settings-item-list">
              {plugins.map((p) => (
                <div
                  key={p.name}
                  className={`settings-rule${p.enabled ? "" : " settings-rule--disabled"}`}
                >
                  <div className="settings-rule-info">
                    <span className="settings-rule-id">{p.name}</span>
                    <span className="settings-rule-detail">
                      {p.protocol}{p.hooks.length > 0 ? ` \u2014 ${p.hooks.join(", ")}` : ""}
                    </span>
                  </div>
                  <div className="settings-rule-actions">
                    <label className="settings-toggle">
                      <input
                        type="checkbox"
                        checked={p.enabled}
                        onChange={() => handleToggle(p.name, p.enabled)}
                        disabled={loading}
                      />
                      <span className="settings-toggle-slider" />
                    </label>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => handleReload(p.name)}
                      disabled={loading}
                    >
                      Reload
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="settings-empty">
              No plugins registered
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
