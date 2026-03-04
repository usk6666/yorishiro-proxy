import { useCallback, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "../../components/ui/Badge.js";
import { Button } from "../../components/ui/Button.js";
import { Spinner } from "../../components/ui/Spinner.js";
import { Table } from "../../components/ui/Table.js";
import { useToast } from "../../components/ui/Toast.js";
import { useMacro, useQuery } from "../../lib/mcp/hooks.js";
import type { MacroDeleteResult, MacrosEntry } from "../../lib/mcp/types.js";
import "./MacrosPage.css";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return ts;
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function MacrosPage() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { macro: macroAction, loading: actionLoading } = useMacro();

  // --- Query macros list ---
  const { data, loading, error, refetch } = useQuery("macros", {
    pollInterval: 5000,
  });

  const macros = data?.macros ?? [];

  // --- Delete confirmation state ---
  const [deletingName, setDeletingName] = useState<string | null>(null);

  // --- Row click -> navigate to detail ---
  const handleRowClick = useCallback(
    (macro: MacrosEntry) => {
      navigate(`/macros/${encodeURIComponent(macro.name)}`);
    },
    [navigate],
  );

  // --- Run macro ---
  const handleRun = useCallback(
    async (e: React.MouseEvent, name: string) => {
      e.stopPropagation();
      try {
        await macroAction({
          action: "run_macro",
          params: { name },
        });
        addToast({ type: "success", message: `Macro "${name}" executed successfully` });
        refetch();
      } catch (err) {
        addToast({
          type: "error",
          message: `Failed to run macro: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    },
    [macroAction, addToast, refetch],
  );

  // --- Delete macro ---
  const handleDeleteClick = useCallback(
    (e: React.MouseEvent, name: string) => {
      e.stopPropagation();
      setDeletingName(name);
    },
    [],
  );

  const handleDeleteConfirm = useCallback(async () => {
    if (!deletingName) return;
    try {
      await macroAction<MacroDeleteResult>({
        action: "delete_macro",
        params: { name: deletingName },
      });
      addToast({ type: "success", message: `Macro "${deletingName}" deleted` });
      setDeletingName(null);
      refetch();
    } catch (err) {
      addToast({
        type: "error",
        message: `Failed to delete macro: ${err instanceof Error ? err.message : String(err)}`,
      });
      setDeletingName(null);
    }
  }, [deletingName, macroAction, addToast, refetch]);

  const handleDeleteCancel = useCallback(() => {
    setDeletingName(null);
  }, []);

  return (
    <div className="page macros-page">
      <div className="macros-header">
        <div className="macros-header-top">
          <div>
            <h1 className="page-title">Macros</h1>
            <p className="page-description">
              Define and execute multi-step request sequences.
            </p>
          </div>
          <Button
            variant="primary"
            onClick={() => navigate("/macros/new")}
          >
            New Macro
          </Button>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="macros-error">
          Error loading macros: {error.message}
        </div>
      )}

      {/* Loading state (initial) */}
      {loading && !data && (
        <div className="macros-loading">
          <Spinner size="lg" />
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && data && macros.length === 0 && (
        <div className="macros-empty">
          <span>No macros defined.</span>
          <span>Create a new macro to automate multi-step request sequences.</span>
        </div>
      )}

      {/* Macros table */}
      {macros.length > 0 && (
        <div className="macros-table-wrapper">
          <Table className="macros-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Description</th>
                <th>Steps</th>
                <th>Created</th>
                <th>Updated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {macros.map((m) => (
                <tr
                  key={m.name}
                  className="macros-row"
                  onClick={() => handleRowClick(m)}
                >
                  <td className="macros-cell-name">{m.name}</td>
                  <td className="macros-cell-desc">
                    {m.description || <span className="macros-text-muted">--</span>}
                  </td>
                  <td>
                    <Badge variant="default">{m.step_count} steps</Badge>
                  </td>
                  <td className="macros-cell-time">
                    {formatTimestamp(m.created_at)}
                  </td>
                  <td className="macros-cell-time">
                    {formatTimestamp(m.updated_at)}
                  </td>
                  <td className="macros-cell-actions">
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={(e) => handleRun(e, m.name)}
                      disabled={actionLoading}
                    >
                      Run
                    </Button>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigate(`/macros/${encodeURIComponent(m.name)}`);
                      }}
                    >
                      Edit
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={(e) => handleDeleteClick(e, m.name)}
                      disabled={actionLoading}
                    >
                      Delete
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>
        </div>
      )}

      {/* Delete confirmation dialog */}
      {deletingName && (
        <div className="macros-dialog-overlay" onClick={handleDeleteCancel}>
          <div className="macros-dialog" onClick={(e) => e.stopPropagation()}>
            <h3 className="macros-dialog-title">Delete Macro</h3>
            <p className="macros-dialog-body">
              Are you sure you want to delete macro &quot;{deletingName}&quot;?
              This action cannot be undone.
            </p>
            <div className="macros-dialog-actions">
              <Button variant="secondary" size="sm" onClick={handleDeleteCancel}>
                Cancel
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={handleDeleteConfirm}
                disabled={actionLoading}
              >
                {actionLoading ? "Deleting..." : "Delete"}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
