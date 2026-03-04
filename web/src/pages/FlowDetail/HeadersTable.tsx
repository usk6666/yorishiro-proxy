/**
 * HeadersTable — Displays HTTP headers as a key-value table.
 */

import "./FlowDetailPage.css";

export interface HeadersTableProps {
  headers: Record<string, string[]> | undefined;
}

export function HeadersTable({ headers }: HeadersTableProps) {
  if (!headers || Object.keys(headers).length === 0) {
    return <div className="sd-empty-section">No headers</div>;
  }

  return (
    <div className="sd-headers-table-wrapper">
      <table className="sd-headers-table">
        <thead>
          <tr>
            <th>Header</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(headers).map(([key, values]) =>
            values.map((value, idx) => (
              <tr key={`${key}-${idx}`}>
                <td className="sd-header-key">{key}</td>
                <td className="sd-header-value">{value}</td>
              </tr>
            )),
          )}
        </tbody>
      </table>
    </div>
  );
}
