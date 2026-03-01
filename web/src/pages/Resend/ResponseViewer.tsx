import { useState } from "react";
import type { SessionDetailResult } from "../../lib/mcp/types.js";
import { Tabs } from "../../components/ui/Tabs.js";
import "./ResponseViewer.css";

/** Resend result shape. */
interface ResendResult {
  response_status_code?: number;
  response_headers?: Record<string, string[]>;
  response_body?: string;
  response_body_encoding?: string;
  duration_ms?: number;
  dry_run?: boolean;
}

/** Tabs for the response viewer. */
const RESPONSE_TABS = [
  { id: "body", label: "Body" },
  { id: "headers", label: "Headers" },
  { id: "diff", label: "Diff" },
];

export interface ResponseViewerProps {
  response: ResendResult;
  originalSession: SessionDetailResult;
}

/**
 * Displays the response from a resend operation,
 * including body, headers, and a diff with the original response.
 */
export function ResponseViewer({ response, originalSession }: ResponseViewerProps) {
  const [activeTab, setActiveTab] = useState("body");

  return (
    <div className="response-viewer">
      <Tabs tabs={RESPONSE_TABS} activeTab={activeTab} onTabChange={setActiveTab}>
        {activeTab === "body" && (
          <div className="response-body-view">
            <pre className="response-body-content">
              {response.response_body || "(empty body)"}
            </pre>
          </div>
        )}
        {activeTab === "headers" && (
          <div className="response-headers-view">
            {response.response_headers ? (
              <table className="response-headers-table">
                <thead>
                  <tr>
                    <th>Header</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(response.response_headers).map(([key, values]) =>
                    values.map((value, idx) => (
                      <tr key={`${key}-${idx}`}>
                        <td className="response-header-key">{key}</td>
                        <td className="response-header-value">{value}</td>
                      </tr>
                    )),
                  )}
                </tbody>
              </table>
            ) : (
              <div className="response-empty">No response headers</div>
            )}
          </div>
        )}
        {activeTab === "diff" && (
          <DiffView
            originalBody={originalSession.response_body}
            originalStatus={originalSession.response_status_code}
            newBody={response.response_body}
            newStatus={response.response_status_code}
          />
        )}
      </Tabs>
    </div>
  );
}

/** Simple line-by-line diff between original and new response. */
function DiffView({
  originalBody,
  originalStatus,
  newBody,
  newStatus,
}: {
  originalBody?: string;
  originalStatus?: number;
  newBody?: string;
  newStatus?: number;
}) {
  const origLines = (originalBody ?? "").split("\n");
  const newLines = (newBody ?? "").split("\n");
  const maxLen = Math.max(origLines.length, newLines.length);

  const statusChanged = originalStatus !== newStatus;

  return (
    <div className="diff-view">
      {statusChanged && (
        <div className="diff-status-change">
          Status code changed: <span className="diff-removed">{originalStatus ?? "?"}</span>
          {" -> "}
          <span className="diff-added">{newStatus ?? "?"}</span>
        </div>
      )}
      <pre className="diff-content">
        {Array.from({ length: maxLen }, (_, i) => {
          const origLine = origLines[i] ?? "";
          const newLine = newLines[i] ?? "";
          if (origLine === newLine) {
            return (
              <div key={i} className="diff-line diff-line--same">
                <span className="diff-line-number">{i + 1}</span>
                <span className="diff-line-content">{`  ${origLine}`}</span>
              </div>
            );
          }
          return (
            <div key={i} className="diff-line-pair">
              {origLine !== undefined && origLines[i] !== undefined && (
                <div className="diff-line diff-line--removed">
                  <span className="diff-line-number">{i + 1}</span>
                  <span className="diff-line-content">{`- ${origLine}`}</span>
                </div>
              )}
              {newLine !== undefined && newLines[i] !== undefined && (
                <div className="diff-line diff-line--added">
                  <span className="diff-line-number">{i + 1}</span>
                  <span className="diff-line-content">{`+ ${newLine}`}</span>
                </div>
              )}
            </div>
          );
        })}
      </pre>
      {origLines.length === 0 && newLines.length === 0 && (
        <div className="diff-empty">Both responses are empty.</div>
      )}
      {originalBody === newBody && !statusChanged && (
        <div className="diff-identical">Responses are identical.</div>
      )}
    </div>
  );
}
