import { useMemo, useState } from "react";
import { CodeViewer } from "../../components/ui/CodeViewer.js";
import { Tabs } from "../../components/ui/Tabs.js";
import type { FlowDetailResult } from "../../lib/mcp/types.js";
import type { ResendResult } from "./ResendPage.js";
import "./ResponseViewer.css";

/** Tabs for the response viewer. */
const RESPONSE_TABS = [
  { id: "body", label: "Body" },
  { id: "headers", label: "Headers" },
  { id: "diff", label: "Diff" },
];

export interface ResponseViewerProps {
  response: ResendResult;
  originalFlow: FlowDetailResult;
}

/**
 * Displays the response from a resend operation,
 * including body, headers, and a diff with the original response.
 */
export function ResponseViewer({ response, originalFlow }: ResponseViewerProps) {
  const [activeTab, setActiveTab] = useState("body");

  /** Extract Content-Type from response headers (case-insensitive). */
  const responseContentType = useMemo(() => {
    if (!response.response_headers) return "";
    for (const [key, values] of Object.entries(response.response_headers)) {
      if (key.toLowerCase() === "content-type" && values.length > 0) {
        return values[0];
      }
    }
    return "";
  }, [response.response_headers]);

  const bodyText = response.response_body_encoding === "base64"
    ? "(Binary content, base64 encoded)"
    : response.response_body || "";

  return (
    <div className="response-viewer">
      <Tabs tabs={RESPONSE_TABS} activeTab={activeTab} onTabChange={setActiveTab}>
        {activeTab === "body" && (
          <div className="response-body-view">
            {bodyText ? (
              <CodeViewer code={bodyText} contentType={responseContentType} />
            ) : (
              <div className="response-empty">(empty body)</div>
            )}
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
            originalBody={originalFlow.response_body}
            originalStatus={originalFlow.response_status_code}
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
