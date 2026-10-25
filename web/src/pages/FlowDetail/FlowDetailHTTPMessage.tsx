/**
 * FlowDetailHTTPMessage — Renders the request/response panels for HTTP flows
 * (HTTP/1.x and HTTP/2) and the HTTP side of WS / gRPC / gRPC-Web / SSE
 * streams. Includes the original-vs-modified variant diff.
 *
 * HTTP/2 needs no separate pseudo-header view: the recorder moves
 * :method / :path / :authority / :scheme / :status into the message fields,
 * so recorded headers never contain them and the Headers tab shows them as
 * recorded for every version.
 *
 * Extracted from FlowDetailPage as part of RFC-001 N8 (USK-668) so the parent
 * page can dispatch on protocol without keeping per-protocol logic inline.
 */

import { useState } from "react";
import { Badge } from "../../components/ui/Badge.js";
import { Tabs } from "../../components/ui/Tabs.js";
import type { FlowDetailResult } from "../../lib/mcp/types.js";
import { hasResponse } from "../../lib/mcp/dispatch.js";
import { BodyViewer } from "./BodyViewer.js";
import "./FlowDetailPage.css";
import { HeadersTable } from "./HeadersTable.js";
import { RawBytesViewer } from "./RawBytesViewer.js";

// ---------------------------------------------------------------------------
// Tab definitions
// ---------------------------------------------------------------------------

const REQUEST_TABS = [
  { id: "headers", label: "Headers" },
  { id: "body", label: "Body" },
];

const REQUEST_TABS_RAW = [
  { id: "headers", label: "Headers" },
  { id: "body", label: "Body" },
  { id: "raw", label: "Raw" },
];

const RESPONSE_TABS = [
  { id: "headers", label: "Headers" },
  { id: "body", label: "Body" },
];

const RESPONSE_TABS_RAW = [
  { id: "headers", label: "Headers" },
  { id: "body", label: "Body" },
  { id: "raw", label: "Raw" },
];

export interface FlowDetailHTTPMessageProps {
  flow: FlowDetailResult;
}

export function FlowDetailHTTPMessage({ flow }: FlowDetailHTTPMessageProps) {
  const [requestTab, setRequestTab] = useState("headers");
  const [responseTab, setResponseTab] = useState("headers");

  const reqTabs = flow.raw_request ? REQUEST_TABS_RAW : REQUEST_TABS;
  const resTabs = flow.raw_response ? RESPONSE_TABS_RAW : RESPONSE_TABS;

  const responseStatus = flow.response_status_code ?? 0;
  const isSseStreaming = flow.tags?.streaming_type === "sse";

  return (
    <>
      {/* Variant diff: original vs modified request */}
      {flow.original_request && (
        <div className="sd-section">
          <h2 className="sd-section-title">
            Request Modification (Original vs Modified)
          </h2>
          <div className="sd-panels">
            {/* Original request */}
            <div className="sd-panel">
              <div className="sd-panel-header">
                <span className="sd-panel-title">Original Request</span>
                <Badge variant="default">original</Badge>
              </div>
              <Tabs
                tabs={reqTabs}
                activeTab={requestTab}
                onTabChange={setRequestTab}
              >
                {requestTab === "headers" && (
                  <HeadersTable
                    headers={flow.original_request.headers}
                  />
                )}
                {requestTab === "body" && (
                  <BodyViewer
                    key={`${flow.id}-original-request`}
                    body={flow.original_request.body}
                    encoding={flow.original_request.body_encoding}
                    truncated={flow.original_request.body_truncated ?? false}
                    headers={flow.original_request.headers}
                    bodyDecoded={flow.original_request.body_decoded}
                    bodyDecodedEncoding={flow.original_request.body_decoded_encoding}
                    bodyEncodingApplied={flow.original_request.body_encoding_applied}
                    bodyDecodeAnomaly={flow.original_request.body_decode_anomaly}
                  />
                )}
                {requestTab === "raw" && flow.raw_request && (
                  <RawBytesViewer
                    rawBytes={flow.raw_request}
                    label="Raw Request"
                  />
                )}
              </Tabs>
            </div>

            {/* Modified request */}
            <div className="sd-panel">
              <div className="sd-panel-header">
                <span className="sd-panel-title">Modified Request</span>
                <Badge variant="warning">modified</Badge>
              </div>
              <Tabs
                tabs={reqTabs}
                activeTab={requestTab}
                onTabChange={setRequestTab}
              >
                {requestTab === "headers" && (
                  <HeadersTable headers={flow.request_headers} />
                )}
                {requestTab === "body" && (
                  <BodyViewer
                    key={`${flow.id}-modified-request`}
                    body={flow.request_body}
                    encoding={flow.request_body_encoding}
                    truncated={flow.request_body_truncated}
                    headers={flow.request_headers}
                    bodyDecoded={flow.request_body_decoded}
                    bodyDecodedEncoding={flow.request_body_decoded_encoding}
                    bodyEncodingApplied={flow.request_body_encoding_applied}
                    bodyDecodeAnomaly={flow.request_body_decode_anomaly}
                  />
                )}
                {requestTab === "raw" && flow.raw_request && (
                  <RawBytesViewer
                    rawBytes={flow.raw_request}
                    label="Raw Request"
                  />
                )}
              </Tabs>
            </div>
          </div>
        </div>
      )}

      {/* Variant diff: original vs modified response */}
      {flow.original_response && (
        <div className="sd-section">
          <h2 className="sd-section-title">
            Response Modification (Original vs Modified)
          </h2>
          <div className="sd-panels">
            {/* Original response */}
            <div className="sd-panel">
              <div className="sd-panel-header">
                <span className="sd-panel-title">Original Response</span>
                <Badge variant="default">original</Badge>
                {flow.original_response.status_code > 0 && (
                  <Badge
                    variant={
                      flow.original_response.status_code < 300
                        ? "success"
                        : flow.original_response.status_code < 400
                          ? "info"
                          : flow.original_response.status_code < 500
                            ? "warning"
                            : "danger"
                    }
                  >
                    {flow.original_response.status_code}
                  </Badge>
                )}
              </div>
              <Tabs
                tabs={resTabs}
                activeTab={responseTab}
                onTabChange={setResponseTab}
              >
                {responseTab === "headers" && (
                  <HeadersTable
                    headers={flow.original_response.headers}
                  />
                )}
                {responseTab === "body" && (
                  <BodyViewer
                    key={`${flow.id}-original-response`}
                    body={flow.original_response.body}
                    encoding={flow.original_response.body_encoding}
                    truncated={flow.original_response.body_truncated}
                    headers={flow.original_response.headers}
                    bodyDecoded={flow.original_response.body_decoded}
                    bodyDecodedEncoding={flow.original_response.body_decoded_encoding}
                    bodyEncodingApplied={flow.original_response.body_encoding_applied}
                    bodyDecodeAnomaly={flow.original_response.body_decode_anomaly}
                  />
                )}
                {responseTab === "raw" && flow.raw_response && (
                  <RawBytesViewer
                    rawBytes={flow.raw_response}
                    label="Raw Response"
                  />
                )}
              </Tabs>
            </div>

            {/* Modified response */}
            <div className="sd-panel">
              <div className="sd-panel-header">
                <span className="sd-panel-title">Modified Response</span>
                <Badge variant="warning">modified</Badge>
                {responseStatus > 0 && (
                  <Badge
                    variant={
                      responseStatus < 300
                        ? "success"
                        : responseStatus < 400
                          ? "info"
                          : responseStatus < 500
                            ? "warning"
                            : "danger"
                    }
                  >
                    {responseStatus}
                  </Badge>
                )}
              </div>
              <Tabs
                tabs={resTabs}
                activeTab={responseTab}
                onTabChange={setResponseTab}
              >
                {responseTab === "headers" && (
                  <HeadersTable headers={flow.response_headers} />
                )}
                {responseTab === "body" && (
                  <BodyViewer
                    key={`${flow.id}-modified-response`}
                    body={flow.response_body}
                    encoding={flow.response_body_encoding}
                    truncated={flow.response_body_truncated}
                    headers={flow.response_headers}
                    bodyDecoded={flow.response_body_decoded}
                    bodyDecodedEncoding={flow.response_body_decoded_encoding}
                    bodyEncodingApplied={flow.response_body_encoding_applied}
                    bodyDecodeAnomaly={flow.response_body_decode_anomaly}
                  />
                )}
                {responseTab === "raw" && flow.raw_response && (
                  <RawBytesViewer
                    rawBytes={flow.raw_response}
                    label="Raw Response"
                  />
                )}
              </Tabs>
            </div>
          </div>
        </div>
      )}

      {/* Request / Response panels (shown when no variant diff) */}
      <div className="sd-panels">
        {!flow.original_request && (
          <div className="sd-panel">
            <div className="sd-panel-header">
              <span className="sd-panel-title">Request</span>
            </div>
            <Tabs
              tabs={reqTabs}
              activeTab={requestTab}
              onTabChange={setRequestTab}
            >
              {requestTab === "headers" && (
                <HeadersTable headers={flow.request_headers} />
              )}
              {requestTab === "body" && (
                <BodyViewer
                  key={`${flow.id}-request`}
                  body={flow.request_body}
                  encoding={flow.request_body_encoding}
                  truncated={flow.request_body_truncated}
                  headers={flow.request_headers}
                  bodyDecoded={flow.request_body_decoded}
                  bodyDecodedEncoding={flow.request_body_decoded_encoding}
                  bodyEncodingApplied={flow.request_body_encoding_applied}
                  bodyDecodeAnomaly={flow.request_body_decode_anomaly}
                />
              )}
              {requestTab === "raw" && flow.raw_request && (
                <RawBytesViewer
                  rawBytes={flow.raw_request}
                  label="Raw Request"
                />
              )}
            </Tabs>
          </div>
        )}

        {!flow.original_response && (
          <div
            className={
              flow.original_request ? "sd-panel sd-panel--full-width" : "sd-panel"
            }
          >
            <div className="sd-panel-header">
              <span className="sd-panel-title">Response</span>
              {responseStatus > 0 && (
                <Badge
                  variant={
                    responseStatus < 300
                      ? "success"
                      : responseStatus < 400
                        ? "info"
                        : responseStatus < 500
                          ? "warning"
                          : "danger"
                  }
                >
                  {responseStatus}
                </Badge>
              )}
              {!hasResponse(flow) && (
                <Badge variant="danger">No Response</Badge>
              )}
            </div>
            {hasResponse(flow) ? (
              <Tabs
                tabs={resTabs}
                activeTab={responseTab}
                onTabChange={setResponseTab}
              >
                {responseTab === "headers" && (
                  <HeadersTable headers={flow.response_headers} />
                )}
                {responseTab === "body" &&
                  (isSseStreaming ? (
                    <div className="sd-no-response">
                      SSE (Server-Sent Events) streaming response. The
                      response body was streamed directly to the client and
                      was not recorded.
                    </div>
                  ) : (
                    <BodyViewer
                      key={`${flow.id}-response`}
                      body={flow.response_body}
                      encoding={flow.response_body_encoding}
                      truncated={flow.response_body_truncated}
                      headers={flow.response_headers}
                      bodyDecoded={flow.response_body_decoded}
                      bodyDecodedEncoding={flow.response_body_decoded_encoding}
                      bodyEncodingApplied={flow.response_body_encoding_applied}
                      bodyDecodeAnomaly={flow.response_body_decode_anomaly}
                    />
                  ))}
                {responseTab === "raw" && flow.raw_response && (
                  <RawBytesViewer
                    rawBytes={flow.raw_response}
                    label="Raw Response"
                  />
                )}
              </Tabs>
            ) : (
              <div className="sd-no-response">
                {flow.blocked_by === "intercept_cancelled"
                  ? "This request was held by an intercept rule and the connection or proxy went away before it was released or dropped."
                  : flow.state === "error"
                  ? "This flow ended with an error. No response was received from the upstream server."
                  : flow.state === "active"
                    ? "This flow is still active. The response has not been received yet."
                    : flow.blocked_by === "intercept_drop"
                      ? "This request was dropped by an intercept rule. No response was generated."
                      : "No response data available for this flow."}
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}
