/**
 * FlowDetailHTTPMessage — Renders the request/response panels for HTTP/1.x,
 * HTTPS, and HTTP/2 (including gRPC and gRPC-Web, which ride on HTTP/2 wire
 * frames). Includes the original-vs-modified variant diff.
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
import { Http2PseudoHeaders, filterRegularHeaders } from "./Http2Info.js";
import { RawBytesViewer } from "./RawBytesViewer.js";

// ---------------------------------------------------------------------------
// Tab definitions (kept local to the HTTP panel; HTTP/2 adds a Pseudo-Headers
// tab the other protocols don't need).
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

const REQUEST_TABS_H2 = [
  { id: "pseudo", label: "Pseudo-Headers" },
  { id: "headers", label: "Headers" },
  { id: "body", label: "Body" },
];

const REQUEST_TABS_H2_RAW = [
  { id: "pseudo", label: "Pseudo-Headers" },
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

const RESPONSE_TABS_H2 = [
  { id: "pseudo", label: "Pseudo-Headers" },
  { id: "headers", label: "Headers" },
  { id: "body", label: "Body" },
];

const RESPONSE_TABS_H2_RAW = [
  { id: "pseudo", label: "Pseudo-Headers" },
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

  const isH2 = flow.protocol === "HTTP/2";
  const hasRawReq = !!flow.raw_request;
  const hasRawResp = !!flow.raw_response;
  const reqTabs = isH2
    ? hasRawReq
      ? REQUEST_TABS_H2_RAW
      : REQUEST_TABS_H2
    : hasRawReq
      ? REQUEST_TABS_RAW
      : REQUEST_TABS;
  const resTabs = isH2
    ? hasRawResp
      ? RESPONSE_TABS_H2_RAW
      : RESPONSE_TABS_H2
    : hasRawResp
      ? RESPONSE_TABS_RAW
      : RESPONSE_TABS;

  // For HTTP/2, separate pseudo-headers from regular headers.
  const displayReqHeaders = isH2
    ? filterRegularHeaders(flow.request_headers)
    : flow.request_headers;
  const displayRespHeaders = isH2
    ? filterRegularHeaders(flow.response_headers)
    : flow.response_headers;

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
                {requestTab === "pseudo" && isH2 && (
                  <Http2PseudoHeaders
                    headers={flow.original_request.headers}
                    type="request"
                  />
                )}
                {requestTab === "headers" && (
                  <HeadersTable
                    headers={
                      isH2
                        ? filterRegularHeaders(
                            flow.original_request.headers,
                          )
                        : flow.original_request.headers
                    }
                  />
                )}
                {requestTab === "body" && (
                  <BodyViewer
                    body={flow.original_request.body}
                    encoding={flow.original_request.body_encoding}
                    truncated={false}
                    headers={flow.original_request.headers}
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
                {requestTab === "pseudo" && isH2 && (
                  <Http2PseudoHeaders
                    headers={flow.request_headers}
                    type="request"
                  />
                )}
                {requestTab === "headers" && (
                  <HeadersTable headers={displayReqHeaders} />
                )}
                {requestTab === "body" && (
                  <BodyViewer
                    body={flow.request_body}
                    encoding={flow.request_body_encoding}
                    truncated={flow.request_body_truncated}
                    headers={flow.request_headers}
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
                {responseTab === "pseudo" && isH2 && (
                  <Http2PseudoHeaders
                    headers={flow.original_response.headers}
                    type="response"
                  />
                )}
                {responseTab === "headers" && (
                  <HeadersTable
                    headers={
                      isH2
                        ? filterRegularHeaders(
                            flow.original_response.headers,
                          )
                        : flow.original_response.headers
                    }
                  />
                )}
                {responseTab === "body" && (
                  <BodyViewer
                    body={flow.original_response.body}
                    encoding={flow.original_response.body_encoding}
                    truncated={flow.original_response.body_truncated}
                    headers={flow.original_response.headers}
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
                {responseTab === "pseudo" && isH2 && (
                  <Http2PseudoHeaders
                    headers={flow.response_headers}
                    type="response"
                  />
                )}
                {responseTab === "headers" && (
                  <HeadersTable headers={displayRespHeaders} />
                )}
                {responseTab === "body" && (
                  <BodyViewer
                    body={flow.response_body}
                    encoding={flow.response_body_encoding}
                    truncated={flow.response_body_truncated}
                    headers={flow.response_headers}
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
              {requestTab === "pseudo" && isH2 && (
                <Http2PseudoHeaders
                  headers={flow.request_headers}
                  type="request"
                />
              )}
              {requestTab === "headers" && (
                <HeadersTable headers={displayReqHeaders} />
              )}
              {requestTab === "body" && (
                <BodyViewer
                  body={flow.request_body}
                  encoding={flow.request_body_encoding}
                  truncated={flow.request_body_truncated}
                  headers={flow.request_headers}
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
                {responseTab === "pseudo" && isH2 && (
                  <Http2PseudoHeaders
                    headers={flow.response_headers}
                    type="response"
                  />
                )}
                {responseTab === "headers" && (
                  <HeadersTable headers={displayRespHeaders} />
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
                      body={flow.response_body}
                      encoding={flow.response_body_encoding}
                      truncated={flow.response_body_truncated}
                      headers={flow.response_headers}
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
                {flow.state === "error"
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
