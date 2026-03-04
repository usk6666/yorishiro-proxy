/**
 * GrpcPanel -- Structured display for gRPC flow details.
 *
 * Features:
 * - Service name / method name structured display (e.g., UserService / ListUsers)
 * - grpc-status code with human-readable label (0=OK, 1=CANCELLED, ...)
 * - Streaming type badge (Unary / Server Streaming / Client Streaming / Bidi)
 * - gRPC metadata (custom headers) dedicated table
 * - Protobuf body Base64/Hex display toggle
 */

import { useState, useMemo, useCallback } from "react";
import type { FlowDetailResult } from "../../lib/mcp/types.js";
import { Badge } from "../../components/ui/Badge.js";
import "./FlowDetailPage.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface GrpcPanelProps {
  flow: FlowDetailResult;
}

type ProtobufViewMode = "base64" | "hex";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Map of gRPC status code to human-readable label. */
const GRPC_STATUS_LABELS: Record<string, string> = {
  "0": "OK",
  "1": "CANCELLED",
  "2": "UNKNOWN",
  "3": "INVALID_ARGUMENT",
  "4": "DEADLINE_EXCEEDED",
  "5": "NOT_FOUND",
  "6": "ALREADY_EXISTS",
  "7": "PERMISSION_DENIED",
  "8": "RESOURCE_EXHAUSTED",
  "9": "FAILED_PRECONDITION",
  "10": "ABORTED",
  "11": "OUT_OF_RANGE",
  "12": "UNIMPLEMENTED",
  "13": "INTERNAL",
  "14": "UNAVAILABLE",
  "15": "DATA_LOSS",
  "16": "UNAUTHENTICATED",
};

/** Badge variant for gRPC status codes. */
function grpcStatusVariant(
  code: string,
): "success" | "danger" | "warning" | "info" | "default" {
  switch (code) {
    case "0":
      return "success";
    case "1":
    case "4":
      return "warning";
    case "5":
    case "12":
      return "info";
    default:
      return "danger";
  }
}

/** Human-readable label for gRPC streaming type. */
function streamTypeLabel(flowType: string): string {
  switch (flowType) {
    case "unary":
      return "Unary";
    case "stream":
      return "Streaming";
    case "bidirectional":
      return "Bidi Streaming";
    default:
      return flowType;
  }
}

/** Badge variant for streaming type. */
function streamTypeBadgeVariant(
  flowType: string,
): "default" | "success" | "warning" | "danger" | "info" {
  switch (flowType) {
    case "unary":
      return "default";
    case "stream":
      return "info";
    case "bidirectional":
      return "warning";
    default:
      return "default";
  }
}

/** Well-known gRPC metadata header prefixes that should be displayed in metadata table. */
const GRPC_METADATA_PREFIXES = [
  "grpc-",
  "x-",
  "authorization",
  "user-agent",
  "te",
];

/** Headers that are standard HTTP/2 pseudo-headers, not gRPC metadata. */
const EXCLUDED_HEADERS = new Set([
  ":method",
  ":path",
  ":scheme",
  ":authority",
  ":status",
  "content-type",
  "content-length",
  "accept-encoding",
]);

/** Check if a header key is gRPC metadata (custom or well-known gRPC headers). */
function isGrpcMetadata(key: string): boolean {
  const lower = key.toLowerCase();
  if (EXCLUDED_HEADERS.has(lower)) return false;
  for (const prefix of GRPC_METADATA_PREFIXES) {
    if (lower.startsWith(prefix)) return true;
  }
  // Headers starting with custom app prefixes are also metadata
  return !lower.startsWith(":");
}

/** Convert a base64 string to a hex dump display. */
function base64ToHexDump(base64: string): string {
  let bytes: Uint8Array;
  try {
    const binary = atob(base64);
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
  } catch {
    return "(Failed to decode base64 content)";
  }

  const lines: string[] = [];
  const maxBytes = Math.min(bytes.length, 4096);

  for (let offset = 0; offset < maxBytes; offset += 16) {
    const hexParts: string[] = [];
    const asciiParts: string[] = [];

    for (let i = 0; i < 16; i++) {
      if (offset + i < maxBytes) {
        const byte = bytes[offset + i];
        hexParts.push(byte.toString(16).padStart(2, "0"));
        asciiParts.push(
          byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".",
        );
      } else {
        hexParts.push("  ");
        asciiParts.push(" ");
      }
    }

    const offsetStr = offset.toString(16).padStart(8, "0");
    const hex =
      hexParts.slice(0, 8).join(" ") + "  " + hexParts.slice(8).join(" ");
    const ascii = asciiParts.join("");
    lines.push(`${offsetStr}  ${hex}  |${ascii}|`);
  }

  if (bytes.length > maxBytes) {
    lines.push(`... (${bytes.length - maxBytes} more bytes truncated)`);
  }

  return lines.join("\n");
}

/** Convert a text body to hex dump via base64 intermediate. */
function textToHexDump(text: string): string {
  try {
    const encoded = btoa(
      Array.from(new TextEncoder().encode(text))
        .map((b) => String.fromCharCode(b))
        .join(""),
    );
    return base64ToHexDump(encoded);
  } catch {
    return "(Failed to encode content for hex display)";
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** Display gRPC service and method name in a structured way. */
function ServiceMethodDisplay({
  service,
  method,
}: {
  service: string;
  method: string;
}) {
  return (
    <div className="sd-grpc-service-method">
      <div className="sd-grpc-service-method-row">
        <span className="sd-grpc-label">Service</span>
        <span className="sd-grpc-service-name">{service || "--"}</span>
      </div>
      <span className="sd-grpc-separator">/</span>
      <div className="sd-grpc-service-method-row">
        <span className="sd-grpc-label">Method</span>
        <span className="sd-grpc-method-name">{method || "--"}</span>
      </div>
    </div>
  );
}

/** Display gRPC status code with human-readable label. */
function GrpcStatusDisplay({ statusCode }: { statusCode: string }) {
  const label = GRPC_STATUS_LABELS[statusCode] ?? `CODE_${statusCode}`;
  const variant = grpcStatusVariant(statusCode);

  return (
    <div className="sd-grpc-status">
      <Badge variant={variant}>
        {statusCode} {label}
      </Badge>
    </div>
  );
}

/** Display gRPC metadata headers in a dedicated table. */
function GrpcMetadataTable({
  requestHeaders,
  responseHeaders,
}: {
  requestHeaders: Record<string, string[]> | undefined;
  responseHeaders: Record<string, string[]> | undefined;
}) {
  const requestMetadata = useMemo(() => {
    if (!requestHeaders) return [];
    return Object.entries(requestHeaders)
      .filter(([key]) => isGrpcMetadata(key))
      .flatMap(([key, values]) => values.map((v) => ({ key, value: v })));
  }, [requestHeaders]);

  const responseMetadata = useMemo(() => {
    if (!responseHeaders) return [];
    return Object.entries(responseHeaders)
      .filter(([key]) => isGrpcMetadata(key))
      .flatMap(([key, values]) => values.map((v) => ({ key, value: v })));
  }, [responseHeaders]);

  if (requestMetadata.length === 0 && responseMetadata.length === 0) {
    return <div className="sd-empty-section">No gRPC metadata</div>;
  }

  return (
    <div className="sd-grpc-metadata-tables">
      {requestMetadata.length > 0 && (
        <div className="sd-grpc-metadata-section">
          <span className="sd-grpc-metadata-section-title">
            Request Metadata
          </span>
          <div className="sd-headers-table-wrapper">
            <table className="sd-headers-table">
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {requestMetadata.map((entry, idx) => (
                  <tr key={`req-${entry.key}-${idx}`}>
                    <td className="sd-header-key">{entry.key}</td>
                    <td className="sd-header-value">{entry.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {responseMetadata.length > 0 && (
        <div className="sd-grpc-metadata-section">
          <span className="sd-grpc-metadata-section-title">
            Response Metadata / Trailers
          </span>
          <div className="sd-headers-table-wrapper">
            <table className="sd-headers-table">
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {responseMetadata.map((entry, idx) => (
                  <tr key={`resp-${entry.key}-${idx}`}>
                    <td className="sd-header-key">{entry.key}</td>
                    <td className="sd-header-value">{entry.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

/** Display protobuf body with Base64/Hex toggle. */
function ProtobufBodyViewer({
  label,
  body,
  encoding,
}: {
  label: string;
  body: string;
  encoding: string;
}) {
  const [viewMode, setViewMode] = useState<ProtobufViewMode>("base64");

  const handleModeChange = useCallback((mode: ProtobufViewMode) => {
    setViewMode(mode);
  }, []);

  const displayContent = useMemo<string>(() => {
    if (!body) return "";

    if (viewMode === "hex") {
      if (encoding === "base64") {
        return base64ToHexDump(body);
      }
      return textToHexDump(body);
    }

    // base64 mode
    if (encoding === "base64") {
      return body;
    }
    // If the body is not base64-encoded, convert it
    try {
      return btoa(
        Array.from(new TextEncoder().encode(body))
          .map((b) => String.fromCharCode(b))
          .join(""),
      );
    } catch {
      return body;
    }
  }, [body, encoding, viewMode]);

  if (!body) {
    return (
      <div className="sd-grpc-protobuf-body">
        <div className="sd-grpc-protobuf-header">
          <span className="sd-grpc-protobuf-label">{label}</span>
        </div>
        <div className="sd-empty-section">Empty body</div>
      </div>
    );
  }

  return (
    <div className="sd-grpc-protobuf-body">
      <div className="sd-grpc-protobuf-header">
        <span className="sd-grpc-protobuf-label">{label}</span>
        <div className="sd-body-mode-selector">
          <button
            className={`sd-body-mode-btn ${viewMode === "base64" ? "sd-body-mode-btn--active" : ""}`}
            onClick={() => handleModeChange("base64")}
          >
            Base64
          </button>
          <button
            className={`sd-body-mode-btn ${viewMode === "hex" ? "sd-body-mode-btn--active" : ""}`}
            onClick={() => handleModeChange("hex")}
          >
            Hex
          </button>
        </div>
      </div>
      <pre
        className={`sd-body-content ${viewMode === "hex" ? "sd-body-content--hex" : "sd-body-content--base64"}`}
      >
        {displayContent}
      </pre>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export function GrpcPanel({ flow }: GrpcPanelProps) {
  const summary = flow.protocol_summary ?? {};

  const service = summary.service ?? "";
  const method = summary.method ?? "";
  const grpcStatus = summary.grpc_status ?? "";
  const grpcStatusName = summary.grpc_status_name ?? "";

  return (
    <div className="sd-grpc-panel">
      {/* gRPC Overview header */}
      <div className="sd-grpc-overview">
        <h2 className="sd-section-title">gRPC Details</h2>

        <div className="sd-grpc-overview-content">
          {/* Service / Method */}
          <ServiceMethodDisplay service={service} method={method} />

          {/* Status + Stream Type badges row */}
          <div className="sd-grpc-badges">
            {/* Stream Type badge */}
            <div className="sd-meta-item">
              <span className="sd-meta-label">Stream Type</span>
              <Badge variant={streamTypeBadgeVariant(flow.flow_type)}>
                {streamTypeLabel(flow.flow_type)}
              </Badge>
            </div>

            {/* gRPC Status */}
            {grpcStatus && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">gRPC Status</span>
                <GrpcStatusDisplay statusCode={grpcStatus} />
              </div>
            )}

            {/* gRPC Status Name (if provided by backend separately) */}
            {grpcStatusName && !GRPC_STATUS_LABELS[grpcStatus] && (
              <div className="sd-meta-item">
                <span className="sd-meta-label">Status Name</span>
                <span className="sd-meta-value">{grpcStatusName}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* gRPC Metadata table */}
      <div className="sd-grpc-metadata-panel">
        <h3 className="sd-grpc-subsection-title">gRPC Metadata</h3>
        <GrpcMetadataTable
          requestHeaders={flow.request_headers}
          responseHeaders={flow.response_headers}
        />
      </div>

      {/* Protobuf body viewers */}
      <div className="sd-grpc-bodies">
        <h3 className="sd-grpc-subsection-title">Protobuf Payload</h3>
        <div className="sd-grpc-bodies-grid">
          <ProtobufBodyViewer
            label="Request Body"
            body={flow.request_body}
            encoding={flow.request_body_encoding}
          />
          <ProtobufBodyViewer
            label="Response Body"
            body={flow.response_body}
            encoding={flow.response_body_encoding}
          />
        </div>
      </div>
    </div>
  );
}
