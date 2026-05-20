import { Badge } from "../../components/ui/Badge.js";
import type { ResendGRPCResult } from "../../lib/mcp/types.js";

export interface GrpcResponseViewerProps {
  response: ResendGRPCResult;
}

/**
 * Render a typed `ResendGRPCResult` (stream_id, start_metadata, response-side
 * LPMs, trailer end, warnings). gRPC has no concept of an HTTP status code
 * on the response — the authoritative outcome is `end.status` (the gRPC
 * status enum). When `end` is absent the upstream terminated without a
 * trailer HEADERS frame; we surface that case explicitly rather than
 * silently fall through to "OK".
 */
export function GrpcResponseViewer({ response }: GrpcResponseViewerProps) {
  const warnings = response.warnings ?? [];
  const messages = response.messages ?? [];
  const startMetadata = response.start_metadata ?? [];

  return (
    <div className="resend-grpc-response">
      {warnings.length > 0 && (
        <div
          className="resend-grpc-warnings"
          role="status"
          aria-label="resend warnings"
        >
          <div className="resend-grpc-warnings-title">
            {warnings.length} warning{warnings.length === 1 ? "" : "s"}
          </div>
          <ul className="resend-grpc-warnings-list">
            {warnings.map((w, i) => (
              <li key={i}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="resend-grpc-summary">
        <span className="resend-grpc-summary-label">stream_id</span>
        <code className="resend-grpc-summary-value">{response.stream_id}</code>
      </div>

      {response.end ? (
        <div className="resend-grpc-summary">
          <span className="resend-grpc-summary-label">status</span>
          <Badge variant={response.end.status === 0 ? "success" : "danger"}>
            {response.end.status}
          </Badge>
          {response.end.message && (
            <span className="resend-grpc-summary-value">
              {response.end.message}
            </span>
          )}
        </div>
      ) : (
        <div className="resend-grpc-summary">
          <Badge variant="warning">no trailer</Badge>
          <span className="resend-grpc-summary-value">
            Upstream terminated without a trailer HEADERS frame.
          </span>
        </div>
      )}

      <div className="resend-grpc-section">
        <div className="resend-grpc-section-title">
          Start metadata ({startMetadata.length})
        </div>
        {startMetadata.length === 0 ? (
          <div className="resend-empty-response">(no metadata)</div>
        ) : (
          <ul className="resend-grpc-kv-list">
            {startMetadata.map((kv, i) => (
              <li key={i} className="resend-grpc-kv-row">
                <code className="resend-grpc-kv-name">{kv.name}</code>
                <span className="resend-grpc-kv-value">{kv.value}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="resend-grpc-section">
        <div className="resend-grpc-section-title">
          Messages ({messages.length})
        </div>
        {messages.length === 0 ? (
          <div className="resend-empty-response">(no response messages)</div>
        ) : (
          <ol className="resend-grpc-message-list">
            {messages.map((m, i) => (
              <li key={i} className="resend-grpc-message">
                <div className="resend-grpc-message-meta">
                  <Badge variant="info">#{i + 1}</Badge>
                  <Badge variant="default">{m.payload_encoding}</Badge>
                  {m.compressed && <Badge variant="warning">compressed</Badge>}
                </div>
                <pre className="resend-grpc-message-payload">{m.payload}</pre>
              </li>
            ))}
          </ol>
        )}
      </div>

      {response.end?.trailers && response.end.trailers.length > 0 && (
        <div className="resend-grpc-section">
          <div className="resend-grpc-section-title">
            Trailers ({response.end.trailers.length})
          </div>
          <ul className="resend-grpc-kv-list">
            {response.end.trailers.map((kv, i) => (
              <li key={i} className="resend-grpc-kv-row">
                <code className="resend-grpc-kv-name">{kv.name}</code>
                <span className="resend-grpc-kv-value">{kv.value}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
