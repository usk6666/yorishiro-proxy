import { Badge } from "../../components/ui/Badge.js";
import type { ResendWSResult } from "../../lib/mcp/types.js";

export interface WsResponseViewerProps {
  response: ResendWSResult;
}

/**
 * Render a typed `ResendWSResult`. Single-frame view (the backend's
 * resend_ws is single-frame by design) — close-frame metadata
 * (close_code / close_reason) only surfaces when present.
 */
export function WsResponseViewer({ response }: WsResponseViewerProps) {
  return (
    <div className="resend-ws-response">
      <div className="resend-grpc-summary">
        <span className="resend-grpc-summary-label">stream_id</span>
        <code className="resend-grpc-summary-value">{response.stream_id}</code>
      </div>

      <div className="resend-grpc-summary">
        <Badge variant="info">{response.opcode}</Badge>
        {response.fin && <Badge variant="default">FIN</Badge>}
        {response.compressed && <Badge variant="warning">compressed</Badge>}
        <Badge variant="default">{response.payload_encoding}</Badge>
      </div>

      {(response.close_code != null || response.close_reason) && (
        <div className="resend-grpc-summary">
          <span className="resend-grpc-summary-label">close</span>
          {response.close_code != null && (
            <Badge
              variant={response.close_code === 1000 ? "success" : "warning"}
            >
              {response.close_code}
            </Badge>
          )}
          {response.close_reason && (
            <span className="resend-grpc-summary-value">
              {response.close_reason}
            </span>
          )}
        </div>
      )}

      <div className="resend-grpc-section">
        <div className="resend-grpc-section-title">Payload</div>
        {response.payload ? (
          <pre className="resend-grpc-message-payload">{response.payload}</pre>
        ) : (
          <div className="resend-empty-response">(empty payload)</div>
        )}
      </div>
    </div>
  );
}
