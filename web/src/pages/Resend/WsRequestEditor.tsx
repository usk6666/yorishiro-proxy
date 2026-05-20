/**
 * State managed by the parent ResendPage and threaded through this editor.
 * Mirrors the subset of `ResendWSParams` exposed in the minimum-viable
 * WebSocket editor (USK-936). Multi-frame editing, mask/payload_set
 * advanced flags, ping/pong plans, and TLS-fingerprint controls are
 * deferred to a follow-up Issue.
 */
export interface WsRequestEditorState {
  /** Upstream target (host:port). Optional — backend recovers from flow when blank. */
  targetAddr: string;
  /** Transport scheme ("wss" / "ws"). */
  scheme: string;
  /** Request path (recovered from the source flow URL). */
  path: string;
  /** WebSocket frame opcode. */
  opcode: "text" | "binary" | "ping" | "pong" | "close";
  /** Final frame flag — typically true for one-shot frames. */
  fin: boolean;
  /** Payload as text or base64 (selectable). */
  payload: string;
  /** "text" | "base64" — body_encoding sent to the backend for the payload field. */
  bodyEncoding: "text" | "base64";
  /** Optional per-message-deflate flag (only meaningful on text/binary frames). */
  compressed: boolean;
  /** Close-frame status code (1000-4999) — only used when opcode === "close". */
  closeCode: string;
  /** Close-frame reason — only used when opcode === "close". */
  closeReason: string;
}

export interface WsRequestEditorProps {
  state: WsRequestEditorState;
  onChange: (next: WsRequestEditorState) => void;
}

const OPCODE_OPTIONS: WsRequestEditorState["opcode"][] = [
  "text",
  "binary",
  "ping",
  "pong",
  "close",
];

/**
 * Minimum-viable WebSocket single-frame editor for the Resend page.
 *
 * `resend_ws` is single-frame by design on the backend; we surface the
 * opcode / payload / fin / encoding / compressed knobs plus close-frame
 * fields that the protocol allows. Multi-frame replay is owned by the
 * follow-up Issue.
 */
export function WsRequestEditor({ state, onChange }: WsRequestEditorProps) {
  const isCloseFrame = state.opcode === "close";
  const supportsPayload =
    state.opcode === "text" ||
    state.opcode === "binary" ||
    state.opcode === "ping" ||
    state.opcode === "pong";
  const supportsCompressed =
    state.opcode === "text" || state.opcode === "binary";

  return (
    <div className="resend-ws-editor">
      <div className="resend-tcp-target-row">
        <input
          className="resend-url-input"
          type="text"
          value={state.targetAddr}
          onChange={(e) => onChange({ ...state, targetAddr: e.target.value })}
          placeholder="host:port (e.g. ws.example.com:443) — optional, recovered from flow when blank"
          spellCheck={false}
        />
        <select
          className="resend-method-select"
          value={state.scheme}
          onChange={(e) => onChange({ ...state, scheme: e.target.value })}
          title="Transport scheme"
        >
          <option value="wss">wss</option>
          <option value="ws">ws</option>
        </select>
      </div>

      <div className="resend-ws-rpc-row">
        <input
          className="resend-url-input"
          type="text"
          value={state.path}
          onChange={(e) => onChange({ ...state, path: e.target.value })}
          placeholder="/ws/path"
          spellCheck={false}
        />
      </div>

      <div className="resend-ws-frame-row">
        <select
          className="resend-method-select"
          value={state.opcode}
          onChange={(e) =>
            onChange({
              ...state,
              opcode: e.target.value as WsRequestEditorState["opcode"],
            })
          }
          title="Frame opcode"
        >
          {OPCODE_OPTIONS.map((op) => (
            <option key={op} value={op}>
              {op}
            </option>
          ))}
        </select>
        <label className="resend-dryrun-toggle">
          <input
            type="checkbox"
            checked={state.fin}
            onChange={(e) => onChange({ ...state, fin: e.target.checked })}
          />
          <span>FIN</span>
        </label>
        {supportsCompressed && (
          <label
            className="resend-dryrun-toggle"
            title="Mark as per-message-deflate (RFC 7692) compressed"
          >
            <input
              type="checkbox"
              checked={state.compressed}
              onChange={(e) =>
                onChange({ ...state, compressed: e.target.checked })
              }
            />
            <span>Compressed</span>
          </label>
        )}
      </div>

      {supportsPayload && (
        <div className="resend-grpc-section">
          <div className="resend-grpc-section-title">
            Payload (
            <select
              className="resend-ws-encoding-select"
              value={state.bodyEncoding}
              onChange={(e) =>
                onChange({
                  ...state,
                  bodyEncoding: e.target.value as "text" | "base64",
                })
              }
              title="Payload encoding"
            >
              <option value="text">text</option>
              <option value="base64">base64</option>
            </select>
            )
          </div>
          <textarea
            className="resend-body-textarea"
            value={state.payload}
            onChange={(e) => onChange({ ...state, payload: e.target.value })}
            placeholder={
              state.bodyEncoding === "base64"
                ? "Base64-encoded payload"
                : "Frame payload as text"
            }
            spellCheck={false}
          />
        </div>
      )}

      {isCloseFrame && (
        <div className="resend-grpc-section">
          <div className="resend-grpc-section-title">Close frame</div>
          <div className="resend-tcp-target-row">
            <input
              className="resend-url-input"
              type="text"
              inputMode="numeric"
              value={state.closeCode}
              onChange={(e) =>
                onChange({ ...state, closeCode: e.target.value })
              }
              placeholder="close_code (1000-4999)"
              spellCheck={false}
            />
            <input
              className="resend-url-input"
              type="text"
              value={state.closeReason}
              onChange={(e) =>
                onChange({ ...state, closeReason: e.target.value })
              }
              placeholder="close_reason"
              spellCheck={false}
            />
          </div>
        </div>
      )}
    </div>
  );
}
