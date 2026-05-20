import { HeaderEditor, type HeaderEntry } from "./HeaderEditor.js";

/**
 * State managed by the parent ResendPage and threaded through this editor.
 * Mirrors the subset of `ResendGRPCParams` exposed in the minimum-viable
 * gRPC editor (USK-936). Multi-message editing, trailer_metadata, proto
 * schema-aware message edit modes, and request-side compression toggles
 * are out of scope here — they will be addressed in a follow-up Issue.
 */
export interface GrpcRequestEditorState {
  /** Upstream target (host:port). Optional — backend recovers from flow when blank. */
  targetAddr: string;
  /** Transport scheme ("https" / "http"). */
  scheme: string;
  /** Fully-qualified gRPC service name (e.g. "package.Service"). */
  service: string;
  /** RPC method name (e.g. "MethodName"). */
  method: string;
  /** Initial request metadata (HEADERS frame). */
  metadata: HeaderEntry[];
  /** Plaintext message payload for the first (and only, in MVP) request LPM. */
  messagePayload: string;
}

export interface GrpcRequestEditorProps {
  state: GrpcRequestEditorState;
  onChange: (next: GrpcRequestEditorState) => void;
}

/**
 * Minimum-viable gRPC request editor for the Resend page.
 *
 * Exposes the fields required to invoke `resend_grpc` against an upstream
 * gRPC server: service / method / target address / scheme, plus an
 * ordered initial metadata block (HeaderEditor) and a single plaintext
 * message payload. Encoded as a single text-mode `ResendGRPCData` by the
 * caller (no proto-json round-trip; that's a follow-up).
 */
export function GrpcRequestEditor({ state, onChange }: GrpcRequestEditorProps) {
  return (
    <div className="resend-grpc-editor">
      <div className="resend-tcp-target-row">
        <input
          className="resend-url-input"
          type="text"
          value={state.targetAddr}
          onChange={(e) => onChange({ ...state, targetAddr: e.target.value })}
          placeholder="host:port (e.g. grpc.example.com:443) — optional, recovered from flow when blank"
          spellCheck={false}
        />
        <select
          className="resend-method-select"
          value={state.scheme}
          onChange={(e) => onChange({ ...state, scheme: e.target.value })}
          title="Transport scheme"
        >
          <option value="https">https</option>
          <option value="http">http</option>
        </select>
      </div>

      <div className="resend-grpc-rpc-row">
        <input
          className="resend-url-input"
          type="text"
          value={state.service}
          onChange={(e) => onChange({ ...state, service: e.target.value })}
          placeholder="Fully-qualified service (package.Service)"
          spellCheck={false}
        />
        <input
          className="resend-url-input"
          type="text"
          value={state.method}
          onChange={(e) => onChange({ ...state, method: e.target.value })}
          placeholder="Method name"
          spellCheck={false}
        />
      </div>

      <div className="resend-grpc-section">
        <div className="resend-grpc-section-title">Metadata</div>
        <HeaderEditor
          headers={state.metadata}
          onChange={(headers) => onChange({ ...state, metadata: headers })}
        />
      </div>

      <div className="resend-grpc-section">
        <div className="resend-grpc-section-title">Message payload (text)</div>
        <textarea
          className="resend-body-textarea"
          value={state.messagePayload}
          onChange={(e) =>
            onChange({ ...state, messagePayload: e.target.value })
          }
          placeholder="Plaintext message body — proto-schema-aware editing is deferred."
          spellCheck={false}
        />
      </div>
    </div>
  );
}
