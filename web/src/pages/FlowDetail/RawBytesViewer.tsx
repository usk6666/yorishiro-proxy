/**
 * RawBytesViewer -- Read-only hex dump + text view for raw bytes in flow detail.
 *
 * Displays the raw_request / raw_response fields from flow detail as
 * hex dump or plain text.
 */

import { useMemo, useState } from "react";

import {
  type RawViewMode,
  bytesToText,
  decodeBase64,
  formatHexDump,
  HEX_DUMP_VIEWER_MAX,
} from "../../lib/rawBytes";
import "./FlowDetailPage.css";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RawBytesViewerProps {
  /** Base64-encoded raw bytes. */
  rawBytes: string;
  /** Label to display (e.g., "Raw Request", "Raw Response"). */
  label: string;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function RawBytesViewer({ rawBytes, label }: RawBytesViewerProps) {
  const [viewMode, setViewMode] = useState<RawViewMode>("hex");

  const bytes = useMemo(() => decodeBase64(rawBytes), [rawBytes]);
  const hexDump = useMemo(() => formatHexDump(bytes, HEX_DUMP_VIEWER_MAX), [bytes]);
  const textContent = useMemo(() => bytesToText(bytes), [bytes]);

  if (!rawBytes) {
    return (
      <div className="sd-empty-section">
        No {label.toLowerCase()} data available
      </div>
    );
  }

  return (
    <div className="sd-raw-bytes-viewer">
      <div className="sd-body-controls">
        <div className="sd-body-mode-selector">
          <button
            className={`sd-body-mode-btn ${viewMode === "hex" ? "sd-body-mode-btn--active" : ""}`}
            onClick={() => setViewMode("hex")}
          >
            Hex
          </button>
          <button
            className={`sd-body-mode-btn ${viewMode === "text" ? "sd-body-mode-btn--active" : ""}`}
            onClick={() => setViewMode("text")}
          >
            Text
          </button>
        </div>
        <span className="sd-body-content-type">{bytes.length} bytes</span>
      </div>

      <pre className={`sd-body-content ${viewMode === "hex" ? "sd-body-content--hex" : ""}`}>
        {viewMode === "hex" ? hexDump : textContent}
      </pre>
    </div>
  );
}
