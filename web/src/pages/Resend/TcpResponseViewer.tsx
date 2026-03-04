import { useMemo, useState } from "react";
import { Tabs } from "../../components/ui/Tabs.js";
import "./TcpResponseViewer.css";

/** Result from resend_raw or tcp_replay execute actions. */
export interface TcpResendResult {
  new_flow_id?: string;
  response_data?: string;
  response_size?: number;
  duration_ms?: number;
  tag?: string;
  dry_run?: boolean;
  raw_preview?: {
    data_base64: string;
    data_size: number;
    patches_applied: number;
  };
}

const TCP_RESPONSE_TABS = [
  { id: "decoded", label: "Decoded" },
  { id: "hex", label: "Hex Dump" },
  { id: "raw", label: "Raw (base64)" },
];

export interface TcpResponseViewerProps {
  response: TcpResendResult;
}

/**
 * Displays the response from a resend_raw or tcp_replay operation.
 * Shows decoded text, hex dump, and raw base64 views.
 */
export function TcpResponseViewer({ response }: TcpResponseViewerProps) {
  const [activeTab, setActiveTab] = useState("decoded");

  // For dry-run, show the raw preview.
  if (response.dry_run && response.raw_preview) {
    return (
      <div className="tcp-response-viewer">
        <div className="tcp-response-dry-run">
          <div className="tcp-response-dry-run-header">
            Dry Run Preview
          </div>
          <div className="tcp-response-dry-run-info">
            <span>Data size: {response.raw_preview.data_size} bytes</span>
            <span>Patches applied: {response.raw_preview.patches_applied}</span>
          </div>
          <pre className="tcp-response-raw-content">
            {response.raw_preview.data_base64}
          </pre>
        </div>
      </div>
    );
  }

  const base64Data = response.response_data ?? "";

  return (
    <div className="tcp-response-viewer">
      <Tabs
        tabs={TCP_RESPONSE_TABS}
        activeTab={activeTab}
        onTabChange={setActiveTab}
      >
        {activeTab === "decoded" && (
          <DecodedView base64Data={base64Data} />
        )}
        {activeTab === "hex" && (
          <HexView base64Data={base64Data} />
        )}
        {activeTab === "raw" && (
          <div className="tcp-response-raw-view">
            {base64Data ? (
              <pre className="tcp-response-raw-content">{base64Data}</pre>
            ) : (
              <div className="tcp-response-empty">(empty response)</div>
            )}
          </div>
        )}
      </Tabs>
    </div>
  );
}

/** Decode base64 and show as text, replacing non-printable chars with dots. */
function DecodedView({ base64Data }: { base64Data: string }) {
  const text = useMemo(() => {
    if (!base64Data) return "";
    try {
      const decoded = atob(base64Data);
      return decoded.replace(/[^\x09\x0A\x0D\x20-\x7E]/g, ".");
    } catch {
      return "(failed to decode base64)";
    }
  }, [base64Data]);

  if (!text) {
    return <div className="tcp-response-empty">(empty response)</div>;
  }

  return (
    <div className="tcp-response-decoded-view">
      <pre className="tcp-response-decoded-content">{text}</pre>
    </div>
  );
}

/** Show base64 data as hex dump. */
function HexView({ base64Data }: { base64Data: string }) {
  const hexDump = useMemo(() => {
    if (!base64Data) return "";
    try {
      const decoded = atob(base64Data);
      const lines: string[] = [];

      for (let offset = 0; offset < decoded.length; offset += 16) {
        const chunk = decoded.slice(offset, offset + 16);
        const hexParts: string[] = [];
        let ascii = "";

        for (let i = 0; i < 16; i++) {
          if (i < chunk.length) {
            const byte = chunk.charCodeAt(i);
            hexParts.push(byte.toString(16).padStart(2, "0"));
            ascii += byte >= 0x20 && byte <= 0x7e ? chunk[i] : ".";
          } else {
            hexParts.push("  ");
            ascii += " ";
          }
        }

        const offsetStr = offset.toString(16).padStart(8, "0");
        const hexLeft = hexParts.slice(0, 8).join(" ");
        const hexRight = hexParts.slice(8).join(" ");
        lines.push(`${offsetStr}  ${hexLeft}  ${hexRight}  |${ascii}|`);
      }

      return lines.join("\n");
    } catch {
      return "(failed to decode base64)";
    }
  }, [base64Data]);

  if (!hexDump) {
    return <div className="tcp-response-empty">(empty response)</div>;
  }

  return (
    <div className="tcp-response-hex-view">
      <pre className="tcp-response-hex-content">{hexDump}</pre>
    </div>
  );
}
