import { useMcpClient } from "../../lib/mcp/index.js";
import { Badge } from "../ui/index.js";
import "./Header.css";

interface HeaderProps {
  onToggleSidebar: () => void;
  sidebarCollapsed: boolean;
}

const STATUS_BADGE_VARIANT = {
  connecting: "warning",
  connected: "success",
  disconnected: "default",
  error: "danger",
} as const;

export function Header({ onToggleSidebar, sidebarCollapsed }: HeaderProps) {
  const { status, error, connected, reconnect } = useMcpClient();

  return (
    <header className="header">
      <div className="header-left">
        <button
          className="header-menu-btn"
          onClick={onToggleSidebar}
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <MenuIcon />
        </button>
        <div className="header-logo">
          <span className="header-logo-text">yorishiro</span>
          <span className="header-logo-accent">-proxy</span>
        </div>
      </div>
      <div className="header-right">
        <div className="header-status">
          <Badge variant={STATUS_BADGE_VARIANT[status]}>
            {connected ? "MCP Connected" : `MCP: ${status}`}
          </Badge>
          {status === "error" && <ErrorAction error={error} reconnect={reconnect} />}
        </div>
      </div>
    </header>
  );
}

function ErrorAction({
  error,
  reconnect,
}: {
  error: Error | null;
  reconnect: () => Promise<void>;
}) {
  const authError =
    error != null &&
    "code" in error &&
    (error as { code: unknown }).code === 401;

  if (authError) {
    return (
      <span className="header-auth-hint">
        Re-open using the token URL from server logs
      </span>
    );
  }

  return (
    <button
      className="header-reconnect"
      onClick={() => void reconnect()}
      title="Reconnect"
    >
      retry
    </button>
  );
}

function MenuIcon() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 18 18"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
    >
      <line x1="3" y1="5" x2="15" y2="5" />
      <line x1="3" y1="9" x2="15" y2="9" />
      <line x1="3" y1="13" x2="15" y2="13" />
    </svg>
  );
}
