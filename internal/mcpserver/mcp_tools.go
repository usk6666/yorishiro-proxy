package mcpserver

import (
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/mcp"
)

// logToolAllowlist logs, once at boot, that the -mcp-tools allowlist is
// active (USK-1120): the exposed tools and how many tools it hides. names
// has already passed mcp.ValidateToolAllowlist.
func logToolAllowlist(logger *slog.Logger, names []string) {
	allowed := make(map[string]bool, len(names))
	exposed := make([]string, 0, len(names))
	for _, n := range names {
		if !allowed[n] {
			allowed[n] = true
			exposed = append(exposed, n)
		}
	}
	logger.Info("MCP tool allowlist active",
		"tools", exposed,
		"hidden", len(mcp.ToolNames())-len(exposed))
}
