package mcpserver

import (
	"log/slog"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	rulescommon "github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// applyInterceptQueueConfig seeds the HoldQueue from the loaded
// ProxyConfig.InterceptQueue substruct. A nil cfg is a no-op (built-in
// defaults seeded by rulescommon.NewHoldQueue stand). USK-855
// (USK-851 follow-up B).
//
// Validation has already run via ProxyConfig.Validate before reaching
// this helper, so unknown protocol keys / sub-floor timeouts cannot
// land here. The helper still defends gracefully: an unknown key is
// logged at slog.Warn level and skipped rather than panicking.
func applyInterceptQueueConfig(q *rulescommon.HoldQueue, cfg *config.InterceptQueueConfig, logger *slog.Logger) {
	if q == nil || cfg == nil {
		return
	}
	if cfg.TimeoutMs > 0 {
		q.SetTimeout(time.Duration(cfg.TimeoutMs) * time.Millisecond)
	}
	if cfg.TimeoutBehavior != "" {
		q.SetTimeoutBehavior(rulescommon.TimeoutBehavior(cfg.TimeoutBehavior))
	}
	for key, ov := range cfg.ProtocolOverrides {
		if ov == nil {
			// A null entry on the file-config side is "no override".
			// Clear any built-in seed so the global wins for this
			// protocol (operator opt-out of the default seed).
			q.ClearProtocolOverride(envelope.Protocol(key))
			continue
		}
		proto := envelope.Protocol(key)
		if !isCanonicalInterceptQueueProtocolMCPServer(proto) {
			if logger != nil {
				logger.Warn("intercept_queue.protocol_overrides: skipping unknown protocol key",
					slog.String("key", key))
			}
			continue
		}
		if ov.TimeoutMs > 0 {
			q.SetProtocolTimeout(proto, time.Duration(ov.TimeoutMs)*time.Millisecond)
		}
		if ov.TimeoutBehavior != "" {
			q.SetProtocolBehavior(proto, rulescommon.TimeoutBehavior(ov.TimeoutBehavior))
		}
	}
}

// isCanonicalInterceptQueueProtocolMCPServer mirrors the config package's
// canonical-key check. Duplicated here as a tiny defensive check so this
// helper does not pull a non-exported identifier across packages — the
// authoritative validator lives on ProxyConfig.Validate.
func isCanonicalInterceptQueueProtocolMCPServer(p envelope.Protocol) bool {
	switch p {
	case envelope.ProtocolHTTP,
		envelope.ProtocolWebSocket,
		envelope.ProtocolGRPC,
		envelope.ProtocolGRPCWeb,
		envelope.ProtocolSSE,
		envelope.ProtocolRaw,
		envelope.ProtocolTLSHandshake:
		return true
	}
	return false
}
