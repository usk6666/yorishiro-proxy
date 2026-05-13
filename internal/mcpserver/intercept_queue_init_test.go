package mcpserver

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	rulescommon "github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// silentLogger returns a slog.Logger that discards every record. Used in
// tests where the helper's slog.Warn paths are exercised but the log
// output is irrelevant to the assertion.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestApplyInterceptQueueConfig_NilCfg_NoOp(t *testing.T) {
	q := rulescommon.NewHoldQueue()
	before := q.Timeout()
	applyInterceptQueueConfig(q, nil, silentLogger())
	if q.Timeout() != before {
		t.Errorf("Timeout = %v, want unchanged %v", q.Timeout(), before)
	}
}

func TestApplyInterceptQueueConfig_GlobalOnly(t *testing.T) {
	q := rulescommon.NewHoldQueue()
	cfg := &config.InterceptQueueConfig{
		TimeoutMs:       30000,
		TimeoutBehavior: "auto_drop",
	}
	applyInterceptQueueConfig(q, cfg, silentLogger())
	if got := q.Timeout(); got != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", got)
	}
	if got := q.TimeoutBehavior(); got != rulescommon.TimeoutAutoDrop {
		t.Errorf("TimeoutBehavior = %v, want auto_drop", got)
	}
}

func TestApplyInterceptQueueConfig_ProtocolOverrides(t *testing.T) {
	q := rulescommon.NewHoldQueue()
	cfg := &config.InterceptQueueConfig{
		ProtocolOverrides: map[string]*config.InterceptQueueProtocolOverride{
			"ws":   {TimeoutMs: 1500},
			"grpc": {TimeoutMs: 30000, TimeoutBehavior: "auto_drop"},
		},
	}
	applyInterceptQueueConfig(q, cfg, silentLogger())

	timeout, behavior := q.ProtocolOverrideResolved(envelope.ProtocolWebSocket)
	if timeout != 1500*time.Millisecond {
		t.Errorf("WS timeout = %v, want 1500ms", timeout)
	}
	if behavior != rulescommon.TimeoutAutoRelease {
		t.Errorf("WS behavior = %v, want auto_release (inherit global)", behavior)
	}

	timeout, behavior = q.ProtocolOverrideResolved(envelope.ProtocolGRPC)
	if timeout != 30*time.Second {
		t.Errorf("gRPC timeout = %v, want 30s", timeout)
	}
	if behavior != rulescommon.TimeoutAutoDrop {
		t.Errorf("gRPC behavior = %v, want auto_drop", behavior)
	}
}

// TestApplyInterceptQueueConfig_NullEntryClears guards the
// file-config-loader semantics: a `null` value under protocol_overrides
// clears any built-in seed for that protocol so the global timeout
// applies. The HoldQueue starts with ws/sse/grpc seeds; a null override
// must wipe them.
func TestApplyInterceptQueueConfig_NullEntryClears(t *testing.T) {
	q := rulescommon.NewHoldQueue()
	cfg := &config.InterceptQueueConfig{
		ProtocolOverrides: map[string]*config.InterceptQueueProtocolOverride{
			"ws": nil,
		},
	}
	applyInterceptQueueConfig(q, cfg, silentLogger())

	got := q.ProtocolOverrides()
	if _, ok := got[envelope.ProtocolWebSocket]; ok {
		t.Errorf("ws override should be cleared, got %+v", got[envelope.ProtocolWebSocket])
	}
}

// TestApplyInterceptQueueConfig_UnknownKey_Skipped confirms that an
// unknown protocol key (which the validator would have already rejected
// upstream) is skipped here rather than panicking. Defense-in-depth.
func TestApplyInterceptQueueConfig_UnknownKey_Skipped(t *testing.T) {
	q := rulescommon.NewHoldQueue()
	cfg := &config.InterceptQueueConfig{
		ProtocolOverrides: map[string]*config.InterceptQueueProtocolOverride{
			"http2": {TimeoutMs: 1500},
		},
	}
	applyInterceptQueueConfig(q, cfg, silentLogger())

	// No panic, no entry recorded under "http2".
	got := q.ProtocolOverrides()
	if _, ok := got[envelope.Protocol("http2")]; ok {
		t.Errorf("http2 override should NOT be recorded (unknown key)")
	}
}
