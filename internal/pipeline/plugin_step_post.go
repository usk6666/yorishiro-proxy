package pipeline

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// PluginStepPost fires hooks registered with phase="post_pipeline" — after
// Transform + Macro variant fan-out, before Record + Layer encode (RFC §9.3
// D1). Plugins observe the final wire-bound bytes; intended for signing,
// last-mile mutation, forensic stamping.
//
// Resend / fuzz / macro variant Pipelines RETAIN this Step (only PluginStepPre
// is excluded). A signing plugin therefore registers post_pipeline once and
// fires once per envelope on every variant — wire, resend, fuzz, macro.
//
// MessageOnly mutations from a post_pipeline hook regenerate Envelope.Raw
// via the configured WireEncoderRegistry so the bytes shipped to wire reflect
// the plugin's edit. RawOnly / Both mutations ship the plugin's bytes
// verbatim ("raw wins" per RFC §9.3 D4).
type PluginStepPost struct {
	pluginDispatcher
}

// NewPluginStepPost constructs a PluginStepPost. nil engine → no-op Step.
// nil encoders → MessageOnly mutations preserve original Raw with a Debug
// log (Q-7 fail-soft); operator should pass a configured registry for any
// production usage where post_pipeline plugins are expected to mutate
// Message-side fields. nil logger → slog.Default.
func NewPluginStepPost(engine *pluginv2.Engine, encoders *WireEncoderRegistry, logger *slog.Logger) *PluginStepPost {
	if logger == nil {
		logger = slog.Default()
	}
	return &PluginStepPost{
		pluginDispatcher: pluginDispatcher{
			engine:   engine,
			encoders: encoders,
			logger:   logger,
		},
	}
}

// Process dispatches the post_pipeline hook chain.
func (s *PluginStepPost) Process(ctx context.Context, env *envelope.Envelope) Result {
	return s.dispatch(ctx, env, pluginv2.PhasePostPipeline)
}
