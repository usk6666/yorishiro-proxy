package pipeline

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// PluginStepPre fires hooks registered with phase="pre_pipeline" — after
// Safety, before Intercept (RFC §9.3 D1). Plugins observe pristine wire-
// fresh data; intended for annotation, fingerprinting, AI-visible pre-
// screening.
//
// Resend / fuzz / macro variant Pipelines exclude this Step (Pipeline.Without
// matches by reflect.TypeOf; the orchestrator constructs the resend Pipeline
// as livePipeline.Without(&PluginStepPre{}, &InterceptStep{})).
//
// MessageOnly mutations from a pre_pipeline hook produce an envelope with
// new Message + (re-encoded Raw if encoders provided, else original Raw).
// The cascade through Intercept/Transform/Macro/PluginStepPost reaches
// PluginStepPost where the final Raw is regenerated for wire send.
type PluginStepPre struct {
	pluginDispatcher
}

// NewPluginStepPre constructs a PluginStepPre. nil engine → no-op Step.
// nil encoders → MessageOnly mutations skip Raw regeneration (the Pre Step
// can rely on a downstream Step to render Raw, but optional encoders here
// avoid surprising plugin authors who expect their headers tweak in a
// pre_pipeline hook to take effect on the recorded "modified" variant
// even when no PluginStepPost is in the Pipeline). nil logger → slog.Default.
func NewPluginStepPre(engine *pluginv2.Engine, encoders *WireEncoderRegistry, logger *slog.Logger) *PluginStepPre {
	if logger == nil {
		logger = slog.Default()
	}
	return &PluginStepPre{
		pluginDispatcher: pluginDispatcher{
			engine:   engine,
			encoders: encoders,
			logger:   logger,
		},
	}
}

// Process dispatches the pre_pipeline hook chain.
func (s *PluginStepPre) Process(ctx context.Context, env *envelope.Envelope) Result {
	return s.dispatch(ctx, env, pluginv2.PhasePrePipeline)
}
