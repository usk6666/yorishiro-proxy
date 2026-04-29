package pluginv2

// Phase identifies when a hook fires relative to the Pipeline Step chain.
// RFC §9.3 Decision item 1.
type Phase string

const (
	// PhasePrePipeline fires after Safety, before Intercept. Default for
	// non-lifecycle hooks. Plugins observe pristine wire-fresh data.
	PhasePrePipeline Phase = "pre_pipeline"

	// PhasePostPipeline fires after Transform + Macro variant fan-out,
	// before Record + Layer encode. Plugins observe final wire-bound bytes.
	// Resend / Fuzz / Macro variant paths fire only this phase.
	PhasePostPipeline Phase = "post_pipeline"

	// PhaseNone marks lifecycle and observation-only hooks that do not
	// participate in the Pipeline (connection.*, tls.on_handshake,
	// socks5.on_connect, *.on_close, *.on_end). Plugins cannot pass
	// PhaseNone explicitly via register_hook — the value is inferred
	// from the surface table when a lifecycle event is registered.
	PhaseNone Phase = "none"
)

// IsValid reports whether p is one of the three defined phase values.
func (p Phase) IsValid() bool {
	switch p {
	case PhasePrePipeline, PhasePostPipeline, PhaseNone:
		return true
	default:
		return false
	}
}
