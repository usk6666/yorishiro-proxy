package connector

import (
	"context"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// RedialUpstreamH1 establishes a fresh upstream HTTP/1.x *Layer for target,
// reusing the EnvelopeContext template carried by stale (so the new Layer
// stamps envelopes with the same ConnID / TargetHost / TLS reality the
// caller already recorded). The TLS knobs (per-host overlay, fingerprint,
// upstream proxy) are resolved through cfg the same way the original
// CONNECT path did — runtime-mutable overrides therefore reach the redial.
//
// generation identifies which step of the redial chain this dial is for
// (USK-998 — mirroring the USK-991 h2 redial scheme): generation==1 is the
// first redial (label suffix `/upstream-redial`); generation>=2 appends
// `-N`. Callers pass len(chain)+1 (where chain is the slice of prior fresh
// Layers, including the original).
//
// USK-998: invoked by proxybuild's h1 chain inside the per-exchange dial
// closure when [http1.Layer.HealthCheck] reports the current Layer is
// stale (peer FIN / RST during idle keep-alive, or RFC 9112 violation
// during idle). HTTP/1 has no connection pool — the per-CONNECT
// lifetime owns its single upstream Layer (and any redialed successors).
//
// ALPN: offers only "http/1.1". By definition the prior negotiation
// produced http/1.1 (we were holding a *http1.Layer); re-negotiating to
// h2 would invalidate the Layer type already wired into the client side
// of the stack.
//
// Returned errors are upstream dial / TLS errors verbatim so the caller
// can wrap them via fmt.Errorf("dial: %w", ...) the same way the regular
// dial closure does, keeping ClassifyError taxonomy intact.
//
// Wire fidelity: the fresh Layer is constructed identically to the
// original buildStackFromRoute "http1" upstream path (same options, same
// EnvelopeContext template), so envelopes flowing through it round-trip
// with the same wire shape.
func RedialUpstreamH1(
	ctx context.Context,
	target string,
	stale *http1.Layer,
	cfg *BuildConfig,
	generation int,
) (*http1.Layer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("connector: RedialUpstreamH1: cfg is nil")
	}
	if stale == nil {
		return nil, fmt.Errorf("connector: RedialUpstreamH1: stale is nil")
	}

	host := extractHost(target)
	if host == "" {
		return nil, fmt.Errorf("connector: RedialUpstreamH1: invalid target %q", target)
	}

	hostTLS, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		return nil, err
	}

	// Offer only http/1.1: the prior negotiation produced http/1.1 and the
	// stack's client side is wired for an *http1.Layer. Re-negotiating to
	// h2 would force a Layer type swap upstream-side that the per-CONNECT
	// stack is not prepared for.
	upstreamConn, _, err := dialUpstreamWithALPN(ctx, target, host,
		[]string{ALPNProtocolHTTP11},
		hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg,
	)
	if err != nil {
		return nil, err
	}

	// Reuse the original Layer's EnvelopeContext template (mirroring h2:
	// the older TLS snapshot is kept on the template; Pipeline / RecordStep
	// already snapshotted the original handshake on prior envelopes, so
	// keeping the template coherent for the CONNECT's lifetime is more
	// useful than re-recording TLS here).
	envCtx := stale.EnvelopeContextTemplate()
	connID := redialConnIDLabel(envCtx.ConnID, generation)

	fresh := http1.New(upstreamConn, connID, envelope.Receive,
		http1.WithScheme("https"),
		http1.WithEnvelopeContext(envCtx),
		http1.WithBodySpillDir(cfg.BodySpillDir),
		http1.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http1.WithMaxBodySize(cfg.MaxBodySize),
		http1.WithMaxRawCaptureSize(cfg.MaxRawCaptureSize),
		http1.WithStateReleaser(cfg.PluginV2Engine),
		// USK-655: bypass body draining for SSE responses so the swap
		// orchestrator (session.runUpgradeSSE) can hand the still-open
		// body to sse.Wrap without blocking on a never-ending drain.
		// Matches the option set used in buildStackFromRoute "http1".
		http1.WithStreamingResponseDetect(http1.IsSSEResponse),
	)
	return fresh, nil
}
