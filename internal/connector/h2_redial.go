package connector

import (
	"context"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// RedialUpstreamH2 establishes a fresh upstream HTTP/2 *Layer for target,
// reusing the EnvelopeContext template carried by stale (so the new Layer
// stamps envelopes with the same ConnID / TargetHost / TLS reality the
// caller already recorded). The TLS knobs (per-host overlay, fingerprint,
// upstream proxy) are resolved through cfg the same way the original
// CONNECT path did — runtime-mutable overrides therefore reach the redial.
//
// USK-816: invoked by proxybuild.buildOnHTTP2Stack at dial-closure time
// when the pooled upstreamH2 has gone stale during a long intercept hold
// (server sent GOAWAY, or upstream FIN closed the conn). The fresh Layer
// is owned by the caller — this helper does NOT insert it into HTTP2Pool
// because the per-CONNECT lifecycle owns the redial; reuse across
// CONNECTs is the pool's job and is opt-in via Pool.Put.
//
// Returned errors are upstream dial / TLS / http2.New errors verbatim so
// the caller can wrap them via fmt.Errorf("dial: %w", ...) the same way
// the regular dial closure does, keeping ClassifyError taxonomy intact.
//
// Wire fidelity: the fresh Layer is constructed identically to the
// original buildH2Stack path (same options, same EnvelopeContext template),
// so envelopes flowing through it round-trip with the same wire shape.
func RedialUpstreamH2(
	ctx context.Context,
	target string,
	stale *http2.Layer,
	cfg *BuildConfig,
) (*http2.Layer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("connector: RedialUpstreamH2: cfg is nil")
	}
	if stale == nil {
		return nil, fmt.Errorf("connector: RedialUpstreamH2: stale is nil")
	}

	host := extractHost(target)
	if host == "" {
		return nil, fmt.Errorf("connector: RedialUpstreamH2: invalid target %q", target)
	}

	hostTLS, err := resolvePerHostTLS(target, cfg)
	if err != nil {
		return nil, err
	}

	// Offer only h2 — by definition the prior negotiation produced h2 (we
	// were holding a *http2.Layer). Re-negotiating to anything else would
	// invalidate the per-stream layering already established on the client
	// side of the stack.
	upstreamConn, _, err := dialUpstreamWithALPN(ctx, target, host,
		[]string{ALPNProtocolH2},
		hostTLS.insecureSkip, hostTLS.clientCert, hostTLS.rootCAs, cfg,
	)
	if err != nil {
		return nil, err
	}

	// Reuse the original Layer's EnvelopeContext template. The TLS snapshot
	// inside refers to the prior dial's handshake — strictly speaking the
	// fresh dial produced a new TLSSnapshot, but Pipeline / RecordStep
	// already snapshotted the original handshake on prior envelopes; using
	// the older template keeps the recorded story coherent for this
	// CONNECT's lifetime. A future enhancement could project the new snap
	// onto each envelope, but the immediate USK-816 fix is to land the
	// fresh stream on the wire — not to re-record TLS.
	envCtx := stale.EnvelopeContextTemplate()

	connID := envCtx.ConnID
	if connID == "" {
		connID = "redial"
	}
	connID += "/upstream-redial"

	fresh, err := http2.New(upstreamConn, connID, http2.ClientRole,
		http2.WithScheme("https"),
		http2.WithEnvelopeContext(envCtx),
		http2.WithBodySpillDir(cfg.BodySpillDir),
		http2.WithBodySpillThreshold(cfg.BodySpillThreshold),
		http2.WithMaxBodySize(cfg.MaxBodySize),
		http2.WithStateReleaser(cfg.PluginV2Engine),
	)
	if err != nil {
		return nil, fmt.Errorf("connector: redial h2 layer: %w", err)
	}

	// USK-623: notify push-channel observers so the upstream push recorder
	// attaches before any PUSH_PROMISE arrives. The prior Layer's recorder
	// goroutine is bound to the prior Layer; the fresh one needs its own.
	if cfg.OnHTTP2UpstreamDialed != nil {
		cfg.OnHTTP2UpstreamDialed(fresh)
	}

	return fresh, nil
}
