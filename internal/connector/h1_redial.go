package connector

import (
	"context"
	"fmt"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// RedialUpstreamH1 establishes a fresh upstream HTTP/1.x *Layer for ut,
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
// Transport: the redial matches the stale Layer's scheme (USK-1079 review
// F-1) — a scheme="http" Layer (plain-HTTP forward proxy / plaintext
// CONNECT inner) is redialed over plain TCP, a scheme="https" Layer over
// TLS. See redialUpstreamH1Conn.
//
// ClientHello (TLS redial only): shape is how the stack's first upstream
// connection was dialed (UpstreamTLSShapeOf), so the redial keeps its
// shape:
//
//   - UpstreamTLSProfiled (zero value; CONNECT / SOCKS5 MITM and
//     ALPN-carrying transparent MITM): the configured uTLS profile
//     offering only "http/1.1". By definition the prior negotiation
//     produced http/1.1 (we were holding a *http1.Layer); re-offering h2
//     could negotiate h2 onto a stack whose client side is wired for an
//     *http1.Layer. A first offer of [h2 http/1.1] is therefore narrowed
//     to [http/1.1] deliberately; a solo [http/1.1] offer is reproduced
//     as is.
//   - UpstreamTLSStandardNoALPN (transparent MITM of a ClientHello with no
//     ALPN extension): Go's standard crypto/tls with no ALPN extension,
//     exactly like the first dial (dialUpstreamStandardNoALPN) — adding
//     an http/1.1 offer or the uTLS fingerprint the client never sent
//     would break MITM principle 1.
//
// ut carries the stack's dial target / TLS authority split (USK-1315;
// UpstreamTargetOf): the fresh conn dials ut.Dial and a TLS redial sends the
// TLS authority's host as ServerName and resolves per-host TLS by it — the
// same routing BuildConnectionStack applied to the original dial.
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
	ut UpstreamTarget,
	shape UpstreamTLSShape,
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

	if extractHost(ut.Dial) == "" {
		return nil, fmt.Errorf("connector: RedialUpstreamH1: invalid target %q", ut.Dial)
	}
	host := ut.tlsHost()
	if host == "" {
		return nil, fmt.Errorf("connector: RedialUpstreamH1: invalid TLS authority %q", ut.tlsAuthority())
	}

	upstreamConn, err := redialUpstreamH1Conn(ctx, ut, shape, host, stale.Scheme(), cfg)
	if err != nil {
		return nil, err
	}

	// Reuse the original Layer's EnvelopeContext template (mirroring h2:
	// the older TLS snapshot is kept on the template; Pipeline / RecordStep
	// already snapshotted the original handshake on prior envelopes, so
	// keeping the template coherent for the CONNECT's lifetime is more
	// useful than re-recording TLS here).
	// USK-1116: the copied template still names the stale socket's peer;
	// overwrite it with the fresh socket's.
	envCtx := WithUpstreamPeer(stale.EnvelopeContextTemplate(), upstreamConn)
	connID := redialConnIDLabel(envCtx.ConnID, generation)

	fresh := http1.New(upstreamConn, connID, envelope.Receive,
		http1.WithScheme(stale.Scheme()),
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

// redialUpstreamH1Conn dials the replacement upstream conn over the same
// transport the stale Layer's stack was built on (USK-1079 review F-1).
// An "http" Layer comes from BuildPlainHTTPStack (plain-HTTP forward proxy
// or plaintext CONNECT inner) and sits on plain TCP, so the redial is a
// plain dial — a TLS dial to a plaintext upstream would only fail. Any
// other scheme is a TLS MITM "https" stack and is redialed over TLS in the
// stack's first-dial shape (see RedialUpstreamH1).
func redialUpstreamH1Conn(ctx context.Context, ut UpstreamTarget, shape UpstreamTLSShape, host, scheme string, cfg *BuildConfig) (net.Conn, error) {
	target := ut.Dial
	if scheme == "http" {
		return dialPlainUpstream(ContextWithDialTarget(ctx, target), target, cfg)
	}

	hostTLS, err := resolvePerHostTLS(ut.tlsAuthority(), cfg)
	if err != nil {
		return nil, err
	}

	if shape == UpstreamTLSStandardNoALPN {
		upstreamConn, _, err := dialUpstreamStandardNoALPN(ctx, ut, host, hostTLS, cfg)
		if err != nil {
			return nil, err
		}
		return upstreamConn, nil
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
	return upstreamConn, nil
}
