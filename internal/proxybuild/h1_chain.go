package proxybuild

import (
	"context"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// h1Chain owns the per-CONNECT chain of upstream HTTP/1.x Layers (USK-998).
//
// HTTP/1 has no connection pool — each CONNECT tunnel owns its single
// upstream Layer. When the upstream peer closes its keep-alive connection
// during idle (Keep-Alive: timeout expiry, RFC 9112 §9.6), the parser
// goroutine in [http1.Layer] does not observe the FIN until the next
// response read; meanwhile the next request's wire Write hits EPIPE.
//
// The chain wraps the per-CONNECT upstream Layer and, on each per-exchange
// dial, calls [http1.Layer.HealthCheck] to detect the stale state proactively
// and transparently redial via [connector.RedialUpstreamH1] when needed.
//
// Shape vs h2's redialChain (USK-991/992):
//   - Thinner: HTTP/1 has no pool, no GOAWAY observer, no pre-warm worker.
//   - Layer slice retains every layer (the original + every redial) so
//     closeAll on CONNECT exit reliably terminates every parser goroutine
//     and underlying conn.
//   - Single sync.Mutex serialises EnsureFresh with closeAll. EnsureFresh
//     calls do not overlap meaningfully in HTTP/1 — the wire is strictly
//     serial per RFC 9112 §9.5 and the per-exchange goroutines pulling
//     from the client Channel are time-sliced by the spawn loop anyway —
//     but the mutex defends against concurrent dial closures from
//     pipelined exchanges and against a racing CONNECT teardown.
type h1Chain struct {
	mu      sync.Mutex
	current *http1.Layer
	layers  []*http1.Layer
	target  string
	cfg     *connector.BuildConfig
}

// newH1Chain wraps the initial upstream Layer (the one constructed at
// CONNECT-time by buildStackFromRoute) so subsequent dial-time stale checks
// can redial transparently.
func newH1Chain(initial *http1.Layer, target string, cfg *connector.BuildConfig) *h1Chain {
	return &h1Chain{
		current: initial,
		layers:  []*http1.Layer{initial},
		target:  target,
		cfg:     cfg,
	}
}

// EnsureFresh returns a Layer guaranteed to have passed a HealthCheck. If
// the current Layer is stale, it is replaced with a freshly redialed Layer;
// the stale Layer is Closed synchronously. Returns the dial error verbatim
// on redial failure — the caller surfaces it through the per-exchange
// session as state="error" (same shape as the original dial closure's
// error path) and the next exchange retries via this same EnsureFresh.
//
// Concurrency: a single mutex serialises with concurrent EnsureFresh and
// closeAll. HealthCheck holds [http1.Layer.pendingMu] briefly during its
// 1-byte SetReadDeadline read; that mutex does not race with the parser
// goroutine in the expected (pendingQ empty) case.
func (c *h1Chain) EnsureFresh(ctx context.Context) (*http1.Layer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.current.HealthCheck(); err == nil {
		return c.current, nil
	}
	fresh, err := connector.RedialUpstreamH1(ctx, c.target, c.current, c.cfg, len(c.layers))
	if err != nil {
		return nil, err
	}
	// Close the stale Layer synchronously. HTTP/1 is wire-serial and
	// HealthCheck's contract requires an empty pendingQ on call, so by
	// construction there is no in-flight Channel reader to disrupt. Close
	// is sync.Once-guarded inside the Layer.
	_ = c.current.Close()
	c.current = fresh
	c.layers = append(c.layers, fresh)
	return fresh, nil
}

// closeAll closes every Layer in the chain. Called from the CONNECT-exit
// deferred cleanup in runHTTP1ExchangeLoop so every redial step's parser
// goroutine and underlying conn is torn down.
func (c *h1Chain) closeAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, l := range c.layers {
		_ = l.Close()
	}
}
