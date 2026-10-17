package proxybuild

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// USK-1179 — pre-warm cap. Against an upstream that answers every new
// connection with GOAWAY, the pre-warm worker used to replace each
// speculative connection the moment it went away, redialing roughly every
// RTT for the whole lifetime of the client connection. The worker now
// refuses to replace a head that it produced itself and that never carried
// a locally initiated stream; a head that did carry a stream is still
// replaced as before (USK-992 / USK-994).

// prewarmCapHarness drives the production startH2UpstreamRedial wiring with
// a mint that hands out net.Pipe-backed Layers whose peer end the test
// controls.
type prewarmCapHarness struct {
	t       *testing.T
	chain   *redialChain
	metrics *H2UpstreamMetrics
	chain0  *http2.Layer
	peer0   net.Conn
	stop    func()
	cancel  context.CancelFunc

	mu    sync.Mutex
	peers map[*http2.Layer]net.Conn
	dials int
}

func newPrewarmCapHarness(t *testing.T) *prewarmCapHarness {
	t.Helper()
	h := &prewarmCapHarness{
		t:       t,
		metrics: NewH2UpstreamMetrics(),
		peers:   make(map[*http2.Layer]net.Conn),
	}
	h.chain = newRedialChain(h.metrics)
	h.chain0, h.peer0 = dialPeerH2Layer(t)

	mint := func(_ context.Context, _ string, _ *http2.Layer, _ int, onGoAway func()) (*http2.Layer, error) {
		cli, srv := net.Pipe()
		// Drain everything the Layer writes (preface, SETTINGS, HEADERS) so
		// its writer never blocks on the synchronous pipe.
		go func() { _, _ = io.Copy(io.Discard, srv) }()
		l, err := http2.New(cli, "test-prewarm-cap", http2.ClientRole, http2.WithGoAwayObserver(onGoAway))
		if err != nil {
			_ = srv.Close()
			return nil, err
		}
		h.mu.Lock()
		h.peers[l] = srv
		h.dials++
		h.mu.Unlock()
		return l, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	_, h.stop = startH2UpstreamRedial(ctx, "example.test:443", h.chain0, h.chain, mint, silentLogger())
	return h
}

func (h *prewarmCapHarness) Cleanup() {
	h.cancel()
	h.stop()
	_ = h.chain0.Close()
	_ = h.peer0.Close()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, p := range h.peers {
		_ = p.Close()
	}
}

func (h *prewarmCapHarness) dialCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dials
}

func (h *prewarmCapHarness) peerOf(l *http2.Layer) net.Conn {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.peers[l]
}

// awaitHead waits until the chain head is a Layer other than prev and
// returns it.
func (h *prewarmCapHarness) awaitHead(prev *http2.Layer) *http2.Layer {
	h.t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cur := h.chain.current.Load(); cur != nil && cur != prev {
			return cur
		}
		time.Sleep(5 * time.Millisecond)
	}
	h.t.Fatalf("chain head did not move past %p within 2s (dials=%d)", prev, h.dialCount())
	return nil
}

// sendRequestHeaders opens a stream on l and sends a GET HEADERS, which is
// what allocates a locally initiated stream id.
func sendRequestHeaders(t *testing.T, l *http2.Layer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ch, err := l.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if err := ch.Send(ctx, &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method: "GET", Scheme: "https", Authority: "example.test", Path: "/",
			EndStream: true,
		},
	}); err != nil {
		t.Fatalf("Send HEADERS: %v", err)
	}
}

// TestRedialChain_PrewarmSuppressedForUnusedSpeculativeHead: chain[0]'s
// GOAWAY pre-warms fresh1; fresh1 then goes away without ever carrying a
// stream. The worker must not dial a replacement for it.
func TestRedialChain_PrewarmSuppressedForUnusedSpeculativeHead(t *testing.T) {
	h := newPrewarmCapHarness(t)
	defer h.Cleanup()

	injectGoAwayFromPeer(t, h.peer0, 0, 0)
	fresh1 := h.awaitHead(nil)

	injectGoAwayFromPeer(t, h.peerOf(fresh1), 0, 0)
	awaitGoAwayClosed(t, fresh1)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.metrics.Snapshot().PrewarmSuppressed < 1 && h.dialCount() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	// Give a (wrong) replacement dial time to land before sampling.
	time.Sleep(200 * time.Millisecond)

	if got := h.dialCount(); got != 1 {
		t.Errorf("pre-warm dials = %d, want 1 (an unused speculative head must not be replaced)", got)
	}
	if cur := h.chain.current.Load(); cur != fresh1 {
		t.Errorf("chain head = %p, want fresh1 %p (left in place for the reactive path)", cur, fresh1)
	}
	if got := h.metrics.Snapshot().PrewarmSuppressed; got != 1 {
		t.Errorf("PrewarmSuppressed = %d, want 1", got)
	}
}

// TestRedialChain_PrewarmReplacesSpeculativeHeadThatCarriedStream: the same
// staging, but fresh1 carries a request before its GOAWAY — a normal
// GOAWAY, so the worker pre-warms fresh2 exactly as before USK-1179.
func TestRedialChain_PrewarmReplacesSpeculativeHeadThatCarriedStream(t *testing.T) {
	h := newPrewarmCapHarness(t)
	defer h.Cleanup()

	injectGoAwayFromPeer(t, h.peer0, 0, 0)
	fresh1 := h.awaitHead(nil)

	sendRequestHeaders(t, fresh1)
	injectGoAwayFromPeer(t, h.peerOf(fresh1), 1, 0)
	awaitGoAwayClosed(t, fresh1)

	h.awaitHead(fresh1)
	if got := h.dialCount(); got != 2 {
		t.Errorf("pre-warm dials = %d, want 2", got)
	}
	if got := h.metrics.Snapshot().PrewarmSuppressed; got != 0 {
		t.Errorf("PrewarmSuppressed = %d, want 0 for a head that carried a stream", got)
	}
}
