//go:build e2e && !e2e_smoke

// USK-999 / USK-998 Phase 2 integration: stale-conn retry on EPIPE.
// These tests exercise retryingUpstreamChannel + h1Chain.Redial against
// a real TCP upstream so the EPIPE classifier path runs through real
// syscall errors rather than synthetic test sentinels.
//
// Why exhaustive tier (`//go:build e2e && !e2e_smoke`): the retry
// wrapper is on the merge-gate path via the proxybuild dial closure,
// but the failure mode (server FIN between HealthCheck and Write) is
// rare and the unit tests in internal/layer/http1/replay_safe_test.go
// already pin the classifier and truth-table deterministically. These
// tests confirm the integration surface; they live in the full nightly
// tier per CLAUDE.md "e2e Test Subsystem Verification Checklist".
package proxybuild

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// flakyConn wraps a net.Conn so the first Write returns syscall.EPIPE
// (simulating the USK-999 race window: server FIN between HealthCheck
// and the proxy's first wire Write). Read passes through normally so
// HealthCheck's 1ms peek reports the connection alive. Subsequent
// Writes (after the first failed one) also pass through so a never-
// retried path would still succeed eventually — though in the retry
// design the inner Channel is swapped on first EPIPE, so the second
// write goes through a freshly dialed upstream conn instead of this
// flakyConn.
type flakyConn struct {
	net.Conn
	failCount atomic.Int32 // how many Writes still to fail (decremented per call)
}

// Write returns syscall.EPIPE while failCount > 0, then passes through.
func (f *flakyConn) Write(p []byte) (int, error) {
	if f.failCount.Load() > 0 {
		f.failCount.Add(-1)
		return 0, syscall.EPIPE
	}
	return f.Conn.Write(p)
}

// dummyUpstreamServer accepts plain HTTP/1.1 connections on a loopback
// listener, parses one request per conn, and writes a fixed "OK"
// response. Used as the redial target so chain.Redial produces a real
// fresh upstream Layer connected to a real server (no TLS for these
// integration tests — the redial dial path is exercised by the
// existing h1_chain_stale_recovery_integration_test.go).
type dummyUpstreamServer struct {
	ln       net.Listener
	addr     string
	gotReqs  atomic.Int32
	gotPaths chan string
	done     chan struct{}
}

func startDummyUpstream(t *testing.T) *dummyUpstreamServer {
	t.Helper()
	// USK-999: the retry path dials via connector.RedialUpstreamH1 which
	// always goes through TLS (matching production CONNECT-MITM shape).
	// The upstream listener must therefore terminate TLS — plain HTTP
	// would trip the TLS handshake on the redial leg.
	cert := generateSelfSignedCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	s := &dummyUpstreamServer{
		ln:       ln,
		addr:     ln.Addr().String(),
		gotPaths: make(chan string, 16),
		done:     make(chan struct{}),
	}
	go func() {
		defer close(s.done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *dummyUpstreamServer) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	defer req.Body.Close()
	body, _ := io.ReadAll(req.Body)
	_ = body
	s.gotReqs.Add(1)
	select {
	case s.gotPaths <- req.URL.Path:
	default:
	}
	_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK"))
}

// buildFlakyChain constructs an h1Chain whose initial Layer wraps a
// flakyConn (peer-side connected to the dummy upstream server) so the
// FIRST request's Send hits EPIPE. The retry wrapper's chain.Redial
// then dials a fresh HTTP/1.1 conn to s.addr through RedialUpstreamH1.
func buildFlakyChain(t *testing.T, s *dummyUpstreamServer, failCount int32) (*h1Chain, *http1.Layer, *flakyConn) {
	t.Helper()
	return buildFlakyChainWithMetrics(t, s, failCount, nil)
}

// buildFlakyChainWithMetrics is the metrics-aware form: callers
// supplying a non-nil [H1UpstreamMetrics] can read counter values
// after the retry path runs to assert end-to-end instrumentation.
// Tests that don't care about counters use [buildFlakyChain] which
// delegates here with nil.
func buildFlakyChainWithMetrics(
	t *testing.T,
	s *dummyUpstreamServer,
	failCount int32,
	metrics *H1UpstreamMetrics,
) (*h1Chain, *http1.Layer, *flakyConn) {
	t.Helper()
	// Dial the upstream once via raw TCP and wrap with flakyConn.
	rawConn, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	flaky := &flakyConn{Conn: rawConn}
	flaky.failCount.Store(failCount)

	envCtx := envelope.EnvelopeContext{ConnID: "test-conn-999", TargetHost: s.addr}
	initial := http1.New(flaky, "stream-999", envelope.Receive,
		http1.WithEnvelopeContext(envCtx),
	)
	t.Cleanup(func() { _ = initial.Close() })

	// BuildConfig for redial — TLS upstream with InsecureSkipVerify
	// (self-signed cert in tests). RedialUpstreamH1 always dials TLS;
	// the test's dummy upstream terminates TLS to match production
	// CONNECT-MITM shape.
	cfg := &connector.BuildConfig{InsecureSkipVerify: true}

	chain := newH1Chain(initial, s.addr, cfg, nil, metrics)
	t.Cleanup(func() { chain.closeAll() })

	return chain, initial, flaky
}

// sendOneRequest builds a single HTTP/1.1 GET / Envelope and Sends
// through the wrapper. Drains the response (so termDone fires) and
// returns the Send error (if any).
func sendOneRequest(t *testing.T, wrapper layer.Channel, method, path string, body []byte, bodyBuffered bool) error {
	t.Helper()
	msg := &envelope.HTTPMessage{
		Method:    method,
		Scheme:    "http",
		Authority: "example.com",
		Path:      path,
		Headers: []envelope.KeyValue{
			{Name: "Host", Value: "example.com"},
			{Name: "User-Agent", Value: "usk-999-test"},
		},
	}
	if len(body) > 0 {
		if bodyBuffered {
			msg.BodyBuffer = bodybuf.NewMemory(body)
			msg.Headers = append(msg.Headers, envelope.KeyValue{Name: "Content-Length", Value: itoa(len(body))})
		} else {
			msg.Body = body
			msg.Headers = append(msg.Headers, envelope.KeyValue{Name: "Content-Length", Value: itoa(len(body))})
		}
	} else {
		msg.Headers = append(msg.Headers, envelope.KeyValue{Name: "Content-Length", Value: "0"})
	}
	env := &envelope.Envelope{
		Protocol:  envelope.ProtocolHTTP,
		Direction: envelope.Send,
		Message:   msg,
		StreamID:  "stream-999",
	}
	return wrapper.Send(context.Background(), env)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// TestHTTP1_StaleConn_GET_RetryPath: GET → first Write EPIPE → wrapper
// triggers chain.Redial → fresh upstream Layer → retry Send → success.
// The dummy upstream observes 1 request landed on the fresh conn.
func TestHTTP1_StaleConn_GET_RetryPath(t *testing.T) {
	s := startDummyUpstream(t)

	chain, _, flaky := buildFlakyChain(t, s, 1)

	// First exchange.
	upCh := chain.current.OpenExchange()
	if upCh == nil {
		t.Fatal("OpenExchange returned nil")
	}
	dispatchWrap := func(ch layer.Channel) layer.Channel { return ch }
	wrapper := newRetryingUpstreamChannel(dispatchWrap(upCh), chain, dispatchWrap, slog.Default(), s.addr, nil)

	if err := sendOneRequest(t, wrapper, "GET", "/replayed", nil, false); err != nil {
		t.Fatalf("Send (GET, expected retry-success): %v", err)
	}

	// Drain the response on the wrapper so the channel terminates cleanly.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := wrapper.Next(ctx); err != nil {
		t.Fatalf("Next after retry: %v", err)
	}

	if got := flaky.failCount.Load(); got != 0 {
		t.Errorf("flakyConn failCount = %d, want 0 (consumed)", got)
	}
	if got := s.gotReqs.Load(); got < 1 {
		t.Errorf("upstream gotReqs = %d, want >= 1", got)
	}
	if got := len(chain.layers); got != 2 {
		t.Errorf("chain.layers = %d, want 2 (original + redial)", got)
	}
}

// TestHTTP1_StaleConn_GET_RetryPath_Metrics is the USK-1000 mirror of
// TestHTTP1_StaleConn_GET_RetryPath: same retry-path-success scenario
// but with a non-nil [H1UpstreamMetrics] threaded through the chain
// and wrapper so the counter snapshot can be asserted end-to-end.
// Pins the chain→retry→success counter triplet
// (write_epipe + redial_write_epipe + replay_success).
func TestHTTP1_StaleConn_GET_RetryPath_Metrics(t *testing.T) {
	s := startDummyUpstream(t)

	metrics := NewH1UpstreamMetrics()
	chain, _, _ := buildFlakyChainWithMetrics(t, s, 1, metrics)

	upCh := chain.current.OpenExchange()
	if upCh == nil {
		t.Fatal("OpenExchange returned nil")
	}
	dispatchWrap := func(ch layer.Channel) layer.Channel { return ch }
	wrapper := newRetryingUpstreamChannel(dispatchWrap(upCh), chain, dispatchWrap, slog.Default(), s.addr, metrics)

	if err := sendOneRequest(t, wrapper, "GET", "/metric-replayed", nil, false); err != nil {
		t.Fatalf("Send (GET, expected retry-success): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := wrapper.Next(ctx); err != nil {
		t.Fatalf("Next after retry: %v", err)
	}

	snap := metrics.Snapshot()
	if snap.WriteEpipe != 1 {
		t.Errorf("write_epipe = %d, want 1", snap.WriteEpipe)
	}
	if snap.RedialWriteEpipe != 1 {
		t.Errorf("redial_write_epipe = %d, want 1", snap.RedialWriteEpipe)
	}
	if snap.ReplaySuccess != 1 {
		t.Errorf("replay_success = %d, want 1", snap.ReplaySuccess)
	}
	// The healthcheck-triggered path did NOT fire on this exchange
	// (the wrapper used force-redial after EPIPE).
	if snap.StaleDetectedHealthcheck != 0 || snap.RedialHealthcheck != 0 {
		t.Errorf("healthcheck-trigger counters fired unexpectedly: %+v", snap)
	}
	if snap.ChainGenerationMax != 1 {
		t.Errorf("chain_generation_max = %d, want 1 (one redial step)", snap.ChainGenerationMax)
	}
	if snap.ChainGenerationLive != 1 {
		t.Errorf("chain_generation_live = %d, want 1 (chain still open)", snap.ChainGenerationLive)
	}
}

// TestHTTP1_StaleConn_POST_NoRetry: POST → first Write EPIPE → wrapper
// observes ReplaySafe=false → returns the StaleUpstreamError to the
// caller. No retry, no chain.Redial.
func TestHTTP1_StaleConn_POST_NoRetry(t *testing.T) {
	s := startDummyUpstream(t)

	chain, _, _ := buildFlakyChain(t, s, 1)

	upCh := chain.current.OpenExchange()
	if upCh == nil {
		t.Fatal("OpenExchange returned nil")
	}
	dispatchWrap := func(ch layer.Channel) layer.Channel { return ch }
	wrapper := newRetryingUpstreamChannel(dispatchWrap(upCh), chain, dispatchWrap, slog.Default(), s.addr, nil)

	err := sendOneRequest(t, wrapper, "POST", "/no-replay", []byte("payload"), false)
	if err == nil {
		t.Fatal("Send (POST, expected NoRetry): got nil error, want StaleUpstreamError surfaced")
	}
	var stale *http1.StaleUpstreamError
	if !errors.As(err, &stale) {
		t.Fatalf("Send (POST): err = %v (%T), want *http1.StaleUpstreamError", err, err)
	}
	if stale.ReplaySafe {
		t.Error("POST StaleUpstreamError ReplaySafe = true, want false")
	}
	if got := len(chain.layers); got != 1 {
		t.Errorf("chain.layers = %d, want 1 (POST should not redial)", got)
	}
}

// TestHTTP1_StaleConn_PUT_WithBuffer_Retry: PUT with a BodyBuffer →
// first Write EPIPE → wrapper retries (PUT is in replaySafeMethods and
// the body is buffered/replayable). Asserts chain.Redial fired.
func TestHTTP1_StaleConn_PUT_WithBuffer_Retry(t *testing.T) {
	s := startDummyUpstream(t)

	chain, _, _ := buildFlakyChain(t, s, 1)

	upCh := chain.current.OpenExchange()
	if upCh == nil {
		t.Fatal("OpenExchange returned nil")
	}
	dispatchWrap := func(ch layer.Channel) layer.Channel { return ch }
	wrapper := newRetryingUpstreamChannel(dispatchWrap(upCh), chain, dispatchWrap, slog.Default(), s.addr, nil)

	if err := sendOneRequest(t, wrapper, "PUT", "/put-replay", []byte("put-payload"), true); err != nil {
		t.Fatalf("Send (PUT with buffered body, expected retry-success): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := wrapper.Next(ctx); err != nil {
		t.Fatalf("Next after PUT retry: %v", err)
	}

	if got := s.gotReqs.Load(); got < 1 {
		t.Errorf("upstream gotReqs = %d, want >= 1", got)
	}
	if got := len(chain.layers); got != 2 {
		t.Errorf("chain.layers = %d, want 2 (original + redial)", got)
	}
}

// TestHTTP1_NoEnvelopeLossOnRetry: a successful GET retry must surface
// exactly one response Envelope. The retry path swaps the inner Channel
// to a fresh OpenExchange, and Next must read the response off the
// fresh upstream (not the stale conn).
func TestHTTP1_NoEnvelopeLossOnRetry(t *testing.T) {
	s := startDummyUpstream(t)

	chain, _, _ := buildFlakyChain(t, s, 1)

	upCh := chain.current.OpenExchange()
	if upCh == nil {
		t.Fatal("OpenExchange returned nil")
	}
	dispatchWrap := func(ch layer.Channel) layer.Channel { return ch }
	wrapper := newRetryingUpstreamChannel(dispatchWrap(upCh), chain, dispatchWrap, slog.Default(), s.addr, nil)

	if err := sendOneRequest(t, wrapper, "GET", "/observable", nil, false); err != nil {
		t.Fatalf("Send (GET): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	envResp, err := wrapper.Next(ctx)
	if err != nil {
		t.Fatalf("Next 1st (response): %v", err)
	}
	if envResp == nil || envResp.Message == nil {
		t.Fatal("Next: nil envelope/message; expected response")
	}
	httpMsg, ok := envResp.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("response envelope Message = %T, want *envelope.HTTPMessage", envResp.Message)
	}
	if httpMsg.Status != 200 {
		t.Errorf("response status = %d, want 200", httpMsg.Status)
	}

	// Confirm a second Next returns io.EOF (per-exchange Channel one-shot).
	_, err = wrapper.Next(ctx)
	if err == nil {
		t.Error("Next 2nd: got nil, want io.EOF after exchange completion")
	}
}

// TestHTTP1_StaleConn_RetryBudgetOneShot pins the "exactly one retry"
// invariant from the design review. After the first EPIPE → retry →
// succeed cycle, we drive a second Send through a stub inner that
// surfaces another *StaleUpstreamError{ReplaySafe:true}; the wrapper
// MUST return it verbatim without calling chain.Redial a second time.
func TestHTTP1_StaleConn_RetryBudgetOneShot(t *testing.T) {
	s := startDummyUpstream(t)

	chain, _, _ := buildFlakyChain(t, s, 1)

	upCh := chain.current.OpenExchange()
	if upCh == nil {
		t.Fatal("OpenExchange returned nil")
	}
	dispatchWrap := func(ch layer.Channel) layer.Channel { return ch }
	wrapper := newRetryingUpstreamChannel(dispatchWrap(upCh), chain, dispatchWrap, slog.Default(), s.addr, nil)

	// First Send: GET → EPIPE → retry → succeed.
	if err := sendOneRequest(t, wrapper, "GET", "/first", nil, false); err != nil {
		t.Fatalf("Send 1st: %v", err)
	}

	// Confirm the retried bool flipped — budget consumed.
	if !wrapper.retried.Load() {
		t.Error("wrapper.retried = false after successful retry, want true (budget consumed)")
	}

	// Snapshot the chain length AFTER the first retry so a stray
	// second redial would be observable.
	layersAfterFirst := len(chain.layers)

	// Swap the inner to a stub that returns ReplaySafe=true stale; the
	// wrapper MUST surface this verbatim because the one-shot budget is
	// consumed.
	stale := &http1.StaleUpstreamError{
		Underlying: syscall.EPIPE,
		ReplaySafe: true,
		Stage:      "header",
	}
	stub := layer.Channel(&replayStubChannel{sendErr: stale})
	wrapper.inner.Store(&stub)

	msg := &envelope.HTTPMessage{Method: "GET", Path: "/second", Authority: "example.com"}
	env := &envelope.Envelope{Protocol: envelope.ProtocolHTTP, Direction: envelope.Send, Message: msg}
	err := wrapper.Send(context.Background(), env)
	if err == nil {
		t.Fatal("Send 2nd: got nil, want StaleUpstreamError verbatim (budget exhausted)")
	}
	var stale2 *http1.StaleUpstreamError
	if !errors.As(err, &stale2) {
		t.Fatalf("Send 2nd: err = %v (%T), want *StaleUpstreamError verbatim", err, err)
	}
	if got := len(chain.layers); got != layersAfterFirst {
		t.Errorf("chain.layers = %d after second Send; want %d (no second redial)", got, layersAfterFirst)
	}
}

// TestHTTP1_StaleConn_NonReplaySafe_ReturnsErrorVerbatim covers the
// case where the inner returns a stale-conn error but ReplaySafe=false
// (e.g. POST). The wrapper must NOT redial and must NOT swap inner.
// The error is the StaleUpstreamError verbatim (errors.As-reachable
// for diagnostic logging by the session loop).
func TestHTTP1_StaleConn_NonReplaySafe_ReturnsErrorVerbatim(t *testing.T) {
	s := startDummyUpstream(t)

	chain, _, _ := buildFlakyChain(t, s, 1)
	originalLayer := chain.current

	upCh := chain.current.OpenExchange()
	dispatchWrap := func(ch layer.Channel) layer.Channel { return ch }
	wrapper := newRetryingUpstreamChannel(dispatchWrap(upCh), chain, dispatchWrap, slog.Default(), s.addr, nil)

	err := sendOneRequest(t, wrapper, "POST", "/no-retry", []byte("p"), false)
	if err == nil {
		t.Fatal("Send (POST): got nil, want non-nil")
	}

	// chain.current must not have been swapped.
	if chain.current != originalLayer {
		t.Error("chain.current swapped after non-ReplaySafe error; redial must not fire")
	}
	if wrapper.retried.Load() {
		t.Error("wrapper.retried = true after non-ReplaySafe error; budget must not be consumed")
	}

	// The error must surface a *StaleUpstreamError up the chain.
	var stale *http1.StaleUpstreamError
	if !errors.As(err, &stale) {
		t.Errorf("err = %v (%T); want *StaleUpstreamError reachable via errors.As", err, err)
	}
}

// TestHTTP1_FlakyConn_NonStaleErrorNotRetried documents the contract:
// only known stale-conn sentinels trigger retry. A synthetic error
// (e.g. invalid envelope) passes through the wrapper unchanged.
//
// Since we cannot easily inject a non-stale error on the real Send
// path without wedging the parser, we test the wrapper directly with
// a stub inner Channel that returns a custom error. This exercises
// the same retry-decision tree.
func TestHTTP1_FlakyConn_NonStaleErrorNotRetried(t *testing.T) {
	chain := &h1Chain{} // unused (no retry fires)
	stub := &replayStubChannel{sendErr: errors.New("synthetic-unrelated-error")}
	wrapper := newRetryingUpstreamChannel(
		stub,
		chain,
		func(ch layer.Channel) layer.Channel { return ch },
		slog.Default(),
		"127.0.0.1:0",
		nil,
	)

	msg := &envelope.HTTPMessage{Method: "GET", Path: "/", Authority: "example.com"}
	env := &envelope.Envelope{Protocol: envelope.ProtocolHTTP, Direction: envelope.Send, Message: msg}
	err := wrapper.Send(context.Background(), env)
	if err == nil {
		t.Fatal("Send: got nil, want synthetic error")
	}
	if !strings.Contains(err.Error(), "synthetic-unrelated-error") {
		t.Errorf("err = %v; want substring 'synthetic-unrelated-error'", err)
	}
	if wrapper.retried.Load() {
		t.Error("retried = true on non-stale error; budget must not be consumed")
	}
}

// replayStubChannel is a minimal layer.Channel implementation used by the
// non-stale-error-not-retried test. Returns a fixed error from Send
// and otherwise behaves as a closed Channel.
type replayStubChannel struct {
	mu      sync.Mutex
	sendErr error
	closed  chan struct{}
	once    sync.Once
}

func (s *replayStubChannel) StreamID() string { return "stub" }
func (s *replayStubChannel) Next(_ context.Context) (*envelope.Envelope, error) {
	return nil, io.EOF
}
func (s *replayStubChannel) Send(_ context.Context, _ *envelope.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendErr
}
func (s *replayStubChannel) Close() error {
	s.once.Do(func() {
		s.closed = make(chan struct{})
		close(s.closed)
	})
	return nil
}
func (s *replayStubChannel) Closed() <-chan struct{} {
	s.once.Do(func() {
		s.closed = make(chan struct{})
	})
	return s.closed
}
func (s *replayStubChannel) Err() error { return io.EOF }
