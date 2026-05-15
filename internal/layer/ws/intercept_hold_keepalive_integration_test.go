//go:build e2e

// Package ws_test exercises the USK-854 WS hold-window keepalive injection
// path: while a WS frame is held in the intercept queue, the proxy emits
// synthetic WS Ping frames toward the upstream so the upstream's idle
// timer does not expire. When the hold is released the upstream is still
// warm and the released frame lands cleanly — distinct from USK-851
// (observability only).
//
// The test stays in the smoke tier (//go:build e2e) so a regression in
// the keepalive logic OR the USK-851 fallback (when keepalive is disabled)
// is caught on every PR.
package ws_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// TestWSHoldKeepalive_EnabledInjectsPingsDuringHold drives the full
// USK-854 path: client opens a WS, the proxy holds the first frame, the
// keepalive goroutine emits synthetic Pings toward the upstream while the
// hold is in flight, and we assert at least one Ping landed.
//
// Acceptance:
//   - >=1 Ping frame was observed on the upstream wire while the hold
//     was active.
//   - The synthetic Ping carries Opcode=0x9, Fin=true, and an empty
//     payload (RFC 6455 §5.5.2 permits empty Ping).
func TestWSHoldKeepalive_EnabledInjectsPingsDuringHold(t *testing.T) {
	runWSHoldKeepaliveCase(t, keepaliveCase{
		name:                   "enabled",
		keepaliveEnabled:       true,
		keepaliveInterval:      50 * time.Millisecond,
		holdDuration:           400 * time.Millisecond,
		assertPingObserved:     true,
		assertTagAppendedTag:   false,
		closeUpstreamWhileHeld: false,
	})
}

// TestWSHoldKeepalive_DisabledStillTagsEOF is the regression guard for the
// USK-851 fallback behaviour. With keepalive disabled (default) the
// existing observability-only path must still append the
// intercept_hold_outcome=upstream_closed_after_intercept_release tag when
// the upstream EOFs shortly after release.
func TestWSHoldKeepalive_DisabledStillTagsEOF(t *testing.T) {
	runWSHoldKeepaliveCase(t, keepaliveCase{
		name:                   "disabled",
		keepaliveEnabled:       false,
		keepaliveInterval:      50 * time.Millisecond,
		holdDuration:           200 * time.Millisecond,
		assertPingObserved:     false,
		assertTagAppendedTag:   true,
		closeUpstreamWhileHeld: true,
	})
}

type keepaliveCase struct {
	name                   string
	keepaliveEnabled       bool
	keepaliveInterval      time.Duration
	holdDuration           time.Duration
	assertPingObserved     bool
	assertTagAppendedTag   bool
	closeUpstreamWhileHeld bool
}

// pingObserver reads bytes off upstreamB and counts the Ping frames it
// observes. It is the test-side "upstream WS server" — it does not write
// anything back (the test does not care about Pong reflection because we
// only assert on the Ping appearing on the wire).
type pingObserver struct {
	mu       sync.Mutex
	pingHits int32
	wireBuf  []byte
}

func (o *pingObserver) snapshot() (int, []byte) {
	o.mu.Lock()
	defer o.mu.Unlock()
	buf := append([]byte(nil), o.wireBuf...)
	return int(atomic.LoadInt32(&o.pingHits)), buf
}

func runWSHoldKeepaliveCase(t *testing.T, tc keepaliveCase) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientA, clientB := pipePairUSK854(t)
	upstreamA, upstreamB := pipePairUSK854(t)
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
		_ = upstreamA.Close()
		_ = upstreamB.Close()
	})

	stack := connector.NewConnectionStack("usk854-conn")
	clientLayer := http1.New(clientB, "client-stream", envelope.Send)
	upstreamLayer := http1.New(upstreamA, "upstream-stream", envelope.Receive)
	stack.PushClient(clientLayer)
	stack.PushUpstream(upstreamLayer)
	t.Cleanup(func() { _ = stack.Close() })

	store := &tagCapturingStore{}

	wsEngine := wsrules.NewInterceptEngine()
	wsEngine.SetRules([]wsrules.InterceptRule{{
		ID:        "usk854-catch-all",
		Enabled:   true,
		Direction: wsrules.DirectionBoth,
	}})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(30 * time.Second)
	releaseTracker := common.NewReleaseTracker()
	holdTracker := common.NewHoldTracker()

	logger := slog.Default()
	steps := []pipeline.Step{
		pipeline.NewHostScopeStep(nil),
		pipeline.NewHTTPScopeStep(nil),
		pipeline.NewSafetyStep(nil, nil, nil, logger),
		pipeline.NewTransformStep(nil, nil, nil, nil),
		pipeline.NewInterceptStep(nil, wsEngine, nil, nil, holdQueue, nil, logger).
			WithHoldTracker(holdTracker),
		pipeline.NewRecordStep(store, logger),
		session.NewUpgradeStep(),
	}
	p := pipeline.New(steps...)

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		ch, ok := <-upstreamLayer.Channels()
		if !ok || ch == nil {
			return nil, errors.New("upstream Channels closed before yielding")
		}
		return ch, nil
	}

	sessionDone := make(chan struct{})
	var sessionErr error
	var once sync.Once
	opts := session.SessionOptions{
		InterceptReleaseTracker: releaseTracker,
		InterceptHoldTracker:    holdTracker,
		WSHoldKeepaliveEnabled:  tc.keepaliveEnabled,
		WSHoldKeepaliveInterval: tc.keepaliveInterval,
		OnInterceptReleaseEOF: func(cbCtx context.Context, streamID string) {
			_ = store.UpdateStream(cbCtx, streamID, flow.StreamUpdate{
				AppendTags: map[string]string{
					"intercept_hold_outcome": "upstream_closed_after_intercept_release",
				},
			})
		},
		OnComplete: func(cbCtx context.Context, streamID string, err error) {
			state := "complete"
			if err != nil && !errors.Is(err, io.EOF) {
				state = "error"
			}
			if streamID != "" {
				_ = store.UpdateStream(cbCtx, streamID, flow.StreamUpdate{
					State:         state,
					FailureReason: session.ClassifyError(err),
				})
			}
		},
	}

	go func() {
		defer close(sessionDone)
		err := session.RunStackSession(ctx, stack, dial, p, opts)
		once.Do(func() { sessionErr = err })
	}()

	// Drive the WS upgrade handshake, then observe upstream-wire bytes
	// looking for Pings injected by the proxy while the hold is in flight.
	observer := &pingObserver{}
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		runUpstreamServerForUSK854(t, upstreamB, observer)
	}()

	driveWSUpgradeUSK854(t, ctx, clientA, stack)

	// Client sends a single text frame; the catch-all intercept rule
	// holds it. The keepalive goroutine (if enabled) starts injecting
	// Pings into upstreamB at the configured cadence.
	writeMaskedTextFrame(t, clientA, []byte("usk854-payload"))

	// Wait for the held entry.
	heldID := waitForHeldEntry(t, holdQueue, 3*time.Second)
	heldEntry, err := holdQueue.Get(heldID)
	if err != nil {
		t.Fatalf("holdQueue.Get(%s): %v", heldID, err)
	}

	// Hold the frame for tc.holdDuration so the keepalive ticker
	// fires several times (interval=50ms, hold>=200ms → >=3 ticks).
	time.Sleep(tc.holdDuration)

	if tc.assertPingObserved {
		// Snapshot the upstream wire BEFORE we release so we are only
		// counting Pings that fired during the hold window. After release,
		// the released text frame also appears on the wire and would
		// confound the assertion if we counted post-release.
		pings, _ := observer.snapshot()
		if pings < 1 {
			t.Errorf("expected >=1 synthetic Ping observed on upstream wire during hold (interval=%s, hold=%s); got %d",
				tc.keepaliveInterval, tc.holdDuration, pings)
		}
	} else {
		// Disabled path: no Pings should appear during the hold window.
		pings, _ := observer.snapshot()
		if pings != 0 {
			t.Errorf("expected 0 Pings observed (keepalive disabled); got %d", pings)
		}
	}

	if tc.closeUpstreamWhileHeld {
		// USK-851 fallback: simulate the upstream half-close path. Stamp
		// release tracker (mirrors the production MCP intercept tool
		// path) then release the frame; close upstream so the relay sees
		// EOF within the correlation window.
		now := time.Now()
		releaseTracker.MarkRelease(heldEntry.Envelope.StreamID, heldEntry.Envelope.Direction, now)
		if err := holdQueue.Release(heldID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
			t.Fatalf("Release: %v", err)
		}
		// Let the released frame clear the dst.Send path.
		time.Sleep(100 * time.Millisecond)
		_ = upstreamB.Close()
	} else {
		// Enabled path: release the frame normally. The keepalive
		// goroutine sees IsHeld=false on its next tick and stops
		// injecting; the relay tears down cleanly when we close the
		// client.
		if err := holdQueue.Release(heldID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
			t.Fatalf("Release: %v", err)
		}
	}

	_ = clientA.Close()
	// Close upstream too so both relay goroutines see EOF and the session
	// tears down. Without this, the keepalive-enabled case leaves the
	// Receive-direction relay goroutine parked on upstream.Next forever
	// because the upstream side never half-closes on its own. The
	// closeUpstreamWhileHeld branch already closed upstreamB above; this
	// second Close is idempotent (net.Conn.Close returns an error on the
	// second invocation but we ignore it).
	if !tc.closeUpstreamWhileHeld {
		_ = upstreamB.Close()
	}
	select {
	case <-sessionDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("session did not terminate within 5s; err=%v", sessionErr)
	}

	if tc.assertTagAppendedTag {
		if !store.hasTag("intercept_hold_outcome", "upstream_closed_after_intercept_release") {
			t.Errorf("expected USK-851 tag; got updates=%d, tag batches=%d",
				len(store.streamUpdates), len(store.appendTagBatch))
		}
	}

	// Drain the upstream-observer goroutine. The pipe is closed; the
	// reader returns immediately.
	select {
	case <-upstreamDone:
	case <-time.After(2 * time.Second):
	}
}

// pipePairUSK854 mirrors pipePairUSK851; duplicated to keep this file
// self-contained per the project's per-file isolation convention.
func pipePairUSK854(t *testing.T) (a, b net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	ch := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, accErr := ln.Accept()
		if accErr != nil {
			errCh <- accErr
			return
		}
		ch <- c
	}()
	a, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case b = <-ch:
		return a, b
	case err = <-errCh:
		t.Fatalf("accept: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatalf("pipePairUSK854: accept timeout")
	}
	return nil, nil
}

// runUpstreamServerForUSK854 reads the WS upgrade request, writes the 101
// response, then continuously reads frames off the upstream wire counting
// the Ping opcodes it observes. Non-Ping bytes are still consumed but
// not counted.
//
// The function returns when the conn closes or a read error surfaces.
func runUpstreamServerForUSK854(t *testing.T, upstreamB net.Conn, observer *pingObserver) {
	t.Helper()

	// Read the upgrade request, then write 101.
	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	_ = upstreamB.SetReadDeadline(deadline)
	for {
		n, err := upstreamB.Read(buf)
		if err != nil {
			return
		}
		if n > 0 && containsBlankLine(buf[:n]) {
			const resp101 = "HTTP/1.1 101 Switching Protocols\r\n" +
				"Upgrade: websocket\r\n" +
				"Connection: Upgrade\r\n" +
				"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
				"\r\n"
			if _, werr := upstreamB.Write([]byte(resp101)); werr != nil {
				return
			}
			break
		}
	}
	_ = upstreamB.SetReadDeadline(time.Time{})

	// Frame-level read loop. ReadFrame parses one WS frame at a time off
	// the connection and surfaces an unmasked Frame struct. Pings flowing
	// proxy→upstream are unmasked (RoleClient with h2Mode=false would
	// normally mask, but the proxy's ws.Layer is RoleClient writing toward
	// upstream which means MASKED frames per RFC 6455 §5.3 — see
	// applySendMask). ReadFrame handles unmasking transparently.
	for {
		f, err := ws.ReadFrame(upstreamB)
		if err != nil {
			return
		}
		if f.Opcode == ws.OpcodePing {
			atomic.AddInt32(&observer.pingHits, 1)
		}
		// Any other opcode is consumed silently; the test does not
		// assert beyond the Ping count.
	}
}

// driveWSUpgradeUSK854 drives the client side of the WS upgrade handshake.
// The upstream side is driven by runUpstreamServerForUSK854.
func driveWSUpgradeUSK854(t *testing.T, ctx context.Context, clientA net.Conn, stack *connector.ConnectionStack) {
	t.Helper()

	const req = "GET /chat HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"

	if _, err := clientA.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}
	// Read the 101 off clientA.
	resp := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	_ = clientA.SetReadDeadline(deadline)
	for {
		n, err := clientA.Read(resp)
		if err != nil {
			t.Fatalf("read 101: %v", err)
		}
		if n > 0 && containsBlankLine(resp[:n]) {
			break
		}
	}
	_ = clientA.SetReadDeadline(time.Time{})

	swapDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(swapDeadline) {
		_, clientOK := stack.ClientTopmost().(*ws.Layer)
		_, upOK := stack.UpstreamTopmost().(*ws.Layer)
		if clientOK && upOK {
			time.Sleep(50 * time.Millisecond)
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("ctx cancelled before WS swap: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("WS swap did not complete: client=%T upstream=%T",
		stack.ClientTopmost(), stack.UpstreamTopmost())
}
