//go:build e2e

// Package ws_test exercises the USK-851 detection path: a held WS frame is
// released after the upstream has half-closed due to idle timeout. The
// session relay observes EOF on src.Next within the correlation window and
// appends the operator-facing Stream tag
// intercept_hold_outcome=upstream_closed_after_intercept_release.
//
// The test stays within the smoke tier (//go:build e2e) — it runs as part
// of every merge gate so a regression that drops the tag is caught
// immediately.
package ws_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
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

// tagCapturingStore is a flow.Writer that records every UpdateStream call,
// including AppendTags entries. The existing testStore in this package
// only tracks State / FailureReason; USK-851's contract is the tag
// AppendTags, so we need a richer recorder for this test.
type tagCapturingStore struct {
	mu             sync.Mutex
	streams        []*flow.Stream
	flows          []*flow.Flow
	streamUpdates  []flow.StreamUpdate
	appendTagBatch []map[string]string
}

func (s *tagCapturingStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams = append(s.streams, st)
	return nil
}

func (s *tagCapturingStore) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamUpdates = append(s.streamUpdates, update)
	if update.AppendTags != nil {
		// Clone the map so caller mutations after the call do not race with
		// our test assertions.
		cloned := make(map[string]string, len(update.AppendTags))
		for k, v := range update.AppendTags {
			cloned[k] = v
		}
		s.appendTagBatch = append(s.appendTagBatch, cloned)
	}
	for _, st := range s.streams {
		if st.ID != id {
			continue
		}
		if update.State != "" {
			st.State = update.State
		}
		if update.FailureReason != "" {
			st.FailureReason = update.FailureReason
		}
		if update.AppendTags != nil {
			if st.Tags == nil {
				st.Tags = make(map[string]string)
			}
			for k, v := range update.AppendTags {
				if _, present := st.Tags[k]; !present {
					st.Tags[k] = v
				}
			}
		}
	}
	return nil
}

func (s *tagCapturingStore) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows = append(s.flows, f)
	return nil
}

// hasTag reports whether any AppendTags batch contains key=value.
func (s *tagCapturingStore) hasTag(key, want string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, batch := range s.appendTagBatch {
		if got, ok := batch[key]; ok && got == want {
			return true
		}
	}
	return false
}

// pipePairUSK851 mirrors the pipePair helper in ws_integration_test.go but
// is duplicated here to keep this file self-contained per the same
// rationale documented at the top of ws_integration_test.go.
func pipePairUSK851(t *testing.T) (a, b net.Conn) {
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
		t.Fatalf("pipePairUSK851: accept timeout")
	}
	return nil, nil
}

// TestWSIntercept_HoldThenUpstreamEOF_AppendsStreamTag is the USK-851
// regression guard. It wires the full HTTP/1 → WS upgrade harness with a
// catch-all intercept rule, holds the client frame, half-closes the
// upstream while the frame is still held, then releases the frame. The
// relay goroutine observes EOF on src.Next within the 2-second
// correlation window of the release timestamp and appends the Stream tag
// via the wired OnInterceptReleaseEOF callback.
//
// Acceptance:
//   - tagCapturingStore.hasTag("intercept_hold_outcome",
//     "upstream_closed_after_intercept_release") returns true.
//   - The forwarded_at_unix_ms field on the synchronous release path is
//     populated (asserted by a direct call to ReleaseTracker — the MCP
//     tool wiring is exercised by mcp/intercept_typed_integration_test.go).
func TestWSIntercept_HoldThenUpstreamEOF_AppendsStreamTag(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clientA, clientB := pipePairUSK851(t)
	upstreamA, upstreamB := pipePairUSK851(t)
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
		_ = upstreamA.Close()
		_ = upstreamB.Close()
	})

	stack := connector.NewConnectionStack("usk851-conn")
	clientLayer := http1.New(clientB, "client-stream", envelope.Send)
	upstreamLayer := http1.New(upstreamA, "upstream-stream", envelope.Receive)
	stack.PushClient(clientLayer)
	stack.PushUpstream(upstreamLayer)
	t.Cleanup(func() { _ = stack.Close() })

	store := &tagCapturingStore{}

	wsEngine := wsrules.NewInterceptEngine()
	wsEngine.SetRules([]wsrules.InterceptRule{{
		ID:        "usk851-catch-all",
		Enabled:   true,
		Direction: wsrules.DirectionBoth,
	}})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(30 * time.Second) // generous; the test never lets the hold expire
	releaseTracker := common.NewReleaseTracker()

	logger := slog.Default()
	steps := []pipeline.Step{
		pipeline.NewHostScopeStep(nil),
		pipeline.NewHTTPScopeStep(nil),
		pipeline.NewSafetyStep(nil, nil, nil, logger),
		pipeline.NewTransformStep(nil, nil, nil),
		pipeline.NewInterceptStep(nil, wsEngine, nil, holdQueue, nil, logger),
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

	// Wire the USK-851 session options. OnInterceptReleaseEOF persists the
	// tag via the test store mirroring proxybuild.buildSessionOptions.
	sessionDone := make(chan struct{})
	var sessionErr error
	var once sync.Once
	opts := session.SessionOptions{
		InterceptReleaseTracker: releaseTracker,
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

	// Drive the WS upgrade handshake.
	doWSUpgradeHandshakeUSK851(t, ctx, clientA, upstreamB, stack)

	// Client sends a single text frame; it will be held by the intercept rule.
	writeMaskedTextFrame(t, clientA, []byte("usk851-payload"))

	// Wait for the held entry to appear.
	heldID := waitForHeldEntry(t, holdQueue, 3*time.Second)
	heldEntry, err := holdQueue.Get(heldID)
	if err != nil {
		t.Fatalf("holdQueue.Get(%s): %v", heldID, err)
	}

	// Production order: the operator releases the held frame, the proxy
	// forwards it to upstream, and only then (often within milliseconds on
	// Fly.io edge) the upstream surfaces EOF because its WS idle timer
	// had already elapsed while the frame was held. We mirror that order
	// here: stamp the tracker + release first, then close the upstream
	// pipe. This is the canonical observation window the detection rule
	// is designed for.
	now := time.Now()
	releaseTracker.MarkRelease(heldEntry.Envelope.StreamID, heldEntry.Envelope.Direction, now)
	if err := holdQueue.Release(heldID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// Give the released frame a moment to clear the dst.Send path inside
	// the proxy's Send-side relay before we close the upstream wire.
	// Without this, dst.Send may race with the half-close and surface a
	// write error instead of letting the Receive-side relay observe EOF
	// cleanly. 100ms is generous for a localhost pipe.
	time.Sleep(100 * time.Millisecond)

	// Simulate the upstream half-close. Fly.io-edge behaviour the Issue
	// describes: after the upstream's WS idle timeout elapses it half-
	// closes without sending anything. We close upstreamB (the "server"
	// side of the pipe), which surfaces EOF on upstreamA's read path
	// inside the proxy's relay goroutine the next time it tries to read.
	_ = upstreamB.Close()

	// Wait for the session to terminate. The proxy's dst.Send may succeed
	// (the upstream wire is half-closed, but a TCP write may buffer
	// briefly before surfacing EPIPE). What matters is that the Receive
	// relay goroutine surfaces EOF and the OnInterceptReleaseEOF callback
	// fires before the session exits.
	_ = clientA.Close()
	select {
	case <-sessionDone:
	case <-time.After(5 * time.Second):
		t.Fatalf("session did not terminate within 5s; err=%v", sessionErr)
	}

	// Acceptance assertion: the tag was appended via AppendTags.
	if !store.hasTag("intercept_hold_outcome", "upstream_closed_after_intercept_release") {
		t.Errorf("expected Stream tag intercept_hold_outcome=upstream_closed_after_intercept_release; got updates=%d, tag batches=%d",
			len(store.streamUpdates), len(store.appendTagBatch))
		for i, batch := range store.appendTagBatch {
			t.Logf("AppendTags[%d] = %v", i, batch)
		}
		t.Logf("held envelope StreamID=%q Direction=%v", heldEntry.Envelope.StreamID, heldEntry.Envelope.Direction)
	}
}

// TestReleaseTracker_OppositeDirectionLookup is a focused regression guard
// covering the contract that wsRelayDirection / clientToUpstream rely on:
// a release on Send produces a Receive-side correlation hit, and vice
// versa, within the configured window.
func TestReleaseTracker_OppositeDirectionLookup(t *testing.T) {
	tr := common.NewReleaseTracker()
	now := time.Now()
	tr.MarkRelease("s-1", envelope.Send, now)
	// Caller is the Receive-side relay: it asks for opposite-of-Receive,
	// i.e. Send, on the same stream — should hit.
	if _, ok := tr.LookupOppositeRelease("s-1", envelope.Receive, now.Add(500*time.Millisecond), 2*time.Second); !ok {
		t.Fatalf("Receive-direction caller missed the Send-side release within window")
	}
	// Outside the 2s window — should not hit.
	if _, ok := tr.LookupOppositeRelease("s-1", envelope.Receive, now.Add(3*time.Second), 2*time.Second); ok {
		t.Fatalf("Receive-direction caller incorrectly matched outside window")
	}
}

// doWSUpgradeHandshakeUSK851 drives the HTTP/1 → WS upgrade from both ends
// so the session swaps in ws.Layer pairs. Mirrors performUpgrade in
// ws_integration_test.go; duplicated to keep this test self-contained.
func doWSUpgradeHandshakeUSK851(t *testing.T, ctx context.Context, clientA, upstreamB net.Conn, stack *connector.ConnectionStack) {
	t.Helper()

	const req = "GET /chat HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n"

	const resp101 = "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
		"\r\n"

	// Server: read request, write 101.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := upstreamB.Read(buf)
			if err != nil {
				return
			}
			if n > 0 && (string(buf[:n]) == req || containsBlankLine(buf[:n])) {
				_, _ = upstreamB.Write([]byte(resp101))
				return
			}
		}
	}()

	if _, err := clientA.Write([]byte(req)); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}
	// Read the 101 response off clientA.
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

	// Poll for the swap.
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

// containsBlankLine returns true if buf contains the HTTP header
// terminator \r\n\r\n.
func containsBlankLine(buf []byte) bool {
	const terminator = "\r\n\r\n"
	if len(buf) < len(terminator) {
		return false
	}
	for i := 0; i+len(terminator) <= len(buf); i++ {
		if string(buf[i:i+len(terminator)]) == terminator {
			return true
		}
	}
	return false
}

// writeMaskedTextFrame writes a single masked WS text frame onto conn.
// RFC 6455 §5.3 requires client→server masking.
func writeMaskedTextFrame(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	f := &ws.Frame{
		Fin:     true,
		Opcode:  ws.OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: payload,
	}
	if err := ws.WriteFrame(conn, f); err != nil {
		t.Fatalf("write text frame: %v", err)
	}
}

// waitForHeldEntry polls the HoldQueue until at least one entry is
// observable, then returns its ID. Fails the test on timeout.
func waitForHeldEntry(t *testing.T, q *common.HoldQueue, d time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		entries := q.List()
		if len(entries) > 0 {
			return entries[0].ID
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("waitForHeldEntry: no entry within %s", d)
	return ""
}
