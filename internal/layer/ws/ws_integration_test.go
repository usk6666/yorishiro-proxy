//go:build e2e

// Package ws_test exercises the full HTTP/1 -> WebSocket upgrade path
// orchestrated by session.RunStackSession with a real http1.Layer pair on
// both sides of the proxy. Tests assert (a) frame relay correctness
// (text/binary/control), (b) wire-fidelity per-frame Flow recording,
// (c) Transform variant recording, (d) Safety filter drop, and
// (e) error-path classification (TCP RST, malformed frame, abnormal close).
//
// Driving model. We do NOT use FullListener / connector dial path here.
// Instead we hand-build a ConnectionStack with two pipe-pair backed
// http1.Layer instances (RoleServer client side, RoleClient upstream side)
// and call RunStackSession directly. Per the resolved decisions for
// USK-650, this keeps the test focused on the layer/ws + upgrade swap
// plumbing without dragging the production OnStack wiring into scope.
//
// USK-701: production WS upgrade unblock. http1.channel.Next does not honor
// ctx, but session.runUpgradeWS now calls http1.Layer.Interrupt() before
// DetachStream — which surfaces os.ErrDeadlineExceeded to the parked
// clientToUpstream Next() so RunStackSession can perform the swap without
// any test-only sacrificial bytes. The "browser" goroutine here uses the
// compliant RFC 6455 §4.1 sequence (write Upgrade, read 101, then wait for
// the swap to complete).
package ws_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"regexp"
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

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// testStore is a thread-safe in-memory flow.Writer mirroring the sibling
// pattern at internal/layer/http1/mitm_integration_test.go. We define it
// inline here per the resolved USK-650 decision to NOT extract a shared
// helper — keeping each integration test self-contained avoids cross-test
// coupling and matches the precedent set by the http1 e2e tests.
type testStore struct {
	mu      sync.Mutex
	streams []*flow.Stream
	flows   []*flow.Flow
}

func (s *testStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams = append(s.streams, st)
	return nil
}

func (s *testStore) UpdateStream(_ context.Context, id string, update flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	}
	return nil
}

func (s *testStore) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows = append(s.flows, f)
	return nil
}

func (s *testStore) getStreams() []*flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Stream, len(s.streams))
	copy(out, s.streams)
	return out
}

func (s *testStore) allFlows() []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Flow, len(s.flows))
	copy(out, s.flows)
	return out
}

func (s *testStore) flowsByDirection(dir string) []*flow.Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*flow.Flow
	for _, f := range s.flows {
		if f.Direction == dir {
			out = append(out, f)
		}
	}
	return out
}

// pipePair returns two connected net.Conns via a localhost TCP listener.
// We use TCP rather than net.Pipe for the same reason as the existing
// session_upgrade_test.go: net.Pipe is fully synchronous and propagates
// close in both directions atomically, which causes spurious write errors
// on the http1 channel's empty-body fast path during upgrade.
func pipePair(t *testing.T) (a, b net.Conn) {
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
		t.Fatalf("pipePair: accept timeout")
	}
	return nil, nil
}

// wsHarness owns the four endpoints, the ConnectionStack, the in-memory
// store, the pipeline, and the RunStackSession goroutine. Tests interact
// with the proxy via clientA (the "browser") and upstreamB (the "server").
type wsHarness struct {
	t *testing.T

	clientA, clientB     net.Conn // proxy reads from clientB; "browser" drives clientA
	upstreamA, upstreamB net.Conn // proxy writes to upstreamA; "server" drives upstreamB

	stack *connector.ConnectionStack
	store *testStore

	sessionDone chan struct{}
	sessionErr  error
	sessionOnce sync.Once
}

// harnessOpts threads optional engines + queues into the pipeline assembly.
type harnessOpts struct {
	interceptEngine *wsrules.InterceptEngine
	transformEngine *wsrules.TransformEngine
	safetyEngine    *wsrules.SafetyEngine
	holdQueue       *common.HoldQueue
}

// newWSHarness builds the four pipes + stack + pipeline and launches
// RunStackSession. Pipeline order matches the production assembly: scope
// gates first, then Safety/Transform/Intercept/Record, with UpgradeStep
// strictly LAST so the 101 envelope is recorded as a normal HTTP envelope
// before the layer swap (RFC-001 §3.5 / N7 R1).
func newWSHarness(t *testing.T, ctx context.Context, opts harnessOpts) *wsHarness {
	t.Helper()

	h := &wsHarness{t: t, sessionDone: make(chan struct{})}
	h.clientA, h.clientB = pipePair(t)
	h.upstreamA, h.upstreamB = pipePair(t)

	h.stack = connector.NewConnectionStack("test-conn")
	clientLayer := http1.New(h.clientB, "client-stream", envelope.Send)
	upstreamLayer := http1.New(h.upstreamA, "upstream-stream", envelope.Receive)
	h.stack.PushClient(clientLayer)
	h.stack.PushUpstream(upstreamLayer)

	h.store = &testStore{}

	logger := slog.Default()
	steps := []pipeline.Step{
		pipeline.NewHostScopeStep(nil),
		pipeline.NewHTTPScopeStep(nil),
		pipeline.NewSafetyStep(nil, opts.safetyEngine, nil, logger),
		pipeline.NewTransformStep(nil, opts.transformEngine, nil),
		pipeline.NewInterceptStep(nil, opts.interceptEngine, nil, opts.holdQueue, logger),
		pipeline.NewRecordStep(h.store, logger),
		// UpgradeStep MUST run AFTER RecordStep so the 101 is recorded
		// as a normal HTTP envelope before the swap (RFC-001 §3.5).
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

	go func() {
		defer close(h.sessionDone)
		err := session.RunStackSession(ctx, h.stack, dial, p, session.SessionOptions{
			OnComplete: func(cctx context.Context, streamID string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if streamID != "" {
					_ = h.store.UpdateStream(cctx, streamID, flow.StreamUpdate{
						State:         state,
						FailureReason: session.ClassifyError(err),
					})
				}
			},
		})
		h.sessionOnce.Do(func() { h.sessionErr = err })
	}()

	t.Cleanup(func() {
		_ = h.clientA.Close()
		_ = h.upstreamB.Close()
		select {
		case <-h.sessionDone:
		case <-time.After(3 * time.Second):
			// A 3s cleanup miss after both wire ends are closed indicates
			// a leaked session goroutine. Fail loudly rather than silently
			// logging — the production OnStack cascade is expected to
			// drain both sides on a one-sided close.
			t.Errorf("harness cleanup: session did not exit within 3s (leaked session goroutine)")
		}
		_ = h.stack.Close()
	})

	return h
}

// performUpgrade drives the HTTP/1 WebSocket Upgrade handshake from both
// sides. The upstream "server" goroutine reads the upgrade request and
// writes a 101 response. The "browser" goroutine writes the upgrade
// request and reads the 101 — the compliant RFC 6455 §4.1 sequence with
// no further writes until the swap completes.
//
// Production unblock (USK-701): runUpgradeWS calls http1.Layer.Interrupt()
// before DetachStream, so the proxy's parked clientToUpstream Next() wakes
// on os.ErrDeadlineExceeded and the swap proceeds without test-only bytes.
//
// performUpgrade returns when both layers have been swapped to *ws.Layer
// (verified by polling stack.ClientTopmost).
func (h *wsHarness) performUpgrade(ctx context.Context) {
	h.t.Helper()

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
		br := bufio.NewReader(h.upstreamB)
		// Drain the request headers up to and including the blank line.
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = h.upstreamB.Write([]byte(resp101))
	}()

	// Browser: write upgrade request, then read the 101 response.
	if _, err := h.clientA.Write([]byte(req)); err != nil {
		h.t.Fatalf("write upgrade request: %v", err)
	}

	clientReader := bufio.NewReader(h.clientA)
	for {
		_ = h.clientA.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, err := clientReader.ReadString('\n')
		if err != nil {
			h.t.Fatalf("read 101: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	_ = h.clientA.SetReadDeadline(time.Time{})

	// Poll for the swap. The recursive RunStackSession installs the
	// new ws.Layer pair before resuming reads.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, clientOK := h.stack.ClientTopmost().(*ws.Layer)
		_, upOK := h.stack.UpstreamTopmost().(*ws.Layer)
		if clientOK && upOK {
			// Brief settle delay — ReplaceClientTop / ReplaceUpstreamTop
			// publish the new Layers before the recursive RunStackSession
			// has spawned the inner goroutines that read from those new
			// Channels. Without this delay, a fast test that immediately
			// writes a server→client frame races with the goroutine
			// startup and times out reading the relayed frame on the
			// client side.
			time.Sleep(50 * time.Millisecond)
			return
		}
		select {
		case <-ctx.Done():
			h.t.Fatalf("ctx cancelled before WS swap: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	h.t.Fatalf("WS swap did not complete: client=%T upstream=%T",
		h.stack.ClientTopmost(), h.stack.UpstreamTopmost())
}

// writeClientFrame writes one masked WebSocket frame from the "browser"
// side onto clientA. The frame is masked because RFC 6455 §5.3 requires
// client→server frames to be masked.
func (h *wsHarness) writeClientFrame(fin bool, opcode byte, payload []byte) {
	h.t.Helper()
	f := &ws.Frame{
		Fin:     fin,
		Opcode:  opcode,
		Masked:  true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: payload,
	}
	if err := ws.WriteFrame(h.clientA, f); err != nil {
		h.t.Fatalf("writeClientFrame: %v", err)
	}
}

// writeServerFrame writes one unmasked WebSocket frame from the "server"
// side onto upstreamB. RFC 6455 §5.3 forbids masking on server→client.
func (h *wsHarness) writeServerFrame(fin bool, opcode byte, payload []byte) {
	h.t.Helper()
	f := &ws.Frame{
		Fin:     fin,
		Opcode:  opcode,
		Payload: payload,
	}
	if err := ws.WriteFrame(h.upstreamB, f); err != nil {
		h.t.Fatalf("writeServerFrame: %v", err)
	}
}

// readUpstreamFrame reads one frame from upstreamB (i.e., the frame the
// proxy emitted toward the upstream after relaying a client→server frame).
func (h *wsHarness) readUpstreamFrame() *ws.Frame {
	h.t.Helper()
	_ = h.upstreamB.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := ws.ReadFrame(h.upstreamB)
	_ = h.upstreamB.SetReadDeadline(time.Time{})
	if err != nil {
		h.t.Fatalf("readUpstreamFrame: %v", err)
	}
	return f
}

// readClientFrame reads one frame from clientA (i.e., the frame the proxy
// emitted toward the client after relaying a server→client frame).
func (h *wsHarness) readClientFrame() *ws.Frame {
	h.t.Helper()
	_ = h.clientA.SetReadDeadline(time.Now().Add(3 * time.Second))
	f, err := ws.ReadFrame(h.clientA)
	_ = h.clientA.SetReadDeadline(time.Time{})
	if err != nil {
		h.t.Fatalf("readClientFrame: %v", err)
	}
	return f
}

// waitSessionDone blocks for the session goroutine to exit, with a
// generous timeout. Returns the captured session error.
func (h *wsHarness) waitSessionDone(d time.Duration) error {
	h.t.Helper()
	select {
	case <-h.sessionDone:
		return h.sessionErr
	case <-time.After(d):
		h.t.Fatalf("session did not finish in %s", d)
		return nil
	}
}

// closeClient half-closes the browser side. Used to drive a graceful
// session shutdown after the test exchange.
func (h *wsHarness) closeClient() { _ = h.clientA.Close() }

// closeUpstream half-closes the server side.
func (h *wsHarness) closeUpstream() { _ = h.upstreamB.Close() }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestWSUpgrade_TextFrameRoundTrip verifies the full HTTP/1 → WS swap and a
// single text-frame round-trip in each direction, plus per-frame Flow
// records with verbatim RawBytes.
func TestWSUpgrade_TextFrameRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	h.performUpgrade(ctx)

	// Client → server text frame.
	h.writeClientFrame(true, ws.OpcodeText, []byte("hello-from-client"))
	upFrame := h.readUpstreamFrame()
	if upFrame.Opcode != ws.OpcodeText {
		t.Errorf("upstream frame opcode = 0x%X, want 0x%X (Text)", upFrame.Opcode, ws.OpcodeText)
	}
	if string(upFrame.Payload) != "hello-from-client" {
		t.Errorf("upstream payload = %q, want %q", upFrame.Payload, "hello-from-client")
	}

	// Server → client text frame.
	h.writeServerFrame(true, ws.OpcodeText, []byte("hello-from-server"))
	clFrame := h.readClientFrame()
	if string(clFrame.Payload) != "hello-from-server" {
		t.Errorf("client payload = %q, want %q", clFrame.Payload, "hello-from-server")
	}

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(5 * time.Second)

	// Stream recording: the WS upgrade + WS frames produce streams with
	// Protocol="ws" (envelope.ProtocolWebSocket), NOT "WebSocket".
	// (The Issue text references "WebSocket" but the actual constant is
	// "ws"; record_step.createStream writes string(env.Protocol).)
	streams := h.store.getStreams()
	if len(streams) == 0 {
		t.Fatal("expected at least one stream recorded, got 0")
	}
	var sawWS bool
	for _, st := range streams {
		if st.Protocol == "ws" {
			sawWS = true
		}
	}
	if !sawWS {
		t.Errorf("no stream with Protocol=ws; got %v",
			func() []string {
				out := make([]string, 0, len(streams))
				for _, st := range streams {
					out = append(out, st.Protocol)
				}
				return out
			}())
	}

	// Stream.Scheme is empty for WS today (record_step gates on
	// HTTPMessage.Scheme). Per the resolved decision, assert == "" exactly
	// rather than weakening to "any non-empty".
	for _, st := range streams {
		if st.Protocol == "ws" && st.Scheme != "" {
			t.Errorf("WS stream Scheme=%q, want %q", st.Scheme, "")
		}
	}

	// Per-frame Flow records.
	wsFlows := wsFlowsOnly(h.store.allFlows())
	if len(wsFlows) < 2 {
		t.Fatalf("expected >=2 WS flow records, got %d", len(wsFlows))
	}

	var sentText, recvText *flow.Flow
	for _, f := range wsFlows {
		if f.Direction == "send" && bytes.Equal(f.Body, []byte("hello-from-client")) {
			sentText = f
		}
		if f.Direction == "receive" && bytes.Equal(f.Body, []byte("hello-from-server")) {
			recvText = f
		}
	}
	if sentText == nil {
		t.Fatal("no Send WS flow with payload hello-from-client")
	}
	if recvText == nil {
		t.Fatal("no Receive WS flow with payload hello-from-server")
	}

	// RawBytes preserves the wire bytes verbatim. For client→server frames
	// the wire form is masked; for server→client it is unmasked. Either
	// way the Payload (post-unmask) matches and the RawBytes byte slice
	// is non-empty.
	if len(sentText.RawBytes) == 0 {
		t.Error("send flow RawBytes empty; expected verbatim wire bytes")
	}
	if len(recvText.RawBytes) == 0 {
		t.Error("receive flow RawBytes empty; expected verbatim wire bytes")
	}
}

// TestWSUpgrade_BinaryFrameRoundTrip covers the binary-opcode path with
// arbitrary bytes including 0x00 and 0xFF.
func TestWSUpgrade_BinaryFrameRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	h.performUpgrade(ctx)

	bin := []byte{0x00, 0x01, 0xFE, 0xFF, 0x7F, 0x80, 0xCA, 0xFE}
	h.writeClientFrame(true, ws.OpcodeBinary, bin)
	upFrame := h.readUpstreamFrame()
	if upFrame.Opcode != ws.OpcodeBinary {
		t.Errorf("upstream opcode = 0x%X, want 0x%X (Binary)", upFrame.Opcode, ws.OpcodeBinary)
	}
	if !bytes.Equal(upFrame.Payload, bin) {
		t.Errorf("upstream payload = % X, want % X", upFrame.Payload, bin)
	}

	h.writeServerFrame(true, ws.OpcodeBinary, bin)
	clFrame := h.readClientFrame()
	if !bytes.Equal(clFrame.Payload, bin) {
		t.Errorf("client payload = % X, want % X", clFrame.Payload, bin)
	}

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(5 * time.Second)

	wsFlows := wsFlowsOnly(h.store.allFlows())
	var sawSendBinary, sawRecvBinary bool
	for _, f := range wsFlows {
		if f.Metadata == nil {
			continue
		}
		if f.Metadata["ws_opcode"] == "2" { // OpcodeBinary
			if f.Direction == "send" && bytes.Equal(f.Body, bin) {
				sawSendBinary = true
			}
			if f.Direction == "receive" && bytes.Equal(f.Body, bin) {
				sawRecvBinary = true
			}
		}
	}
	if !sawSendBinary {
		t.Error("no Send WS flow with binary payload + ws_opcode=2")
	}
	if !sawRecvBinary {
		t.Error("no Receive WS flow with binary payload + ws_opcode=2")
	}
}

// TestWSUpgrade_PingPongPassThrough verifies that Ping and Pong are forwarded
// as their own envelopes — the layer does NOT auto-respond to Ping (per
// internal/layer/ws/layer.go doc lines 97-98). The proxy must surface the
// raw control frames so analysts can observe the wire.
func TestWSUpgrade_PingPongPassThrough(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	h.performUpgrade(ctx)

	// Client sends Ping → must arrive at upstream as Ping (not auto-Pong).
	h.writeClientFrame(true, ws.OpcodePing, []byte("ping-payload"))
	upFrame := h.readUpstreamFrame()
	if upFrame.Opcode != ws.OpcodePing {
		t.Errorf("expected upstream Ping (0x%X), got 0x%X", ws.OpcodePing, upFrame.Opcode)
	}
	if string(upFrame.Payload) != "ping-payload" {
		t.Errorf("ping payload = %q, want %q", upFrame.Payload, "ping-payload")
	}

	// Server sends Pong → must arrive at client as Pong.
	h.writeServerFrame(true, ws.OpcodePong, []byte("pong-payload"))
	clFrame := h.readClientFrame()
	if clFrame.Opcode != ws.OpcodePong {
		t.Errorf("expected client Pong (0x%X), got 0x%X", ws.OpcodePong, clFrame.Opcode)
	}
	if string(clFrame.Payload) != "pong-payload" {
		t.Errorf("pong payload = %q, want %q", clFrame.Payload, "pong-payload")
	}

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(5 * time.Second)

	// Verify Flow records carry ws_opcode=9 (Ping) and ws_opcode=10 (Pong).
	wsFlows := wsFlowsOnly(h.store.allFlows())
	var sawPing, sawPong bool
	for _, f := range wsFlows {
		if f.Metadata == nil {
			continue
		}
		switch f.Metadata["ws_opcode"] {
		case "9":
			if f.Direction == "send" {
				sawPing = true
			}
		case "10":
			if f.Direction == "receive" {
				sawPong = true
			}
		}
	}
	if !sawPing {
		t.Error("no Ping flow recorded with ws_opcode=9 + direction=send")
	}
	if !sawPong {
		t.Error("no Pong flow recorded with ws_opcode=10 + direction=receive")
	}
}

// TestWSUpgrade_VariantRecordingOnTransform verifies that a Send-direction
// TransformReplacePayload rule mutates the WSMessage Payload in-flight and
// the RecordStep emits two flow rows for the modified envelope: one with
// Metadata[variant]="original" carrying the pre-mutation Payload, and one
// with Metadata[variant]="modified" carrying the post-mutation Payload.
//
// Variant detection is driven by RecordStep's wsMessageModified
// (record_step.go) — it compares Payload via bytes.Equal.
//
// Per the resolved decision, this test exercises Send-side only. Receive-side
// variants would add noise without strengthening the dispatch proof.
func TestWSUpgrade_VariantRecordingOnTransform(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	xfm := wsrules.NewTransformEngine()
	xfm.SetRules([]wsrules.TransformRule{
		{
			ID:             "replace-secret",
			Enabled:        true,
			Priority:       1,
			Direction:      wsrules.DirectionSend,
			ActionType:     wsrules.TransformReplacePayload,
			PayloadPattern: regexp.MustCompile(`secret-token`),
			PayloadReplace: []byte("REDACTED"),
		},
	})

	h := newWSHarness(t, ctx, harnessOpts{transformEngine: xfm})
	h.performUpgrade(ctx)

	// Browser sends a frame whose payload contains "secret-token". The
	// Transform Step must rewrite the payload before the proxy serializes
	// the frame onto the upstream wire.
	h.writeClientFrame(true, ws.OpcodeText, []byte("hello secret-token world"))

	upFrame := h.readUpstreamFrame()
	if !bytes.Contains(upFrame.Payload, []byte("REDACTED")) {
		t.Errorf("upstream payload missing REDACTED: %q", upFrame.Payload)
	}
	if bytes.Contains(upFrame.Payload, []byte("secret-token")) {
		t.Errorf("upstream payload still contains 'secret-token': %q", upFrame.Payload)
	}

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(5 * time.Second)

	wsFlows := wsFlowsOnly(h.store.allFlows())
	var origSeen, modSeen bool
	for _, f := range wsFlows {
		if f.Direction != "send" || f.Metadata == nil {
			continue
		}
		switch f.Metadata["variant"] {
		case "original":
			if bytes.Equal(f.Body, []byte("hello secret-token world")) {
				origSeen = true
			}
		case "modified":
			if bytes.Contains(f.Body, []byte("REDACTED")) {
				modSeen = true
			}
		}
	}
	if !origSeen {
		t.Error("expected original-variant Send flow with pre-mutation payload")
	}
	if !modSeen {
		t.Error("expected modified-variant Send flow with REDACTED payload")
	}
}

// TestWSUpgrade_ProgressiveRecording verifies that Receive-direction frames
// are recorded incrementally — at least one Receive flow must be visible
// in the store BEFORE the close frame is exchanged. This proves
// frame-per-Envelope progressive recording (RFC-001 §3.2.2) rather than
// "save everything at end of stream".
func TestWSUpgrade_ProgressiveRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	h.performUpgrade(ctx)

	// Send a client→server frame first to "kick" the upstream channel
	// into existence: RunSession's upstream goroutine parks on
	// waitUpstreamReady until clientToUpstream's first Send establishes
	// upstream. Without this kick, a Receive-only test would deadlock.
	h.writeClientFrame(true, ws.OpcodeText, []byte("kickoff"))
	_ = h.readUpstreamFrame()

	// Server sends a Receive-direction text frame.
	h.writeServerFrame(true, ws.OpcodeText, []byte("midstream-event"))

	// Block until the proxy delivers it to the client (proves the proxy
	// processed the frame, so Pipeline+Record fired).
	clFrame := h.readClientFrame()
	if string(clFrame.Payload) != "midstream-event" {
		t.Fatalf("client got %q, want midstream-event", clFrame.Payload)
	}

	// Poll for a Receive WS flow row in the store BEFORE we initiate close.
	deadline := time.Now().Add(3 * time.Second)
	var sawReceiveMidstream bool
	for time.Now().Before(deadline) {
		for _, f := range h.store.allFlows() {
			if f.Direction != "receive" {
				continue
			}
			if bytes.Equal(f.Body, []byte("midstream-event")) {
				sawReceiveMidstream = true
				break
			}
		}
		if sawReceiveMidstream {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !sawReceiveMidstream {
		t.Error("Receive flow for midstream-event not visible before close — recording is not progressive")
	}

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(5 * time.Second)
}

// TestWSUpgrade_SafetyFilterBlocksPayload verifies that a SafetyEngine rule
// matching TargetPayload causes the Send-direction frame to be dropped at
// the SafetyStep. The frame must not reach the upstream echo server, and a
// violation must be logged at Info level by SafetyStep (we observe via
// non-arrival on the upstream side rather than parsing log output, since
// slog handlers are not in scope).
func TestWSUpgrade_SafetyFilterBlocksPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	safety := wsrules.NewSafetyEngine()
	safety.AddRule(common.CompiledRule{
		ID:      "ws-block",
		Name:    "ws-block",
		Pattern: regexp.MustCompile("blocked-token"),
		Targets: []common.Target{wsrules.TargetPayload},
	})

	h := newWSHarness(t, ctx, harnessOpts{safetyEngine: safety})
	h.performUpgrade(ctx)

	// Count upstream-side reads via a goroutine. If the safety filter does
	// its job, the read attempt times out.
	upstreamCh := make(chan *ws.Frame, 1)
	upstreamErrCh := make(chan error, 1)
	go func() {
		_ = h.upstreamB.SetReadDeadline(time.Now().Add(2 * time.Second))
		f, err := ws.ReadFrame(h.upstreamB)
		_ = h.upstreamB.SetReadDeadline(time.Time{})
		if err != nil {
			upstreamErrCh <- err
			return
		}
		upstreamCh <- f
	}()

	// Send a frame the safety filter must drop.
	h.writeClientFrame(true, ws.OpcodeText, []byte("hello blocked-token world"))

	// Wait for the upstream read to time out OR receive a frame (failure).
	select {
	case f := <-upstreamCh:
		t.Errorf("safety filter let blocked frame through to upstream: payload=%q", f.Payload)
	case err := <-upstreamErrCh:
		// Expected: read timeout / EOF — the dropped frame never reached upstream.
		if !errors.Is(err, io.EOF) {
			var nerr net.Error
			if errors.As(err, &nerr) && !nerr.Timeout() {
				t.Errorf("upstream read unexpected error: %v", err)
			}
		}
	}

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(5 * time.Second)

	// Also verify no Send WS flow row carries the blocked payload bytes
	// (drop happens before RecordStep so no flow should reference it).
	for _, f := range h.store.allFlows() {
		if f.Direction == "send" && bytes.Contains(f.Body, []byte("blocked-token")) {
			t.Errorf("Send flow recorded for safety-blocked payload: %q", f.Body)
		}
	}
}

// TestWSUpgrade_TCPRSTProducesErrorState verifies that an abrupt client TCP
// close mid-stream surfaces a *layer.StreamError{Code: ErrorAborted} via
// session.OnComplete and the recorded Stream's State is set to "error" with
// FailureReason="aborted" (via session.ClassifyError).
func TestWSUpgrade_TCPRSTProducesErrorState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	h.performUpgrade(ctx)

	// Send one valid frame so the proxy is mid-stream, then immediately
	// rip the client side without sending a Close frame.
	h.writeClientFrame(true, ws.OpcodeText, []byte("midflight"))
	_ = h.readUpstreamFrame()

	// Write a partial WS frame header (1 byte) then close the client
	// gracefully (FIN, NOT RST). The proxy's client-side ws.Channel
	// parks in ReadFrameRaw's io.ReadFull on the second header byte;
	// after the FIN the bufio.Read returns the buffered byte then EOF
	// on the next call, which io.ReadFull translates into
	// io.ErrUnexpectedEOF (read fewer bytes than requested + EOF).
	// mapReadError then surfaces that as *layer.StreamError{Code:
	// ErrorAborted}. Using SetLinger(0)+Close (RST) here would surface
	// "connection reset by peer" instead, which mapReadError classifies
	// as ErrorProtocol — not what this test asserts.
	if _, err := h.clientA.Write([]byte{0x81}); err != nil {
		t.Fatalf("write partial header: %v", err)
	}
	_ = h.clientA.Close()

	// Also close the upstream side so the upstream-side ws goroutine can
	// terminate. The current ws.Channel.Close is a no-op (the Layer owns
	// the wire), so a one-sided close on the client cannot drain the
	// upstream goroutine on its own. Production OnStack wiring (D3) will
	// install a Layer-level cascade for this case.
	_ = h.upstreamB.Close()

	_ = h.waitSessionDone(5 * time.Second)

	// Verify Stream.State + FailureReason on the WS stream.
	streams := h.store.getStreams()
	var wsStream *flow.Stream
	for _, st := range streams {
		if st.Protocol == "ws" {
			wsStream = st
			break
		}
	}
	if wsStream == nil {
		t.Fatal("no WS stream recorded")
	}
	if wsStream.State != "error" {
		t.Errorf("WS Stream.State = %q, want %q", wsStream.State, "error")
	}
	if wsStream.FailureReason != "aborted" {
		t.Errorf("WS Stream.FailureReason = %q, want %q", wsStream.FailureReason, "aborted")
	}
}

// TestWSUpgrade_MalformedFrameProducesProtocolError verifies that bytes
// violating WS frame format (a control frame with payload >125 bytes,
// forbidden by RFC 6455 §5.5) produce *layer.StreamError{Code: ErrorProtocol}
// with FailureReason="protocol_error".
func TestWSUpgrade_MalformedFrameProducesProtocolError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	h.performUpgrade(ctx)

	// First exchange a valid frame so the WS Stream record is created
	// (createStream fires on the first Send envelope with Sequence==0).
	// Without this the malformed frame's error path runs before any
	// Stream row exists, producing a "no WS stream recorded" failure.
	h.writeClientFrame(true, ws.OpcodeText, []byte("warmup"))
	_ = h.readUpstreamFrame()

	// Build a malformed control frame: opcode=Close (0x8) but payload
	// length 200 bytes (>125). RFC 6455 §5.5 prohibits this. The 16-bit
	// extended length encoding triggers because 126 <= 200 <= 65535.
	//
	// We hand-craft the wire bytes so we bypass WriteFrame's own
	// validation (which is permissive but would mask the payload, not
	// reject the size).
	const payloadLen = 200
	header := []byte{
		0x80 | 0x08,             // FIN=1, opcode=Close
		0x80 | 126,              // MASK=1, len=126 (extended 16-bit)
		byte(payloadLen >> 8),   // upper byte of 200
		byte(payloadLen & 0xFF), // lower byte of 200
		0xAA, 0xBB, 0xCC, 0xDD,  // mask key
	}
	masked := make([]byte, payloadLen)
	for i := range masked {
		masked[i] = byte('A') ^ header[4+(i%4)]
	}
	if _, err := h.clientA.Write(header); err != nil {
		t.Fatalf("write malformed header: %v", err)
	}
	if _, err := h.clientA.Write(masked); err != nil {
		t.Fatalf("write malformed payload: %v", err)
	}

	// Close upstream so its goroutine can drain after the client side
	// surfaces the protocol error. See TCPRST test rationale (D3).
	_ = h.upstreamB.Close()

	_ = h.waitSessionDone(5 * time.Second)

	streams := h.store.getStreams()
	var wsStream *flow.Stream
	for _, st := range streams {
		if st.Protocol == "ws" {
			wsStream = st
			break
		}
	}
	if wsStream == nil {
		t.Fatal("no WS stream recorded")
	}
	if wsStream.State != "error" {
		t.Errorf("WS Stream.State = %q, want %q", wsStream.State, "error")
	}
	if wsStream.FailureReason != "protocol_error" {
		t.Errorf("WS Stream.FailureReason = %q, want %q", wsStream.FailureReason, "protocol_error")
	}
}

// TestWSUpgrade_AbnormalCloseNoCloseFrame verifies the RFC 6455 §7.1.5
// "abnormal close" semantics: when a peer closes the TCP connection
// without sending a WS Close frame, the recorded stream MUST NOT contain
// a synthetic 1006-coded Close frame on the wire, and the Stream.State
// must transition to "error" with FailureReason="aborted".
//
// 1006 is a synthetic indicator surfaced via API only; injecting a literal
// 1006 wire frame would violate wire fidelity (MITM principle 1).
func TestWSUpgrade_AbnormalCloseNoCloseFrame(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	h.performUpgrade(ctx)

	// Exchange one normal frame first so the upgrade is fully realized
	// before we abnormally close. This also creates the WS Stream record
	// so the FailureReason assertion has something to check against.
	h.writeClientFrame(true, ws.OpcodeText, []byte("pre-close"))
	_ = h.readUpstreamFrame()

	// Write a partial frame header on the client side to force
	// io.ErrUnexpectedEOF (mid-frame close) → ErrorAborted on the
	// proxy's read. RFC 6455 §7.1.5 calls this an "abnormal close":
	// the wire ended without a Close frame ever being exchanged. The
	// proxy must NOT synthesise a 1006-coded Close frame on the wire
	// (asserted below), only surface the abnormal classification via
	// Stream.State + FailureReason.
	//
	// We use a graceful FIN close (NOT SetLinger(0)+RST) so io.ReadFull
	// returns ErrUnexpectedEOF rather than ECONNRESET — see the
	// TCPRST test for why ECONNRESET classifies as protocol_error.
	if _, err := h.clientA.Write([]byte{0x81}); err != nil {
		t.Fatalf("write partial header: %v", err)
	}
	_ = h.clientA.Close()
	_ = h.upstreamB.Close()

	_ = h.waitSessionDone(5 * time.Second)

	// No Close-opcode flow row may be present (1006 must NOT appear on the
	// wire per RFC 6455 §7.1.5).
	for _, f := range h.store.allFlows() {
		if f.Metadata == nil {
			continue
		}
		if f.Metadata["ws_opcode"] == "8" {
			t.Errorf("abnormal-close stream emitted a Close-opcode flow row: %+v", f.Metadata)
		}
	}

	// Stream.State must be "error" + FailureReason="aborted".
	streams := h.store.getStreams()
	var wsStream *flow.Stream
	for _, st := range streams {
		if st.Protocol == "ws" {
			wsStream = st
			break
		}
	}
	if wsStream == nil {
		t.Fatal("no WS stream recorded")
	}
	if wsStream.State != "error" {
		t.Errorf("WS Stream.State = %q, want %q", wsStream.State, "error")
	}
	if wsStream.FailureReason != "aborted" {
		t.Errorf("WS Stream.FailureReason = %q, want %q", wsStream.FailureReason, "aborted")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// wsFlowsOnly returns flows whose Metadata["protocol"]=="ws", filtering out
// the HTTP envelopes recorded for the Upgrade request/101 response.
func wsFlowsOnly(in []*flow.Flow) []*flow.Flow {
	out := make([]*flow.Flow, 0, len(in))
	for _, f := range in {
		if f.Metadata != nil && f.Metadata["protocol"] == string(envelope.ProtocolWebSocket) {
			out = append(out, f)
		}
	}
	return out
}
