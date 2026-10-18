package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	sserules "github.com/usk6666/yorishiro-proxy/internal/rules/sse"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

// USK-1196: a hold's pin must outlive the hold until the session has
// dispatched the hold's Result. Every stream session of one h2 connection
// (and both relay goroutines of one HTTP/1 / WS / SSE session) share one
// LiveConnHandle, so a Settle from a sibling — another stream's exit, or
// the opposite relay direction's loop top — that lands while the released
// Result is still inside client.Send must not cut the connection under it.
//
// The ordering is forced without sleeps: the receiving side's Send / Write
// blocks on a test gate and signals that the dispatch entered it; the
// sibling's Settle is then driven to completion through its real code path
// before the gate opens.

// dispatchChan is a scripted layer.Channel. Next yields envelopes queued on
// in and parks while in is empty (io.EOF once in is closed); every Next
// entry is reported on nextCalls. Send blocks on sendGate (when set) after
// signalling sendEntered, and fails with sendErr (when set).
type dispatchChan struct {
	id string
	in chan *envelope.Envelope

	nextCalls chan int

	sendGate     chan struct{}
	sendEntered  chan struct{}
	enteredOnce  sync.Once
	sendErr      error
	closedCalled chan struct{}
	closedOnce   sync.Once

	mu        sync.Mutex
	nexts     int
	sent      []*envelope.Envelope
	sentAtCut int
	closeOnce sync.Once
	closed    chan struct{}
}

func newDispatchChan(id string, gated bool) *dispatchChan {
	c := &dispatchChan{
		id:           id,
		in:           make(chan *envelope.Envelope, 4),
		nextCalls:    make(chan int, 64),
		sendEntered:  make(chan struct{}),
		closedCalled: make(chan struct{}),
		closed:       make(chan struct{}),
		sentAtCut:    -1,
	}
	if gated {
		c.sendGate = make(chan struct{})
	}
	return c
}

func (c *dispatchChan) StreamID() string { return c.id }

func (c *dispatchChan) Next(ctx context.Context) (*envelope.Envelope, error) {
	c.mu.Lock()
	c.nexts++
	n := c.nexts
	c.mu.Unlock()
	select {
	case c.nextCalls <- n:
	default:
	}
	select {
	case env, ok := <-c.in:
		if !ok {
			return nil, io.EOF
		}
		return env, nil
	case <-c.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *dispatchChan) Send(ctx context.Context, env *envelope.Envelope) error {
	c.enteredOnce.Do(func() { close(c.sendEntered) })
	if c.sendGate != nil {
		select {
		case <-c.sendGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if c.sendErr != nil {
		return c.sendErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return errors.New("send on closed channel")
	default:
	}
	c.sent = append(c.sent, env)
	return nil
}

func (c *dispatchChan) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.sentAtCut = len(c.sent)
		c.mu.Unlock()
		close(c.closed)
	})
	return nil
}

func (c *dispatchChan) Closed() <-chan struct{} {
	c.closedOnce.Do(func() { close(c.closedCalled) })
	return c.closed
}

func (c *dispatchChan) Err() error { return nil }

func (c *dispatchChan) openGate() {
	if c.sendGate == nil {
		return
	}
	select {
	case <-c.sendGate:
	default:
		close(c.sendGate)
	}
}

// snapshot returns the envelopes sent so far and how many had been sent
// when the connection cut closed the channel (-1: not closed yet — the
// closeOnCut watcher closes it asynchronously, so wait on closed first).
func (c *dispatchChan) snapshot() ([]*envelope.Envelope, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*envelope.Envelope(nil), c.sent...), c.sentAtCut
}

// dispatchHarness is one registered live connection to 127.0.0.1:8080
// with a scope that admits it until deny is called.
type dispatchHarness struct {
	scope *connector.TargetScope
	reg   *connector.LiveConns
	ctx   context.Context
	queue *common.HoldQueue
	host  *pipeline.HostScopeStep

	mu    sync.Mutex
	drops []string
}

func newDispatchHarness(t *testing.T) *dispatchHarness {
	t.Helper()
	h := &dispatchHarness{scope: connector.NewTargetScope(), queue: common.NewHoldQueue()}
	h.scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1"}}, nil)
	h.reg = connector.NewLiveConns(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, rel, err := h.reg.Register(context.Background(), connector.LiveConn{
		ConnID: "c1", Via: "connect", Target: "127.0.0.1:8080",
		Admit: func() (bool, string) { return h.scope.CheckTarget("http", "127.0.0.1", 8080, "") },
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	t.Cleanup(rel)
	h.ctx = ctx
	h.host = pipeline.NewHostScopeStep(h.scope)
	return h
}

func (h *dispatchHarness) pipeline(step *pipeline.InterceptStep) *pipeline.Pipeline {
	return pipeline.New(h.host, step.WithScopeRecheck(h.host, nil))
}

func (h *dispatchHarness) opts() SessionOptions {
	return SessionOptions{OnPipelineDrop: func(_ context.Context, _ *envelope.Envelope, blockedBy string) {
		h.mu.Lock()
		h.drops = append(h.drops, blockedBy)
		h.mu.Unlock()
	}}
}

func (h *dispatchHarness) dropsSnapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.drops...)
}

// closeOnCut models the buildOnStack watcher: closing the connection's
// channels when its context is cancelled.
func (h *dispatchHarness) closeOnCut(t *testing.T, chans ...*dispatchChan) {
	t.Helper()
	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-h.ctx.Done():
			for _, c := range chans {
				_ = c.Close()
			}
		case <-stop:
		}
	}()
	t.Cleanup(func() {
		for _, c := range chans {
			c.openGate()
		}
		close(stop)
		<-done
	})
}

// waitHeld waits for the first held entry, denies the host and reconciles
// (the connection is revoked but pinned), then resolves the hold.
func (h *dispatchHarness) waitHeldDenyResolve(t *testing.T, action *common.HoldAction) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for h.queue.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("envelope was never held")
		}
		time.Sleep(time.Millisecond)
	}
	h.deny(t)
	if action == nil {
		return // left to the queue's timeout
	}
	entries := h.queue.List()
	if len(entries) != 1 {
		t.Fatalf("held entries after deny Reconcile = %d, want 1", len(entries))
	}
	if err := h.queue.Release(entries[0].ID, action); err != nil {
		t.Fatalf("Release: %v", err)
	}
}

func (h *dispatchHarness) deny(t *testing.T) {
	t.Helper()
	h.scope.ReplacePolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}}, connector.PolicyOrigin{})
	if _, deferred := h.reg.ReconcileWithDeferred("test"); deferred != 1 {
		t.Fatalf("deny Reconcile deferred %d connections, want 1 (the hold must pin it)", deferred)
	}
}

func (h *dispatchHarness) assertNotCut(t *testing.T, what string) {
	t.Helper()
	if h.ctx.Err() != nil {
		t.Fatalf("%s cut the connection while a released hold's Result was still being dispatched: %v", what, context.Cause(h.ctx))
	}
}

func (h *dispatchHarness) awaitCut(t *testing.T) {
	t.Helper()
	select {
	case <-h.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("revoked connection was never cut after the hold's Result was dispatched (pin leaked)")
	}
	if !errors.Is(context.Cause(h.ctx), connector.ErrTargetScopeRevoked) {
		t.Errorf("connection cause = %v, want ErrTargetScopeRevoked", context.Cause(h.ctx))
	}
}

func waitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// waitNextCall waits until the channel's Next has been entered n times.
func waitNextCall(t *testing.T, c *dispatchChan, n int, what string) {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case got := <-c.nextCalls:
			if got >= n {
				return
			}
		case <-timeout:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func heldHTTPRequest(streamID string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID: streamID, FlowID: streamID + "-f", Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
		Context: envelope.EnvelopeContext{TargetHost: "127.0.0.1:8080"},
		Message: &envelope.HTTPMessage{Method: "GET", Scheme: "http", Authority: "127.0.0.1:8080", Path: "/held"},
	}
}

func requestInterceptStep(h *dispatchHarness) *pipeline.InterceptStep {
	engine := httprules.NewInterceptEngine()
	engine.SetRules([]httprules.InterceptRule{{ID: "req", Enabled: true, Direction: httprules.DirectionRequest}})
	return pipeline.NewInterceptStep(engine, nil, nil, nil, h.queue, nil, nil)
}

func responseInterceptStep(h *dispatchHarness) *pipeline.InterceptStep {
	engine := httprules.NewInterceptEngine()
	engine.SetRules([]httprules.InterceptRule{{ID: "resp", Enabled: true, Direction: httprules.DirectionResponse}})
	return pipeline.NewInterceptStep(engine, nil, nil, nil, h.queue, nil, nil)
}

func wsReceiveInterceptStep(h *dispatchHarness) *pipeline.InterceptStep {
	engine := wsrules.NewInterceptEngine()
	engine.SetRules([]wsrules.InterceptRule{{ID: "ws", Enabled: true, Direction: wsrules.DirectionReceive}})
	return pipeline.NewInterceptStep(nil, engine, nil, nil, h.queue, nil, nil)
}

func assert403(t *testing.T, env *envelope.Envelope, blockedBy string) {
	t.Helper()
	resp, ok := env.Message.(*envelope.HTTPMessage)
	if !ok || resp.Status != 403 {
		t.Fatalf("client got %T %+v, want a 403 HTTPMessage", env.Message, env.Message)
	}
	var body struct {
		BlockedBy string `json:"blocked_by"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil || body.BlockedBy != blockedBy {
		t.Errorf("403 body = %q (err %v), want blocked_by %s", resp.Body, err, blockedBy)
	}
}

func noDial(t *testing.T) DialFunc {
	return func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		t.Error("unexpected upstream dial")
		return nil, errors.New("no dial")
	}
}

// Test plan #2 — the reported h2 shape: stream A's released request is
// answered 403 target_scope; while that 403 is inside A's client.Send, a
// sibling stream B on the same connection ends (its clientToUpstream exit
// Settles). The connection must stay up until A's 403 was sent.
func TestRunSession_LiveConn_SiblingSettleDuringReleasedRespond(t *testing.T) {
	h := newDispatchHarness(t)
	p := h.pipeline(requestInterceptStep(h))

	a := newDispatchChan("stream-a", true)
	a.in <- heldHTTPRequest("stream-a")
	h.closeOnCut(t, a)

	aDone := make(chan error, 1)
	go func() { aDone <- RunSession(h.ctx, a, noDial(t), p, h.opts()) }()

	h.waitHeldDenyResolve(t, &common.HoldAction{Type: common.ActionRelease})
	waitSignal(t, a.sendEntered, "stream A's 403 to enter client.Send")

	// Sibling stream B: its client half-closes at once, so its session
	// runs the clientToUpstream exit Settle and returns.
	if err := RunSession(h.ctx, &mockChannel{streamID: "stream-b"}, noDial(t), p, h.opts()); err != nil {
		t.Fatalf("sibling RunSession: %v", err)
	}
	h.assertNotCut(t, "sibling stream B's exit Settle")

	a.openGate()
	h.awaitCut(t)
	select {
	case <-aDone:
	case <-time.After(5 * time.Second):
		t.Fatal("stream A's session did not end after the cut")
	}
	waitSignal(t, a.closed, "the cut to close stream A's channel")
	sent, atCut := a.snapshot()
	if len(sent) < 1 || atCut < 1 {
		t.Fatalf("stream A received %d envelopes before the cut (at cut: %d), want its 403 first", len(sent), atCut)
	}
	assert403(t, sent[0], pipeline.BlockedByTargetScope)
	if got := h.dropsSnapshot(); len(got) != 1 || got[0] != pipeline.BlockedByTargetScope {
		t.Errorf("OnPipelineDrop calls = %v, want [target_scope]", got)
	}
}

// Test plan #4 — HTTP/1 Receive hold: the released response is inside
// client.Send when the client half-closes, so clientToUpstream exits and
// Settles. The response must still be delivered before the cut.
func TestRunSession_LiveConn_ClientEOFDuringReleasedResponse(t *testing.T) {
	h := newDispatchHarness(t)
	p := h.pipeline(responseInterceptStep(h))

	a := newDispatchChan("s1", true)
	a.in <- heldHTTPRequest("s1")
	h.closeOnCut(t, a)
	upstream := &mockChannel{
		nextEnvelopes: []*envelope.Envelope{{
			StreamID: "s1", FlowID: "r1", Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP,
			Context: envelope.EnvelopeContext{TargetHost: "127.0.0.1:8080"},
			Message: &envelope.HTTPMessage{Status: 200, Body: []byte("ok")},
		}},
	}
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) { return upstream, nil }

	done := make(chan error, 1)
	go func() { done <- RunSession(h.ctx, a, dial, p, h.opts()) }()

	h.waitHeldDenyResolve(t, &common.HoldAction{Type: common.ActionRelease})
	waitSignal(t, a.sendEntered, "the released response to enter client.Send")

	// The client half-closes; clientToUpstream returns (lateClientErrorWatcher
	// reaching client.Closed() proves it did, Settle included).
	// (A cut by that Settle also ends the wait: the watcher then returns on
	// ctx.Done without reaching client.Closed().)
	close(a.in)
	select {
	case <-a.closedCalled:
	case <-h.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for clientToUpstream to exit")
	}
	h.assertNotCut(t, "clientToUpstream's exit Settle")

	a.openGate()
	h.awaitCut(t)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not end after the cut")
	}
	sent, _ := a.snapshot()
	if len(sent) != 1 {
		t.Fatalf("client received %d envelopes, want the released response", len(sent))
	}
	if m, ok := sent[0].Message.(*envelope.HTTPMessage); !ok || m.Status != 200 {
		t.Errorf("client got %+v, want the released 200", sent[0].Message)
	}
}

func wsEnv(dir envelope.Direction, payload string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID: "ws-1", FlowID: "ws-f-" + payload, Direction: dir, Protocol: envelope.ProtocolWebSocket,
		Context: envelope.EnvelopeContext{TargetHost: "127.0.0.1:8080"},
		Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte(payload)},
	}
}

// startWSRelays runs both relay directions of one WS session (as
// runWSOverH2Relay does) on the connection ctx.
func startWSRelays(h *dispatchHarness, p *pipeline.Pipeline, client, upstream *dispatchChan) chan error {
	done := make(chan error, 2)
	reg := &bodyBufRegistry{}
	go func() { done <- wsRelayDirection(h.ctx, p, reg, client, upstream, h.opts(), envelope.Send) }()
	go func() { done <- wsRelayDirection(h.ctx, p, reg, upstream, client, h.opts(), envelope.Receive) }()
	return done
}

// Test plan #3 — WS Receive hold: the released upstream frame is inside
// the client-side Send when the client relay direction handles a frame
// (blocked by HostScope on the revoked connection) and Settles at its loop
// top. The frame must still be delivered before the cut.
func TestWSRelay_LiveConn_SendRelaySettleDuringReleasedFrame(t *testing.T) {
	h := newDispatchHarness(t)
	p := h.pipeline(wsReceiveInterceptStep(h))

	client := newDispatchChan("ws-1", true)
	upstream := newDispatchChan("ws-1", false)
	h.closeOnCut(t, client, upstream)
	upstream.in <- wsEnv(envelope.Receive, "from-upstream")
	done := startWSRelays(h, p, client, upstream)

	h.waitHeldDenyResolve(t, &common.HoldAction{Type: common.ActionRelease})
	waitSignal(t, client.sendEntered, "the released frame to enter the client Send")

	client.in <- wsEnv(envelope.Send, "from-client")
	waitNextCall(t, client, 2, "the Send relay to loop back to Next")
	h.assertNotCut(t, "the Send relay's loop-top Settle")
	if got := h.dropsSnapshot(); len(got) != 1 || got[0] != pipeline.BlockedByTargetScope {
		t.Errorf("OnPipelineDrop calls = %v, want [target_scope] for the client frame", got)
	}

	client.openGate()
	h.awaitCut(t)
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("WS relay did not end after the cut")
		}
	}
	waitSignal(t, client.closed, "the cut to close the client channel")
	sent, atCut := client.snapshot()
	if len(sent) != 1 || atCut != 1 {
		t.Fatalf("client received %d frames (at cut: %d), want the released frame before the cut", len(sent), atCut)
	}
	if m, ok := sent[0].Message.(*envelope.WSMessage); !ok || string(m.Payload) != "from-upstream" {
		t.Errorf("client got %+v, want the released upstream frame", sent[0].Message)
	}
	if got := len(upstream.sent); got != 0 {
		t.Errorf("upstream received %d frames, want 0", got)
	}
}

// gatedWriter is an SSE client writer whose Write blocks on gate after
// signalling entered.
type gatedWriter struct {
	gate        chan struct{}
	entered     chan struct{}
	enteredOnce sync.Once
	mu          sync.Mutex
	buf         bytes.Buffer
}

func (w *gatedWriter) Write(b []byte) (int, error) {
	w.enteredOnce.Do(func() { close(w.entered) })
	<-w.gate
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(b)
}

func (w *gatedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// Test plan #5 — h2 SSE event hold: the released event is inside the
// client write when a sibling stream on the same connection ends and
// Settles. The event must still be written before the cut.
func TestDriveSSEEventLoop_LiveConn_SiblingSettleDuringReleasedEvent(t *testing.T) {
	h := newDispatchHarness(t)
	engine := sserules.NewInterceptEngine()
	engine.SetRules([]sserules.InterceptRule{{ID: "sse", Enabled: true, Direction: sserules.DirectionReceive}})
	p := h.pipeline(pipeline.NewInterceptStep(nil, nil, nil, engine, h.queue, nil, nil))

	w := &gatedWriter{gate: make(chan struct{}), entered: make(chan struct{})}
	var gateOnce sync.Once
	openGate := func() { gateOnce.Do(func() { close(w.gate) }) }
	t.Cleanup(openGate)
	br := sse.NewEventBoundaryReader(bytes.NewReader([]byte("event: tick\ndata: held\n\n")), 0)
	flowCtx := envelope.EnvelopeContext{TargetHost: "127.0.0.1:8080"}

	done := make(chan error, 1)
	go func() {
		seq := 0
		done <- driveSSEEventLoop(h.ctx, p, br, w, false, "sse-1", flowCtx, &seq, 0)
	}()

	h.waitHeldDenyResolve(t, &common.HoldAction{Type: common.ActionRelease})
	waitSignal(t, w.entered, "the released event to enter the client write")

	if err := RunSession(h.ctx, &mockChannel{streamID: "stream-b"}, noDial(t), p, h.opts()); err != nil {
		t.Fatalf("sibling RunSession: %v", err)
	}
	h.assertNotCut(t, "sibling stream B's exit Settle")

	openGate()
	h.awaitCut(t)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SSE loop did not end")
	}
	if got := w.String(); !bytes.Contains([]byte(got), []byte("data: held")) {
		t.Errorf("client wrote %q, want the released event", got)
	}
}

// Test plan #7 — guard: every Result kind, a dispatch error and a hold
// timeout release the handed-off pin, so the revoked connection is cut
// once the Result was dispatched with no Settle from outside the session.
// The client and upstream park after the dispatch, so only the session's
// own loop-top / exit Settle can cut.
func TestRunSession_LiveConn_HandedOffPinNeverLeaks(t *testing.T) {
	type tc struct {
		name      string
		recv      bool               // hold the response instead of the request
		action    *common.HoldAction // nil: left to the queue timeout
		behavior  common.TimeoutBehavior
		sendErr   error
		blockedBy string // the 403 the client must see ("" for none)
	}
	modified := heldHTTPRequest("s1")
	modified.Message.(*envelope.HTTPMessage).Path = "/modified"
	for _, c := range []tc{
		{name: "release_target_scope", action: &common.HoldAction{Type: common.ActionRelease}, blockedBy: pipeline.BlockedByTargetScope},
		{name: "drop", action: &common.HoldAction{Type: common.ActionDrop}, blockedBy: pipeline.BlockedByInterceptDrop},
		{name: "modify_and_forward", action: &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modified}, blockedBy: pipeline.BlockedByTargetScope},
		{name: "receive_release", recv: true, action: &common.HoldAction{Type: common.ActionRelease}},
		{name: "dispatch_error", action: &common.HoldAction{Type: common.ActionRelease}, sendErr: errors.New("client gone")},
		{name: "timeout_auto_release", behavior: common.TimeoutAutoRelease, blockedBy: pipeline.BlockedByTargetScope},
		{name: "timeout_auto_drop", behavior: common.TimeoutAutoDrop, blockedBy: pipeline.BlockedByInterceptDrop},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newDispatchHarness(t)
			if c.action == nil {
				h.queue.SetTimeout(200 * time.Millisecond)
				h.queue.SetTimeoutBehavior(c.behavior)
			}
			step := requestInterceptStep(h)
			if c.recv {
				step = responseInterceptStep(h)
			}
			p := h.pipeline(step)

			client := newDispatchChan("s1", false)
			client.sendErr = c.sendErr
			client.in <- heldHTTPRequest("s1")
			h.closeOnCut(t, client)
			upstream := newDispatchChan("s1", false)
			h.closeOnCut(t, upstream)
			if c.recv {
				upstream.in <- &envelope.Envelope{
					StreamID: "s1", FlowID: "r1", Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP,
					Context: envelope.EnvelopeContext{TargetHost: "127.0.0.1:8080"},
					Message: &envelope.HTTPMessage{Status: 200, Body: []byte("ok")},
				}
			}
			dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
				if !c.recv {
					t.Error("unexpected upstream dial")
				}
				return upstream, nil
			}

			done := make(chan error, 1)
			go func() { done <- RunSession(h.ctx, client, dial, p, h.opts()) }()
			h.waitHeldDenyResolve(t, c.action)

			h.awaitCut(t)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("session did not end after the cut")
			}
			sent, _ := client.snapshot()
			switch {
			case c.sendErr != nil:
			case c.blockedBy != "":
				if len(sent) != 1 {
					t.Fatalf("client received %d envelopes, want the 403", len(sent))
				}
				assert403(t, sent[0], c.blockedBy)
			case c.recv:
				if len(sent) != 1 {
					t.Fatalf("client received %d envelopes, want the released response", len(sent))
				}
			}
		})
	}

	t.Run("ws_drop", func(t *testing.T) {
		h := newDispatchHarness(t)
		p := h.pipeline(wsReceiveInterceptStep(h))
		client := newDispatchChan("ws-1", false)
		upstream := newDispatchChan("ws-1", false)
		h.closeOnCut(t, client, upstream)
		upstream.in <- wsEnv(envelope.Receive, "from-upstream")
		done := startWSRelays(h, p, client, upstream)

		h.waitHeldDenyResolve(t, &common.HoldAction{Type: common.ActionDrop})
		h.awaitCut(t)
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("WS relay did not end after the cut")
			}
		}
		if sent, _ := client.snapshot(); len(sent) != 0 {
			t.Errorf("client received %d frames, want 0 (the frame was dropped)", len(sent))
		}
	})
}
