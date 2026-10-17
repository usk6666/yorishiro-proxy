package session

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// USK-1192: an intercept-held request on a connection that a policy
// change revokes is answered (403 target_scope) and recorded BEFORE the
// connection is cut — the session settles the deferred cut only after the
// Result was dispatched.

// liveConnClient yields one envelope, then parks Next until Close (or ctx
// cancel), like an idle keep-alive HTTP/1.x client connection. Sends are
// recorded; closed snapshots how many had been sent when Close ran.
type liveConnClient struct {
	first *envelope.Envelope

	mu         sync.Mutex
	served     bool
	sent       []*envelope.Envelope
	sentAtStop int
	closeOnce  sync.Once
	closed     chan struct{}
}

func newLiveConnClient(first *envelope.Envelope) *liveConnClient {
	return &liveConnClient{first: first, closed: make(chan struct{}), sentAtStop: -1}
}

func (c *liveConnClient) StreamID() string { return c.first.StreamID }

func (c *liveConnClient) Next(ctx context.Context) (*envelope.Envelope, error) {
	c.mu.Lock()
	if !c.served {
		c.served = true
		c.mu.Unlock()
		return c.first, nil
	}
	c.mu.Unlock()
	select {
	case <-c.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *liveConnClient) Send(_ context.Context, env *envelope.Envelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return errors.New("send on closed client")
	default:
	}
	c.sent = append(c.sent, env)
	return nil
}

func (c *liveConnClient) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.sentAtStop = len(c.sent)
		c.mu.Unlock()
		close(c.closed)
	})
	return nil
}

func (c *liveConnClient) Closed() <-chan struct{} { return c.closed }
func (c *liveConnClient) Err() error              { return nil }

func TestRunSession_LiveConnRevokedDuringHold_RespondsBeforeCut(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1"}}, nil)
	reg := connector.NewLiveConns(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, rel, err := reg.Register(context.Background(), connector.LiveConn{
		ConnID: "c1", Via: "http1-forward", Target: "127.0.0.1:8080",
		Admit: func() (bool, string) { return scope.CheckTarget("http", "127.0.0.1", 8080, "") },
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer rel()

	req := &envelope.Envelope{
		StreamID: "s1", FlowID: "f1", Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
		Context: envelope.EnvelopeContext{TargetHost: "127.0.0.1:8080"},
		Message: &envelope.HTTPMessage{Method: "GET", Scheme: "http", Authority: "127.0.0.1:8080", Path: "/held"},
	}
	client := newLiveConnClient(req)

	// The buildOnStack watcher: close the client when the connection ctx
	// is cancelled.
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-time.After(10 * time.Second):
		}
	}()

	engine := httprules.NewInterceptEngine()
	engine.SetRules([]httprules.InterceptRule{{ID: "all", Enabled: true, Direction: httprules.DirectionRequest}})
	queue := common.NewHoldQueue()
	host := pipeline.NewHostScopeStep(scope)
	p := pipeline.New(host, pipeline.NewInterceptStep(engine, nil, nil, nil, queue, nil, nil).WithScopeRecheck(host, nil))

	var dials atomic.Int64
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		dials.Add(1)
		return &mockChannel{}, nil
	}
	var mu sync.Mutex
	var drops []string
	opts := SessionOptions{OnPipelineDrop: func(_ context.Context, _ *envelope.Envelope, blockedBy string) {
		mu.Lock()
		drops = append(drops, blockedBy)
		mu.Unlock()
	}}

	sessDone := make(chan error, 1)
	go func() { sessDone <- RunSession(ctx, client, dial, p, opts) }()

	deadline := time.Now().Add(3 * time.Second)
	for queue.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("request was never held")
		}
		time.Sleep(time.Millisecond)
	}
	scope.ReplacePolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}}, connector.PolicyOrigin{})
	reg.Reconcile("test")
	entries := queue.List()
	if len(entries) != 1 {
		t.Fatalf("held entries after deny Reconcile = %d, want 1 (hold vanished with its connection)", len(entries))
	}
	if err := queue.Release(entries[0].ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
		t.Fatalf("Release: %v", err)
	}

	select {
	case <-sessDone:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not end after the deferred cut")
	}
	<-watcherDone

	if !errors.Is(context.Cause(ctx), connector.ErrTargetScopeRevoked) {
		t.Errorf("connection cause = %v, want ErrTargetScopeRevoked (deferred cut never ran)", context.Cause(ctx))
	}
	client.mu.Lock()
	sentAtStop, sent := client.sentAtStop, append([]*envelope.Envelope(nil), client.sent...)
	client.mu.Unlock()
	if sentAtStop < 1 || len(sent) < 1 {
		t.Fatalf("client received %d envelopes before the connection was closed (sentAtStop=%d), want the 403 first", len(sent), sentAtStop)
	}
	resp, ok := sent[0].Message.(*envelope.HTTPMessage)
	if !ok || resp.Status != 403 {
		t.Fatalf("client got %T %+v, want a 403 HTTPMessage", sent[0].Message, sent[0].Message)
	}
	var body struct {
		BlockedBy string `json:"blocked_by"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil || body.BlockedBy != "target_scope" {
		t.Errorf("403 body = %q (err %v), want blocked_by target_scope", resp.Body, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(drops) != 1 || drops[0] != pipeline.BlockedByTargetScope {
		t.Errorf("OnPipelineDrop calls = %v, want [target_scope]", drops)
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("upstream dials = %d, want 0", n)
	}
}

// While the connection is revoke-pending the WS hold-keepalive must not
// inject Pings toward the denied upstream. The not-revoked subtest is the
// guard that the harness does observe Pings.
func TestWSHoldKeepalive_SkipsWhileRevokePending(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		name := "not_revoked"
		if revoke {
			name = "revoke_pending"
		}
		t.Run(name, func(t *testing.T) {
			scope := connector.NewTargetScope()
			scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1"}}, nil)
			reg := connector.NewLiveConns(slog.New(slog.NewTextHandler(io.Discard, nil)))
			ctx, rel, err := reg.Register(context.Background(), connector.LiveConn{
				ConnID: "c1", Via: "connect", Target: "127.0.0.1:443",
				Admit: func() (bool, string) { return scope.CheckTarget("https", "127.0.0.1", 443, "") },
			})
			if err != nil {
				t.Fatalf("Register: %v", err)
			}
			defer rel()
			h := connector.LiveConnFromContext(ctx)
			h.Pin()
			defer h.Unpin()
			if revoke {
				scope.ReplacePolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}}, connector.PolicyOrigin{})
				reg.Reconcile("test")
				if ctx.Err() != nil {
					t.Fatalf("pinned connection cut: %v", context.Cause(ctx))
				}
			}

			tracker := common.NewHoldTracker()
			tracker.MarkHold("ws-1", envelope.Send, time.Now())
			dst := &mockChannel{}
			sender := newWSSendSerializer(dst)
			opt := SessionOptions{
				WSHoldKeepaliveEnabled:  true,
				WSHoldKeepaliveInterval: 5 * time.Millisecond,
				InterceptHoldTracker:    tracker,
			}
			stop := startWSHoldKeepalive(ctx, opt, sender, "ws-1", envelope.Send, "c1")
			time.Sleep(80 * time.Millisecond)
			stop()
			pings := len(dst.getSent())
			if revoke && pings != 0 {
				t.Errorf("keepalive sent %d Pings on a revoke-pending connection, want 0", pings)
			}
			if !revoke && pings == 0 {
				t.Errorf("guard: keepalive sent no Pings on a live connection")
			}
		})
	}
}
