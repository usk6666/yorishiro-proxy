package proxybuild

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// orderedReleaser is a pluginv2.StateReleaser that appends every release to
// a shared event log, so a test can tell a release that happened before a
// plugin dispatch from one that happened after it.
type orderedReleaser struct {
	mu  sync.Mutex
	log []string
}

func (r *orderedReleaser) ReleaseTransaction(connID, id string) {
	r.mark("release-tx " + connID + "|" + id)
}

func (r *orderedReleaser) ReleaseStream(connID, id string) {
	r.mark("release-stream " + connID + "|" + id)
}

func (r *orderedReleaser) mark(ev string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = append(r.log, ev)
}

func (r *orderedReleaser) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.log...)
}

// watcherCloseStep stands in for PluginStep racing the ctx-cancel watcher:
// on the first envelope it closes the stack (what the watcher does on
// listener shutdown / a live-conn cut), and only then "dispatches" — the
// point at which pluginv2.Engine.NewCtx re-creates the (ConnID, StreamID)
// scopes the Layer.Close just released.
type watcherCloseStep struct {
	stack *connector.ConnectionStack
	rel   *orderedReleaser
	once  sync.Once
}

func (s *watcherCloseStep) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	s.once.Do(func() {
		_ = s.stack.Close()
		s.rel.mark("dispatch " + env.Context.ConnID + "|" + env.StreamID)
	})
	return pipeline.Result{}
}

// TestRunSingleChannelSession_RawReleasesStateAfterSessionExit pins USK-1083
// review S-2: when the ctx-cancel watcher's stack.Close is the first
// Layer.Close, a PluginStep dispatch already in flight re-creates the
// client StreamID scope after that release, and the deferred stack.Close is
// a no-op on the Layers by then. The raw relay must release the scope once
// more after the session has exited, so no dispatch can follow the last
// release.
func TestRunSingleChannelSession_RawReleasesStateAfterSessionExit(t *testing.T) {
	clientPeer, clientConn := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	defer clientPeer.Close()
	defer upstreamPeer.Close()

	const connID = "c1"
	clientStreamID := connID + "/client"
	rel := &orderedReleaser{}
	stack := connector.NewConnectionStack(connID)
	stack.PushClient(bytechunk.New(clientConn, clientStreamID, envelope.Send,
		bytechunk.WithEnvelopeContext(envelope.EnvelopeContext{ConnID: connID, TargetHost: "example.com:25"}),
		bytechunk.WithStateReleaser(rel),
	))
	stack.PushUpstream(bytechunk.New(upstreamConn, connID+"/upstream", envelope.Receive,
		bytechunk.WithEnvelopeContext(envelope.EnvelopeContext{ConnID: connID, TargetHost: "example.com:25"}),
	))
	defer stack.Close()

	p := pipeline.New(&watcherCloseStep{stack: stack, rel: rel})

	go func() { _, _ = clientPeer.Write([]byte("EHLO x\r\n")) }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runSingleChannelSession(ctx, stack, nil, p, session.SessionOptions{})
	}()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("runSingleChannelSession did not return after the stack was closed")
	}

	log := rel.snapshot()
	lastDispatch, lastTx, lastStream := -1, -1, -1
	for i, ev := range log {
		switch ev {
		case "dispatch " + connID + "|" + clientStreamID:
			lastDispatch = i
		case "release-tx " + connID + "|" + clientStreamID:
			lastTx = i
		case "release-stream " + connID + "|" + clientStreamID:
			lastStream = i
		}
	}
	if lastDispatch < 0 {
		t.Fatalf("the step never dispatched; log = %v", log)
	}
	if lastTx < lastDispatch || lastStream < lastDispatch {
		t.Errorf("no release of %s|%s after the in-flight dispatch; log = %v", connID, clientStreamID, log)
	}
}
