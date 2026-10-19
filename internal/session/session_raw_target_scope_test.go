package session

import (
	"net"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// TestRelaySendErr_RawTargetScopeTeardown pins USK-1083 review F-1: once a
// raw target scope deny tore the connection down, upstreamToClient may still
// be inside client.Send relaying an upstream chunk it had already read (a
// server-first banner, say). That Send fails on the aborted client conn, and
// the failure is a consequence of the proxy's deliberate teardown — it must
// not be able to win the errgroup's first-error slot over
// errRawBlockedByTargetScope. The control sub-test keeps an ordinary client
// Send failure surfacing.
func TestRelaySendErr_RawTargetScopeTeardown(t *testing.T) {
	sendErr := &net.OpError{Op: "write", Net: "tcp", Err: net.ErrClosed}

	t.Run("after raw target scope teardown", func(t *testing.T) {
		client := &mockChannel{streamID: "raw-client"}
		uh := &upstreamHolder{ch: &mockChannel{streamID: "raw-up"}}
		env := &envelope.Envelope{
			StreamID:  "raw-client",
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolRaw,
		}
		if err := rawTargetScopeTeardown(client, uh, env, pipeline.Drop, pipeline.BlockedByTargetScope); err == nil {
			t.Fatal("rawTargetScopeTeardown returned nil for a raw target scope Drop")
		}
		if err := relaySendErr(uh, sendErr); err != nil {
			t.Errorf("relaySendErr after raw target scope teardown = %v, want nil", err)
		}
	})

	t.Run("ordinary client send failure", func(t *testing.T) {
		uh := &upstreamHolder{ch: &mockChannel{streamID: "raw-up"}}
		if err := relaySendErr(uh, sendErr); err == nil {
			t.Error("relaySendErr without a proxy teardown = nil, want the client.Send error")
		}
	})
}
