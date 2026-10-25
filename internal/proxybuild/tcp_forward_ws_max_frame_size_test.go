package proxybuild

import (
	"context"
	"log/slog"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// TestTCPForwardSessionOpts_WSMaxFrameSize pins that both TCP forward
// SessionOptions builders carry BuildConfig.WSMaxFrameSize into the
// session, so the ws.Layer legs built by runUpgradeWS (websocket forward
// over h1, and WS over h2 per RFC 8441) honor web_socket.max_frame_size
// (USK-1322).
func TestTCPForwardSessionOpts_WSMaxFrameSize(t *testing.T) {
	const want = int64(32 << 20)
	parent := &Stack{BuildConfig: &connector.BuildConfig{WSMaxFrameSize: want}}
	ctx := context.Background()

	t.Run("h1", func(t *testing.T) {
		m := &Manager{}
		if got := m.tcpForwardSessionOpts(parent, ctx).WSMaxFrameSize; got != want {
			t.Errorf("tcpForwardSessionOpts WSMaxFrameSize = %d, want %d", got, want)
		}
	})
	t.Run("h2", func(t *testing.T) {
		if got := tcpForwardH2SessionOpts(parent, ctx, slog.Default()).WSMaxFrameSize; got != want {
			t.Errorf("tcpForwardH2SessionOpts WSMaxFrameSize = %d, want %d", got, want)
		}
	})
}
