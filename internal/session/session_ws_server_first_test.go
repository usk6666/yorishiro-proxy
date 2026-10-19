package session

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// wsServerFirstFixture wires a client http1 Layer and an upstream http1
// Layer over loopback TCP pairs, runs RunStackSession with UpgradeStep,
// and drives an RFC 6455 handshake from the "browser" side. The
// "server" answers the proxied upgrade with a 101 and then (optionally)
// writes one frame on its own initiative — the server-speaks-first
// shape (greetings, push) USK-1171 covers. The browser never writes a
// WS frame.
type wsServerFirstFixture struct {
	browser  net.Conn
	browserR *bufio.Reader
	server   net.Conn
	done     chan error

	mu         sync.Mutex
	completeID []string
}

func (f *wsServerFirstFixture) completeIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.completeID...)
}

func startWSServerFirstFixture(t *testing.T, ctx context.Context, serverFrame []byte) *wsServerFirstFixture {
	t.Helper()

	browser, proxyClientSide := pipePair()
	proxyUpstreamSide, server := pipePair()
	t.Cleanup(func() {
		_ = browser.Close()
		_ = server.Close()
	})

	stack := connector.NewConnectionStack("test-ws-server-first")
	clientLayer := http1.New(proxyClientSide, "client-stream", envelope.Send)
	upstreamLayer := http1.New(proxyUpstreamSide, "upstream-stream", envelope.Receive)
	stack.PushClient(clientLayer)
	stack.PushUpstream(upstreamLayer)

	// Server: read the proxied upgrade request up to CRLFCRLF, answer
	// 101, then push serverFrame without waiting for any client frame.
	go func() {
		br := bufio.NewReader(server)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if line == "\r\n" {
				break
			}
		}
		_, _ = server.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
			"\r\n"))
		if serverFrame != nil {
			// Let the 101 cross the proxy first so the frame genuinely
			// arrives after the swap, not as 101 leftover bytes.
			time.Sleep(50 * time.Millisecond)
			_, _ = server.Write(serverFrame)
		}
	}()

	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		ch, ok := <-upstreamLayer.Channels()
		if !ok {
			return nil, errors.New("upstream Channels closed before yielding")
		}
		return ch, nil
	}

	f := &wsServerFirstFixture{
		browser:  browser,
		browserR: bufio.NewReader(browser),
		server:   server,
		done:     make(chan error, 1),
	}
	opt := SessionOptions{
		OnComplete: func(_ context.Context, streamID string, _ error) {
			f.mu.Lock()
			f.completeID = append(f.completeID, streamID)
			f.mu.Unlock()
		},
	}
	go func() {
		f.done <- RunStackSession(ctx, stack, dial, pipeline.New(NewUpgradeStep()), opt)
	}()

	if _, err := browser.Write([]byte("GET /chat HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"\r\n")); err != nil {
		t.Fatalf("browser write upgrade request: %v", err)
	}
	status, err := f.browserR.ReadString('\n')
	if err != nil {
		t.Fatalf("browser read 101 status line: %v", err)
	}
	if !strings.Contains(status, " 101 ") {
		t.Fatalf("browser status line = %q, want 101", status)
	}
	for {
		line, err := f.browserR.ReadString('\n')
		if err != nil {
			t.Fatalf("browser read 101 headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	return f
}

// TestRunStackSession_WSUpgrade_RelaysServerFirstFrameWithoutClientSend
// pins USK-1171: after the WS swap, a frame the upstream sends on its own
// initiative must reach the client even though the client has not sent
// any WS frame. Before the fix the post-swap session only started reading
// upstream after the first client envelope.
func TestRunStackSession_WSUpgrade_RelaysServerFirstFrameWithoutClientSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := startWSServerFirstFixture(t, ctx, makeWSFrame(0x1, []byte("server-hello")))

	_ = f.browser.SetReadDeadline(time.Now().Add(2 * time.Second))
	frame, err := ws.ReadFrame(f.browserR)
	if err != nil {
		t.Fatalf("server-first frame not relayed to the client without a client send: %v", err)
	}
	if frame.Opcode != ws.OpcodeText || string(frame.Payload) != "server-hello" {
		t.Errorf("relayed frame = opcode %d payload %q, want text %q", frame.Opcode, frame.Payload, "server-hello")
	}
}

// TestRunStackSession_WSUpgrade_ClientCloseWithoutFrameCompletesStream
// pins the OnComplete side of USK-1171: when the client closes after the
// 101 without ever sending a frame (and the upstream stays idle), the
// post-swap session must still return, and OnComplete must carry the
// handshake StreamID — an empty id makes the recorder skip the terminal
// update and leaves the WS Stream stuck at state=active.
func TestRunStackSession_WSUpgrade_ClientCloseWithoutFrameCompletesStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	f := startWSServerFirstFixture(t, ctx, nil)

	// Let the swap install the ws.Layers before the client goes away.
	time.Sleep(100 * time.Millisecond)
	_ = f.browser.Close()

	select {
	case <-f.done:
	case <-time.After(3 * time.Second):
		t.Fatal("RunStackSession did not return after the client closed (upstream idle)")
	}

	ids := f.completeIDs()
	if len(ids) != 1 {
		t.Fatalf("OnComplete fired %d times (%q), want exactly 1", len(ids), ids)
	}
	if ids[0] == "" {
		t.Errorf("OnComplete streamID = %q, want the handshake StreamID", ids[0])
	}
}
