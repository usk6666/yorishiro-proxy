//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	sserules "github.com/usk6666/yorishiro-proxy/internal/rules/sse"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1239: RFC-001 §9.3 D4 "Raw wins" on the SSE wire. SSE events are
// written to the client by the session, so a plugin msg["raw"] write on
// (sse, on_event) must reach the client verbatim while the recorded
// modified variant holds the same bytes. Each test drives a real
// Starlark plugin through BuildLiveStack over a tcp_forward with
// protocol "sse".

// sseRawWinsOddEvent is a non-canonical upstream event (id before event,
// no space after "data:", a comment line).
const sseRawWinsOddEvent = "id: 7\nevent: tick\ndata:v1\n: keep-me\n\n"

// sseRawWinsSecondEvent is never touched by the plugins below.
const sseRawWinsSecondEvent = "data:  second\n\n"

// sseRawWinsPlugin is what the plugins assign to msg["raw"].
const sseRawWinsPlugin = "event: injected\ndata:x\n\n"

const sseRawWinsPreScript = `
def on_ev(msg, ctx):
    if msg["event"] == "tick":
        msg["raw"] = b"event: injected\ndata:x\n\n"
register_hook("sse", "on_event", on_ev)
`

// startSSERawWinsUpstream serves one SSE response carrying the two
// events above, either chunked or close-delimited.
func startSSERawWinsUpstream(t *testing.T, chunked bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go serveSSERawWins(c, chunked)
		}
	}()
	return ln.Addr().String()
}

func serveSSERawWins(c net.Conn, chunked bool) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
	}
	hdr := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n"
	if chunked {
		hdr += "Transfer-Encoding: chunked\r\n"
	} else {
		hdr += "Connection: close\r\n"
	}
	if _, err := c.Write([]byte(hdr + "\r\n")); err != nil {
		return
	}
	for _, ev := range []string{sseRawWinsOddEvent, sseRawWinsSecondEvent} {
		payload := ev
		if chunked {
			payload = fmt.Sprintf("%X\r\n%s\r\n", len(ev), ev)
		}
		if _, err := c.Write([]byte(payload)); err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if chunked {
		_, _ = c.Write([]byte("0\r\n\r\n"))
	}
}

// startSSERawWinsForward boots a Manager with a real plugin engine (and
// optionally an SSE Transform engine) and a tcp_forward of protocol sse.
func startSSERawWinsForward(t *testing.T, ctx context.Context, script, target string, transform *sserules.TransformEngine) (*flowStoreCapture, string) {
	t.Helper()
	store := &flowStoreCapture{}
	engine := loadRawWinsPlugin(t, ctx, script)
	buildCfg := rawWinsBuildConfig(t)
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger: testutil.DiscardLogger(),
		StackFactory: func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
			return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
				Logger:             testutil.DiscardLogger(),
				ListenerName:       name,
				ListenAddr:         addr,
				FlowStore:          store,
				BuildConfig:        buildCfg,
				PluginV2Engine:     engine,
				SSETransformEngine: transform,
			})
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{"0": {Target: target, Protocol: "sse"}},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	fwd := mgr.TCPForwardAddrs()["0"]
	if fwd == "" {
		t.Fatal("TCPForwardAddrs missing port 0")
	}
	return store, fwd
}

// readSSERawWinsBody sends the SSE request, consumes the response
// headers, and returns the first n body bytes as received on the wire
// (chunk framing included).
func readSSERawWinsBody(t *testing.T, fwd string, n int) []byte {
	t.Helper()
	c, br := dialForward(t, fwd)
	if _, err := c.Write([]byte("GET /events HTTP/1.1\r\nHost: example.test\r\nAccept: text/event-stream\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("status = %q, err = %v", status, err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	body := make([]byte, n)
	got, err := io.ReadFull(br, body)
	if err != nil {
		t.Fatalf("read body: got %d/%d bytes %q: %v", got, n, body[:got], err)
	}
	return body
}

func sseRawWinsFrame(payload string, chunked bool) string {
	if !chunked {
		return payload
	}
	return fmt.Sprintf("%X\r\n%s\r\n", len(payload), payload)
}

// TestPluginRawWins_SSE_Event covers Test Plan #1, #2 and #5: the
// client receives exactly the plugin bytes for the rewritten event and
// the untouched event byte-identical, on chunked and close-delimited
// HTTP/1.1 SSE; the modified variant records the plugin bytes.
func TestPluginRawWins_SSE_Event(t *testing.T) {
	for _, chunked := range []bool{true, false} {
		name := "close-delimited"
		if chunked {
			name = "chunked"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			up := startSSERawWinsUpstream(t, chunked)
			store, fwd := startSSERawWinsForward(t, ctx, sseRawWinsPreScript, up, nil)

			want := sseRawWinsFrame(sseRawWinsPlugin, chunked) + sseRawWinsFrame(sseRawWinsSecondEvent, chunked)
			if got := readSSERawWinsBody(t, fwd, len(want)); string(got) != want {
				t.Errorf("client received\n%q\nwant\n%q", got, want)
			}

			mod := waitFlow(store, "receive", "modified", func(b []byte) bool {
				return bytes.Equal(b, []byte(sseRawWinsPlugin))
			})
			if mod == nil {
				t.Errorf("no modified variant recording the plugin bytes; flows:%s", describeFlows(store))
			}
		})
	}
}

// TestPluginRawWins_SSE_TransformPrecedence covers Test Plan #7 at the
// integration tier: a pre_pipeline raw write followed by a firing SSE
// Transform rule puts the Transform output on the wire, and a
// post_pipeline raw write after the Transform wins.
func TestPluginRawWins_SSE_TransformPrecedence(t *testing.T) {
	transformed, err := sse.EncodeWireBytes(&envelope.Envelope{
		Protocol: envelope.ProtocolSSE,
		Message:  &envelope.SSEMessage{Event: "tick", ID: "7", Data: "TRANSFORMED"},
	})
	if err != nil {
		t.Fatalf("EncodeWireBytes: %v", err)
	}
	cases := []struct {
		name  string
		phase string
		first string
	}{
		{name: "pre_pipeline raw then Transform", phase: "pre_pipeline", first: string(transformed)},
		{name: "Transform then post_pipeline raw", phase: "post_pipeline", first: sseRawWinsPlugin},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			r, err := sserules.CompileTransformRule("set", 0, "", "^tick$", "", "", nil, nil, nil,
				sserules.TransformSetData, "", "", "TRANSFORMED", "", "", "", "", 0)
			if err != nil {
				t.Fatalf("CompileTransformRule: %v", err)
			}
			te := sserules.NewTransformEngine()
			te.AddRule(*r)

			script := `
def on_ev(msg, ctx):
    if msg["event"] == "tick":
        msg["raw"] = b"event: injected\ndata:x\n\n"
register_hook("sse", "on_event", on_ev, phase="` + tc.phase + `")
`
			up := startSSERawWinsUpstream(t, true)
			_, fwd := startSSERawWinsForward(t, ctx, script, up, te)

			want := sseRawWinsFrame(tc.first, true) + sseRawWinsFrame(sseRawWinsSecondEvent, true)
			if got := readSSERawWinsBody(t, fwd, len(want)); string(got) != want {
				t.Errorf("client received\n%q\nwant\n%q", got, want)
			}
		})
	}
}
