//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

// USK-1238: RFC-001 §9.3 D4 "Raw wins" on WebSocket. A plugin that assigns
// msg["raw"] on a (ws, on_message) hook must have exactly those frame
// bytes reach the peer; untouched frames keep the Message re-encode path.
//
// Every test drives a real Starlark plugin through BuildLiveStack on a
// tcp_forwards protocol=websocket listener and observes the bytes on the
// far side.

// --- capturing WS upstream -------------------------------------------------

// wsCaptureUpstream answers the RFC 6455 handshake with 101 (adding
// Sec-WebSocket-Extensions when ext is set), optionally writes greeting
// verbatim right after it, and then records every byte the proxy sends.
type wsCaptureUpstream struct {
	ln       net.Listener
	ext      string
	greeting []byte

	mu   sync.Mutex
	buf  bytes.Buffer
	wg   sync.WaitGroup
	done chan struct{}
}

func startWSCaptureUpstream(t *testing.T, ext string, greeting []byte) *wsCaptureUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	u := &wsCaptureUpstream{ln: ln, ext: ext, greeting: greeting, done: make(chan struct{})}
	u.wg.Add(1)
	go u.acceptOnce()
	t.Cleanup(func() {
		_ = ln.Close()
		close(u.done)
		waitDone := make(chan struct{})
		go func() { u.wg.Wait(); close(waitDone) }()
		select {
		case <-waitDone:
		case <-time.After(2 * time.Second):
		}
	})
	return u
}

func (u *wsCaptureUpstream) Addr() string { return u.ln.Addr().String() }

func (u *wsCaptureUpstream) acceptOnce() {
	defer u.wg.Done()
	c, err := u.ln.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	go func() { <-u.done; _ = c.Close() }()
	br := bufio.NewReader(c)
	if _, err := br.ReadString('\n'); err != nil {
		return
	}
	var key string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "sec-websocket-key:") {
			key = strings.TrimSpace(line[len("sec-websocket-key:"):])
		}
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + computeWSAcceptForUSK913(key) + "\r\n"
	if u.ext != "" {
		resp += "Sec-WebSocket-Extensions: " + u.ext + "\r\n"
	}
	if _, err := c.Write([]byte(resp + "\r\n")); err != nil {
		return
	}
	if len(u.greeting) > 0 {
		time.Sleep(50 * time.Millisecond)
		if _, err := c.Write(u.greeting); err != nil {
			return
		}
	}
	_, _ = io.Copy(lockedWriter{mu: &u.mu, buf: &u.buf}, br)
}

// capturedFrame is one frame read by the upstream, with its wire bytes.
type capturedFrame struct {
	frame *ws.Frame
	raw   []byte
}

// waitFrames polls until the upstream has read at least n complete frames
// or the deadline passes, then returns what it has.
func (u *wsCaptureUpstream) waitFrames(n int) []capturedFrame {
	end := time.Now().Add(5 * time.Second)
	var out []capturedFrame
	for time.Now().Before(end) {
		u.mu.Lock()
		b := append([]byte(nil), u.buf.Bytes()...)
		u.mu.Unlock()
		out = parseWSFrames(b)
		if len(out) >= n {
			return out
		}
		time.Sleep(20 * time.Millisecond)
	}
	return out
}

func parseWSFrames(b []byte) []capturedFrame {
	var out []capturedFrame
	r := bytes.NewReader(b)
	for r.Len() > 0 {
		f, raw, err := ws.ReadFrameRaw(r)
		if err != nil {
			break
		}
		out = append(out, capturedFrame{frame: f, raw: raw})
	}
	return out
}

// --- client side -----------------------------------------------------------

// dialWSForward opens a client connection to the forward listener and
// completes the RFC 6455 handshake (offering permessage-deflate when
// deflate is true).
func dialWSForward(t *testing.T, addr string, deflate bool) (net.Conn, *bufio.Reader) {
	t.Helper()
	c, br := dialForward(t, addr)
	req := "GET /usk1238 HTTP/1.1\r\nHost: example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
	if deflate {
		req += "Sec-WebSocket-Extensions: permessage-deflate\r\n"
	}
	if _, err := c.Write([]byte(req + "\r\n")); err != nil {
		t.Fatalf("write handshake: %v", err)
	}
	if err := readWS101ForUSK913(br); err != nil {
		t.Fatalf("read 101: %v", err)
	}
	return c, br
}

var clientMaskKey = [4]byte{0xAA, 0xBB, 0xCC, 0xDD}

// clientFrame encodes a masked client→server frame with clientMaskKey.
func clientFrame(t *testing.T, f ws.Frame) []byte {
	t.Helper()
	f.Masked = true
	f.MaskKey = clientMaskKey
	var b bytes.Buffer
	if err := ws.WriteFrame(&b, &f); err != nil {
		t.Fatalf("encode frame: %v", err)
	}
	return b.Bytes()
}

func writeAll(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	if _, err := c.Write(b); err != nil {
		t.Fatalf("client write: %v", err)
	}
}

// starlarkBytes renders b as a Starlark bytes literal.
func starlarkBytes(b []byte) string {
	var s strings.Builder
	s.WriteString(`b"`)
	for _, c := range b {
		fmt.Fprintf(&s, `\x%02x`, c)
	}
	s.WriteString(`"`)
	return s.String()
}

// pluginWSClientRaw is a client→server frame the Message path can never
// produce: masked text "PLUGIN" with a fixed mask key 01 02 03 04 and
// RSV2 set (Send zeroes RSV2 and draws a fresh mask).
func pluginWSClientRaw() []byte {
	key := [4]byte{0x01, 0x02, 0x03, 0x04}
	p := []byte("PLUGIN")
	for i := range p {
		p[i] ^= key[i%4]
	}
	out := []byte{0x80 | 0x20 | ws.OpcodeText, 0x80 | byte(len(p))}
	out = append(out, key[:]...)
	return append(out, p...)
}

// pluginWSServerRaw is a server→client frame with RSV3 set and a
// non-minimal 16-bit extended length for a 5-byte payload.
func pluginWSServerRaw() []byte {
	return append([]byte{0x80 | 0x10 | ws.OpcodeText, 126, 0x00, 0x05}, "SPOOF"...)
}

// assertMessagePathFrame checks f is a Message-path re-encode of a client
// frame: the expected payload, masked with a fresh key, no RSV bits.
func assertMessagePathFrame(t *testing.T, f capturedFrame, payload string) {
	t.Helper()
	if string(f.frame.Payload) != payload {
		t.Errorf("upstream frame payload = %q, want %q (raw %x)", f.frame.Payload, payload, f.raw)
	}
	if !f.frame.Masked || f.frame.MaskKey == clientMaskKey {
		t.Errorf("upstream frame mask = %v key %x; want a fresh proxy mask (client key %x) — Raw leaked to the wire", f.frame.Masked, f.frame.MaskKey, clientMaskKey)
	}
	if f.frame.RSV1 || f.frame.RSV2 || f.frame.RSV3 {
		t.Errorf("upstream frame RSV bits set: raw %x", f.raw)
	}
}

// --- tests -----------------------------------------------------------------

// TestPluginRawWins_WS_ClientToServer covers Test Plan #1 and #3: a
// msg["raw"] write on a client frame (pre and post_pipeline) reaches the
// upstream verbatim, the variants record client / plugin bytes, and the
// next untouched frame on the same connection is re-encoded as before.
func TestPluginRawWins_WS_ClientToServer(t *testing.T) {
	pluginRaw := pluginWSClientRaw()
	for _, phaseArg := range []string{"", `, phase="post_pipeline"`} {
		name := "pre_pipeline"
		if phaseArg != "" {
			name = "post_pipeline"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			script := `
def on_msg(msg, ctx):
    if msg["payload"] == b"hello":
        msg["raw"] = ` + starlarkBytes(pluginRaw) + `
register_hook("ws", "on_message", on_msg` + phaseArg + `)
`
			up := startWSCaptureUpstream(t, "", nil)
			h, fwd := startRawWinsForward(t, ctx, script, up.Addr(), "websocket", nil)
			c, _ := dialWSForward(t, fwd, false)

			hello := clientFrame(t, ws.Frame{Fin: true, Opcode: ws.OpcodeText, Payload: []byte("hello")})
			writeAll(t, c, hello)
			up.waitFrames(1)
			writeAll(t, c, clientFrame(t, ws.Frame{Fin: true, Opcode: ws.OpcodeText, Payload: []byte("keep")}))

			frames := up.waitFrames(2)
			if len(frames) < 2 {
				t.Fatalf("upstream got %d frames, want 2", len(frames))
			}
			if !bytes.Equal(frames[0].raw, pluginRaw) {
				t.Errorf("upstream frame 1 = %x, want plugin bytes %x", frames[0].raw, pluginRaw)
			}
			assertMessagePathFrame(t, frames[1], "keep")

			if orig := waitFlow(h.store, "send", "original", func(b []byte) bool { return bytes.Equal(b, hello) }); orig == nil {
				t.Errorf("original send variant with the client frame missing; flows:%s", describeFlows(h.store))
			}
			if mod := waitFlow(h.store, "send", "modified", func(b []byte) bool { return bytes.Equal(b, pluginRaw) }); mod == nil {
				t.Errorf("modified send variant must equal the wire bytes %x; flows:%s", pluginRaw, describeFlows(h.store))
			}
		})
	}
}

// TestPluginRawWins_WS_ServerToClient covers Test Plan #2: a msg["raw"]
// write on an upstream frame reaches the client verbatim.
func TestPluginRawWins_WS_ServerToClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pluginRaw := pluginWSServerRaw()
	var greeting bytes.Buffer
	if err := ws.WriteFrame(&greeting, &ws.Frame{Fin: true, Opcode: ws.OpcodeText, Payload: []byte("hello-from-up")}); err != nil {
		t.Fatal(err)
	}
	up := startWSCaptureUpstream(t, "", greeting.Bytes())
	h, fwd := startRawWinsForward(t, ctx, `
def on_msg(msg, ctx):
    if msg["payload"] == b"hello-from-up":
        msg["raw"] = `+starlarkBytes(pluginRaw)+`
register_hook("ws", "on_message", on_msg)
`, up.Addr(), "websocket", nil)
	c, br := dialWSForward(t, fwd, false)

	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, len(pluginRaw))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("read relayed frame: %v (got %x)", err, got)
	}
	if !bytes.Equal(got, pluginRaw) {
		t.Errorf("client received %x, want plugin bytes %x", got, pluginRaw)
	}
	if mod := waitFlow(h.store, "receive", "modified", func(b []byte) bool { return bytes.Equal(b, pluginRaw) }); mod == nil {
		t.Errorf("modified receive variant must equal the wire bytes; flows:%s", describeFlows(h.store))
	}
}

// TestPluginRawWins_WS_MessageOnlyReencodes covers Test Plan #4 (reverse
// guard): a payload-only mutation goes out re-encoded, never as Raw.
func TestPluginRawWins_WS_MessageOnlyReencodes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up := startWSCaptureUpstream(t, "", nil)
	_, fwd := startRawWinsForward(t, ctx, `
def on_msg(msg, ctx):
    if msg["payload"] == b"hello":
        msg["payload"] = b"changed"
register_hook("ws", "on_message", on_msg)
`, up.Addr(), "websocket", nil)
	c, _ := dialWSForward(t, fwd, false)
	writeAll(t, c, clientFrame(t, ws.Frame{Fin: true, Opcode: ws.OpcodeText, Payload: []byte("hello")}))

	frames := up.waitFrames(1)
	if len(frames) < 1 {
		t.Fatal("upstream got no frame")
	}
	assertMessagePathFrame(t, frames[0], "changed")
}

// TestPluginRawWins_WS_TransformPrecedence covers Test Plan #5: pipeline
// order decides between a plugin raw write and a firing WS Transform rule.
func TestPluginRawWins_WS_TransformPrecedence(t *testing.T) {
	pluginRaw := pluginWSClientRaw()
	cases := []struct {
		name     string
		phaseArg string
		wantRaw  bool
	}{
		{name: "pre_pipeline raw then Transform", phaseArg: "", wantRaw: false},
		{name: "Transform then post_pipeline raw", phaseArg: `, phase="post_pipeline"`, wantRaw: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			te := wsrules.NewTransformEngine()
			te.AddRule(wsrules.TransformRule{
				ID: "usk-1238-replace", Enabled: true, Direction: wsrules.DirectionSend,
				ActionType:     wsrules.TransformReplacePayload,
				PayloadPattern: regexp.MustCompile(`hello`), PayloadReplace: []byte("XFORM"),
			})
			script := `
def on_msg(msg, ctx):
    if msg["payload"] in (b"hello", b"XFORM"):
        msg["raw"] = ` + starlarkBytes(pluginRaw) + `
register_hook("ws", "on_message", on_msg` + tc.phaseArg + `)
`
			up := startWSCaptureUpstream(t, "", nil)
			_, fwd := startRawWinsForwardDeps(t, ctx, script, up.Addr(), "websocket", func(d *proxybuild.Deps) {
				d.WSTransformEngine = te
			})
			c, _ := dialWSForward(t, fwd, false)
			writeAll(t, c, clientFrame(t, ws.Frame{Fin: true, Opcode: ws.OpcodeText, Payload: []byte("hello")}))

			frames := up.waitFrames(1)
			if len(frames) < 1 {
				t.Fatal("upstream got no frame")
			}
			if tc.wantRaw {
				if !bytes.Equal(frames[0].raw, pluginRaw) {
					t.Errorf("upstream frame = %x, want plugin bytes %x", frames[0].raw, pluginRaw)
				}
				return
			}
			if bytes.Equal(frames[0].raw, pluginRaw) {
				t.Fatal("upstream received the pre_pipeline plugin bytes; the later Transform must win")
			}
			assertMessagePathFrame(t, frames[0], "XFORM")
		})
	}
}

// wsDeflator compresses successive messages through one long-lived flate
// writer (permessage-deflate with context takeover), stripping the
// RFC 7692 §7.2.1 trailer.
type wsDeflator struct {
	buf bytes.Buffer
	w   *flate.Writer
}

func (d *wsDeflator) compress(t *testing.T, p []byte) []byte {
	t.Helper()
	if d.w == nil {
		w, err := flate.NewWriter(&d.buf, flate.DefaultCompression)
		if err != nil {
			t.Fatal(err)
		}
		d.w = w
	}
	d.buf.Reset()
	if _, err := d.w.Write(p); err != nil {
		t.Fatal(err)
	}
	if err := d.w.Flush(); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(append([]byte(nil), d.buf.Bytes()...), []byte{0x00, 0x00, 0xff, 0xff})
}

// wsInflator is a persistent (context-takeover) inflater, as a real peer
// keeps across messages.
type wsInflator struct{ dict []byte }

func (m *wsInflator) inflate(src []byte) ([]byte, error) {
	in := append(append([]byte(nil), src...), 0x00, 0x00, 0xff, 0xff)
	fr := flate.NewReaderDict(bytes.NewReader(in), m.dict)
	defer fr.Close()
	out, err := io.ReadAll(fr)
	if err != nil && err != io.ErrUnexpectedEOF {
		return out, err
	}
	m.dict = append(m.dict, out...)
	if len(m.dict) > 32768 {
		m.dict = m.dict[len(m.dict)-32768:]
	}
	return out, nil
}

// TestPluginRawWins_WS_DeflateContextTakeover covers Test Plan #6: with
// permessage-deflate context takeover, a raw-wins compressed message goes
// out verbatim AND the proxy's send compressor stays in step with the
// upstream's inflater, so the following untouched message (which repeats
// m0 and so back-references the shared window) still decodes.
func TestPluginRawWins_WS_DeflateContextTakeover(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	m0 := []byte("the quick brown fox jumps over the lazy dog 0123456789")
	m1 := []byte("ZYXWVUTSRQPONMLKJIHGFEDCBA zyxwvutsrqponmlkjihgfedcba 9876543210!!")
	msgs := [][]byte{m0, m1, m0}

	up := startWSCaptureUpstream(t, "permessage-deflate", nil)
	_, fwd := startRawWinsForward(t, ctx, `
def on_msg(msg, ctx):
    if msg["payload"] == `+starlarkBytes(m1)+`:
        msg["raw"] = msg["raw"]
register_hook("ws", "on_message", on_msg)
`, up.Addr(), "websocket", nil)
	c, _ := dialWSForward(t, fwd, true)

	var d wsDeflator
	var clientFrames [][]byte
	for i, m := range msgs {
		f := clientFrame(t, ws.Frame{Fin: true, RSV1: true, Opcode: ws.OpcodeText, Payload: d.compress(t, m)})
		clientFrames = append(clientFrames, f)
		writeAll(t, c, f)
		up.waitFrames(i + 1)
	}

	frames := up.waitFrames(len(msgs))
	if len(frames) < len(msgs) {
		t.Fatalf("upstream got %d frames, want %d", len(frames), len(msgs))
	}
	if !bytes.Equal(frames[1].raw, clientFrames[1]) {
		t.Errorf("upstream m1 frame = %x, want the plugin's (client's) bytes %x", frames[1].raw, clientFrames[1])
	}
	var inf wsInflator
	for i, f := range frames[:len(msgs)] {
		got, err := inf.inflate(f.frame.Payload)
		if err != nil || !bytes.Equal(got, msgs[i]) {
			t.Errorf("upstream inflater message %d = %q (err %v), want %q", i, got, err, msgs[i])
		}
	}
}
