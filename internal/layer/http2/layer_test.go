package http2

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// h2Peer is a manually-driven HTTP/2 peer used to exercise a Layer under test.
// It writes/reads raw frames against the other end of a net.Pipe.
type h2Peer struct {
	conn    net.Conn
	rd      *frame.Reader
	wr      *frame.Writer
	encoder *hpack.Encoder
	decoder *hpack.Decoder
}

func newH2Peer(c net.Conn) *h2Peer {
	return &h2Peer{
		conn:    c,
		rd:      frame.NewReader(c),
		wr:      frame.NewWriter(c),
		encoder: hpack.NewEncoder(4096, true),
		decoder: hpack.NewDecoder(4096),
	}
}

// startServerLayer starts a Layer in ServerRole at one end of a net.Pipe and
// returns the peer (h2Peer) on the other end. The peer is responsible for
// writing the client preface before any frame.
func startServerLayer(t *testing.T, opts ...Option) (*Layer, *h2Peer, func()) {
	t.Helper()
	cliConn, srvConn := net.Pipe()

	peer := newH2Peer(cliConn)

	type layerResult struct {
		l   *Layer
		err error
	}
	done := make(chan layerResult, 1)
	go func() {
		l, err := New(srvConn, "test-server", ServerRole, opts...)
		done <- layerResult{l: l, err: err}
	}()

	// Send client preface synchronously so the server New() can return.
	if _, err := peer.conn.Write([]byte(ClientPreface)); err != nil {
		t.Fatalf("write preface: %v", err)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("New(server): %v", res.err)
	}

	cleanup := func() {
		_ = res.l.Close()
		_ = peer.conn.Close()
	}
	return res.l, peer, cleanup
}

// startClientLayer starts a Layer in ClientRole at one end and returns the peer
// on the other end. The peer is responsible for reading the client preface.
func startClientLayer(t *testing.T, opts ...Option) (*Layer, *h2Peer, func()) {
	t.Helper()
	cliConn, srvConn := net.Pipe()

	peer := newH2Peer(srvConn)

	type layerResult struct {
		l   *Layer
		err error
	}
	done := make(chan layerResult, 1)
	go func() {
		l, err := New(cliConn, "test-client", ClientRole, opts...)
		done <- layerResult{l: l, err: err}
	}()

	// Read the client preface (24 bytes) so the layer's New() can proceed.
	buf := make([]byte, 24)
	if _, err := io.ReadFull(peer.conn, buf); err != nil {
		t.Fatalf("read preface: %v", err)
	}
	if string(buf) != ClientPreface {
		t.Fatalf("preface mismatch: %q", buf)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("New(client): %v", res.err)
	}
	cleanup := func() {
		_ = res.l.Close()
		_ = peer.conn.Close()
	}
	return res.l, peer, cleanup
}

// expectSettings reads frames from the peer until SETTINGS is consumed AND
// any startup connection-level WINDOW_UPDATE has been drained.
func (p *h2Peer) consumePeerSettings(t *testing.T) {
	t.Helper()
	sawSettings := false
	sawWU := false
	deadline := time.Now().Add(2 * time.Second)
	for !(sawSettings && sawWU) && time.Now().Before(deadline) {
		f, err := p.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read peer setup: %v", err)
		}
		switch f.Header.Type {
		case frame.TypeSettings:
			if !f.Header.Flags.Has(frame.FlagAck) {
				sawSettings = true
			}
		case frame.TypeWindowUpdate:
			sawWU = true
		}
	}
	if !sawSettings {
		t.Fatalf("did not see initial SETTINGS")
	}
}

// sendInitialSettings sends our SETTINGS to the peer's layer and expects to
// receive an ACK back.
func (p *h2Peer) sendInitialSettings(t *testing.T) {
	t.Helper()
	if err := p.wr.WriteSettings(nil); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}
}

// expectSettingsAck reads frames until it sees a SETTINGS ACK or fails.
func (p *h2Peer) expectSettingsAck(t *testing.T) {
	t.Helper()
	for i := 0; i < 4; i++ {
		f, err := p.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read SETTINGS ACK: %v", err)
		}
		if f.Header.Type == frame.TypeSettings && f.Header.Flags.Has(frame.FlagAck) {
			return
		}
	}
	t.Fatalf("did not see SETTINGS ACK after 4 frames")
}

// --- Layer construction tests ---

func TestLayer_NewServer(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	if l.Channels() == nil {
		t.Errorf("Channels() returned nil")
	}
	if l.role != ServerRole {
		t.Errorf("role = %s, want server", l.role)
	}
}

func TestLayer_NewClient(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	if l.role != ClientRole {
		t.Errorf("role = %s, want client", l.role)
	}
}

func TestLayer_OpenStream_ServerRoleRejected(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	_, err := l.OpenStream(context.Background())
	if err == nil {
		t.Fatalf("OpenStream(server role) want error, got nil")
	}
}

func TestLayer_OpenStream_AllocatesOddIDs(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ids := []uint32{}
	for i := 0; i < 3; i++ {
		ch, err := l.OpenStream(context.Background())
		if err != nil {
			t.Fatalf("OpenStream %d: %v", i, err)
		}
		c := ch.(*channel)
		ids = append(ids, c.h2Stream)
	}
	for _, id := range ids {
		if id%2 == 0 {
			t.Errorf("OpenStream returned even ID %d", id)
		}
	}
	if ids[0] != 1 || ids[1] != 3 || ids[2] != 5 {
		t.Errorf("OpenStream IDs = %v, want [1 3 5]", ids)
	}
}

func TestLayer_Close_NoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()

	l, peer, _ := startClientLayer(t)
	peer.consumePeerSettings(t)

	if err := l.Close(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Close: %v", err)
	}
	_ = peer.conn.Close()

	// Allow goroutines to terminate.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	after := runtime.NumGoroutine()
	if after > before+1 {
		t.Errorf("goroutine leak: before=%d after=%d", before, after)
	}
}

func TestLayer_Close_Idempotent(t *testing.T) {
	l, peer, _ := startClientLayer(t)
	peer.consumePeerSettings(t)
	_ = peer.conn.Close()

	for i := 0; i < 3; i++ {
		if err := l.Close(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("Close #%d: %v", i, err)
		}
	}
}

// --- Channels lifecycle ---

func TestLayer_Channels_ChannelEmittedOnPeerHeaders(t *testing.T) {
	l, peer, cleanup := startServerLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	// Send a HEADERS frame from the peer (client) — this should trigger the
	// server-side Layer to emit a Channel.
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":path", Value: "/hello"},
		{Name: ":authority", Value: "example.com"},
	}
	encoded := peer.encoder.Encode(headers)
	if err := peer.wr.WriteHeaders(1, true, true, encoded); err != nil {
		t.Fatalf("write HEADERS: %v", err)
	}

	var ch layer.Channel
	select {
	case ch = <-l.Channels():
	case <-time.After(time.Second):
		t.Fatalf("did not receive Channel within 1s")
	}
	if ch == nil {
		t.Fatal("nil Channel")
	}

	// Read the envelope.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("Channel.Next: %v", err)
	}
	if env.Direction != envelope.Send {
		t.Errorf("envelope direction = %s, want send", env.Direction)
	}
	msg := env.Message.(*envelope.HTTPMessage)
	if msg.Method != "GET" {
		t.Errorf("method = %q, want GET", msg.Method)
	}
	if msg.Path != "/hello" {
		t.Errorf("path = %q, want /hello", msg.Path)
	}
	if msg.Authority != "example.com" {
		t.Errorf("authority = %q, want example.com", msg.Authority)
	}
}

// --- WithInitialSettings ---

func TestLayer_WithInitialSettings(t *testing.T) {
	custom := DefaultSettings()
	custom.MaxConcurrentStreams = 7
	l, peer, cleanup := startServerLayer(t, WithInitialSettings(custom))
	defer cleanup()

	// Read peer's initial SETTINGS, look for our custom value.
	f, err := peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read SETTINGS: %v", err)
	}
	if f.Header.Type != frame.TypeSettings {
		t.Fatalf("got %s, want SETTINGS", f.Header.Type)
	}
	params, err := f.SettingsParams()
	if err != nil {
		t.Fatalf("parse SETTINGS: %v", err)
	}
	found := false
	for _, p := range params {
		if p.ID == frame.SettingMaxConcurrentStreams && p.Value == 7 {
			found = true
		}
	}
	if !found {
		t.Errorf("SETTINGS did not include MaxConcurrentStreams=7: %+v", params)
	}
	_ = l
}
