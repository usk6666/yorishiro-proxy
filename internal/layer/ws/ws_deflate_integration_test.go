//go:build e2e

// ws_deflate_integration_test.go — USK-847 acceptance gate for the
// session.runUpgradeWS path that propagates the wire-observed
// Sec-WebSocket-Extensions response header onto the post-swap ws.Layer
// pair. With the bug fix in place, a server that selects RFC 7692
// per-message-deflate causes the proxy to decode the wire-compressed
// payload into WSMessage.Payload while preserving the wire-compressed
// bytes in Envelope.Raw → Flow.RawBytes.
//
// The harness reuses the same in-memory testStore, pipePair, and
// pipeline assembly as ws_integration_test.go (defined there as
// untagged helpers in the same `ws_test` package — both files share the
// `//go:build e2e` constraint). We define a permessage-deflate-aware
// upgrade dance + echo handler inline; the precedent in
// ws_integration_test.go's testStore comment explicitly preferred
// self-contained integration files over cross-test helpers.

package ws_test

import (
	"bufio"
	"bytes"
	"compress/flate"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// performDeflateUpgrade drives an HTTP/1 → WebSocket upgrade whose 101
// response advertises Sec-WebSocket-Extensions: permessage-deflate (or
// the caller-supplied value). The pre-swap dance mirrors
// performUpgrade in ws_integration_test.go; the post-swap polling
// confirms both Layer slots flipped to *ws.Layer before returning.
func (h *wsHarness) performDeflateUpgrade(ctx context.Context, negotiated string) {
	h.t.Helper()

	const req = "GET /chat HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate\r\n" +
		"\r\n"

	resp101 := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" +
		"Sec-WebSocket-Extensions: " + negotiated + "\r\n" +
		"\r\n"

	go func() {
		br := bufio.NewReader(h.upstreamB)
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

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, clientOK := h.stack.ClientTopmost().(*ws.Layer)
		_, upOK := h.stack.UpstreamTopmost().(*ws.Layer)
		if clientOK && upOK {
			// Settle delay: mirror performUpgrade's 50ms gap so the
			// recursive RunStackSession has spawned its inner goroutines
			// before tests start writing frames.
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

// deflatePayload returns the RFC 7692 §7.2.2 deflate-encoded form of
// src: raw DEFLATE compressed bytes with the trailing 4 bytes
// (0x00 0x00 0xff 0xff) stripped — the trailer the spec mandates the
// sender omit on the wire. Used to forge a client→server compressed
// frame from the "browser" side.
func deflatePayload(t *testing.T, src []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	if _, err := w.Write(src); err != nil {
		t.Fatalf("flate Write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flate Flush: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("flate Close: %v", err)
	}
	out := buf.Bytes()
	// Strip the SYNC_FLUSH trailer (0x00 0x00 0xff 0xff) per RFC 7692
	// §7.2.2; the WS peer re-appends it before decompression.
	if len(out) >= 4 && bytes.Equal(out[len(out)-4:], []byte{0x00, 0x00, 0xff, 0xff}) {
		out = out[:len(out)-4]
	}
	return out
}

// writeClientDeflateFrame writes a single masked client→server WS frame
// with the per-message-deflate RSV1 bit set. The payload is the
// compressed bytes; the proxy's post-swap ws.Layer is expected to
// inflate it into WSMessage.Payload.
func (h *wsHarness) writeClientDeflateFrame(payload []byte) {
	h.t.Helper()
	f := &ws.Frame{
		Fin:     true,
		RSV1:    true,
		Opcode:  ws.OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: payload,
	}
	if err := ws.WriteFrame(h.clientA, f); err != nil {
		h.t.Fatalf("writeClientDeflateFrame: %v", err)
	}
}

// writeServerDeflateFrame writes a single unmasked server→client WS
// frame with RSV1 set (compressed). Used to exercise the
// upstream→client direction of the post-swap deflate state.
func (h *wsHarness) writeServerDeflateFrame(payload []byte) {
	h.t.Helper()
	f := &ws.Frame{
		Fin:     true,
		RSV1:    true,
		Opcode:  ws.OpcodeText,
		Payload: payload,
	}
	if err := ws.WriteFrame(h.upstreamB, f); err != nil {
		h.t.Fatalf("writeServerDeflateFrame: %v", err)
	}
}

// TestWSUpgrade_PermessageDeflate_RoundTrip is the canonical USK-847
// regression test. It drives a full HTTP/1 → WS upgrade whose 101
// advertises Sec-WebSocket-Extensions: permessage-deflate, then
// exchanges one compressed frame in each direction. With the fix in
// place, the proxy's post-swap ws.Layer pair honors the negotiated
// extension: each compressed wire frame is inflated into
// WSMessage.Payload (decoded text) while Envelope.Raw → Flow.RawBytes
// preserves the wire-compressed bytes verbatim.
//
// The bug this test pins shut: before USK-847, runUpgradeWS ignored the
// Sec-WebSocket-Extensions response header so the post-swap ws.Layer
// emerged with deflateEnabled=false. The compressed frame is then
// rejected with a protocol error ("ws: unexpected RSV1 with no
// permessage-deflate"), causing the session to abort and only the
// pre-swap HTTP envelopes to be recorded.
func TestWSUpgrade_PermessageDeflate_RoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	h.performDeflateUpgrade(ctx, "permessage-deflate")

	clientText := "hello-deflate-client"
	clientCompressed := deflatePayload(t, []byte(clientText))
	if len(clientCompressed) == 0 {
		t.Fatal("client compressed payload is empty")
	}
	if bytes.Equal(clientCompressed, []byte(clientText)) {
		t.Fatal("client compressed payload equals plaintext; deflatePayload helper broken")
	}
	h.writeClientDeflateFrame(clientCompressed)

	// The proxy decodes the inbound compressed frame, then re-encodes
	// it on Send if the upstream direction is also deflate-enabled.
	// With "permessage-deflate" (no _no_context_takeover params) both
	// directions are enabled by default per parseDeflateExtension.
	upFrame := h.readUpstreamFrame()
	if upFrame.Opcode != ws.OpcodeText {
		t.Errorf("upstream frame opcode = 0x%X, want 0x%X (Text)", upFrame.Opcode, ws.OpcodeText)
	}
	if !upFrame.RSV1 {
		t.Errorf("upstream frame RSV1 = false, want true (deflate re-encoded)")
	}
	// Decompress to verify the round-tripped payload is correct.
	got := mustInflate(t, upFrame.Payload)
	if string(got) != clientText {
		t.Errorf("upstream decompressed payload = %q, want %q", got, clientText)
	}

	// Reverse direction: server → client deflate frame.
	serverText := "hello-deflate-server"
	serverCompressed := deflatePayload(t, []byte(serverText))
	h.writeServerDeflateFrame(serverCompressed)
	clFrame := h.readClientFrame()
	if !clFrame.RSV1 {
		t.Errorf("client frame RSV1 = false, want true (deflate re-encoded toward browser)")
	}
	gotClient := mustInflate(t, clFrame.Payload)
	if string(gotClient) != serverText {
		t.Errorf("client decompressed payload = %q, want %q", gotClient, serverText)
	}

	h.closeClient()
	h.closeUpstream()
	if err := h.waitSessionDone(5 * time.Second); err != nil && !errors.Is(err, io.EOF) {
		// EOF on graceful client/upstream close is fine; surface
		// anything else so a regression that surfaces as session
		// abort is identifiable.
		t.Logf("session done err = %v", err)
	}

	// HTTP flow recording: the 101 upgrade response must surface the
	// Sec-WebSocket-Extensions header verbatim. This is the wire
	// evidence the orchestrator must read.
	allFlows := h.store.allFlows()
	var saw101 bool
	for _, f := range allFlows {
		if f.Direction != "receive" || f.StatusCode != 101 {
			continue
		}
		saw101 = true
		// keyValuesToMap preserves wire-observed header name casing
		// verbatim (MITM principle #1 — do not canonicalize).
		vs, ok := f.Headers["Sec-WebSocket-Extensions"]
		if !ok || len(vs) == 0 || vs[0] != "permessage-deflate" {
			t.Errorf("101 Sec-WebSocket-Extensions = %v (Headers=%v), want [permessage-deflate]", vs, f.Headers)
		}
	}
	if !saw101 {
		t.Error("no Receive flow with StatusCode=101; the HTTP upgrade response was not recorded")
	}

	// WS frame recording: at least one Send + one Receive WS flow with
	// the Compressed indicator surfaced. Payload (Body) must be the
	// DECODED plaintext; RawBytes must contain the wire-compressed
	// bytes (length differs from Body to confirm L4 fidelity).
	wsFlows := wsFlowsOnly(allFlows)
	var sendWS, recvWS *flow.Flow
	for _, f := range wsFlows {
		if f.Direction == "send" && bytes.Equal(f.Body, []byte(clientText)) {
			sendWS = f
		}
		if f.Direction == "receive" && bytes.Equal(f.Body, []byte(serverText)) {
			recvWS = f
		}
	}
	if sendWS == nil {
		t.Fatal("no Send WS flow with decoded plaintext body")
	}
	if recvWS == nil {
		t.Fatal("no Receive WS flow with decoded plaintext body")
	}
	if len(sendWS.RawBytes) == 0 {
		t.Error("send WS flow RawBytes empty; expected wire-compressed bytes")
	}
	if len(recvWS.RawBytes) == 0 {
		t.Error("receive WS flow RawBytes empty; expected wire-compressed bytes")
	}
	// Wire-fidelity check: RawBytes length should differ from Body
	// length (compression is lossy w.r.t. byte count). A regression
	// that records the decoded payload as RawBytes would equalise the
	// two.
	if len(sendWS.RawBytes) == len(sendWS.Body) {
		t.Errorf("send WS flow RawBytes len = Body len = %d; wire bytes should be compressed", len(sendWS.Body))
	}
}

// TestWSUpgrade_PermessageDeflate_WithParameters covers the recommended
// optional defensive case: parameters such as
// client_no_context_takeover are negotiated and the round-trip still
// succeeds. We do NOT introspect the internal deflateState struct
// (private) — instead we exercise multiple frames so a missing
// no_context_takeover (which resets the dictionary per message) would
// surface as decode-failure on the second frame.
func TestWSUpgrade_PermessageDeflate_WithParameters(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	h.performDeflateUpgrade(ctx, "permessage-deflate; client_no_context_takeover")

	for i, payload := range []string{"frame-one", "frame-two", "frame-three"} {
		h.writeClientDeflateFrame(deflatePayload(t, []byte(payload)))
		up := h.readUpstreamFrame()
		got := mustInflate(t, up.Payload)
		if string(got) != payload {
			t.Errorf("frame %d: upstream payload = %q, want %q", i, got, payload)
		}
	}

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(5 * time.Second)
}

// mustInflate decompresses a raw DEFLATE byte slice using the RFC 7692
// §7.2.2 algorithm: re-append the 4-byte sync trailer, then inflate.
// Used to verify the post-swap proxy produced canonical deflate frames
// on the upstream wire.
func mustInflate(t *testing.T, src []byte) []byte {
	t.Helper()
	with := append(append([]byte{}, src...), 0x00, 0x00, 0xff, 0xff)
	fr := flate.NewReader(bytes.NewReader(with))
	defer fr.Close()
	out, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("flate.NewReader read: %v", err)
	}
	return out
}
