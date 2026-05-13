//go:build e2e && !e2e_smoke

// ws_deflate_multiframe_integration_test.go — USK-867 acceptance gate for
// permessage-deflate context-takeover across MULTIPLE frames in one
// direction (Node ws@8.20.1 reproducer).
//
// The bug pinned by these tests: when permessage-deflate is negotiated
// with context-takeover (the RFC 7692 default — no _no_context_takeover
// params), Node clients/servers use a SINGLE long-lived flate writer that
// emits successive frames whose compressed bytes reference back into the
// LZ77 sliding window populated by previous messages. The proxy MUST
// maintain a matching decompressor dictionary so frame N (N>=2) decodes
// correctly. The earlier USK-847 round-trip test exchanges only ONE
// compressed frame per direction and the WithParameters companion uses
// client_no_context_takeover (which resets every message), so neither
// covered the continuation scenario. These tests close that gap.
//
// Test design notes:
//   - The wire-format compressed bytes are produced by a SHARED flate
//     writer (one per direction) via `deflateCompressWithContext` in
//     deflate_test.go — same package as the production code. We
//     re-implement an equivalent helper here because the deflate_test.go
//     copy lives in the internal `ws` package while these tests live in
//     `ws_test`. Both produce byte-for-byte the same wire format as
//     Node ws@8.20.1.
//   - The receive-side verification (mustInflateMulti below) uses a
//     symmetric long-lived flate.Reader to mirror what a real peer would
//     do. Each frame is inflated against the accumulated decompressor
//     state from prior frames.
//   - Tests are gated `e2e && !e2e_smoke` per CLAUDE.md USK-728 (default
//     for new integration tests; promote to smoke only when explicitly
//     part of the merge gate).

package ws_test

import (
	"bytes"
	"compress/flate"
	"context"
	"io"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// multiFrameDeflator simulates a peer that compresses multiple messages
// through a single long-lived flate.Writer — matching Node ws@8.20.1's
// permessage-deflate (context-takeover) wire production. Each Compress
// call writes payload + Flush, then strips the RFC 7692 §7.2.1 trailer
// (0x00 0x00 0xff 0xff) the spec mandates the sender omit on the wire.
type multiFrameDeflator struct {
	buf bytes.Buffer
	w   *flate.Writer
}

// newMultiFrameDeflator returns a deflator backed by a fresh flate.Writer.
// The writer is reused across Compress calls so the LZ77 sliding window
// accumulates — that is exactly the context-takeover wire production.
func newMultiFrameDeflator(t *testing.T) *multiFrameDeflator {
	t.Helper()
	d := &multiFrameDeflator{}
	w, err := flate.NewWriter(&d.buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate.NewWriter: %v", err)
	}
	d.w = w
	return d
}

// Compress encodes one message and returns the wire bytes (trailer
// stripped). The internal flate writer's state is preserved across calls
// so successive messages share an LZ77 window.
func (d *multiFrameDeflator) Compress(t *testing.T, payload []byte) []byte {
	t.Helper()
	d.buf.Reset()
	if _, err := d.w.Write(payload); err != nil {
		t.Fatalf("flate write: %v", err)
	}
	if err := d.w.Flush(); err != nil {
		t.Fatalf("flate flush: %v", err)
	}
	out := make([]byte, d.buf.Len())
	copy(out, d.buf.Bytes())
	trailer := []byte{0x00, 0x00, 0xff, 0xff}
	if bytes.HasSuffix(out, trailer) {
		out = out[:len(out)-4]
	}
	return out
}

// multiFrameInflator is the receive-side analogue of multiFrameDeflator:
// it inflates successive permessage-deflate frames against an
// accumulated LZ77 history. Because Go's compress/flate caches errors
// permanently on a single Reader, we mirror the production strategy
// from deflate.go — keep a dict []byte of cumulative decompressed
// output and pass it to flate.NewReaderDict on each frame.
type multiFrameInflator struct {
	dict []byte
}

// Inflate decompresses a permessage-deflate wire payload (trailer
// stripped) and returns the original plaintext. The internal dict is
// updated so the next Inflate call resolves back-references that refer
// into the LZ77 window populated by this frame.
func (m *multiFrameInflator) Inflate(t *testing.T, src []byte) []byte {
	t.Helper()
	with := append(append([]byte{}, src...), 0x00, 0x00, 0xff, 0xff)
	var fr io.ReadCloser
	if len(m.dict) > 0 {
		fr = flate.NewReaderDict(bytes.NewReader(with), m.dict)
	} else {
		fr = flate.NewReader(bytes.NewReader(with))
	}
	defer fr.Close()
	out, err := io.ReadAll(fr)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		t.Fatalf("flate read: %v", err)
	}
	m.dict = append(m.dict, out...)
	if len(m.dict) > 32768 {
		m.dict = m.dict[len(m.dict)-32768:]
	}
	return out
}

// writeClientCompressedFrame writes a single masked client→server WS
// frame with RSV1 set; caller supplies the pre-compressed wire payload.
// Differs from writeClientDeflateFrame in ws_deflate_integration_test.go
// only in name (kept distinct so test failures point to the multi-frame
// suite when grepped). Mask key is fixed for reproducibility — the
// production proxy generates fresh keys per frame on its own Send path.
func (h *wsHarness) writeClientCompressedFrame(payload []byte) {
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
		h.t.Fatalf("writeClientCompressedFrame: %v", err)
	}
}

// writeServerCompressedFrame writes a single unmasked server→client WS
// frame with RSV1 set; caller supplies the pre-compressed wire payload.
func (h *wsHarness) writeServerCompressedFrame(payload []byte) {
	h.t.Helper()
	f := &ws.Frame{
		Fin:     true,
		RSV1:    true,
		Opcode:  ws.OpcodeText,
		Payload: payload,
	}
	if err := ws.WriteFrame(h.upstreamB, f); err != nil {
		h.t.Fatalf("writeServerCompressedFrame: %v", err)
	}
}

// TestWSUpgrade_PermessageDeflate_ContextTakeover_MultiFrame_ClientToServer
// exercises three successive compressed text frames from the client to
// the server, all produced by a single long-lived flate.Writer (matching
// Node ws@8.20.1's wire format). The proxy's post-swap WS Layer must
// honor the LZ77 sliding window — the second and third frames reference
// the first frame's bytes via back-references, so a missing or reset
// dictionary on the proxy side would surface as
// "deflate decompress: unexpected EOF" (the USK-867 symptom).
func TestWSUpgrade_PermessageDeflate_ContextTakeover_MultiFrame_ClientToServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	// Plain "permessage-deflate" — context-takeover ON by default per
	// parseDeflateExtension; matches Node ws@8.20.1's default.
	h.performDeflateUpgrade(ctx, "permessage-deflate")

	// Use a SHARED deflator so successive compressed bytes carry the
	// LZ77 history. The text payloads share the literal "fox" and
	// "the " so frames 2 and 3 will contain LZ77 back-references that
	// only resolve against frame 1's plaintext.
	cd := newMultiFrameDeflator(t)
	plain := []string{
		"the quick brown fox jumps over the lazy dog",
		"the quick brown fox jumps over the lazy dog again",
		"the fox returns: the quick brown fox over the lazy dog yet again",
	}

	// Sequential write + read keeps the test deterministic; the
	// production keepalive race (see Phase C audit) is exercised by a
	// separate goroutine-based test.
	upInf := &multiFrameInflator{}
	for i, msg := range plain {
		h.writeClientCompressedFrame(cd.Compress(t, []byte(msg)))
		up := h.readUpstreamFrame()
		if !up.RSV1 {
			t.Errorf("frame %d: upstream RSV1=false, want true (deflate re-encoded)", i)
		}
		if up.Opcode != ws.OpcodeText {
			t.Errorf("frame %d: upstream opcode = 0x%X, want 0x%X (Text)", i, up.Opcode, ws.OpcodeText)
		}
		got := upInf.Inflate(t, up.Payload)
		if string(got) != msg {
			t.Errorf("frame %d: upstream payload = %q, want %q", i, got, msg)
		}
	}

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(5 * time.Second)

	// Verify recorded flows for each frame surface Compressed=true and
	// state=complete (no protocol_error).
	wsFlows := wsFlowsOnly(h.store.allFlows())
	sendCount := 0
	for _, f := range wsFlows {
		if f.Direction != "send" {
			continue
		}
		sendCount++
		if got := f.Metadata["ws_compressed"]; got != "true" {
			t.Errorf("send flow %d: ws_compressed = %q, want true", sendCount, got)
		}
		if len(f.RawBytes) == 0 {
			t.Errorf("send flow %d: RawBytes empty; wire-compressed bytes expected", sendCount)
		}
	}
	if sendCount < len(plain) {
		t.Errorf("recorded send WS flows = %d, want >= %d", sendCount, len(plain))
	}
	for _, st := range h.store.getStreams() {
		if st.FailureReason == "protocol_error" {
			t.Errorf("stream %s recorded FailureReason=protocol_error (USK-867 regression)", st.ID)
		}
	}
}

// TestWSUpgrade_PermessageDeflate_ContextTakeover_MultiFrame_ServerToClient
// is the symmetric direction of the client→server test. A real upstream
// (e.g., Node ws@8.20.1 echo server) compresses successive messages with
// a single long-lived writer for the server-side direction. The proxy's
// post-swap WS Layer must hold the serverDS dictionary across reads.
//
// Harness note: the test sends one tiny client→server "nudge" frame
// first because performDeflateUpgrade returns before the upstream-facing
// goroutine has finished arming its Channel.Next loop. The nudge does
// not affect the serverDS dictionary under test (clientDS is the
// c→s direction). Documented at length under
// TestWSUpgrade_PermessageDeflate_ContextTakeover_MultiFrame_Bidirectional —
// the same harness wrinkle.
func TestWSUpgrade_PermessageDeflate_ContextTakeover_MultiFrame_ServerToClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	h.performDeflateUpgrade(ctx, "permessage-deflate")

	// Harness arming nudge: send + drain one c→s frame to ensure both
	// directions of the post-swap session goroutine are fully running.
	nudge := newMultiFrameDeflator(t)
	h.writeClientCompressedFrame(nudge.Compress(t, []byte("nudge")))
	_ = h.readUpstreamFrame()

	sd := newMultiFrameDeflator(t)
	plain := []string{
		"server frame one: status okay",
		"server frame two: status okay, status okay",
		"server frame three: still okay, server frame three still okay",
	}

	clInf := &multiFrameInflator{}
	for i, msg := range plain {
		h.writeServerCompressedFrame(sd.Compress(t, []byte(msg)))
		cl := h.readClientFrame()
		if !cl.RSV1 {
			t.Errorf("frame %d: client RSV1=false, want true", i)
		}
		got := clInf.Inflate(t, cl.Payload)
		if string(got) != msg {
			t.Errorf("frame %d: client payload = %q, want %q", i, got, msg)
		}
	}

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(5 * time.Second)

	wsFlows := wsFlowsOnly(h.store.allFlows())
	recvCount := 0
	for _, f := range wsFlows {
		if f.Direction != "receive" {
			continue
		}
		recvCount++
		if got := f.Metadata["ws_compressed"]; got != "true" {
			t.Errorf("receive flow %d: ws_compressed = %q, want true", recvCount, got)
		}
	}
	if recvCount < len(plain) {
		t.Errorf("recorded receive WS flows = %d, want >= %d", recvCount, len(plain))
	}
	for _, st := range h.store.getStreams() {
		if st.FailureReason == "protocol_error" {
			t.Errorf("stream %s recorded FailureReason=protocol_error (USK-867 regression)", st.ID)
		}
	}
}

// TestWSUpgrade_PermessageDeflate_ContextTakeover_MultiFrame_Bidirectional
// interleaves three frames in each direction (C→S→C→S→C→S) to confirm
// the proxy maintains DISTINCT clientDS and serverDS dictionaries
// without cross-contamination. Includes one duplicate-content frame
// (frame 2 and frame 3 share "the cat sat on the mat") to force LZ77
// back-references and confirm dict continuity is correctly applied.
func TestWSUpgrade_PermessageDeflate_ContextTakeover_MultiFrame_Bidirectional(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	h := newWSHarness(t, ctx, harnessOpts{})
	h.performDeflateUpgrade(ctx, "permessage-deflate")

	cDef := newMultiFrameDeflator(t)
	sDef := newMultiFrameDeflator(t)
	upInf := &multiFrameInflator{}
	clInf := &multiFrameInflator{}

	clientMsgs := []string{
		"the cat sat on the mat",
		"the cat sat on the mat again",
		"the cat sat on the mat yet again, the cat sat on the mat",
	}
	serverMsgs := []string{
		"server reply alpha alpha alpha",
		"server reply alpha beta gamma",
		"server reply alpha beta gamma delta, alpha beta gamma",
	}

	for i := 0; i < 3; i++ {
		// client → server
		h.writeClientCompressedFrame(cDef.Compress(t, []byte(clientMsgs[i])))
		up := h.readUpstreamFrame()
		if !up.RSV1 {
			t.Errorf("c2s frame %d: RSV1=false", i)
		}
		if got := string(upInf.Inflate(t, up.Payload)); got != clientMsgs[i] {
			t.Errorf("c2s frame %d: got %q, want %q", i, got, clientMsgs[i])
		}

		// server → client
		h.writeServerCompressedFrame(sDef.Compress(t, []byte(serverMsgs[i])))
		cl := h.readClientFrame()
		if !cl.RSV1 {
			t.Errorf("s2c frame %d: RSV1=false", i)
		}
		if got := string(clInf.Inflate(t, cl.Payload)); got != serverMsgs[i] {
			t.Errorf("s2c frame %d: got %q, want %q", i, got, serverMsgs[i])
		}
	}

	h.closeClient()
	h.closeUpstream()
	_ = h.waitSessionDone(5 * time.Second)

	wsFlows := wsFlowsOnly(h.store.allFlows())
	var sendN, recvN int
	for _, f := range wsFlows {
		switch f.Direction {
		case "send":
			sendN++
		case "receive":
			recvN++
		}
	}
	if sendN < 3 {
		t.Errorf("recorded send WS flows = %d, want >= 3", sendN)
	}
	if recvN < 3 {
		t.Errorf("recorded receive WS flows = %d, want >= 3", recvN)
	}
	for _, st := range h.store.getStreams() {
		if st.FailureReason == "protocol_error" {
			t.Errorf("stream %s recorded FailureReason=protocol_error (USK-867 regression)", st.ID)
		}
	}
	// Sanity: each client message must appear verbatim as the Body of
	// some recorded send flow. The Pipeline records the post-decompression
	// plaintext (not the wire bytes — those live in Envelope.Raw), so the
	// match is deterministic.
	for i, msg := range clientMsgs {
		want := []byte(msg)
		found := false
		for _, f := range wsFlows {
			if f.Direction == "send" && bytes.Equal(f.Body, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("client message %d: body %q not found among recorded send flows", i, msg)
		}
	}
}
