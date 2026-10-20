//go:build e2e && !e2e_smoke

// USK-1251 — native gRPC wire fidelity through the full MITM path
// (startGRPCMITMProxy: CONNECT → TLS → HTTP/2 → gRPC Layer → Pipeline →
// gRPC Layer → HTTP/2 → TLS upstream).
//
// Both ends are raw x/net/http2 Framers so the exact frame sequence and
// decoded header lists are observable: grpc-go would neither send an
// arbitrary request header layout nor surface the response :status, the
// header order, or the HEADERS-vs-TRAILERS frame split to the caller. The
// origin answers per :path with a hand-written HPACK response:
//
//   - /fid.Svc/Status503    HEADERS(:status 503, content-type) + TRAILERS(grpc-status 14)
//   - /fid.Svc/TrailersOnly HEADERS(:status 200, x-envoy, content-type, grpc-status 14, grpc-message, END_STREAM)
//   - /fid.Svc/Bare503      HEADERS(:status 503, server: lb, END_STREAM)
//   - anything else         HEADERS(:status 200, content-type) + TRAILERS(grpc-status 0)
package grpc_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"context"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
)

// fidelityOrigin is a raw HTTP/2 gRPC origin that records every request's
// decoded header list and answers with the response selected by :path.
type fidelityOrigin struct {
	ln net.Listener

	mu       sync.Mutex
	conns    []net.Conn
	requests [][]hpack.HeaderField // decoded request header lists, arrival order

	wg sync.WaitGroup
}

func startFidelityOrigin(t *testing.T, issuer *cert.Issuer) *fidelityOrigin {
	t.Helper()
	leaf, err := issuer.GetCertificate("localhost")
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	o := &fidelityOrigin{ln: ln}
	o.wg.Add(1)
	go o.acceptLoop()
	t.Cleanup(o.close)
	return o
}

func (o *fidelityOrigin) addr() string { return o.ln.Addr().String() }

func (o *fidelityOrigin) acceptLoop() {
	defer o.wg.Done()
	for {
		c, err := o.ln.Accept()
		if err != nil {
			return
		}
		o.mu.Lock()
		o.conns = append(o.conns, c)
		o.mu.Unlock()
		o.wg.Add(1)
		go func() {
			defer o.wg.Done()
			defer c.Close()
			o.serveConn(c)
		}()
	}
}

func (o *fidelityOrigin) close() {
	_ = o.ln.Close()
	o.mu.Lock()
	for _, c := range o.conns {
		_ = c.Close()
	}
	o.mu.Unlock()
	done := make(chan struct{})
	go func() { o.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
	}
}

// waitRequest returns the first recorded request header list.
func (o *fidelityOrigin) waitRequest(t *testing.T, timeout time.Duration) []hpack.HeaderField {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		o.mu.Lock()
		if len(o.requests) > 0 {
			r := o.requests[0]
			o.mu.Unlock()
			return r
		}
		o.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("origin received no request within %v", timeout)
	return nil
}

func (o *fidelityOrigin) serveConn(c net.Conn) {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 1 << 20
	if err := fr.WriteSettings(); err != nil {
		return
	}
	paths := map[uint32]string{}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch ff := f.(type) {
		case *http2.SettingsFrame:
			if !ff.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					return
				}
			}
		case *http2.PingFrame:
			if !ff.IsAck() {
				if err := fr.WritePing(true, ff.Data); err != nil {
					return
				}
			}
		case *http2.MetaHeadersFrame:
			fields := slices.Clone(ff.Fields)
			o.mu.Lock()
			o.requests = append(o.requests, fields)
			o.mu.Unlock()
			paths[ff.StreamID] = ff.PseudoValue("path")
			if ff.StreamEnded() {
				if err := respondFidelity(fr, ff.StreamID, paths[ff.StreamID]); err != nil {
					return
				}
			}
		case *http2.DataFrame:
			if ff.StreamEnded() {
				if err := respondFidelity(fr, ff.StreamID, paths[ff.StreamID]); err != nil {
					return
				}
			}
		}
	}
}

func hpackBlock(fields ...hpack.HeaderField) []byte {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, f := range fields {
		_ = enc.WriteField(f)
	}
	return buf.Bytes()
}

func hf(name, value string) hpack.HeaderField { return hpack.HeaderField{Name: name, Value: value} }

// fidelityTrailersOnlyFields is the trailers-only response the origin sends
// for /fid.Svc/TrailersOnly (regular fields only, wire order).
var fidelityTrailersOnlyFields = []hpack.HeaderField{
	hf("x-envoy", "1"),
	hf("content-type", "application/grpc"),
	hf("grpc-status", "14"),
	hf("grpc-message", "no%20healthy%20upstream"),
}

// respondFidelity writes the response selected by path. Called from the
// single reader goroutine, so Framer writes are not concurrent.
func respondFidelity(fr *http2.Framer, streamID uint32, path string) error {
	headers := func(end bool, fields ...hpack.HeaderField) error {
		return fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID: streamID, BlockFragment: hpackBlock(fields...), EndHeaders: true, EndStream: end,
		})
	}
	switch path {
	case "/fid.Svc/Status503":
		if err := headers(false, hf(":status", "503"), hf("content-type", "application/grpc")); err != nil {
			return err
		}
		return headers(true, hf("grpc-status", "14"))
	case "/fid.Svc/TrailersOnly":
		return headers(true, append([]hpack.HeaderField{hf(":status", "200")}, fidelityTrailersOnlyFields...)...)
	case "/fid.Svc/Bare503":
		return headers(true, hf(":status", "503"), hf("server", "lb"))
	default:
		if err := headers(false, hf(":status", "200"), hf("content-type", "application/grpc")); err != nil {
			return err
		}
		return headers(true, hf("grpc-status", "0"))
	}
}

// rawFrame is one frame the raw client observed on its request stream.
type rawFrame struct {
	kind      string // "headers", "data", "rst"
	fields    []hpack.HeaderField
	endStream bool
	rstCode   http2.ErrCode
}

func (f rawFrame) String() string {
	var b strings.Builder
	b.WriteString(f.kind)
	b.WriteString("(")
	for i, h := range f.fields {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(h.Name + ": " + h.Value)
	}
	if f.endStream {
		b.WriteString(", END_STREAM")
	}
	if f.kind == "rst" {
		b.WriteString(f.rstCode.String())
	}
	b.WriteString(")")
	return b.String()
}

// rawGRPCCall sends one gRPC request (HEADERS with the given regular
// fields + one LPM DATA frame with END_STREAM) on stream 1 through the
// proxy and returns every frame observed on that stream until it ends
// (END_STREAM or RST_STREAM) or the deadline passes.
func rawGRPCCall(t *testing.T, proxyAddr, target, path string, regular []hpack.HeaderField) []rawFrame {
	t.Helper()
	raw, err := connectTunnelDialer(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	conn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
		NextProtos:         []string{"h2"},
		ServerName:         "localhost",
	})
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	fr := http2.NewFramer(conn, conn)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 1 << 20
	if err := fr.WriteSettings(); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	fields := []hpack.HeaderField{
		hf(":method", "POST"), hf(":scheme", "https"), hf(":authority", target), hf(":path", path),
	}
	fields = append(fields, regular...)
	if err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: hpackBlock(fields...), EndHeaders: true}); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if err := fr.WriteData(1, true, []byte{0, 0, 0, 0, 3, 'r', 'e', 'q'}); err != nil {
		t.Fatalf("write data: %v", err)
	}

	var out []rawFrame
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read frame (observed so far %v): %v", out, err)
		}
		switch ff := f.(type) {
		case *http2.SettingsFrame:
			if !ff.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !ff.IsAck() {
				_ = fr.WritePing(true, ff.Data)
			}
		case *http2.GoAwayFrame:
			t.Fatalf("GOAWAY %v (observed so far %v)", ff.ErrCode, out)
		case *http2.MetaHeadersFrame:
			if ff.StreamID != 1 {
				continue
			}
			out = append(out, rawFrame{kind: "headers", fields: slices.Clone(ff.Fields), endStream: ff.StreamEnded()})
			if ff.StreamEnded() {
				return out
			}
		case *http2.DataFrame:
			if ff.StreamID != 1 {
				continue
			}
			out = append(out, rawFrame{kind: "data", endStream: ff.StreamEnded()})
			if ff.StreamEnded() {
				return out
			}
		case *http2.RSTStreamFrame:
			if ff.StreamID != 1 {
				continue
			}
			return append(out, rawFrame{kind: "rst", rstCode: ff.ErrCode})
		}
	}
}

func regularFields(fields []hpack.HeaderField) []hpack.HeaderField {
	var out []hpack.HeaderField
	for _, f := range fields {
		if !strings.HasPrefix(f.Name, ":") {
			out = append(out, hpack.HeaderField{Name: f.Name, Value: f.Value})
		}
	}
	return out
}

func pseudoValue(fields []hpack.HeaderField, name string) string {
	for _, f := range fields {
		if f.Name == name {
			return f.Value
		}
	}
	return ""
}

func startFidelityHarness(t *testing.T) (proxyAddr string, store *testStore, origin *fidelityOrigin) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ca, issuer := makeCA(t)
	origin = startFidelityOrigin(t, issuer)
	proxyAddr, store = startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{})
	return proxyAddr, store, origin
}

// TestGRPCFidelity_UpstreamStatusReachesClientAndRecord (T1, T2): an
// upstream :status 503 on a gRPC response reaches the client as 503 and
// is recorded as the Receive Start flow's StatusCode.
func TestGRPCFidelity_UpstreamStatusReachesClientAndRecord(t *testing.T) {
	proxyAddr, store, origin := startFidelityHarness(t)

	frames := rawGRPCCall(t, proxyAddr, origin.addr(), "/fid.Svc/Status503", []hpack.HeaderField{
		hf("content-type", "application/grpc"), hf("te", "trailers"),
	})
	if len(frames) == 0 || frames[0].kind != "headers" {
		t.Fatalf("client frames = %v, want response HEADERS first", frames)
	}
	if got := pseudoValue(frames[0].fields, ":status"); got != "503" {
		t.Errorf("client :status = %q, want 503 (frames %v)", got, frames)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	starts := waitForGRPCFlows(t, store, st.ID, "start", "receive", 1, 5*time.Second)
	if got := starts[0].StatusCode; got != 503 {
		t.Errorf("recorded Receive Start StatusCode = %d, want 503", got)
	}
}

// TestGRPCFidelity_RequestHeaderLayoutReachesUpstream (T4, T9): the
// client's request header list — control headers after metadata, raw
// grpc-timeout / grpc-accept-encoding values, no te — reaches the origin
// byte-identical.
func TestGRPCFidelity_RequestHeaderLayoutReachesUpstream(t *testing.T) {
	proxyAddr, store, origin := startFidelityHarness(t)

	want := []hpack.HeaderField{
		hf("user-agent", "grpc-go/1.70"),
		hf("content-type", "application/grpc"),
		hf("grpc-accept-encoding", "identity, gzip"),
		hf("grpc-timeout", "1000m"),
		hf("x-md", "v"),
	}
	frames := rawGRPCCall(t, proxyAddr, origin.addr(), "/fid.Svc/Echo", want)
	if got := regularFields(origin.waitRequest(t, 5*time.Second)); !slices.Equal(got, want) {
		t.Errorf("origin request headers:\n got  %v\n want %v", got, want)
	}
	if n := len(frames); n == 0 || !frames[n-1].endStream {
		t.Errorf("client frames = %v, want the response to end with END_STREAM", frames)
	}
	st := firstGRPCStream(t, store, 5*time.Second)
	waitForStreamState(t, store, st.ID, "complete", 5*time.Second)
}

// TestGRPCFidelity_TrailersOnlyRelayedAsSingleHeaders (T10): a
// trailers-only response reaches the client as exactly one HEADERS frame
// with END_STREAM and the identical header list; the flow still records a
// Receive Start and an End with grpc-status 14.
func TestGRPCFidelity_TrailersOnlyRelayedAsSingleHeaders(t *testing.T) {
	proxyAddr, store, origin := startFidelityHarness(t)

	frames := rawGRPCCall(t, proxyAddr, origin.addr(), "/fid.Svc/TrailersOnly", []hpack.HeaderField{
		hf("content-type", "application/grpc"), hf("te", "trailers"),
	})
	if len(frames) != 1 || frames[0].kind != "headers" || !frames[0].endStream {
		t.Fatalf("client frames = %v, want exactly one HEADERS frame with END_STREAM", frames)
	}
	if got := pseudoValue(frames[0].fields, ":status"); got != "200" {
		t.Errorf("client :status = %q, want 200", got)
	}
	if got := regularFields(frames[0].fields); !slices.Equal(got, fidelityTrailersOnlyFields) {
		t.Errorf("client headers:\n got  %v\n want %v", got, fidelityTrailersOnlyFields)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	waitForGRPCFlows(t, store, st.ID, "start", "receive", 1, 5*time.Second)
	ends := waitForGRPCFlows(t, store, st.ID, "end", "receive", 1, 5*time.Second)
	if got := ends[0].Metadata["grpc_status"]; got != "14" {
		t.Errorf("recorded End grpc_status = %q, want 14", got)
	}
	waitForStreamState(t, store, st.ID, "complete", 5*time.Second)
}

// TestGRPCFidelity_EndStreamResponseWithoutGRPCStatus (T12): a bare
// HEADERS(:status 503, server: lb, END_STREAM) reaches the client as
// exactly that frame — no fabricated content-type or grpc-status — and the
// flow records the placeholder End with the missing-status anomaly.
func TestGRPCFidelity_EndStreamResponseWithoutGRPCStatus(t *testing.T) {
	proxyAddr, store, origin := startFidelityHarness(t)

	frames := rawGRPCCall(t, proxyAddr, origin.addr(), "/fid.Svc/Bare503", []hpack.HeaderField{
		hf("content-type", "application/grpc"), hf("te", "trailers"),
	})
	if len(frames) != 1 || frames[0].kind != "headers" || !frames[0].endStream {
		t.Fatalf("client frames = %v, want exactly one HEADERS frame with END_STREAM", frames)
	}
	if got := pseudoValue(frames[0].fields, ":status"); got != "503" {
		t.Errorf("client :status = %q, want 503", got)
	}
	if got, want := regularFields(frames[0].fields), []hpack.HeaderField{hf("server", "lb")}; !slices.Equal(got, want) {
		t.Errorf("client headers:\n got  %v\n want %v", got, want)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	starts := waitForGRPCFlows(t, store, st.ID, "start", "receive", 1, 5*time.Second)
	if got := starts[0].StatusCode; got != 503 {
		t.Errorf("recorded Receive Start StatusCode = %d, want 503", got)
	}
	ends := waitForGRPCFlows(t, store, st.ID, "end", "receive", 1, 5*time.Second)
	if _, ok := ends[0].Metadata["grpc_anomaly_missing_status"]; !ok {
		t.Errorf("recorded End Metadata = %v, want grpc_anomaly_missing_status", ends[0].Metadata)
	}
	waitForStreamState(t, store, st.ID, "complete", 5*time.Second)
}

// TestGRPCFidelity_DroppedEndAfterHeldStartResetsClient: an intercept drop
// of the Receive End of a bare HEADERS(:status 503, END_STREAM) response,
// after its Start was released, leaves the deferred response HEADERS
// unsent. The client must not hang: session teardown resets the stream,
// and no response HEADERS reaches it (documented in sendStart).
func TestGRPCFidelity_DroppedEndAfterHeldStartResetsClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ca, issuer := makeCA(t)
	origin := startFidelityOrigin(t, issuer)

	engine := grpcrules.NewInterceptEngine()
	engine.SetRules([]grpcrules.InterceptRule{{
		ID:        "hold-receive",
		Enabled:   true,
		Direction: grpcrules.DirectionReceive,
	}})
	queue := common.NewHoldQueue()
	proxyAddr, _ := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{intercept: engine, queue: queue})

	// Release the held Receive Start unchanged; drop the held Receive End.
	go func() {
		for ctx.Err() == nil {
			for _, e := range queue.List() {
				switch e.Envelope.Message.(type) {
				case *envelope.GRPCStartMessage:
					_ = queue.Release(e.ID, &common.HoldAction{Type: common.ActionRelease})
				case *envelope.GRPCEndMessage:
					_ = queue.Release(e.ID, &common.HoldAction{Type: common.ActionDrop})
					return
				}
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()

	start := time.Now()
	frames := rawGRPCCall(t, proxyAddr, origin.addr(), "/fid.Svc/Bare503", []hpack.HeaderField{
		hf("content-type", "application/grpc"), hf("te", "trailers"),
	})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("client stream ended after %v, want a prompt reset", elapsed)
	}
	if len(frames) != 1 || frames[0].kind != "rst" {
		t.Errorf("client frames = %v, want exactly one RST_STREAM (the held HEADERS is discarded)", frames)
	}
}
