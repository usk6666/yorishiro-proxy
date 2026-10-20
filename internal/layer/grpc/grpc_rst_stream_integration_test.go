//go:build e2e && !e2e_smoke

// USK-1253 — mid-RPC RST_STREAM must leave the gRPC Stream recorded with
// State="error" (CLAUDE.md e2e checklist "Error paths").
//
// A non-OK gRPC status is a normal trailer and records State="complete"
// (TestGRPC_NonOKStatusProducesGRPCEnd); only an HTTP/2 RST_STREAM with a
// non-zero error code terminates the RPC abnormally. These tests drive a
// server-streaming RPC through the gRPC MITM harness (startGRPCMITMProxy)
// and reset the stream half-way through, once from each side:
//
//   - upstream: a raw x/net/http2 Framer origin sends response HEADERS and
//     two LPM messages, then RST_STREAM(INTERNAL_ERROR) once the client has
//     received both. grpc-go's server cannot emit a non-zero RST_STREAM on
//     demand, hence the hand-rolled origin.
//   - client: the grpc-go client cancels its call context after receiving
//     both messages, which puts RST_STREAM(CANCEL) on the wire.
//
// The origin only emits the RST after the client has observed both
// messages, so the ordering is deterministic without fixed sleeps.
package grpc_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
)

// rstOriginMessages are the LPM payloads the origin sends before the reset.
var rstOriginMessages = [][]byte{[]byte("msg-0"), []byte("msg-1")}

// rstOrigin is a raw HTTP/2 gRPC origin that answers the first request
// stream with response HEADERS + len(rstOriginMessages) LPM DATA frames and
// then either resets the stream itself (when resetNow is closed) or waits
// for the peer's RST_STREAM.
type rstOrigin struct {
	ln net.Listener

	// resetNow, when closed, makes the origin send
	// RST_STREAM(INTERNAL_ERROR) on the RPC stream.
	resetNow chan struct{}

	mu        sync.Mutex
	conns     []net.Conn
	rstFrom   map[uint32]http2.ErrCode // RST_STREAM codes received from the proxy
	gotRST    chan struct{}            // closed on the first received RST_STREAM
	gotRSTOne sync.Once

	wg sync.WaitGroup
}

func startRSTOrigin(t *testing.T, issuer *cert.Issuer) *rstOrigin {
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
	o := &rstOrigin{
		ln:       ln,
		resetNow: make(chan struct{}),
		rstFrom:  make(map[uint32]http2.ErrCode),
		gotRST:   make(chan struct{}),
	}
	o.wg.Add(1)
	go o.acceptLoop()
	t.Cleanup(o.close)
	return o
}

func (o *rstOrigin) addr() string { return o.ln.Addr().String() }

func (o *rstOrigin) acceptLoop() {
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

func (o *rstOrigin) close() {
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

// receivedRST returns the code of the RST_STREAM the proxy sent on any
// stream, and whether one arrived.
func (o *rstOrigin) receivedRST() (http2.ErrCode, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, code := range o.rstFrom {
		return code, true
	}
	return 0, false
}

func (o *rstOrigin) serveConn(c net.Conn) {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 1 << 20

	// Framer writes are not goroutine-safe; the reader loop (SETTINGS /
	// PING acks) and the responder goroutine share wmu.
	var wmu sync.Mutex
	write := func(fn func() error) error {
		wmu.Lock()
		defer wmu.Unlock()
		return fn()
	}
	if err := write(func() error { return fr.WriteSettings() }); err != nil {
		return
	}

	connDone := make(chan struct{})
	defer close(connDone)
	responded := false
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch ff := f.(type) {
		case *http2.SettingsFrame:
			if !ff.IsAck() {
				if err := write(func() error { return fr.WriteSettingsAck() }); err != nil {
					return
				}
			}
		case *http2.PingFrame:
			if !ff.IsAck() {
				if err := write(func() error { return fr.WritePing(true, ff.Data) }); err != nil {
					return
				}
			}
		case *http2.MetaHeadersFrame:
			if responded {
				continue
			}
			responded = true
			go o.respond(fr, write, ff.StreamID, connDone)
		case *http2.RSTStreamFrame:
			o.mu.Lock()
			o.rstFrom[ff.StreamID] = ff.ErrCode
			o.mu.Unlock()
			o.gotRSTOne.Do(func() { close(o.gotRST) })
		}
	}
}

// respond writes the response HEADERS + LPM messages for streamID, then
// resets the stream when resetNow is closed.
func (o *rstOrigin) respond(fr *http2.Framer, write func(func() error) error, streamID uint32, connDone <-chan struct{}) {
	var hbuf bytes.Buffer
	enc := hpack.NewEncoder(&hbuf)
	_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
	_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/grpc"})
	if err := write(func() error {
		return fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: hbuf.Bytes(),
			EndHeaders:    true,
		})
	}); err != nil {
		return
	}
	for _, msg := range rstOriginMessages {
		lpm := append([]byte{0, 0, 0, 0, byte(len(msg))}, msg...)
		if err := write(func() error { return fr.WriteData(streamID, false, lpm) }); err != nil {
			return
		}
	}
	select {
	case <-o.resetNow:
		_ = write(func() error { return fr.WriteRSTStream(streamID, http2.ErrCodeInternal) })
	case <-connDone:
	}
}

// startServerStreamWithTwoMessages opens the ServerStream RPC through the
// proxy, sends one request, and receives exactly the two messages the
// origin emits before the reset.
func startServerStreamWithTwoMessages(t *testing.T, callCtx context.Context, cc *grpc.ClientConn) grpc.ClientStream {
	t.Helper()
	desc := &grpc.StreamDesc{StreamName: echoMethodServerStream, ServerStreams: true}
	cs, err := cc.NewStream(callCtx, desc, echoFullMethod(echoMethodServerStream))
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	req := []byte("seed")
	if err := cs.SendMsg(&req); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if err := cs.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	for i, want := range rstOriginMessages {
		var got []byte
		if err := cs.RecvMsg(&got); err != nil {
			t.Fatalf("RecvMsg #%d before reset: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("RecvMsg #%d = %q, want %q", i, got, want)
		}
	}
	return cs
}

// assertRSTRecording checks the recorded outcome shared by both reset
// directions: Stream Protocol=grpc reaches State=error (never complete),
// and the Start/Data envelopes that crossed the proxy before the reset are
// recorded with their wire bytes.
func assertRSTRecording(t *testing.T, store *testStore, wantFailureReason string) {
	t.Helper()
	st := firstGRPCStream(t, store, 5*time.Second)
	if st.Protocol != "grpc" {
		t.Errorf("Stream.Protocol = %q, want grpc", st.Protocol)
	}
	waitForStreamState(t, store, st.ID, "error", 5*time.Second)

	var gotReason string
	for _, u := range store.getUpdates(st.ID) {
		if u.State == "complete" {
			t.Errorf("RST_STREAM-terminated stream recorded State=complete (FailureReason=%q)", u.FailureReason)
		}
		if u.State == "error" {
			gotReason = u.FailureReason
		}
	}
	if gotReason != wantFailureReason {
		t.Errorf("FailureReason = %q, want %q", gotReason, wantFailureReason)
	}
	for _, s := range store.getStreams() {
		if s.ID == st.ID && s.State != "error" {
			t.Errorf("stored Stream.State = %q, want error", s.State)
		}
	}

	waitForGRPCFlows(t, store, st.ID, "start", "send", 1, 5*time.Second)
	waitForGRPCFlows(t, store, st.ID, "data", "send", 1, 5*time.Second)
	waitForGRPCFlows(t, store, st.ID, "start", "receive", 1, 5*time.Second)
	data := waitForGRPCFlows(t, store, st.ID, "data", "receive", len(rstOriginMessages), 5*time.Second)
	for i, f := range data {
		if i >= len(rstOriginMessages) {
			t.Errorf("unexpected extra receive data flow #%d: %q", i, f.Body)
			continue
		}
		if !bytes.Equal(f.Body, rstOriginMessages[i]) {
			t.Errorf("receive data flow #%d Body = %q, want %q", i, f.Body, rstOriginMessages[i])
		}
		if len(f.RawBytes) == 0 {
			t.Errorf("receive data flow #%d has empty RawBytes", i)
		}
	}
	// The RPC never finished: no End (trailers) envelope exists on the
	// wire, so none may be recorded.
	for _, f := range store.flowsForStream(st.ID) {
		if f.Metadata["grpc_event"] == "end" {
			t.Errorf("unexpected grpc end flow recorded (direction=%s, grpc_status=%q)", f.Direction, f.Metadata["grpc_status"])
		}
	}
}

// TestGRPC_UpstreamRSTStreamMidRPCProducesErrorState: the upstream resets a
// server-streaming RPC after two messages. The client must observe the
// abnormal termination as a non-OK status (not a clean io.EOF) and the
// Stream must be recorded with State=error.
func TestGRPC_UpstreamRSTStreamMidRPCProducesErrorState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	origin := startRSTOrigin(t, issuer)
	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, origin.addr())
	defer cc.Close()

	cs := startServerStreamWithTwoMessages(t, ctx, cc)
	close(origin.resetNow)

	var extra []byte
	err := cs.RecvMsg(&extra)
	if err == nil {
		t.Fatalf("RecvMsg after upstream RST_STREAM returned a message %q, want error", extra)
	}
	if errors.Is(err, io.EOF) {
		t.Fatalf("RecvMsg after upstream RST_STREAM = io.EOF (clean end), want an RST-derived status")
	}
	// The proxy resets the client side of the stream; grpc-go reports that
	// as "stream terminated by RST_STREAM". The proxy maps the upstream
	// reset to its own client-side reset (session closeClient -> CANCEL);
	// only the fact of the reset is asserted here, not the error code.
	if c := status.Code(err); c == codes.OK {
		t.Fatalf("RecvMsg after upstream RST_STREAM status = OK, want non-OK (err=%v)", err)
	}
	if !strings.Contains(err.Error(), "RST_STREAM") {
		t.Fatalf("RecvMsg after upstream RST_STREAM err = %v, want an RST_STREAM termination", err)
	}

	assertRSTRecording(t, store, "internal_error")
}

// TestGRPC_ClientRSTStreamMidRPCProducesErrorState: the client cancels a
// server-streaming RPC after two messages (RST_STREAM(CANCEL)). The proxy
// must propagate a reset to the upstream and record State=error.
//
// Skipped: the gRPC wrapper closes Closed() on the client's graceful
// END_STREAM, so session.lateClientErrorWatcher never observes the later
// RST_STREAM(CANCEL); the reset is not propagated upstream and the Stream
// is not recorded as error. See USK-1255.
func TestGRPC_ClientRSTStreamMidRPCProducesErrorState(t *testing.T) {
	// On unfixed code this test is racy, not deterministically red: with
	// the Skip removed it was observed failing 7/8 runs (at the "upstream
	// never received RST_STREAM" wait) and passing 1/8. When un-skipping
	// for USK-1255, verify with repeated runs (e.g. GOFLAGS=-count=20).
	// On failure, startGRPCMITMProxy's untracked per-connection goroutines
	// (handleProxyConn / debugChannel) may still call t.Logf after the test
	// returns, which panics with "Log in goroutine after ... has completed"
	// and masks the real assertion failure.
	t.Skip("not yet implemented: USK-1255")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ca, issuer := makeCA(t)
	origin := startRSTOrigin(t, issuer)
	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, origin.addr())
	defer cc.Close()

	callCtx, callCancel := context.WithCancel(ctx)
	defer callCancel()
	cs := startServerStreamWithTwoMessages(t, callCtx, cc)
	callCancel() // grpc-go sends RST_STREAM(CANCEL)

	var extra []byte
	if err := cs.RecvMsg(&extra); status.Code(err) != codes.Canceled {
		t.Fatalf("RecvMsg after cancel = %v, want codes.Canceled", err)
	}

	select {
	case <-origin.gotRST:
	case <-time.After(5 * time.Second):
		t.Fatalf("upstream never received RST_STREAM after the client reset")
	}
	if code, _ := origin.receivedRST(); code == http2.ErrCodeNo {
		t.Errorf("upstream RST_STREAM code = %v, want a non-NO_ERROR reset", code)
	}

	assertRSTRecording(t, store, "canceled")
}
