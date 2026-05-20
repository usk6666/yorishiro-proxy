//go:build e2e && !e2e_smoke

// Package proxybuild_test exhaustive tier — USK-934 H1 grpc-web
// auto-classify. Validates the Issue repro: a tcp_forwards listener
// configured with Protocol="http" carrying gRPC-Web traffic on HTTP/1.1
// must record Stream.Protocol="grpc-web" (not "http"), so the flow is
// queryable via filter.protocol=grpc-web.
//
// Pre-USK-934 behaviour: the H1 path never inspected content-type to
// dispatch to grpcweb.Wrap, so all HTTP/1.x grpc-web traffic was recorded
// as protocol=http (wire bytes preserved, classification wrong).
//
// USK-934 fix: DispatchH1Channel + WrapH1UpstreamForDispatch in the H1
// per-exchange dispatcher (sibling of H2's DispatchH2Stream pattern).
package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// stdBase64Encode wraps the stdlib base64 encoder so the per-helper
// callsites stay readable.
func stdBase64Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// h1GRPCWebEchoUpstream starts a minimal HTTP/1.1 server that responds to
// any POST with a gRPC-Web LPM data frame echoing a fixed message + a
// trailer LPM frame (grpc-status: 0). Returns (addr, shutdown).
//
// We don't use net/http here — the response must contain a verbatim
// trailer LPM frame inside the response body (per gRPC-Web RFC). The
// minimal handler is a hand-rolled accept loop that reads the request
// header section, drains the body, then writes a static response.
func h1GRPCWebEchoUpstream(t *testing.T, contentType string) (addr string, shutdown func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleH1GRPCWebConn(c, contentType, stop)
		}
	}()
	return ln.Addr().String(), func() {
		close(stop)
		_ = ln.Close()
	}
}

func handleH1GRPCWebConn(c net.Conn, contentType string, _ <-chan struct{}) {
	defer c.Close()
	// Allow keep-alive: loop reading requests until the conn closes.
	br := bufio.NewReader(c)
	for {
		// Read headers (until blank line).
		reqHdr, err := readH1Headers(br)
		if err != nil {
			return
		}
		// Drain request body if Content-Length specified.
		cl, _ := strconv.Atoi(strings.TrimSpace(reqHdr["content-length"]))
		if cl > 0 {
			if _, err := io.CopyN(io.Discard, br, int64(cl)); err != nil {
				return
			}
		}

		// Build the response body: one data LPM frame ("hello!!" payload)
		// + one trailer LPM frame.
		var bodyBuf bytes.Buffer
		payload := []byte("hello!!")
		// Data LPM: flags=0, length=7, payload=hello!!
		bodyBuf.WriteByte(0x00)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
		bodyBuf.Write(lenBuf[:])
		bodyBuf.Write(payload)
		// Trailer LPM: flags=0x80, payload="grpc-status: 0\r\n"
		trailerText := []byte("grpc-status: 0\r\n")
		bodyBuf.WriteByte(0x80)
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(trailerText)))
		bodyBuf.Write(lenBuf[:])
		bodyBuf.Write(trailerText)
		body := bodyBuf.Bytes()

		// Write a minimal HTTP/1.1 response.
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\n")
		fmt.Fprintf(c, "Content-Type: %s\r\n", contentType)
		fmt.Fprintf(c, "Content-Length: %d\r\n", len(body))
		fmt.Fprintf(c, "Connection: keep-alive\r\n")
		fmt.Fprintf(c, "\r\n")
		if _, err := c.Write(body); err != nil {
			return
		}
		// Loop for keep-alive — but the test sends a single request, so
		// the conn usually closes on the next ReadString failure.
	}
}

// readH1Headers reads HTTP/1.x request lines + headers until the blank
// terminator and returns a normalised lowercase header map (first value
// per name). The request line is consumed but not parsed beyond the
// blank-line gate.
func readH1Headers(br *bufio.Reader) (map[string]string, error) {
	// Request line.
	if _, err := br.ReadString('\n'); err != nil {
		return nil, err
	}
	hdr := make(map[string]string)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return hdr, nil
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(line[:i]))
		value := strings.TrimSpace(line[i+1:])
		if _, ok := hdr[name]; !ok {
			hdr[name] = value
		}
	}
}

// startH1ForwardListener spins up the proxy with one TCP forward entry
// targeting upstreamAddr with Protocol="http" (h1 path). Returns the
// bound forward address.
func startH1ForwardListener(t *testing.T, ctx context.Context, upstreamAddr string) (
	mgr *proxybuild.Manager, fwdAddr string, store *flowStoreCapture,
) {
	t.Helper()
	store = &flowStoreCapture{}
	logger := testutil.DiscardLogger()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	factory := func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
		return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
			Logger:       logger,
			ListenerName: name,
			ListenAddr:   addr,
			FlowStore:    store,
			BuildConfig:  buildCfg,
		})
	}
	m, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:       logger,
		StackFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.StopAll(context.Background()) })

	if err := m.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := m.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: upstreamAddr, Protocol: "http"},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards(http): %v", err)
	}
	addrs := m.TCPForwardAddrs()
	fwdAddr = addrs["0"]
	if fwdAddr == "" {
		t.Fatalf("TCPForwardAddrs missing port 0: %v", addrs)
	}
	return m, fwdAddr, store
}

// sendH1GRPCWebRequest dials the proxy's H1 forward listener, writes a
// minimal POST with the supplied content-type + LPM body, and returns
// the raw response bytes.
func sendH1GRPCWebRequest(t *testing.T, proxyAddr, contentType string, lpmBody []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var req bytes.Buffer
	fmt.Fprintf(&req, "POST /hello.HelloService/SayHello HTTP/1.1\r\n")
	fmt.Fprintf(&req, "Host: %s\r\n", proxyAddr)
	fmt.Fprintf(&req, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&req, "Content-Length: %d\r\n", len(lpmBody))
	fmt.Fprintf(&req, "Connection: close\r\n")
	fmt.Fprintf(&req, "\r\n")
	req.Write(lpmBody)

	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatalf("write request: %v", err)
	}
	respBytes, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return respBytes
}

// buildLPMBody returns the LPM-framed body for a request: one data
// frame with the supplied payload.
func buildLPMBody(payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(0x00)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	buf.Write(lenBuf[:])
	buf.Write(payload)
	return buf.Bytes()
}

// TestProxybuild_TCPForward_H1_GRPCWeb_Binary_AutoClassify is the
// authoritative Issue repro: a tcp_forwards entry with Protocol="http"
// carrying application/grpc-web+proto LPM traffic over HTTP/1.1 must
// produce a Stream with Protocol="grpc-web". Pre-USK-934 this assertion
// failed (Protocol stayed at "http").
func TestProxybuild_TCPForward_H1_GRPCWeb_Binary_AutoClassify(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, upStop := h1GRPCWebEchoUpstream(t, "application/grpc-web+proto")
	defer upStop()

	mgr, fwdAddr, store := startH1ForwardListener(t, ctx, upAddr)
	defer mgr.StopAll(context.Background())

	reqBody := buildLPMBody([]byte("ping"))
	respBytes := sendH1GRPCWebRequest(t, fwdAddr, "application/grpc-web+proto", reqBody)
	if !bytes.Contains(respBytes, []byte("HTTP/1.1 200")) {
		t.Fatalf("expected HTTP/1.1 200 in response, got: %q", string(respBytes))
	}
	// Verify the body contains the upstream's data LPM payload "hello!!".
	if !bytes.Contains(respBytes, []byte("hello!!")) {
		t.Errorf("response missing upstream LPM payload; got %q", string(respBytes))
	}

	// Wait for asynchronous Stream/Flow recording to complete.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hasStreamWithProtocol(store, "grpc-web") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	streams := store.Streams()
	if len(streams) < 1 {
		t.Fatalf("expected at least 1 stream recorded, got %d", len(streams))
	}

	// The H1 grpc-web dispatch path produces a Stream initially tagged
	// http; record_step.maybeRetagProtocol then UpdateStream-rewrites the
	// Protocol to "grpc-web" when the first grpcweb envelope hits Record.
	// Our flowStoreCapture applies StreamUpdate.Protocol to the in-memory
	// row, so the final state should be Protocol="grpc-web".
	checkStreamProtocolEventually(t, store, "grpc-web")
}

// TestProxybuild_TCPForward_H1_GRPCWeb_Text_AutoClassify exercises the
// base64-encoded text variant (application/grpc-web-text). Same Issue
// scope — the dispatcher must wrap regardless of binary vs text.
func TestProxybuild_TCPForward_H1_GRPCWeb_Text_AutoClassify(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, upStop := h1GRPCWebEchoUpstreamBase64(t, "application/grpc-web-text+proto")
	defer upStop()

	mgr, fwdAddr, store := startH1ForwardListener(t, ctx, upAddr)
	defer mgr.StopAll(context.Background())

	reqBody := buildBase64LPMBody([]byte("ping"))
	respBytes := sendH1GRPCWebRequest(t, fwdAddr, "application/grpc-web-text+proto", reqBody)
	if !bytes.Contains(respBytes, []byte("HTTP/1.1 200")) {
		t.Fatalf("expected HTTP/1.1 200 in response, got: %q", string(respBytes))
	}

	checkStreamProtocolEventually(t, store, "grpc-web")
}

// TestProxybuild_TCPForward_H1_JSONPOST_StaysHTTP is the negative
// control: a non-grpc-web POST (application/json) flowing through the
// same H1 forward path must NOT be re-tagged to grpc-web. The
// dispatcher's content-type discriminator is the only gate.
func TestProxybuild_TCPForward_H1_JSONPOST_StaysHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Reuse the gRPC-Web echo upstream but advertise application/json
	// on the response. The handler still writes its (now-meaningless)
	// LPM bytes, but the proxy must not classify it as grpc-web because
	// the REQUEST content-type drives the dispatcher.
	upAddr, upStop := h1GRPCWebEchoUpstream(t, "application/json")
	defer upStop()

	mgr, fwdAddr, store := startH1ForwardListener(t, ctx, upAddr)
	defer mgr.StopAll(context.Background())

	respBytes := sendH1GRPCWebRequest(t, fwdAddr, "application/json", []byte(`{"hello":"world"}`))
	if !bytes.Contains(respBytes, []byte("HTTP/1.1 200")) {
		t.Fatalf("expected HTTP/1.1 200 in response, got: %q", string(respBytes))
	}

	// Wait for recording to settle.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(store.Streams()) >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	streams := store.Streams()
	if len(streams) < 1 {
		t.Fatalf("expected at least 1 stream recorded, got %d", len(streams))
	}
	// None of the streams should be re-tagged to grpc-web.
	for _, st := range streams {
		// Take updates into account (the maybeRetagProtocol path).
		final := finalStreamProtocol(store, st.ID)
		if final == "grpc-web" {
			t.Errorf("stream %q was re-tagged to grpc-web for a JSON POST (negative-control violation): %+v",
				st.ID, st)
		}
	}
}

// buildBase64LPMBody returns the base64-encoded LPM body for a request
// payload (text variant).
func buildBase64LPMBody(payload []byte) []byte {
	bin := buildLPMBody(payload)
	// std base64 (no URL-safe variant per RFC).
	return []byte(stdBase64Encode(bin))
}

// h1GRPCWebEchoUpstreamBase64 is identical to h1GRPCWebEchoUpstream
// except the response body is base64-encoded (text variant). The
// content-type advertises the text format.
func h1GRPCWebEchoUpstreamBase64(t *testing.T, contentType string) (addr string, shutdown func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleH1GRPCWebConnBase64(c, contentType, stop)
		}
	}()
	return ln.Addr().String(), func() {
		close(stop)
		_ = ln.Close()
	}
}

func handleH1GRPCWebConnBase64(c net.Conn, contentType string, _ <-chan struct{}) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		hdr, err := readH1Headers(br)
		if err != nil {
			return
		}
		cl, _ := strconv.Atoi(strings.TrimSpace(hdr["content-length"]))
		if cl > 0 {
			if _, err := io.CopyN(io.Discard, br, int64(cl)); err != nil {
				return
			}
		}
		payload := []byte("hello!!")
		var bin bytes.Buffer
		bin.WriteByte(0x00)
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(payload)))
		bin.Write(lenBuf[:])
		bin.Write(payload)
		trailerText := []byte("grpc-status: 0\r\n")
		bin.WriteByte(0x80)
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(trailerText)))
		bin.Write(lenBuf[:])
		bin.Write(trailerText)
		body := []byte(stdBase64Encode(bin.Bytes()))

		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\n")
		fmt.Fprintf(c, "Content-Type: %s\r\n", contentType)
		fmt.Fprintf(c, "Content-Length: %d\r\n", len(body))
		fmt.Fprintf(c, "Connection: keep-alive\r\n")
		fmt.Fprintf(c, "\r\n")
		if _, err := c.Write(body); err != nil {
			return
		}
	}
}

// hasStreamWithProtocol returns true when any recorded Stream's
// effective Protocol (after StreamUpdate replay) matches want.
func hasStreamWithProtocol(store *flowStoreCapture, want string) bool {
	for _, st := range store.Streams() {
		if finalStreamProtocol(store, st.ID) == want {
			return true
		}
	}
	return false
}

// finalStreamProtocol returns the effective Protocol for a Stream after
// folding all recorded StreamUpdates over the initial SaveStream value.
// Required because flowStoreCapture's UpdateStream stores updates in a
// side map rather than mutating the original Stream row.
func finalStreamProtocol(store *flowStoreCapture, streamID string) string {
	var initial string
	for _, st := range store.Streams() {
		if st.ID == streamID {
			initial = st.Protocol
			break
		}
	}
	final := initial
	for _, upd := range store.StreamUpdates(streamID) {
		if upd.Protocol != "" {
			final = upd.Protocol
		}
	}
	return final
}

// checkStreamProtocolEventually polls store for up to 3s until at least
// one Stream is observed with effective Protocol == want. Fails the
// test if the deadline elapses first.
func checkStreamProtocolEventually(t *testing.T, store *flowStoreCapture, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hasStreamWithProtocol(store, want) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Build a diagnostic dump.
	var lines []string
	for _, st := range store.Streams() {
		final := finalStreamProtocol(store, st.ID)
		lines = append(lines, fmt.Sprintf("stream %q initial=%q final=%q state=%q",
			st.ID, st.Protocol, final, st.State))
	}
	t.Fatalf("no stream observed with Protocol=%q after 3s; recorded streams:\n%s",
		want, strings.Join(lines, "\n"))
}
