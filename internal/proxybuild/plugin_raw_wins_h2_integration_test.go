//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/grpc/metadata"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// USK-1237: RFC-001 §9.3 D4 "Raw wins" policy for the HTTP/2 family. A
// plugin msg["raw"] on an envelope whose destination Layer writes a
// header block (h2 HTTPMessage, gRPC Start/End, gRPC-Web Start) cannot be
// written verbatim — the bytes are unframed HPACK against the source
// connection's dynamic table. The write is refused before RecordStep so
// the recorded modified variant matches the wire: RawOnly → Unchanged (no
// modified variant), Both → MessageOnly (modified variant = encoder output
// of the mutated Message). DATA-payload envelopes (gRPC Data) keep
// honouring msg["raw"].
//
// Every test drives a real Starlark plugin through BuildLiveStack via a
// tcp_forwards entry and observes the far side with a capturing peer.

// modifiedFlows returns every recorded flow tagged variant=modified in
// the given direction ("" matches any direction).
func modifiedFlows(store *flowStoreCapture, direction string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range store.Flows() {
		if f == nil || f.Metadata["variant"] != "modified" {
			continue
		}
		if direction != "" && f.Direction != direction {
			continue
		}
		out = append(out, f)
	}
	return out
}

// waitAnyFlow polls until the store holds a flow in direction, then lets
// the pipeline settle so a would-be modified variant has had time to land.
func waitAnyFlow(t *testing.T, store *flowStoreCapture, direction string) {
	t.Helper()
	end := time.Now().Add(5 * time.Second)
	for time.Now().Before(end) {
		for _, f := range store.Flows() {
			if f != nil && f.Direction == direction {
				time.Sleep(300 * time.Millisecond)
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no %s flow recorded; flows:%s", direction, describeFlows(store))
}

// h2Seen captures what the h2c upstream observed for one request.
type h2Seen struct {
	mu      sync.Mutex
	path    string
	headers gohttp.Header
	body    []byte
}

func (s *h2Seen) snapshot() (string, gohttp.Header, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path, s.headers.Clone(), append([]byte(nil), s.body...)
}

func startCapturingH2CUpstream(t *testing.T) (string, *h2Seen) {
	t.Helper()
	seen := &h2Seen{}
	addr, stop := h2cEchoUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		seen.mu.Lock()
		seen.path = r.URL.Path
		seen.headers = r.Header.Clone()
		seen.body = body
		seen.mu.Unlock()
		w.Header().Set("X-Upstream", "orig")
		_, _ = fmt.Fprintf(w, "upstream:%s", r.URL.Path)
	}))
	t.Cleanup(stop)
	return addr, seen
}

// doH2C sends one request through the h2c forward and returns status +
// body. Dialed conns are force-closed on cleanup.
func doH2C(t *testing.T, ctx context.Context, fwd, method, path string, body []byte) (int, string) {
	t.Helper()
	var conns []net.Conn
	var mu sync.Mutex
	cli := h2cForwardClient(fwd, &conns, &mu)
	t.Cleanup(func() {
		cli.CloseIdleConnections()
		mu.Lock()
		defer mu.Unlock()
		closeDialedConns(conns)
	})
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := gohttp.NewRequestWithContext(ctx, method, "http://"+fwd+path, rd)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("X-Marker", "orig")
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client Do: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// decodeH2Frames decodes an HTTP/2 frame sequence (HEADERS/CONTINUATION/
// DATA) into its header field list and concatenated DATA payload.
func decodeH2Frames(t *testing.T, raw []byte) ([]hpack.HeaderField, []byte) {
	t.Helper()
	fr := http2.NewFramer(nil, bytes.NewReader(raw))
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	var fields []hpack.HeaderField
	var body []byte
	sawHeaders := false
	for {
		f, err := fr.ReadFrame()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("modified variant RawBytes are not an HTTP/2 frame sequence: %v (raw=%q)", err, raw)
		}
		switch f := f.(type) {
		case *http2.MetaHeadersFrame:
			if !sawHeaders {
				fields = append(fields, f.Fields...)
				sawHeaders = true
			}
		case *http2.DataFrame:
			body = append(body, f.Data()...)
		}
	}
	if !sawHeaders {
		t.Fatalf("modified variant RawBytes carry no HEADERS frame (raw=%q)", raw)
	}
	return fields, body
}

func fieldValue(fields []hpack.HeaderField, name string) (string, bool) {
	for _, f := range fields {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

// TestPluginRawWins_H2_RequestRawOnly_Refused (Test Plan T1).
func TestPluginRawWins_H2_RequestRawOnly_Refused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, seen := startCapturingH2CUpstream(t)
	h, fwd := startRawWinsForwardDeps(t, ctx, `
def on_req(msg, ctx):
    msg["raw"] = b"PLUGIN-RAW-H2-REQUEST"
register_hook("http", "on_request", on_req)
`, upAddr, "http2", nil)

	status, body := doH2C(t, ctx, fwd, "GET", "/orig", nil)
	if status != 200 || body != "upstream:/orig" {
		t.Fatalf("client got %d %q, want 200 upstream:/orig", status, body)
	}
	path, hdr, _ := seen.snapshot()
	if path != "/orig" || hdr.Get("X-Marker") != "orig" {
		t.Errorf("upstream saw path=%q x-marker=%q, want the original request", path, hdr.Get("X-Marker"))
	}

	waitAnyFlow(t, h.store, "receive")
	if mods := modifiedFlows(h.store, "send"); len(mods) != 0 {
		t.Errorf("modified Send variant recorded (raw=%q) although the wire carried the original request; flows:%s",
			mods[0].RawBytes, describeFlows(h.store))
	}
	for _, f := range h.store.Flows() {
		if f.Direction == "send" && bytes.Equal(f.RawBytes, []byte("PLUGIN-RAW-H2-REQUEST")) {
			t.Errorf("a Send flow records the plugin bytes; record != wire")
		}
	}
}

// TestPluginRawWins_H2_RequestBoth_MessageOnly (Test Plan T2).
func TestPluginRawWins_H2_RequestBoth_MessageOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, seen := startCapturingH2CUpstream(t)
	h, fwd := startRawWinsForwardDeps(t, ctx, `
def on_req(msg, ctx):
    msg["headers"].append("x-plugin", "1")
    msg["raw"] = b"PLUGIN-RAW-H2-REQUEST"
register_hook("http", "on_request", on_req)
`, upAddr, "http2", nil)

	status, _ := doH2C(t, ctx, fwd, "POST", "/both", []byte("req-body"))
	if status != 200 {
		t.Fatalf("client status = %d, want 200", status)
	}
	path, hdr, upBody := seen.snapshot()
	if hdr.Get("X-Plugin") != "1" {
		t.Fatalf("upstream did not see x-plugin: 1 (Message edit lost): %v", hdr)
	}

	waitAnyFlow(t, h.store, "receive")
	mods := modifiedFlows(h.store, "send")
	if len(mods) != 1 {
		t.Fatalf("modified Send variants = %d, want 1; flows:%s", len(mods), describeFlows(h.store))
	}
	fields, body := decodeH2Frames(t, mods[0].RawBytes)
	if v, _ := fieldValue(fields, ":path"); v != path {
		t.Errorf("modified :path = %q, upstream saw %q", v, path)
	}
	if v, _ := fieldValue(fields, "x-plugin"); v != "1" {
		t.Errorf("modified x-plugin = %q, want 1", v)
	}
	for name, vals := range hdr {
		lname := strings.ToLower(name)
		v, ok := fieldValue(fields, lname)
		if !ok {
			t.Errorf("upstream-observed header %q missing from the modified variant", lname)
			continue
		}
		if v != vals[0] {
			t.Errorf("header %q: modified=%q upstream=%q", lname, v, vals[0])
		}
	}
	if !bytes.Equal(body, upBody) {
		t.Errorf("modified body = %q, upstream saw %q", body, upBody)
	}
}

// TestPluginRawWins_H2_ResponseRawOnly_Refused (Test Plan T3).
func TestPluginRawWins_H2_ResponseRawOnly_Refused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, _ := startCapturingH2CUpstream(t)
	h, fwd := startRawWinsForwardDeps(t, ctx, `
def on_resp(msg, ctx):
    msg["raw"] = b"PLUGIN-RAW-H2-RESPONSE"
register_hook("http", "on_response", on_resp)
`, upAddr, "http2", nil)

	status, body := doH2C(t, ctx, fwd, "GET", "/resp", nil)
	if status != 200 || body != "upstream:/resp" {
		t.Fatalf("client got %d %q, want the upstream's original response", status, body)
	}
	waitAnyFlow(t, h.store, "receive")
	if mods := modifiedFlows(h.store, "receive"); len(mods) != 0 {
		t.Errorf("modified Receive variant recorded (raw=%q) although the client got the original response; flows:%s",
			mods[0].RawBytes, describeFlows(h.store))
	}
}

// TestPluginRawWins_GRPC_StartRawOnly_Refused (Test Plan T4).
func TestPluginRawWins_GRPC_StartRawOnly_Refused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var mu sync.Mutex
	var seenMarker []string
	upAddr, upStop := startH2CGRPCUpstream(t, &echoServer{
		unary: func(ctx context.Context, req []byte) ([]byte, error) {
			md, _ := metadata.FromIncomingContext(ctx)
			mu.Lock()
			seenMarker = md.Get("x-marker")
			mu.Unlock()
			return append([]byte("echo:"), req...), nil
		},
	})
	defer upStop()

	h, fwd := startRawWinsForwardDeps(t, ctx, `
def on_start(msg, ctx):
    msg["raw"] = b"PLUGIN-RAW-GRPC-START"
register_hook("grpc", "on_start", on_start)
`, upAddr, "grpc", nil)

	cc := dialGRPCViaForward(t, fwd)
	defer cc.Close()
	req := []byte("ping")
	var resp []byte
	callCtx := metadata.AppendToOutgoingContext(ctx, "x-marker", "orig")
	if err := cc.Invoke(callCtx, fwdEchoFullMethod(fwdEchoMethodUnary), &req, &resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if string(resp) != "echo:ping" {
		t.Errorf("resp = %q, want echo:ping", resp)
	}
	mu.Lock()
	if len(seenMarker) != 1 || seenMarker[0] != "orig" {
		t.Errorf("upstream x-marker = %v, want [orig]", seenMarker)
	}
	mu.Unlock()

	waitAnyFlow(t, h.store, "receive")
	if mods := modifiedFlows(h.store, ""); len(mods) != 0 {
		t.Errorf("modified variant recorded (dir=%s raw=%q) although the wire carried the original Start; flows:%s",
			mods[0].Direction, mods[0].RawBytes, describeFlows(h.store))
	}
}

// TestPluginRawWins_GRPC_DataRawOnly_Honoured (Test Plan T5): the guard
// that DATA-payload envelopes keep honouring msg["raw"].
func TestPluginRawWins_GRPC_DataRawOnly_Honoured(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, upStop := startH2CGRPCUpstream(t, &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) {
			return append([]byte("echo:"), req...), nil
		},
	})
	defer upStop()

	// 5-byte LPM prefix (uncompressed, length 8) + "new-data".
	h, fwd := startRawWinsForwardDeps(t, ctx, `
def on_data(msg, ctx):
    if msg["payload"] == b"orig-data":
        msg["raw"] = b"\x00\x00\x00\x00\x08new-data"
register_hook("grpc", "on_data", on_data)
`, upAddr, "grpc", nil)

	cc := dialGRPCViaForward(t, fwd)
	defer cc.Close()
	req := []byte("orig-data")
	var resp []byte
	if err := cc.Invoke(ctx, fwdEchoFullMethod(fwdEchoMethodUnary), &req, &resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if string(resp) != "echo:new-data" {
		t.Errorf("resp = %q, want echo:new-data (plugin LPM frame on the wire)", resp)
	}
	want := []byte("\x00\x00\x00\x00\x08new-data")
	if f := waitFlow(h.store, "send", "modified", func(b []byte) bool { return bytes.Equal(b, want) }); f == nil {
		t.Errorf("no modified Send variant recording the plugin LPM frame; flows:%s", describeFlows(h.store))
	}
}

// grpcWebSeen captures one HTTP/1.1 gRPC-Web request as the upstream saw it.
type grpcWebSeen struct {
	mu   sync.Mutex
	head string
}

// startCapturingGRPCWebUpstream answers every request with one data LPM
// frame + an OK trailer frame and records the request head bytes.
func startCapturingGRPCWebUpstream(t *testing.T) (string, *grpcWebSeen) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	seen := &grpcWebSeen{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				var head strings.Builder
				cl := 0
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					head.WriteString(line)
					if line == "\r\n" {
						break
					}
					if i := strings.IndexByte(line, ':'); i > 0 && strings.EqualFold(strings.TrimSpace(line[:i]), "content-length") {
						cl, _ = strconv.Atoi(strings.TrimSpace(line[i+1:]))
					}
				}
				if cl > 0 {
					if _, err := io.CopyN(io.Discard, br, int64(cl)); err != nil {
						return
					}
				}
				seen.mu.Lock()
				seen.head = head.String()
				seen.mu.Unlock()

				var body bytes.Buffer
				var l [4]byte
				body.WriteByte(0x00)
				binary.BigEndian.PutUint32(l[:], 7)
				body.Write(l[:])
				body.WriteString("hello!!")
				tr := "grpc-status: 0\r\n"
				body.WriteByte(0x80)
				binary.BigEndian.PutUint32(l[:], uint32(len(tr)))
				body.Write(l[:])
				body.WriteString(tr)
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", body.Len())
				_, _ = c.Write(body.Bytes())
			}(c)
		}
	}()
	return ln.Addr().String(), seen
}

// TestPluginRawWins_GRPCWeb_StartRawOnly_Refused (Test Plan T6).
func TestPluginRawWins_GRPCWeb_StartRawOnly_Refused(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upAddr, seen := startCapturingGRPCWebUpstream(t)
	h, fwd := startRawWinsForwardDeps(t, ctx, `
def on_start(msg, ctx):
    msg["raw"] = b"PLUGIN-RAW-GRPCWEB-START"
register_hook("grpc-web", "on_start", on_start)
`, upAddr, "http", nil)

	resp := sendH1GRPCWebRequest(t, fwd, "application/grpc-web+proto", buildLPMBody([]byte("ping")))
	if !bytes.Contains(resp, []byte("hello!!")) {
		t.Fatalf("client response missing upstream payload: %q", resp)
	}
	seen.mu.Lock()
	head := seen.head
	seen.mu.Unlock()
	if !strings.HasPrefix(head, "POST /hello.HelloService/SayHello ") || strings.Contains(head, "PLUGIN-RAW") {
		t.Errorf("upstream request head = %q, want the original request", head)
	}

	waitAnyFlow(t, h.store, "receive")
	if mods := modifiedFlows(h.store, ""); len(mods) != 0 {
		t.Errorf("modified variant recorded (dir=%s raw=%q) although the wire carried the original Start; flows:%s",
			mods[0].Direction, mods[0].RawBytes, describeFlows(h.store))
	}
}
