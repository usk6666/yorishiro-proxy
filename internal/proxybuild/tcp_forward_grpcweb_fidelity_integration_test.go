//go:build e2e && !e2e_smoke

// USK-1219 (⊇ USK-1062), USK-1069 (⊇ USK-1110) and the empty-body
// delivery gap, driven through the production wiring: BuildLiveStack +
// a tcp_forwards entry with Protocol="http", which auto-classifies
// gRPC-Web on HTTP/1.1 and wraps both legs in the grpcweb Layer
// (DispatchH1Channel / WrapH1UpstreamForDispatch).
package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// rawH1Upstream is an HTTP/1.1 upstream that captures every request it
// reads (request line + header block + Content-Length body, verbatim)
// and answers each with the fixed raw response bytes, then closes.
type rawH1Upstream struct {
	addr string
	mu   sync.Mutex
	reqs [][]byte
}

func (u *rawH1Upstream) requests() [][]byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([][]byte, len(u.reqs))
	copy(out, u.reqs)
	return out
}

func startRawH1Upstream(t *testing.T, response []byte) *rawH1Upstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	u := &rawH1Upstream{addr: ln.Addr().String()}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				req, rerr := readRawH1Request(bufio.NewReader(c))
				if rerr != nil {
					return
				}
				u.mu.Lock()
				u.reqs = append(u.reqs, req)
				u.mu.Unlock()
				_, _ = c.Write(response)
			}(c)
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		wg.Wait()
	})
	return u
}

// readRawH1Request reads one request: header block up to the blank line,
// then a Content-Length body. Returns the bytes verbatim.
func readRawH1Request(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	cl := 0
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		buf.WriteString(line)
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		if name, value, ok := strings.Cut(trimmed, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "content-length") {
			cl, _ = strconv.Atoi(strings.TrimSpace(value))
		}
	}
	if cl > 0 {
		body := make([]byte, cl)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, err
		}
		buf.Write(body)
	}
	return buf.Bytes(), nil
}

// startH1ForwardListenerWithGRPCSafety is startH1ForwardListener with an
// optional gRPC Input SafetyEngine on the parent Stack's Pipeline.
func startH1ForwardListenerWithGRPCSafety(t *testing.T, ctx context.Context, upstreamAddr string, safety *grpcrules.SafetyEngine) (
	fwdAddr string, store *flowStoreCapture,
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
			Logger:           logger,
			ListenerName:     name,
			ListenAddr:       addr,
			FlowStore:        store,
			BuildConfig:      buildCfg,
			GRPCSafetyEngine: safety,
		})
	}
	m, err := proxybuild.NewManager(proxybuild.ManagerConfig{Logger: logger, StackFactory: factory})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	t.Cleanup(func() { _ = m.StopAll(context.Background()) })
	if err := m.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := m.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{"0": {Target: upstreamAddr, Protocol: "http"}},
	}); err != nil {
		t.Fatalf("StartTCPForwards(http): %v", err)
	}
	fwdAddr = m.TCPForwardAddrs()["0"]
	if fwdAddr == "" {
		t.Fatalf("TCPForwardAddrs missing port 0")
	}
	return fwdAddr, store
}

// exchangeRaw writes req to the forward listener and returns everything
// read until the proxy closes the connection or the deadline elapses.
func exchangeRaw(t *testing.T, addr string, req []byte) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	var out bytes.Buffer
	_, rerr := io.Copy(&out, conn)
	var ne net.Error
	if rerr != nil && !(errors.As(rerr, &ne) && ne.Timeout()) {
		t.Fatalf("read response: %v", rerr)
	}
	return out.Bytes()
}

// grpcWebRequest builds an HTTP/1.1 gRPC-Web request with the given
// request-target and extra header lines, wire order preserved.
func grpcWebRequest(target, host string, headerLines []string, body []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "POST %s HTTP/1.1\r\n", target)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	for _, l := range headerLines {
		b.WriteString(l + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	b.Write(body)
	return b.Bytes()
}

// splitRawHTTP returns the start line, the header lines (wire order) and
// the body of a raw HTTP/1.x message.
func splitRawHTTP(t *testing.T, raw []byte) (startLine string, headers []string, body []byte) {
	t.Helper()
	head, body, ok := bytes.Cut(raw, []byte("\r\n\r\n"))
	if !ok {
		t.Fatalf("no header terminator in %q", raw)
	}
	lines := strings.Split(string(head), "\r\n")
	return lines[0], lines[1:], body
}

// headerLinesNamed returns the header lines whose name case-insensitively
// matches one of names, in wire order, verbatim.
func headerLinesNamed(lines []string, names ...string) []string {
	var out []string
	for _, l := range lines {
		name, _, _ := strings.Cut(l, ":")
		for _, n := range names {
			if strings.EqualFold(strings.TrimSpace(name), n) {
				out = append(out, l)
				break
			}
		}
	}
	return out
}

// flowsWhere polls the store until pred matches a flow, returning it.
func flowWhere(t *testing.T, store *flowStoreCapture, desc string, pred func(*flow.Flow) bool) *flow.Flow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range store.Flows() {
			if pred(f) {
				return f
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no recorded flow matched %s (have %d flows)", desc, len(store.Flows()))
	return nil
}

func isGRPCEvent(dir, event string) func(*flow.Flow) bool {
	return func(f *flow.Flow) bool {
		return f.Direction == dir && f.Metadata != nil && f.Metadata["grpc_event"] == event
	}
}

// T7: the upstream status reaches the client verbatim, with the
// Content-Type casing and position the upstream sent, and the recorded
// Receive start flow reports it.
func TestProxybuild_TCPForward_H1_GRPCWeb_UpstreamStatusReachesClient(t *testing.T) {
	validBody := buildLPMBody([]byte("hello!!"))
	validBody = append(validBody, 0x80, 0, 0, 0, 16)
	validBody = append(validBody, []byte("grpc-status: 0\r\n")...)

	tests := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{"503_text_plain_body", "text/plain", []byte("Service Unavailable")},
		{"503_grpc_web_frames", "application/grpc-web+proto", validBody},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			resp := []byte(fmt.Sprintf("HTTP/1.1 503 Service Unavailable\r\nX-First: 1\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
				tt.contentType, len(tt.body)))
			resp = append(resp, tt.body...)
			up := startRawH1Upstream(t, resp)
			fwdAddr, store := startH1ForwardListenerWithGRPCSafety(t, ctx, up.addr, nil)

			got := exchangeRaw(t, fwdAddr, grpcWebRequest("/hello.HelloService/SayHello", fwdAddr,
				[]string{"Content-Type: application/grpc-web+proto"}, buildLPMBody([]byte("ping"))))
			startLine, headers, body := splitRawHTTP(t, got)
			if startLine != "HTTP/1.1 503 Service Unavailable" {
				t.Errorf("client status line = %q, want %q", startLine, "HTTP/1.1 503 Service Unavailable")
			}
			wantOrder := []string{"X-First: 1", "Content-Type: " + tt.contentType}
			if gotOrder := headerLinesNamed(headers, "x-first", "content-type"); strings.Join(gotOrder, "|") != strings.Join(wantOrder, "|") {
				t.Errorf("client header layout = %q, want %q", gotOrder, wantOrder)
			}
			if !bytes.Equal(body, tt.body) {
				t.Errorf("client body = %q, want %q", body, tt.body)
			}

			f := flowWhere(t, store, "receive start", isGRPCEvent("receive", "start"))
			if f.StatusCode != 503 {
				t.Errorf("recorded receive-start StatusCode = %d, want 503", f.StatusCode)
			}
		})
	}
}

// T8: the client's query string reaches the upstream, the request-side
// control headers keep their wire casing / position / raw value, and the
// Send start flow's URL carries the query.
func TestProxybuild_TCPForward_H1_GRPCWeb_QueryAndHeaderLayoutReachUpstream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	okBody := buildLPMBody([]byte("hello!!"))
	resp := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(okBody)))
	resp = append(resp, okBody...)
	up := startRawH1Upstream(t, resp)
	fwdAddr, store := startH1ForwardListenerWithGRPCSafety(t, ctx, up.addr, nil)

	const target = "/hello.HelloService/SayHello?trace=1&x=%27"
	_ = exchangeRaw(t, fwdAddr, grpcWebRequest(target, fwdAddr,
		[]string{"X-Before: 1", "Content-Type: application/grpc-web+proto", "Grpc-Timeout: 5S"},
		buildLPMBody([]byte("ping"))))

	reqs := up.requests()
	if len(reqs) != 1 {
		t.Fatalf("upstream saw %d requests, want 1", len(reqs))
	}
	startLine, headers, _ := splitRawHTTP(t, reqs[0])
	if want := "POST " + target + " HTTP/1.1"; startLine != want {
		t.Errorf("upstream request line = %q, want %q", startLine, want)
	}
	wantOrder := []string{"Host: " + fwdAddr, "X-Before: 1", "Content-Type: application/grpc-web+proto", "Grpc-Timeout: 5S"}
	if got := headerLinesNamed(headers, "host", "x-before", "content-type", "grpc-timeout"); strings.Join(got, "|") != strings.Join(wantOrder, "|") {
		t.Errorf("upstream header layout = %q, want %q", got, wantOrder)
	}

	f := flowWhere(t, store, "send start", isGRPCEvent("send", "start"))
	if f.URL == nil {
		t.Fatal("send-start Flow.URL = nil")
	}
	if f.URL.RawQuery != "trace=1&x=%27" {
		t.Errorf("send-start Flow.URL.RawQuery = %q, want %q", f.URL.RawQuery, "trace=1&x=%27")
	}
}

// T10: a destructive-sql payload carried only in the gRPC-Web query is
// now scanned by the gRPC Input SafetyFilter and blocked. The client-side
// terminator shape is USK-1220's concern and deliberately not asserted.
func TestProxybuild_TCPForward_H1_GRPCWeb_SafetyBlocksDestructiveQuery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	okBody := buildLPMBody([]byte("hello!!"))
	resp := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(okBody)))
	resp = append(resp, okBody...)
	up := startRawH1Upstream(t, resp)

	safety := grpcrules.NewSafetyEngine()
	if err := safety.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatalf("LoadPreset: %v", err)
	}
	fwdAddr, store := startH1ForwardListenerWithGRPCSafety(t, ctx, up.addr, safety)

	_ = exchangeRaw(t, fwdAddr, grpcWebRequest("/hello.HelloService/SayHello?q=DROP/**/TABLE/**/users", fwdAddr,
		[]string{"Content-Type: application/grpc-web+proto"}, buildLPMBody([]byte("ping"))))

	deadline := time.Now().Add(3 * time.Second)
	blocked := false
	for time.Now().Before(deadline) && !blocked {
		for _, st := range store.Streams() {
			if st.BlockedBy == pipeline.BlockedBySafetyFilter {
				blocked = true
			}
			for _, u := range store.StreamUpdates(st.ID) {
				if u.BlockedBy == pipeline.BlockedBySafetyFilter {
					blocked = true
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !blocked {
		t.Errorf("no stream recorded with BlockedBy=%q", pipeline.BlockedBySafetyFilter)
	}
	if reqs := up.requests(); len(reqs) != 0 {
		t.Errorf("upstream received %d request(s), want 0; first: %q", len(reqs), reqs[0])
	}
}

// T11 (N1): an empty-body response — a bare 503 or a gRPC-Web
// trailers-only response — is delivered to the client with its status
// and headers, without a fabricated trailer frame, and recorded.
func TestProxybuild_TCPForward_H1_GRPCWeb_EmptyBodyResponseDelivered(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		statusLine string
		wantLines  []string
	}{
		{
			name:       "503_content_length_zero",
			response:   "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			statusLine: "HTTP/1.1 503 Service Unavailable",
			wantLines:  []string{"Content-Type: text/plain", "Content-Length: 0"},
		},
		{
			name:       "trailers_only",
			response:   "HTTP/1.1 200 OK\r\nContent-Type: application/grpc-web+proto\r\nGrpc-Status: 12\r\nGrpc-Message: unimplemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
			statusLine: "HTTP/1.1 200 OK",
			wantLines:  []string{"Content-Type: application/grpc-web+proto", "Grpc-Status: 12", "Grpc-Message: unimplemented", "Content-Length: 0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			up := startRawH1Upstream(t, []byte(tt.response))
			fwdAddr, store := startH1ForwardListenerWithGRPCSafety(t, ctx, up.addr, nil)

			got := exchangeRaw(t, fwdAddr, grpcWebRequest("/hello.HelloService/SayHello", fwdAddr,
				[]string{"Content-Type: application/grpc-web+proto"}, buildLPMBody([]byte("ping"))))
			if len(got) == 0 {
				t.Fatal("client received 0 bytes")
			}
			startLine, headers, body := splitRawHTTP(t, got)
			if startLine != tt.statusLine {
				t.Errorf("client status line = %q, want %q", startLine, tt.statusLine)
			}
			if gotLines := headerLinesNamed(headers, "content-type", "grpc-status", "grpc-message", "content-length"); strings.Join(gotLines, "|") != strings.Join(tt.wantLines, "|") {
				t.Errorf("client headers = %q, want %q", gotLines, tt.wantLines)
			}
			if len(body) != 0 {
				t.Errorf("client body = %x, want empty (no fabricated trailer frame)", body)
			}

			_ = flowWhere(t, store, "receive start", isGRPCEvent("receive", "start"))
			_ = flowWhere(t, store, "receive end", isGRPCEvent("receive", "end"))
		})
	}
}
