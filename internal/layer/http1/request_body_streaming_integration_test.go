//go:build e2e && !e2e_smoke

package http1_test

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// USK-1414 exhaustive tier: request body streaming against the rules that
// need the whole body (Safety body target, Intercept), max_body_size,
// Expect: 100-continue and header-only Transform recording. Helpers live
// in request_body_streaming_smoke_integration_test.go and
// body_streaming_smoke_integration_test.go.

// heldBody returns the whole body a request Message carries in memory or
// in its BodyBuffer.
func heldBody(t *testing.T, msg *envelope.HTTPMessage) []byte {
	t.Helper()
	if msg.Body != nil {
		return msg.Body
	}
	if msg.BodyBuffer != nil {
		b, err := msg.BodyBuffer.Bytes(context.Background())
		if err != nil {
			t.Fatalf("BodyBuffer.Bytes: %v", err)
		}
		return b
	}
	return nil
}

// stepFunc is a pass-through Pipeline Step that calls fn on every envelope.
type stepFunc func(ctx context.Context, env *envelope.Envelope)

func (f stepFunc) Process(ctx context.Context, env *envelope.Envelope) pipeline.Result {
	f(ctx, env)
	return pipeline.Result{}
}

// dropCapture records the envelope of the first policy Drop / Respond.
type dropCapture struct {
	mu        sync.Mutex
	env       *envelope.Envelope
	blockedBy string
}

func (d *dropCapture) hook(_ context.Context, env *envelope.Envelope, blockedBy string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.env == nil {
		d.env, d.blockedBy = env, blockedBy
	}
}

func (d *dropCapture) get() (*envelope.Envelope, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.env, d.blockedBy
}

// TestHTTP1_RequestBodyStreaming_SafetyBodyRuleJudgesWholeBody (T5): with a
// Safety body-target rule loaded, a destructive payload carried only in
// the second body fragment is blocked with 403, the upstream reads no
// byte, and the request the filter judged carried the whole body.
func TestHTTP1_RequestBodyStreaming_SafetyBodyRuleJudgesWholeBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	target, up := startCountingUpstream(t)
	safety := httprules.NewSafetyEngine()
	if err := safety.LoadPreset("destructive-sql"); err != nil {
		t.Fatalf("LoadPreset: %v", err)
	}
	drops := &dropCapture{}
	proxyAddr, _, sessionDone := startRequestStreamingProxy(t, ctx, target, proxyOpts{
		safetyEngine:   safety,
		onPipelineDrop: drops.hook,
	})

	frag1 := strings.Repeat("benign payload ", 300)
	frag2 := "; DROP TABLE users;"
	body := frag1 + frag2
	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	if _, err := fmt.Fprintf(conn, "POST /api HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", target, len(body), frag1); err != nil {
		t.Fatalf("write fragment 1: %v", err)
	}
	if _, err := io.WriteString(conn, frag2); err != nil {
		t.Fatalf("write fragment 2: %v", err)
	}
	br := bufio.NewReader(conn)
	if head := readHeadWithin(t, conn, br); !strings.HasPrefix(head, "HTTP/1.1 403") {
		t.Fatalf("response head = %q, want 403", head)
	}
	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for the session to complete")
	}
	if n := up.total(t); n != 0 {
		t.Errorf("upstream read %d bytes, want 0", n)
	}
	env, blockedBy := drops.get()
	if env == nil || blockedBy != "safety_filter" {
		t.Fatalf("policy drop = (%v, %q), want the safety_filter block", env, blockedBy)
	}
	msg, _ := env.Message.(*envelope.HTTPMessage)
	if msg == nil {
		t.Fatalf("blocked envelope Message = %T", env.Message)
	}
	if msg.BodyStream != nil {
		t.Error("blocked request carried a BodyStream; a Safety body rule must see the buffered body")
	}
	if got := heldBody(t, msg); string(got) != body {
		t.Errorf("blocked request body = %d bytes, want the whole %d-byte body", len(got), len(body))
	}
}

// TestHTTP1_RequestBodyStreaming_SafetyBodyRuleOverMaxBodySize (T6): with
// a Safety body-target rule loaded, a request body over max_body_size is
// still buffered, so it fails as before: the connection closes without a
// response and the upstream reads no byte.
func TestHTTP1_RequestBodyStreaming_SafetyBodyRuleOverMaxBodySize(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	target, up := startCountingUpstream(t)
	safety := httprules.NewSafetyEngine()
	if err := safety.LoadPreset("destructive-sql"); err != nil {
		t.Fatalf("LoadPreset: %v", err)
	}
	proxyAddr, _, sessionDone := startRequestStreamingProxy(t, ctx, target, proxyOpts{
		safetyEngine:       safety,
		bodySpillDir:       t.TempDir(),
		bodySpillThreshold: 512 << 10,
		maxBodySize:        1 << 20,
	})

	body := makeSmokeBody(2 << 20)
	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	go func() {
		_, _ = fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", target, len(body))
		_, _ = conn.Write(body)
	}()
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	got, err := io.ReadAll(conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("connection still open after the over-cap body: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("client received %q, want no response (the over-cap body fails before any)", got)
	}
	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for the session to complete")
	}
	if n := up.total(t); n != 0 {
		t.Errorf("upstream read %d bytes, want 0", n)
	}
}

// TestHTTP1_RequestBodyStreaming_InterceptHoldsWholeBody (T7): a request
// held by a matching Intercept rule carries its whole body (never a
// BodyStream), and releasing it forwards that body.
func TestHTTP1_RequestBodyStreaming_InterceptHoldsWholeBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	ie := httprules.NewInterceptEngine()
	ie.AddRule(httprules.InterceptRule{
		ID:          "hold-upload",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/hold$`),
	})
	q := common.NewHoldQueue()
	proxyAddr, _, _ := startRequestStreamingProxy(t, ctx, target, proxyOpts{interceptEngine: ie, holdQueue: q})

	body := string(makeSmokeBody(20000))
	respCh := make(chan string, 1)
	go func() {
		respCh <- connectAndSendHTTP(t, proxyAddr, target,
			fmt.Sprintf("POST /hold HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", target, len(body), body))
	}()

	var entries []*common.HeldEntry
	deadline := time.Now().Add(10 * time.Second)
	for len(entries) == 0 && time.Now().Before(deadline) {
		entries = q.List()
		if len(entries) == 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if len(entries) == 0 {
		t.Fatal("no request was held")
	}
	msg, _ := entries[0].Envelope.Message.(*envelope.HTTPMessage)
	if msg == nil {
		t.Fatalf("held Message = %T", entries[0].Envelope.Message)
	}
	if msg.BodyStream != nil {
		t.Error("held request carries a BodyStream; a matching Intercept rule must buffer the body")
	}
	if got := heldBody(t, msg); string(got) != body {
		t.Errorf("held body = %d bytes, want the whole %d-byte body", len(got), len(body))
	}
	if err := q.Release(entries[0].ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
		t.Fatalf("Release: %v", err)
	}
	select {
	case resp := <-respCh:
		if !strings.Contains(resp, "200 OK") {
			t.Errorf("client response = %q, want 200", resp)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for the response")
	}
	reqs := getUpstreamReqs()
	if len(reqs) != 1 || !bytes.HasSuffix(reqs[0], []byte(body)) {
		t.Errorf("upstream requests = %d, want 1 carrying the whole body", len(reqs))
	}
}

// TestHTTP1_RequestBodyStreaming_ExpectContinue (T13): a client that sends
// Expect: 100-continue and waits for the interim response before its body
// gets the upstream's 100 (the head is forwarded before any body byte),
// then the final response; the 100 is recorded.
func TestHTTP1_RequestBodyStreaming_ExpectContinue(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	const body = "hello"
	upBody := make(chan string, 1)
	target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
		if _, err := readRequestHeadRaw(br); err != nil {
			return
		}
		_, _ = io.WriteString(c, "HTTP/1.1 100 Continue\r\n\r\n")
		got, err := readFullWithin(c, br, len(body))
		if err != nil {
			upBody <- "error: " + err.Error()
			return
		}
		upBody <- string(got)
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	proxyAddr, store, _ := startRequestStreamingProxy(t, ctx, target, proxyOpts{})

	conn := connectThroughProxy(t, proxyAddr, target)
	defer conn.Close()
	fmt.Fprintf(conn, "PUT /upload HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n", target, len(body))
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	interim, err := readRequestHeadRaw(br)
	if err != nil {
		t.Fatalf("no interim response within 10s (got %q): %v", interim, err)
	}
	if !strings.HasPrefix(interim, "HTTP/1.1 100 Continue\r\n") {
		t.Fatalf("interim response = %q, want 100 Continue", interim)
	}
	_ = conn.SetReadDeadline(time.Time{})
	if _, err := io.WriteString(conn, body); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if head := readHeadWithin(t, conn, br); !strings.HasPrefix(head, "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("final response head = %q, want 200", head)
	}
	select {
	case got := <-upBody:
		if got != body {
			t.Errorf("upstream body = %q, want %q", got, body)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upstream did not finish")
	}
	waitStreamState(t, store, "complete")
	var saw100 bool
	for _, fl := range waitFlowsByDirection(t, store, "receive", 2) {
		if fl.StatusCode == 100 {
			saw100 = true
		}
	}
	if !saw100 {
		t.Error("the 100 Continue interim response was not recorded")
	}
}

// TestHTTP1_RequestBodyStreaming_HeaderTransformVariants (T17): a
// header-only Transform on a streamed request records the original and the
// modified variant; the modified variant's raw bytes are the re-encoded
// head followed by the raw body, and the upstream receives that.
func TestHTTP1_RequestBodyStreaming_HeaderTransformVariants(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	const chunked = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	upReq := make(chan []byte, 1)
	target, _ := startGatedUpstream(t, func(c net.Conn, br *bufio.Reader) {
		head, err := readRequestHeadRaw(br)
		if err != nil {
			upReq <- nil
			return
		}
		b, err := readFullWithin(c, br, len(chunked))
		upReq <- append([]byte(head), b...)
		if err == nil {
			_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		}
	})

	tf := httprules.NewTransformEngine()
	rule, err := httprules.CompileTransformRule("add", 0, httprules.DirectionRequest,
		"", "^/xform$", nil, httprules.TransformAddHeader, "X-Added", "1", "", "")
	if err != nil {
		t.Fatalf("CompileTransformRule: %v", err)
	}
	tf.AddRule(*rule)
	streamed := make(chan bool, 1)
	inspect := stepFunc(func(_ context.Context, env *envelope.Envelope) {
		if m, ok := env.Message.(*envelope.HTTPMessage); ok && env.Direction == envelope.Send {
			select {
			case streamed <- m.BodyStream != nil:
			default:
			}
		}
	})
	proxyAddr, store, _ := startRequestStreamingProxy(t, ctx, target, proxyOpts{
		transformEngine:    tf,
		prependCustomSteps: []pipeline.Step{inspect},
	})

	resp := connectAndSendHTTP(t, proxyAddr, target, fmt.Sprintf(
		"POST /xform HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n%s", target, chunked))
	if !strings.Contains(resp, "200 OK") {
		t.Fatalf("client response = %q, want 200", resp)
	}
	select {
	case s := <-streamed:
		if !s {
			t.Error("the request was buffered; a header-only Transform must not force buffering")
		}
	default:
		t.Fatal("inspection step saw no request")
	}
	waitStreamState(t, store, "complete")
	variants := map[string]*flow.Flow{}
	for _, fl := range waitFlowsByDirection(t, store, "send", 2) {
		variants[fl.Metadata["variant"]] = fl
	}
	orig, mod := variants["original"], variants["modified"]
	if orig == nil || mod == nil {
		t.Fatalf("send variants = %v, want original and modified", variants)
	}
	if bytes.Contains(orig.RawBytes, []byte("X-Added")) || !bytes.HasSuffix(orig.RawBytes, []byte(chunked)) {
		t.Errorf("original raw = %q, want the client's head + raw chunked body", orig.RawBytes)
	}
	if !bytes.Contains(mod.RawBytes, []byte("X-Added: 1\r\n")) || !bytes.HasSuffix(mod.RawBytes, []byte("\r\n\r\n"+chunked)) {
		t.Errorf("modified raw = %q, want the re-encoded head + raw chunked body", mod.RawBytes)
	}
	if string(mod.Body) != "hello world" || string(orig.Body) != "hello world" {
		t.Errorf("variant bodies = %q / %q, want %q", orig.Body, mod.Body, "hello world")
	}
	select {
	case req := <-upReq:
		if !bytes.Contains(req, []byte("X-Added: 1\r\n")) || !bytes.HasSuffix(req, []byte("\r\n\r\n"+chunked)) {
			t.Errorf("upstream request = %q, want the modified head + raw chunked body", req)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upstream saw no request")
	}
}
