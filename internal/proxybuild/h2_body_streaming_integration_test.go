//go:build e2e && !e2e_smoke

// USK-1401 exhaustive tier: HTTP/2 body streaming on the live
// BuildLiveStack paths — recording while a body is in flight, the rule
// engines that still buffer, client cancellation, DATA framing, trailers,
// a Pipeline answer to a streamed upload, GOAWAY redial and tcp_forwards.
package proxybuild_test

import (
	"bytes"
	"context"
	"io"
	gohttp "net/http"
	"regexp"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

var (
	okStatus = hpack.HeaderField{Name: ":status", Value: "200"}
	octetCT  = hpack.HeaderField{Name: "content-type", Value: "application/octet-stream"}
)

// readUntilData reads events of stream id until the first DATA frame (or
// fails t).
func readUntilData(t *testing.T, p *h2Peer, id uint32, what string) []h2Ev {
	t.Helper()
	var evs []h2Ev
	for {
		ev, ok := p.next(t, id, 10*time.Second)
		if !ok {
			t.Fatalf("%s: no DATA within 10s (events so far: %v)", what, evs)
		}
		evs = append(evs, ev)
		if ev.kind == "rst" {
			t.Fatalf("%s: got %v before any DATA (events: %v)", what, ev, evs)
		}
		if ev.kind == "data" {
			return evs
		}
	}
}

// TestH2BodyStreaming_RecordingActiveThenComplete (T3): while a streamed
// response body is in flight the Stream is active and no Receive flow is
// saved; at the body's end the Stream completes and the Receive flow carries
// the body, the raw bytes (HEADERS block + DATA payloads) and the h2-frame
// overlay rows, one per DATA frame.
func TestH2BodyStreaming_RecordingActiveThenComplete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	part1, part2 := []byte("streamed-part-one"), []byte("streamed-part-two")
	finish := newGateCh()
	defer finish.open()
	origin := startScriptedH2Origin(t, func(_ int, p *h2Peer, req h2Ev) {
		_ = p.writeHeaders(req.stream, false, okStatus, octetCT)
		_ = p.writeData(req.stream, false, part1)
		if finish.wait(20 * time.Second) {
			_ = p.writeData(req.stream, true, part2)
		}
	})
	store := &flowStoreForH2Pool{}
	proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{})
	cli := dialH2PeerThroughProxy(t, proxyAddr, origin.addr)
	mustWrite(t, cli.writeHeaders(1, true, requestFields("GET", origin.addr, "/active")...))
	evs := readUntilData(t, cli, 1, "first response DATA")

	// Mid-body: the Stream exists and is active, the request is recorded,
	// the response is not (its Flow is saved at the body's end).
	deadline := time.Now().Add(5 * time.Second)
	for len(streamingSemanticFlows(store, "send")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	streams := store.Streams()
	if len(streams) != 1 || streams[0].State != "active" {
		t.Fatalf("mid-body streams = %v, want one active Stream", streamOutcomes(streams))
	}
	if n := len(streamingSemanticFlows(store, "receive")); n != 0 {
		t.Errorf("mid-body receive flows = %d, want 0", n)
	}

	finish.open()
	evs = append(evs, cli.collectUntilEnd(t, 1, 10*time.Second)...)
	body, _ := dataPayloads(evs)
	want := append(append([]byte(nil), part1...), part2...)
	if !bytes.Equal(body, want) || !evs[len(evs)-1].end {
		t.Fatalf("client events = %v, want the whole body and END_STREAM", evs)
	}

	waitStreamOutcomes(t, store, map[string]int{"complete/": 1}, 10*time.Second)
	recv := waitSemanticFlow(t, store, "receive", 5*time.Second)
	if !bytes.Equal(recv.Body, want) {
		t.Errorf("recorded body = %q, want %q", recv.Body, want)
	}
	if !bytes.HasSuffix(recv.RawBytes, want) || len(recv.RawBytes) <= len(want) {
		t.Errorf("recorded raw bytes (%d) are not the HEADERS block followed by the DATA payloads", len(recv.RawBytes))
	}
	var overlays [][]byte
	for _, f := range store.Flows() {
		if f.Direction == "receive" && f.WireLevel == flow.WireLevelH2Frame {
			overlays = append(overlays, f.RawBytes)
		}
	}
	if len(overlays) != 2 || !bytes.Equal(overlays[0], part1) || !bytes.Equal(overlays[1], part2) {
		t.Errorf("receive h2-frame overlay rows = %q, want one per DATA frame %q, %q", overlays, part1, part2)
	}
}

// TestH2BodyStreaming_RulesStillBuffer (T6) guards that a rule needing the
// whole body keeps it buffered on h2: replace_body rewrites (both variants
// recorded), Intercept holds the whole body, and a Safety body-target rule
// blocks before the upstream sees the request.
func TestH2BodyStreaming_RulesStillBuffer(t *testing.T) {
	t.Run("replace_body", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		upAddr, _, upShutdown := startH2TLSUpstreamForPoolTest(t, "localhost", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			_, _ = w.Write([]byte("hello origin-secret world"))
		}))
		defer upShutdown()
		tf := httprules.NewTransformEngine()
		rule, err := httprules.CompileTransformRule("rb", 0, httprules.DirectionResponse,
			"", "^/rb$", nil, httprules.TransformReplaceBody, "", "", "origin-secret", "proxy-public!")
		if err != nil {
			t.Fatal(err)
		}
		tf.AddRule(*rule)
		store := &flowStoreForH2Pool{}
		proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{transform: tf})
		cli := newH2ClientThroughProxyForPoolTest(proxyAddr, upAddr)
		req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/rb", nil)
		resp, err := cli.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "hello proxy-public! world" {
			t.Errorf("client body = %q, want the replaced body", b)
		}
		waitStreamOutcomes(t, store, map[string]int{"complete/": 1}, 10*time.Second)
		var orig, mod *flow.Flow
		for _, f := range streamingSemanticFlows(store, "receive") {
			switch f.Metadata["variant"] {
			case "original":
				orig = f
			case "modified":
				mod = f
			}
		}
		if orig == nil || mod == nil || string(orig.Body) != "hello origin-secret world" || string(mod.Body) != "hello proxy-public! world" {
			t.Errorf("receive variants original=%v modified=%v, want both with the original / replaced body", orig != nil, mod != nil)
		}
	})

	t.Run("intercept_holds_whole_body", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		respBody := bytes.Repeat([]byte("i"), 40000)
		upAddr, _, upShutdown := startH2TLSUpstreamForPoolTest(t, "localhost", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			_, _ = w.Write(respBody)
		}))
		defer upShutdown()
		ie := httprules.NewInterceptEngine()
		ie.AddRule(httprules.InterceptRule{
			ID: "hold-resp", Enabled: true, Direction: httprules.DirectionResponse,
			PathPattern: regexp.MustCompile(`^/held$`),
		})
		hq := common.NewHoldQueue()
		hq.SetTimeout(10 * time.Second)
		store := &flowStoreForH2Pool{}
		proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{intercept: ie, holdQueue: hq})
		got := make(chan []byte, 1)
		go func() {
			cli := newH2ClientThroughProxyForPoolTest(proxyAddr, upAddr)
			req, _ := gohttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/held", nil)
			resp, err := cli.Do(req)
			if err != nil {
				got <- nil
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			got <- b
		}()
		held := releaseFirstHeldEntry(t, hq, 10*time.Second, func(*common.HeldEntry) *common.HoldAction {
			return &common.HoldAction{Type: common.ActionRelease}
		})
		if m := httpMessageOf(held); m == nil || m.BodyStream != nil || !bytes.Equal(m.Body, respBody) {
			t.Errorf("held response is not the whole buffered body")
		}
		select {
		case b := <-got:
			if !bytes.Equal(b, respBody) {
				t.Errorf("client body = %d bytes, want %d", len(b), len(respBody))
			}
		case <-time.After(10 * time.Second):
			t.Fatal("client never got the released response")
		}
	})

	t.Run("safety_body_target_blocks", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		hits := make(chan struct{}, 4)
		upAddr, _, upShutdown := startH2TLSUpstreamForPoolTest(t, "localhost", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			hits <- struct{}{}
			_, _ = io.Copy(io.Discard, r.Body)
		}))
		defer upShutdown()
		se := httprules.NewSafetyEngine()
		if err := se.LoadPreset(common.PresetDestructiveSQL); err != nil {
			t.Fatal(err)
		}
		store := &flowStoreForH2Pool{}
		proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{safety: se})
		cli := newH2ClientThroughProxyForPoolTest(proxyAddr, upAddr)
		body := append(bytes.Repeat([]byte("x"), 30000), []byte("DROP TABLE users;")...)
		req, _ := gohttp.NewRequestWithContext(ctx, "POST", "https://"+upAddr+"/sql", bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		if resp, err := cli.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		select {
		case <-hits:
			t.Fatal("the upstream received a request whose body a Safety rule blocks")
		case <-time.After(500 * time.Millisecond):
		}
	})
}

// TestH2BodyStreaming_ClientCancelMidRequestBody (T8): the client resets
// the stream after part of a streamed request body. The upstream sees the
// DATA forwarded so far, then RST_STREAM(CANCEL) and never END_STREAM; the
// Stream ends in error with the partial request recorded as truncated.
func TestH2BodyStreaming_ClientCancelMidRequestBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	part1 := []byte("uploaded-part-one")
	originGotPart1 := newGateCh()
	originEvents := make(chan []h2Ev, 1)
	origin := startScriptedH2Origin(t, func(_ int, p *h2Peer, req h2Ev) {
		var evs []h2Ev
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case ev := <-p.stream(req.stream):
				if ev.kind == "headers" {
					continue
				}
				evs = append(evs, ev)
				if ev.kind == "data" && bytes.Equal(ev.data, part1) {
					originGotPart1.open()
				}
				if ev.kind == "rst" || ev.end {
					originEvents <- evs
					return
				}
			case <-time.After(100 * time.Millisecond):
			}
		}
		originEvents <- evs
	})
	store := &flowStoreForH2Pool{}
	proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{})
	cli := dialH2PeerThroughProxy(t, proxyAddr, origin.addr)
	mustWrite(t, cli.writeHeaders(1, false, requestFields("POST", origin.addr, "/upload", octetCT)...))
	mustWrite(t, cli.writeData(1, false, part1))
	if !originGotPart1.wait(10 * time.Second) {
		t.Fatal("the origin never received the first DATA of the request (body buffered)")
	}
	mustWrite(t, cli.writeRST(1, http2.ErrCodeCancel))

	var evs []h2Ev
	select {
	case evs = <-originEvents:
	case <-time.After(15 * time.Second):
		t.Fatal("origin never saw the end of the request stream")
	}
	body, _ := dataPayloads(evs)
	if !bytes.Equal(body, part1) {
		t.Errorf("origin DATA = %q, want %q", body, part1)
	}
	last := evs[len(evs)-1]
	if last.kind != "rst" || last.code != http2.ErrCodeCancel {
		t.Errorf("origin stream ended with %v, want RST_STREAM(CANCEL); events %v", last, evs)
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		st := store.Streams()
		if len(st) == 1 && st[0].State == "error" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("streams = %v, want one Stream in state error", streamOutcomes(st))
		}
		time.Sleep(20 * time.Millisecond)
	}
	send := waitSemanticFlow(t, store, "send", 5*time.Second)
	if !bytes.Equal(send.Body, part1) {
		t.Errorf("recorded request body = %q, want %q", send.Body, part1)
	}
	if send.Metadata["http_anomaly_truncated_body"] == "" {
		t.Errorf("send flow metadata lacks http_anomaly_truncated_body: %v", send.Metadata)
	}
}

// boundarySizes is the DATA framing T9 sends: tiny frames and one at the
// default SETTINGS_MAX_FRAME_SIZE, which a re-chunking proxy would merge.
var boundarySizes = []int{1, 7, 16384, 100}

func boundaryFrames() [][]byte {
	out := make([][]byte, len(boundarySizes))
	for i, n := range boundarySizes {
		out[i] = bytes.Repeat([]byte{byte('a' + i)}, n)
	}
	return out
}

// TestH2BodyStreaming_DataBoundariesPreserved (T9): each DATA frame of a
// streamed body crosses the proxy as one DATA frame of the same size, in
// both directions.
func TestH2BodyStreaming_DataBoundariesPreserved(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	frames := boundaryFrames()
	reqSizes := make(chan []int, 1)
	origin := startScriptedH2Origin(t, func(_ int, p *h2Peer, req h2Ev) {
		var evs []h2Ev
	read:
		for {
			select {
			case ev := <-p.stream(req.stream):
				if ev.kind == "headers" {
					continue
				}
				evs = append(evs, ev)
				if ev.end || ev.kind == "rst" {
					break read
				}
			case <-time.After(20 * time.Second):
				break read
			}
		}
		_, sizes := dataPayloads(evs)
		reqSizes <- sizes
		_ = p.writeHeaders(req.stream, false, okStatus, octetCT)
		for i, f := range frames {
			_ = p.writeData(req.stream, i == len(frames)-1, f)
		}
	})
	store := &flowStoreForH2Pool{}
	proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{})
	cli := dialH2PeerThroughProxy(t, proxyAddr, origin.addr)
	mustWrite(t, cli.writeHeaders(1, false, requestFields("POST", origin.addr, "/frames", octetCT)...))
	for i, f := range frames {
		mustWrite(t, cli.writeData(1, i == len(frames)-1, f))
	}
	select {
	case got := <-reqSizes:
		if !equalInts(got, boundarySizes) {
			t.Errorf("request DATA frame sizes at the origin = %v, want %v", got, boundarySizes)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("origin never got the whole request")
	}
	evs := cli.collectUntilEnd(t, 1, 10*time.Second)
	if _, got := dataPayloads(evs); !equalInts(got, boundarySizes) {
		t.Errorf("response DATA frame sizes at the client = %v, want %v", got, boundarySizes)
	}
}

// httpMessageOf returns the HTTPMessage of a held entry, or nil.
func httpMessageOf(held *common.HeldEntry) *envelope.HTTPMessage {
	if held == nil || held.Envelope == nil {
		return nil
	}
	m, _ := held.Envelope.Message.(*envelope.HTTPMessage)
	return m
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestH2BodyStreaming_TrailersAfterStreamedBody (T10): trailers that follow
// a streamed response body reach the client after the body, carrying
// END_STREAM, and are recorded.
func TestH2BodyStreaming_TrailersAfterStreamedBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	origin := startScriptedH2Origin(t, func(_ int, p *h2Peer, req h2Ev) {
		_ = p.writeHeaders(req.stream, false, okStatus, octetCT)
		_ = p.writeData(req.stream, false, []byte("body-before-trailers"))
		_ = p.writeHeaders(req.stream, true, hpack.HeaderField{Name: "x-checksum", Value: "abc123"})
	})
	store := &flowStoreForH2Pool{}
	proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{})
	cli := dialH2PeerThroughProxy(t, proxyAddr, origin.addr)
	mustWrite(t, cli.writeHeaders(1, true, requestFields("GET", origin.addr, "/trailers")...))
	evs := cli.collectUntilEnd(t, 1, 10*time.Second)
	if len(evs) < 3 {
		t.Fatalf("client events = %v, want HEADERS, DATA, trailer HEADERS", evs)
	}
	last := evs[len(evs)-1]
	if last.kind != "headers" || !last.end || last.field("x-checksum") != "abc123" {
		t.Errorf("last client event = %v, want trailer HEADERS x-checksum with END_STREAM", last)
	}
	if body, _ := dataPayloads(evs); string(body) != "body-before-trailers" {
		t.Errorf("client body = %q", body)
	}
	waitStreamOutcomes(t, store, map[string]int{"complete/": 1}, 10*time.Second)
	recv := waitSemanticFlow(t, store, "receive", 5*time.Second)
	if got := recv.Trailers["x-checksum"]; len(got) != 1 || got[0] != "abc123" {
		t.Errorf("recorded trailers = %v, want x-checksum: abc123", recv.Trailers)
	}
}

// TestH2BodyStreaming_ScopeDenyStreamedUpload (T13): HTTPScope denies a
// streamed upload. The client gets the 403 without sending its whole body,
// then RST_STREAM(NO_ERROR) (RFC 9113 §8.1: stop sending the request body),
// and the upstream is never contacted.
func TestH2BodyStreaming_ScopeDenyStreamedUpload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	hits := make(chan struct{}, 4)
	origin := startScriptedH2Origin(t, func(_ int, p *h2Peer, req h2Ev) { hits <- struct{}{} })
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/allowed/"}}, nil)
	store := &flowStoreForH2Pool{}
	proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{scope: scope})
	cli := dialH2PeerThroughProxy(t, proxyAddr, origin.addr)
	mustWrite(t, cli.writeHeaders(1, false, requestFields("POST", origin.addr, "/forbidden",
		hpack.HeaderField{Name: "content-length", Value: "100000"})...))
	mustWrite(t, cli.writeData(1, false, bytes.Repeat([]byte("u"), 1000)))

	evs := cli.collectUntilEnd(t, 1, 10*time.Second)
	if len(evs) == 0 || evs[0].kind != "headers" || evs[0].field(":status") != "403" {
		t.Fatalf("client events = %v, want a 403 before the upload finished", evs)
	}
	if !evs[len(evs)-1].end {
		t.Fatalf("client events = %v, want the 403 to end with END_STREAM", evs)
	}
	// The client keeps uploading; the proxy resets the request half.
	_ = cli.writeData(1, false, bytes.Repeat([]byte("v"), 1000))
	ev, ok := cli.next(t, 1, 10*time.Second)
	if !ok || ev.kind != "rst" || ev.code != http2.ErrCodeNo {
		t.Errorf("after the 403 the client got %v (ok=%v), want RST_STREAM(NO_ERROR)", ev, ok)
	}
	select {
	case <-hits:
		t.Error("the origin was contacted for a denied request")
	default:
	}
}

// TestH2BodyStreaming_AfterGoAwayRedial (T14): a response on a stream that
// opened on a redialed upstream connection (after the first one sent
// GOAWAY) still streams.
func TestH2BodyStreaming_AfterGoAwayRedial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	clientGotPart1 := newGateCh()
	defer clientGotPart1.open()
	origin := startScriptedH2Origin(t, func(conn int, p *h2Peer, req h2Ev) {
		if conn == 1 {
			body := []byte("first connection")
			_ = p.writeHeaders(req.stream, false, okStatus, octetCT,
				hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(body))})
			_ = p.writeData(req.stream, true, body)
			_ = p.writeGoAway(req.stream)
			return
		}
		_ = p.writeHeaders(req.stream, false, okStatus, octetCT)
		_ = p.writeData(req.stream, false, []byte("redialed-part-one"))
		if clientGotPart1.wait(20 * time.Second) {
			_ = p.writeData(req.stream, true, []byte("redialed-part-two"))
		}
	})
	store := &flowStoreForH2Pool{}
	proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{})
	cli := dialH2PeerThroughProxy(t, proxyAddr, origin.addr)
	mustWrite(t, cli.writeHeaders(1, true, requestFields("GET", origin.addr, "/one")...))
	if evs := cli.collectUntilEnd(t, 1, 10*time.Second); len(evs) == 0 || !evs[len(evs)-1].end {
		t.Fatalf("first request: %v", evs)
	}
	mustWrite(t, cli.writeHeaders(3, true, requestFields("GET", origin.addr, "/two")...))
	readUntilData(t, cli, 3, "redialed stream")
	clientGotPart1.open()
	evs := cli.collectUntilEnd(t, 3, 10*time.Second)
	if len(evs) == 0 || !evs[len(evs)-1].end {
		t.Fatalf("redialed stream did not complete: %v", evs)
	}
}

// TestH2BodyStreaming_TCPForwardH2 (T14): the tcp_forwards h2 path streams
// response bodies too.
func TestH2BodyStreaming_TCPForwardH2(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	clientGotPart1 := newGateCh()
	defer clientGotPart1.open()
	origin := startScriptedH2OriginH2C(t, func(_ int, p *h2Peer, req h2Ev) {
		_ = p.writeHeaders(req.stream, false, okStatus, octetCT)
		_ = p.writeData(req.stream, false, []byte("forward-part-one"))
		if clientGotPart1.wait(20 * time.Second) {
			_ = p.writeData(req.stream, true, []byte("forward-part-two"))
		}
	})
	_, fwdAddr, _ := startH2ForwardForRedialTest(t, ctx, config.ForwardConfig{
		Target: origin.addr, Protocol: "http2",
	})
	cli := dialH2PeerDirect(t, fwdAddr)
	mustWrite(t, cli.writeHeaders(1, true,
		hpack.HeaderField{Name: ":method", Value: "GET"},
		hpack.HeaderField{Name: ":scheme", Value: "http"},
		hpack.HeaderField{Name: ":authority", Value: origin.addr},
		hpack.HeaderField{Name: ":path", Value: "/fwd"}))
	readUntilData(t, cli, 1, "tcp_forward h2 stream")
	clientGotPart1.open()
	if evs := cli.collectUntilEnd(t, 1, 10*time.Second); len(evs) == 0 || !evs[len(evs)-1].end {
		t.Fatalf("forward stream did not complete: %v", evs)
	}
}
