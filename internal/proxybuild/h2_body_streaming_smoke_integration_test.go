//go:build e2e

// USK-1401 smoke tier: HTTP/2 request and response bodies are forwarded
// while they arrive (RFC-001 §3.2.1 "HTTP body streaming") on the live
// BuildLiveStack CONNECT MITM path, with no rule or plugin that needs them
// whole.
package proxybuild_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	gohttp "net/http"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// makeStreamingBody returns size deterministic bytes.
func makeStreamingBody(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// TestSmoke_H2BodyStreaming_ResponseFirstDataBeforeEndStream (T1): the
// origin writes the first DATA and then waits until the client has read it
// before it sends the rest. A buffered proxy holds the first DATA until
// END_STREAM, so the client never sees it while the origin waits.
func TestSmoke_H2BodyStreaming_ResponseFirstDataBeforeEndStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	chunk1 := bytes.Repeat([]byte("a"), 1000)
	chunk2 := bytes.Repeat([]byte("b"), 3000)
	clientRead := newGateCh()
	defer clientRead.open()
	upAddr, _, upShutdown := startH2TLSUpstreamForPoolTest(t, "localhost", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		_, _ = w.Write(chunk1)
		w.(gohttp.Flusher).Flush()
		clientRead.wait(20 * time.Second)
		_, _ = w.Write(chunk2)
	}))
	defer upShutdown()

	store := &flowStoreForH2Pool{}
	proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{})
	cli := newH2ClientThroughProxyForPoolTest(proxyAddr, upAddr)

	req, _ := gohttp.NewRequestWithContext(ctx, gohttp.MethodGet, "https://"+upAddr+"/stream", nil)
	// The response head and the first chunk must both arrive while the
	// origin is still waiting: a buffering proxy delivers neither (the head
	// waits for END_STREAM too), so the deadline covers Do as well.
	type first struct {
		resp *gohttp.Response
		err  error
	}
	got1 := make(chan first, 1)
	buf := make([]byte, len(chunk1))
	go func() {
		resp, err := cli.Do(req)
		if err != nil {
			got1 <- first{err: err}
			return
		}
		_, err = io.ReadFull(resp.Body, buf)
		got1 <- first{resp: resp, err: err}
	}()
	var resp *gohttp.Response
	select {
	case f := <-got1:
		if f.err != nil {
			t.Fatalf("request / first chunk: %v", f.err)
		}
		resp = f.resp
	case <-time.After(10 * time.Second):
		t.Fatal("the first DATA did not reach the client before the origin's END_STREAM (body buffered)")
	}
	defer resp.Body.Close()
	if !bytes.Equal(buf, chunk1) {
		t.Fatalf("first chunk differs")
	}
	clientRead.open()
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if !bytes.Equal(rest, chunk2) {
		t.Fatalf("rest of the body = %d bytes, want %d", len(rest), len(chunk2))
	}
	waitStreamOutcomes(t, store, map[string]int{"complete/": 1}, 10*time.Second)
}

// TestSmoke_H2BodyStreaming_RequestFirstDataBeforeClientSendsRest (T2): the
// client sends the first part of the request body and waits until the
// origin has read it before it sends the rest.
func TestSmoke_H2BodyStreaming_RequestFirstDataBeforeClientSendsRest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	part1 := bytes.Repeat([]byte("p"), 2000)
	part2 := bytes.Repeat([]byte("q"), 5000)
	originGotPart1 := newGateCh()
	gotRest := make(chan []byte, 1)
	upAddr, _, upShutdown := startH2TLSUpstreamForPoolTest(t, "localhost", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		b := make([]byte, len(part1))
		if _, err := io.ReadFull(r.Body, b); err != nil || !bytes.Equal(b, part1) {
			w.WriteHeader(500)
			return
		}
		originGotPart1.open()
		rest, _ := io.ReadAll(r.Body)
		gotRest <- rest
		w.WriteHeader(200)
	}))
	defer upShutdown()

	store := &flowStoreForH2Pool{}
	proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{})
	cli := newH2ClientThroughProxyForPoolTest(proxyAddr, upAddr)

	pr, pw := io.Pipe()
	defer pw.Close()
	req, _ := gohttp.NewRequestWithContext(ctx, gohttp.MethodPost, "https://"+upAddr+"/upload", pr)
	type result struct {
		status int
		err    error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := cli.Do(req)
		if err != nil {
			done <- result{err: err}
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		done <- result{status: resp.StatusCode}
	}()

	go func() { _, _ = pw.Write(part1) }()
	if !originGotPart1.wait(10 * time.Second) {
		t.Fatal("the origin did not receive the first part of the request body while the client held the rest (body buffered)")
	}
	if _, err := pw.Write(part2); err != nil {
		t.Fatalf("write part 2: %v", err)
	}
	pw.Close()

	select {
	case rest := <-gotRest:
		if !bytes.Equal(rest, part2) {
			t.Errorf("origin read %d more bytes, want %d", len(rest), len(part2))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("origin never read the rest of the body")
	}
	select {
	case r := <-done:
		if r.err != nil || r.status != 200 {
			t.Fatalf("client: status=%d err=%v, want 200", r.status, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("client never got the response")
	}
	waitStreamOutcomes(t, store, map[string]int{"complete/": 1}, 10*time.Second)
}

// TestSmoke_H2BodyStreaming_OverMaxBodySizeBothDirections (T4): bodies over
// max_body_size reach the peer whole in both directions when nothing needs
// them whole; the recorded copies are cut at max_record_body_size and marked,
// and the Stream completes.
func TestSmoke_H2BodyStreaming_OverMaxBodySizeBothDirections(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const (
		maxBody   = 512 << 10
		recordCap = 64 << 10
		bodySize  = 1 << 20
	)
	reqBody := makeStreamingBody(bodySize)
	respBody := makeStreamingBody(bodySize)
	respBody[0] = 'R'
	upReqHash := make(chan [32]byte, 1)
	upAddr, _, upShutdown := startH2TLSUpstreamForPoolTest(t, "localhost", gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		b, _ := io.ReadAll(r.Body)
		upReqHash <- sha256.Sum256(b)
		w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
		_, _ = w.Write(respBody)
	}))
	defer upShutdown()

	store := &flowStoreForH2Pool{}
	proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{
		maxBody: maxBody, recordCap: recordCap, spillDir: t.TempDir(),
	})
	cli := newH2ClientThroughProxyForPoolTest(proxyAddr, upAddr)
	req, _ := gohttp.NewRequestWithContext(ctx, gohttp.MethodPost, "https://"+upAddr+"/big", bytes.NewReader(reqBody))
	req.ContentLength = int64(len(reqBody))
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	got, rerr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if rerr != nil {
		t.Fatalf("read response after %d bytes: %v", len(got), rerr)
	}
	if sha256.Sum256(got) != sha256.Sum256(respBody) {
		t.Errorf("client got %d response bytes that differ from the %d-byte upstream body", len(got), len(respBody))
	}
	select {
	case h := <-upReqHash:
		if h != sha256.Sum256(reqBody) {
			t.Error("upstream request body differs from the client's")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never read the request")
	}

	waitStreamOutcomes(t, store, map[string]int{"complete/": 1}, 10*time.Second)
	for _, dir := range []string{"send", "receive"} {
		fl := waitSemanticFlow(t, store, dir, 5*time.Second)
		want := reqBody
		if dir == "receive" {
			want = respBody
		}
		if !fl.BodyTruncated || len(fl.Body) != recordCap {
			t.Errorf("%s flow body = %d bytes truncated=%v, want %d truncated", dir, len(fl.Body), fl.BodyTruncated, recordCap)
		}
		if !bytes.Equal(fl.Body, want[:len(fl.Body)]) {
			t.Errorf("%s flow body is not the leading bytes of the body", dir)
		}
		if fl.Metadata["http_anomaly_raw_body_truncated"] == "" {
			t.Errorf("%s flow metadata lacks http_anomaly_raw_body_truncated: %v", dir, fl.Metadata)
		}
		if len(fl.RawBytes) > recordCap {
			t.Errorf("%s flow raw bytes = %d, want <= %d", dir, len(fl.RawBytes), recordCap)
		}
	}
}

// TestSmoke_H2BodyStreaming_UpstreamResetMidBody (T7): the origin resets the
// stream after part of a streamed response body. The client receives the
// DATA the origin sent, then RST_STREAM with the origin's exact code; the
// Stream ends in error and the partial body is recorded as truncated.
func TestSmoke_H2BodyStreaming_UpstreamResetMidBody(t *testing.T) {
	part1 := []byte("first part of the body")
	part2 := []byte("second part, then a reset")
	for _, code := range []http2.ErrCode{http2.ErrCodeEnhanceYourCalm, http2.ErrCode(0x1234)} {
		t.Run(code.String(), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			clientGotPart1 := newGateCh()
			defer clientGotPart1.open()
			origin := startScriptedH2Origin(t, func(_ int, p *h2Peer, req h2Ev) {
				_ = p.writeHeaders(req.stream, false,
					hpack.HeaderField{Name: ":status", Value: "200"},
					hpack.HeaderField{Name: "content-type", Value: "application/octet-stream"})
				_ = p.writeData(req.stream, false, part1)
				if !clientGotPart1.wait(20 * time.Second) {
					return
				}
				_ = p.writeData(req.stream, false, part2)
				_ = p.writeRST(req.stream, code)
			})
			store := &flowStoreForH2Pool{}
			proxyAddr := startH2StreamProxy(t, ctx, store, h2StreamProxyOpts{})

			cli := dialH2PeerThroughProxy(t, proxyAddr, origin.addr)
			mustWrite(t, cli.writeHeaders(1, true, requestFields("GET", origin.addr, "/reset")...))

			var evs []h2Ev
			for {
				ev, ok := cli.next(t, 1, 10*time.Second)
				if !ok {
					t.Fatalf("no DATA reached the client before the origin's reset (events so far: %v)", evs)
				}
				evs = append(evs, ev)
				if ev.kind == "rst" {
					t.Fatalf("client got %v before any DATA (events: %v)", ev, evs)
				}
				if ev.kind == "data" {
					break
				}
			}
			clientGotPart1.open()
			evs = append(evs, cli.collectUntilEnd(t, 1, 10*time.Second)...)

			body, _ := dataPayloads(evs)
			if want := append(append([]byte(nil), part1...), part2...); !bytes.Equal(body, want) {
				t.Errorf("client DATA = %q, want %q", body, want)
			}
			last := evs[len(evs)-1]
			if last.kind != "rst" || last.code != code {
				t.Fatalf("stream ended with %v, want RST_STREAM(%v); events: %v", last, code, evs)
			}
			for _, ev := range evs {
				if ev.end {
					t.Errorf("client saw END_STREAM (%v) on a reset stream", ev)
				}
			}

			waitStreamOutcomes(t, store, map[string]int{"error/aborted": 1}, 10*time.Second)
			recv := waitSemanticFlow(t, store, "receive", 5*time.Second)
			if want := append(append([]byte(nil), part1...), part2...); !bytes.Equal(recv.Body, want) {
				t.Errorf("recorded receive body = %q, want %q", recv.Body, want)
			}
			if recv.Metadata["http_anomaly_truncated_body"] == "" {
				t.Errorf("receive flow metadata lacks http_anomaly_truncated_body: %v", recv.Metadata)
			}
		})
	}
}
