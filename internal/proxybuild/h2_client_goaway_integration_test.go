//go:build e2e && !e2e_smoke

// USK-1174 exhaustive-tier coverage: a GOAWAY the *client* sends to the
// proxy must not cut the client's own in-flight streams. RFC 9113 §6.8:
// last_stream_id names the highest stream initiated by the GOAWAY's
// receiver (here the proxy, which initiates none on the client leg), so a
// browser draining its connection with GOAWAY(0, NO_ERROR) still expects
// every in-flight response. Before USK-1174 the proxy's ServerRole Layer
// applied last_stream_id to the client's streams, failed them as
// "refused", cancelled them upstream, and reset them toward the client.
//
// The origin is an INVENTED frame-level fixture: it answers the request
// HEADERS with a 200 HEADERS frame (no END_STREAM), holds the body until
// the test releases it — after the client's GOAWAY reached the proxy — and
// records every RST_STREAM it receives. It reuses the TLS listener and raw
// h2 client from h2_upstream_refused_integration_test.go.
package proxybuild_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const gatedOriginBody = "body released after client GOAWAY"

// gatedH2Origin is a TLS h2 origin whose response body waits on release.
type gatedH2Origin struct {
	addr    string
	ln      net.Listener
	release chan struct{}
	// headersSent closes once the first response HEADERS was written.
	headersSent     chan struct{}
	headersSentOnce sync.Once
	wg              sync.WaitGroup

	mu    sync.Mutex
	conns []net.Conn
	rsts  []originFrame
}

func startGatedH2Origin(t *testing.T) *gatedH2Origin {
	t.Helper()
	ln := listenTLSH2Origin(t)
	o := &gatedH2Origin{
		addr:        ln.Addr().String(),
		ln:          ln,
		release:     make(chan struct{}),
		headersSent: make(chan struct{}),
	}
	go o.acceptLoop()
	t.Cleanup(o.close)
	return o
}

func (o *gatedH2Origin) acceptLoop() {
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

func (o *gatedH2Origin) close() {
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

func (o *gatedH2Origin) receivedRSTs() []originFrame {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]originFrame(nil), o.rsts...)
}

// serveConn reads frames on a dedicated goroutine (recording RST_STREAM
// while the response is held) and writes from this one; writes from the
// reader goroutine (SETTINGS / PING acks) share writeMu.
func (o *gatedH2Origin) serveConn(c net.Conn) {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	fr := http2.NewFramer(c, c)
	fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	fr.MaxHeaderListSize = 1 << 20
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	var writeMu sync.Mutex
	if err := fr.WriteSettings(); err != nil {
		return
	}

	requests := make(chan uint32, 8)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch ff := f.(type) {
			case *http2.SettingsFrame:
				if !ff.IsAck() {
					writeMu.Lock()
					_ = fr.WriteSettingsAck()
					writeMu.Unlock()
				}
			case *http2.PingFrame:
				if !ff.IsAck() {
					writeMu.Lock()
					_ = fr.WritePing(true, ff.Data)
					writeMu.Unlock()
				}
			case *http2.MetaHeadersFrame:
				select {
				case requests <- ff.StreamID:
				default:
				}
			case *http2.RSTStreamFrame:
				o.mu.Lock()
				o.rsts = append(o.rsts, originFrame{streamID: ff.StreamID, typ: http2.FrameRSTStream, rstCode: ff.ErrCode})
				o.mu.Unlock()
			}
		}
	}()

	for {
		var id uint32
		select {
		case id = <-requests:
		case <-readDone:
			return
		}
		writeMu.Lock()
		buf.Reset()
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/plain"})
		err := fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: buf.Bytes(), EndHeaders: true})
		writeMu.Unlock()
		if err != nil {
			return
		}
		o.headersSentOnce.Do(func() { close(o.headersSent) })
		select {
		case <-o.release:
		case <-readDone:
			return
		case <-time.After(10 * time.Second):
			return
		}
		writeMu.Lock()
		err = fr.WriteData(id, true, []byte(gatedOriginBody))
		writeMu.Unlock()
		if err != nil {
			return
		}
	}
}

// TestH2ClientGoAway_InFlightResponseCompletes is the browser-drain
// scenario: the client sends GOAWAY(0, NO_ERROR) while its stream 1 is
// mid-response (origin sent the response HEADERS, body pending). The response
// must still complete end to end — full body with END_STREAM, no
// RST_STREAM on either leg — and the Stream must record as complete, not
// as refused (the proxy must not invent a refusal the wire never carried).
func TestH2ClientGoAway_InFlightResponseCompletes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startGatedH2Origin(t)
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	cli := dialRawH2ThroughProxy(t, proxyAddr, origin.addr)
	cli.sendGETs(t, origin.addr, 1)

	// Wait until the origin has answered with its response HEADERS, so
	// the GOAWAY lands while stream 1 is mid-response. (The live stack
	// aggregates the H2 response into one HTTPMessage, so the client sees
	// nothing on stream 1 until the body completes.)
	select {
	case <-origin.headersSent:
	case <-time.After(10 * time.Second):
		t.Fatal("origin never received the request")
	}

	// Browser drain: GOAWAY(0) — this client accepts no server-initiated
	// stream; it says nothing about stream 1, which the client opened.
	if err := cli.fr.WriteGoAway(0, http2.ErrCodeNo, nil); err != nil {
		t.Fatalf("write GOAWAY: %v", err)
	}
	// Give the proxy time to act on the GOAWAY before the body exists;
	// pre-USK-1174 it cancelled stream 1 on both legs right here.
	time.Sleep(300 * time.Millisecond)
	close(origin.release)

	res := &rawStreamResult{}
	var body []byte
	_ = cli.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for !res.done() {
		f, err := cli.fr.ReadFrame()
		if err != nil {
			break
		}
		switch ff := f.(type) {
		case *http2.SettingsFrame:
			if !ff.IsAck() {
				_ = cli.fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !ff.IsAck() {
				_ = cli.fr.WritePing(true, ff.Data)
			}
		case *http2.DataFrame:
			if ff.StreamID == 1 {
				body = append(body, ff.Data()...)
				res.ended = ff.StreamEnded()
			}
		case *http2.MetaHeadersFrame:
			if ff.StreamID == 1 {
				res.statuses = append(res.statuses, ff.PseudoValue("status"))
				if ff.StreamEnded() {
					res.ended = true
				}
			}
		case *http2.RSTStreamFrame:
			if ff.StreamID == 1 {
				res.rst, res.rstCode = true, ff.ErrCode
			}
		}
	}
	_ = cli.conn.SetReadDeadline(time.Time{})
	if res.rst {
		t.Errorf("client got RST_STREAM(%v) on stream 1 after its own GOAWAY(0), want the full response", res.rstCode)
	}
	if !res.ended || len(res.statuses) != 1 || res.statuses[0] != "200" || string(body) != gatedOriginBody {
		t.Errorf("client stream 1: statuses=%v ended=%v body=%q, want [200], END_STREAM and %q", res.statuses, res.ended, body, gatedOriginBody)
	}

	waitStreamOutcomes(t, store, map[string]int{"complete/": 1}, 5*time.Second)
	for _, st := range store.Streams() {
		if st.Protocol != "http" {
			t.Errorf("stream %s protocol = %q, want http", st.ID, st.Protocol)
		}
	}
	var sends, receives int
	for _, f := range store.Flows() {
		switch f.Direction {
		case "send":
			sends++
		case "receive":
			receives++
		}
	}
	if sends == 0 || receives == 0 {
		t.Errorf("recorded flows: %d send, %d receive; want both", sends, receives)
	}

	if got := origin.receivedRSTs(); len(got) != 0 {
		t.Errorf("origin received RST_STREAM frames %+v, want none (the client never abandoned stream 1)", got)
	}
}
