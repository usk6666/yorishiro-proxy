package http1

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1320: a header section larger than the raw-capture cap must reach
// the next hop byte-identical when nothing modified it. Only the record
// copy (RawBytes / Envelope.Raw) is capped; the wire is sent from the
// complete head. Every envelope here is produced by real Layers parsing
// real wire bytes (fixture shapes after TestChannel_RoundTrip_ZeroCopy and
// TestOpaqueSend_LineOnlyRewriteKeepsHeaderSectionVerbatim).

const overCapSmall = 64

// overCapRequests are request heads that exceed overCapSmall in different
// places: a long header line, a long request-target (the request line
// alone crosses the cap), and an obs-fold continuation beyond the cap.
var overCapRequests = []struct {
	name, wire string
}{
	{"long header line", "POST /p HTTP/1.1\r\nHost: example.test\r\nX-Long: " + strings.Repeat("a", 200) + "\r\nContent-Length: 3\r\n\r\nabc"},
	{"long request-target", "GET /" + strings.Repeat("b", 200) + " HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc"},
	{"obs-fold past the cap", "POST /p HTTP/1.1\r\nHost: example.test\r\nX-Pad: " + strings.Repeat("p", 80) + "\r\nX-Fold:  a\r\n  folded\r\nContent-Length: 3\r\n\r\nabc"},
}

var overCapResponses = []struct {
	name, wire string
}{
	{"long header line", "HTTP/1.1 200 OK\r\nX-Long: " + strings.Repeat("z", 200) + "\r\nContent-Length: 2\r\n\r\nok"},
	{"long reason phrase", "HTTP/1.1 200 " + strings.Repeat("R", 200) + "\r\nContent-Length: 2\r\n\r\nok"},
	{"obs-fold past the cap", "HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("p", 80) + "\r\nX-Fold:  a\r\n  folded\r\nContent-Length: 2\r\n\r\nok"},
}

const overCapSmallReq = "GET /s HTTP/1.1\r\nHost: example.test\r\n\r\n"
const overCapSmallResp = "HTTP/1.1 204 No Content\r\n\r\n"

// overCapResult is what one exchange through two real Layers produced.
type overCapResult struct {
	reqSent, respSent []byte
	reqEnv, respEnv   *envelope.Envelope
}

// runOverCapExchange parses reqWire on a client-facing Layer, sends the
// envelope unmodified on an upstream-facing Layer, answers respWire from
// the upstream peer and sends that response unmodified back to the client.
// Large writes run on their own goroutines because multi-MiB heads fill
// the loopback socket buffers.
func runOverCapExchange(t *testing.T, opts []Option, reqWire, respWire string) overCapResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var res overCapResult

	clientPeer, clientSide := testConn(t)
	defer clientPeer.Close()
	defer clientSide.Close()
	upPeer, upSide := testConn(t)
	defer upPeer.Close()
	defer upSide.Close()

	cl := New(clientSide, "usk-1320-client", envelope.Send, opts...)
	defer cl.Close()
	ul := New(upSide, "usk-1320-up", envelope.Receive, opts...)
	defer ul.Close()

	go func() { _, _ = clientPeer.Write([]byte(reqWire)) }()
	cch := <-cl.Channels()
	reqEnv, err := cch.Next(ctx)
	if err != nil {
		t.Fatalf("client Next: %v", err)
	}
	res.reqEnv = reqEnv
	uch := ul.OpenExchange()
	sendErr := make(chan error, 1)
	go func() { sendErr <- uch.Send(ctx, reqEnv) }()
	res.reqSent = readOverCap(t, upPeer, len(reqWire))
	if err := <-sendErr; err != nil {
		t.Fatalf("upstream Send: %v", err)
	}

	go func() { _, _ = upPeer.Write([]byte(respWire)) }()
	respEnv, err := uch.Next(ctx)
	if err != nil {
		t.Fatalf("upstream Next: %v", err)
	}
	res.respEnv = respEnv
	go func() { sendErr <- cch.Send(ctx, respEnv) }()
	res.respSent = readOverCap(t, clientPeer, len(respWire))
	if err := <-sendErr; err != nil {
		t.Fatalf("client Send: %v", err)
	}
	return res
}

// readOverCap reads up to n bytes (stopping early when the sender stalls),
// then picks up any bytes that follow promptly.
func readOverCap(t *testing.T, c interface {
	io.Reader
	SetReadDeadline(time.Time) error
}, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, n)
	got, _ := io.ReadFull(c, buf)
	buf = buf[:got]
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	extra := make([]byte, 4096)
	if k, _ := c.Read(extra); k > 0 {
		buf = append(buf, extra[:k]...)
	}
	return buf
}

// diffAt describes where got first departs from want.
func diffAt(got, want []byte) string {
	i := 0
	for i < len(got) && i < len(want) && got[i] == want[i] {
		i++
	}
	tail := func(b []byte) []byte {
		return b[i:min(i+40, len(b))]
	}
	return fmt.Sprintf("len(got)=%d len(want)=%d, first difference at %d: got %q, want %q",
		len(got), len(want), i, tail(got), tail(want))
}

// TestOpaqueSend_RequestHeadOverCap_ForwardedByteIdentical (T1).
func TestOpaqueSend_RequestHeadOverCap_ForwardedByteIdentical(t *testing.T) {
	for _, tc := range overCapRequests {
		t.Run(tc.name, func(t *testing.T) {
			res := runOverCapExchange(t, []Option{WithMaxRawCaptureSize(overCapSmall)}, tc.wire, overCapSmallResp)
			if !bytes.Equal(res.reqSent, []byte(tc.wire)) {
				t.Errorf("upstream received a different request: %s", diffAt(res.reqSent, []byte(tc.wire)))
			}
		})
	}
}

// TestOpaqueSend_ResponseHeadOverCap_ForwardedByteIdentical (T2).
func TestOpaqueSend_ResponseHeadOverCap_ForwardedByteIdentical(t *testing.T) {
	for _, tc := range overCapResponses {
		t.Run(tc.name, func(t *testing.T) {
			res := runOverCapExchange(t, []Option{WithMaxRawCaptureSize(overCapSmall)}, overCapSmallReq, tc.wire)
			if !bytes.Equal(res.respSent, []byte(tc.wire)) {
				t.Errorf("client received a different response: %s", diffAt(res.respSent, []byte(tc.wire)))
			}
		})
	}
}

// TestOpaqueSend_DefaultCap_MultiMiBHeadsForwardedByteIdentical (T3): the
// Issue's reproduction at the default 2 MiB cap — a 3 MiB Cookie, a
// request line just over 2 MiB (Chromium's kMaxURLChars is 2 MiB), and a
// 3 MiB Set-Cookie response.
func TestOpaqueSend_DefaultCap_MultiMiBHeadsForwardedByteIdentical(t *testing.T) {
	cookieReq := "GET / HTTP/1.1\r\nHost: example.test\r\nCookie: " + strings.Repeat("c", 3<<20) + "\r\nContent-Length: 3\r\n\r\nabc"
	longLineReq := "GET /" + strings.Repeat("u", 2<<20+20) + " HTTP/1.1\r\nHost: example.test\r\nContent-Length: 3\r\n\r\nabc"
	setCookieResp := "HTTP/1.1 200 OK\r\nSet-Cookie: " + strings.Repeat("s", 3<<20) + "\r\nContent-Length: 2\r\n\r\nok"

	t.Run("3 MiB Cookie request", func(t *testing.T) {
		res := runOverCapExchange(t, nil, cookieReq, overCapSmallResp)
		if !bytes.Equal(res.reqSent, []byte(cookieReq)) {
			t.Errorf("upstream received a different request: %s", diffAt(res.reqSent, []byte(cookieReq)))
		}
	})
	t.Run("2 MiB+20 request line", func(t *testing.T) {
		res := runOverCapExchange(t, nil, longLineReq, overCapSmallResp)
		if !bytes.Equal(res.reqSent, []byte(longLineReq)) {
			t.Errorf("upstream received a different request: %s", diffAt(res.reqSent, []byte(longLineReq)))
		}
	})
	t.Run("3 MiB Set-Cookie response", func(t *testing.T) {
		res := runOverCapExchange(t, nil, overCapSmallReq, setCookieResp)
		if !bytes.Equal(res.respSent, []byte(setCookieResp)) {
			t.Errorf("client received a different response: %s", diffAt(res.respSent, []byte(setCookieResp)))
		}
	})
}

// headOf returns the header section (through CRLFCRLF) of a fixture.
func headOf(t *testing.T, wire string) string {
	t.Helper()
	i := strings.Index(wire, "\r\n\r\n")
	if i < 0 {
		t.Fatalf("fixture has no CRLFCRLF: %q", wire)
	}
	return wire[:i+4]
}

func envAnomalyCount(env *envelope.Envelope, typ envelope.AnomalyType) int {
	n := 0
	for _, a := range env.Message.(*envelope.HTTPMessage).Anomalies {
		if a.Type == typ {
			n++
		}
	}
	return n
}

// TestLayer_HeadOverCap_RecordCappedAndFlagged (T4): the record copy stays
// capped, Envelope.Raw starts with the capped head, the complete head is
// kept for the wire, and the envelope carries RawHeaderTruncated. A head
// within the cap carries no such anomaly.
func TestLayer_HeadOverCap_RecordCappedAndFlagged(t *testing.T) {
	reqWire := overCapRequests[0].wire
	respWire := overCapResponses[0].wire
	res := runOverCapExchange(t, []Option{WithMaxRawCaptureSize(overCapSmall)}, reqWire, respWire)

	rawReq := res.reqEnv.Opaque.(*opaqueHTTP1).rawReq
	rawResp := res.respEnv.Opaque.(*opaqueHTTP1).rawResp
	for _, c := range []struct {
		name      string
		raw       []byte
		wireHead  []byte
		truncated bool
		env       *envelope.Envelope
		wire      string
	}{
		{"request", rawReq.RawBytes, rawReq.WireHead, rawReq.Truncated, res.reqEnv, reqWire},
		{"response", rawResp.RawBytes, rawResp.WireHead, rawResp.Truncated, res.respEnv, respWire},
	} {
		head := headOf(t, c.wire)
		if len(c.raw) != overCapSmall || !c.truncated {
			t.Errorf("%s: len(RawBytes) = %d Truncated = %v, want %d / true", c.name, len(c.raw), c.truncated, overCapSmall)
		}
		if string(c.raw) != head[:overCapSmall] {
			t.Errorf("%s: RawBytes = %q, want wire prefix %q", c.name, c.raw, head[:overCapSmall])
		}
		if string(c.wireHead) != head {
			t.Errorf("%s: WireHead = %q, want complete head %q", c.name, c.wireHead, head)
		}
		if !bytes.HasPrefix(c.env.Raw, []byte(head[:overCapSmall])) {
			t.Errorf("%s: Envelope.Raw does not start with the capped head: %q", c.name, c.env.Raw)
		}
		if bytes.HasPrefix(c.env.Raw, []byte(head)) {
			t.Errorf("%s: Envelope.Raw holds the complete head; the record copy must stay capped", c.name)
		}
		if n := envAnomalyCount(c.env, envelope.AnomalyRawHeaderTruncated); n != 1 {
			t.Errorf("%s: RawHeaderTruncated anomalies = %d, want 1", c.name, n)
		}
	}

	small := runOverCapExchange(t, []Option{WithMaxRawCaptureSize(1024)}, reqWire, respWire)
	for name, env := range map[string]*envelope.Envelope{"request": small.reqEnv, "response": small.respEnv} {
		if n := envAnomalyCount(env, envelope.AnomalyRawHeaderTruncated); n != 0 {
			t.Errorf("%s within cap: RawHeaderTruncated anomalies = %d, want 0", name, n)
		}
	}
	sr := small.reqEnv.Opaque.(*opaqueHTTP1).rawReq
	if !bytes.Equal(sr.RawBytes, sr.WireHead) || sr.Truncated {
		t.Errorf("within cap: RawBytes %q WireHead %q Truncated %v, want equal / false", sr.RawBytes, sr.WireHead, sr.Truncated)
	}
	if !bytes.Equal(small.reqSent, []byte(reqWire)) || !bytes.Equal(small.respSent, []byte(respWire)) {
		t.Errorf("within cap: wire changed (req %s; resp %s)", diffAt(small.reqSent, []byte(reqWire)), diffAt(small.respSent, []byte(respWire)))
	}
}

// TestOpaqueSend_LineOnlyRewrite_OverCapKeepsHeaderSectionVerbatim (T6):
// a start-line-only rewrite on a head past the cap re-emits the header
// section verbatim — including an obs-fold line beyond the cap — and the
// modified variant's Raw (EncodeWireBytes) equals what was sent.
func TestOpaqueSend_LineOnlyRewrite_OverCapKeepsHeaderSectionVerbatim(t *testing.T) {
	pad := "X-Pad: " + strings.Repeat("p", 80) + "\r\n"
	reqWire := "GET /p HTTP/1.1\r\nhost: x\r\n" + pad + "X-F:  a\r\n b\r\n\r\n"
	respWire := "HTTP/1.1 200 OK\r\n" + pad + "X-F:  a\r\n b\r\nContent-Length: 2\r\n\r\nok"
	res := runLineExchange(t, lineExchange{
		reqWire: reqWire, respWire: respWire,
		mutateReq:  func(m *envelope.HTTPMessage) { m.Path = "/new" },
		mutateResp: func(m *envelope.HTTPMessage) { m.Status = 404 },
		opts:       []Option{WithMaxRawCaptureSize(overCapSmall)},
	})
	wantReq := "GET /new HTTP/1.1\r\nhost: x\r\n" + pad + "X-F:  a\r\n b\r\n\r\n"
	wantResp := "HTTP/1.1 404 OK\r\n" + pad + "X-F:  a\r\n b\r\nContent-Length: 2\r\n\r\nok"
	if string(res.reqSent) != wantReq {
		t.Errorf("request wire = %q, want %q", res.reqSent, wantReq)
	}
	if !bytes.Equal(res.reqSent, res.reqEncoded) {
		t.Errorf("request EncodeWireBytes = %q, differs from wire %q", res.reqEncoded, res.reqSent)
	}
	if string(res.respSent) != wantResp {
		t.Errorf("response wire = %q, want %q", res.respSent, wantResp)
	}
	if !bytes.Equal(res.respSent, res.respEncoded) {
		t.Errorf("response EncodeWireBytes = %q, differs from wire %q", res.respEncoded, res.respSent)
	}
}
