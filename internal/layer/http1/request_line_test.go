package http1

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1148: on the opaque send path a Message-field rewrite of the
// request line (method / path / raw_query) or status line (status /
// status_reason) reaches the wire, unchanged parts stay verbatim, and
// EncodeWireBytes — the modified variant's Raw — equals what Send wrote.
//
// Every envelope here is produced by a real Layer parsing real wire
// bytes, so opaqueHTTP1 is populated exactly as in production.

// snapLine fills the parse-time start-line snapshot on a hand-built
// envelope's Opaque from its Message, as parseRequest / parseResponse /
// buildStreamingResponseEnvelope do, and returns env.
func snapLine(env *envelope.Envelope) *envelope.Envelope {
	o := env.Opaque.(*opaqueHTTP1)
	msg := env.Message.(*envelope.HTTPMessage)
	if o.rawReq != nil {
		o.snapshotRequestLine(msg)
	}
	if o.rawResp != nil {
		o.snapshotStatusLine(msg)
	}
	return env
}

// lineExchange drives one exchange through two real Layers: a
// client-facing Layer parses reqWire, the request (after mutateReq) is
// sent on an upstream-facing Layer, the upstream answers respWire, and
// the response (after mutateResp) is sent back on the client-facing
// Channel. It returns, per direction, the bytes observed on the wire and
// EncodeWireBytes of the envelope that was sent.
type lineExchange struct {
	reqWire, respWire     string
	mutateReq, mutateResp func(m *envelope.HTTPMessage)
}

type lineResult struct {
	reqSent, reqEncoded   []byte
	respSent, respEncoded []byte
}

// rewriteMessage mirrors pipeline applyMutation MutationMessageOnly: a
// shallow envelope copy with a fresh Message; Opaque is kept.
func rewriteMessage(env *envelope.Envelope, mutate func(m *envelope.HTTPMessage)) *envelope.Envelope {
	if mutate == nil {
		return env
	}
	m := *env.Message.(*envelope.HTTPMessage)
	m.Headers = cloneKV(m.Headers)
	mutate(&m)
	next := *env
	next.Message = &m
	return &next
}

// readExactly reads n bytes, then checks no more bytes follow promptly.
func readExactly(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
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

func runLineExchange(t *testing.T, x lineExchange) lineResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var res lineResult

	clientPeer, clientSide := testConn(t)
	defer clientPeer.Close()
	defer clientSide.Close()
	upPeer, upSide := testConn(t)
	defer upPeer.Close()
	defer upSide.Close()

	cl := New(clientSide, "usk-1148-client", envelope.Send)
	defer cl.Close()
	ul := New(upSide, "usk-1148-up", envelope.Receive)
	defer ul.Close()

	if _, err := clientPeer.Write([]byte(x.reqWire)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	cch := <-cl.Channels()
	reqEnv, err := cch.Next(ctx)
	if err != nil {
		t.Fatalf("client Next: %v", err)
	}
	reqEnv = rewriteMessage(reqEnv, x.mutateReq)
	if res.reqEncoded, err = EncodeWireBytes(reqEnv); err != nil {
		t.Fatalf("EncodeWireBytes(request): %v", err)
	}
	uch := ul.OpenExchange()
	if err := uch.Send(ctx, reqEnv); err != nil {
		t.Fatalf("upstream Send: %v", err)
	}
	res.reqSent = readExactly(t, upPeer, len(res.reqEncoded))

	if _, err := upPeer.Write([]byte(x.respWire)); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	respEnv, err := uch.Next(ctx)
	if err != nil {
		t.Fatalf("upstream Next: %v", err)
	}
	respEnv = rewriteMessage(respEnv, x.mutateResp)
	if res.respEncoded, err = EncodeWireBytes(respEnv); err != nil {
		t.Fatalf("EncodeWireBytes(response): %v", err)
	}
	if err := cch.Send(ctx, respEnv); err != nil {
		t.Fatalf("client Send: %v", err)
	}
	res.respSent = readExactly(t, clientPeer, len(res.respEncoded))
	return res
}

const lineRespWire = "HTTP/1.1 200 OK\r\nX-Odd:  v\r\nContent-Length: 2\r\n\r\nok"

const lineChunkedReq = "POST /c?a=1 HTTP/1.1\r\nhost: example.test\r\nX-Odd:  v\r\nTransfer-Encoding: chunked\r\n\r\n5;e=1\r\nhello\r\n0\r\n\r\n"

// TestOpaqueSend_LineRewriteParity covers Test Plan #5: for each kind of
// rewrite, the bytes Send writes equal EncodeWireBytes and carry the
// rewritten line with every other byte of the head preserved.
func TestOpaqueSend_LineRewriteParity(t *testing.T) {
	cases := []struct {
		name     string
		x        lineExchange
		wantReq  string
		wantResp string
	}{
		{
			name: "path only",
			x: lineExchange{
				reqWire:   "GET /p?a=1 HTTP/1.1\r\nhost: example.test\r\nX-Odd:  v\r\n\r\n",
				respWire:  lineRespWire,
				mutateReq: func(m *envelope.HTTPMessage) { m.Path = "/new" },
			},
			wantReq:  "GET /new?a=1 HTTP/1.1\r\nhost: example.test\r\nX-Odd:  v\r\n\r\n",
			wantResp: lineRespWire,
		},
		{
			name: "query removed",
			x: lineExchange{
				reqWire:   "GET /p?a=1 HTTP/1.1\r\nhost: example.test\r\n\r\n",
				respWire:  lineRespWire,
				mutateReq: func(m *envelope.HTTPMessage) { m.RawQuery = "" },
			},
			wantReq:  "GET /p HTTP/1.1\r\nhost: example.test\r\n\r\n",
			wantResp: lineRespWire,
		},
		{
			name: "method and header",
			x: lineExchange{
				reqWire:  "GET /p?a=1 HTTP/1.1\r\nhost: example.test\r\nX-Odd:  v\r\n\r\n",
				respWire: lineRespWire,
				mutateReq: func(m *envelope.HTTPMessage) {
					m.Method = "DELETE"
					m.Headers = append(m.Headers, envelope.KeyValue{Name: "X-Added", Value: "1"})
				},
			},
			wantReq:  "DELETE /p?a=1 HTTP/1.1\r\nhost: example.test\r\nX-Odd:  v\r\nX-Added: 1\r\n\r\n",
			wantResp: lineRespWire,
		},
		{
			name: "path with chunked body kept",
			x: lineExchange{
				reqWire:   lineChunkedReq,
				respWire:  lineRespWire,
				mutateReq: func(m *envelope.HTTPMessage) { m.Path = "/d" },
			},
			wantReq:  strings.Replace(lineChunkedReq, "POST /c?a=1 ", "POST /d?a=1 ", 1),
			wantResp: lineRespWire,
		},
		{
			name: "path with chunked body changed",
			x: lineExchange{
				reqWire:  lineChunkedReq,
				respWire: lineRespWire,
				mutateReq: func(m *envelope.HTTPMessage) {
					m.Path = "/d"
					m.Body = []byte("bye")
				},
			},
			wantReq:  "POST /d?a=1 HTTP/1.1\r\nhost: example.test\r\nX-Odd:  v\r\nContent-Length: 3\r\n\r\nbye",
			wantResp: lineRespWire,
		},
		{
			name: "absolute-form path keeps prefix",
			x: lineExchange{
				reqWire:   "GET http://Example.TEST:80/p?a=1 HTTP/1.1\r\nhost: example.test\r\n\r\n",
				respWire:  lineRespWire,
				mutateReq: func(m *envelope.HTTPMessage) { m.Path = "/new" },
			},
			wantReq:  "GET http://Example.TEST:80/new?a=1 HTTP/1.1\r\nhost: example.test\r\n\r\n",
			wantResp: lineRespWire,
		},
		{
			name: "plugin path with CRLF written verbatim",
			x: lineExchange{
				reqWire:   "GET /p HTTP/1.1\r\nhost: example.test\r\n\r\n",
				respWire:  lineRespWire,
				mutateReq: func(m *envelope.HTTPMessage) { m.Path = "/a HTTP/1.1\r\nHost: x\r\n\r\nGET /b" },
			},
			wantReq:  "GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b HTTP/1.1\r\nhost: example.test\r\n\r\n",
			wantResp: lineRespWire,
		},
		{
			name: "status only",
			x: lineExchange{
				reqWire:    "GET /p HTTP/1.1\r\nhost: example.test\r\n\r\n",
				respWire:   lineRespWire,
				mutateResp: func(m *envelope.HTTPMessage) { m.Status = 404 },
			},
			wantReq:  "GET /p HTTP/1.1\r\nhost: example.test\r\n\r\n",
			wantResp: "HTTP/1.1 404 OK\r\nX-Odd:  v\r\nContent-Length: 2\r\n\r\nok",
		},
		{
			name: "status, reason and header",
			x: lineExchange{
				reqWire:  "GET /p HTTP/1.1\r\nhost: example.test\r\n\r\n",
				respWire: lineRespWire,
				mutateResp: func(m *envelope.HTTPMessage) {
					m.Status = 503
					m.StatusReason = "Busy Now"
					m.Headers = append(m.Headers, envelope.KeyValue{Name: "Retry-After", Value: "1"})
				},
			},
			wantReq:  "GET /p HTTP/1.1\r\nhost: example.test\r\n\r\n",
			wantResp: "HTTP/1.1 503 Busy Now\r\nX-Odd:  v\r\nContent-Length: 2\r\nRetry-After: 1\r\n\r\nok",
		},
		{
			name: "empty reason",
			x: lineExchange{
				reqWire:    "GET /p HTTP/1.1\r\nhost: example.test\r\n\r\n",
				respWire:   lineRespWire,
				mutateResp: func(m *envelope.HTTPMessage) { m.StatusReason = "" },
			},
			wantReq:  "GET /p HTTP/1.1\r\nhost: example.test\r\n\r\n",
			wantResp: "HTTP/1.1 200\r\nX-Odd:  v\r\nContent-Length: 2\r\n\r\nok",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runLineExchange(t, tc.x)
			if string(res.reqSent) != tc.wantReq {
				t.Errorf("request wire = %q, want %q", res.reqSent, tc.wantReq)
			}
			if !bytes.Equal(res.reqSent, res.reqEncoded) {
				t.Errorf("request EncodeWireBytes = %q, differs from wire %q", res.reqEncoded, res.reqSent)
			}
			if string(res.respSent) != tc.wantResp {
				t.Errorf("response wire = %q, want %q", res.respSent, tc.wantResp)
			}
			if !bytes.Equal(res.respSent, res.respEncoded) {
				t.Errorf("response EncodeWireBytes = %q, differs from wire %q", res.respEncoded, res.respSent)
			}
		})
	}
}

// TestOpaqueSend_LineUnchangedKeepsWire covers Test Plan #6 (reverse
// guard): when the line fields equal their wire values the original
// line is re-emitted byte-for-byte — including forms a rebuilt target
// would not reproduce — and a method-only rewrite keeps the target.
func TestOpaqueSend_LineUnchangedKeepsWire(t *testing.T) {
	cases := []struct {
		name    string
		reqWire string
		mutate  func(m *envelope.HTTPMessage)
		want    string
	}{
		{name: "no rewrite, bare query mark", reqWire: "GET /p? HTTP/1.1\r\nhost: x\r\n\r\n",
			want: "GET /p? HTTP/1.1\r\nhost: x\r\n\r\n"},
		{name: "same-value reassignment", reqWire: "GET /p? HTTP/1.1\r\nhost: x\r\n\r\n",
			mutate: func(m *envelope.HTTPMessage) { m.Path, m.RawQuery, m.Method = m.Path+"", m.RawQuery+"", m.Method+"" },
			want:   "GET /p? HTTP/1.1\r\nhost: x\r\n\r\n"},
		{name: "header-only rewrite, bare query mark", reqWire: "GET /p? HTTP/1.1\r\nhost: x\r\n\r\n",
			mutate: func(m *envelope.HTTPMessage) {
				m.Headers = append(m.Headers, envelope.KeyValue{Name: "X-A", Value: "1"})
			},
			want: "GET /p? HTTP/1.1\r\nhost: x\r\nX-A: 1\r\n\r\n"},
		{name: "method-only keeps bare query mark", reqWire: "GET /p? HTTP/1.1\r\nhost: x\r\n\r\n",
			mutate: func(m *envelope.HTTPMessage) { m.Method = "PUT" },
			want:   "PUT /p? HTTP/1.1\r\nhost: x\r\n\r\n"},
		{name: "method-only keeps percent-encoded absolute-form", reqWire: "GET http://x/a%2Fb?q HTTP/1.1\r\nhost: x\r\n\r\n",
			mutate: func(m *envelope.HTTPMessage) { m.Method = "PUT" },
			want:   "PUT http://x/a%2Fb?q HTTP/1.1\r\nhost: x\r\n\r\n"},
		{name: "asterisk-form method-only", reqWire: "OPTIONS * HTTP/1.1\r\nhost: x\r\n\r\n",
			mutate: func(m *envelope.HTTPMessage) { m.Method = "GET" },
			want:   "GET * HTTP/1.1\r\nhost: x\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runLineExchange(t, lineExchange{reqWire: tc.reqWire, respWire: lineRespWire, mutateReq: tc.mutate})
			if string(res.reqSent) != tc.want {
				t.Errorf("request wire = %q, want %q", res.reqSent, tc.want)
			}
			if !bytes.Equal(res.reqSent, res.reqEncoded) {
				t.Errorf("request EncodeWireBytes = %q, differs from wire %q", res.reqEncoded, res.reqSent)
			}
			if string(res.respSent) != lineRespWire {
				t.Errorf("response wire = %q, want unchanged %q", res.respSent, lineRespWire)
			}
		})
	}
}

// TestOpaqueSend_LineOnlyRewriteKeepsHeaderSectionVerbatim (USK-1148
// review F-1): a start-line-only rewrite must not route the header
// section through the lossy RawHeaders re-serialization. Header forms the
// parser folds or reinterprets — obs-fold continuations, orphan
// continuation lines, colon-less lines, bare-LF terminators — must reach
// the wire byte-for-byte after the rewritten line, on Send and in
// EncodeWireBytes alike.
func TestOpaqueSend_LineOnlyRewriteKeepsHeaderSectionVerbatim(t *testing.T) {
	const respFold = "HTTP/1.1 200 OK\r\nX-F:  a\r\n b\r\nContent-Length: 2\r\n\r\nok"
	cases := []struct {
		name       string
		reqWire    string
		respWire   string
		mutateReq  func(m *envelope.HTTPMessage)
		mutateResp func(m *envelope.HTTPMessage)
		wantReq    string
		wantResp   string
	}{
		{
			name:      "path only, obs-fold header",
			reqWire:   "GET /p HTTP/1.1\r\nhost: x\r\nX-F:  a\r\n b\r\n\r\n",
			respWire:  lineRespWire,
			mutateReq: func(m *envelope.HTTPMessage) { m.Path = "/new" },
			wantReq:   "GET /new HTTP/1.1\r\nhost: x\r\nX-F:  a\r\n b\r\n\r\n",
			wantResp:  lineRespWire,
		},
		{
			name:      "method only, orphan continuation line",
			reqWire:   "GET /p HTTP/1.1\r\n orphan\r\nhost: x\r\n\r\n",
			respWire:  lineRespWire,
			mutateReq: func(m *envelope.HTTPMessage) { m.Method = "PUT" },
			wantReq:   "PUT /p HTTP/1.1\r\n orphan\r\nhost: x\r\n\r\n",
			wantResp:  lineRespWire,
		},
		{
			name:      "query only, colon-less header line",
			reqWire:   "GET /p?a=1 HTTP/1.1\r\nhost: x\r\nNoColonHere\r\n\r\n",
			respWire:  lineRespWire,
			mutateReq: func(m *envelope.HTTPMessage) { m.RawQuery = "b=2" },
			wantReq:   "GET /p?b=2 HTTP/1.1\r\nhost: x\r\nNoColonHere\r\n\r\n",
			wantResp:  lineRespWire,
		},
		{
			name:      "path only, bare-LF header terminators",
			reqWire:   "GET /p HTTP/1.1\nhost: x\nX-A: 1\n\n",
			respWire:  lineRespWire,
			mutateReq: func(m *envelope.HTTPMessage) { m.Path = "/q" },
			wantReq:   "GET /q HTTP/1.1\r\nhost: x\nX-A: 1\n\n",
			wantResp:  lineRespWire,
		},
		{
			name:       "status only, obs-fold header",
			reqWire:    "GET /p HTTP/1.1\r\nhost: x\r\n\r\n",
			respWire:   respFold,
			mutateResp: func(m *envelope.HTTPMessage) { m.Status = 404 },
			wantReq:    "GET /p HTTP/1.1\r\nhost: x\r\n\r\n",
			wantResp:   "HTTP/1.1 404 OK\r\nX-F:  a\r\n b\r\nContent-Length: 2\r\n\r\nok",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runLineExchange(t, lineExchange{
				reqWire: tc.reqWire, respWire: tc.respWire,
				mutateReq: tc.mutateReq, mutateResp: tc.mutateResp,
			})
			if string(res.reqSent) != tc.wantReq {
				t.Errorf("request wire = %q, want %q", res.reqSent, tc.wantReq)
			}
			if !bytes.Equal(res.reqSent, res.reqEncoded) {
				t.Errorf("request EncodeWireBytes = %q, differs from wire %q", res.reqEncoded, res.reqSent)
			}
			if string(res.respSent) != tc.wantResp {
				t.Errorf("response wire = %q, want %q", res.respSent, tc.wantResp)
			}
			if !bytes.Equal(res.respSent, res.respEncoded) {
				t.Errorf("response EncodeWireBytes = %q, differs from wire %q", res.respEncoded, res.respSent)
			}
		})
	}
}
