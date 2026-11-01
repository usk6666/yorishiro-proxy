package http1

import (
	"bufio"
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// USK-1117: on the explicit plain-HTTP forward proxy the upstream request
// is origin-form and carries no Proxy-Connection / Proxy-Authorization,
// while the recording (Envelope.Raw) stays the bytes the client sent.
//
// Every envelope is produced by a real Layer parsing real wire bytes
// (runLineExchange), so opaqueHTTP1 is populated exactly as in
// production. The curl fixture is the request curl 8.14.1 sends for
// `curl -x http://<proxy> http://app.target.test:8080/echo?y2=1`.

const fwdCurlRequest = "GET http://app.target.test:8080/echo?y2=1 HTTP/1.1\r\n" +
	"Host: app.target.test:8080\r\n" +
	"User-Agent: curl/8.14.1\r\n" +
	"Accept: */*\r\n" +
	"Proxy-Connection: Keep-Alive\r\n" +
	"\r\n"

func fwdOpts() []Option { return []Option{WithForwardProxyOriginForm()} }

// TestForwardOriginForm_Send is Test Plan T1 (unit seam), T6, T7 and T9:
// the bytes the upstream-facing Channel writes for a request parsed by a
// forward-proxy ingress Layer, and that EncodeWireBytes (the modified
// variant's Raw) equals them.
func TestForwardOriginForm_Send(t *testing.T) {
	cases := []struct {
		name   string
		req    string
		mutate func(m *envelope.HTTPMessage)
		want   string
	}{
		{
			name: "curl absolute-form with Proxy-Connection",
			req:  fwdCurlRequest,
			want: "GET /echo?y2=1 HTTP/1.1\r\nHost: app.target.test:8080\r\nUser-Agent: curl/8.14.1\r\nAccept: */*\r\n\r\n",
		},
		{
			name: "mixed casing interleaved keeps other headers byte-identical",
			req: "GET http://h.test/p HTTP/1.1\r\nX-A:  1 \r\nproxy-authorization: Basic dTpw\r\nhost: h.test\r\n" +
				"PROXY-CONNECTION: keep-alive\r\nUser-Agent: ua\r\nProxy-Authorization: Basic second\r\n\r\n",
			want: "GET /p HTTP/1.1\r\nX-A:  1 \r\nhost: h.test\r\nUser-Agent: ua\r\n\r\n",
		},
		{
			name: "empty path becomes slash",
			req:  "GET http://h.test HTTP/1.1\r\nHost: h.test\r\n\r\n",
			want: "GET / HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "empty path with query",
			req:  "GET http://h.test?x=1 HTTP/1.1\r\nHost: h.test\r\n\r\n",
			want: "GET /?x=1 HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "OPTIONS empty path becomes asterisk-form",
			req:  "OPTIONS http://h.test:8001 HTTP/1.1\r\nHost: h.test:8001\r\n\r\n",
			want: "OPTIONS * HTTP/1.1\r\nHost: h.test:8001\r\n\r\n",
		},
		{
			name: "OPTIONS empty path with query keeps slash",
			req:  "OPTIONS http://h.test?x=1 HTTP/1.1\r\nHost: h.test\r\n\r\n",
			want: "OPTIONS /?x=1 HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "OPTIONS with path keeps path",
			req:  "OPTIONS http://h.test/ HTTP/1.1\r\nHost: h.test\r\n\r\n",
			want: "OPTIONS / HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "userinfo goes with the prefix",
			req:  "GET http://u:p@h.test/p HTTP/1.1\r\nHost: h.test\r\n\r\n",
			want: "GET /p HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "non-spliceable bare trailing question mark keeps wire tail",
			req:  "GET http://h.test/p? HTTP/1.1\r\nHost: h.test\r\n\r\n",
			want: "GET /p? HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "percent-encoded path is the wire substring",
			req:  "GET http://h.test/a%3Fb%20c?q=x%3Ay HTTP/1.1\r\nHost: h.test\r\n\r\n",
			want: "GET /a%3Fb%20c?q=x%3Ay HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "origin-form with Proxy-Authorization keeps line verbatim",
			req:  "GET /p HTTP/1.1\r\nHost: h.test\r\nProxy-Authorization: Basic dTpw\r\n\r\n",
			want: "GET /p HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "asterisk-form unchanged",
			req:  "OPTIONS * HTTP/1.1\r\nHost: h.test\r\nProxy-Connection: close\r\n\r\n",
			want: "OPTIONS * HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "obs-fold continuation dropped with its Proxy header, kept on others",
			req: "GET http://h.test/p HTTP/1.1\r\nHost: h.test\r\nProxy-Authorization: Basic\r\n  dTpw\r\n" +
				"X-Other: a\r\n\tb\r\n\r\n",
			want: "GET /p HTTP/1.1\r\nHost: h.test\r\nX-Other: a\r\n\tb\r\n\r\n",
		},
		{
			name: "bare LF terminators kept on the header section",
			req:  "GET /p HTTP/1.1\nHost: h.test\nProxy-Connection: x\nX-B: y\n\n",
			want: "GET /p HTTP/1.1\nHost: h.test\nX-B: y\n\n",
		},
		{
			name: "whitespace before colon is not a Proxy header",
			req:  "GET http://h.test/p HTTP/1.1\r\nHost: h.test\r\nProxy-Connection : x\r\n\r\n",
			want: "GET /p HTTP/1.1\r\nHost: h.test\r\nProxy-Connection : x\r\n\r\n",
		},
		{
			name: "duplicate casings both stripped",
			req:  "GET /p HTTP/1.1\r\nproxy-connection: a\r\nHost: h.test\r\nProxy-Connection: b\r\n\r\n",
			want: "GET /p HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "identity body follows the rewritten head",
			req:  "POST http://h.test/p HTTP/1.1\r\nHost: h.test\r\nProxy-Connection: k\r\nContent-Length: 2\r\n\r\nhi",
			want: "POST /p HTTP/1.1\r\nHost: h.test\r\nContent-Length: 2\r\n\r\nhi",
		},
		{
			name: "chunked body framing kept",
			req: "POST http://h.test/c?a=1 HTTP/1.1\r\nhost: h.test\r\nProxy-Connection: k\r\nTransfer-Encoding: chunked\r\n\r\n" +
				"5;e=1\r\nhello\r\n0\r\n\r\n",
			want: "POST /c?a=1 HTTP/1.1\r\nhost: h.test\r\nTransfer-Encoding: chunked\r\n\r\n5;e=1\r\nhello\r\n0\r\n\r\n",
		},
		{
			name:   "changed origin path is not spliced behind the prefix",
			req:    "GET http://h.test/old?q=1 HTTP/1.1\r\nHost: h.test\r\nProxy-Connection: k\r\n\r\n",
			mutate: func(m *envelope.HTTPMessage) { m.Path = "/new" },
			want:   "GET /new?q=1 HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "absolute URI written into path is honoured verbatim",
			req:  "GET http://h.test/old HTTP/1.1\r\nHost: h.test\r\nProxy-Connection: k\r\n\r\n",
			mutate: func(m *envelope.HTTPMessage) {
				m.Path = "http://other.test/x"
			},
			want: "GET http://other.test/x HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name:   "method-only change still origin-form",
			req:    "GET http://h.test/p HTTP/1.1\r\nHost: h.test\r\n\r\n",
			mutate: func(m *envelope.HTTPMessage) { m.Method = "HEAD" },
			want:   "HEAD /p HTTP/1.1\r\nHost: h.test\r\n\r\n",
		},
		{
			name: "header edit re-serializes without Proxy headers",
			req:  "GET http://h.test/p HTTP/1.1\r\nHost: h.test\r\nProxy-Authorization: Basic x\r\nX-A:  1\r\n\r\n",
			mutate: func(m *envelope.HTTPMessage) {
				m.Headers = append(m.Headers, envelope.KeyValue{Name: "X-M", Value: "1"})
			},
			want: "GET /p HTTP/1.1\r\nHost: h.test\r\nX-A:  1\r\nX-M: 1\r\n\r\n",
		},
		{
			name: "Proxy-Authorization added by an edit is still stripped",
			req:  "GET /p HTTP/1.1\r\nHost: h.test\r\n\r\n",
			mutate: func(m *envelope.HTTPMessage) {
				m.Headers = append(m.Headers, envelope.KeyValue{Name: "Proxy-Authorization", Value: "Basic y"},
					envelope.KeyValue{Name: "X-M", Value: "1"})
			},
			want: "GET /p HTTP/1.1\r\nHost: h.test\r\nX-M: 1\r\n\r\n",
		},
		{
			name: "body edit re-serializes without Proxy headers",
			req:  "POST http://h.test/p HTTP/1.1\r\nHost: h.test\r\nProxy-Connection: k\r\nContent-Length: 2\r\n\r\nhi",
			mutate: func(m *envelope.HTTPMessage) {
				m.Body = []byte("bye")
			},
			want: "POST /p HTTP/1.1\r\nHost: h.test\r\nContent-Length: 3\r\n\r\nbye",
		},
		{
			name: "origin-form without Proxy headers is verbatim",
			req:  "GET /p?x HTTP/1.1\r\nHost: h.test\r\nX-A:  1 \r\n\r\n",
			want: "GET /p?x HTTP/1.1\r\nHost: h.test\r\nX-A:  1 \r\n\r\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runLineExchange(t, lineExchange{
				reqWire:   tc.req,
				respWire:  lineRespWire,
				mutateReq: tc.mutate,
				opts:      fwdOpts(),
			})
			if string(res.reqSent) != tc.want {
				t.Errorf("upstream wire:\n got %q\nwant %q", res.reqSent, tc.want)
			}
			if !bytes.Equal(res.reqEncoded, res.reqSent) {
				t.Errorf("EncodeWireBytes = %q, want the bytes sent %q", res.reqEncoded, res.reqSent)
			}
		})
	}
}

// TestForwardOriginForm_DisabledSendsVerbatim: a Layer without the option
// (CONNECT / SOCKS5 inner plaintext, transparent, tcp_forwards, TLS MITM,
// or forward_as_received) relays absolute-form and Proxy-* as received.
func TestForwardOriginForm_DisabledSendsVerbatim(t *testing.T) {
	res := runLineExchange(t, lineExchange{reqWire: fwdCurlRequest, respWire: lineRespWire})
	if string(res.reqSent) != fwdCurlRequest {
		t.Errorf("upstream wire = %q, want verbatim %q", res.reqSent, fwdCurlRequest)
	}
}

// parseForwardRequest parses wire on a forward-proxy ingress Layer and
// returns the request envelope.
func parseForwardRequest(t *testing.T, wire string, opts ...Option) *envelope.Envelope {
	t.Helper()
	peer, side := testConn(t)
	t.Cleanup(func() { _ = peer.Close(); _ = side.Close() })
	l := New(side, "usk-1117-client", envelope.Send, opts...)
	t.Cleanup(func() { _ = l.Close() })
	if _, err := peer.Write([]byte(wire)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	ch := <-l.Channels()
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return env
}

// TestForwardOriginForm_RecordingIsAsReceived is T2 at the Layer seam:
// Envelope.Raw and the L7 view keep absolute-form and Proxy-*.
func TestForwardOriginForm_RecordingIsAsReceived(t *testing.T) {
	env := parseForwardRequest(t, fwdCurlRequest, fwdOpts()...)
	if string(env.Raw) != fwdCurlRequest {
		t.Errorf("Envelope.Raw = %q, want the received bytes %q", env.Raw, fwdCurlRequest)
	}
	msg := env.Message.(*envelope.HTTPMessage)
	found := false
	for _, kv := range msg.Headers {
		if kv.Name == "Proxy-Connection" && kv.Value == "Keep-Alive" {
			found = true
		}
	}
	if !found {
		t.Errorf("Message.Headers = %v, want Proxy-Connection kept in the L7 view", msg.Headers)
	}
}

// TestForwardOriginForm_ZeroCopy is T5: a request that needs no
// conversion is written from rawReq.WireHead itself.
func TestForwardOriginForm_ZeroCopy(t *testing.T) {
	const wire = "GET /p HTTP/1.1\r\nHost: h.test\r\nX-A:  1 \r\n\r\n"
	env := parseForwardRequest(t, wire, fwdOpts()...)
	opaque := env.Opaque.(*opaqueHTTP1)
	head, d := opaqueRequestHead(env.Message.(*envelope.HTTPMessage), opaque)
	if !d.zeroCopy {
		t.Errorf("zeroCopy = false, want true for an origin-form request without Proxy headers")
	}
	if len(head) == 0 || len(opaque.rawReq.WireHead) == 0 || &head[0] != &opaque.rawReq.WireHead[0] {
		t.Errorf("head does not alias rawReq.WireHead (a copy was made)")
	}
	if string(head) != wire {
		t.Errorf("head = %q, want %q", head, wire)
	}
}

// TestForwardOriginForm_ConversionIsNotZeroCopy: a request that needs the
// conversion never aliases WireHead (the parse-time buffer is not mutated).
func TestForwardOriginForm_ConversionIsNotZeroCopy(t *testing.T) {
	env := parseForwardRequest(t, fwdCurlRequest, fwdOpts()...)
	opaque := env.Opaque.(*opaqueHTTP1)
	head, d := opaqueRequestHead(env.Message.(*envelope.HTTPMessage), opaque)
	if d.zeroCopy {
		t.Errorf("zeroCopy = true for an absolute-form request on the forward stack")
	}
	if strings.HasPrefix(string(head), "GET http://") {
		t.Errorf("head = %q, want origin-form", head)
	}
	if string(opaque.rawReq.WireHead) != fwdCurlRequest {
		t.Errorf("WireHead mutated: %q", opaque.rawReq.WireHead)
	}
}

// TestForwardOriginForm_RawWinsVerbatim is T10: plugin msg["raw"] goes
// out byte-for-byte, Proxy-* and absolute-form included.
func TestForwardOriginForm_RawWinsVerbatim(t *testing.T) {
	env := parseForwardRequest(t, fwdCurlRequest, fwdOpts()...)
	env.Raw = []byte(fwdCurlRequest)
	env.RawAuthoritative = true

	upPeer, upSide := testConn(t)
	defer upPeer.Close()
	defer upSide.Close()
	ul := New(upSide, "usk-1117-up", envelope.Receive)
	defer ul.Close()
	ch := ul.OpenExchange()
	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := readExactly(t, upPeer, len(fwdCurlRequest)); string(got) != fwdCurlRequest {
		t.Errorf("wire = %q, want verbatim %q", got, fwdCurlRequest)
	}
}

// parsedHeaders parses "GET / HTTP/1.1\r\n" + section with the real
// parser and returns its headers, or ok=false when it does not parse.
func parsedHeaders(section []byte) (parser.RawHeaders, bool) {
	head := append([]byte("GET / HTTP/1.1\r\n"), section...)
	req, err := parser.ParseRequest(bufio.NewReader(bytes.NewReader(head)))
	if err != nil {
		return nil, false
	}
	return req.Headers, true
}

func isProxyHeaderName(name string) bool {
	return strings.EqualFold(name, "Proxy-Connection") || strings.EqualFold(name, "Proxy-Authorization")
}

// FuzzStripForwardProxyHeaders checks the line filter against the real
// parser: whatever header section the parser accepts, the filtered
// section parses to the same headers minus the Proxy-* ones, and it is
// never longer than the input. It must not panic on any input.
func FuzzStripForwardProxyHeaders(f *testing.F) {
	seeds := []string{
		"Host: h\r\nProxy-Connection: Keep-Alive\r\n\r\n",
		"Host: h\r\nProxy-Authorization: Basic\r\n  dTpw\r\nX-Other: a\r\n\tb\r\n\r\n",
		"Host: h\nProxy-Connection: x\nX-B: y\n\n",
		" orphan\r\nProxy-Connection: x\r\nHost: h\r\n\r\n",
		"Proxy-Connection : x\r\nno-colon-line\r\n\r\n",
		"proxy-connection: a\r\nProxy-Connection: b\r\n\r\n",
		"Host: h\r\nProxy-Connection: x",
		"\r\n",
		"",
		"Proxy-Authorization: a\r\r\n\r\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out := stripForwardProxyHeaders(in)
		if len(out) > len(in) {
			t.Fatalf("output longer than input: %q -> %q", in, out)
		}
		inHdrs, ok := parsedHeaders(in)
		if !ok {
			return
		}
		outHdrs, ok := parsedHeaders(out)
		if !ok {
			t.Fatalf("filtered section no longer parses: %q -> %q", in, out)
		}
		var want parser.RawHeaders
		for _, h := range inHdrs {
			if !isProxyHeaderName(h.Name) {
				want = append(want, h)
			}
		}
		if len(outHdrs) != len(want) {
			t.Fatalf("headers %q -> %q:\n got %+v\nwant %+v", in, out, outHdrs, want)
		}
		for i := range want {
			if outHdrs[i] != want[i] {
				t.Fatalf("header %d: got %+v want %+v (in %q out %q)", i, outHdrs[i], want[i], in, out)
			}
		}
	})
}
