package http1

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// USK-1229: an HTTP/1.x exchange whose request was delivered but which never
// got a (complete) final response must end the client connection, and an
// upstream that closes before (or in the middle of) its response must be
// reported as an aborted exchange rather than a clean end.

// expectChannelsClosed fails unless l.Channels() closes without yielding a
// further Channel within a short bound.
func expectChannelsClosed(t *testing.T, l *Layer) {
	t.Helper()
	select {
	case ch, ok := <-l.Channels():
		if !ok {
			return
		}
		env, err := ch.Next(context.Background())
		var path string
		if env != nil {
			if m, mok := env.Message.(*envelope.HTTPMessage); mok {
				path = m.Path
			}
		}
		t.Fatalf("Channels() yielded another exchange (path=%q, err=%v) after an unanswered request; want the connection ended", path, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Channels() still open 2s after an unanswered request; want it closed")
	}
}

// nextRequestPath reads the next Channel's request and returns its path.
func nextRequestPath(t *testing.T, l *Layer) (layer.Channel, string) {
	t.Helper()
	select {
	case ch, ok := <-l.Channels():
		if !ok {
			t.Fatal("Channels() closed; want a further exchange")
		}
		env, err := ch.Next(context.Background())
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		return ch, env.Message.(*envelope.HTTPMessage).Path
	case <-time.After(2 * time.Second):
		t.Fatal("no further Channel within 2s")
	}
	return nil, ""
}

func response(status int, anomalies ...envelope.Anomaly) *envelope.Envelope {
	return &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:    status,
			Headers:   []envelope.KeyValue{{Name: "Content-Length", Value: "0"}},
			Anomalies: anomalies,
		},
	}
}

// TestLayer_Send_UnansweredRequest_EndsConnection covers Test Plan #7: a
// request that was delivered to the consumer but whose Channel closed
// without a response written ends the client connection; a pipelined
// request behind it is never yielded (it would otherwise be answered in
// the unanswered request's place).
func TestLayer_Send_UnansweredRequest_EndsConnection(t *testing.T) {
	cases := []struct {
		name     string
		answered int // leading exchanges answered with 200 before the unanswered one
	}{
		{name: "initial exchange", answered: 0},
		{name: "keep-alive exchange", answered: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testConn(t)
			defer client.Close()
			defer server.Close()

			l := New(server, "conn-1", envelope.Send)
			defer l.Close()

			var reqs strings.Builder
			for i := 0; i < tc.answered; i++ {
				reqs.WriteString("GET /answered HTTP/1.1\r\nHost: example.com\r\n\r\n")
			}
			reqs.WriteString("GET /unanswered HTTP/1.1\r\nHost: example.com\r\n\r\n")
			reqs.WriteString("GET /pipelined HTTP/1.1\r\nHost: example.com\r\n\r\n")
			go func() { _, _ = client.Write([]byte(reqs.String())) }()

			for i := 0; i < tc.answered; i++ {
				ch, path := nextRequestPath(t, l)
				if path != "/answered" {
					t.Fatalf("path = %q, want /answered", path)
				}
				if err := ch.Send(context.Background(), response(200)); err != nil {
					t.Fatalf("Send 200: %v", err)
				}
				_ = ch.Close()
			}

			ch, path := nextRequestPath(t, l)
			if path != "/unanswered" {
				t.Fatalf("path = %q, want /unanswered", path)
			}
			_ = ch.Close()

			expectChannelsClosed(t, l)
		})
	}
}

// TestLayer_Send_FinalResponseRule covers Test Plan #8: only a complete
// final response keeps the keep-alive connection usable. An interim 1xx
// alone, or a final response whose body the upstream truncated, ends it.
func TestLayer_Send_FinalResponseRule(t *testing.T) {
	cases := []struct {
		name      string
		responses []*envelope.Envelope
		wantNext  bool
	}{
		{name: "final 200 keeps the connection", responses: []*envelope.Envelope{response(200)}, wantNext: true},
		{name: "100 then 200 keeps the connection", responses: []*envelope.Envelope{response(100), response(200)}, wantNext: true},
		{name: "only 100 Continue ends the connection", responses: []*envelope.Envelope{response(100)}},
		{
			name: "truncated final response ends the connection",
			responses: []*envelope.Envelope{response(200, envelope.Anomaly{
				Type:   envelope.AnomalyTruncatedBody,
				Detail: "connection closed after 0 of 0 body bytes",
			})},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testConn(t)
			defer client.Close()
			defer server.Close()

			l := New(server, "conn-1", envelope.Send)
			defer l.Close()

			go func() {
				_, _ = client.Write([]byte("GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n" +
					"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n"))
				_, _ = io.Copy(io.Discard, client)
			}()

			ch, _ := nextRequestPath(t, l)
			for _, r := range tc.responses {
				if err := ch.Send(context.Background(), r); err != nil {
					t.Fatalf("Send %d: %v", r.Message.(*envelope.HTTPMessage).Status, err)
				}
			}
			_ = ch.Close()

			if !tc.wantNext {
				expectChannelsClosed(t, l)
				return
			}
			ch2, path := nextRequestPath(t, l)
			if path != "/b" {
				t.Errorf("next path = %q, want /b", path)
			}
			_ = ch2.Close()
		})
	}
}

// upstreamPeer reads one request from c and then writes reply and closes.
func upstreamPeer(c net.Conn, reply string) {
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = c.Close()
			return
		}
		if line == "\r\n" {
			break
		}
	}
	if reply != "" {
		_, _ = c.Write([]byte(reply))
	}
	_ = c.Close()
}

func sendGET(t *testing.T, ch layer.Channel) {
	t.Helper()
	req := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:  "GET",
			Path:    "/",
			Headers: []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
		},
	}
	if err := ch.Send(context.Background(), req); err != nil {
		t.Fatalf("Send request: %v", err)
	}
}

func requireAborted(t *testing.T, err error, wantReason string) {
	t.Helper()
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v (%T), want *layer.StreamError", err, err)
	}
	if se.Code != layer.ErrorAborted {
		t.Errorf("StreamError.Code = %v, want aborted", se.Code)
	}
	if !strings.Contains(se.Reason, wantReason) {
		t.Errorf("StreamError.Reason = %q, want it to contain %q", se.Reason, wantReason)
	}
	if errors.Is(err, io.EOF) {
		t.Errorf("err %v satisfies errors.Is(io.EOF); a missing response must not look like a clean end", err)
	}
}

// TestLayer_Receive_UpstreamClosedBeforeResponse covers Test Plan #9: once a
// request was written, an upstream that closes with no (or only part of a)
// response head is reported as an aborted exchange.
func TestLayer_Receive_UpstreamClosedBeforeResponse(t *testing.T) {
	cases := []struct {
		name  string
		reply string
		// interim is the number of 1xx responses expected before the error.
		interim int
	}{
		{name: "zero bytes", reply: ""},
		{name: "partial status line", reply: "HTTP/1.1 20"},
		{name: "partial header section", reply: "HTTP/1.1 200 OK\r\nContent-Le"},
		{name: "interim response only", reply: "HTTP/1.1 100 Continue\r\n\r\n", interim: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testConn(t)
			defer client.Close()
			defer server.Close()
			go upstreamPeer(server, tc.reply)

			l := New(client, "up-1", envelope.Receive)
			defer l.Close()
			ch := l.OpenExchange()
			sendGET(t, ch)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			for i := 0; i < tc.interim; i++ {
				env, err := ch.Next(ctx)
				if err != nil {
					t.Fatalf("Next interim: %v", err)
				}
				if st := env.Message.(*envelope.HTTPMessage).Status; st != 100 {
					t.Fatalf("interim status = %d, want 100", st)
				}
			}
			_, err := ch.Next(ctx)
			requireAborted(t, err, "upstream closed the connection before sending a response")
		})
	}
}

// TestLayer_Receive_NextWithoutSend_KeepsEOF guards the legacy single-shot
// contract: a Receive Channel that never Sent a request sees io.EOF on a
// peer close (there was no request to answer).
func TestLayer_Receive_NextWithoutSend_KeepsEOF(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	_ = server.Close()

	l := New(client, "up-1", envelope.Receive)
	defer l.Close()
	ch := <-l.Channels()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := ch.Next(ctx)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("Next = %v, want io.EOF", err)
	}
}

// TestLayer_Receive_TruncatedBody covers Test Plan #13: an upstream that
// closes mid-body yields the response exactly as received, tagged with the
// TruncatedBody anomaly, followed by an aborted terminal error. Both the
// in-memory and the disk-spill body paths are covered.
func TestLayer_Receive_TruncatedBody(t *testing.T) {
	const clHead = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
	const chunkedHead = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	cases := []struct {
		name     string
		reply    string
		wantBody string
	}{
		{name: "short content-length", reply: clHead + "0123456789", wantBody: "0123456789"},
		{name: "chunked cut mid-chunk", reply: chunkedHead + "5\r\nhello\r\na\r\nabc", wantBody: "helloabc"},
		{name: "chunked cut before terminal chunk", reply: chunkedHead + "5\r\nhello\r\n", wantBody: "hello"},
		{name: "chunked cut inside chunk-size line", reply: chunkedHead + "5\r\nhello\r\n1", wantBody: "hello"},
	}
	spills := []struct {
		name string
		opts []Option
	}{
		{name: "memory"},
		{name: "spill", opts: []Option{WithBodySpillThreshold(4), WithBodySpillDir(t.TempDir())}},
	}
	for _, sp := range spills {
		for _, tc := range cases {
			t.Run(sp.name+"/"+tc.name, func(t *testing.T) {
				client, server := testConn(t)
				defer client.Close()
				defer server.Close()
				go upstreamPeer(server, tc.reply)

				l := New(client, "up-1", envelope.Receive, sp.opts...)
				defer l.Close()
				ch := l.OpenExchange()
				sendGET(t, ch)

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				env, err := ch.Next(ctx)
				if err != nil {
					t.Fatalf("Next: %v; want the truncated response delivered", err)
				}
				msg := env.Message.(*envelope.HTTPMessage)
				body := msg.Body
				if msg.BodyBuffer != nil {
					b, berr := msg.BodyBuffer.Bytes(ctx)
					if berr != nil {
						t.Fatalf("BodyBuffer.Bytes: %v", berr)
					}
					body = b
				}
				if string(body) != tc.wantBody {
					t.Errorf("body = %q, want %q", body, tc.wantBody)
				}
				wire, werr := env.WireBytes(ctx)
				if werr != nil {
					t.Fatalf("WireBytes: %v", werr)
				}
				if !bytes.Equal(wire, []byte(tc.reply)) {
					t.Errorf("wire bytes = %q, want exactly what the upstream sent %q", wire, tc.reply)
				}
				if !hasAnomaly(msg, envelope.AnomalyTruncatedBody) {
					t.Errorf("anomalies = %+v, want %s", msg.Anomalies, envelope.AnomalyTruncatedBody)
				}

				_, err = ch.Next(ctx)
				requireAborted(t, err, "upstream closed the connection mid-body")
			})
		}
	}
}

// TestLayer_Receive_CompleteBody_NoTruncation guards the complete-body
// paths: no anomaly and a clean end after the response.
func TestLayer_Receive_CompleteBody_NoTruncation(t *testing.T) {
	cases := []struct{ name, reply string }{
		{name: "content-length", reply: "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"},
		{name: "chunked", reply: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"},
		{name: "close-delimited", reply: "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testConn(t)
			defer client.Close()
			defer server.Close()
			go upstreamPeer(server, tc.reply)

			l := New(client, "up-1", envelope.Receive)
			defer l.Close()
			ch := l.OpenExchange()
			sendGET(t, ch)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			env, err := ch.Next(ctx)
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			msg := env.Message.(*envelope.HTTPMessage)
			if hasAnomaly(msg, envelope.AnomalyTruncatedBody) {
				t.Errorf("complete body flagged %s", envelope.AnomalyTruncatedBody)
			}
			if _, err := ch.Next(ctx); !errors.Is(err, io.EOF) {
				t.Errorf("second Next = %v, want io.EOF", err)
			}
		})
	}
}

// TestLayer_Send_TruncatedRequestBody_RecordsAnomaly is the request-side
// twin: a client that closes mid-body yields a request tagged with the
// TruncatedBody anomaly carrying exactly the bytes received.
func TestLayer_Send_TruncatedRequestBody_RecordsAnomaly(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "conn-1", envelope.Send)
	defer l.Close()

	go func() {
		_, _ = client.Write([]byte("POST /p HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\n\r\n0123456789"))
		_ = client.(*net.TCPConn).CloseWrite()
	}()

	ch, _ := nextRequestPathEnv(t, l)
	defer ch.ch.Close()
	msg := ch.env.Message.(*envelope.HTTPMessage)
	if string(msg.Body) != "0123456789" {
		t.Errorf("body = %q, want the 10 received bytes", msg.Body)
	}
	if !hasAnomaly(msg, envelope.AnomalyTruncatedBody) {
		t.Errorf("anomalies = %+v, want %s", msg.Anomalies, envelope.AnomalyTruncatedBody)
	}
}

type chEnv struct {
	ch  layer.Channel
	env *envelope.Envelope
}

func nextRequestPathEnv(t *testing.T, l *Layer) (chEnv, string) {
	t.Helper()
	select {
	case ch, ok := <-l.Channels():
		if !ok {
			t.Fatal("Channels() closed")
		}
		env, err := ch.Next(context.Background())
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		return chEnv{ch: ch, env: env}, env.Message.(*envelope.HTTPMessage).Path
	case <-time.After(2 * time.Second):
		t.Fatal("no Channel within 2s")
	}
	return chEnv{}, ""
}

// answerOKWire is what answerOK writes on the wire.
const answerOKWire = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

// answerOK writes a bodiless 200 response on a Send-direction exchange
// Channel, so a keep-alive test that expects the next request to be parsed
// answers this one first (USK-1229: an unanswered request ends the
// connection). The peer must be reading (net.Pipe writes are synchronous).
func answerOK(t *testing.T, ch layer.Channel) {
	t.Helper()
	if err := ch.Send(context.Background(), response(200)); err != nil {
		t.Fatalf("Send 200: %v", err)
	}
}

func hasAnomaly(msg *envelope.HTTPMessage, typ envelope.AnomalyType) bool {
	for _, a := range msg.Anomalies {
		if a.Type == typ {
			return true
		}
	}
	return false
}
