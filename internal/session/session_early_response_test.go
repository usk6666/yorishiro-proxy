package session

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// USK-1415: the upstream answers (413) before the proxy finished writing the
// request body, and the body write fails because the upstream reset the
// connection. The request direction ends cleanly — no cascade close of the
// upstream Channel — so the response is still delivered and the session
// ends without error.

// earlyAnswerConn is the proxy's upstream connection: the first Write (the
// request head) passes, every later one fails with ECONNRESET. Read returns
// the canned response only once the gate opened, then EOF.
type earlyAnswerConn struct {
	net.Conn
	writes   atomic.Int32
	gate     chan struct{}
	resp     *strings.Reader
	gateOnce sync.Once
}

func (c *earlyAnswerConn) open() { c.gateOnce.Do(func() { close(c.gate) }) }

func (c *earlyAnswerConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) == 1 {
		return len(p), nil
	}
	return 0, &net.OpError{Op: "write", Net: "tcp", Err: os.NewSyscallError("write", syscall.ECONNRESET)}
}

func (c *earlyAnswerConn) Read(p []byte) (int, error) {
	<-c.gate
	return c.resp.Read(p)
}

// gatedUpstreamChannel opens the conn's gate when the session ends the
// request direction: Close (the error exit's cascade close) or CloseWrite
// (the clean end's half-close). The response is therefore readable only
// after the request direction ended — the order in which the loss happened.
type gatedUpstreamChannel struct {
	layer.Channel
	conn       *earlyAnswerConn
	closeCalls atomic.Int32
}

func (g *gatedUpstreamChannel) Close() error {
	g.closeCalls.Add(1)
	g.conn.open()
	return g.Channel.Close()
}

func (g *gatedUpstreamChannel) CloseWrite() error {
	g.conn.open()
	return nil
}

func streamAllRequests(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode {
	return layer.Stream()
}

// TestRunSession_EarlyResponseAfterBodyWriteReset (T3): the response the
// upstream sent before resetting the connection reaches the client and the
// session ends without error. A streamed request then ends the client
// connection (its body is unfinished); a buffered one keeps it usable.
func TestRunSession_EarlyResponseAfterBodyWriteReset(t *testing.T) {
	const resp413 = "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbig!"
	tests := []struct {
		name     string
		streamed bool
	}{
		{"buffered", false},
		{"streamed", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			browser, proxyClientSide := pipePair()
			proxyUpstreamSide, server := pipePair()
			t.Cleanup(func() {
				_ = browser.Close()
				_ = server.Close()
			})

			var opts []http1.Option
			if tt.streamed {
				opts = append(opts, http1.WithRequestBodyMode(streamAllRequests))
			}
			clientLayer := http1.New(proxyClientSide, "client", envelope.Send, opts...)
			upConn := &earlyAnswerConn{Conn: proxyUpstreamSide, gate: make(chan struct{}), resp: strings.NewReader(resp413)}
			upstreamLayer := http1.New(upConn, "upstream", envelope.Receive)
			t.Cleanup(func() {
				upConn.open()
				_ = clientLayer.Close()
				_ = upstreamLayer.Close()
			})

			body := strings.Repeat("x", 64)
			if tt.streamed {
				// The client sends the head and part of the body, then waits.
				fmt.Fprintf(browser, "POST /upload HTTP/1.1\r\nHost: up.test\r\nContent-Length: %d\r\n\r\n%s", len(body)+1024, body)
			} else {
				fmt.Fprintf(browser, "POST /upload HTTP/1.1\r\nHost: up.test\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			}

			var clientCh layer.Channel
			select {
			case clientCh = <-clientLayer.Channels():
			case <-ctx.Done():
				t.Fatal("no client Channel")
			}
			gated := &gatedUpstreamChannel{conn: upConn}
			dial := func(context.Context, *envelope.Envelope) (layer.Channel, error) {
				gated.Channel = upstreamLayer.OpenExchange()
				if gated.Channel == nil {
					return nil, errors.New("OpenExchange returned nil")
				}
				return gated, nil
			}
			done := make(chan error, 1)
			go func() { done <- RunSession(ctx, clientCh, dial, pipeline.New(passStep{})) }()

			br := bufio.NewReader(browser)
			_ = browser.SetReadDeadline(time.Now().Add(10 * time.Second))
			head, err := readHTTPHead(br)
			if err != nil {
				t.Fatalf("client read %q, then %v; want the upstream's 413", head, err)
			}
			if !strings.HasPrefix(head, "HTTP/1.1 413 ") {
				t.Fatalf("client response head = %q, want the 413", head)
			}
			got := make([]byte, 4)
			if _, err := io.ReadFull(br, got); err != nil || string(got) != "big!" {
				t.Fatalf("client response body = %q (%v), want %q", got, err, "big!")
			}

			select {
			case err := <-done:
				if err != nil {
					t.Errorf("RunSession = %v, want nil (the response arrived)", err)
				}
			case <-ctx.Done():
				t.Fatal("RunSession did not return")
			}

			if tt.streamed {
				rest, err := io.ReadAll(br)
				if err != nil {
					t.Errorf("client read %q, then %v; want its connection ended (EOF)", rest, err)
				}
				return
			}
			_ = browser.SetReadDeadline(time.Time{})
			if _, err := io.WriteString(browser, "GET /next HTTP/1.1\r\nHost: up.test\r\n\r\n"); err != nil {
				t.Fatalf("write next request: %v", err)
			}
			select {
			case ch, ok := <-clientLayer.Channels():
				if !ok {
					t.Fatal("client connection ended after the 413; a buffered request keeps it usable")
				}
				env, err := ch.Next(ctx)
				if err != nil {
					t.Fatalf("next request: %v", err)
				}
				if p := env.Message.(*envelope.HTTPMessage).Path; p != "/next" {
					t.Errorf("next request path = %q, want /next", p)
				}
			case <-ctx.Done():
				t.Fatal("no Channel for the next request")
			}
		})
	}
}

// readHTTPHead reads a header section through the blank line.
func readHTTPHead(br *bufio.Reader) (string, error) {
	var head strings.Builder
	for {
		line, err := br.ReadString('\n')
		head.WriteString(line)
		if err != nil {
			return head.String(), err
		}
		if line == "\r\n" {
			return head.String(), nil
		}
	}
}

// TestRunSession_UpstreamStoppedReadingBody (T9): an upstream Send error
// matching layer.ErrUpstreamStoppedReadingBody ends the request direction
// without an error: nothing more is forwarded, the upstream Channel is not
// cascade-closed while the response is pending, the response is delivered
// and the session ends nil. Any other Send error still fails the session.
func TestRunSession_UpstreamStoppedReadingBody(t *testing.T) {
	tests := []struct {
		name    string
		sendErr error
		wantErr bool
	}{
		{"sentinel", fmt.Errorf("http1: %w: %w", layer.ErrUpstreamStoppedReadingBody, errors.New("stale body write")), false},
		{"other error", errors.New("write error"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientCh := &mockChannel{
				streamID:      "client",
				nextEnvelopes: []*envelope.Envelope{makeEnvelope(envelope.Send, 0), makeEnvelope(envelope.Send, 1)},
			}
			sent := make(chan struct{})
			var sends atomic.Int32
			resp := makeEnvelope(envelope.Receive, 0)
			upstreamCh := &mockChannel{
				streamID:      "upstream",
				nextEnvelopes: []*envelope.Envelope{resp},
				nextGate:      make(chan struct{}, 1),
				sendHook: func(context.Context, *envelope.Envelope) error {
					if sends.Add(1) == 1 {
						close(sent)
					}
					return tt.sendErr
				},
			}
			// Every upstream Next waits until the Send happened: the
			// response, then EOF (the end of the response direction).
			go func() {
				<-sent
				close(upstreamCh.nextGate)
			}()
			dial := func(context.Context, *envelope.Envelope) (layer.Channel, error) { return upstreamCh, nil }

			err := RunSession(context.Background(), clientCh, dial, pipeline.New(passStep{}))
			if tt.wantErr {
				if err == nil || !errors.Is(err, tt.sendErr) {
					t.Errorf("RunSession = %v, want an error wrapping %v", err, tt.sendErr)
				}
				return
			}
			if err != nil {
				t.Errorf("RunSession = %v, want nil", err)
			}
			if n := sends.Load(); n != 1 {
				t.Errorf("upstream Sends = %d, want 1 (the request direction ended)", n)
			}
			got := clientCh.getSent()
			if len(got) != 1 || got[0] != resp {
				t.Errorf("client received %d envelopes, want the upstream response", len(got))
			}
		})
	}
}
