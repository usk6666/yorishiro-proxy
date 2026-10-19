package http1

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// USK-1181: when the client-facing Layer closes a connection while reading a
// request head (header deadline with bytes received, 414, 431), Channel.Next
// must surface a *RequestHeadError carrying the received bytes instead of a
// bare io.EOF, so the consumer can record it. A zero-byte keep-alive idle
// expiry must not.

const usk1181KeepAliveReq1 = "GET /one HTTP/1.1\r\nHost: example.com\r\n\r\n"

// nextOnRequestN returns the Channel for request n (1-based) on l. Earlier
// requests must parse successfully; their Channels are closed.
func nextOnRequestN(t *testing.T, l *Layer, n int) nextResult {
	t.Helper()
	for i := 1; i < n; i++ {
		ch := recvChannel(t, l, 2*time.Second)
		r := <-nextAsync(ch)
		if r.err != nil {
			t.Fatalf("request %d: %v", i, r.err)
		}
		_ = ch.Close()
	}
	var ch layer.Channel
	select {
	case c, ok := <-l.Channels():
		if !ok {
			return nextResult{err: io.EOF}
		}
		ch = c
	case <-time.After(5 * time.Second):
		t.Fatalf("no Channel for request %d", n)
	}
	select {
	case r := <-nextAsync(ch):
		return r
	case <-time.After(5 * time.Second):
		t.Fatalf("Next on request %d did not return", n)
	}
	return nextResult{}
}

func asRequestHeadError(t *testing.T, err error) *RequestHeadError {
	t.Helper()
	if err == nil {
		t.Fatal("Next err = nil, want a *RequestHeadError")
	}
	var rhe *RequestHeadError
	if !errors.As(err, &rhe) {
		t.Fatalf("Next err = %v (%T), want *RequestHeadError", err, err)
	}
	return rhe
}

func TestChannelNext_RequestHeadTimeout_ReturnsRequestHeadError(t *testing.T) {
	cases := []struct {
		name       string
		requestN   int
		partial    string
		wantPhase  string
		wantMethod string
		wantTarget string
	}{
		{name: "first request headers", requestN: 1,
			partial:   "GET /x?y=1 HTTP/1.1\r\nHost: example.com\r\nX-Pa",
			wantPhase: RequestHeadPhaseHeaders, wantMethod: "GET", wantTarget: "/x?y=1"},
		{name: "first request line", requestN: 1,
			partial: "GET /x", wantPhase: RequestHeadPhaseRequestLine},
		{name: "keep-alive second request", requestN: 2,
			partial:   "POST /two HTTP/1.1\r\nHost: example.com\r\nContent-Le",
			wantPhase: RequestHeadPhaseHeaders, wantMethod: "POST", wantTarget: "/two"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testConn(t)
			defer client.Close()
			defer server.Close()

			const headerTimeout = 200 * time.Millisecond
			l := New(server, "s", envelope.Send,
				WithScheme("https"),
				WithRequestHeaderTimeout(constDuration(headerTimeout)),
				WithKeepAliveIdleTimeout(constDuration(5*time.Second)))
			defer l.Close()

			if tc.requestN > 1 {
				if _, err := client.Write([]byte(usk1181KeepAliveReq1)); err != nil {
					t.Fatal(err)
				}
				ch := recvChannel(t, l, 2*time.Second)
				if r := <-nextAsync(ch); r.err != nil {
					t.Fatalf("request 1: %v", r.err)
				}
				_ = ch.Close()
			}
			if _, err := client.Write([]byte(tc.partial)); err != nil {
				t.Fatal(err)
			}
			r := nextOnRequestN(t, l, 1)
			if r.env != nil {
				t.Fatalf("Next returned an envelope for a partial request head")
			}
			rhe := asRequestHeadError(t, r.err)
			if rhe.Reason != RequestHeadTimeout {
				t.Errorf("Reason = %q, want %q", rhe.Reason, RequestHeadTimeout)
			}
			if !errors.Is(r.err, os.ErrDeadlineExceeded) {
				t.Errorf("errors.Is(err, os.ErrDeadlineExceeded) = false; err = %v", r.err)
			}
			if string(rhe.Raw) != tc.partial {
				t.Errorf("Raw = %q, want %q", rhe.Raw, tc.partial)
			}
			if rhe.RawTruncated {
				t.Error("RawTruncated = true, want false")
			}
			if rhe.Phase != tc.wantPhase {
				t.Errorf("Phase = %q, want %q", rhe.Phase, tc.wantPhase)
			}
			if rhe.Method != tc.wantMethod || rhe.RequestTarget != tc.wantTarget {
				t.Errorf("request line = %q %q, want %q %q", rhe.Method, rhe.RequestTarget, tc.wantMethod, tc.wantTarget)
			}
			if rhe.Timeout != headerTimeout {
				t.Errorf("Timeout = %v, want %v", rhe.Timeout, headerTimeout)
			}
			if rhe.Scheme != "https" {
				t.Errorf("Scheme = %q, want https", rhe.Scheme)
			}
			if rhe.ResponseWritten || rhe.Status != 0 || len(rhe.Response) != 0 {
				t.Errorf("timeout carries a response: status=%d written=%v len=%d", rhe.Status, rhe.ResponseWritten, len(rhe.Response))
			}
			if rhe.Started.IsZero() {
				t.Error("Started is zero")
			}
		})
	}
}

// Guard: a keep-alive idle expiry with zero bytes of the next request is a
// normal close and must not be reported as a RequestHeadError.
func TestChannelNext_IdleExpiryZeroBytes_NoRequestHeadError(t *testing.T) {
	for _, requestN := range []int{1, 2} {
		t.Run("request "+string(rune('0'+requestN)), func(t *testing.T) {
			client, server := testConn(t)
			defer client.Close()
			defer server.Close()

			l := New(server, "s", envelope.Send,
				WithRequestHeaderTimeout(constDuration(100*time.Millisecond)),
				WithKeepAliveIdleTimeout(constDuration(200*time.Millisecond)))
			defer l.Close()

			if requestN > 1 {
				if _, err := client.Write([]byte(usk1181KeepAliveReq1)); err != nil {
					t.Fatal(err)
				}
			}
			r := nextOnRequestN(t, l, requestN)
			if r.env != nil {
				t.Fatal("Next returned an envelope from an idle client")
			}
			var rhe *RequestHeadError
			if errors.As(r.err, &rhe) {
				t.Fatalf("idle expiry with zero bytes surfaced a RequestHeadError: %+v", rhe)
			}
		})
	}
}

func TestChannelNext_RequestHeadTooLarge_RespondsAndReturnsError(t *testing.T) {
	SetRejectLingerTimeoutForTest(t, 200*time.Millisecond)
	const capBytes = 1024
	headerSection := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Big: " + strings.Repeat("b", 4<<20) + "\r\n\r\n"

	cases := []struct {
		name       string
		payload    string
		wantReason RequestHeadReason
		wantStatus int
		wantLine   string
		wantPhase  string
		wantSent   error
	}{
		{name: "431 header section", payload: headerSection,
			wantReason: RequestHeadHeaderTooLarge, wantStatus: 431,
			wantLine:  "HTTP/1.1 431 Request Header Fields Too Large\r\n",
			wantPhase: RequestHeadPhaseHeaders, wantSent: parser.ErrHeaderSectionTooLarge},
		{name: "414 request line", payload: overLimitRequestLine(),
			wantReason: RequestHeadLineTooLong, wantStatus: 414,
			wantLine:  "HTTP/1.1 414 URI Too Long\r\n",
			wantPhase: RequestHeadPhaseRequestLine, wantSent: parser.ErrRequestLineTooLong},
	}
	for _, tc := range cases {
		for _, requestN := range []int{1, 2} {
			t.Run(tc.name+"/request "+string(rune('0'+requestN)), func(t *testing.T) {
				client, server := testConn(t)
				defer client.Close()
				defer server.Close()

				l := New(server, "s", envelope.Send, WithMaxRawCaptureSize(capBytes))
				defer l.Close()

				payload := tc.payload
				if requestN > 1 {
					payload = usk1181KeepAliveReq1 + payload
				}
				// Half-close once the upload is done: the post-reject drain
				// then ends at EOF (a clean FIN) instead of waiting out the
				// linger deadline, which stays as an upper bound only.
				go func() {
					_, _ = client.Write([]byte(payload))
					_ = client.(*net.TCPConn).CloseWrite()
				}()

				res := make(chan nextResult, 1)
				go func() { res <- nextOnRequestN(t, l, requestN) }()

				// Request 1 (when present) is never answered, so the reject
				// is the only response on the wire.
				_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
				got, readErr := io.ReadAll(client)
				if readErr != nil {
					t.Errorf("reading the response: %v (want the response then a clean EOF)", readErr)
				}
				if !strings.HasPrefix(string(got), tc.wantLine) {
					t.Fatalf("client read %q, want a response starting %q", truncateForLog(got), tc.wantLine)
				}
				rr, err := parser.ParseResponse(bufio.NewReader(strings.NewReader(string(got))))
				if err != nil {
					t.Fatalf("parse response: %v", err)
				}
				if c := rr.Headers.Get("Connection"); !strings.EqualFold(c, "close") {
					t.Errorf("Connection = %q, want close", c)
				}

				var r nextResult
				select {
				case r = <-res:
				case <-time.After(5 * time.Second):
					t.Fatal("Next did not return")
				}
				rhe := asRequestHeadError(t, r.err)
				if !errors.Is(r.err, tc.wantSent) {
					t.Errorf("errors.Is(err, %v) = false; err = %v", tc.wantSent, r.err)
				}
				if rhe.Reason != tc.wantReason {
					t.Errorf("Reason = %q, want %q", rhe.Reason, tc.wantReason)
				}
				if rhe.Status != tc.wantStatus {
					t.Errorf("Status = %d, want %d", rhe.Status, tc.wantStatus)
				}
				if !rhe.ResponseWritten {
					t.Error("ResponseWritten = false, want true")
				}
				if string(rhe.Response) != string(got) {
					t.Errorf("Response = %q, want the bytes the client read %q", rhe.Response, truncateForLog(got))
				}
				if rhe.Phase != tc.wantPhase {
					t.Errorf("Phase = %q, want %q", rhe.Phase, tc.wantPhase)
				}
				if !rhe.RawTruncated || len(rhe.Raw) != capBytes {
					t.Errorf("Raw = %d bytes truncated=%v, want %d bytes truncated", len(rhe.Raw), rhe.RawTruncated, capBytes)
				}
				if !strings.HasPrefix(tc.payload, string(rhe.Raw)) {
					t.Errorf("Raw is not a prefix of the rejected request (request 1 bytes leaked?): %q", truncateForLog(rhe.Raw))
				}
			})
		}
	}
}
