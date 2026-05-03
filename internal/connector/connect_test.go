package connector

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// pipeConn creates a synchronous net.Conn pair for in-memory tests.
func pipeConn() (clientSide, proxySide net.Conn) {
	return net.Pipe()
}

func TestCONNECTNegotiator_Success(t *testing.T) {
	client, proxySide := pipeConn()
	defer client.Close()
	defer proxySide.Close()

	go func() {
		_, _ = client.Write([]byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"))
	}()

	pc := NewPeekConn(proxySide)
	neg := NewCONNECTNegotiator(newTestLogger())

	var (
		target string
		err    error
		done   = make(chan struct{})
	)
	go func() {
		defer close(done)
		target, err = neg.Negotiate(context.Background(), pc)
	}()

	// Read the proxy's reply from the client side.
	buf := make([]byte, 128)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := client.Read(buf)
	reply := string(buf[:n])

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Negotiate did not complete")
	}

	if err != nil {
		t.Fatalf("Negotiate error: %v", err)
	}
	if target != "example.com:443" {
		t.Errorf("target = %q, want example.com:443", target)
	}
	if !strings.HasPrefix(reply, "HTTP/1.1 200") {
		t.Errorf("reply = %q, want HTTP/1.1 200 ...", reply)
	}
}

func TestCONNECTNegotiator_MalformedMethod(t *testing.T) {
	client, proxySide := pipeConn()
	defer client.Close()
	defer proxySide.Close()

	go func() {
		_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	}()

	pc := NewPeekConn(proxySide)
	neg := NewCONNECTNegotiator(newTestLogger())

	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err = neg.Negotiate(context.Background(), pc)
	}()
	go io.Copy(io.Discard, client)
	<-done

	if err == nil {
		t.Fatal("expected error for non-CONNECT method, got nil")
	}
}

func TestNormalizeCONNECTTarget(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		host    string
		want    string
		wantErr bool
	}{
		{name: "uri only", uri: "example.com:443", want: "example.com:443"},
		{name: "host header", host: "example.com:443", want: "example.com:443"},
		{name: "missing port", uri: "example.com", wantErr: true},
		{name: "invalid port", uri: "example.com:abc", wantErr: true},
		{name: "zero port", uri: "example.com:0", wantErr: true},
		{name: "crlf", uri: "evil\r\n:443", wantErr: true},
		{name: "ipv6", uri: "[::1]:443", want: "[::1]:443"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &parser.RawRequest{
				RequestURI: tc.uri,
			}
			if tc.host != "" {
				req.Headers = parser.RawHeaders{{Name: "Host", Value: tc.host}}
			}
			got, err := normalizeCONNECTTarget(req)
			if tc.wantErr {
				if err == nil {
					t.Errorf("want error, got target=%q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
