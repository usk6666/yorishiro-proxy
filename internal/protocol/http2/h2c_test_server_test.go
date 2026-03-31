package http2

import (
	"context"
	"net"
	gohttp "net/http"
	"testing"
)

// h2cTestServer wraps an h2c server for tests that need HTTP/2 upstream.
// It provides both the net.Listener (for frame-engine tests that need the
// raw address) and a URL string (for recording/subsystem tests that need
// an HTTP URL).
type h2cTestServer struct {
	Listener net.Listener
	URL      string
	cancel   context.CancelFunc
}

func (s *h2cTestServer) Close() {
	s.cancel()
}

// Addr returns the listener address string (host:port).
func (s *h2cTestServer) Addr() string {
	return s.Listener.Addr().String()
}

// newH2CTestServer starts an h2c-capable test server, replacing
// httptest.NewServer for gRPC tests that need HTTP/2 upstream.
func newH2CTestServer(t *testing.T, handler gohttp.Handler) *h2cTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	protos := &gohttp.Protocols{}
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	server := &gohttp.Server{Handler: handler, Protocols: protos}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		if err := server.Serve(ln); err != nil && err != gohttp.ErrServerClosed {
			// Cannot use t.Fatalf from a goroutine; log and let test timeout.
			t.Errorf("h2c test server.Serve: %v", err)
		}
	}()
	go func() { <-ctx.Done(); server.Close() }()
	s := &h2cTestServer{
		Listener: ln,
		URL:      "http://" + ln.Addr().String(),
		cancel:   cancel,
	}
	t.Cleanup(s.Close)
	return s
}
