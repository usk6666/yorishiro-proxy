package mcptest

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
)

// GRPCWebHitCounter records how many gRPC-Web method invocations the
// upstream test server actually received. It is the gRPC-Web mirror of
// GRPCHitCounter (see grpc_upstream.go) and follows the same shape so
// per-protocol assertions stay symmetrical between the two test files.
//
// Concurrency: increments happen on the http2.Server handler goroutine;
// reads happen on the test goroutine. Total / PerMethod use atomic loads
// (Total) plus a mutex (PerMethod) for the per-method map.
type GRPCWebHitCounter struct {
	total atomic.Int64

	mu      sync.Mutex
	methods map[string]int64
}

// NewGRPCWebHitCounter constructs an empty counter.
func NewGRPCWebHitCounter() *GRPCWebHitCounter {
	return &GRPCWebHitCounter{methods: make(map[string]int64)}
}

// Total returns the cumulative number of upstream invocations recorded
// by the harness gRPC-Web handler.
func (c *GRPCWebHitCounter) Total() int64 {
	if c == nil {
		return 0
	}
	return c.total.Load()
}

// PerMethod returns the number of invocations for the given path
// (e.g. "/yorishiro.test.WebSafety/Echo"). Zero if the method has not
// been called.
func (c *GRPCWebHitCounter) PerMethod(fullMethod string) int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.methods[fullMethod]
}

// record is invoked from inside the gRPC-Web handler.
func (c *GRPCWebHitCounter) record(fullMethod string) {
	if c == nil {
		return
	}
	c.total.Add(1)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.methods[fullMethod]++
}

// GRPCWebSafetyServiceName is the gRPC-Web service name registered on
// the harness gRPC-Web upstream. The handler accepts requests targeting
// any method under this service, but tests should address
// GRPCWebSafetyEchoMethod for the canonical echo path.
const (
	GRPCWebSafetyServiceName = "yorishiro.test.WebSafety"
	GRPCWebSafetyEchoMethod  = "/" + GRPCWebSafetyServiceName + "/Echo"
)

// buildGRPCWebUpstream stands up a TLS listener (NextProtos=h2) hosting
// a hand-rolled gRPC-Web responder. Unlike buildGRPCUpstream — which
// reuses google.golang.org/grpc's server — gRPC-Web has no canonical
// server library in std, so we drive http2.Server directly with an
// http.Handler that decodes the inbound LPM frames and writes back a
// single data frame plus a trailer frame.
//
// Both binary (`application/grpc-web[+proto]`) and base64/text
// (`application/grpc-web-text[+proto]`) request wire formats are
// accepted; the response is encoded in the same wire form the request
// arrived in (USK-780 acceptance: smoke must exercise both variants).
//
// The returned *httptest.Server is shaped exactly like the one
// buildGRPCUpstream returns (URL, Listener, TLS, no-op Config) so the
// rest of the harness does not need to fork by upstream protocol. The
// custom Listener wrapper drains http2.Server connections on Close.
func buildGRPCWebUpstream() (*httptest.Server, *FingerprintObserver, *GRPCWebHitCounter, error) {
	leafCert, err := newSelfSignedLeaf("localhost", "127.0.0.1")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("self-signed leaf: %w", err)
	}
	base := &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}
	tlsCfg, fpObs := installFingerprintObserver(base)

	hits := NewGRPCWebHitCounter()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept both binary (application/grpc-web[+proto]) and
		// base64/text (application/grpc-web-text[+proto]) wire formats.
		// USK-780 acceptance criterion #4: smoke must exercise both.
		ct := r.Header.Get("Content-Type")
		if !grpcweb.IsGRPCWebContentType(ct) {
			http.Error(w, "mcptest grpc-web upstream: only application/grpc-web[-text] is supported", http.StatusUnsupportedMediaType)
			return
		}
		base64Wire := grpcweb.IsBase64Encoded(ct)

		// Read the request body to completion; the gRPC-Web layer always
		// presents a fully buffered body to the upstream Send (the
		// httpaggregator merges DATA events into a single body). Bound
		// the read at 1 MiB so a misbehaving client cannot exhaust the
		// test goroutine.
		body, rerr := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if rerr != nil {
			http.Error(w, fmt.Sprintf("mcptest grpc-web upstream: read body: %v", rerr), http.StatusBadRequest)
			return
		}

		parsed, perr := grpcweb.DecodeBody(body, base64Wire)
		if perr != nil {
			http.Error(w, fmt.Sprintf("mcptest grpc-web upstream: decode LPM: %v", perr), http.StatusBadRequest)
			return
		}
		if len(parsed.DataFrames) == 0 {
			http.Error(w, "mcptest grpc-web upstream: no data frame", http.StatusBadRequest)
			return
		}

		// Echo back the first data frame's payload.
		reqPayload := parsed.DataFrames[0].Payload

		hits.record(r.URL.Path)

		// Build response: one data frame carrying the echo payload,
		// followed by one trailer frame with grpc-status: 0. Casing of
		// the trailer key is lowercase per RFC 9113 / gRPC spec. The
		// response wire form mirrors the request — base64 in / base64
		// out, binary in / binary out.
		dataFrame := grpcweb.EncodeFrame(false, false, reqPayload)
		trailerText := "grpc-status: 0\r\ngrpc-message: \r\n"
		trailerFrame := grpcweb.EncodeFrame(true, false, []byte(trailerText))
		respBody := append(append([]byte{}, dataFrame...), trailerFrame...)
		respCT := "application/grpc-web+proto"
		if base64Wire {
			respBody = grpcweb.EncodeBase64Body(respBody)
			respCT = "application/grpc-web-text+proto"
		}

		w.Header().Set("Content-Type", respCT)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBody)
	})

	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("listen: %w", err)
	}

	wrapped := &grpcWebListener{
		Listener: tcpLn,
		tlsCfg:   tlsCfg,
		handler:  handler,
		h2s:      &http2.Server{},
	}
	wrapped.acceptDone.Add(1)
	go wrapped.serve()

	srv := &httptest.Server{
		Listener: wrapped,
		// Config must be non-nil because httptest.Server.Close calls
		// s.Config.SetKeepAlivesEnabled. An empty http.Server is a
		// safe no-op recipient.
		Config: &http.Server{},
		URL:    "https://" + tcpLn.Addr().String(),
		TLS:    tlsCfg,
	}
	return srv, fpObs, hits, nil
}

// grpcWebListener wraps a TCP listener with a single Accept goroutine
// that promotes each connection to TLS (h2 ALPN) and serves it via
// http2.Server. Close drains all in-flight connections.
type grpcWebListener struct {
	net.Listener

	tlsCfg  *tls.Config
	handler http.Handler
	h2s     *http2.Server

	acceptDone sync.WaitGroup
	connsWG    sync.WaitGroup
	once       sync.Once
}

func (l *grpcWebListener) serve() {
	defer l.acceptDone.Done()
	for {
		c, aerr := l.Listener.Accept()
		if aerr != nil {
			// Listener.Close was called or another fatal accept error;
			// terminate the accept loop so Close can complete.
			return
		}
		l.connsWG.Add(1)
		go func(raw net.Conn) {
			defer l.connsWG.Done()
			defer raw.Close()
			tlsConn := tls.Server(raw, l.tlsCfg)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			// http2.Server.ServeConn blocks until the connection
			// terminates (either side closes or h2 GOAWAY).
			l.h2s.ServeConn(tlsConn, &http2.ServeConnOpts{Handler: l.handler})
		}(c)
	}
}

func (l *grpcWebListener) Close() error {
	l.once.Do(func() {
		// Close the underlying listener so the accept goroutine exits
		// the next time Accept returns.
		_ = l.Listener.Close()
		l.acceptDone.Wait()
		// Bound the in-flight wait so a hung handler cannot deadlock
		// test cleanup.
		done := make(chan struct{})
		go func() {
			l.connsWG.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			// Fall through — the handler goroutines hold only
			// per-connection state and will be released when their
			// tls.Conn deadline fires.
		}
	})
	return nil
}
