// Package testproxy provides a minimal test proxy for E2E testing of the
// Codec + Pipeline + Session architecture. It is separate from testutil to
// avoid import cycles (testutil is used by internal/flow tests).
package testproxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/codec/http1"
	"github.com/usk6666/yorishiro-proxy/internal/codec/tcp"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/session"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// httpMethods lists the HTTP method prefixes used for protocol detection.
var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("CONNECT "),
	[]byte("TRACE "),
}

// TestProxy is a minimal proxy server for E2E testing. It accepts TCP
// connections, detects the protocol by peeking at the first bytes, and
// routes to the appropriate Codec + Session.
type TestProxy struct {
	Listener net.Listener
	Pipeline *pipeline.Pipeline
	Store    *flow.SQLiteStore

	// CapturedLogs provides access to log output for debugging test failures.
	CapturedLogs *testutil.CaptureLogger

	// TCPTarget is the upstream address for TCP relay mode. It must be set
	// before Start() when testing TCP (non-HTTP) connections.
	TCPTarget string

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a TestProxy backed by a SQLite store in t.TempDir().
// Additional pipeline Steps can be provided; RecordStep is always appended.
func New(t *testing.T, steps ...pipeline.Step) *TestProxy {
	t.Helper()

	dbPath := t.TempDir() + "/test.db"
	capture, logger := testutil.NewCaptureLogger()

	ctx := context.Background()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("testproxy: new sqlite store: %v", err)
	}

	recordStep := pipeline.NewRecordStep(store, logger)
	allSteps := append(steps, recordStep)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		store.Close()
		t.Fatalf("testproxy: listen: %v", err)
	}

	return &TestProxy{
		Listener:     ln,
		Pipeline:     pipeline.New(allSteps...),
		Store:        store,
		CapturedLogs: capture,
	}
}

// Start begins accepting connections in the background. Call Close() to stop.
func (p *TestProxy) Start(ctx context.Context) {
	ctx, p.cancel = context.WithCancel(ctx)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, err := p.Listener.Accept()
			if err != nil {
				return
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				p.handleConn(ctx, conn)
			}()
		}
	}()
}

// Addr returns the listener address (host:port).
func (p *TestProxy) Addr() string {
	return p.Listener.Addr().String()
}

// Close shuts down the proxy, waiting for active connections to finish.
func (p *TestProxy) Close() {
	p.Listener.Close()
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()
	p.Store.Close()
}

// handleConn peeks at the first bytes to detect protocol, then runs a session.
func (p *TestProxy) handleConn(ctx context.Context, conn net.Conn) {
	connID := proxy.GenerateConnID()
	ctx = proxy.ContextWithConnID(ctx, connID)

	buf := make([]byte, 8)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return
	}
	peeked := buf[:n]

	prefixed := newPrefixConn(conn, peeked)

	if isHTTP(peeked) {
		p.handleHTTP(ctx, prefixed)
	} else {
		p.handleTCP(ctx, prefixed)
	}
}

// handleHTTP creates an HTTP/1.x Codec pair and runs a session.
func (p *TestProxy) handleHTTP(ctx context.Context, conn net.Conn) {
	clientCodec := http1.NewCodec(conn, http1.ClientRole)

	dial := func(ctx context.Context, ex *exchange.Exchange) (codec.Codec, error) {
		return dialHTTP(ex)
	}

	onComplete := func(ctx context.Context, streamID string, sessionErr error) {
		state := "complete"
		if sessionErr != nil {
			state = "error"
		}
		if streamID != "" {
			_ = p.Store.UpdateStream(ctx, streamID, flow.StreamUpdate{State: state})
		}
	}

	_ = session.RunSession(ctx, clientCodec, dial, p.Pipeline, session.SessionOptions{
		OnComplete: onComplete,
	})
}

// handleTCP creates a TCP Codec pair and runs a session.
func (p *TestProxy) handleTCP(ctx context.Context, conn net.Conn) {
	clientCodec := tcp.NewWithStreamID(conn, exchange.Send)

	var upstreamConn net.Conn
	var upstreamMu sync.Mutex

	target := p.TCPTarget
	dial := func(ctx context.Context, ex *exchange.Exchange) (codec.Codec, error) {
		if target == "" {
			return nil, fmt.Errorf("testproxy: TCP target not configured")
		}
		upstream, err := net.Dial("tcp", target)
		if err != nil {
			return nil, fmt.Errorf("testproxy: dial tcp %s: %w", target, err)
		}
		upstreamMu.Lock()
		upstreamConn = upstream
		upstreamMu.Unlock()
		return tcp.New(upstream, ex.StreamID, exchange.Receive), nil
	}

	// Close upstream connection when context is cancelled to unblock
	// blocking reads in the upstream Codec.
	go func() {
		<-ctx.Done()
		upstreamMu.Lock()
		if upstreamConn != nil {
			upstreamConn.Close()
		}
		upstreamMu.Unlock()
	}()

	onComplete := func(ctx context.Context, streamID string, sessionErr error) {
		state := "complete"
		if sessionErr != nil {
			state = "error"
		}
		if streamID != "" {
			_ = p.Store.UpdateStream(ctx, streamID, flow.StreamUpdate{State: state})
		}
	}

	_ = session.RunSession(ctx, clientCodec, dial, p.Pipeline, session.SessionOptions{
		OnComplete: onComplete,
	})
}

// isHTTP checks whether the peeked bytes look like an HTTP request.
func isHTTP(peeked []byte) bool {
	for _, m := range httpMethods {
		if bytes.HasPrefix(peeked, m) {
			return true
		}
	}
	return false
}

// prefixConn replays peeked bytes before reading from the underlying conn.
type prefixConn struct {
	net.Conn
	prefix []byte
	offset int
}

func newPrefixConn(conn net.Conn, prefix []byte) *prefixConn {
	return &prefixConn{Conn: conn, prefix: prefix}
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if c.offset < len(c.prefix) {
		n := copy(p, c.prefix[c.offset:])
		c.offset += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// dialHTTP dials the upstream host from the Exchange URL and returns an
// HTTP/1.x Codec in UpstreamRole.
func dialHTTP(ex *exchange.Exchange) (*http1.Codec, error) {
	if ex.URL == nil {
		return nil, fmt.Errorf("testproxy: HTTP dial requires URL in Exchange")
	}
	host := ex.URL.Host
	if !hasPort(host) {
		if ex.URL.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	conn, err := net.Dial("tcp", host)
	if err != nil {
		return nil, fmt.Errorf("testproxy: dial %s: %w", host, err)
	}
	return http1.NewCodec(conn, http1.UpstreamRole), nil
}

// hasPort reports whether host contains a port number.
func hasPort(host string) bool {
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return true
		}
		if host[i] == ']' {
			return false
		}
	}
	return false
}
