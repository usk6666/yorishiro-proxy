package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/session"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// newTestCA creates a CA with a generated certificate for testing.
func newTestCA(t *testing.T) *cert.CA {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("generate test CA: %v", err)
	}
	return ca
}

// newTestStore creates a SQLite session store for testing.
func newTestStore(t *testing.T) session.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := session.NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// setupTestSession creates a connected MCP client session for testing tools.
// It returns the client session and a cleanup function.
func setupTestSession(t *testing.T, ca *cert.CA, store ...session.Store) *gomcp.ClientSession {
	t.Helper()
	var st0 session.Store
	if len(store) > 0 {
		st0 = store[0]
	}
	return setupTestSessionWithStore(t, ca, st0)
}

// setupTestSessionWithStore creates a connected MCP client session for testing tools
// with a custom session store.
func setupTestSessionWithStore(t *testing.T, ca *cert.CA, store session.Store) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), ca, store, nil)
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs
}

// testEntry is a convenience struct for creating test sessions with send/receive messages.
type testEntry struct {
	Session *session.Session
	Send    *session.Message
	Receive *session.Message
}

// saveTestEntry saves a session with send and receive messages and returns a testEntry.
func saveTestEntry(t *testing.T, store session.Store, sess *session.Session, send *session.Message, recv *session.Message) *testEntry {
	t.Helper()
	ctx := context.Background()
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if send != nil {
		send.SessionID = sess.ID
		if err := store.AppendMessage(ctx, send); err != nil {
			t.Fatalf("AppendMessage(send): %v", err)
		}
	}
	if recv != nil {
		recv.SessionID = sess.ID
		if err := store.AppendMessage(ctx, recv); err != nil {
			t.Fatalf("AppendMessage(recv): %v", err)
		}
	}
	return &testEntry{Session: sess, Send: send, Receive: recv}
}

// stubDetector is a minimal ProtocolDetector for testing.
type stubDetector struct{}

func (d *stubDetector) Detect(_ []byte) proxy.ProtocolHandler { return nil }

// setupTestSessionWithManager creates an MCP client session with a ProxyManager for testing.
func setupTestSessionWithManager(t *testing.T, manager *proxy.Manager) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(context.Background(), nil, nil, manager)
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs
}

// newPermissiveClient returns an HTTP client without SSRF protection,
// suitable for tests that need to connect to localhost echo servers.
func newPermissiveClient() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newEchoServer creates a test HTTP server that echoes back request details as JSON.
func newEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		resp := map[string]any{
			"method":  r.Method,
			"url":     r.URL.String(),
			"headers": r.Header,
			"body":    string(body),
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Echo", "true")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(server.Close)
	return server
}

// testDialer wraps a net.Dialer to satisfy the rawDialer interface for tests.
// It allows connections to localhost (bypassing SSRF protection).
type testDialer struct{}

func (d *testDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
}

// newRawEchoServer creates a TCP server that reads HTTP-like data and echoes back a simple response.
func newRawEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read the request.
				reader := bufio.NewReader(c)
				var reqBuf bytes.Buffer
				for {
					line, err := reader.ReadString('\n')
					reqBuf.WriteString(line)
					if err != nil || strings.TrimSpace(line) == "" {
						break
					}
				}
				// Send a simple response.
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nX-Echo: raw\r\n\r\nhello world"
				c.Write([]byte(resp))
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}
