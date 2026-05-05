//go:build e2e

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-635 — N6.5 acceptance gate for MCP tool surface.
//
// Proves that a 25 MiB response body round-trips through the RFC-001 pipeline
// (http1 layer → rules/pipeline RecordStep materialize → SQLite flow.Store),
// and that the MCP `query` tool serves the full body back with the correct
// base64 encoding and `response_body_truncated` flag.
//
// Two subtests:
//   - full_body_below_cap: RecordStep MaxBodySize = config.MaxBodySize (default
//     254 MiB). 25 MiB fits under the cap → ResponseBodyTruncated=false, full
//     body returned base64-encoded.
//   - truncated_above_cap: RecordStep MaxBodySize = 10 MiB. 25 MiB body is
//     truncated to 10 MiB → ResponseBodyTruncated=true, body reflects the
//     first 10 MiB (not the discarded tail).

const (
	mcpLargeBodySize25MiB = 25 << 20
	mcpRecordCapTruncate  = 10 << 20
)

// ---------------------------------------------------------------------------
// Self-contained http1 MITM helpers (inlined because test helpers from
// layer/http1 live in package http1_test and are not importable).
// ---------------------------------------------------------------------------

func newMCPLargeTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mcp-large-upstream"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"mcp-large-upstream"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
	}
}

// startMCPLargeUpstream serves a canned 25 MiB response on every request.
func startMCPLargeUpstream(t *testing.T, body []byte) (net.Listener, string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", newMCPLargeTLSConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				// Read one request (Content-Length: 0 implicit because GET).
				for {
					line, rerr := br.ReadBytes('\n')
					if rerr != nil {
						return
					}
					if bytes.Equal(line, []byte("\r\n")) {
						break
					}
				}
				// Write a 25 MiB Content-Length-framed response + Connection:
				// close so the proxy drains the full body and the session ends.
				header := fmt.Sprintf(
					"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
					len(body),
				)
				c.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, werr := c.Write([]byte(header)); werr != nil {
					return
				}
				_, _ = c.Write(body)
			}(conn)
		}
	}()
	return ln, ln.Addr().String()
}

// startMCPLargeProxy stands up a minimal http1 MITM listener backed by store.
// recordCap caps RecordStep.MaxBodySize; 0 means "use config.MaxBodySize".
func startMCPLargeProxy(t *testing.T, ctx context.Context, store flow.Writer, recordCap int64) (proxyAddr string, done <-chan struct{}) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	sessionDone := make(chan struct{})

	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	onStack := func(sctx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		defer close(sessionDone)
		defer stack.Close()

		clientCh := <-stack.ClientTopmost().Channels()

		recordOpts := []pipeline.Option{
			pipeline.WithWireEncoder(envelope.ProtocolHTTP, http1.EncodeWireBytes),
		}
		if recordCap > 0 {
			recordOpts = append(recordOpts, pipeline.WithMaxBodySize(recordCap))
		}

		steps := []pipeline.Step{
			pipeline.NewHostScopeStep(nil),
			pipeline.NewHTTPScopeStep(nil),
			pipeline.NewRecordStep(store, testutil.DiscardLogger(), recordOpts...),
		}
		p := pipeline.New(steps...)

		session.RunSession(sctx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			return <-stack.UpstreamTopmost().Channels(), nil
		}, p)
	}

	flCfg := connector.FullListenerConfig{
		Name: "test",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator: connector.NewCONNECTNegotiator(testutil.DiscardLogger()),
			BuildCfg:   buildCfg,
			OnStack:    onStack,
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx)
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for FullListener ready")
	}

	return fl.Addr(), sessionDone
}

// drainResponseThroughProxy performs CONNECT + TLS + GET against target via
// proxyAddr. Returns the full received body (header-stripped) and the first
// read error, if any.
func drainResponseThroughProxy(t *testing.T, proxyAddr, target string) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "200") {
		t.Fatalf("unexpected CONNECT response: %q", string(buf[:n]))
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}

	if _, err := tlsConn.Write([]byte(fmt.Sprintf(
		"GET /big HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target,
	))); err != nil {
		t.Fatalf("write GET: %v", err)
	}

	tlsConn.SetReadDeadline(time.Now().Add(120 * time.Second))
	br := bufio.NewReader(tlsConn)

	// Parse status/headers.
	contentLength := 0
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read response headers: %v", err)
		}
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
		if strings.HasPrefix(strings.ToLower(string(line)), "content-length:") {
			val := strings.TrimSpace(string(line[len("content-length:"):]))
			contentLength, _ = strconv.Atoi(val)
		}
	}
	if contentLength <= 0 {
		t.Fatalf("Content-Length = %d, want > 0", contentLength)
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}

// buildMCPClient wires an MCP server backed by store + ca (no manager) to an
// in-memory client transport. Query calls land on this client.
func buildMCPClient(t *testing.T, ctx context.Context, ca *cert.CA, store flow.Store) *gomcp.ClientSession {
	t.Helper()
	mcpServer := newServer(ctx, ca, store, nil)

	ct, st := gomcp.NewInMemoryTransports()

	ss, err := mcpServer.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "large-body-test",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// callQueryFlow calls the MCP query tool with resource=flow id=<id> and
// unmarshals the result.
func callQueryFlow(t *testing.T, cs *gomcp.ClientSession, id string) queryFlowResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: queryInput{
			Resource: "flow",
			ID:       id,
		},
	})
	if err != nil {
		t.Fatalf("CallTool(query): %v", err)
	}
	if result.IsError {
		t.Fatalf("CallTool(query) returned error: %v", result.Content)
	}
	if len(result.Content) == 0 {
		t.Fatal("query returned empty content")
	}
	text, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	var out queryFlowResult
	if err := json.Unmarshal([]byte(text.Text), &out); err != nil {
		t.Fatalf("unmarshal queryFlowResult: %v", err)
	}
	return out
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

func TestLargeBody_MCPQueryReturnsFullBody(t *testing.T) {
	makeBody := func(size int) []byte {
		b := make([]byte, size)
		for i := range b {
			b[i] = byte(i % 251)
		}
		return b
	}

	cases := []struct {
		name         string
		recordCap    int64
		wantLen      int
		wantTruncate bool
	}{
		{
			name:         "full_body_below_cap",
			recordCap:    0, // defaults to config.MaxBodySize (254 MiB)
			wantLen:      mcpLargeBodySize25MiB,
			wantTruncate: false,
		},
		{
			name:         "truncated_above_cap",
			recordCap:    mcpRecordCapTruncate, // 10 MiB cap on 25 MiB body
			wantLen:      mcpRecordCapTruncate,
			wantTruncate: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
			defer cancel()

			respBody := makeBody(mcpLargeBodySize25MiB)
			wantBytes := respBody
			if tc.wantTruncate {
				wantBytes = respBody[:tc.wantLen]
			}
			wantHash := sha256.Sum256(wantBytes)

			// SQLite store.
			dbPath := filepath.Join(t.TempDir(), "large-body.db")
			store, err := flow.NewSQLiteStore(ctx, dbPath, testutil.DiscardLogger())
			if err != nil {
				t.Fatalf("NewSQLiteStore: %v", err)
			}
			t.Cleanup(func() { store.Close() })

			upstreamLn, target := startMCPLargeUpstream(t, respBody)
			defer upstreamLn.Close()

			proxyAddr, sessionDone := startMCPLargeProxy(t, ctx, store, tc.recordCap)

			// Drive one request through the proxy. The client-side body must
			// match respBody byte-for-byte (wire-fidelity proof: MaxBodySize
			// cap only affects RecordStep projection, not wire round-trip).
			got := drainResponseThroughProxy(t, proxyAddr, target)
			if len(got) != mcpLargeBodySize25MiB {
				t.Fatalf("client body length = %d, want %d", len(got), mcpLargeBodySize25MiB)
			}
			if gotHash := sha256.Sum256(got); gotHash != sha256.Sum256(respBody) {
				t.Fatalf("client body hash mismatch (wire round-trip)")
			}

			select {
			case <-sessionDone:
			case <-time.After(60 * time.Second):
				t.Fatal("timeout waiting for session to complete")
			}

			// Locate the Stream ID (single exchange per test).
			streams, err := store.ListStreams(ctx, flow.StreamListOptions{})
			if err != nil {
				t.Fatalf("ListStreams: %v", err)
			}
			if len(streams) != 1 {
				t.Fatalf("got %d streams, want 1", len(streams))
			}
			streamID := streams[0].ID

			// MCP query tool entry.
			ca := &cert.CA{}
			if err := ca.Generate(); err != nil {
				t.Fatal(err)
			}
			cs := buildMCPClient(t, ctx, ca, store)
			fq := callQueryFlow(t, cs, streamID)

			if fq.ResponseBodyEncoding != "base64" {
				t.Errorf("ResponseBodyEncoding = %q, want %q "+
					"(25 MiB byte(i%%251) is non-UTF-8, must base64-encode)",
					fq.ResponseBodyEncoding, "base64")
			}
			if fq.ResponseBodyTruncated != tc.wantTruncate {
				t.Errorf("ResponseBodyTruncated = %v, want %v", fq.ResponseBodyTruncated, tc.wantTruncate)
			}

			// Decode base64 body and hash-compare to the expected slice.
			decoded, err := base64.StdEncoding.DecodeString(fq.ResponseBody)
			if err != nil {
				t.Fatalf("decode base64 response_body: %v", err)
			}
			if len(decoded) != tc.wantLen {
				t.Errorf("decoded response_body length = %d, want %d", len(decoded), tc.wantLen)
			}
			gotHash := sha256.Sum256(decoded)
			if gotHash != wantHash {
				t.Errorf("decoded response_body hash mismatch: got=%x want=%x", gotHash, wantHash)
			}

			// Sanity: StatusCode == 200, Protocol reflects HTTPS.
			if fq.ResponseStatusCode != 200 {
				t.Errorf("ResponseStatusCode = %d, want 200", fq.ResponseStatusCode)
			}
			if fq.Scheme != "https" {
				t.Errorf("Scheme = %q, want https", fq.Scheme)
			}
		})
	}
}
