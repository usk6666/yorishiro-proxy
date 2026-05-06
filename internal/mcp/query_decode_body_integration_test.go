//go:build e2e && !e2e_smoke

package mcp

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-731 — proves that an HTTPS response with Content-Encoding: gzip
// round-trips through the proxy unchanged at the wire/store layer, and that
// the MCP query tool decodes it on the way out without altering the stored
// compressed bytes.
//
// Helpers from large_body_integration_test.go (same package):
//
//	startMCPLargeProxy, drainResponseThroughProxy, buildMCPClient,
//	newMCPLargeTLSConfig.
func TestDecodeBody_GzipResponse_E2E(t *testing.T) {
	plaintext := []byte(`{"users":[{"id":1,"name":"alice"}]}`)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(plaintext); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	compressed := buf.Bytes()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	upstream, target := startGzipUpstream(t, compressed)
	defer upstream.Close()

	dbPath := filepath.Join(t.TempDir(), "decode-body.db")
	store, err := flow.NewSQLiteStore(ctx, dbPath, testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	proxyAddr, sessionDone := startMCPLargeProxy(t, ctx, store, 0)

	// Drive one request through the proxy; the client receives the gzip
	// bytes verbatim (proxy must not decode the CE on the wire path).
	got := drainResponseThroughProxy(t, proxyAddr, target)
	if !bytes.Equal(got, compressed) {
		t.Fatalf("client body diverges from upstream gzip bytes — proxy must not decode on the wire path")
	}

	select {
	case <-sessionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("session did not complete")
	}

	streams, err := store.ListStreams(ctx, flow.StreamListOptions{})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("got %d streams, want 1", len(streams))
	}
	streamID := streams[0].ID

	// Verify the Store still holds the original compressed bytes —
	// resend_http reads from this Body field, so any decompression here
	// would silently break replay fidelity.
	flows, err := store.GetFlows(ctx, streamID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	var recvBody []byte
	for _, f := range flows {
		if f.Direction == "receive" {
			recvBody = f.Body
		}
	}
	if !bytes.Equal(recvBody, compressed) {
		t.Errorf("Store.Flow.Body diverged from gzip bytes (resend fidelity broken)")
	}

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	cs := buildMCPClient(t, ctx, ca, store)

	fq := callQueryFlow(t, cs, streamID)

	// (a) wire-form body unchanged: base64-of-gzip.
	if fq.ResponseBodyEncoding != "base64" {
		t.Errorf("ResponseBodyEncoding = %q, want base64", fq.ResponseBodyEncoding)
	}
	wire, err := base64.StdEncoding.DecodeString(fq.ResponseBody)
	if err != nil {
		t.Fatalf("decode wire body base64: %v", err)
	}
	if !bytes.Equal(wire, compressed) {
		t.Errorf("MCP response_body diverged from gzip wire bytes")
	}

	// (b) decoded body populated with plaintext.
	if fq.ResponseBodyEncodingApplied != "gzip" {
		t.Errorf("ResponseBodyEncodingApplied = %q, want gzip", fq.ResponseBodyEncodingApplied)
	}
	if fq.ResponseBodyDecodedEncoding != "text" {
		t.Errorf("ResponseBodyDecodedEncoding = %q, want text", fq.ResponseBodyDecodedEncoding)
	}
	if fq.ResponseBodyDecoded != string(plaintext) {
		t.Errorf("ResponseBodyDecoded mismatch: got %q want %q", fq.ResponseBodyDecoded, string(plaintext))
	}
	if fq.ResponseBodyDecodeAnomaly != nil {
		t.Errorf("unexpected anomaly: %+v", fq.ResponseBodyDecodeAnomaly)
	}
}

// startGzipUpstream is a minimal HTTP/1.x server that always replies with the
// supplied gzip-encoded body and a Content-Encoding: gzip header.
func startGzipUpstream(t *testing.T, gzipBody []byte) (net.Listener, string) {
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
			go handleGzipUpstreamConn(conn, gzipBody)
		}
	}()
	return ln, ln.Addr().String()
}

func handleGzipUpstreamConn(c net.Conn, gzipBody []byte) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return
		}
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	header := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		len(gzipBody),
	)
	c.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if _, err := c.Write([]byte(header)); err != nil {
		return
	}
	_, _ = c.Write(gzipBody)
}
