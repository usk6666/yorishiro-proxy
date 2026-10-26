//go:build e2e && !e2e_smoke

package connector_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// USK-1385: raw_passthrough_hosts is matched in the dial-equivalent form,
// so a CONNECT / SOCKS5 authority that respells an entry's destination
// (trailing dot, case, IPv4-mapped IPv6, a leading-zero port) is relayed
// through the bytechunk layer and recorded as protocol "raw", exactly as
// the entry's own spelling is. Legacy IPv4 spellings are not folded (see
// TestTunnelRouteOpaque_RawPassthroughLegacyIPv4NotFolded; a real dial of
// "127.1" fails under Go's pure resolver, so that control is unit-level).

// rawAliasCase is one respelled authority and the entry it must match.
type rawAliasCase struct {
	name string
	// entry and authority build the raw_passthrough_hosts entry and the
	// CONNECT / SOCKS5 authority from the upstream port.
	entry, authority func(port string) string
}

func rawAliasCases() []rawAliasCase {
	hostPort := func(host string) func(string) string {
		return func(port string) string { return net.JoinHostPort(host, port) }
	}
	return []rawAliasCase{
		{"trailing dot", hostPort("localhost"), hostPort("localhost.")},
		{"upper case trailing dot", hostPort("localhost"), hostPort("LOCALHOST.")},
		{"entry with trailing dot", hostPort("localhost."), hostPort("localhost")},
		{"IPv4-mapped IPv6", hostPort("127.0.0.1"), hostPort("::ffff:127.0.0.1")},
		{"IPv4-mapped IPv6 hex", hostPort("127.0.0.1"), hostPort("::ffff:7f00:1")},
		{"leading-zero port", hostPort("localhost"), func(port string) string { return "localhost:0" + port }},
	}
}

// startRawAliasUpstream starts the HTTPS upstream used by the alias tests.
func startRawAliasUpstream(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nraw")
	})
	t.Cleanup(func() { ln.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split upstream addr: %v", err)
	}
	return ln, port
}

// assertRawRecorded checks that the session was relayed raw: one stream
// with protocol "raw" whose flows carry the request bytes as written.
func assertRawRecorded(t *testing.T, store *testStore, resp, rawReq string) {
	t.Helper()
	if !strings.Contains(resp, "200 OK") {
		t.Errorf("response missing 200 OK: %q", resp)
	}
	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream, got 0")
	}
	if streams[0].Protocol != "raw" {
		t.Errorf("stream protocol = %q, want %q (respelled authority must take the raw_passthrough_hosts route)", streams[0].Protocol, "raw")
	}
	var sawReq bool
	for _, f := range store.allFlows() {
		if bytes.Contains(f.RawBytes, []byte(rawReq)) {
			sawReq = true
			break
		}
	}
	if !sawReq {
		t.Errorf("no flow carries the request bytes verbatim in RawBytes")
	}
}

// T4: CONNECT with a respelled authority is relayed raw (bytechunk).
func TestFullListener_RawPassthroughHostAliases_CONNECT(t *testing.T) {
	for _, tc := range rawAliasCases() {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			_, port := startRawAliasUpstream(t)
			authority := tc.authority(port)
			proxyAddr, store, wg := startFullListenerProxy(t, ctx, fullListenerOpts{
				proxyConfig: &config.ProxyConfig{RawPassthroughHosts: []string{tc.entry(port)}},
			})

			wg.Add(1)
			rawReq := fmt.Sprintf("GET /raw-alias HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", authority)
			resp := connectAndSendHTTP(t, proxyAddr, authority, rawReq)
			waitSessionDone(t, wg)

			assertRawRecorded(t, store, resp, rawReq)
		})
	}
}

// T5: SOCKS5 with a domain-ATYP trailing-dot host is relayed raw.
func TestFullListener_RawPassthroughHostAliases_SOCKS5(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, port := startRawAliasUpstream(t)
	proxyAddr, store, wg := startFullListenerProxy(t, ctx, fullListenerOpts{
		proxyConfig: &config.ProxyConfig{RawPassthroughHosts: []string{net.JoinHostPort("localhost", port)}},
	})

	authority := net.JoinHostPort("localhost.", port)
	wg.Add(1)
	rawReq := fmt.Sprintf("GET /raw-alias-socks HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", authority)
	resp := socks5ConnectAndSendHTTP(t, proxyAddr, authority, rawReq)
	waitSessionDone(t, wg)

	assertRawRecorded(t, store, resp, rawReq)
}
