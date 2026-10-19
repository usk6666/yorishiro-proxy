//go:build e2e

package mcptest_test

// USK-1213: helpers shared by the smoke-tier resend_http_h2 e2e and the
// exhaustive-tier wire_path_fidelity / fingerprint_coherence e2e. They live
// in a plain-`e2e` file so the smoke build (-tags 'e2e e2e_smoke') still
// compiles them; the full build is a superset and reuses them unchanged.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// wirePathFlow is the subset of query("flows") the tests read.
type wirePathFlow struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	URL      string `json:"url"`
}

// waitForWirePathFlow polls query("flows") for a complete flow whose URL
// contains substr and was not already seen (exclude), returning it.
func waitForWirePathFlow(t *testing.T, h *mcptest.Harness, substr string, exclude map[string]bool, timeout time.Duration) wirePathFlow {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows"})
		var parsed struct {
			Flows []wirePathFlow `json:"flows"`
		}
		if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
			t.Fatalf("decode query(flows): %v (text=%q)", err, res.Text)
		}
		for _, f := range parsed.Flows {
			if exclude[f.ID] || f.State != "complete" {
				continue
			}
			if strings.Contains(f.URL, substr) {
				return f
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no complete flow with URL containing %q within %v; flows=%+v", substr, timeout, parsed.Flows)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// h2RawGET opens a CONNECT tunnel through the proxy, completes TLS with
// ALPN h2 against the MITM leaf, and sends one GET whose :path is written
// verbatim with x/net's Framer + HPACK encoder (net/http would re-derive
// the path from a *url.URL). Returns the response :status.
func h2RawGET(t *testing.T, proxyAddr, target, wirePathWithQuery string) string {
	t.Helper()
	raw, err := fpDialCONNECTTunnel(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT tunnel: %v", err)
	}
	host, _, _ := net.SplitHostPort(target)
	conn := tls.Client(raw, &tls.Config{
		ServerName:         host,
		NextProtos:         []string{"h2"},
		InsecureSkipVerify: true, //nolint:gosec // test client trusts the proxy MITM leaf
	})
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := conn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("client leg ALPN = %q, want h2", got)
	}

	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, f := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: target},
		{Name: ":path", Value: wirePathWithQuery},
	} {
		if err := enc.WriteField(f); err != nil {
			t.Fatalf("hpack encode: %v", err)
		}
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: hb.Bytes(), EndStream: true, EndHeaders: true,
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}

	status := ""
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		if f.Name == ":status" {
			status = f.Value
		}
	})
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("read frame (status so far %q): %v", status, err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = fr.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				_ = fr.WritePing(true, f.Data)
			}
		case *http2.HeadersFrame:
			if f.StreamID == 1 {
				if _, err := dec.Write(f.HeaderBlockFragment()); err != nil {
					t.Fatalf("hpack decode: %v", err)
				}
				if f.StreamEnded() {
					return status
				}
			}
		case *http2.DataFrame:
			if f.StreamID == 1 && f.StreamEnded() {
				return status
			}
		case *http2.RSTStreamFrame:
			t.Fatalf("stream reset: %v", f.ErrCode)
		case *http2.GoAwayFrame:
			t.Fatalf("goaway: %v", f.ErrCode)
		}
	}
}

// fpDialCONNECTTunnel opens a CONNECT tunnel to proxyAddr for target and
// returns the post-200 raw connection. Uniquely named to avoid colliding
// with connect_modes_smoke's dialCONNECTTunnel (both compile into the same
// package under -tags e2e).
func fpDialCONNECTTunnel(proxyAddr, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := c.Write([]byte(req)); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if !strings.Contains(line, "200") {
		_ = c.Close()
		return nil, fmt.Errorf("CONNECT failed: %s", line)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	if br.Buffered() > 0 {
		_ = c.Close()
		return nil, fmt.Errorf("unexpected buffered bytes after CONNECT response")
	}
	return c, nil
}
