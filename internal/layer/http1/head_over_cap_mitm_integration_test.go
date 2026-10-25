//go:build e2e && !e2e_smoke

package http1_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// TestHTTPSMITM_HeadOverRawCaptureCap_ByteIdentical (USK-1320, T9): through
// a real CONNECT MITM proxy, a request and a response whose header
// sections are ~3 MiB (over the 2 MiB default max_raw_capture_size, under
// the 4 MiB parser limit) arrive at the other side byte-identical. The
// recorded flows keep a capped wire prefix and flag the truncation via
// http_anomaly_raw_header_truncated.
func TestHTTPSMITM_HeadOverRawCaptureCap_ByteIdentical(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	respWire := "HTTP/1.1 200 OK\r\nSet-Cookie: " + strings.Repeat("s", 3<<20) +
		"\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte(respWire)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{})

	reqWire := fmt.Sprintf("POST /big HTTP/1.1\r\nHost: %s\r\nCookie: %s\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",
		target, strings.Repeat("c", 3<<20))
	resp := connectAndSendHTTP(t, proxyAddr, target, reqWire)
	upstreamReqs := getUpstreamReqs()

	select {
	case <-sessionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// --- Communication: byte-identical in both directions ---
	if len(upstreamReqs) != 1 {
		t.Fatalf("upstream received %d complete requests, want 1", len(upstreamReqs))
	}
	if !bytes.Equal(upstreamReqs[0], []byte(reqWire)) {
		t.Errorf("upstream request differs from the client's: len(got)=%d len(want)=%d",
			len(upstreamReqs[0]), len(reqWire))
	}
	if resp != respWire {
		t.Errorf("client response differs from upstream's: len(got)=%d len(want)=%d", len(resp), len(respWire))
	}

	// --- Recording: capped wire prefix + discoverable truncation ---
	reqHead := reqWire[:strings.Index(reqWire, "\r\n\r\n")+4]
	respHead := respWire[:strings.Index(respWire, "\r\n\r\n")+4]
	for _, c := range []struct {
		dir, head string
	}{{"send", reqHead}, {"receive", respHead}} {
		flows := store.flowsByDirection(c.dir)
		if len(flows) < 1 {
			t.Errorf("no %s flow recorded", c.dir)
			continue
		}
		f := flows[0]
		prefix := c.head[:parser.MaxRawCaptureSize]
		if !bytes.HasPrefix(f.RawBytes, []byte(prefix)) {
			t.Errorf("%s flow RawBytes does not start with the 2 MiB wire prefix (len %d)", c.dir, len(f.RawBytes))
		}
		if bytes.HasPrefix(f.RawBytes, []byte(c.head)) {
			t.Errorf("%s flow RawBytes holds the complete head; the record must stay capped", c.dir)
		}
		if _, ok := f.Metadata["http_anomaly_raw_header_truncated"]; !ok {
			t.Errorf("%s flow Metadata lacks http_anomaly_raw_header_truncated: %v", c.dir, metadataKeys(f.Metadata))
		}
	}
	streams := store.getStreams()
	if len(streams) < 1 || streams[0].Protocol != "http" || streams[0].State != "complete" {
		t.Errorf("stream = %+v, want protocol http / state complete", streams)
	}
}

func metadataKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
