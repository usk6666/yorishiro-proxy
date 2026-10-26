//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

var logConnIDRe = regexp.MustCompile(`\bconn_id=(\S+)`)

// waitTransparentLogConnID waits for the "connection closed" log line of
// the client connection whose local address is remoteAddr and returns its
// conn_id. Every log line carrying that remote_addr and a conn_id must
// agree on it.
func waitTransparentLogConnID(t *testing.T, logs *testutil.CaptureLogger, remoteAddr string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		found := ""
		ids := map[string]bool{}
		for _, line := range strings.Split(logs.Output(), "\n") {
			if !strings.Contains(line, " remote_addr="+remoteAddr+" ") && !strings.HasSuffix(line, " remote_addr="+remoteAddr) {
				continue
			}
			m := logConnIDRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			ids[m[1]] = true
			if strings.Contains(line, `msg="connection closed"`) {
				found = m[1]
			}
		}
		if found != "" {
			if len(ids) != 1 {
				t.Errorf("log lines for remote_addr %s carry %d distinct conn_ids %v, want 1", remoteAddr, len(ids), ids)
			}
			return found
		}
		if time.Now().After(deadline) {
			t.Fatalf("no \"connection closed\" log line with remote_addr %s and a conn_id (conn_ids seen: %v)", remoteAddr, ids)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func assertTransparentConnID(t *testing.T, streamID, streamConnID, logConnID string) {
	t.Helper()
	if streamConnID != logConnID {
		t.Errorf("stream %s ConnID = %q, want the logged conn_id %q", streamID, streamConnID, logConnID)
	}
	if _, err := uuid.Parse(logConnID); err != nil {
		t.Errorf("logged conn_id %q is not a uuid: %v", logConnID, err)
	}
}

// TestTransparent_ConnID_StreamMatchesLog: on a transparent listener the
// plain-HTTP Stream, the TLS MITM Stream and the metadata-only
// passthrough Stream each carry the conn_id FullListener logged for the
// same client connection.
func TestTransparent_ConnID_StreamMatchesLog(t *testing.T) {
	t.Run("plain HTTP", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newRawHTTPUpstream(t)
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		resp, _, local := transparentExchange(t, p.addr, "GET /ci HTTP/1.1\r\nHost: named.invalid\r\nConnection: close\r\n\r\n")
		if resp.StatusCode != 200 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		st, _ := waitStream(t, p.store, 2, isHTTPStream)
		assertTransparentConnID(t, st.ID, st.ConnID, waitTransparentLogConnID(t, p.logs, local))
	})

	t.Run("TLS h2 MITM", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newCapturingTLSUpstream(t, []string{"h2", "http/1.1"}, serveHTTPS)
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		tc, body := h2Get(t, p, "h2.example", []string{"h2"}, "/ci")
		if body != "tls host=h2.example path=/ci proto=HTTP/2.0" {
			t.Fatalf("body %q", body)
		}
		local := tc.LocalAddr().String()
		st, _ := waitStream(t, p.store, 2, isMITMHTTPSStream)
		_ = tc.Close()
		assertTransparentConnID(t, st.ID, st.ConnID, waitTransparentLogConnID(t, p.logs, local))
	})

	t.Run("opaque passthrough", func(t *testing.T) {
		ctx := transparentCtx(t)
		up := newEchoUpstream(t)
		p := startTransparentProxy(t, ctx, up.addr(), nil)
		c := p.dial(t)
		local := c.LocalAddr().String()
		payload := []byte("SSH-2.0-OpenSSH_9.6\r\n\x00\x01binary")
		go func() {
			_, _ = c.Write(payload)
			_ = c.(*net.TCPConn).CloseWrite()
		}()
		if _, err := io.ReadAll(c); err != nil {
			t.Fatalf("read: %v", err)
		}
		_ = c.Close()
		st, _, _ := waitPassthroughDone(t, p.store, "opaque")
		assertTransparentConnID(t, st.ID, st.ConnID, waitTransparentLogConnID(t, p.logs, local))
	})
}
