//go:build e2e && !e2e_smoke

// USK-1383 exhaustive tier: cleartext h2c spoken inside a plaintext CONNECT
// or SOCKS5 tunnel must redial upstream as cleartext h2c after the origin
// sends GOAWAY. The redial (pre-warm, reactive and refused-stream retry all
// share one mint) must reproduce the first connection's transport — no TLS
// handshake the first connection never had.
package proxybuild_test

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	h2pool "github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// firstByteRelay forwards every accepted conn to target and records the
// first byte the proxy sent on it (0x16 = TLS ClientHello, 'P' = h2c
// client preface).
type firstByteRelay struct {
	addr  string
	mu    sync.Mutex
	first []byte
}

func startFirstByteRelay(t *testing.T, target string) *firstByteRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	r := &firstByteRelay{addr: ln.Addr().String()}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 1)
				if _, err := io.ReadFull(c, b); err != nil {
					return
				}
				r.mu.Lock()
				r.first = append(r.first, b[0])
				r.mu.Unlock()
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				if _, err := up.Write(b); err != nil {
					return
				}
				go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
				_, _ = io.Copy(up, c)
			}()
		}
	}()
	return r
}

func (r *firstByteRelay) firstBytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.first...)
}

// newRawH2CClient starts a prior-knowledge cleartext h2 client on an
// established tunnel conn.
func newRawH2CClient(t *testing.T, conn net.Conn) *rawH2Client {
	t.Helper()
	_ = conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatalf("write preface: %v", err)
	}
	c := &rawH2Client{conn: conn, fr: http2.NewFramer(conn, conn), scheme: "http"}
	c.enc = hpack.NewEncoder(&c.buf)
	c.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	c.fr.MaxHeaderListSize = 1 << 20
	if err := c.fr.WriteSettings(); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return c
}

// TestH2CTunnel_UpstreamGoAway_RedialsCleartext: inside a plaintext CONNECT
// or SOCKS5 tunnel, after the h2c origin answers stream 1 and sends GOAWAY,
// stream 3 is answered over a connection redialed as cleartext h2c, and no
// upstream connection ever begins with a TLS record.
func TestH2CTunnel_UpstreamGoAway_RedialsCleartext(t *testing.T) {
	for _, via := range []string{"connect", "socks5"} {
		t.Run(via, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			origin := startRefusingH2OriginOpts(t, refusingOriginOpts{
				mode: originGoAwayAfterFirst, batch: 1, plaintext: true,
			})
			relay := startFirstByteRelay(t, origin.addr)
			store := &flowStoreForH2Pool{}
			metrics := proxybuild.NewH2UpstreamMetrics()
			proxyAddr := startProxyForH2PoolInterceptTestWithMetrics(t, ctx, store,
				httprules.NewInterceptEngine(), common.NewHoldQueue(), h2pool.New(h2pool.PoolOptions{}), metrics)

			var tunnel net.Conn
			switch via {
			case "connect":
				c, err := connectTunnelDialerForPoolTest(proxyAddr, relay.addr)
				if err != nil {
					t.Fatalf("CONNECT: %v", err)
				}
				tunnel = c
			case "socks5":
				host, portStr, err := net.SplitHostPort(relay.addr)
				if err != nil {
					t.Fatalf("split relay addr: %v", err)
				}
				port, err := strconv.Atoi(portStr)
				if err != nil {
					t.Fatalf("relay port: %v", err)
				}
				c, rep := socks5Connect(t, proxyAddr, host, port)
				if rep != 0x00 {
					t.Fatalf("SOCKS5 REP = %#x, want 0x00", rep)
				}
				// socks5Connect reads only VER/REP/RSV/ATYP; drain the
				// IPv4 BND.ADDR + BND.PORT so h2 framing starts clean.
				if _, err := io.ReadFull(c, make([]byte, 6)); err != nil {
					t.Fatalf("SOCKS5 reply tail: %v", err)
				}
				tunnel = c
			}
			cli := newRawH2CClient(t, tunnel)

			cli.sendGETs(t, relay.addr, 1)
			requireOK(t, 1, cli.collect(t, 10*time.Second, 1)[1])

			// Settle: the origin's GOAWAY wakes the pre-warm worker, which
			// opens the second upstream connection on its own. Wait for it
			// (whatever its transport) so stream 3 is opened strictly after
			// the GOAWAY was observed.
			deadline := time.Now().Add(5 * time.Second)
			for len(relay.firstBytes()) < 2 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}

			cli.sendGETs(t, relay.addr, 3)
			r3 := cli.collect(t, 10*time.Second, 3)[3]
			fb := relay.firstBytes()
			if !r3.ended || r3.rst || len(r3.statuses) == 0 || r3.statuses[0] != "200" {
				t.Fatalf("stream 3: statuses=%v ended=%v rst=%v code=%v; want :status 200 (upstream conn first bytes %q, metrics %+v)",
					r3.statuses, r3.ended, r3.rst, r3.rstCode, fb, metrics.Snapshot())
			}

			if len(fb) < 2 {
				t.Errorf("upstream conns = %d (first bytes %q), want >= 2 (stream 3 served by a redialed connection)", len(fb), fb)
			}
			for i, b := range fb {
				if b != 'P' {
					t.Errorf("upstream conn #%d began with %q; want the cleartext h2c preface 'P' (0x16 = TLS ClientHello)", i+1, b)
				}
			}
			m := metrics.Snapshot()
			if m.RedialFailedPrewarm != 0 || m.RedialFailedReactive != 0 || m.RedialFailedRefusedStream != 0 {
				t.Errorf("failed redials: prewarm=%d reactive=%d refused_stream=%d, want 0 each",
					m.RedialFailedPrewarm, m.RedialFailedReactive, m.RedialFailedRefusedStream)
			}

			waitStreamOutcomes(t, store, map[string]int{"complete/": 2}, 5*time.Second)
			for _, st := range store.Streams() {
				if st.Protocol != "http" {
					t.Errorf("stream %s protocol = %q, want http", st.ID, st.Protocol)
				}
				if st.Scheme != "http" {
					t.Errorf("stream %s scheme = %q, want http (no TLS on either leg)", st.ID, st.Scheme)
				}
			}
		})
	}
}
