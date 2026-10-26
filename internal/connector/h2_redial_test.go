package connector

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// TestRedialConnIDLabel_GenerationProgression locks the USK-991 label
// scheme:
//   - generation<=1 preserves the USK-816 historical suffix
//     `/upstream-redial` so existing log scrapers / flow filters keep
//     working unchanged.
//   - generation>=2 appends `-N` so each chain step is visibly distinct
//     in flow rows / structured logs / debugging dumps.
//
// Also pins the empty-base-ConnID fallback to "redial" so the suffix is
// never the only component (which would conflict across CONNECTs in any
// log aggregator that groups by ConnID prefix).
func TestRedialConnIDLabel_GenerationProgression(t *testing.T) {
	tests := []struct {
		name       string
		base       string
		generation int
		want       string
	}{
		{"first redial preserves USK-816 label", "conn-abc", 1, "conn-abc/upstream-redial"},
		{"generation 0 also yields the first-redial label", "conn-abc", 0, "conn-abc/upstream-redial"},
		{"second redial appends -2", "conn-abc", 2, "conn-abc/upstream-redial-2"},
		{"third redial appends -3", "conn-abc", 3, "conn-abc/upstream-redial-3"},
		{"empty base ConnID falls back to 'redial'", "", 1, "redial/upstream-redial"},
		{"empty base + Nth redial still labels uniquely", "", 5, "redial/upstream-redial-5"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := redialConnIDLabel(tc.base, tc.generation)
			if got != tc.want {
				t.Errorf("redialConnIDLabel(%q, %d) = %q, want %q",
					tc.base, tc.generation, got, tc.want)
			}
		})
	}
}

// TestRedialConnIDLabel_ChainUniqueness asserts that a 5-step chain
// produces 5 distinct ConnID labels — the user-visible guarantee USK-991
// added so a multi-GOAWAY flow can be triaged in logs / flow lists.
func TestRedialConnIDLabel_ChainUniqueness(t *testing.T) {
	const base = "live-conn-xyz"
	seen := make(map[string]struct{})
	for gen := 1; gen <= 5; gen++ {
		label := redialConnIDLabel(base, gen)
		if _, dup := seen[label]; dup {
			t.Errorf("generation %d label %q collides with a prior chain step", gen, label)
		}
		seen[label] = struct{}{}
	}
	if got := len(seen); got != 5 {
		t.Fatalf("5-step chain produced %d distinct labels, want 5", got)
	}
}

// firstByteRecorder is a 127.0.0.1 listener that records the first byte of
// every accepted conn. A TLS record (0x16) is answered by closing the conn
// so a TLS dial fails fast; any other first byte is drained until the test
// ends so a cleartext h2 client can finish its preface / SETTINGS writes.
type firstByteRecorder struct {
	addr  string
	mu    sync.Mutex
	first []byte
}

func startFirstByteRecorder(t *testing.T) *firstByteRecorder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	r := &firstByteRecorder{addr: ln.Addr().String()}
	var wg sync.WaitGroup
	var connsMu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		connsMu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		connsMu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				b := make([]byte, 1)
				if _, err := io.ReadFull(c, b); err != nil {
					return
				}
				r.mu.Lock()
				r.first = append(r.first, b[0])
				r.mu.Unlock()
				if b[0] == 0x16 {
					return
				}
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return r
}

func (r *firstByteRecorder) firstBytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.first...)
}

// newStaleH2Layer builds a ClientRole Layer with the given scheme over a
// real TCP conn to a draining listener, standing in for the chain head a
// redial is minted from.
func newStaleH2Layer(t *testing.T, scheme string) *http2.Layer {
	t.Helper()
	sink := startFirstByteRecorder(t)
	conn, err := net.Dial("tcp", sink.addr)
	if err != nil {
		t.Fatalf("dial sink: %v", err)
	}
	l, err := http2.New(conn, "stale", http2.ClientRole, http2.WithScheme(scheme))
	if err != nil {
		t.Fatalf("http2.New stale: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// TestRedialUpstreamH2_TransportMatchesStaleScheme: a redial off a
// cleartext h2c Layer (scheme "http") dials plain TCP — its first byte is
// the h2 client preface, not a TLS record — and the fresh Layer stays
// "http" for later chain generations. Any other stale scheme, including
// the zero-value Layer's "", keeps the TLS dial.
func TestRedialUpstreamH2_TransportMatchesStaleScheme(t *testing.T) {
	cases := []struct {
		name      string
		stale     func(t *testing.T) *http2.Layer
		wantFirst byte
		wantOK    bool
	}{
		{"cleartext h2c stale redials plain", func(t *testing.T) *http2.Layer { return newStaleH2Layer(t, "http") }, 'P', true},
		{"https stale redials TLS", func(t *testing.T) *http2.Layer { return newStaleH2Layer(t, "https") }, 0x16, false},
		{"zero-value stale redials TLS", func(*testing.T) *http2.Layer { return &http2.Layer{} }, 0x16, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := startFirstByteRecorder(t)
			cfg := &BuildConfig{ProxyConfig: &config.ProxyConfig{}, InsecureSkipVerify: true}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			fresh, err := RedialUpstreamH2(ctx, SameUpstreamTarget(rec.addr), tc.stale(t), cfg, 1, nil)
			if fresh != nil {
				t.Cleanup(func() { _ = fresh.Close() })
			}
			waitFirstBytes(rec, 1, 2*time.Second)
			if got := rec.firstBytes(); len(got) != 1 || got[0] != tc.wantFirst {
				t.Errorf("redial first bytes = %q, want [%q]", got, tc.wantFirst)
			}
			if tc.wantOK {
				if err != nil {
					t.Fatalf("RedialUpstreamH2: %v", err)
				}
				if got := fresh.Scheme(); got != "http" {
					t.Errorf("fresh Layer Scheme() = %q, want \"http\"", got)
				}
				if tmpl := fresh.EnvelopeContextTemplate(); tmpl.TLS != nil {
					t.Errorf("fresh Layer EnvelopeContext TLS = %+v, want nil", tmpl.TLS)
				}
			} else if err == nil {
				t.Errorf("RedialUpstreamH2 succeeded, want the TLS handshake to fail against the plain recorder")
			}
		})
	}
}

// waitFirstBytes polls r until it has recorded n first bytes or timeout
// elapses (the recorder's read races the dialer's return).
func waitFirstBytes(r *firstByteRecorder, n int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for len(r.firstBytes()) < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
}
