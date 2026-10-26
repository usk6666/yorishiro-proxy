package connector

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1379: a capacity rejection on a transparent listener carries the
// connection's original destination in RejectInfo.OriginalDst; a
// non-transparent listener never resolves one.

// startCapacityTransparentListener starts a FullListener with
// MaxConnections=1 whose only slot is held by one connection. When
// transparent is true the listener is transparent (resolver r, a holding
// OnTransparent); otherwise it is an explicit listener whose OnTCP holds
// the slot (r is still set, without OnTransparent). It returns the listener address.
func startCapacityTransparentListener(t *testing.T, transparent bool, r OriginalDstResolver, onReject func(RejectInfo)) string {
	t.Helper()
	barrier := make(chan struct{})
	held := make(chan struct{}, 1)
	hold := func(context.Context, *PeekConn) error {
		held <- struct{}{}
		<-barrier
		return nil
	}
	cfg := FullListenerConfig{
		Name:           "transparent-reject-test",
		MaxConnections: 1,
		OnReject:       onReject,
	}
	cfg.OriginalDst = r
	if transparent {
		cfg.OnTransparent = hold
	} else {
		cfg.OnTCP = hold
	}
	fl := newTestFullListener(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	startFullListener(t, ctx, fl)

	holder, err := net.Dial("tcp4", fl.Addr())
	if err != nil {
		t.Fatalf("dial holder: %v", err)
	}
	_, _ = holder.Write([]byte{0xFF}) // raw TCP — routed to OnTCP on the explicit listener
	t.Cleanup(func() {
		close(barrier)
		_ = holder.Close()
		cancel()
	})
	select {
	case <-held:
	case <-time.After(3 * time.Second):
		t.Fatal("holder connection never reached the handler")
	}
	return fl.Addr()
}

func TestFullListener_OnReject_TransparentOriginalDst(t *testing.T) {
	tests := []struct {
		name string
		// overCap is the resolver's answer for the over-cap connection
		// (the holder always resolves to a valid dst).
		overCap func(conn net.Conn) (netip.AddrPort, error)
		want    string
	}{
		{
			name: "IPv4 original dst is reported",
			overCap: func(net.Conn) (netip.AddrPort, error) {
				return netip.MustParseAddrPort("192.0.2.10:80"), nil
			},
			want: "192.0.2.10:80",
		},
		{
			name: "IPv4-mapped original dst is unmapped",
			overCap: func(net.Conn) (netip.AddrPort, error) {
				return netip.MustParseAddrPort("[::ffff:198.51.100.7]:443"), nil
			},
			want: "198.51.100.7:443",
		},
		{
			name: "IPv6 original dst is reported",
			overCap: func(net.Conn) (netip.AddrPort, error) {
				return netip.MustParseAddrPort("[2001:db8::1]:8443"), nil
			},
			want: "[2001:db8::1]:8443",
		},
		{
			name: "resolver error leaves OriginalDst empty",
			overCap: func(net.Conn) (netip.AddrPort, error) {
				return netip.AddrPort{}, errors.New("no conntrack entry")
			},
			want: "",
		},
		{
			name: "self original dst leaves OriginalDst empty",
			overCap: func(conn net.Conn) (netip.AddrPort, error) {
				return netip.MustParseAddrPort(conn.LocalAddr().String()), nil
			},
			want: "",
		},
		{
			name: "unspecified original dst leaves OriginalDst empty",
			overCap: func(net.Conn) (netip.AddrPort, error) {
				return netip.MustParseAddrPort("0.0.0.0:80"), nil
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			r := OriginalDstFunc(func(conn net.Conn) (netip.AddrPort, error) {
				if calls.Add(1) == 1 {
					return netip.MustParseAddrPort("203.0.113.1:80"), nil
				}
				return tt.overCap(conn)
			})
			rec := newRejectRecorder()
			addr := startCapacityTransparentListener(t, true, r, rec.onReject)

			conn := dialAndSend(t, addr, []byte("GET /cap HTTP/1.1\r\nHost: x\r\n\r\n"))
			defer conn.Close()

			info := rec.next(t, 3*time.Second)
			if info.OriginalDst != tt.want {
				t.Errorf("RejectInfo.OriginalDst = %q, want %q", info.OriginalDst, tt.want)
			}
			if info.Target != "/cap" {
				t.Errorf("RejectInfo.Target = %q, want the wire request-target /cap", info.Target)
			}
			if got := calls.Load(); got != 2 {
				t.Errorf("resolver calls = %d, want 2 (holder + over-cap)", got)
			}
		})
	}
}

func TestFullListener_OnReject_ExplicitListenerHasNoOriginalDst(t *testing.T) {
	var calls atomic.Int32
	r := OriginalDstFunc(func(net.Conn) (netip.AddrPort, error) {
		calls.Add(1)
		return netip.MustParseAddrPort("192.0.2.10:80"), nil
	})
	rec := newRejectRecorder()
	// A resolver without OnTransparent does not make a listener
	// transparent; the reject path must not consult it.
	addr := startCapacityTransparentListener(t, false, r, rec.onReject)

	conn := dialAndSend(t, addr, []byte("GET /cap HTTP/1.1\r\nHost: x\r\n\r\n"))
	defer conn.Close()

	info := rec.next(t, 3*time.Second)
	if info.OriginalDst != "" {
		t.Errorf("RejectInfo.OriginalDst = %q on an explicit listener, want empty", info.OriginalDst)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("resolver calls = %d, want 0", got)
	}
}

func TestLogCapacityRejection_OriginalDstAttr(t *testing.T) {
	tests := []struct {
		name        string
		originalDst string
		want        bool
	}{
		{name: "transparent rejection logs original_dst", originalDst: "192.0.2.10:80", want: true},
		{name: "no original dst omits the attr", originalDst: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logs, logger := testutil.NewCaptureLogger()
			LogCapacityRejection(logger, nil, RejectInfo{
				Listener:    "gw",
				RemoteAddr:  "10.0.0.2:5555",
				OriginalDst: tt.originalDst,
			})
			if got := logs.Contains("original_dst="); got != tt.want {
				t.Errorf("log contains original_dst = %v, want %v; output:\n%s", got, tt.want, logs.Output())
			}
			if tt.want && !logs.Contains("original_dst="+tt.originalDst) {
				t.Errorf("log lacks original_dst=%s; output:\n%s", tt.originalDst, logs.Output())
			}
		})
	}
}
