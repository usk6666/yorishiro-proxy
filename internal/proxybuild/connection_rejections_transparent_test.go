package proxybuild

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// USK-1379: the blocked_by=capacity audit Stream of a connection refused on
// a transparent listener carries tags.original_dst, like every other
// transparent-mode Stream. Driven through BuildLiveStack with a real
// over-cap dial; the original destination comes from a fake resolver
// (a real REDIRECT needs root and an nftables rule).

// capacityRejectStack builds and starts a MaxConnections=1 Stack whose
// only slot is held by a silent connection, then sends an HTTP/1.1 request
// on an over-cap connection. It returns the audit Streams written and the
// aggregator.
func capacityRejectStack(t *testing.T, transparent bool, r connector.OriginalDstResolver) ([]*flow.Stream, *ConnectionRejections) {
	t.Helper()
	store := &recordingFlowStore{}
	rej := NewConnectionRejections(ConnectionRejectionsConfig{Store: store, Logger: silentLogger()})
	t.Cleanup(rej.Close)

	deps := newTestDeps(t)
	deps.MaxConnections = 1
	deps.ConnectionRejections = rej
	deps.OriginalDstResolver = r
	// A silent holder keeps the only slot for the whole test.
	deps.PeekTimeout = 10 * time.Second
	if transparent {
		deps.TransparentMode = config.TransparentModeRedirect
		deps.TransparentPeekTimeout = 10 * time.Second
	}
	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = stack.Listener.Start(ctx)
	}()
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready")
	}
	addr := stack.Listener.Addr()

	holder, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatalf("dial holder: %v", err)
	}
	t.Cleanup(func() {
		_ = holder.Close()
		cancel()
		<-done
	})
	deadline := time.Now().Add(3 * time.Second)
	for stack.Listener.ActiveConnections() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("holder connection never became active")
		}
		time.Sleep(10 * time.Millisecond)
	}

	over, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatalf("dial over-cap: %v", err)
	}
	defer over.Close()
	if _, err := over.Write([]byte("GET /cap HTTP/1.1\r\nHost: x\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}

	streams := waitForStreams(t, store, 1)
	if len(streams) != 1 {
		t.Fatalf("audit Streams = %d, want 1", len(streams))
	}
	if streams[0].BlockedBy != pipeline.BlockedByCapacity {
		t.Fatalf("BlockedBy = %q, want %q", streams[0].BlockedBy, pipeline.BlockedByCapacity)
	}
	if got := streams[0].Tags["target"]; got != "/cap" {
		t.Errorf("Tags[target] = %q, want the wire request-target /cap", got)
	}
	return streams, rej
}

func TestConnectionRejections_TransparentListener_TagsOriginalDst(t *testing.T) {
	r := connector.OriginalDstFunc(func(net.Conn) (netip.AddrPort, error) {
		return netip.MustParseAddrPort("192.0.2.10:80"), nil
	})
	streams, rej := capacityRejectStack(t, true, r)

	if got := streams[0].Tags[connector.TagOriginalDst]; got != "192.0.2.10:80" {
		t.Errorf("Tags[%s] = %q, want 192.0.2.10:80", connector.TagOriginalDst, got)
	}
	snap := rej.Snapshot()
	if len(snap.Recent) != 1 {
		t.Fatalf("Snapshot().Recent = %d entries, want 1", len(snap.Recent))
	}
	if got := snap.Recent[0].OriginalDst; got != "192.0.2.10:80" {
		t.Errorf("Snapshot().Recent[0].OriginalDst = %q, want 192.0.2.10:80", got)
	}
}

func TestConnectionRejections_ExplicitListener_NoOriginalDst(t *testing.T) {
	var calls atomic.Int32
	r := connector.OriginalDstFunc(func(net.Conn) (netip.AddrPort, error) {
		calls.Add(1)
		return netip.MustParseAddrPort("192.0.2.10:80"), nil
	})
	streams, rej := capacityRejectStack(t, false, r)

	if got, ok := streams[0].Tags[connector.TagOriginalDst]; ok {
		t.Errorf("Tags[%s] = %q on an explicit listener, want no such key", connector.TagOriginalDst, got)
	}
	if got := rej.Snapshot().Recent[0].OriginalDst; got != "" {
		t.Errorf("Snapshot().Recent[0].OriginalDst = %q, want empty", got)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("resolver calls = %d on an explicit listener, want 0", got)
	}
}

func TestConnectionRejections_TransparentListener_UnusableDstStillRecorded(t *testing.T) {
	tests := []struct {
		name    string
		overCap func(conn net.Conn) (netip.AddrPort, error)
	}{
		{
			name: "resolver error",
			overCap: func(net.Conn) (netip.AddrPort, error) {
				return netip.AddrPort{}, errors.New("no conntrack entry")
			},
		},
		{
			name: "original dst is the listener itself",
			overCap: func(conn net.Conn) (netip.AddrPort, error) {
				return netip.MustParseAddrPort(conn.LocalAddr().String()), nil
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			r := connector.OriginalDstFunc(func(conn net.Conn) (netip.AddrPort, error) {
				if calls.Add(1) == 1 {
					// The holder resolves so it keeps the slot.
					return netip.MustParseAddrPort("192.0.2.10:80"), nil
				}
				return tt.overCap(conn)
			})
			streams, rej := capacityRejectStack(t, true, r)

			if got, ok := streams[0].Tags[connector.TagOriginalDst]; ok {
				t.Errorf("Tags[%s] = %q for an unusable original dst, want no such key", connector.TagOriginalDst, got)
			}
			if got := rej.Snapshot().Recent[0].OriginalDst; got != "" {
				t.Errorf("Snapshot().Recent[0].OriginalDst = %q, want empty", got)
			}
			if got := calls.Load(); got < 2 {
				t.Errorf("resolver calls = %d, want the over-cap connection resolved too", got)
			}
		})
	}
}
