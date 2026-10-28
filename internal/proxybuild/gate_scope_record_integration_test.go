//go:build e2e && !e2e_smoke

// USK-1403 exhaustive tier: a CONNECT, plain-HTTP forward or SOCKS5
// connection the main listener's scope gate refuses leaves one
// State="error", BlockedBy="target_scope" Stream (no Flow rows), while the
// client still sees exactly the refusal bytes it saw before and the target
// is never dialled. Driven through a real Manager + BuildLiveStack; the
// fixtures are gate_ratelimit_record_integration_test.go's.
package proxybuild_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// gateScopeDenyResponse is the CONNECT / plain-HTTP forward gates' scope
// 403, byte for byte (connector.forwardErrorResponse).
const gateScopeDenyResponse = "HTTP/1.1 403 Forbidden\r\n" +
	"Server: yorishiro-proxy\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Length: 42\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	"yorishiro-proxy: target blocked by scope\r\n"

// blockedStreams returns the Streams whose BlockedBy is blockedBy.
func (p *gateRateLimitProxy) blockedStreams(blockedBy string) []*flow.Stream {
	var out []*flow.Stream
	for _, st := range p.store.Streams() {
		if st.BlockedBy == blockedBy {
			out = append(out, st)
		}
	}
	return out
}

// waitScopeStreams polls until want target_scope Streams exist or 5s pass.
func (p *gateRateLimitProxy) waitScopeStreams(want int) []*flow.Stream {
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := p.blockedStreams("target_scope")
		if len(got) >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// denyTarget installs a Policy deny on target's host:port.
func (p *gateRateLimitProxy) denyTarget(t *testing.T, target string) {
	t.Helper()
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split %q: %v", target, err)
	}
	p.scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: host, Ports: []int{portOf(t, target)}}})
}

// checkGateScopeStream asserts the common shape of a gate scope refusal
// Stream.
func checkGateScopeStream(t *testing.T, p *gateRateLimitProxy, st *flow.Stream, protocol, scheme, via, target string, client net.Conn) {
	t.Helper()
	if st.State != "error" || st.FailureReason != "target_scope" || st.BlockedBy != "target_scope" {
		t.Errorf("Stream State=%q FailureReason=%q BlockedBy=%q, want error / target_scope / target_scope", st.State, st.FailureReason, st.BlockedBy)
	}
	if st.Protocol != protocol || st.Scheme != scheme {
		t.Errorf("Stream Protocol=%q Scheme=%q, want %q / %q", st.Protocol, st.Scheme, protocol, scheme)
	}
	if st.ListenerName != proxybuild.DefaultListenerName {
		t.Errorf("Stream ListenerName = %q, want %q", st.ListenerName, proxybuild.DefaultListenerName)
	}
	if st.ConnID == "" {
		t.Error("Stream ConnID is empty")
	}
	if st.ConnInfo == nil || st.ConnInfo.ClientAddr != client.LocalAddr().String() || st.ConnInfo.ServerAddr != "" {
		t.Errorf("Stream ConnInfo = %+v, want ClientAddr %s and no ServerAddr", st.ConnInfo, client.LocalAddr())
	}
	wantTags := map[string]string{
		"via":    via,
		"target": target,
		"reason": "blocked by policy deny rule",
	}
	for k, v := range wantTags {
		if st.Tags[k] != v {
			t.Errorf("Tags[%s] = %q, want %q (tags %v)", k, st.Tags[k], v, st.Tags)
		}
	}
	if n := p.flowCount(st.ID); n != 0 {
		t.Errorf("target_scope Stream has %d Flow rows, want 0", n)
	}
}

// TestProxybuild_GateScopeRecord is T11: a scope-denied CONNECT, plain-HTTP
// forward and SOCKS5 connection each get exactly the refusal bytes they
// got before, never reach the upstream, and each leave one target_scope
// Stream.
func TestProxybuild_GateScopeRecord(t *testing.T) {
	t.Run("CONNECT", func(t *testing.T) {
		target, accepts := acceptCountingUpstream(t)
		p := startGateRateLimitProxy(t, nil, nil)
		p.denyTarget(t, target)

		c, got := sendAndReadAll(t, p.proxyAddr, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
		if string(got) != gateScopeDenyResponse {
			t.Errorf("denied CONNECT answered %q, want %q", got, gateScopeDenyResponse)
		}
		if n := settleAccepts(accepts, 0, 300*time.Millisecond); n != 0 {
			t.Errorf("upstream accepted %d connections, want 0", n)
		}
		streams := p.waitScopeStreams(1)
		if len(streams) != 1 {
			t.Fatalf("%d target_scope Streams, want 1; streams=%v", len(streams), p.store.Streams())
		}
		checkGateScopeStream(t, p, streams[0], "http", "", "connect", target, c)
	})
	t.Run("forward", func(t *testing.T) {
		target, accepts := acceptCountingUpstream(t)
		p := startGateRateLimitProxy(t, nil, nil)
		p.denyTarget(t, target)

		c, got := sendAndReadAll(t, p.proxyAddr, "GET http://"+target+"/usk1403 HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
		if string(got) != gateScopeDenyResponse {
			t.Errorf("denied forward answered %q, want %q", got, gateScopeDenyResponse)
		}
		if n := settleAccepts(accepts, 0, 300*time.Millisecond); n != 0 {
			t.Errorf("upstream accepted %d connections, want 0", n)
		}
		streams := p.waitScopeStreams(1)
		if len(streams) != 1 {
			t.Fatalf("%d target_scope Streams, want 1; streams=%v", len(streams), p.store.Streams())
		}
		checkGateScopeStream(t, p, streams[0], "http", "http", "http1-forward", target, c)
	})
	t.Run("SOCKS5", func(t *testing.T) {
		target, accepts := acceptCountingUpstream(t)
		p := startGateRateLimitProxy(t, nil, nil)
		p.denyTarget(t, target)

		req := []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
		req = binary.BigEndian.AppendUint16(req, uint16(portOf(t, target)))
		c, got := sendAndReadAll(t, p.proxyAddr, string(req))
		want := []byte{0x05, 0x00, 0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		if !bytes.Equal(got, want) {
			t.Errorf("denied SOCKS5 answered %x, want %x", got, want)
		}
		if n := settleAccepts(accepts, 0, 300*time.Millisecond); n != 0 {
			t.Errorf("upstream accepted %d connections, want 0", n)
		}
		streams := p.waitScopeStreams(1)
		if len(streams) != 1 {
			t.Fatalf("%d target_scope Streams, want 1; streams=%v", len(streams), p.store.Streams())
		}
		checkGateScopeStream(t, p, streams[0], "raw", "", "socks5", "127.0.0.1:"+strconv.Itoa(portOf(t, target)), c)
	})
}

// TestProxybuild_GateScopeRecord_CaptureScopeExcluded is T13: a scope
// refusal whose target capture_scope excludes is still answered 403 but
// writes no Stream.
func TestProxybuild_GateScopeRecord_CaptureScopeExcluded(t *testing.T) {
	target, _ := acceptCountingUpstream(t)
	rs := flow.NewRecordScope()
	rs.SetRules(nil, []flow.ScopeRule{{Hostname: "127.0.0.1"}})
	p := startGateRateLimitProxy(t, nil, rs)
	p.denyTarget(t, target)

	_, got := sendAndReadAll(t, p.proxyAddr, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")
	if string(got) != gateScopeDenyResponse {
		t.Errorf("denied CONNECT answered %q, want %q", got, gateScopeDenyResponse)
	}
	time.Sleep(200 * time.Millisecond)
	if s := p.store.Streams(); len(s) != 0 {
		t.Errorf("%d Streams recorded for a capture_scope-excluded target, want 0: %v", len(s), s)
	}
}
