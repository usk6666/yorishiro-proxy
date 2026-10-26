package connector

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"
)

// USK-1312: Go's net.Dial reads an empty host (":80") and an unspecified
// address ("0.0.0.0:80", "[::]:80") as the local host, so a scope that
// denies 127.0.0.1 / localhost / ::1 to protect services on the proxy host
// must not let those spellings through. Whenever rules exist, an empty or
// unspecified dial host is refused before deny and allow evaluation
// (decision (b), RFC-001 §3.4.2). Open mode is unchanged and name legs
// (Host / :authority with a known dial target) are not affected.

// loopbackDenies is the operator config the Issue describes: deny the
// proxy host's own loopback names.
func loopbackDenies() []TargetRule {
	return []TargetRule{{Hostname: "127.0.0.1"}, {Hostname: "localhost"}, {Hostname: "::1"}}
}

func loopbackDenyScope() *TargetScope {
	s := NewTargetScope()
	s.SetPolicyRules(nil, loopbackDenies())
	return s
}

// unspecifiedDialHosts are every spelling of an empty or unspecified host
// the scope can be handed by a gate or an MCP helper. The legacy forms
// ("0", "0.0", "0x0", "00") fold to 0.0.0.0 through hostcanon.ParseLegacyIPv4: a
// libc resolver or an upstream proxy reads them as that address.
var unspecifiedDialHosts = []string{
	"", "0.0.0.0", "::", "[::]", "::ffff:0.0.0.0", "[::ffff:0.0.0.0]",
	"0:0::0", "::%lo", "[::%lo]", "0.0.0.0.", "0", "0.0", "0x0", "00",
}

// T5: every scope entry point refuses an empty or unspecified dial host
// with the new reason, whatever the rule shape: deny-only, allow-only,
// and a ports-only any-host allow that would otherwise admit it.
func TestTargetScope_UnspecifiedDialHostFailsClosed(t *testing.T) {
	scopes := map[string]func() *TargetScope{
		"deny-only": loopbackDenyScope,
		"allow-only": func() *TargetScope {
			s := NewTargetScope()
			s.SetPolicyRules([]TargetRule{{Hostname: "10.0.0.5"}}, nil)
			return s
		},
		"ports-only any-host allow": func() *TargetScope {
			s := NewTargetScope()
			s.SetPolicyRules([]TargetRule{{Ports: []int{80, 443}}}, nil)
			return s
		},
		"agent deny only": func() *TargetScope {
			s := NewTargetScope()
			if err := s.SetAgentRules(nil, []TargetRule{{Hostname: "localhost"}}); err != nil {
				panic(err)
			}
			return s
		},
	}
	for name, mk := range scopes {
		s := mk()
		for _, h := range unspecifiedDialHosts {
			t.Run(fmt.Sprintf("%s/%q", name, h), func(t *testing.T) {
				if ok, reason := s.CheckTarget("http", h, 80, "/"); ok || reason != unspecifiedHostReason {
					t.Errorf("CheckTarget = (%v, %q), want (false, %q)", ok, reason, unspecifiedHostReason)
				}
				if ok, pending, reason := s.CheckHost("https", h, 443); ok || pending || reason != unspecifiedHostReason {
					t.Errorf("CheckHost = (%v, %v, %q), want (false, false, %q)", ok, pending, reason, unspecifiedHostReason)
				}
				if ok, reason := s.CheckOpaqueTarget("https", h, 443); ok || reason != unspecifiedHostReason {
					t.Errorf("CheckOpaqueTarget = (%v, %q), want (false, %q)", ok, reason, unspecifiedHostReason)
				}
			})
		}
	}
}

// Negative controls for T5: hosts next to the unspecified address keep
// their existing verdicts.
func TestTargetScope_UnspecifiedDialHost_NeighboursUnaffected(t *testing.T) {
	s := loopbackDenyScope()
	if ok, reason := s.CheckTarget("http", "127.0.0.1", 80, "/"); ok || reason != "blocked by policy deny rule" {
		t.Errorf("CheckTarget(127.0.0.1) = (%v, %q), want the ordinary deny", ok, reason)
	}
	for _, h := range []string{"0.0.0.1", "10.0.0.0", "example.com"} {
		if ok, reason := s.CheckTarget("http", h, 80, "/"); !ok {
			t.Errorf("CheckTarget(%q) = (false, %q), want allowed", h, reason)
		}
		if ok, _, reason := s.CheckHost("http", h, 80); !ok {
			t.Errorf("CheckHost(%q) = (false, %q), want allowed", h, reason)
		}
	}
}

// T6: with no rules (open mode) nothing changes.
func TestTargetScope_UnspecifiedDialHost_OpenModeUnchanged(t *testing.T) {
	s := NewTargetScope()
	for _, h := range unspecifiedDialHosts {
		if ok, reason := s.CheckTarget("http", h, 80, "/"); !ok {
			t.Errorf("open mode CheckTarget(%q) = (false, %q), want allowed", h, reason)
		}
		if ok, _, reason := s.CheckHost("http", h, 80); !ok {
			t.Errorf("open mode CheckHost(%q) = (false, %q), want allowed", h, reason)
		}
	}
}

// T7: name legs with a known dial target are not dial legs. An empty or
// unspecified Host / :authority value on a connection that dials an
// allowed address is a legitimate Host-injection value under the name-leg
// rules and stays allowed. (Characterization: adding the unspecified
// guard to nameDenyLocked turns this red.)
func TestTargetScope_UnspecifiedNameLegUnchanged(t *testing.T) {
	s := NewTargetScope()
	s.SetPolicyRules([]TargetRule{{Hostname: "10.0.0.5"}}, loopbackDenies())
	const dial = "10.0.0.5:80"
	for _, v := range []string{"0.0.0.0", "", "[::]", "0.0.0.0:80"} {
		if ok, reason := s.CheckHostHeader("http", v, "/", dial); !ok {
			t.Errorf("CheckHostHeader(%q, dial %s) = (false, %q), want allowed", v, dial, reason)
		}
	}
	for _, v := range []string{"::", "0.0.0.0", "[::]:80"} {
		if ok, reason := s.CheckAuthority("http", v, "/", dial); !ok {
			t.Errorf("CheckAuthority(%q, dial %s) = (false, %q), want allowed", v, dial, reason)
		}
	}
}

// T1 / T2 / T6: the plain-HTTP forward gate, real handler, real dial.
func TestNewHTTP1ForwardHandler_UnspecifiedHostNeverDialed(t *testing.T) {
	cases := []struct {
		name string
		raw  string // %s is the listener port
	}{
		{name: "absolute-form [::]", raw: "GET http://[::]:%s/ HTTP/1.1\r\nHost: x\r\n\r\n"},
		{name: "absolute-form 0.0.0.0", raw: "GET http://0.0.0.0:%s/ HTTP/1.1\r\nHost: x\r\n\r\n"},
		{name: "absolute-form mapped 0.0.0.0", raw: "GET http://[::ffff:0.0.0.0]:%s/ HTTP/1.1\r\nHost: x\r\n\r\n"},
		{name: "Host [::]", raw: "GET / HTTP/1.1\r\nHost: [::]:%s\r\n\r\n"},
		{name: "Host 0.0.0.0", raw: "GET / HTTP/1.1\r\nHost: 0.0.0.0:%s\r\n\r\n"},
		{name: "Host empty host", raw: "GET / HTTP/1.1\r\nHost: :%s\r\n\r\n"},
		{name: "absolute-form empty host", raw: "GET http://:%s/ HTTP/1.1\r\nHost: x\r\n\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, accepts := countingListener(t)
			resp := runForwardHandler(t, HTTP1ForwardHandlerConfig{Scope: loopbackDenyScope()}, fmt.Sprintf(c.raw, strconv.Itoa(p)))
			if !strings.HasPrefix(string(resp), "HTTP/1.1 403 ") {
				t.Errorf("response = %q, want 403", resp)
			}
			if got := waitAccepts(accepts, 0, 300*time.Millisecond); got != 0 {
				t.Errorf("loopback listener accepts = %d, want 0", got)
			}
		})
	}

	// Unbracketed "::" in Host takes the default port 80: only the verdict
	// is asserted (the listener is not on 80).
	t.Run("Host :: default port", func(t *testing.T) {
		resp := runForwardHandler(t, HTTP1ForwardHandlerConfig{Scope: loopbackDenyScope()}, "GET / HTTP/1.1\r\nHost: ::\r\n\r\n")
		if !strings.HasPrefix(string(resp), "HTTP/1.1 403 ") {
			t.Errorf("response = %q, want 403", resp)
		}
	})

	// T6: open mode still dials the unspecified address (positive control:
	// the counter does observe the dial, so the zero rows are not vacuous).
	t.Run("open mode 0.0.0.0 reaches the listener", func(t *testing.T) {
		p, accepts := countingListener(t)
		_ = runForwardHandler(t, HTTP1ForwardHandlerConfig{}, fmt.Sprintf("GET http://0.0.0.0:%d/ HTTP/1.1\r\nHost: x\r\n\r\n", p))
		if got := waitAccepts(accepts, 1, 2*time.Second); got != 1 {
			t.Errorf("open mode accepts = %d, want 1", got)
		}
	})
}

// T3 / T6: the CONNECT gate, real handler, real dial.
func TestCONNECTHandler_UnspecifiedHostRefused(t *testing.T) {
	run := func(t *testing.T, scope *TargetScope, target string) (string, *echoCountingListener) {
		t.Helper()
		up := startCountingListener(t)
		_, port, _ := strings.Cut(up.addr(), ":")
		client, _ := serveOneConn(t, NewCONNECTHandler(CONNECTHandlerConfig{
			Negotiator:       NewCONNECTNegotiator(newTestLogger()),
			BuildCfg:         &BuildConfig{},
			Scope:            scope,
			InnerPeekTimeout: 2 * time.Second,
			OnStack:          onStackProbe(make(chan struct{}, 1)),
			Logger:           newTestLogger(),
		}))
		line := writeCONNECT(t, client, fmt.Sprintf(target, port))
		_, _ = client.Write([]byte{0x00, 0x01, 'r', 'a', 'w'})
		return line, up
	}
	for _, target := range []string{"[::]:%s", "0.0.0.0:%s", "[::ffff:0.0.0.0]:%s", "0:%s"} {
		t.Run(target, func(t *testing.T) {
			line, up := run(t, loopbackDenyScope(), target)
			if !strings.Contains(line, "403") {
				t.Errorf("CONNECT status = %q, want 403", line)
			}
			time.Sleep(200 * time.Millisecond)
			if n := up.accepts.Load(); n != 0 {
				t.Errorf("loopback listener accepts = %d, want 0", n)
			}
		})
	}
	t.Run("open mode [::] admitted", func(t *testing.T) {
		line, _ := run(t, nil, "[::]:%s")
		if !strings.Contains(line, "200") {
			t.Errorf("open mode CONNECT status = %q, want 200", line)
		}
	})
}

// T4: the SOCKS5 gate refuses every ATYP spelling of the unspecified host.
func TestSOCKS5Negotiator_UnspecifiedHostRefused(t *testing.T) {
	var v6Unspec, v6Mapped [16]byte
	v6Mapped[10], v6Mapped[11] = 0xff, 0xff
	cases := []struct {
		name string
		req  []byte
	}{
		{name: "ATYP v4 0.0.0.0", req: buildConnectIPv4([4]byte{}, 80)},
		{name: "ATYP v6 ::", req: buildConnectIPv6(v6Unspec, 80)},
		{name: "ATYP v6 ::ffff:0.0.0.0", req: buildConnectIPv6(v6Mapped, 80)},
		{name: "domain ::", req: buildConnectDomain("::", 80)},
		{name: "domain 0", req: buildConnectDomain("0", 80)},
		{name: "domain 0.0.0.0", req: buildConnectDomain("0.0.0.0", 80)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			neg := NewSOCKS5Negotiator(newTestLogger())
			neg.Scope = loopbackDenyScope()
			rig := newSOCKS5TestRig(t, neg)
			defer rig.closeAll()
			rig.start()
			go func() {
				rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
				rig.writeClient(c.req)
			}()
			_ = rig.readClient(2)
			reply := rig.readClient(10)
			if len(reply) < 2 || reply[1] != socks5ReplyConnectionNotAllowed {
				t.Errorf("reply = %x, want REP=0x02", reply)
			}
			// Drain anything else so Negotiate can return.
			go func() { _, _ = io.Copy(io.Discard, rig.client) }()
			rig.waitDone(2 * time.Second)
			if !errors.Is(rig.retErr, ErrSOCKS5BlockedByScope) {
				t.Errorf("err = %v, want ErrSOCKS5BlockedByScope", rig.retErr)
			}
		})
	}
}
