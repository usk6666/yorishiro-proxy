package connector

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// USK-1273: canonicalScopeHost folds legacy inet_aton IPv4 spellings
// ("0x7f.0.0.1", "2130706433", "127.1", "0177.0.0.1") into dotted-quad for
// comparison, which is exact for a deny but widens an allow: Go's pure
// resolver does not read those spellings as addresses. It sends the hex
// ones to DNS (with the resolv.conf search list), so an allow for
// 127.0.0.1 admitted "0x7f.0.0.1" and the dial landed wherever DNS
// pointed. Whenever rules exist, a dial host that is an IPv4 address in any
// spelling other than canonical dotted-quad decimal is now refused before
// deny and allow evaluation. Open mode and name legs are unchanged.

// loopbackAllowScope is the operator config from the report: allow the
// loopback upstream only.
func loopbackAllowScope() *TargetScope {
	s := NewTargetScope()
	s.SetPolicyRules([]TargetRule{{Hostname: "127.0.0.1"}}, nil)
	return s
}

// legacyIPv4DialHosts are non-canonical spellings of an IPv4 address that
// canonicalScopeHost folds into a dotted-quad (all but "10.0.5" fold into
// 127.0.0.1).
var legacyIPv4DialHosts = []string{
	"0x7f.0.0.1",      // hex first part: Go's pure resolver sends it to DNS
	"0X7F.0.0.1",      // uppercase hex prefix
	"2130706433",      // 32-bit integer
	"0x7f000001",      // hex integer
	"127.1",           // two-part short form
	"127.0.1",         // three-part short form
	"0177.0.0.1",      // octal first part
	"127.0.0.01",      // leading-zero last part
	"127.000.000.001", // leading zeros everywhere
	"127.0.0.1.",      // canonical dotted-quad with a trailing dot
	"2130706433.",     // integer with a trailing dot
	"0x7f.0.0.1.",     // hex with a trailing dot
	"[127.0.0.1]",     // bracketed IPv4
	"10.0.5",          // short form of an address the allow does not name
}

func TestLegacyIPv4Spelling(t *testing.T) {
	for _, h := range legacyIPv4DialHosts {
		if !legacyIPv4Spelling(h) {
			t.Errorf("legacyIPv4Spelling(%q) = false, want true", h)
		}
	}
	for _, h := range []string{
		"127.0.0.1", "10.0.0.5", "0.0.0.0", "255.255.255.255", // canonical
		"::ffff:127.0.0.1", "[::ffff:7f00:1]", "::1", "[::1]", "fe80::1%eth0", // IPv6 is dialed as an IP literal
		"localhost", "example.com", "foo.0x7f", "1.2.3.4.5", "0x", "", ".", "[]", // not an IPv4 address
	} {
		if legacyIPv4Spelling(h) {
			t.Errorf("legacyIPv4Spelling(%q) = true, want false", h)
		}
	}
}

// T1 / T2: every scope entry point refuses a non-canonical IPv4 dial host
// with the new reason, under an allow that names the folded address, an
// agent-layer allow, and a deny-only scope that does not name it.
func TestTargetScope_LegacyIPv4DialHostFailsClosed(t *testing.T) {
	scopes := map[string]func() *TargetScope{
		"policy allow 127.0.0.1": loopbackAllowScope,
		"agent allow 127.0.0.1": func() *TargetScope {
			s := NewTargetScope()
			if err := s.SetAgentRules([]TargetRule{{Hostname: "127.0.0.1"}}, nil); err != nil {
				panic(err)
			}
			return s
		},
		"deny-only unrelated": func() *TargetScope {
			s := NewTargetScope()
			s.SetPolicyRules(nil, []TargetRule{{Hostname: "evil.example"}})
			return s
		},
		"ports-only any-host allow": func() *TargetScope {
			s := NewTargetScope()
			s.SetPolicyRules([]TargetRule{{Ports: []int{80, 443}}}, nil)
			return s
		},
	}
	for name, mk := range scopes {
		s := mk()
		for _, h := range legacyIPv4DialHosts {
			t.Run(fmt.Sprintf("%s/%q", name, h), func(t *testing.T) {
				if ok, reason := s.CheckTarget("https", h, 443, ""); ok || reason != legacyIPv4Reason {
					t.Errorf("CheckTarget = (%v, %q), want (false, %q)", ok, reason, legacyIPv4Reason)
				}
				if ok, reason := s.CheckTarget("http", h, 80, "/"); ok || reason != legacyIPv4Reason {
					t.Errorf("CheckTarget(path /) = (%v, %q), want (false, %q)", ok, reason, legacyIPv4Reason)
				}
				if ok, pending, reason := s.CheckHost("https", h, 443); ok || pending || reason != legacyIPv4Reason {
					t.Errorf("CheckHost = (%v, %v, %q), want (false, false, %q)", ok, pending, reason, legacyIPv4Reason)
				}
				if ok, reason := s.CheckOpaqueTarget("https", h, 443); ok || reason != legacyIPv4Reason {
					t.Errorf("CheckOpaqueTarget = (%v, %q), want (false, %q)", ok, reason, legacyIPv4Reason)
				}
			})
		}
	}
	s := loopbackAllowScope()
	for _, raw := range []string{"http://0x7f.0.0.1/", "http://2130706433:80/x", "https://127.1/", "http://0177.0.0.1:8080/"} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", raw, err)
		}
		if ok, reason := s.CheckURL(u); ok || reason != legacyIPv4Reason {
			t.Errorf("CheckURL(%q) = (%v, %q), want (false, %q)", raw, ok, reason, legacyIPv4Reason)
		}
	}
}

// T3: neighbours keep their verdicts, and the step-0 order is
// unspecified -> numeric -> legacy (the legacy "0" / "0x0" fold into
// 0.0.0.0 and keep unspecifiedHostReason).
func TestTargetScope_LegacyIPv4DialHost_NeighboursUnaffected(t *testing.T) {
	s := loopbackAllowScope()
	for _, h := range []string{"127.0.0.1", "::ffff:127.0.0.1", "[::ffff:7f00:1]", "[::ffff:127.0.0.1]"} {
		if ok, reason := s.CheckTarget("https", h, 443, ""); !ok {
			t.Errorf("CheckTarget(%q) = (false, %q), want allowed", h, reason)
		}
		if ok, _, reason := s.CheckHost("https", h, 443); !ok {
			t.Errorf("CheckHost(%q) = (false, %q), want allowed", h, reason)
		}
	}
	if ok, reason := s.CheckTarget("https", "10.0.0.5", 443, ""); ok || reason != "not in policy allow list" {
		t.Errorf("CheckTarget(10.0.0.5) = (%v, %q), want the ordinary allow-list miss", ok, reason)
	}
	for _, h := range []string{"0", "0x0", "00", "0.0", "0.0.0.0."} {
		if ok, reason := s.CheckTarget("https", h, 443, ""); ok || reason != unspecifiedHostReason {
			t.Errorf("CheckTarget(%q) = (%v, %q), want (false, %q)", h, ok, reason, unspecifiedHostReason)
		}
	}
	for _, h := range []string{"1.2.3.4.5", "0x.0.0.1", "08.0.0.1"} {
		if ok, reason := s.CheckTarget("https", h, 443, ""); ok || reason != numericHostReason {
			t.Errorf("CheckTarget(%q) = (%v, %q), want (false, %q)", h, ok, reason, numericHostReason)
		}
	}
}

// T4: with no rules (open mode) nothing changes.
func TestTargetScope_LegacyIPv4DialHost_OpenModeUnchanged(t *testing.T) {
	s := NewTargetScope()
	for _, h := range legacyIPv4DialHosts {
		if ok, reason := s.CheckTarget("https", h, 443, ""); !ok {
			t.Errorf("open mode CheckTarget(%q) = (false, %q), want allowed", h, reason)
		}
		if ok, _, reason := s.CheckHost("https", h, 443); !ok {
			t.Errorf("open mode CheckHost(%q) = (false, %q), want allowed", h, reason)
		}
		if ok, reason := s.CheckOpaqueTarget("https", h, 443); !ok {
			t.Errorf("open mode CheckOpaqueTarget(%q) = (false, %q), want allowed", h, reason)
		}
	}
}

// T5: name legs with a known dial target are not dial legs. A legacy IPv4
// Host / :authority value on a connection dialing the allowed address is a
// legitimate Host-injection value (plan B) and stays allowed; a deny for
// the folded address still blocks it. (Characterization: wiring the new
// predicate into nameDenyLocked or numericHostUnparsable turns this red.)
func TestTargetScope_LegacyIPv4NameLegUnchanged(t *testing.T) {
	const dial = "127.0.0.1:80"
	allow := loopbackAllowScope()
	deny := NewTargetScope()
	deny.SetPolicyRules(nil, []TargetRule{{Hostname: "127.0.0.1"}})
	for _, v := range []string{"0x7f.0.0.1", "2130706433", "127.1:80", "0177.0.0.1:80", "127.0.0.1."} {
		if ok, reason := allow.CheckHostHeader("http", v, "/", dial); !ok {
			t.Errorf("allow: CheckHostHeader(%q) = (false, %q), want allowed", v, reason)
		}
		if ok, reason := allow.CheckAuthority("http", v, "/", dial); !ok {
			t.Errorf("allow: CheckAuthority(%q) = (false, %q), want allowed", v, reason)
		}
		if ok, reason := allow.CheckAbsoluteFormAuthority("http", v, "/", dial); !ok {
			t.Errorf("allow: CheckAbsoluteFormAuthority(%q) = (false, %q), want allowed", v, reason)
		}
		if ok, _ := deny.CheckHostHeader("http", v, "/", dial); ok {
			t.Errorf("deny 127.0.0.1: CheckHostHeader(%q) = allowed, want blocked", v)
		}
		if ok, _ := deny.CheckAuthority("http", v, "/", dial); ok {
			t.Errorf("deny 127.0.0.1: CheckAuthority(%q) = allowed, want blocked", v)
		}
	}
}

// T6: the plain-HTTP forward gate, real handler, real dial.
func TestNewHTTP1ForwardHandler_LegacyIPv4HostNeverDialed(t *testing.T) {
	cases := []struct {
		name string
		raw  string // %s is the listener port
	}{
		{name: "absolute-form hex", raw: "GET http://0x7f.0.0.1:%s/ HTTP/1.1\r\nHost: x\r\n\r\n"},
		{name: "absolute-form integer", raw: "GET http://2130706433:%s/ HTTP/1.1\r\nHost: x\r\n\r\n"},
		{name: "absolute-form short", raw: "GET http://127.1:%s/ HTTP/1.1\r\nHost: x\r\n\r\n"},
		{name: "Host hex", raw: "GET / HTTP/1.1\r\nHost: 0x7f.0.0.1:%s\r\n\r\n"},
		{name: "Host octal", raw: "GET / HTTP/1.1\r\nHost: 0177.0.0.1:%s\r\n\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, accepts := countingListener(t)
			resp := runForwardHandler(t, HTTP1ForwardHandlerConfig{Scope: loopbackAllowScope()}, fmt.Sprintf(c.raw, strconv.Itoa(p)))
			if !strings.HasPrefix(string(resp), "HTTP/1.1 403 ") {
				t.Errorf("response = %q, want 403", resp)
			}
			if got := waitAccepts(accepts, 0, 300*time.Millisecond); got != 0 {
				t.Errorf("loopback listener accepts = %d, want 0", got)
			}
		})
	}

	// Positive control: the canonical spelling does reach the listener, so
	// the zero rows above are not vacuous.
	t.Run("dotted 127.0.0.1 reaches the listener", func(t *testing.T) {
		p, accepts := countingListener(t)
		_ = runForwardHandler(t, HTTP1ForwardHandlerConfig{Scope: loopbackAllowScope()}, fmt.Sprintf("GET http://127.0.0.1:%d/ HTTP/1.1\r\nHost: x\r\n\r\n", p))
		if got := waitAccepts(accepts, 1, 2*time.Second); got != 1 {
			t.Errorf("accepts = %d, want 1", got)
		}
	})
}

// T6: the CONNECT gate, real handler, real dial.
func TestCONNECTHandler_LegacyIPv4HostRefused(t *testing.T) {
	run := func(t *testing.T, target string) (string, *echoCountingListener) {
		t.Helper()
		up := startCountingListener(t)
		_, port, _ := strings.Cut(up.addr(), ":")
		client, _ := serveOneConn(t, NewCONNECTHandler(CONNECTHandlerConfig{
			Negotiator:       NewCONNECTNegotiator(newTestLogger()),
			BuildCfg:         &BuildConfig{},
			Scope:            loopbackAllowScope(),
			InnerPeekTimeout: 2 * time.Second,
			OnStack:          onStackProbe(make(chan struct{}, 1)),
			Logger:           newTestLogger(),
		}))
		line := writeCONNECT(t, client, fmt.Sprintf(target, port))
		_, _ = client.Write([]byte{0x00, 0x01, 'r', 'a', 'w'})
		return line, up
	}
	for _, target := range []string{"0x7f.0.0.1:%s", "2130706433:%s", "127.1:%s", "0177.0.0.1:%s"} {
		t.Run(target, func(t *testing.T) {
			line, up := run(t, target)
			if !strings.Contains(line, "403") {
				t.Errorf("CONNECT status = %q, want 403", line)
			}
			time.Sleep(200 * time.Millisecond)
			if n := up.accepts.Load(); n != 0 {
				t.Errorf("loopback listener accepts = %d, want 0", n)
			}
		})
	}
	t.Run("dotted 127.0.0.1 admitted", func(t *testing.T) {
		line, _ := run(t, "127.0.0.1:%s")
		if !strings.Contains(line, "200") {
			t.Errorf("CONNECT status = %q, want 200", line)
		}
	})
}

// T6: the SOCKS5 gate refuses a legacy spelling in a domain-name ATYP.
func TestSOCKS5Negotiator_LegacyIPv4DomainRefused(t *testing.T) {
	for _, host := range []string{"0x7f.0.0.1", "2130706433", "127.1", "0177.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			neg := NewSOCKS5Negotiator(newTestLogger())
			neg.Scope = loopbackAllowScope()
			rig := newSOCKS5TestRig(t, neg)
			defer rig.closeAll()
			rig.start()
			go func() {
				rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
				rig.writeClient(buildConnectDomain(host, 80))
			}()
			_ = rig.readClient(2)
			reply := rig.readClient(10)
			if len(reply) < 2 || reply[1] != socks5ReplyConnectionNotAllowed {
				t.Errorf("reply = %x, want REP=0x02", reply)
			}
			go func() { _, _ = io.Copy(io.Discard, rig.client) }()
			rig.waitDone(2 * time.Second)
			if !errors.Is(rig.retErr, ErrSOCKS5BlockedByScope) {
				t.Errorf("err = %v, want ErrSOCKS5BlockedByScope", rig.retErr)
			}
		})
	}
}
