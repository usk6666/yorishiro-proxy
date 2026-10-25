package connector

import (
	"net/url"
	"strings"
	"testing"
)

// USK-1262: the port a scope check reads must be the port the dialer
// connects to. net.Dial wraps a decimal port modulo 2^32 ("4294975376" →
// 8080), skips leading whitespace and a "+" sign, and resolves service
// names ("http" → 80), while CheckURL read u.Port() with strconv.Atoi (a
// large value no rule names) and, when net/url could not split the port
// at all, judged the whole "host:port" string as the hostname on the
// default port. Whenever rules exist, a URL or dial target whose port is
// present but not a decimal 1..65535 (SplitTargetHostPort's rule) is now
// refused. Open mode is unchanged.

// dialPortDenyScope denies 127.0.0.1 on port 8080 only.
func dialPortDenyScope() *TargetScope {
	s := NewTargetScope()
	s.SetPolicyRules(nil, []TargetRule{{Hostname: "127.0.0.1", Ports: []int{8080}}})
	return s
}

// structURL builds a URL the way the MCP tools do (envelope.URLFromWirePath),
// with the authority as u.Host verbatim — a form url.Parse would reject.
func structURL(host string) *url.URL {
	return &url.URL{Scheme: "http", Host: host, Path: "/"}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// nonStrictPortURLs are URLs whose port net.Dial reads differently from a
// decimal 1..65535 (or refuses), so no ports rule can be matched on them.
func nonStrictPortURLs(t *testing.T) map[string]*url.URL {
	return map[string]*url.URL{
		"parsed :8080+2^32":        mustParseURL(t, "http://127.0.0.1:4294975376/"),
		"parsed :0":                mustParseURL(t, "http://127.0.0.1:0/"),
		"parsed :65536":            mustParseURL(t, "http://127.0.0.1:65536/"),
		"parsed other host big":    mustParseURL(t, "http://example.com:4294967376/"),
		"struct leading space":     structURL("127.0.0.1: 8080"),
		"struct plus sign":         structURL("127.0.0.1:+8080"),
		"struct service name":      structURL("127.0.0.1:http"),
		"struct bracketed v6 name": structURL("[::1]:http"),
		"struct bracketed v6 sp":   structURL("[::1]: 8080"),
	}
}

func TestCheckURL_NonStrictPortBlockedWithRules(t *testing.T) {
	s := dialPortDenyScope()
	for name, u := range nonStrictPortURLs(t) {
		allowed, reason := s.CheckURL(u)
		if allowed {
			t.Errorf("%s: CheckURL(%q) allowed, want blocked", name, u.Host)
			continue
		}
		if !strings.Contains(reason, "port") {
			t.Errorf("%s: CheckURL(%q) reason %q, want a port reason", name, u.Host, reason)
		}
	}
}

func TestCheckURL_NonStrictPortOpenModeAllowed(t *testing.T) {
	s := NewTargetScope()
	for name, u := range nonStrictPortURLs(t) {
		if allowed, reason := s.CheckURL(u); !allowed {
			t.Errorf("%s: open mode CheckURL(%q) = blocked (%q), want allowed", name, u.Host, reason)
		}
	}
}

// Strict and port-less forms keep their verdicts: leading zeros are a
// decimal port (RFC 3986 §3.2.3) and match the deny; IPv6 hosts and an
// empty port are unaffected.
func TestCheckURL_StrictPortFormsUnchanged(t *testing.T) {
	s := dialPortDenyScope()
	cases := []struct {
		name    string
		u       *url.URL
		allowed bool
	}{
		{"leading zeros match the deny", mustParseURL(t, "http://127.0.0.1:008080/"), false},
		{"denied port", mustParseURL(t, "http://127.0.0.1:8080/"), false},
		{"other port", mustParseURL(t, "http://127.0.0.1:9090/"), true},
		{"no port", mustParseURL(t, "http://127.0.0.1/"), true},
		{"empty port", mustParseURL(t, "http://127.0.0.1:/"), true},
		{"bracketed v6 with port", mustParseURL(t, "http://[::1]:8080/"), true},
		{"bracketed v6 no port", mustParseURL(t, "http://[::1]/"), true},
		{"struct bracketed v6 empty port", structURL("[::1]:"), true},
		{"struct bare v6 long", structURL("2001:db8::1"), true},
		{"struct name with port", structURL("example.com:8443"), true},
	}
	for _, c := range cases {
		allowed, reason := s.CheckURL(c.u)
		if allowed != c.allowed {
			t.Errorf("%s: CheckURL(%q) = (%v, %q), want allowed=%v", c.name, c.u.Host, allowed, reason, c.allowed)
		}
	}
}

// T11: a name leg's dial target is read with the same strict rule. A
// dial target whose port is not a decimal 1..65535 fails closed when the
// scope has rules, so the dial port can never silently drop out of the
// deny match.
func TestNameLegs_NonStrictDialTargetPortFailsClosed(t *testing.T) {
	s := dialPortDenyScope()
	for _, dial := range []string{"127.0.0.1:4294975376", "127.0.0.1: 8080", "127.0.0.1:+8080", "127.0.0.1:http", "127.0.0.1:0", "127.0.0.1:65536"} {
		if allowed, _ := s.CheckHostHeader("http", "127.0.0.1", "/", dial); allowed {
			t.Errorf("CheckHostHeader(Host 127.0.0.1, dial %q) allowed, want blocked", dial)
		}
		if allowed, _ := s.CheckAuthority("http", "127.0.0.1", "/", dial); allowed {
			t.Errorf("CheckAuthority(127.0.0.1, dial %q) allowed, want blocked", dial)
		}
		if allowed, _ := s.CheckNameLeg("http", "127.0.0.1", 80, "/", dial); allowed {
			t.Errorf("CheckNameLeg(127.0.0.1:80, dial %q) allowed, want blocked", dial)
		}
		if allowed, _ := s.CheckAuthorityDenyOnly("http", "127.0.0.1", "/", dial); allowed {
			t.Errorf("CheckAuthorityDenyOnly(127.0.0.1, dial %q) allowed, want blocked", dial)
		}
	}
	if allowed, reason := s.CheckAuthorityDenyOnly("http", "127.0.0.1", "/", "127.0.0.1:9090"); !allowed {
		t.Errorf("CheckAuthorityDenyOnly(127.0.0.1, dial 127.0.0.1:9090) = blocked (%q), want allowed", reason)
	}
	// Strict dial targets keep their verdicts.
	if allowed, _ := s.CheckHostHeader("http", "127.0.0.1", "/", "127.0.0.1:008080"); allowed {
		t.Error("CheckHostHeader(Host 127.0.0.1, dial 127.0.0.1:008080) allowed, want blocked by the port deny")
	}
	if allowed, reason := s.CheckHostHeader("http", "127.0.0.1", "/", "127.0.0.1:9090"); !allowed {
		t.Errorf("CheckHostHeader(Host 127.0.0.1, dial 127.0.0.1:9090) = blocked (%q), want allowed", reason)
	}
	if allowed, reason := s.CheckHostHeader("http", "127.0.0.1", "/", "127.0.0.1"); !allowed {
		t.Errorf("CheckHostHeader(Host 127.0.0.1, port-less dial) = blocked (%q), want allowed", reason)
	}
	// Open mode: unchanged.
	open := NewTargetScope()
	if allowed, _ := open.CheckHostHeader("http", "127.0.0.1", "/", "127.0.0.1:4294975376"); !allowed {
		t.Error("open mode CheckHostHeader with a non-strict dial port blocked, want allowed")
	}
	if allowed, _ := open.CheckNameLeg("http", "127.0.0.1", 80, "/", "127.0.0.1:http"); !allowed {
		t.Error("open mode CheckNameLeg with a non-strict dial port blocked, want allowed")
	}
}

// Backstop: CheckTarget refuses a port no TCP dial can use when rules
// exist (a caller that parsed leniently cannot hand it an out-of-range
// value that no ports rule names).
func TestCheckTarget_OutOfRangePortBlockedWithRules(t *testing.T) {
	s := dialPortDenyScope()
	for _, p := range []int{-1, 65536, 4294975376} {
		if allowed, _ := s.CheckTarget("http", "example.com", p, "/"); allowed {
			t.Errorf("CheckTarget(example.com, port %d) allowed, want blocked", p)
		}
		if allowed, _, _ := s.CheckHost("http", "example.com", p); allowed {
			t.Errorf("CheckHost(example.com, port %d) allowed, want blocked", p)
		}
	}
	if allowed, _ := NewTargetScope().CheckTarget("http", "example.com", 65536, "/"); !allowed {
		t.Error("open mode CheckTarget(port 65536) blocked, want allowed")
	}
}
