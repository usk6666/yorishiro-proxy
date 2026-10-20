package connector

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// USK-1264 / USK-1304 / USK-1306: hardening of the name-leg parsing seam.
//
//   - USK-1264: a forward target whose host has colons but is not an IPv6
//     literal ("db.internal:5432:x") was wrapped as "[db.internal:5432:x]:80"
//     and reached an upstream proxy; a bracket holding a non-IPv6 value
//     ("[db.internal:5432]:80") was accepted by SplitTargetHostPort.
//   - USK-1304: a comma-bearing Host value ("ok.example, denied.example")
//     was judged as one name; each part is now also deny-checked.
//   - USK-1306: name-leg deny matching used only the port written in the
//     name; the dial target's port now matches too.

func TestTargetScope_CheckHostHeader_NameLegParsing(t *testing.T) {
	deny := []TargetRule{{Hostname: "denied.example"}}
	portDeny := []TargetRule{{Hostname: "portd.example", Ports: []int{80}}}
	ipAllow := []TargetRule{{Hostname: "10.0.0.5"}}
	tests := []struct {
		name        string
		allows      []TargetRule
		denies      []TargetRule
		value       string
		dialTarget  string
		wantAllowed bool
	}{
		// USK-1304: comma-separated parts are deny-checked.
		{"comma: denied second part", nil, deny, "ok.example, denied.example", "127.0.0.1:80", false},
		{"comma: denied first part", nil, deny, "denied.example, ok.example", "127.0.0.1:80", false},
		{"comma: denied part with port", nil, deny, "ok.example, denied.example:8080", "127.0.0.1:80", false},
		{"comma: no OWS", nil, deny, "ok.example,denied.example", "127.0.0.1:80", false},
		{"comma: HTAB OWS", nil, deny, "ok.example,\tdenied.example\t", "127.0.0.1:80", false},
		{"comma: denied part folds (case, trailing dot)", nil, deny, "ok.example, DENIED.example.", "127.0.0.1:80", false},
		{"comma: IP-literal allowed connection still refused", ipAllow, deny, "ok.example, denied.example", "10.0.0.5:80", false},
		{"comma: domain allow still refused", []TargetRule{{Hostname: "app.example"}}, deny, "app.example, denied.example", "app.example:80", false},
		{"comma: non-IPv6 bracket part fails closed", nil, deny, "ok.example, [db.internal]", "127.0.0.1:80", false},
		{"comma: numeric part fails closed", nil, deny, "ok.example, 1.2.3.4.5", "127.0.0.1:80", false},
		{"comma: non-denied parts pass on an IP-allowed connection", ipAllow, deny, "a.example, b.example", "10.0.0.5:80", true},
		{"comma: non-denied parts pass deny-only", nil, deny, "a.example, b.example", "127.0.0.1:80", true},
		{"comma: trailing empty parts pass deny-only", nil, deny, "ok.example,,", "127.0.0.1:80", true},
		{"comma: lone comma passes deny-only", nil, deny, ",", "127.0.0.1:80", true},
		{"comma: blank parts pass deny-only", nil, deny, ", ,", "127.0.0.1:80", true},
		{"comma: domain allow judges the whole value", []TargetRule{{Hostname: "ok.example"}}, nil, "ok.example,,", "ok.example:80", false},

		// U2: bracket content must be IPv6.
		{"bracket: non-IPv6 content with port", nil, []TargetRule{{Hostname: "db.internal"}}, "[db.internal:5432]:80", "127.0.0.1:80", false},
		{"bracket: name with port", nil, []TargetRule{{Hostname: "db.internal"}}, "[db.internal]:80", "127.0.0.1:80", false},
		{"bracket: name with empty port", nil, []TargetRule{{Hostname: "db.internal"}}, "[db.internal:5432]:", "127.0.0.1:80", false},
		{"bracket: IPv4 content", nil, deny, "[1.2.3.4]:80", "127.0.0.1:80", false},
		{"bracket: IPv6 content passes", nil, deny, "[::2]:8080", "127.0.0.1:80", true},

		// USK-1306: the dial target's port matches a port-scoped deny.
		{"dial port: name port differs from dial port", ipAllow, portDeny, "portd.example:8080", "10.0.0.5:80", false},
		{"dial port: deny-only scope", nil, portDeny, "portd.example:1", "127.0.0.1:80", false},
		{"dial port: neither port matches", ipAllow, portDeny, "portd.example:8080", "10.0.0.5:8080", true},
		{"dial port: portless deny unchanged", ipAllow, deny, "denied.example:8080", "10.0.0.5:8080", false},
		{"dial port: comma part uses the dial port too", ipAllow, portDeny, "ok.example, portd.example:8080", "10.0.0.5:80", false},

		// U1: bare IPv6 keeps working; the last-colon reading is deny-checked.
		{"bare IPv6: last-colon reading hits a port deny", nil, []TargetRule{{Hostname: "2001:db8::1", Ports: []int{8080}}}, "2001:db8::1:8080", "127.0.0.1:80", false},
		{"bare IPv6: last-colon reading hits a host deny", nil, []TargetRule{{Hostname: "2001:db8::1"}}, "2001:db8::1:8080", "127.0.0.1:80", false},
		{"bare IPv6: not denied passes", nil, deny, "::1", "127.0.0.1:80", true},
		{"bare IPv6: whole reading denied", nil, []TargetRule{{Hostname: "::1"}}, "::1", "127.0.0.1:80", false},
		{"bare IPv6: allow judges the whole reading", []TargetRule{{Hostname: "2001:db8::1:8080"}}, nil, "2001:db8::1:8080", "127.0.0.1:80", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTargetScope()
			s.SetPolicyRules(tt.allows, tt.denies)
			got, reason := s.CheckHostHeader("http", tt.value, "/", tt.dialTarget)
			if got != tt.wantAllowed {
				t.Fatalf("CheckHostHeader(%q, dial %q) = %v (%q), want %v", tt.value, tt.dialTarget, got, reason, tt.wantAllowed)
			}
			if !got && reason == "" {
				t.Errorf("blocked without a reason")
			}
		})
	}
}

// Agent-layer denies get the comma split and the dial-port match too.
func TestTargetScope_CheckHostHeader_AgentDenyParts(t *testing.T) {
	s := NewTargetScope()
	if err := s.SetAgentRules(nil, []TargetRule{{Hostname: "denied.example", Ports: []int{80}}}); err != nil {
		t.Fatalf("SetAgentRules: %v", err)
	}
	for _, v := range []string{"ok.example, denied.example", "denied.example:8080", "ok.example, denied.example:8080"} {
		if ok, _ := s.CheckHostHeader("http", v, "/", "127.0.0.1:80"); ok {
			t.Errorf("CheckHostHeader(%q) allowed, want an agent deny", v)
		}
	}
}

func TestTargetScope_CheckNameLeg_DialPortDeny(t *testing.T) {
	portDeny := []TargetRule{{Hostname: "portd.example", Ports: []int{80}}}
	ipAllow := []TargetRule{{Hostname: "10.0.0.5"}}
	tests := []struct {
		name        string
		allows      []TargetRule
		denies      []TargetRule
		agentDenies []TargetRule
		port        int
		dialTarget  string
		wantAllowed bool
	}{
		{name: "dial port matches the deny", allows: ipAllow, denies: portDeny, port: 8080, dialTarget: "10.0.0.5:80", wantAllowed: false},
		{name: "agent deny: dial port matches", allows: ipAllow, agentDenies: portDeny, port: 8080, dialTarget: "10.0.0.5:80", wantAllowed: false},
		{name: "dial port without port defaults by scheme", denies: portDeny, port: 8080, dialTarget: "10.0.0.5", wantAllowed: false},
		{name: "neither port matches", allows: ipAllow, denies: portDeny, port: 8080, dialTarget: "10.0.0.5:8080", wantAllowed: true},
		{name: "name port matches", allows: ipAllow, denies: portDeny, port: 80, dialTarget: "10.0.0.5:8080", wantAllowed: false},
		{name: "no dial target: name port only", denies: portDeny, port: 8080, dialTarget: "", wantAllowed: true},
		{name: "no dial target: name port matches", denies: portDeny, port: 80, dialTarget: "", wantAllowed: false},
		{name: "portless deny unchanged", allows: ipAllow, denies: []TargetRule{{Hostname: "portd.example"}}, port: 8080, dialTarget: "10.0.0.5:9090", wantAllowed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTargetScope()
			s.SetPolicyRules(tt.allows, tt.denies)
			if err := s.SetAgentRules(nil, tt.agentDenies); err != nil {
				t.Fatalf("SetAgentRules: %v", err)
			}
			got, reason := s.CheckNameLeg("http", "portd.example", tt.port, "/", tt.dialTarget)
			if got != tt.wantAllowed {
				t.Fatalf("CheckNameLeg(portd.example:%d, dial %q) = %v (%q), want %v", tt.port, tt.dialTarget, got, reason, tt.wantAllowed)
			}
		})
	}
}

// CheckAuthority is the authority (HTTP/1 Host as parsed, HTTP/2
// :authority) name leg: lenient split as before, plus the comma-part deny
// and the dial-port deny.
func TestTargetScope_CheckAuthority(t *testing.T) {
	deny := []TargetRule{{Hostname: "denied.example"}}
	ipAllow := []TargetRule{{Hostname: "10.0.0.5"}}
	tests := []struct {
		name        string
		allows      []TargetRule
		denies      []TargetRule
		authority   string
		dialTarget  string
		wantAllowed bool
	}{
		{"comma: denied part", ipAllow, deny, "ok.example, denied.example", "10.0.0.5:443", false},
		{"comma: denied part deny-only", nil, deny, "ok.example,denied.example", "127.0.0.1:443", false},
		{"comma: denied part, no dial target", nil, deny, "ok.example, denied.example", "", false},
		{"comma: non-denied parts pass", ipAllow, deny, "a.example, b.example", "10.0.0.5:443", true},
		{"dial port deny", ipAllow, []TargetRule{{Hostname: "portd.example", Ports: []int{443}}}, "portd.example:1", "10.0.0.5:443", false},
		{"plain allowed authority passes", ipAllow, deny, "ok.example", "10.0.0.5:443", true},
		{"lenient port parse kept: non-numeric port takes the default", nil, []TargetRule{{Hostname: "x.example", Ports: []int{443}}}, "x.example:abc", "", false},
		{"denied authority", ipAllow, deny, "denied.example:8443", "10.0.0.5:443", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewTargetScope()
			s.SetPolicyRules(tt.allows, tt.denies)
			got, reason := s.CheckAuthority("https", tt.authority, "/", tt.dialTarget)
			if got != tt.wantAllowed {
				t.Fatalf("CheckAuthority(%q, dial %q) = %v (%q), want %v", tt.authority, tt.dialTarget, got, reason, tt.wantAllowed)
			}
		})
	}
}

// USK-1264: the plain-forward target derivation refuses a multi-colon
// non-IPv6 host and a non-IPv6 bracket, so neither reaches an upstream
// proxy as a CONNECT line. An unbracketed IPv6 Host is still forwarded.
func TestNewHTTP1ForwardHandler_MultiColonHostNeverForwarded(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "db.internal"}})

	cases := []struct {
		name     string
		raw      string
		wantLine string // "" means the proxy must receive nothing
		status   string
	}{
		{name: "origin-form multi-colon Host", raw: "GET / HTTP/1.1\r\nHost: db.internal:5432:x\r\n\r\n", status: "400"},
		{name: "absolute-form multi-colon authority", raw: "GET http://db.internal:5432:80/ HTTP/1.1\r\nHost: x\r\n\r\n", status: "400"},
		{name: "origin-form non-IPv6 bracket", raw: "GET / HTTP/1.1\r\nHost: [db.internal:5432]:80\r\n\r\n", status: "400"},
		{name: "origin-form bracketed name", raw: "GET / HTTP/1.1\r\nHost: [db.internal]\r\n\r\n", status: "400"},
		{
			// Decision U1: an unbracketed IPv6 literal Host is kept.
			name:     "origin-form bare IPv6",
			raw:      "GET / HTTP/1.1\r\nHost: ::1\r\n\r\n",
			wantLine: "CONNECT [::1]:80 HTTP/1.1",
			status:   "502",
		},
		{
			// Positive control: an allowed target reaches the recording proxy.
			name:     "allowed numeric",
			raw:      "GET / HTTP/1.1\r\nHost: allowed.internal:8080\r\n\r\n",
			wantLine: "CONNECT allowed.internal:8080 HTTP/1.1",
			status:   "502",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			proxyURL, recorded := recordingConnectProxy(t)
			resp := runForwardHandler(t, HTTP1ForwardHandlerConfig{
				Scope:    scope,
				BuildCfg: &BuildConfig{UpstreamProxy: proxyURL},
			}, c.raw)
			if !bytes.HasPrefix(resp, []byte("HTTP/1.1 "+c.status+" ")) {
				t.Errorf("response = %q, want status %s", resp, c.status)
			}
			var lines []string
			deadline := time.Now().Add(300 * time.Millisecond)
			for time.Now().Before(deadline) {
				if lines = recorded(); c.wantLine != "" && len(lines) > 0 {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if c.wantLine == "" {
				if len(lines) != 0 {
					t.Errorf("upstream proxy received %q, want nothing", lines)
				}
				return
			}
			if len(lines) != 1 || lines[0] != c.wantLine {
				t.Errorf("upstream proxy received %q, want [%q]", lines, c.wantLine)
			}
		})
	}
}

func TestPeekForwardTarget_MultiColonHost(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "origin multi-colon", raw: "GET / HTTP/1.1\r\nHost: db.internal:5432:x\r\n\r\n", wantErr: true},
		{name: "absolute multi-colon", raw: "GET http://db.internal:5432:80/ HTTP/1.1\r\nHost: x\r\n\r\n", wantErr: true},
		{name: "origin non-IPv6 bracket", raw: "GET / HTTP/1.1\r\nHost: [db.internal:5432]:80\r\n\r\n", wantErr: true},
		{name: "origin bare IPv6", raw: "GET / HTTP/1.1\r\nHost: 2001:db8::1\r\n\r\n", want: "[2001:db8::1]:80"},
		{name: "origin bracketed IPv6 without port", raw: "GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n", want: "[::1]:80"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := peekTargetOf(t, c.raw)
			if c.wantErr {
				if err == nil {
					t.Fatalf("peekForwardTarget = %q, nil; want error", got)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("peekForwardTarget = %q, %v; want %q", got, err, c.want)
			}
		})
	}
}

// U2: every gate that splits with SplitTargetHostPort refuses a bracket
// holding a non-IPv6 value.
func TestScopeChecks_NonIPv6BracketFailsClosed(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "db.internal"}})
	const target = "[db.internal:5432]:443"
	if ok, _, err := connectScopeCheck(scope, target, false); ok || err == nil {
		t.Errorf("connectScopeCheck(%q) = %v, %v; want denied with a split error", target, ok, err)
	}
	if ok, _ := socks5ScopeCheck(scope, target, false); ok {
		t.Errorf("socks5ScopeCheck(%q) allowed, want denied", target)
	}
	if ok, _, err := forwardScopeCheck(scope, "[db.internal:5432]:80"); ok || err == nil {
		t.Errorf("forwardScopeCheck = %v, %v; want denied with a split error", ok, err)
	}
}

func TestNewCONNECTHandler_NonIPv6BracketTarget(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "db.internal"}})
	handler := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:       NewCONNECTNegotiator(nil),
		Scope:            scope,
		InnerPeekTimeout: connectDenialInnerPeek,
	})
	got := runDeniedCONNECT(t, handler, "[db.internal:5432]:443")
	assertCONNECTReject(t, got, 400, "Bad Request", "yorishiro-proxy: invalid CONNECT target")
}

// A SOCKS5 domain carrying a colon becomes "[db.internal:5432]:443" in
// readSOCKS5Request; the scope gate must refuse it.
func TestSOCKS5Negotiator_ColonDomainBlocked(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "db.internal"}})
	neg.Scope = scope

	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
		rig.writeClient(buildConnectDomain("db.internal:5432", 443))
	}()

	_ = rig.readClient(2)
	reply := rig.readClient(10)
	if reply[1] != socks5ReplyConnectionNotAllowed {
		t.Errorf("reply REP = 0x%02x, want 0x02", reply[1])
	}
	rig.waitDone(2 * time.Second)
	if !errors.Is(rig.retErr, ErrSOCKS5BlockedByScope) {
		t.Errorf("err = %v, want ErrSOCKS5BlockedByScope", rig.retErr)
	}
	if rig.retErr != nil && !strings.Contains(rig.retErr.Error(), "scope") {
		t.Errorf("err = %v, want a scope error", rig.retErr)
	}
}
