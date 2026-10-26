package config

import (
	"strconv"
	"strings"
	"testing"
)

func clientTimeoutPtr(v int) *int { return &v }

func fmtClientTimeoutPtr(p *int) string {
	if p == nil {
		return "nil"
	}
	return strconv.Itoa(*p)
}

func TestParseFile_ClientTimeouts(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		wantReq  *int
		wantIdle *int
	}{
		{"omitted", `{}`, nil, nil},
		{"request 300", `{"request_timeout_ms": 300}`, clientTimeoutPtr(300), nil},
		{"request 0 disables", `{"request_timeout_ms": 0}`, clientTimeoutPtr(0), nil},
		{"idle 300", `{"client_idle_timeout_ms": 300}`, nil, clientTimeoutPtr(300)},
		{"idle 0 disables", `{"client_idle_timeout_ms": 0}`, nil, clientTimeoutPtr(0)},
		{"both", `{"request_timeout_ms": 5000, "client_idle_timeout_ms": 3000}`, clientTimeoutPtr(5000), clientTimeoutPtr(3000)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := ParseFile("test.json", []byte(tc.json))
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			if got, want := fmtClientTimeoutPtr(pc.RequestTimeoutMs), fmtClientTimeoutPtr(tc.wantReq); got != want {
				t.Errorf("RequestTimeoutMs = %s, want %s", got, want)
			}
			if got, want := fmtClientTimeoutPtr(pc.ClientIdleTimeoutMs), fmtClientTimeoutPtr(tc.wantIdle); got != want {
				t.Errorf("ClientIdleTimeoutMs = %s, want %s", got, want)
			}
		})
	}
}

func TestProxyConfigValidate_ClientTimeouts(t *testing.T) {
	keys := []struct {
		name string
		set  func(*ProxyConfig, *int)
	}{
		{"request_timeout_ms", func(c *ProxyConfig, v *int) { c.RequestTimeoutMs = v }},
		{"client_idle_timeout_ms", func(c *ProxyConfig, v *int) { c.ClientIdleTimeoutMs = v }},
	}
	values := []struct {
		v       *int
		wantErr bool
	}{
		{nil, false},
		{clientTimeoutPtr(0), false},
		{clientTimeoutPtr(100), false},
		{clientTimeoutPtr(600000), false},
		{clientTimeoutPtr(-1), true},
		{clientTimeoutPtr(1), true},
		{clientTimeoutPtr(99), true},
		{clientTimeoutPtr(600001), true},
	}
	for _, k := range keys {
		for _, tc := range values {
			t.Run(k.name+"="+fmtClientTimeoutPtr(tc.v), func(t *testing.T) {
				var c ProxyConfig
				k.set(&c, tc.v)
				err := c.Validate()
				if (err != nil) != tc.wantErr {
					t.Fatalf("Validate() = %v, wantErr %v", err, tc.wantErr)
				}
				if err != nil && !strings.Contains(err.Error(), k.name) {
					t.Errorf("Validate() error %q does not name %s", err, k.name)
				}
			})
		}
	}
}

func TestValidateClientTimeoutMs(t *testing.T) {
	tests := []struct {
		ms      int
		wantErr bool
	}{
		{0, false}, {MinClientTimeoutMs, false}, {60000, false}, {MaxClientTimeoutMs, false},
		{-1, true}, {MinClientTimeoutMs - 1, true}, {MaxClientTimeoutMs + 1, true},
	}
	for _, tc := range tests {
		err := ValidateClientTimeoutMs("some_timeout_ms", tc.ms)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateClientTimeoutMs(%d) = %v, wantErr %v", tc.ms, err, tc.wantErr)
		}
		if err != nil && !strings.Contains(err.Error(), "some_timeout_ms") {
			t.Errorf("error %q does not name some_timeout_ms", err)
		}
	}
}
