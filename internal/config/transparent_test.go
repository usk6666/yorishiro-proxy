package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// T14 (USK-1316): transparent_mode validation.

func TestValidateTransparentMode(t *testing.T) {
	tests := []struct {
		name        string
		mode        string
		tcpForwards int
		socks5Auth  string
		supported   bool
		wantErr     string // substring; "" = no error
	}{
		{name: "empty", mode: "", supported: true},
		{name: "none", mode: "none", supported: true},
		{name: "none with tcp_forwards", mode: "none", tcpForwards: 1, supported: true},
		{name: "redirect", mode: "redirect", supported: true},
		{name: "redirect with socks5_auth none", mode: "redirect", socks5Auth: "none", supported: true},
		{name: "unknown value", mode: "tproxy", supported: true, wantErr: "transparent_mode"},
		{name: "wrong case", mode: "Redirect", supported: true, wantErr: "transparent_mode"},
		{name: "redirect with tcp_forwards", mode: "redirect", tcpForwards: 2, supported: true, wantErr: "tcp_forwards"},
		{name: "redirect with socks5_auth password", mode: "redirect", socks5Auth: "password", supported: true, wantErr: "socks5_auth"},
		{name: "redirect on an unsupported platform", mode: "redirect", supported: false, wantErr: "Linux"},
		{name: "none on an unsupported platform", mode: "none", supported: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prev := transparentSupported
			transparentSupported = tc.supported
			defer func() { transparentSupported = prev }()

			err := ValidateTransparentMode(tc.mode, tc.tcpForwards, tc.socks5Auth)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateTransparentMode(%q, %d, %q) = %v, want nil", tc.mode, tc.tcpForwards, tc.socks5Auth, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateTransparentMode(%q, %d, %q) = %v, want an error mentioning %q", tc.mode, tc.tcpForwards, tc.socks5Auth, err, tc.wantErr)
			}
		})
	}
}

func TestProxyConfigValidate_TransparentMode(t *testing.T) {
	prev := transparentSupported
	transparentSupported = true
	defer func() { transparentSupported = prev }()

	tests := []struct {
		name    string
		json    string
		wantErr string
	}{
		{name: "redirect", json: `{"transparent_mode":"redirect"}`},
		{name: "none", json: `{"transparent_mode":"none"}`},
		{name: "unknown", json: `{"transparent_mode":"tproxy"}`, wantErr: "transparent_mode"},
		{name: "redirect with tcp_forwards", json: `{"transparent_mode":"redirect","tcp_forwards":{"9000":"127.0.0.1:9001"}}`, wantErr: "tcp_forwards"},
		{name: "redirect with socks5 password", json: `{"transparent_mode":"redirect","socks5_auth":"password","socks5_username":"u","socks5_password":"p"}`, wantErr: "socks5_auth"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var pc ProxyConfig
			if err := json.Unmarshal([]byte(tc.json), &pc); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			err := pc.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				if pc.TransparentMode == "" {
					t.Fatal("transparent_mode did not unmarshal")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want an error mentioning %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateTransparentPeekTimeoutMs(t *testing.T) {
	tests := []struct {
		ms      int
		wantErr bool
	}{
		{0, false}, {100, false}, {1000, false}, {600000, false},
		{99, true}, {600001, true}, {-1, true},
	}
	for _, tc := range tests {
		err := ValidateTransparentPeekTimeoutMs(tc.ms)
		if (err != nil) != tc.wantErr {
			t.Errorf("ValidateTransparentPeekTimeoutMs(%d) = %v, wantErr %v", tc.ms, err, tc.wantErr)
		}
		if err != nil && !strings.Contains(err.Error(), "transparent_peek_timeout_ms") {
			t.Errorf("error %q does not name transparent_peek_timeout_ms", err)
		}
	}
	var pc ProxyConfig
	if err := json.Unmarshal([]byte(`{"transparent_peek_timeout_ms":50}`), &pc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := pc.Validate(); err == nil {
		t.Fatal("Validate() = nil for transparent_peek_timeout_ms=50, want an error")
	}
}

func TestProxyConfigValidate_TransparentModeUnsupportedPlatform(t *testing.T) {
	prev := transparentSupported
	transparentSupported = false
	defer func() { transparentSupported = prev }()

	pc := ProxyConfig{TransparentMode: TransparentModeRedirect}
	if err := pc.Validate(); err == nil {
		t.Fatal("Validate() = nil for transparent_mode=redirect on an unsupported platform, want an error")
	}
}
