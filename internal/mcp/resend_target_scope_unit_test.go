package mcp

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// --- Helper function unit tests (no external dependencies) ---

func TestCheckTargetScopeURL(t *testing.T) {
	tests := []struct {
		name    string
		allows  []proxy.TargetRule
		denies  []proxy.TargetRule
		url     string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "no rules allows all",
			url:     "http://any-host.com/path",
			wantErr: false,
		},
		{
			name:    "allowed by allow rule",
			allows:  []proxy.TargetRule{{Hostname: "allowed.com"}},
			url:     "http://allowed.com/path",
			wantErr: false,
		},
		{
			name:    "blocked by allow list",
			allows:  []proxy.TargetRule{{Hostname: "allowed.com"}},
			url:     "http://blocked.com/path",
			wantErr: true,
			errMsg:  "not in agent allow list",
		},
		{
			name:    "blocked by deny rule",
			denies:  []proxy.TargetRule{{Hostname: "blocked.com"}},
			url:     "http://blocked.com/path",
			wantErr: true,
			errMsg:  "blocked by agent deny rule",
		},
		{
			name:    "deny takes precedence over allow",
			allows:  []proxy.TargetRule{{Hostname: "target.com"}},
			denies:  []proxy.TargetRule{{Hostname: "target.com"}},
			url:     "http://target.com/path",
			wantErr: true,
			errMsg:  "blocked by agent deny rule",
		},
		{
			name:    "wildcard allow",
			allows:  []proxy.TargetRule{{Hostname: "*.example.com"}},
			url:     "http://api.example.com/path",
			wantErr: false,
		},
		{
			name:    "wildcard deny",
			denies:  []proxy.TargetRule{{Hostname: "*.internal"}},
			url:     "http://admin.internal/secret",
			wantErr: true,
			errMsg:  "blocked by agent deny rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := proxy.NewTargetScope()
			ts.SetAgentRules(tt.allows, tt.denies)

			s := &Server{deps: &deps{targetScope: ts}}
			u, err := url.Parse(tt.url)
			if err != nil {
				t.Fatalf("parse URL: %v", err)
			}

			err = s.checkTargetScopeURL(u)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkTargetScopeURL() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error message = %q, want contains %q", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestCheckTargetScopeAddr(t *testing.T) {
	tests := []struct {
		name    string
		allows  []proxy.TargetRule
		denies  []proxy.TargetRule
		scheme  string
		addr    string
		wantErr bool
	}{
		{
			name:    "no rules allows all",
			addr:    "any-host.com:80",
			wantErr: false,
		},
		{
			name:    "allowed host:port",
			allows:  []proxy.TargetRule{{Hostname: "allowed.com"}},
			addr:    "allowed.com:443",
			wantErr: false,
		},
		{
			name:    "blocked host:port",
			allows:  []proxy.TargetRule{{Hostname: "allowed.com"}},
			addr:    "evil.com:80",
			wantErr: true,
		},
		{
			name:    "denied host:port",
			denies:  []proxy.TargetRule{{Hostname: "evil.com"}},
			addr:    "evil.com:80",
			wantErr: true,
		},
		{
			name:    "scheme-based default port matching",
			allows:  []proxy.TargetRule{{Hostname: "example.com", Ports: []int{443}}},
			scheme:  "https",
			addr:    "example.com:443",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := proxy.NewTargetScope()
			ts.SetAgentRules(tt.allows, tt.denies)

			s := &Server{deps: &deps{targetScope: ts}}
			err := s.checkTargetScopeAddr(tt.scheme, tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkTargetScopeAddr() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTargetScopeCheckRedirect(t *testing.T) {
	tests := []struct {
		name    string
		allows  []proxy.TargetRule
		denies  []proxy.TargetRule
		reqURL  string
		via     int
		wantErr bool
		errMsg  string
	}{
		{
			name:    "allowed redirect",
			allows:  []proxy.TargetRule{{Hostname: "allowed.com"}},
			reqURL:  "http://allowed.com/path",
			wantErr: false,
		},
		{
			name:    "blocked redirect",
			allows:  []proxy.TargetRule{{Hostname: "allowed.com"}},
			reqURL:  "http://evil.com/path",
			wantErr: true,
			errMsg:  "redirect blocked by target scope",
		},
		{
			name:    "too many redirects",
			reqURL:  "http://allowed.com/path",
			via:     maxRedirects,
			wantErr: true,
			errMsg:  "too many redirects",
		},
		{
			name:    "no rules allows redirect",
			reqURL:  "http://any-host.com/path",
			wantErr: false,
		},
		{
			name:    "non-HTTP scheme blocked",
			reqURL:  "ftp://allowed.com/path",
			wantErr: true,
			errMsg:  "non-HTTP scheme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := proxy.NewTargetScope()
			if len(tt.allows) > 0 || len(tt.denies) > 0 {
				ts.SetAgentRules(tt.allows, tt.denies)
			}

			checkFn := targetScopeCheckRedirect(ts)

			reqURL, _ := url.Parse(tt.reqURL)
			req := &http.Request{URL: reqURL}
			via := make([]*http.Request, tt.via)

			err := checkFn(req, via)
			if (err != nil) != tt.wantErr {
				t.Errorf("targetScopeCheckRedirect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("error = %q, want contains %q", err.Error(), tt.errMsg)
			}
		})
	}
}

// Test nil target scope (should never block).
func TestCheckTargetScopeURL_NilScope(t *testing.T) {
	s := &Server{deps: &deps{targetScope: nil}}
	u, _ := url.Parse("http://any-host.com/path")
	if err := s.checkTargetScopeURL(u); err != nil {
		t.Errorf("nil targetScope should allow all, got error: %v", err)
	}
}

func TestCheckTargetScopeAddr_NilScope(t *testing.T) {
	s := &Server{deps: &deps{targetScope: nil}}
	if err := s.checkTargetScopeAddr("http", "any-host.com:80"); err != nil {
		t.Errorf("nil targetScope should allow all, got error: %v", err)
	}
}
