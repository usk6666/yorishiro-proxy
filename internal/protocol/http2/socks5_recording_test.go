package http2

import (
	"context"
	"net/url"
	"testing"
	"time"

	gohttp "net/http"

	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestRecordSend_SOCKS5Protocol(t *testing.T) {
	tests := []struct {
		name         string
		ctx          context.Context
		wantProtocol string
		wantTags     map[string]string
	}{
		{
			name:         "no SOCKS5 context records HTTP/2",
			ctx:          context.Background(),
			wantProtocol: "HTTP/2",
			wantTags:     nil,
		},
		{
			name: "SOCKS5 context records SOCKS5+HTTP/2",
			ctx: proxy.ContextWithSOCKS5AuthUser(
				proxy.ContextWithSOCKS5AuthMethod(
					proxy.ContextWithSOCKS5Target(context.Background(), "example.com:443"),
					"username_password"),
				"admin"),
			wantProtocol: "SOCKS5+HTTP/2",
			wantTags: map[string]string{
				"socks5_target":      "example.com:443",
				"socks5_auth_method": "username_password",
				"socks5_auth_user":   "admin",
			},
		},
		{
			name:         "SOCKS5 context without auth records SOCKS5+HTTP/2 with target only",
			ctx:          proxy.ContextWithSOCKS5Target(context.Background(), "10.0.0.1:443"),
			wantProtocol: "SOCKS5+HTTP/2",
			wantTags: map[string]string{
				"socks5_target": "10.0.0.1:443",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockStore{}
			handler := NewHandler(store, testutil.DiscardLogger())

			reqURL, _ := url.Parse("https://example.com/api/test")
			req, _ := gohttp.NewRequestWithContext(tt.ctx, "GET", reqURL.String(), nil)

			result := handler.recordSend(tt.ctx, sendRecordParams{
				connID: "conn-1",
				scheme: "https",
				start:  time.Now(),
				req:    req,
				reqURL: reqURL,
			}, handler.Logger)

			if result == nil {
				t.Fatal("recordSend returned nil")
			}

			entries := store.Entries()
			if len(entries) != 1 {
				t.Fatalf("expected 1 flow entry, got %d", len(entries))
			}

			fl := entries[0].Session
			if fl.Protocol != tt.wantProtocol {
				t.Errorf("protocol = %q, want %q", fl.Protocol, tt.wantProtocol)
			}

			if tt.wantTags == nil {
				// No SOCKS5 tags expected; tags should be nil or empty.
				if len(fl.Tags) != 0 {
					t.Errorf("tags = %v, want empty", fl.Tags)
				}
			} else {
				for k, v := range tt.wantTags {
					if fl.Tags[k] != v {
						t.Errorf("tags[%q] = %q, want %q", k, fl.Tags[k], v)
					}
				}
			}
		})
	}
}

func TestRecordSendWithVariant_SOCKS5Protocol(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := proxy.ContextWithSOCKS5Target(context.Background(), "example.com:443")
	ctx = proxy.ContextWithSOCKS5AuthMethod(ctx, "none")

	reqURL, _ := url.Parse("https://example.com/api/test")
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", reqURL.String(), nil)
	req.Header.Set("Content-Type", "application/json")

	result := handler.recordSendWithVariant(ctx, sendRecordParams{
		connID: "conn-2",
		scheme: "https",
		start:  time.Now(),
		req:    req,
		reqURL: reqURL,
	}, nil, handler.Logger)

	if result == nil {
		t.Fatal("recordSendWithVariant returned nil")
	}

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	fl := entries[0].Session
	if fl.Protocol != "SOCKS5+HTTP/2" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "SOCKS5+HTTP/2")
	}
	if fl.Tags["socks5_target"] != "example.com:443" {
		t.Errorf("tags[socks5_target] = %q, want %q", fl.Tags["socks5_target"], "example.com:443")
	}
	if fl.Tags["socks5_auth_method"] != "none" {
		t.Errorf("tags[socks5_auth_method] = %q, want %q", fl.Tags["socks5_auth_method"], "none")
	}
}

func TestRecordInterceptDrop_SOCKS5Protocol(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := proxy.ContextWithSOCKS5Target(context.Background(), "target.host:443")

	reqURL, _ := url.Parse("https://target.host/path")
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)

	handler.recordInterceptDrop(ctx, sendRecordParams{
		connID: "conn-3",
		scheme: "https",
		start:  time.Now(),
		req:    req,
		reqURL: reqURL,
	}, handler.Logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	fl := entries[0].Session
	if fl.Protocol != "SOCKS5+HTTP/2" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "SOCKS5+HTTP/2")
	}
	if fl.Tags["socks5_target"] != "target.host:443" {
		t.Errorf("tags[socks5_target] = %q, want %q", fl.Tags["socks5_target"], "target.host:443")
	}
}

func TestRecordOutReqError_SOCKS5Protocol(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	ctx := proxy.ContextWithSOCKS5Target(context.Background(), "target.host:443")
	ctx = proxy.ContextWithSOCKS5AuthMethod(ctx, "username_password")
	ctx = proxy.ContextWithSOCKS5AuthUser(ctx, "testuser")

	reqURL, _ := url.Parse("https://target.host/path")
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)

	handler.recordOutReqError(ctx, sendRecordParams{
		connID: "conn-4",
		scheme: "https",
		start:  time.Now(),
		req:    req,
		reqURL: reqURL,
	}, gohttp.ErrAbortHandler, handler.Logger)

	entries := store.Entries()
	if len(entries) != 1 {
		t.Fatalf("expected 1 flow entry, got %d", len(entries))
	}

	fl := entries[0].Session
	if fl.Protocol != "SOCKS5+HTTP/2" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "SOCKS5+HTTP/2")
	}
	if fl.Tags["socks5_target"] != "target.host:443" {
		t.Errorf("tags[socks5_target] = %q, want %q", fl.Tags["socks5_target"], "target.host:443")
	}
	if fl.Tags["socks5_auth_method"] != "username_password" {
		t.Errorf("tags[socks5_auth_method] = %q, want %q", fl.Tags["socks5_auth_method"], "username_password")
	}
	if fl.Tags["socks5_auth_user"] != "testuser" {
		t.Errorf("tags[socks5_auth_user] = %q, want %q", fl.Tags["socks5_auth_user"], "testuser")
	}
	// Error tag should also be present.
	if fl.Tags["error"] == "" {
		t.Error("error tag should be set")
	}
	if fl.State != "error" {
		t.Errorf("state = %q, want %q", fl.State, "error")
	}
}
