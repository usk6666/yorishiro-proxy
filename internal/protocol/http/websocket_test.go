package http

import (
	gohttp "net/http"
	"testing"
)

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name: "valid websocket upgrade",
			headers: map[string]string{
				"Connection": "Upgrade",
				"Upgrade":    "websocket",
			},
			want: true,
		},
		{
			name: "case insensitive upgrade value",
			headers: map[string]string{
				"Connection": "Upgrade",
				"Upgrade":    "WebSocket",
			},
			want: true,
		},
		{
			name: "case insensitive connection value",
			headers: map[string]string{
				"Connection": "upgrade",
				"Upgrade":    "websocket",
			},
			want: true,
		},
		{
			name: "connection with multiple values",
			headers: map[string]string{
				"Connection": "keep-alive, Upgrade",
				"Upgrade":    "websocket",
			},
			want: true,
		},
		{
			name: "missing upgrade header",
			headers: map[string]string{
				"Connection": "Upgrade",
			},
			want: false,
		},
		{
			name: "missing connection header",
			headers: map[string]string{
				"Upgrade": "websocket",
			},
			want: false,
		},
		{
			name: "wrong upgrade protocol",
			headers: map[string]string{
				"Connection": "Upgrade",
				"Upgrade":    "h2c",
			},
			want: false,
		},
		{
			name: "connection without upgrade token",
			headers: map[string]string{
				"Connection": "keep-alive",
				"Upgrade":    "websocket",
			},
			want: false,
		},
		{
			name:    "no headers",
			headers: map[string]string{},
			want:    false,
		},
		{
			name: "upgrade with whitespace",
			headers: map[string]string{
				"Connection": "Upgrade",
				"Upgrade":    " websocket ",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &gohttp.Request{
				Header: gohttp.Header{},
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			got := isWebSocketUpgrade(req)
			if got != tt.want {
				t.Errorf("isWebSocketUpgrade() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHeaderContains(t *testing.T) {
	tests := []struct {
		name   string
		header string
		token  string
		want   bool
	}{
		{"single match", "Upgrade", "upgrade", true},
		{"comma separated", "keep-alive, Upgrade", "upgrade", true},
		{"no match", "keep-alive", "upgrade", false},
		{"empty header", "", "upgrade", false},
		{"empty token", "Upgrade", "", false},
		{"multiple commas", "keep-alive, Upgrade, foo", "upgrade", true},
		{"partial match", "Upgrade-Insecure-Requests", "upgrade", false},
		{"with whitespace", " Upgrade ", "upgrade", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := headerContains(tt.header, tt.token)
			if got != tt.want {
				t.Errorf("headerContains(%q, %q) = %v, want %v", tt.header, tt.token, got, tt.want)
			}
		})
	}
}
