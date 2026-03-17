package proxy

import (
	"context"
	"testing"
)

func TestSOCKS5Protocol(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		base string
		want string
	}{
		{
			name: "no SOCKS5 context, HTTP/1.x",
			ctx:  context.Background(),
			base: "HTTP/1.x",
			want: "HTTP/1.x",
		},
		{
			name: "no SOCKS5 context, HTTPS",
			ctx:  context.Background(),
			base: "HTTPS",
			want: "HTTPS",
		},
		{
			name: "no SOCKS5 context, HTTP/2",
			ctx:  context.Background(),
			base: "HTTP/2",
			want: "HTTP/2",
		},
		{
			name: "no SOCKS5 context, gRPC",
			ctx:  context.Background(),
			base: "gRPC",
			want: "gRPC",
		},
		{
			name: "SOCKS5 context, HTTP/1.x becomes SOCKS5+HTTP",
			ctx:  ContextWithSOCKS5Target(context.Background(), "example.com:80"),
			base: "HTTP/1.x",
			want: "SOCKS5+HTTP",
		},
		{
			name: "SOCKS5 context, HTTPS becomes SOCKS5+HTTPS",
			ctx:  ContextWithSOCKS5Target(context.Background(), "example.com:443"),
			base: "HTTPS",
			want: "SOCKS5+HTTPS",
		},
		{
			name: "SOCKS5 context, HTTP/2 becomes SOCKS5+HTTP/2",
			ctx:  ContextWithSOCKS5Target(context.Background(), "example.com:443"),
			base: "HTTP/2",
			want: "SOCKS5+HTTP/2",
		},
		{
			name: "SOCKS5 context, gRPC becomes SOCKS5+gRPC",
			ctx:  ContextWithSOCKS5Target(context.Background(), "example.com:443"),
			base: "gRPC",
			want: "SOCKS5+gRPC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SOCKS5Protocol(tt.ctx, tt.base)
			if got != tt.want {
				t.Errorf("SOCKS5Protocol() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMergeSOCKS5Tags(t *testing.T) {
	t.Run("no SOCKS5 context returns original tags", func(t *testing.T) {
		ctx := context.Background()
		tags := map[string]string{"existing": "value"}
		result := MergeSOCKS5Tags(ctx, tags)
		if len(result) != 1 || result["existing"] != "value" {
			t.Errorf("unexpected tags: %v", result)
		}
	})

	t.Run("nil tags, no SOCKS5 context", func(t *testing.T) {
		ctx := context.Background()
		result := MergeSOCKS5Tags(ctx, nil)
		if result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})

	t.Run("SOCKS5 context adds all metadata", func(t *testing.T) {
		ctx := context.Background()
		ctx = ContextWithSOCKS5Target(ctx, "example.com:443")
		ctx = ContextWithSOCKS5AuthMethod(ctx, "username_password")
		ctx = ContextWithSOCKS5AuthUser(ctx, "admin")

		tags := map[string]string{"existing": "value"}
		result := MergeSOCKS5Tags(ctx, tags)

		if result["existing"] != "value" {
			t.Error("existing tag lost")
		}
		if result["socks5_target"] != "example.com:443" {
			t.Errorf("socks5_target = %q, want %q", result["socks5_target"], "example.com:443")
		}
		if result["socks5_auth_method"] != "username_password" {
			t.Errorf("socks5_auth_method = %q, want %q", result["socks5_auth_method"], "username_password")
		}
		if result["socks5_auth_user"] != "admin" {
			t.Errorf("socks5_auth_user = %q, want %q", result["socks5_auth_user"], "admin")
		}
	})

	t.Run("SOCKS5 context with nil tags creates map", func(t *testing.T) {
		ctx := context.Background()
		ctx = ContextWithSOCKS5Target(ctx, "10.0.0.1:80")
		ctx = ContextWithSOCKS5AuthMethod(ctx, "none")

		result := MergeSOCKS5Tags(ctx, nil)
		if result == nil {
			t.Fatal("expected non-nil map")
		}
		if result["socks5_target"] != "10.0.0.1:80" {
			t.Errorf("socks5_target = %q, want %q", result["socks5_target"], "10.0.0.1:80")
		}
		if result["socks5_auth_method"] != "none" {
			t.Errorf("socks5_auth_method = %q, want %q", result["socks5_auth_method"], "none")
		}
		if _, ok := result["socks5_auth_user"]; ok {
			t.Error("socks5_auth_user should not be set for empty user")
		}
	})

	t.Run("SOCKS5 target only, no auth", func(t *testing.T) {
		ctx := ContextWithSOCKS5Target(context.Background(), "host:443")
		result := MergeSOCKS5Tags(ctx, nil)
		if result["socks5_target"] != "host:443" {
			t.Errorf("socks5_target = %q, want %q", result["socks5_target"], "host:443")
		}
		if _, ok := result["socks5_auth_method"]; ok {
			t.Error("socks5_auth_method should not be set")
		}
	})
}
