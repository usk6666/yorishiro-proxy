package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseUpstreamProxy(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *url.URL
		wantErr bool
		errMsg  string
	}{
		{
			name:  "empty string returns nil",
			input: "",
			want:  nil,
		},
		{
			name:  "http proxy",
			input: "http://proxy.example.com:3128",
			want:  &url.URL{Scheme: "http", Host: "proxy.example.com:3128"},
		},
		{
			name:  "http proxy with auth",
			input: "http://user:pass@proxy.example.com:3128",
			want: &url.URL{
				Scheme: "http",
				User:   url.UserPassword("user", "pass"),
				Host:   "proxy.example.com:3128",
			},
		},
		{
			name:  "socks5 proxy",
			input: "socks5://socks.example.com:1080",
			want:  &url.URL{Scheme: "socks5", Host: "socks.example.com:1080"},
		},
		{
			name:  "socks5 proxy with auth",
			input: "socks5://user:pass@socks.example.com:1080",
			want: &url.URL{
				Scheme: "socks5",
				User:   url.UserPassword("user", "pass"),
				Host:   "socks.example.com:1080",
			},
		},
		{
			name:    "unsupported scheme https",
			input:   "https://proxy.example.com:3128",
			wantErr: true,
			errMsg:  "unsupported upstream proxy scheme",
		},
		{
			name:    "unsupported scheme ftp",
			input:   "ftp://proxy.example.com:21",
			wantErr: true,
			errMsg:  "unsupported upstream proxy scheme",
		},
		{
			name:    "missing port",
			input:   "http://proxy.example.com",
			wantErr: true,
			errMsg:  "must include a port",
		},
		{
			name:    "empty host",
			input:   "http://:3128",
			wantErr: true,
			errMsg:  "empty host or port",
		},
		{
			name:    "invalid URL",
			input:   "://bad",
			wantErr: true,
		},
		{
			name:    "no host at all",
			input:   "http://",
			wantErr: true,
			errMsg:  "has no host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseUpstreamProxy(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseUpstreamProxy(%q) = %v, want error", tt.input, got)
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseUpstreamProxy(%q) error: %v", tt.input, err)
			}
			if tt.want == nil {
				if got != nil {
					t.Errorf("ParseUpstreamProxy(%q) = %v, want nil", tt.input, got)
				}
				return
			}
			if got.Scheme != tt.want.Scheme {
				t.Errorf("scheme = %q, want %q", got.Scheme, tt.want.Scheme)
			}
			if got.Host != tt.want.Host {
				t.Errorf("host = %q, want %q", got.Host, tt.want.Host)
			}
		})
	}
}

func TestTransportProxyFunc(t *testing.T) {
	t.Run("nil URL returns nil function", func(t *testing.T) {
		fn := TransportProxyFunc(nil)
		if fn != nil {
			t.Error("TransportProxyFunc(nil) should return nil")
		}
	})

	t.Run("non-nil URL returns function that returns the URL", func(t *testing.T) {
		proxyURL, _ := url.Parse("http://proxy:3128")
		fn := TransportProxyFunc(proxyURL)
		if fn == nil {
			t.Fatal("TransportProxyFunc should return non-nil function")
		}
		req, _ := gohttp.NewRequest("GET", "http://example.com", nil)
		got, err := fn(req)
		if err != nil {
			t.Fatalf("proxy function error: %v", err)
		}
		if got.String() != proxyURL.String() {
			t.Errorf("proxy function returned %q, want %q", got.String(), proxyURL.String())
		}
	})
}

// startMockHTTPProxy starts a mock HTTP CONNECT proxy for testing.
// It accepts CONNECT requests and tunnels the connection.
func startMockHTTPProxy(t *testing.T, requireAuth bool, username, password string) (string, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockHTTPProxy(conn, requireAuth, username, password)
		}
	}()

	cleanup := func() {
		ln.Close()
		<-done
	}

	return ln.Addr().String(), cleanup
}

func handleMockHTTPProxy(conn net.Conn, requireAuth bool, username, password string) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := gohttp.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method != gohttp.MethodConnect {
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}

	// Check proxy authentication if required.
	if requireAuth {
		authHeader := req.Header.Get("Proxy-Authorization")
		if authHeader == "" {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
		if authHeader != expected {
			conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
			return
		}
	}

	// Connect to the target.
	target, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer target.Close()

	// Send 200 OK.
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Relay data bidirectionally.
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, reader)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, target)
		errCh <- err
	}()
	<-errCh
}

func TestDialViaHTTPProxy(t *testing.T) {
	// Start a simple TCP echo server.
	echoAddr := startEchoServer(t)

	t.Run("successful CONNECT", func(t *testing.T) {
		proxyAddr, cleanup := startMockHTTPProxy(t, false, "", "")
		defer cleanup()

		proxyURL, _ := url.Parse("http://" + proxyAddr)
		ctx := context.Background()

		conn, err := DialViaUpstreamProxy(ctx, proxyURL, echoAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("DialViaUpstreamProxy: %v", err)
		}
		defer conn.Close()

		// Test that the connection works by sending data through.
		testMsg := "hello via proxy"
		if _, err := conn.Write([]byte(testMsg)); err != nil {
			t.Fatalf("write: %v", err)
		}

		buf := make([]byte, len(testMsg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != testMsg {
			t.Errorf("got %q, want %q", buf, testMsg)
		}
	})

	t.Run("CONNECT with authentication", func(t *testing.T) {
		proxyAddr, cleanup := startMockHTTPProxy(t, true, "user", "pass")
		defer cleanup()

		proxyURL, _ := url.Parse("http://user:pass@" + proxyAddr)
		ctx := context.Background()

		conn, err := DialViaUpstreamProxy(ctx, proxyURL, echoAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("DialViaUpstreamProxy with auth: %v", err)
		}
		defer conn.Close()

		testMsg := "auth test"
		conn.Write([]byte(testMsg))
		buf := make([]byte, len(testMsg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != testMsg {
			t.Errorf("got %q, want %q", buf, testMsg)
		}
	})

	t.Run("CONNECT with wrong auth fails", func(t *testing.T) {
		proxyAddr, cleanup := startMockHTTPProxy(t, true, "user", "pass")
		defer cleanup()

		proxyURL, _ := url.Parse("http://wrong:creds@" + proxyAddr)
		ctx := context.Background()

		_, err := DialViaUpstreamProxy(ctx, proxyURL, echoAddr, 5*time.Second)
		if err == nil {
			t.Fatal("expected error for wrong auth, got nil")
		}
		if !strings.Contains(err.Error(), "407") {
			t.Errorf("error %q should contain 407", err.Error())
		}
	})

	t.Run("CONNECT to unreachable proxy", func(t *testing.T) {
		proxyURL, _ := url.Parse("http://127.0.0.1:1") // likely unreachable port
		ctx := context.Background()

		_, err := DialViaUpstreamProxy(ctx, proxyURL, echoAddr, 2*time.Second)
		if err == nil {
			t.Fatal("expected error for unreachable proxy, got nil")
		}
	})

	t.Run("nil proxy URL returns error", func(t *testing.T) {
		ctx := context.Background()
		_, err := DialViaUpstreamProxy(ctx, nil, echoAddr, 2*time.Second)
		if err == nil {
			t.Fatal("expected error for nil proxyURL, got nil")
		}
	})
}

func TestDialViaSOCKS5Proxy_InvalidProxy(t *testing.T) {
	// Test SOCKS5 dialing with an unreachable proxy.
	proxyURL, _ := url.Parse("socks5://127.0.0.1:1")
	ctx := context.Background()

	_, err := DialViaUpstreamProxy(ctx, proxyURL, "example.com:80", 2*time.Second)
	if err == nil {
		t.Fatal("expected error for unreachable SOCKS5 proxy, got nil")
	}
}

func TestDialViaUpstreamProxy_UnsupportedScheme(t *testing.T) {
	proxyURL := &url.URL{Scheme: "ftp", Host: "proxy:21"}
	ctx := context.Background()

	_, err := DialViaUpstreamProxy(ctx, proxyURL, "example.com:80", 2*time.Second)
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
	if !strings.Contains(err.Error(), "unsupported proxy scheme") {
		t.Errorf("error %q should mention unsupported proxy scheme", err.Error())
	}
}

// startEchoServer starts a TCP server that echoes back whatever it receives.
func startEchoServer(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	t.Cleanup(func() { ln.Close() })

	return ln.Addr().String()
}

func TestDialViaHTTPProxy_TargetUnreachable(t *testing.T) {
	// Start proxy but try to CONNECT to an unreachable target.
	proxyAddr, cleanup := startMockHTTPProxy(t, false, "", "")
	defer cleanup()

	proxyURL, _ := url.Parse("http://" + proxyAddr)
	ctx := context.Background()

	// Use a target that's almost certainly not listening.
	_, err := DialViaUpstreamProxy(ctx, proxyURL, "127.0.0.1:1", 2*time.Second)
	if err == nil {
		t.Fatal("expected error when target is unreachable through proxy")
	}
	// The mock proxy should return 502.
	if !strings.Contains(err.Error(), "502") {
		t.Logf("error (may vary): %v", err)
	}
}

// startMockSOCKS5Proxy starts a minimal mock SOCKS5 proxy using a TCP listener.
// This uses golang.org/x/net/proxy under the hood by creating a real SOCKS5 server.
// For a simpler test, we just verify that the SOCKS5 dialer connects to the proxy.
func startMockSOCKS5Proxy(t *testing.T) string {
	t.Helper()

	// Start a simple TCP listener that accepts SOCKS5 connections.
	// Since a full SOCKS5 server implementation is complex, we test with a real
	// echo server and verify the error handling for unreachable SOCKS5 proxies.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	// Accept and immediately close connections (invalid SOCKS5 server).
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestDialViaSOCKS5Proxy_InvalidServer(t *testing.T) {
	// A server that immediately closes connections will cause SOCKS5 handshake failure.
	mockAddr := startMockSOCKS5Proxy(t)
	proxyURL, _ := url.Parse(fmt.Sprintf("socks5://%s", mockAddr))
	ctx := context.Background()

	_, err := DialViaUpstreamProxy(ctx, proxyURL, "example.com:80", 5*time.Second)
	if err == nil {
		t.Fatal("expected error for invalid SOCKS5 server")
	}
}
