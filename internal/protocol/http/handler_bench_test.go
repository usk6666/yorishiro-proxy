package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func BenchmarkHTTPForwardProxy(b *testing.B) {
	// Start a minimal upstream HTTP server.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyAddr, proxyCancel := startBenchProxy(b, ctx, handler)
	defer proxyCancel()

	// Pre-construct the request line targeting the upstream server.
	reqLine := fmt.Sprintf("GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstream.URL, upstream.Listener.Addr().String())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
		if err != nil {
			b.Fatalf("dial proxy: %v", err)
		}

		if _, err := io.WriteString(conn, reqLine); err != nil {
			conn.Close()
			b.Fatalf("write request: %v", err)
		}

		resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			conn.Close()
			b.Fatalf("read response: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		conn.Close()

		if resp.StatusCode != gohttp.StatusOK {
			b.Fatalf("unexpected status %d", resp.StatusCode)
		}
	}
}

func BenchmarkHTTPForwardProxy_KeepAlive(b *testing.B) {
	// Start a minimal upstream HTTP server.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, nil, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proxyAddr, proxyCancel := startBenchProxy(b, ctx, handler)
	defer proxyCancel()

	reqLine := fmt.Sprintf("GET %s/ HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.URL, upstream.Listener.Addr().String())

	// Use a single connection for all iterations (keep-alive).
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		b.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := io.WriteString(conn, reqLine); err != nil {
			b.Fatalf("write request: %v", err)
		}

		resp, err := gohttp.ReadResponse(reader, nil)
		if err != nil {
			b.Fatalf("read response (iter %d): %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode != gohttp.StatusOK {
			b.Fatalf("unexpected status %d", resp.StatusCode)
		}
	}
}

func BenchmarkHTTPForwardProxy_BodySizes(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"Empty", 0},
		{"1KB", 1024},
		{"64KB", 64 * 1024},
		{"1MB", 1024 * 1024},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			body := strings.Repeat("x", sz.size)
			upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(gohttp.StatusOK)
				fmt.Fprint(w, body)
			}))
			defer upstream.Close()

			store := &mockStore{}
			handler := NewHandler(store, nil, testLogger())

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			proxyAddr, proxyCancel := startBenchProxy(b, ctx, handler)
			defer proxyCancel()

			reqLine := fmt.Sprintf("GET %s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", upstream.URL, upstream.Listener.Addr().String())

			b.ResetTimer()
			b.SetBytes(int64(sz.size))
			for i := 0; i < b.N; i++ {
				conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
				if err != nil {
					b.Fatalf("dial proxy: %v", err)
				}

				if _, err := io.WriteString(conn, reqLine); err != nil {
					conn.Close()
					b.Fatalf("write request: %v", err)
				}

				resp, err := gohttp.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					conn.Close()
					b.Fatalf("read response: %v", err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				conn.Close()
			}
		})
	}
}

// startBenchProxy starts a TCP listener that routes connections through the
// handler's full Handle loop (supporting keep-alive). It uses testing.TB to
// work with both *testing.T and *testing.B.
func startBenchProxy(tb testing.TB, ctx context.Context, handler *Handler) (string, context.CancelFunc) {
	tb.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}

	proxyCtx, proxyCancel := context.WithCancel(ctx)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handler.Handle(proxyCtx, conn)
			}()
		}
	}()

	go func() {
		<-proxyCtx.Done()
		ln.Close()
	}()

	return ln.Addr().String(), proxyCancel
}
