package flow

import (
	"context"
	"fmt"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// newBenchStore creates a SQLiteStore in a temporary directory for benchmarking.
func newBenchStore(b *testing.B) *SQLiteStore {
	b.Helper()
	dbPath := filepath.Join(b.TempDir(), "bench.db")
	logger := testutil.DiscardLogger()
	store, err := NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		b.Fatalf("NewSQLiteStore: %v", err)
	}
	b.Cleanup(func() { store.Close() })
	return store
}

func BenchmarkSaveSession(b *testing.B) {
	store := newBenchStore(b)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fl := &Flow{
			ConnID:    fmt.Sprintf("conn-%d", i),
			Protocol:  "HTTP/1.x",
			FlowType:  "unary",
			State:     "complete",
			Timestamp: time.Now(),
			Duration:  100 * time.Millisecond,
			ConnInfo: &ConnectionInfo{
				ClientAddr: "127.0.0.1:12345",
				ServerAddr: "93.184.216.34:443",
			},
		}
		if err := store.SaveFlow(ctx, fl); err != nil {
			b.Fatalf("SaveFlow: %v", err)
		}
	}
}

func BenchmarkAppendMessage(b *testing.B) {
	store := newBenchStore(b)
	ctx := context.Background()

	// Create a parent flow.
	fl := &Flow{
		ConnID:    "bench-conn",
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		b.Fatalf("SaveFlow: %v", err)
	}

	u, _ := url.Parse("https://example.com/api/test")
	body := []byte(`{"key":"value"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg := &Message{
			FlowID:    fl.ID,
			Sequence:  i,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "POST",
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/json"}},
			Body:      body,
		}
		if err := store.AppendMessage(ctx, msg); err != nil {
			b.Fatalf("AppendMessage: %v", err)
		}
	}
}

func BenchmarkListSessions(b *testing.B) {
	counts := []int{10, 100, 1000}
	for _, n := range counts {
		b.Run(fmt.Sprintf("sessions_%d", n), func(b *testing.B) {
			store := newBenchStore(b)
			ctx := context.Background()

			// Pre-populate sessions.
			for i := 0; i < n; i++ {
				fl := &Flow{
					ConnID:    fmt.Sprintf("conn-%d", i),
					Protocol:  "HTTP/1.x",
					FlowType:  "unary",
					State:     "complete",
					Timestamp: time.Now(),
					Duration:  time.Duration(i) * time.Millisecond,
				}
				if err := store.SaveFlow(ctx, fl); err != nil {
					b.Fatalf("SaveFlow: %v", err)
				}
			}

			opts := ListOptions{Limit: 50}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := store.ListFlows(ctx, opts); err != nil {
					b.Fatalf("ListFlows: %v", err)
				}
			}
		})
	}
}

func BenchmarkListSessions_WithFilter(b *testing.B) {
	store := newBenchStore(b)
	ctx := context.Background()

	// Pre-populate 100 flows with messages.
	for i := 0; i < 100; i++ {
		fl := &Flow{
			ConnID:    fmt.Sprintf("conn-%d", i),
			Protocol:  "HTTP/1.x",
			FlowType:  "unary",
			State:     "complete",
			Timestamp: time.Now(),
			Duration:  time.Duration(i) * time.Millisecond,
		}
		if err := store.SaveFlow(ctx, fl); err != nil {
			b.Fatalf("SaveFlow: %v", err)
		}

		u, _ := url.Parse(fmt.Sprintf("https://example.com/api/v1/resource/%d", i))
		sendMsg := &Message{
			FlowID:    fl.ID,
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now(),
			Method:    "GET",
			URL:       u,
			Headers:   map[string][]string{"Accept": {"application/json"}},
		}
		if err := store.AppendMessage(ctx, sendMsg); err != nil {
			b.Fatalf("AppendMessage: %v", err)
		}

		recvMsg := &Message{
			FlowID:     fl.ID,
			Sequence:   1,
			Direction:  "receive",
			Timestamp:  time.Now(),
			StatusCode: 200,
			Headers:    map[string][]string{"Content-Type": {"application/json"}},
			Body:       []byte(`{"ok":true}`),
		}
		if err := store.AppendMessage(ctx, recvMsg); err != nil {
			b.Fatalf("AppendMessage: %v", err)
		}
	}

	cases := []struct {
		name string
		opts ListOptions
	}{
		{"NoFilter", ListOptions{Limit: 50}},
		{"ByMethod", ListOptions{Method: "GET", Limit: 50}},
		{"ByURL", ListOptions{URLPattern: "resource", Limit: 50}},
		{"ByStatus", ListOptions{StatusCode: 200, Limit: 50}},
		{"Combined", ListOptions{Method: "GET", URLPattern: "resource", StatusCode: 200, Limit: 50}},
	}

	b.ResetTimer()
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := store.ListFlows(ctx, tc.opts); err != nil {
					b.Fatalf("ListFlows: %v", err)
				}
			}
		})
	}
}

func BenchmarkGetSession(b *testing.B) {
	store := newBenchStore(b)
	ctx := context.Background()

	// Create a flow to look up.
	fl := &Flow{
		ConnID:    "bench-get",
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now(),
		Duration:  50 * time.Millisecond,
		ConnInfo: &ConnectionInfo{
			ClientAddr: "127.0.0.1:12345",
			ServerAddr: "93.184.216.34:443",
			TLSVersion: "TLS 1.3",
			TLSCipher:  "TLS_AES_128_GCM_SHA256",
		},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		b.Fatalf("SaveFlow: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.GetFlow(ctx, fl.ID); err != nil {
			b.Fatalf("GetFlow: %v", err)
		}
	}
}
