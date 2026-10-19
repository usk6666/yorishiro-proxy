package connector

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// USK-1142: connections refused because max_connections is saturated must
// be observable. These tests drive the real FullListener reject path (the
// capacity harness from full_listener_test.go fills the listener first) and
// assert on what OnReject receives and what is logged.

// rejectRecorder collects RejectInfo values delivered to OnReject.
type rejectRecorder struct {
	ch chan RejectInfo
}

func newRejectRecorder() *rejectRecorder {
	return &rejectRecorder{ch: make(chan RejectInfo, 256)}
}

func (r *rejectRecorder) onReject(info RejectInfo) {
	r.ch <- info
}

func (r *rejectRecorder) next(t *testing.T, within time.Duration) RejectInfo {
	t.Helper()
	select {
	case info := <-r.ch:
		return info
	case <-time.After(within):
		t.Fatalf("OnReject was not called within %v", within)
		return RejectInfo{}
	}
}

// dialAndSend dials addr, writes payload (if any), and returns the conn.
// The caller closes it.
func dialAndSend(t *testing.T, addr string, payload []byte) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return conn
}

func TestFullListener_OnReject_ReportsKindAndTarget(t *testing.T) {
	tests := []struct {
		name        string
		payload     []byte
		wantKind    ProtocolKind
		wantMethod  string
		wantTarget  string
		wantWrote   bool
		readTimeout time.Duration
		// rejectPeekTimeout overrides FullListener.rejectPeekTimeout
		// when non-zero. Only the silent-client row waits on it.
		rejectPeekTimeout time.Duration
	}{
		{
			name: "HTTP/1 absolute-form request line is reported verbatim",
			// Absolute-form request-target as sent by a browser to a
			// forward proxy (RFC 9112 §3.2.2).
			payload:     []byte("GET http://h/p HTTP/1.1\r\nHost: h\r\n\r\n"),
			wantKind:    ProtocolHTTP1,
			wantMethod:  "GET",
			wantTarget:  "http://h/p",
			wantWrote:   true,
			readTimeout: 2 * time.Second,
		},
		{
			name:        "CONNECT authority is reported",
			payload:     []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
			wantKind:    ProtocolHTTPConnect,
			wantMethod:  "CONNECT",
			wantTarget:  "example.com:443",
			wantWrote:   true,
			readTimeout: 2 * time.Second,
		},
		{
			name:        "SOCKS5 greeting has no target and no 503",
			payload:     []byte{0x05, 0x01, 0x00},
			wantKind:    ProtocolSOCKS5,
			wantWrote:   false,
			readTimeout: 2 * time.Second,
		},
		{
			name:      "silent client is reported as unknown after the reject peek timeout",
			payload:   nil,
			wantKind:  ProtocolUnknown,
			wantWrote: false,
			// Bounded just above the shortened reject peek timeout so
			// a listener that ignored the field (default 1s) goes red.
			readTimeout:       700 * time.Millisecond,
			rejectPeekTimeout: 200 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := newRejectRecorder()
			h := newCapacityRejectionHarnessWith(t, 1, func(cfg *FullListenerConfig) {
				cfg.Name = "reject-test"
				cfg.OnReject = rec.onReject
			}, func(fl *FullListener) {
				if tt.rejectPeekTimeout > 0 {
					fl.rejectPeekTimeout = tt.rejectPeekTimeout
				}
			})
			t.Cleanup(h.Release)

			conn := dialAndSend(t, h.Addr(), tt.payload)
			defer conn.Close()

			info := rec.next(t, tt.readTimeout)
			if info.DetectedKind != tt.wantKind {
				t.Errorf("DetectedKind = %v, want %v", info.DetectedKind, tt.wantKind)
			}
			if info.Method != tt.wantMethod {
				t.Errorf("Method = %q, want %q", info.Method, tt.wantMethod)
			}
			if info.Target != tt.wantTarget {
				t.Errorf("Target = %q, want %q", info.Target, tt.wantTarget)
			}
			if info.TargetTruncated {
				t.Errorf("TargetTruncated = true, want false")
			}
			if info.WroteResponse != tt.wantWrote {
				t.Errorf("WroteResponse = %v, want %v", info.WroteResponse, tt.wantWrote)
			}
			if info.MaxConnections != 1 {
				t.Errorf("MaxConnections = %d, want 1", info.MaxConnections)
			}
			if info.Listener != "reject-test" {
				t.Errorf("Listener = %q, want %q", info.Listener, "reject-test")
			}
			if info.ForwardPort != "" {
				t.Errorf("ForwardPort = %q, want empty for the main listener", info.ForwardPort)
			}
			if got, want := info.RemoteAddr, conn.LocalAddr().String(); got != want {
				t.Errorf("RemoteAddr = %q, want %q", got, want)
			}
			if info.At.IsZero() {
				t.Errorf("At is zero")
			}

			// Exactly one call per rejection.
			select {
			case extra := <-rec.ch:
				t.Errorf("OnReject called twice; extra = %+v", extra)
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// TestFullListener_OnReject_StalledRequestLine covers a CONNECT whose
// request line never completes: the reject goroutine must still finish
// within the reject peek timeout + rejectWriteDeadline and report the
// partial target as observed. Detection and the request-line read share
// one absolute deadline, so the shortened rejectPeekTimeout bounds both.
func TestFullListener_OnReject_StalledRequestLine(t *testing.T) {
	const peekTimeout = 300 * time.Millisecond
	rec := newRejectRecorder()
	h := newCapacityRejectionHarnessWith(t, 1, func(cfg *FullListenerConfig) {
		cfg.OnReject = rec.onReject
	}, func(fl *FullListener) {
		fl.rejectPeekTimeout = peekTimeout
	})
	t.Cleanup(h.Release)

	start := time.Now()
	conn := dialAndSend(t, h.Addr(), []byte("CONNECT exa"))
	defer conn.Close()

	info := rec.next(t, peekTimeout+rejectWriteDeadline)
	if elapsed := time.Since(start); elapsed > peekTimeout+rejectWriteDeadline {
		t.Errorf("rejection took %v, want <= %v", elapsed, peekTimeout+rejectWriteDeadline)
	}
	if info.DetectedKind != ProtocolHTTPConnect {
		t.Errorf("DetectedKind = %v, want %v", info.DetectedKind, ProtocolHTTPConnect)
	}
	if info.Method != "CONNECT" {
		t.Errorf("Method = %q, want CONNECT", info.Method)
	}
	if info.Target != "exa" {
		t.Errorf("Target = %q, want partial %q", info.Target, "exa")
	}
	if info.TargetTruncated {
		t.Errorf("TargetTruncated = true, want false for a short partial line")
	}
}

// TestFullListener_OnReject_LongTargetTruncated: a 9 KiB request-target is
// cut at MaxRejectTargetLen with TargetTruncated set, without parsing past
// the reject-path line cap.
func TestFullListener_OnReject_LongTargetTruncated(t *testing.T) {
	rec := newRejectRecorder()
	h := newCapacityRejectionHarnessWith(t, 1, func(cfg *FullListenerConfig) {
		cfg.OnReject = rec.onReject
	})
	t.Cleanup(h.Release)

	long := strings.Repeat("a", 9*1024)
	conn := dialAndSend(t, h.Addr(), []byte("CONNECT "+long+" HTTP/1.1\r\n\r\n"))
	defer conn.Close()

	info := rec.next(t, 3*time.Second)
	if !info.TargetTruncated {
		t.Errorf("TargetTruncated = false, want true")
	}
	if len(info.Target) != MaxRejectTargetLen {
		t.Errorf("len(Target) = %d, want %d", len(info.Target), MaxRejectTargetLen)
	}
	if !strings.HasPrefix(long, info.Target) || info.Target == "" {
		t.Errorf("Target is not a prefix of the wire target (len=%d)", len(info.Target))
	}
}

// TestFullListener_OnReject_TargetCasingPreserved: MITM Principle 1 — the
// request-target is reported byte-identical, no case folding.
func TestFullListener_OnReject_TargetCasingPreserved(t *testing.T) {
	rec := newRejectRecorder()
	h := newCapacityRejectionHarnessWith(t, 1, func(cfg *FullListenerConfig) {
		cfg.OnReject = rec.onReject
	})
	t.Cleanup(h.Release)

	conn := dialAndSend(t, h.Addr(), []byte("CONNECT ExAmPlE.com:443 HTTP/1.1\r\nHost: ExAmPlE.com:443\r\n\r\n"))
	defer conn.Close()

	info := rec.next(t, 2*time.Second)
	if info.Target != "ExAmPlE.com:443" {
		t.Errorf("Target = %q, want byte-identical %q", info.Target, "ExAmPlE.com:443")
	}
}

// capturedRecord is one slog record seen by captureHandler.
type capturedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]any
}

// captureHandler is a concurrency-safe slog.Handler that keeps every
// record at or above Debug.
type captureHandler struct {
	mu      sync.Mutex
	records []capturedRecord
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{level: r.Level, msg: r.Message, attrs: map[string]any{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	h.records = append(h.records, rec)
	h.mu.Unlock()
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// rejectionLogs returns the captured records that describe a capacity
// rejection, split by level.
func (h *captureHandler) rejectionLogs() (warns, debugs []capturedRecord) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if !strings.Contains(r.msg, "rejected") {
			continue
		}
		switch r.level {
		case slog.LevelWarn:
			warns = append(warns, r)
		case slog.LevelDebug:
			debugs = append(debugs, r)
		}
	}
	return warns, debugs
}

// TestFullListener_RejectionWarn_RateLimited: a burst of rejections inside
// one window yields exactly one Warn (plus one Debug per rejection); the
// first rejection after the window emits a second Warn carrying the number
// of rejections suppressed since the previous Warn.
func TestFullListener_RejectionWarn_RateLimited(t *testing.T) {
	handler := &captureHandler{}
	var clockNs atomic.Int64
	base := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	clockNs.Store(base.UnixNano())
	clock := func() time.Time { return time.Unix(0, clockNs.Load()) }

	h := newCapacityRejectionHarnessWith(t, 1, func(cfg *FullListenerConfig) {
		cfg.Logger = slog.New(handler)
	}, func(fl *FullListener) {
		fl.now = clock
	})
	t.Cleanup(h.Release)

	const burst = 50
	waitRejections := func(n int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			warns, debugs := handler.rejectionLogs()
			if len(debugs) >= n || len(warns) >= n {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	for i := 0; i < burst; i++ {
		// SOCKS5 first byte: detection is immediate, no 503 write, so the
		// reject goroutine finishes quickly.
		c := dialAndSend(t, h.Addr(), []byte{0x05})
		_ = c.Close()
	}
	waitRejections(burst)

	warns, debugs := handler.rejectionLogs()
	if len(warns) != 1 {
		t.Fatalf("Warn count after %d rejections in one window = %d, want 1", burst, len(warns))
	}
	if len(debugs) != burst {
		t.Fatalf("Debug count = %d, want %d (one per rejection)", len(debugs), burst)
	}

	// Advance past the window; the next rejection warns again and reports
	// how many were suppressed.
	clockNs.Add(int64(rejectWarnWindow + time.Second))
	c := dialAndSend(t, h.Addr(), []byte{0x05})
	_ = c.Close()
	waitRejections(burst + 1)

	warns, _ = handler.rejectionLogs()
	if len(warns) != 2 {
		t.Fatalf("Warn count after the window = %d, want 2", len(warns))
	}
	got, ok := warns[1].attrs["suppressed"]
	if !ok {
		t.Fatalf("second Warn has no suppressed attr: %+v", warns[1].attrs)
	}
	if n, _ := got.(int64); n != burst-1 {
		t.Errorf("suppressed = %v, want %d", got, burst-1)
	}
}
