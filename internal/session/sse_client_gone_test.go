package session

import (
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// TestIsClientGoneErr_TypedSentinels verifies the typed-error matcher
// covers each documented sentinel — including USK-903's HTTP/2-specific
// http2.ErrWriterClosed addition. Without that entry, SSE-over-h2
// recorded curl --max-time-style client cancels as state=error instead
// of state=complete (asymmetric with H/1.1).
func TestIsClientGoneErr_TypedSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"net.ErrClosed bare", net.ErrClosed, true},
		{"net.ErrClosed wrapped", fmt.Errorf("session: SSE client write: %w", net.ErrClosed), true},
		{"syscall.EPIPE bare", syscall.EPIPE, true},
		{"syscall.EPIPE wrapped", fmt.Errorf("session: SSE client write: %w", syscall.EPIPE), true},
		{"syscall.ECONNRESET bare", syscall.ECONNRESET, true},
		{"io.ErrClosedPipe bare", io.ErrClosedPipe, true},
		{"http2.ErrWriterClosed bare", http2.ErrWriterClosed, true},
		{"http2.ErrWriterClosed wrapped via fmt.Errorf %w", fmt.Errorf("session: SSE client write: %w", http2.ErrWriterClosed), true},
		{"http2.ErrDetachWriterClosed bare", http2.ErrDetachWriterClosed, true},
		{"http2.ErrDetachWriterClosed wrapped via fmt.Errorf %w", fmt.Errorf("session: SSE client write: %w", http2.ErrDetachWriterClosed), true},
		// Negative cases: real errors that must NOT be classified as
		// client-gone. These are the regression guard against the fix
		// over-matching and silently masking genuine problems.
		{"unrelated error", errors.New("upstream RST_STREAM(INTERNAL_ERROR)"), false},
		{"io.EOF (handled separately upstream)", io.EOF, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isClientGoneErr(tc.err); got != tc.want {
				t.Errorf("isClientGoneErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestIsClientGoneErr_SubstringFallback covers the wrapped/string-form
// path for non-syscall errors that don't preserve the typed sentinel
// through the wrap chain (e.g. TLS net.OpError reformatted as a string,
// or a future code path that wraps the syscall via a string-only
// error). The substring branch must keep recognising these.
func TestIsClientGoneErr_SubstringFallback(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"broken pipe substring", errors.New("write tcp 127.0.0.1:8080: broken pipe"), true},
		{"connection reset substring", errors.New("read tcp 127.0.0.1:8080: connection reset by peer"), true},
		{"use of closed network connection", errors.New("read tcp 127.0.0.1:8080: use of closed network connection"), true},
		// Negative case: a string that contains the word "connection"
		// but is not a client-gone signal.
		{"unrelated error", errors.New("could not establish connection: timeout"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isClientGoneErr(tc.err); got != tc.want {
				t.Errorf("isClientGoneErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestErrClientGoneAcked_IsExportedSentinel confirms the sentinel
// re-export (USK-903) preserves errors.Is identity so cross-package
// callers (proxybuild OnComplete) can match it. A fresh errors.New
// would silently break the projection contract.
func TestErrClientGoneAcked_IsExportedSentinel(t *testing.T) {
	if ErrClientGoneAcked == nil {
		t.Fatal("ErrClientGoneAcked is nil")
	}
	wrapped := fmt.Errorf("driveSSEEventLoop: %w", ErrClientGoneAcked)
	if !errors.Is(wrapped, ErrClientGoneAcked) {
		t.Error("errors.Is on wrapped ErrClientGoneAcked = false; want true (export must preserve sentinel identity)")
	}
}
