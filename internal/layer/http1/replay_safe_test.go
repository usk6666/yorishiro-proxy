package http1

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// TestIsStaleConnErr_TypedSentinels exhausts the classifier's typed-error
// matcher: each of the four stale sentinels matches, both bare and wrapped
// through *net.OpError → *os.SyscallError → syscall.Errno (the unwrap shape
// Go's net stack produces in production).
func TestIsStaleConnErr_TypedSentinels(t *testing.T) {
	wrap := func(label string, e error) error {
		return fmt.Errorf("%s: %w", label, e)
	}
	opErrWrap := func(e error) error {
		return &net.OpError{Op: "write", Net: "tcp", Err: &os.SyscallError{Syscall: "write", Err: e}}
	}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"syscall.EPIPE bare", syscall.EPIPE, true},
		{"syscall.EPIPE wrapped fmt", wrap("http1: send", syscall.EPIPE), true},
		{"syscall.EPIPE wrapped OpError", opErrWrap(syscall.EPIPE), true},
		{"syscall.ECONNRESET bare", syscall.ECONNRESET, true},
		{"syscall.ECONNRESET wrapped fmt", wrap("http1: send", syscall.ECONNRESET), true},
		{"syscall.ECONNRESET wrapped OpError", opErrWrap(syscall.ECONNRESET), true},
		{"io.EOF bare", io.EOF, true},
		{"io.EOF wrapped fmt", wrap("http1: send", io.EOF), true},
		{"net.ErrClosed bare", net.ErrClosed, true},
		{"net.ErrClosed wrapped fmt", wrap("http1: send", net.ErrClosed), true},
		// Negative cases — must NOT classify as stale.
		{"io.ErrUnexpectedEOF", io.ErrUnexpectedEOF, false},
		{"unrelated", errors.New("upstream parse error"), false},
		{"deadline exceeded", os.ErrDeadlineExceeded, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isStaleConnErr(tc.err); got != tc.want {
				t.Errorf("isStaleConnErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestIsReplaySafe_TruthTable is the canonical table for USK-999's
// replay-safety decision. Method × body shape × stage × truncated state.
func TestIsReplaySafe_TruthTable(t *testing.T) {
	type bodyKind int
	const (
		bodyNone bodyKind = iota
		bodyMemory
		bodyTruncated // RawBodyTruncated=true
	)

	makeOpaque := func(k bodyKind) *opaqueHTTP1 {
		req := &parser.RawRequest{}
		switch k {
		case bodyMemory:
			req.RawBody = []byte("hello")
		case bodyTruncated:
			req.RawBody = []byte("hel")
			req.RawBodyTruncated = true
		}
		return &opaqueHTTP1{rawReq: req}
	}

	cases := []struct {
		name   string
		method string
		body   bodyKind
		stage  string
		want   bool
	}{
		// stage=body forces false regardless of method.
		{"GET body-stage", "GET", bodyNone, "body", false},
		{"POST body-stage", "POST", bodyNone, "body", false},
		{"PUT body-stage memory body", "PUT", bodyMemory, "body", false},

		// Truncated body forces false regardless of method.
		{"GET truncated body", "GET", bodyTruncated, "header", false},
		{"PUT truncated body", "PUT", bodyTruncated, "header", false},
		{"DELETE truncated body", "DELETE", bodyTruncated, "header", false},

		// Replay-safe methods on header stage with intact / no body.
		{"GET header no body", "GET", bodyNone, "header", true},
		{"HEAD header no body", "HEAD", bodyNone, "header", true},
		{"OPTIONS header no body", "OPTIONS", bodyNone, "header", true},
		{"DELETE header no body", "DELETE", bodyNone, "header", true},
		{"TRACE header no body", "TRACE", bodyNone, "header", true},
		{"PUT header memory body", "PUT", bodyMemory, "header", true},
		{"PUT header no body", "PUT", bodyNone, "header", true},
		// Method-case insensitive (defensive — production stamps upper).
		{"lowercase get", "get", bodyNone, "header", true},
		{"mixedcase Put", "Put", bodyMemory, "header", true},

		// Non-replay-safe methods.
		{"POST header memory body", "POST", bodyMemory, "header", false},
		{"POST header no body", "POST", bodyNone, "header", false},
		{"PATCH header memory body", "PATCH", bodyMemory, "header", false},
		{"CONNECT header", "CONNECT", bodyNone, "header", false},
		{"custom verb", "FROBNICATE", bodyNone, "header", false},

		// nil opaque (synthetic-only send path).
		{"GET synthetic header", "GET", bodyNone, "header", true},
		{"POST synthetic header", "POST", bodyNone, "header", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := &envelope.HTTPMessage{Method: tc.method}
			opaque := makeOpaque(tc.body)
			// Special: synthetic shape signals via nil opaque.
			if tc.name == "GET synthetic header" || tc.name == "POST synthetic header" {
				opaque = nil
			}
			got := isReplaySafe(msg, opaque, tc.stage)
			if got != tc.want {
				t.Errorf("isReplaySafe(method=%q, body=%v, stage=%q) = %v, want %v",
					tc.method, tc.body, tc.stage, got, tc.want)
			}
		})
	}
}

// TestIsReplaySafe_NilMessage covers the nil-msg defensive branch — must
// return false (and not panic).
func TestIsReplaySafe_NilMessage(t *testing.T) {
	if got := isReplaySafe(nil, nil, "header"); got != false {
		t.Errorf("isReplaySafe(nil msg) = %v, want false", got)
	}
}

// TestStaleUpstreamError_UnwrapChain confirms errors.Is / errors.As walk
// through the StaleUpstreamError wrapper to reach the typed sentinel and
// back out to the StaleUpstreamError pointer.
func TestStaleUpstreamError_UnwrapChain(t *testing.T) {
	underlying := &os.SyscallError{Syscall: "write", Err: syscall.EPIPE}
	staleErr := &StaleUpstreamError{
		Underlying: underlying,
		ReplaySafe: true,
		Stage:      "header",
	}
	wrapped := fmt.Errorf("http1: send request raw: %w", staleErr)

	// errors.As reaches *StaleUpstreamError through fmt-wrap.
	var asStale *StaleUpstreamError
	if !errors.As(wrapped, &asStale) {
		t.Fatal("errors.As(*StaleUpstreamError): did not unwrap through fmt.Errorf %w")
	}
	if asStale.Stage != "header" {
		t.Errorf("asStale.Stage = %q, want \"header\"", asStale.Stage)
	}
	if !asStale.ReplaySafe {
		t.Error("asStale.ReplaySafe = false, want true")
	}

	// errors.Is reaches syscall.EPIPE through both wrap layers.
	if !errors.Is(wrapped, syscall.EPIPE) {
		t.Error("errors.Is(syscall.EPIPE): did not unwrap through StaleUpstreamError → SyscallError chain")
	}

	// Error() includes stage + underlying — useful for slog correlation.
	if got := staleErr.Error(); got != "http1 upstream stale (header): write: broken pipe" {
		t.Logf("Error() = %q (informational; OS-specific underlying text)", got)
		// Don't fail on text shape; just confirm it mentions stage.
		if !errorContains(got, "header") {
			t.Errorf("Error() = %q, want substring 'header'", got)
		}
	}
}

// TestStaleUpstreamError_NonStaleErrorPassThrough confirms wrapStaleErr
// returns the error verbatim when isStaleConnErr does not match — the
// regular session error path must stay unchanged for non-stale write
// failures.
func TestStaleUpstreamError_NonStaleErrorPassThrough(t *testing.T) {
	original := errors.New("upstream parse error")
	got := wrapStaleErr(original, &envelope.HTTPMessage{Method: "GET"}, nil, "header")
	if got != original {
		t.Errorf("wrapStaleErr non-stale: got %v (%T), want original %v (%T)", got, got, original, original)
	}
}

// errorContains is a tiny substring helper to keep the test independent
// of strings imports.
func errorContains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestStaleUpstreamError_PluginStateNotDoubleFired locks the design
// review invariant: a failed Send on the upstream-facing (Receive)
// Channel does NOT emit a FlowID (FlowIDs are minted only in
// parseRequest / parseResponse via recordEmittedFlowID). When the
// Channel is later Closed, releaseTransactionStates iterates an empty
// emittedFlowIDs slice and fires no StateReleaser calls — the retry
// path can therefore replay the Send on a fresh Channel without
// triggering a duplicate per-transaction release.
//
// This is the "no double-fire on retry" guarantee called out in the
// Issue acceptance criteria.
func TestStaleUpstreamError_PluginStateNotDoubleFired(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	rec := &recordingReleaser{}
	l := New(server, "conn-retry-no-doublefire", envelope.Receive,
		WithEnvelopeContext(envelope.EnvelopeContext{ConnID: "test-conn-retry"}),
		WithStateReleaser(rec),
	)
	defer l.Close()

	// Open a per-exchange Channel on the upstream-facing Layer. This
	// mirrors what the runHTTP1Exchange dial closure does. No Send is
	// ever invoked — emittedFlowIDs stays empty (FlowIDs are minted by
	// parseResponse, not by Send).
	upCh := l.OpenExchange()
	if upCh == nil {
		t.Fatal("OpenExchange returned nil")
	}

	// Close the per-exchange Channel — simulates the retry path
	// abandoning a Channel after a stale-conn Send failure. The
	// terminal markTerminated fires releaseTransactionStates with an
	// empty emittedFlowIDs slice → no ReleaseTransaction call.
	if err := upCh.Close(); err != nil {
		t.Fatalf("Channel.Close: %v", err)
	}

	if got := rec.count(); got != 0 {
		t.Errorf("ReleaseTransaction fired %d times on failed-Send Channel close; want 0 (replay must not double-fire)", got)
	}

	// Receive-direction Channels do not fire ReleaseStream (the
	// channel's currentStreamID is empty until a sendRequest captures
	// env.StreamID; a never-Sent Channel never captures one).
	if got := rec.streamCount(); got != 0 {
		t.Errorf("ReleaseStream fired %d times on never-Sent Channel close; want 0", got)
	}
}
