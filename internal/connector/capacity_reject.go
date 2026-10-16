package connector

import (
	"bufio"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// RejectInfo describes one connection refused because max_connections was
// already saturated (USK-1142). It is the payload of
// FullListenerConfig.OnReject and of the TCP forward accept loop's direct
// call into the same aggregator.
type RejectInfo struct {
	// Listener is the listener name the connection arrived on.
	Listener string
	// ForwardPort is the TCP forward port for rejections on a tcp_forwards
	// listener; empty for the main FullListener.
	ForwardPort string
	// RemoteAddr is the client's address.
	RemoteAddr string
	// DetectedKind is the protocol detected from the first bytes, or
	// ProtocolUnknown when the peek failed or timed out.
	DetectedKind ProtocolKind
	// Method is the request-line method (HTTP/1.x and CONNECT only).
	Method string
	// Target is the request-target exactly as observed on the wire
	// (HTTP/1.x and CONNECT), or the configured forward target (TCP forward).
	Target string
	// TargetTruncated reports that Target was cut at MaxRejectTargetLen.
	TargetTruncated bool
	// WroteResponse reports that the 503 response reached the socket.
	WroteResponse bool
	// MaxConnections is the cap in force when the connection was refused.
	MaxConnections int
	// At is the rejection time.
	At time.Time
}

// MaxRejectTargetLen caps the request-target kept for a rejected
// connection. Longer targets are cut and RejectInfo.TargetTruncated is set.
const MaxRejectTargetLen = 512

// rejectRequestLineCap bounds how many bytes the reject path reads while
// looking for the request line. It is deliberately independent of the
// HTTP/1.x parser's request-line limit: the reject path runs exactly when
// the proxy is saturated, so it must stay cheap regardless of how large
// the data-path limit is.
const rejectRequestLineCap = 4 << 10

// rejectWarnWindow is the minimum interval between two capacity-rejection
// Warn logs on one listener; rejections in between are logged at Debug and
// counted in the next Warn's "suppressed" attribute.
const rejectWarnWindow = 10 * time.Second

// readRejectRequestLine reads the request line of an over-cap HTTP/1.x or
// CONNECT client and returns its method and request-target verbatim. It
// reads at most rejectRequestLineCap bytes and never parses headers. The
// caller's read deadline bounds the wait; a line cut short by the deadline,
// EOF, or the cap is returned as observed. The target is cut at
// MaxRejectTargetLen.
func readRejectRequestLine(pc *PeekConn) (method, target string, truncated bool) {
	br := bufio.NewReaderSize(io.LimitReader(pc.Reader(), rejectRequestLineCap), 1024)
	method, target, _, err := parser.ParseRequestLine(br)
	if err != nil {
		return "", "", false
	}
	if len(target) > MaxRejectTargetLen {
		target = target[:MaxRejectTargetLen]
		truncated = true
	}
	return method, target, truncated
}

// RejectWarnLimiter rate-limits capacity-rejection Warn logs for one
// listener: the first rejection warns immediately, later ones warn at most
// once per window and report how many were suppressed in between. It holds
// no goroutine and is safe for concurrent use.
type RejectWarnLimiter struct {
	window     time.Duration
	now        func() time.Time
	lastWarnNs atomic.Int64 // 0 = never warned
	suppressed atomic.Int64
}

// NewRejectWarnLimiter returns a limiter with the default window. now may be
// nil (time.Now).
func NewRejectWarnLimiter(now func() time.Time) *RejectWarnLimiter {
	if now == nil {
		now = time.Now
	}
	return &RejectWarnLimiter{window: rejectWarnWindow, now: now}
}

// observe records one rejection and reports whether it should be logged at
// Warn, together with the number of rejections suppressed since the
// previous Warn.
func (l *RejectWarnLimiter) observe() (warn bool, suppressed int64) {
	now := l.now().UnixNano()
	last := l.lastWarnNs.Load()
	if (last == 0 || now-last >= int64(l.window)) && l.lastWarnNs.CompareAndSwap(last, now) {
		return true, l.suppressed.Swap(0)
	}
	l.suppressed.Add(1)
	return false, 0
}

// LogCapacityRejection logs one capacity rejection: always at Debug with
// the full detail, and at Warn at most once per window per limiter (the
// Warn carries the count of rejections suppressed since the previous one).
// Shared by the FullListener and the TCP forward accept loop. limiter may
// be nil, in which case every rejection warns.
func LogCapacityRejection(logger *slog.Logger, limiter *RejectWarnLimiter, info RejectInfo) {
	if logger == nil {
		return
	}
	attrs := []any{
		"listener", info.Listener,
		"remote_addr", info.RemoteAddr,
		"max_connections", info.MaxConnections,
		"detected_kind", info.DetectedKind.String(),
		"wrote_503", info.WroteResponse,
	}
	if info.ForwardPort != "" {
		attrs = append(attrs, "forward_port", info.ForwardPort)
	}
	if info.Target != "" {
		attrs = append(attrs, "target", info.Target)
	}
	logger.Debug("connection rejected: at capacity", attrs...)

	warn, suppressed := true, int64(0)
	if limiter != nil {
		warn, suppressed = limiter.observe()
	}
	if warn {
		logger.Warn("connections rejected: at capacity",
			append(attrs, "suppressed", suppressed)...)
	}
}
