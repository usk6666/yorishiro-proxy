package connector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

// HTTP1ForwardHandlerConfig holds dependencies for the plain-HTTP forward-proxy
// handler factory.
//
// Fields mirror CONNECTHandlerConfig minus the Negotiator / PassthroughList
// fields: plain HTTP forward proxy has no tunnel negotiation step (the first
// request itself is the negotiation) and TLS passthrough does not apply to
// non-TLS traffic.
type HTTP1ForwardHandlerConfig struct {
	// BuildCfg supplies UpstreamProxy and body-spill / body-cap defaults
	// that the per-connection stack consumes via BuildPlainHTTPStack. Nil
	// is permitted for tests but typical production wiring threads
	// proxybuild's BuildConfig in.
	BuildCfg *BuildConfig

	// Scope validates the forward-proxy target against policy rules.
	// Nil disables.
	Scope *TargetScope

	// RateLimiter checks per-host rate limits. Nil disables.
	RateLimiter *RateLimiter

	// LiveConns, when non-nil, tracks every admitted forward connection so a
	// policy change that no longer admits its target closes it (USK-1160).
	LiveConns *LiveConns

	// OnStack is called after the per-connection stack is built. The
	// callback owns the session lifecycle (RunSession wiring); see
	// connector.OnStackFunc for the contract.
	OnStack OnStackFunc

	// RequestTimeout overrides the default forward-peek deadline used to
	// bound how long this handler waits for the first request's header
	// section. Zero uses the package default (forwardPeekTimeout, 30s).
	// Plumbed via proxybuild.Deps.RequestTimeout → FullListener →
	// HTTPForwardRequestTimeoutProvider for runtime hot-reload (USK-844).
	RequestTimeout time.Duration

	// RequestTimeoutProvider, when non-nil, is consulted on every
	// invocation of the handler so a runtime SetRequestTimeout on the
	// owning FullListener takes effect on the next accepted connection
	// without rebuilding the handler. Returning <=0 falls back to the
	// static RequestTimeout / package default. (USK-844)
	RequestTimeoutProvider func() time.Duration

	// RequestTimeoutDisabled, when non-nil and true, arms no target-peek
	// deadline at all (request_timeout_ms: 0, USK-1185).
	RequestTimeoutDisabled func() bool

	// OnRequestHeadFailure is invoked when the target peek is cut off by
	// its deadline after bytes arrived (USK-1189). head carries the bytes
	// peeked and the 400 the handler returned. Nil disables.
	OnRequestHeadFailure OnRequestHeadFailureFunc

	// Logger for handler-level logging. Nil uses slog.Default().
	Logger *slog.Logger
}

// dialTimeoutPlainHTTP bounds the per-request upstream TCP dial. Aligned with
// connector.defaultDialTimeout; declared here so the timeout is visible at
// the handler call site.
const dialTimeoutPlainHTTP = 30 * time.Second

// forwardPeekTimeout bounds how long the handler waits for the first request's
// header section to arrive. Distinct from FullListener.PeekTimeout (which
// only covers protocol detection) — this deadline applies after detection,
// while the handler is reading enough bytes to determine the upstream
// target. Slowloris clients that stop after the request line still produce
// a parseable target (the http1 Layer parses what's available), so the
// timeout is generous.
//
// This is the zero-config default; operators can tighten it via MCP
// `configure { request_timeout_ms }` (USK-844), which is plumbed through
// proxybuild.Deps.RequestTimeout → FullListener → the per-handler
// RequestTimeoutProvider closure.
const forwardPeekTimeout = 30 * time.Second

// resolveForwardPeekTimeout returns the effective read-deadline for the
// header-section peek on each invocation of the forward handler. Precedence
// (USK-844):
//  0. cfg.RequestTimeoutDisabled reporting true → 0: no deadline at all
//     (request_timeout_ms: 0, USK-1185).
//  1. cfg.RequestTimeoutProvider (runtime hot-reload via Manager).
//  2. cfg.RequestTimeout (boot-time value threaded via proxybuild.Deps).
//  3. forwardPeekTimeout package default (30s zero-config).
//
// Non-positive values from the provider or the static field collapse to the
// next tier so a "0 = default" wire shape is preserved end-to-end.
func resolveForwardPeekTimeout(cfg HTTP1ForwardHandlerConfig) time.Duration {
	if cfg.RequestTimeoutDisabled != nil && cfg.RequestTimeoutDisabled() {
		return 0
	}
	if cfg.RequestTimeoutProvider != nil {
		if d := cfg.RequestTimeoutProvider(); d > 0 {
			return d
		}
	}
	if cfg.RequestTimeout > 0 {
		return cfg.RequestTimeout
	}
	return forwardPeekTimeout
}

// peekHeaderSize bounds how many bytes the handler peeks to extract the
// request line and Host header. The PeekConn's bufio.Reader is constructed
// with the default 4096-byte buffer (see peekconn.go), so Peek calls must
// cap below that or bufio.Reader returns ErrBufferFull. 4000 bytes leaves
// a small safety margin while still fitting any realistic request-line +
// Host header (browsers can ship large Cookie / Authorization headers, but
// those are not needed for target resolution — only the request line and
// Host header are).
const peekHeaderSize = 4000

// NewHTTP1ForwardHandler returns a HandlerFunc that processes plain HTTP/1.x
// forward-proxy connections: peek the first request to determine target →
// scope/rate-limit check → dial upstream plain TCP → BuildPlainHTTPStack →
// invoke OnStack callback.
//
// First-iteration limitation (USK-710): the handler serves exactly ONE
// request per accepted client connection. After OnStack returns the
// connection is closed (via FullListener's deferred Close on PeekConn). HTTP
// keep-alive across multiple requests on the same client conn is deferred
// to a follow-up issue; clients that want to send multiple requests will
// re-dial the proxy, which is the common browser behavior anyway.
//
// On any failure (peek error, scope/rate-limit denial, upstream dial
// failure, stack-build failure) the handler writes a minimal HTTP/1.1 502
// or 403 response to the client and returns. This closes the production
// ERR_EMPTY_RESPONSE bug where unwired OnHTTP1 caused FullListener to drop
// the conn without writing anything.
func NewHTTP1ForwardHandler(cfg HTTP1ForwardHandlerConfig) HandlerFunc {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx context.Context, pc *PeekConn) error {
		connLogger := LoggerFromContext(ctx, logger)

		// Step 1: Peek enough bytes to extract the absolute-form Request-URI
		// or the Host header so we know where to dial upstream. Bound the
		// wait so a slow client cannot stall the goroutine forever — once
		// FullListener cleared its detection deadline, this handler owns
		// per-exchange timeouts. Operator overrides flow through
		// resolveForwardPeekTimeout so a runtime configure { request_timeout_ms }
		// reaches this read deadline (USK-844). Zero means
		// request_timeout_ms is disabled: no deadline (USK-1185).
		deadline := resolveForwardPeekTimeout(cfg)
		started := time.Now()
		if deadline > 0 {
			_ = pc.SetReadDeadline(started.Add(deadline))
		}
		target, perr := peekForwardTarget(pc)
		if deadline > 0 {
			_ = pc.SetReadDeadline(time.Time{})
		}
		if perr != nil {
			connLogger.Debug("plain HTTP: peek target failed", "error", perr)
			resp := forwardErrorResponse(400, "Bad Request",
				"yorishiro-proxy: could not parse request target")
			written := writeForwardResponse(pc, resp)
			reportForwardPeekFailure(ctx, cfg, pc, perr, resp, written, deadline, started)
			return nil
		}

		connLogger = connLogger.With("target", target, "via", "http1-forward")

		// Step 2: TargetScope check. Plain HTTP forward proxy uses scheme
		// "http" so scope rules can disambiguate http vs https traffic for
		// the same host.
		allowed, reason, splitErr := forwardScopeCheck(cfg.Scope, target)
		if splitErr != nil {
			connLogger.Debug("plain HTTP: invalid target", "error", splitErr)
			writeForwardErrorResponse(pc, 400, "Bad Request",
				"yorishiro-proxy: invalid forward-proxy target")
			return nil
		}
		if !allowed {
			connLogger.Info("plain HTTP target blocked by scope",
				"reason", reason)
			writeForwardErrorResponse(pc, 403, "Forbidden",
				"yorishiro-proxy: target blocked by scope")
			return nil
		}

		// USK-1160: track the admitted connection. One entry per accepted
		// client connection, keyed on target — the upstream this handler
		// dials and to which the connection's upstream leg stays bound for
		// its whole life (later keep-alive requests reuse it whatever their
		// Host header says; HostScopeStep re-checks each of them). A policy
		// change that no longer admits target cancels ctx, which the dial
		// and the OnStack session watch.
		ctx, release, ok := trackAdmitted(ctx, cfg.LiveConns, "http1-forward", target, func() (bool, string) {
			allowed, reason, _ := forwardScopeCheck(cfg.Scope, target)
			return allowed, reason
		}, nil, connLogger)
		defer release()
		if !ok {
			writeForwardErrorResponse(pc, 403, "Forbidden",
				"yorishiro-proxy: target blocked by scope")
			return nil
		}

		// Step 3: RateLimit check.
		if cfg.RateLimiter != nil {
			host, _, _ := net.SplitHostPort(target)
			if denial := cfg.RateLimiter.Check(host); denial != nil {
				connLogger.Info("plain HTTP target blocked by rate limit",
					"limit_type", denial.LimitType,
					"effective_rps", denial.EffectiveRPS)
				writeForwardResponse(pc, RateLimitRefusalResponse())
				return nil
			}
		}

		// Step 4: Dial upstream plain TCP. TLSConfig=nil → DialUpstreamRaw
		// returns a plain net.Conn with no TLS handshake. UpstreamProxy is
		// honored when configured. EffectiveUpstreamProxyForCtxErr is
		// consulted so runtime proxy_start / configure updates reach this
		// dial AND per-listener overrides + rotation apply (USK-734 +
		// USK-826 + USK-959). On rotation resolver error, fail-closed
		// with 502 — silent direct-dial fallback is a privacy regression.
		var dialOpts DialRawOpts
		// USK-959: stamp the dial target on ctx so the per_target_host
		// rotation policy can scope state by upstream host.
		dialCtx := ContextWithDialTarget(ctx, target)
		if cfg.BuildCfg != nil {
			u, perr := cfg.BuildCfg.EffectiveUpstreamProxyForCtxErr(dialCtx)
			if perr != nil {
				connLogger.Warn("plain HTTP upstream proxy rotation failed; failing closed",
					"target", target, "error", perr)
				writeForwardErrorResponse(pc, 502, "Bad Gateway",
					"yorishiro-proxy: upstream proxy rotation failed")
				return nil
			}
			dialOpts.UpstreamProxy = u
		}
		dialOpts.DialTimeout = dialTimeoutPlainHTTP

		upstreamConn, _, derr := DialUpstreamRaw(dialCtx, target, dialOpts)
		if derr != nil {
			connLogger.Debug("plain HTTP upstream dial failed", "error", derr)
			writeForwardErrorResponse(pc, 502, "Bad Gateway",
				"yorishiro-proxy: upstream dial failed")
			return nil
		}

		// Step 5: Build the per-connection stack. After this point the
		// stack owns both conns; failures must close upstreamConn explicitly
		// (which BuildPlainHTTPStack does NOT do — it only constructs).
		stack, berr := BuildPlainHTTPStack(ctx, pc, upstreamConn, target, cfg.BuildCfg)
		if berr != nil {
			upstreamConn.Close()
			connLogger.Warn("plain HTTP stack build failed", "error", berr)
			writeForwardErrorResponse(pc, 502, "Bad Gateway",
				"yorishiro-proxy: stack build failed")
			return nil
		}

		connLogger.Debug("plain HTTP stack built")

		// Step 6: Hand off. Plain HTTP cannot route to h2 (no ALPN, no TLS),
		// so we never invoke OnHTTP2Stack — call OnStack directly. nil snaps
		// reflect the no-TLS reality (RFC-001 §3.1 — never synthesize a
		// snapshot for a handshake that did not happen).
		if cfg.OnStack != nil {
			cfg.OnStack(ctx, stack, nil, nil, target)
		} else {
			_ = stack.Close()
		}

		return nil
	}
}

// forwardScopeCheck is the plain-HTTP forward gate's scope check: scheme
// "http", the forward target's host and port, no path. It is both the
// admission check and the live-connection predicate (USK-1160). A nil or
// rule-less scope allows everything. err is non-nil only for a target that
// SplitTargetHostPort rejects (then allowed is false): peekForwardTarget
// already refuses such a target, so this fail-closed branch is
// defense-in-depth (USK-1249).
//
// Every request on the connection reaches the Pipeline (HostScopeStep and
// HTTPScopeStep, which path-checks it), so a path-scoped allow admits the
// host provisionally (USK-1130, see gateScopeCheck). The first request's
// path is known here but deliberately not used: later keep-alive requests
// reuse the same upstream leg and are checked per request anyway.
func forwardScopeCheck(scope *TargetScope, target string) (allowed bool, reason string, err error) {
	if scope == nil || !scope.HasRules() {
		return true, "", nil
	}
	host, port, err := SplitTargetHostPort(target)
	if err != nil {
		return false, "invalid forward-proxy target", err
	}
	allowed, reason = gateScopeCheck(scope, "http", host, port, false)
	return allowed, reason, nil
}

// peekForwardTarget peeks the first request bytes from pc and extracts the
// upstream target host:port. It does NOT consume any bytes — bytes peeked
// via bufio.Reader.Peek remain in the buffer and are read again when the
// http1 Layer parses the request.
//
// Resolution order matches RFC 9112 §3.2.4:
//  1. Absolute-form Request-URI (e.g. "GET http://host/path HTTP/1.1") wins.
//  2. Otherwise, Host header from the request.
//
// Default port is 80 when the URL or Host omits one. Whichever form names
// it, the resulting target must pass SplitTargetHostPort: a port the
// dialer would read differently from TargetScope (a service name such as
// "postgresql", a 10-digit value net.Dial wraps modulo 2^32, a leading
// space, an empty port) is an error, so the handler answers 400 and never
// dials it (USK-1249). The target is never rewritten. CONNECT method is
// rejected — CONNECT detection is owned by FullListener and CONNECT requests
// should reach the OnCONNECT handler instead.
//
// Peek strategy: PeekConn's underlying bufio.Reader has the default 4096-byte
// buffer, so Peek(n) is bounded by that. We iteratively call Peek with
// increasing sizes until we find "\r\n\r\n" (end of headers) or hit
// peekHeaderSize. Each Peek call may issue one underlying conn.Read to fill
// the buffer; iterating bounds the wait so a slow client cannot stall us
// indefinitely (FullListener's peek deadline already capped the first
// detection peek; after detection that deadline was cleared, but the
// per-iteration step keeps progress).
func peekForwardTarget(pc *PeekConn) (string, error) {
	// Step up the peek size in chunks until we find end-of-headers or hit
	// the cap. Start at 256 (request line + a few headers usually fit) and
	// double up to peekHeaderSize.
	buf, err := peekUntilHeadersEnd(pc, peekHeaderSize)
	if len(buf) == 0 {
		if err == nil {
			err = fmt.Errorf("connector: empty peek buffer")
		}
		return "", fmt.Errorf("connector: peek request bytes: %w", err)
	}

	// Locate end-of-headers. If present, slice up to it. If absent we
	// either hit the cap (parse what we have — see comment below) OR the
	// underlying read errored mid-request (Slowloris / timeout / EOF). In
	// the latter case propagate the wrapped error so the caller surfaces
	// "deadline exceeded" / "EOF" instead of a misleading
	// "malformed request line".
	if idx := bytes.Index(buf, []byte("\r\n\r\n")); idx >= 0 {
		buf = buf[:idx]
	} else if err != nil {
		return "", fmt.Errorf("connector: peek request bytes: %w", err)
	}
	// If we get here with no \r\n\r\n and no error, peek hit the cap —
	// try to parse what we have. The request line + Host header normally
	// appear well before the cap, and the http1 Layer is the authoritative
	// parser anyway.

	// Split into request line + headers.
	lines := bytes.Split(buf, []byte("\r\n"))
	if len(lines) == 0 {
		return "", fmt.Errorf("connector: empty request")
	}

	// Parse request line: METHOD SP REQUEST-URI SP HTTP-VERSION.
	parts := bytes.SplitN(lines[0], []byte(" "), 3)
	if len(parts) < 2 {
		return "", fmt.Errorf("connector: malformed request line")
	}
	method := string(parts[0])
	requestURI := string(parts[1])

	// Defensive: CONNECT should not reach this handler; OnCONNECT owns
	// CONNECT-method detection. If a client somehow speaks CONNECT against
	// the OnHTTP1 slot, refuse.
	if strings.EqualFold(method, "CONNECT") {
		return "", fmt.Errorf("connector: CONNECT method routed to plain-HTTP handler")
	}

	// Absolute-form URI takes precedence (RFC 9112 §3.2.2).
	if strings.HasPrefix(strings.ToLower(requestURI), "http://") {
		u, perr := url.Parse(requestURI)
		if perr != nil {
			return "", fmt.Errorf("connector: parse absolute URI: %w", perr)
		}
		host := u.Host
		if host == "" {
			return "", fmt.Errorf("connector: absolute URI missing authority")
		}
		return validForwardTarget(JoinDefaultPort(host, "80"))
	}

	// Origin-form: Host header is mandatory in HTTP/1.1.
	host := findHostHeader(lines[1:])
	if host == "" {
		return "", fmt.Errorf("connector: missing Host header in origin-form request")
	}
	return validForwardTarget(JoinDefaultPort(host, "80"))
}

// validForwardTarget returns target when joinErr (from JoinDefaultPort) is
// nil and target passes SplitTargetHostPort, and an error otherwise.
func validForwardTarget(target string, joinErr error) (string, error) {
	if joinErr != nil {
		return "", fmt.Errorf("connector: forward target: %w", joinErr)
	}
	if _, _, err := SplitTargetHostPort(target); err != nil {
		return "", fmt.Errorf("connector: forward target: %w", err)
	}
	return target, nil
}

// peekUntilHeadersEnd peeks bytes from pc until "\r\n\r\n" is found or max
// bytes are buffered. Returns the bytes peeked so far (which remain in the
// bufio buffer; no consumption).
//
// Error semantics:
//   - On success (terminator found OR cap reached) returns (buf, nil).
//   - On read error from the underlying conn (timeout / EOF / reset)
//     returns (partialBuf, wrappedErr) where wrappedErr wraps the
//     underlying error via %w. Callers can use errors.Is to distinguish
//     io.EOF, os.ErrDeadlineExceeded, etc.
//
// Surfacing the underlying read error matters for diagnostics — a
// Slowloris client that disconnects after sending "GET / HT" otherwise
// looks identical to a syntactically malformed request line. With the
// wrapped error, callers can produce accurate "deadline exceeded" /
// "EOF" messages instead of a misleading "malformed request line".
//
// Why this is non-trivial: bufio.Reader.Peek(n) blocks until exactly n
// bytes OR an error. A client that sends a 60-byte request then waits for
// a response (the normal HTTP/1.1 request-response pattern) makes
// Peek(256) block forever — the TCP socket has no EOF and no further
// bytes arrive.
//
// Strategy:
//  1. Check what bufio already buffers (e.g. FullListener's protocol-
//     detection peek left up to PeekSize bytes there). If `\r\n\r\n` is
//     already present, we're done — never block.
//  2. Otherwise force ONE read by asking for buffered+1 bytes. bufio.fill
//     does a single conn.Read which on a typical TCP socket returns
//     everything currently in the kernel rcv buffer (the full request,
//     usually). After this read, re-check.
//  3. Loop until terminator found, cap reached, or read error.
//
// Each iteration adds at least one byte to the buffer (fill returns >=1
// on success); progress is bounded by the read deadline the caller set on
// the conn (forwardPeekTimeout in NewHTTP1ForwardHandler).
func peekUntilHeadersEnd(pc *PeekConn, max int) ([]byte, error) {
	for {
		// Step 0: check bytes already buffered. This avoids any read syscall
		// when FullListener's detection peek already pulled the full
		// request into the buffer (small requests fit in the 16-byte
		// detection peek? rare, but the case where the kernel delivered
		// the whole request in one TCP segment and it landed in bufio
		// during detect is the common case).
		if buffered := pc.Buffered(); buffered > 0 {
			full, _ := pc.Peek(buffered)
			if bytes.Contains(full, []byte("\r\n\r\n")) {
				return full, nil
			}
			if len(full) >= max {
				return full, nil
			}
		}
		// Step 1: force ONE more byte to be read from the conn. bufio.fill
		// reads up to its buffer capacity in one syscall, so we typically
		// get more than one new byte.
		buffered := pc.Buffered()
		want := buffered + 1
		if want > max {
			want = max
		}
		if _, err := pc.Peek(want); err != nil {
			// Read error (timeout, EOF). Return whatever is buffered now
			// alongside the wrapped error so the caller can distinguish
			// "I/O failed mid-request" from "request line is structurally
			// invalid".
			now := pc.Buffered()
			if now == 0 {
				return nil, fmt.Errorf("peek headers: %w", err)
			}
			full, _ := pc.Peek(now)
			return full, fmt.Errorf("peek headers: %w", err)
		}
		// Loop — Step 0 of the next iteration will re-check the now-
		// expanded buffer.
	}
}

// findHostHeader scans header lines (the lines AFTER the request line) for
// the first Host header (case-insensitive) and returns its trimmed value.
// Returns empty string if no Host header is present.
func findHostHeader(headers [][]byte) string {
	for _, line := range headers {
		colon := bytes.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		name := bytes.TrimSpace(line[:colon])
		if !bytes.EqualFold(name, []byte("Host")) {
			continue
		}
		return string(bytes.TrimSpace(line[colon+1:]))
	}
	return ""
}

// writeForwardErrorResponse writes a minimal HTTP/1.1 error response to the
// client and closes the connection at the listener level (FullListener's
// defer pc.Close runs on handler return). The response is intentionally
// short and identifies the proxy via Server header so operators can
// diagnose whether the failure originated in the proxy or upstream.
//
// Best-effort: write errors are swallowed (the conn is about to close).
func writeForwardErrorResponse(w net.Conn, status int, reason, detail string) {
	writeForwardResponse(w, forwardErrorResponse(status, reason, detail))
}

// forwardErrorResponse returns the bytes writeForwardErrorResponse sends.
func forwardErrorResponse(status int, reason, detail string) []byte {
	body := detail + "\r\n"
	return []byte(fmt.Sprintf(
		"HTTP/1.1 %d %s\r\n"+
			"Server: yorishiro-proxy\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n"+
			"%s",
		status, reason, len(body), body,
	))
}

// writeForwardResponse writes resp under a 5s write deadline and reports
// whether every byte was written.
func writeForwardResponse(w net.Conn, resp []byte) bool {
	_ = w.SetWriteDeadline(time.Now().Add(5 * time.Second))
	n, err := w.Write(resp)
	_ = w.SetWriteDeadline(time.Time{})
	return err == nil && n == len(resp)
}

// reportForwardPeekFailure hands a target peek cut off by its deadline,
// after bytes arrived, to cfg.OnRequestHeadFailure (USK-1189) together with
// the 400 the handler returned. A client close (EOF) and a complete but
// unusable head are not reported. The peeked bytes are still buffered in
// pc (Peek does not consume).
func reportForwardPeekFailure(ctx context.Context, cfg HTTP1ForwardHandlerConfig, pc *PeekConn, perr error, resp []byte, written bool, deadline time.Duration, started time.Time) {
	if cfg.OnRequestHeadFailure == nil || !errors.Is(perr, os.ErrDeadlineExceeded) {
		return
	}
	n := pc.Buffered()
	if n == 0 {
		return
	}
	peeked, _ := pc.Peek(n)
	buf := append([]byte(nil), peeked...)
	var maxRaw int64
	if cfg.BuildCfg != nil {
		maxRaw = cfg.BuildCfg.MaxRawCaptureSize
	}
	head := forwardPeekHeadFailure(buf, perr, deadline, started, maxRaw)
	head.Status = 400
	head.Response = resp
	head.ResponseWritten = written
	cfg.OnRequestHeadFailure(ctx, "", head)
}
