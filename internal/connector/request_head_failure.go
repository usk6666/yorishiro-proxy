package connector

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// connectRequestHeadFailure classifies a CONNECTNegotiator.Negotiate error
// (USK-1189). It returns the RequestHeadError to report, and the validated
// host:port target, when the proxy itself ended the CONNECT request read
// after bytes arrived: the request_timeout_ms deadline (armed) expired, or
// the request line / header section exceeded a parser limit. Any other
// error — a client close, a complete request with an unusable target, a
// non-CONNECT method — returns nil.
//
// maxRaw is BuildConfig.MaxRawCaptureSize (<= 0: the parser default). The
// negotiator parses with the package-default capture cap, so the
// effective cap is the smaller of the two.
//
// Storage bound (USK-1189 security review S-1): only head.Raw is capped at
// maxRaw. The L7 overlay — the verbatim authority and the parsed Headers —
// is bounded by the parser limits instead (MaxLineLength for the request
// line, the header-section limit for Headers), not by max_raw_capture_size.
// The record is made before connectPolicyAllow, so TargetScope and the
// rate limiter do not gate it; only capture_scope (applied by the
// proxybuild recorder) does. The per-record rate is bounded by
// MaxConnections x request_timeout_ms. This is the same exposure USK-1181
// accepted for the Layer-path request-head records; capping the overlay on
// both paths is a separate follow-up.
func connectRequestHeadFailure(err error, armed time.Duration, started time.Time, maxRaw int64) (*http1.RequestHeadError, string) {
	var perr *parser.PartialRequestError
	if !errors.As(err, &perr) || len(perr.Raw) == 0 {
		return nil, ""
	}
	var reason http1.RequestHeadReason
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		reason = http1.RequestHeadCONNECTTimeout
	case errors.Is(err, parser.ErrRequestLineTooLong):
		reason = http1.RequestHeadLineTooLong
	case errors.Is(err, parser.ErrHeaderSectionTooLarge):
		reason = http1.RequestHeadHeaderTooLarge
	default:
		return nil, ""
	}
	head := &http1.RequestHeadError{
		Reason:  reason,
		Timeout: armed,
		Started: started,
		Err:     err,
	}
	head.ApplyPartialRequest(perr)
	// The CONNECT request-target is authority-form (RFC 9110 §9.3.6), not
	// a path: keep it verbatim as the authority instead of splitting it as
	// an origin- / absolute-form target.
	head.Phase = http1.RequestHeadPhaseCONNECTRequest
	head.Path, head.RawQuery = "", ""
	head.Authority = ""
	target := ""
	if perr.RequestLineComplete {
		head.Authority = perr.RequestURI
		if head.Authority == "" {
			head.Authority = perr.Headers.Get("Host")
		}
		target = validCONNECTAuthority(perr.RequestURI)
	}
	head.Raw, head.RawTruncated = capRequestHeadRaw(head.Raw, head.RawTruncated, maxRaw)
	return head, target
}

// validCONNECTAuthority returns uri as a normalized host:port when it is a
// usable CONNECT authority (non-empty host, numeric port in [1, 65535], no
// CR/LF), and "" otherwise. Mirrors normalizeCONNECTTarget's acceptance
// rule for the request-target candidate.
func validCONNECTAuthority(uri string) string {
	if strings.ContainsAny(uri, "\r\n") {
		return ""
	}
	host, port, err := net.SplitHostPort(uri)
	if err != nil || host == "" {
		return ""
	}
	if p, err := strconv.Atoi(port); err != nil || p <= 0 || p > 65535 {
		return ""
	}
	return net.JoinHostPort(host, port)
}

// forwardPeekHeadFailure builds the RequestHeadError for a plain-forward
// target peek cut off by its deadline (USK-1189). buf holds the bytes
// peeked (never terminated by the end of the header section, or the peek
// would have succeeded). The overlay comes from running the real request
// parser over buf, so the phase and fields match what the HTTP/1 Layer
// would have reported; Raw is buf itself, capped at maxRaw.
func forwardPeekHeadFailure(buf []byte, peekErr error, deadline time.Duration, started time.Time, maxRaw int64) *http1.RequestHeadError {
	head := &http1.RequestHeadError{
		Reason:  http1.RequestHeadTimeout,
		Scheme:  "http",
		Timeout: deadline,
		Started: started,
		Err:     peekErr,
	}
	req, err := parser.ParseRequestWithOptions(bufio.NewReader(bytes.NewReader(buf)), parser.ParseOptions{MaxRawCapture: maxRaw})
	var perr *parser.PartialRequestError
	switch {
	case errors.As(err, &perr):
	case err == nil:
		// A head the parser accepts but the peek did not recognise as
		// complete (bare-LF terminators): every field was observed.
		perr = &parser.PartialRequestError{
			RequestLineComplete: true,
			Method:              req.Method,
			RequestURI:          req.RequestURI,
			Proto:               req.Proto,
			Headers:             req.Headers,
		}
	}
	head.ApplyPartialRequest(perr)
	if head.Phase == "" {
		head.Phase = http1.RequestHeadPhaseRequestLine
	}
	head.Raw, head.RawTruncated = capRequestHeadRaw(buf, false, maxRaw)
	return head
}

// capRequestHeadRaw caps raw at maxRaw bytes (<= 0: no extra cap) and
// reports whether the result is truncated.
func capRequestHeadRaw(raw []byte, truncated bool, maxRaw int64) ([]byte, bool) {
	if maxRaw > 0 && int64(len(raw)) > maxRaw {
		return raw[:maxRaw], true
	}
	return raw, truncated
}
