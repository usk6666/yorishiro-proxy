package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	gohttp "net/http"
	"net/url"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// HandlerBase provides shared fields and setter methods for protocol handlers.
// Embed this struct in HTTP/1.x and HTTP/2 handlers to eliminate duplicate
// setter boilerplate for capture scope, target scope, intercept engine/queue,
// upstream proxy, and TLS configuration.
type HandlerBase struct {
	Store           flow.FlowWriter
	Transport       *gohttp.Transport
	Logger          *slog.Logger
	Scope           *CaptureScope
	TargetScope     *TargetScope
	RateLimiter     *RateLimiter
	InterceptEngine *intercept.Engine
	InterceptQueue  *intercept.Queue
	// SafetyEngine is set once at initialization and read concurrently by
	// handler goroutines. No mutex is needed because the field is never
	// modified after the proxy starts accepting connections.
	SafetyEngine *safety.Engine

	// UpstreamMu protects UpstreamProxy for concurrent access.
	UpstreamMu    sync.RWMutex
	UpstreamProxy *url.URL

	// tlsFingerprintProfile stores the current TLS fingerprint profile name.
	// Protected by tlsFingerprintMu for concurrent access.
	tlsFingerprintMu      sync.RWMutex
	tlsFingerprintProfile string
}

// SetTransport replaces the handler's HTTP transport. This is primarily
// useful for testing, where the upstream server uses a self-signed certificate.
func (b *HandlerBase) SetTransport(t *gohttp.Transport) {
	b.Transport = t
}

// SetInsecureSkipVerify configures whether the handler skips TLS certificate
// verification when connecting to upstream servers. When enabled, a warning
// is logged because this disables important security checks.
// This is intended for vulnerability assessments against targets using
// self-signed or expired certificates.
func (b *HandlerBase) SetInsecureSkipVerify(skip bool) {
	if skip {
		b.Logger.Warn("upstream TLS certificate verification is disabled — connections to upstream servers will not verify certificates")
		if b.Transport.TLSClientConfig == nil {
			b.Transport.TLSClientConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}
		b.Transport.TLSClientConfig.InsecureSkipVerify = true
	}
}

// SetCaptureScope sets the capture scope used to filter which requests
// are recorded to the flow store. If scope is nil, all requests are recorded.
func (b *HandlerBase) SetCaptureScope(scope *CaptureScope) {
	b.Scope = scope
}

// CaptureScope returns the handler's capture scope, or nil if not set.
func (b *HandlerBase) CaptureScope() *CaptureScope {
	return b.Scope
}

// SetTargetScope sets the target scope used to enforce which network targets
// are allowed or blocked. When set, requests to targets outside the scope
// receive a 403 Forbidden response.
func (b *HandlerBase) SetTargetScope(scope *TargetScope) {
	b.TargetScope = scope
}

// SetRateLimiter sets the rate limiter used to enforce request rate limits.
// When set, requests that exceed the configured rate receive a 429 Too Many
// Requests response.
func (b *HandlerBase) SetRateLimiter(rl *RateLimiter) {
	b.RateLimiter = rl
}

// SetInterceptEngine sets the intercept rule engine used to determine which
// requests should be intercepted. When set together with an intercept queue,
// matching requests are held for AI agent review.
func (b *HandlerBase) SetInterceptEngine(engine *intercept.Engine) {
	b.InterceptEngine = engine
}

// SetInterceptQueue sets the intercept queue used to hold requests that match
// intercept rules. The queue must be set together with an intercept engine.
func (b *HandlerBase) SetInterceptQueue(queue *intercept.Queue) {
	b.InterceptQueue = queue
}

// SetSafetyEngine sets the safety filter engine used to detect destructive
// payloads in incoming requests. When set, requests matching safety rules
// are blocked (or logged) before reaching the upstream server.
func (b *HandlerBase) SetSafetyEngine(engine *safety.Engine) {
	b.SafetyEngine = engine
}

// CheckSafetyFilter evaluates the safety engine's input rules against
// the request body, URL, and headers. Returns the first violation found,
// or nil if no rules matched or the engine is not configured.
func (b *HandlerBase) CheckSafetyFilter(body []byte, rawURL string, headers gohttp.Header) *safety.InputViolation {
	if b.SafetyEngine == nil {
		return nil
	}
	return b.SafetyEngine.CheckInput(body, rawURL, httputil.HTTPHeaderToRawHeaders(headers))
}

// SafetyFilterAction looks up the action for the matched safety rule.
// Returns the rule's action (block, mask, or log_only). Defaults to block
// if the engine is nil or the rule is not found.
func (b *HandlerBase) SafetyFilterAction(violation *safety.InputViolation) safety.Action {
	if b.SafetyEngine == nil {
		return safety.ActionBlock
	}
	for _, r := range b.SafetyEngine.InputRules() {
		if r.ID == violation.RuleID {
			return r.Action
		}
	}
	return safety.ActionBlock
}

// safetyFilterResponseBody is the JSON structure for safety filter blocked responses.
type safetyFilterResponseBody struct {
	Error     string `json:"error"`
	BlockedBy string `json:"blocked_by"`
	Rule      string `json:"rule"`
	Message   string `json:"message"`
}

// BuildSafetyFilterResponseBody constructs a JSON body for a safety filter
// blocked response. It uses encoding/json to ensure all values are properly
// escaped, preventing JSON injection via rule names or matched fragments.
func BuildSafetyFilterResponseBody(violation *safety.InputViolation) []byte {
	body := safetyFilterResponseBody{
		Error:     "blocked by safety filter",
		BlockedBy: "safety_filter",
		Rule:      violation.RuleID,
		Message:   "Destructive payload detected: " + violation.RuleName + " matched in request " + violation.Target.String(),
	}
	b, err := json.Marshal(body)
	if err != nil {
		// Fallback: this should never happen since all fields are simple strings.
		return []byte(`{"error":"blocked by safety filter","blocked_by":"safety_filter"}`)
	}
	return b
}

// SetUpstreamProxy configures the upstream proxy for outgoing connections.
// Pass nil to disable the upstream proxy (direct connections).
// This method is safe to call concurrently and updates both the transport's
// Proxy function and the stored URL.
func (b *HandlerBase) SetUpstreamProxy(proxyURL *url.URL) {
	b.UpstreamMu.Lock()
	defer b.UpstreamMu.Unlock()
	b.UpstreamProxy = proxyURL
	b.Transport.Proxy = TransportProxyFunc(proxyURL)
}

// GetUpstreamProxy returns the current upstream proxy URL, or nil if not set.
func (b *HandlerBase) GetUpstreamProxy() *url.URL {
	b.UpstreamMu.RLock()
	defer b.UpstreamMu.RUnlock()
	return b.UpstreamProxy
}

// ShouldCapture checks the capture scope to determine whether a request
// should be recorded. Returns true if no scope is configured.
func (b *HandlerBase) ShouldCapture(method string, u *url.URL) bool {
	if b.Scope == nil {
		return true
	}
	return b.Scope.ShouldCapture(method, u)
}

// SetTLSFingerprint sets the TLS ClientHello fingerprint profile for upstream
// connections. Valid values: "chrome", "firefox", "safari", "edge", "random", "none".
// This method is safe to call concurrently.
func (b *HandlerBase) SetTLSFingerprint(profile string) {
	b.tlsFingerprintMu.Lock()
	defer b.tlsFingerprintMu.Unlock()
	b.tlsFingerprintProfile = profile
}

// TLSFingerprint returns the current TLS fingerprint profile name.
// Returns an empty string if not explicitly set.
func (b *HandlerBase) TLSFingerprint() string {
	b.tlsFingerprintMu.RLock()
	defer b.tlsFingerprintMu.RUnlock()
	return b.tlsFingerprintProfile
}

// ApplyOutputFilter applies the safety engine's output filter to the response
// body and headers. If the engine is not configured or no rules match, the data
// is returned unchanged. The caller is responsible for ensuring Content-Length
// is recalculated when the masked body is written to the client (e.g. via
// writeResponse / writeResponseToClient).
func (b *HandlerBase) ApplyOutputFilter(body []byte, headers gohttp.Header, logger *slog.Logger) ([]byte, gohttp.Header) {
	if b.SafetyEngine == nil {
		return body, headers
	}

	bodyResult := b.SafetyEngine.FilterOutput(body)
	maskedHeaders, headerMatches := b.SafetyEngine.FilterOutputHeaders(httputil.HTTPHeaderToRawHeaders(headers))

	// Log matches for observability.
	for _, m := range bodyResult.Matches {
		logger.Info("output filter matched response body",
			"rule_id", m.RuleID, "count", m.Count, "action", m.Action.String())
	}
	for _, m := range headerMatches {
		logger.Info("output filter matched response header",
			"rule_id", m.RuleID, "count", m.Count, "action", m.Action.String())
	}

	return bodyResult.Data, httputil.RawHeadersToHTTPHeader(maskedHeaders)
}

// ApplyOutputFilterHeaders applies the safety engine's output filter to HTTP
// headers (typically trailers). If the engine is not configured or no rules
// match, the headers are returned unchanged. This is separated from
// ApplyOutputFilter to allow independent filtering of response trailers.
func (b *HandlerBase) ApplyOutputFilterHeaders(headers gohttp.Header, logger *slog.Logger) gohttp.Header {
	if b.SafetyEngine == nil {
		return headers
	}

	masked, matches := b.SafetyEngine.FilterOutputHeaders(httputil.HTTPHeaderToRawHeaders(headers))
	for _, m := range matches {
		logger.Info("output filter matched trailer",
			"rule_id", m.RuleID, "count", m.Count, "action", m.Action.String())
	}
	return httputil.RawHeadersToHTTPHeader(masked)
}

// ConnLogger returns the connection-scoped logger from context,
// falling back to the handler's logger.
func (b *HandlerBase) ConnLogger(ctx context.Context) *slog.Logger {
	return LoggerFromContext(ctx, b.Logger)
}

// TruncateForLog truncates s to maxLen bytes for safe inclusion in log fields.
// If s exceeds maxLen, it is truncated and "..." is appended to indicate truncation.
func TruncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
