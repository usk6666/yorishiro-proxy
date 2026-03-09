package proxy

import (
	"context"
	"crypto/tls"
	"log/slog"
	gohttp "net/http"
	"net/url"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
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
	InterceptEngine *intercept.Engine
	InterceptQueue  *intercept.Queue

	// UpstreamMu protects UpstreamProxy for concurrent access.
	UpstreamMu    sync.RWMutex
	UpstreamProxy *url.URL

	// TLSFingerprintProfile stores the current TLS fingerprint profile name.
	// Protected by TLSFingerprintMu for concurrent access.
	TLSFingerprintMu      sync.RWMutex
	TLSFingerprintProfile string
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
	b.TLSFingerprintMu.Lock()
	defer b.TLSFingerprintMu.Unlock()
	b.TLSFingerprintProfile = profile
}

// TLSFingerprint returns the current TLS fingerprint profile name.
// Returns an empty string if not explicitly set.
func (b *HandlerBase) TLSFingerprint() string {
	b.TLSFingerprintMu.RLock()
	defer b.TLSFingerprintMu.RUnlock()
	return b.TLSFingerprintProfile
}

// ConnLogger returns the connection-scoped logger from context,
// falling back to the handler's logger.
func (b *HandlerBase) ConnLogger(ctx context.Context) *slog.Logger {
	return LoggerFromContext(ctx, b.Logger)
}
