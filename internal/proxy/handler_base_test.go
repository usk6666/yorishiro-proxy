package proxy

import (
	"context"
	"crypto/tls"
	gohttp "net/http"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func newTestBase() *HandlerBase {
	return &HandlerBase{
		Logger: testutil.DiscardLogger(),
		Transport: &gohttp.Transport{
			ForceAttemptHTTP2: true,
		},
	}
}

func TestHandlerBase_SetTransport(t *testing.T) {
	b := newTestBase()
	newT := &gohttp.Transport{MaxIdleConns: 42}
	b.SetTransport(newT)

	if b.Transport != newT {
		t.Error("SetTransport did not update Transport field")
	}
}

func TestHandlerBase_SetInsecureSkipVerify_True(t *testing.T) {
	b := newTestBase()
	b.SetInsecureSkipVerify(true)

	if b.Transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil after SetInsecureSkipVerify(true)")
	}
	if !b.Transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
	if b.Transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (TLS 1.2)", b.Transport.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}
}

func TestHandlerBase_SetInsecureSkipVerify_False(t *testing.T) {
	b := newTestBase()
	b.SetInsecureSkipVerify(false)

	if b.Transport.TLSClientConfig != nil {
		t.Errorf("TLSClientConfig = %v, want nil when skip is false", b.Transport.TLSClientConfig)
	}
}

func TestHandlerBase_SetInsecureSkipVerify_PreservesExistingConfig(t *testing.T) {
	b := newTestBase()
	b.Transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	b.SetInsecureSkipVerify(true)

	if b.Transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d (preserved TLS 1.3)", b.Transport.TLSClientConfig.MinVersion, tls.VersionTLS13)
	}
	if !b.Transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false, want true")
	}
}

func TestHandlerBase_SetCaptureScope(t *testing.T) {
	b := newTestBase()
	scope := NewCaptureScope()
	b.SetCaptureScope(scope)

	if b.Scope != scope {
		t.Error("SetCaptureScope did not update Scope field")
	}
	if b.CaptureScope() != scope {
		t.Error("CaptureScope() did not return the set scope")
	}
}

func TestHandlerBase_CaptureScope_NilDefault(t *testing.T) {
	b := newTestBase()
	if b.CaptureScope() != nil {
		t.Error("CaptureScope() should return nil by default")
	}
}

func TestHandlerBase_SetTargetScope(t *testing.T) {
	b := newTestBase()
	scope := NewTargetScope()
	b.SetTargetScope(scope)

	if b.TargetScope != scope {
		t.Error("SetTargetScope did not update TargetScope field")
	}
}

func TestHandlerBase_SetInterceptEngine(t *testing.T) {
	b := newTestBase()
	engine := intercept.NewEngine()
	b.SetInterceptEngine(engine)

	if b.InterceptEngine != engine {
		t.Error("SetInterceptEngine did not update InterceptEngine field")
	}
}

func TestHandlerBase_SetInterceptQueue(t *testing.T) {
	b := newTestBase()
	queue := intercept.NewQueue()
	b.SetInterceptQueue(queue)

	if b.InterceptQueue != queue {
		t.Error("SetInterceptQueue did not update InterceptQueue field")
	}
}

func TestHandlerBase_SetUpstreamProxy(t *testing.T) {
	b := newTestBase()
	proxyURL, _ := url.Parse("http://proxy.example.com:8080")
	b.SetUpstreamProxy(proxyURL)

	got := b.GetUpstreamProxy()
	if got != proxyURL {
		t.Errorf("GetUpstreamProxy() = %v, want %v", got, proxyURL)
	}
	if b.Transport.Proxy == nil {
		t.Error("Transport.Proxy should be set after SetUpstreamProxy")
	}
}

func TestHandlerBase_SetUpstreamProxy_Nil(t *testing.T) {
	b := newTestBase()
	proxyURL, _ := url.Parse("http://proxy.example.com:8080")
	b.SetUpstreamProxy(proxyURL)

	b.SetUpstreamProxy(nil)

	got := b.GetUpstreamProxy()
	if got != nil {
		t.Errorf("GetUpstreamProxy() = %v, want nil", got)
	}
}

func TestHandlerBase_ShouldCapture_NilScope(t *testing.T) {
	b := newTestBase()
	u, _ := url.Parse("http://example.com/test")

	if !b.ShouldCapture("GET", u) {
		t.Error("ShouldCapture with nil scope should return true")
	}
}

func TestHandlerBase_ShouldCapture_WithScope(t *testing.T) {
	b := newTestBase()
	scope := NewCaptureScope()
	scope.SetRules(
		[]ScopeRule{{Hostname: "included.com"}},
		nil,
	)
	b.SetCaptureScope(scope)

	included, _ := url.Parse("http://included.com/test")
	excluded, _ := url.Parse("http://excluded.com/test")

	if !b.ShouldCapture("GET", included) {
		t.Error("ShouldCapture should return true for included host")
	}
	if b.ShouldCapture("GET", excluded) {
		t.Error("ShouldCapture should return false for excluded host")
	}
}

func TestHandlerBase_ConnLogger_FallsBackToHandlerLogger(t *testing.T) {
	b := newTestBase()
	ctx := context.Background()

	logger := b.ConnLogger(ctx)
	if logger == nil {
		t.Error("ConnLogger should not return nil")
	}
}

func TestHandlerBase_ConnLogger_UsesContextLogger(t *testing.T) {
	b := newTestBase()
	ctxLogger := testutil.DiscardLogger().With("ctx", "true")
	ctx := ContextWithLogger(context.Background(), ctxLogger)

	logger := b.ConnLogger(ctx)
	if logger != ctxLogger {
		t.Error("ConnLogger should return the context logger when available")
	}
}
