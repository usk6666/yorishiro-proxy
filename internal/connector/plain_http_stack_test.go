package connector

import (
	"net"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

func TestBuildPlainHTTPStack_Basic(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()
	upstreamA, upstreamB := net.Pipe()
	defer upstreamA.Close()
	defer upstreamB.Close()

	cfg := &BuildConfig{}
	stack, err := BuildPlainHTTPStack(clientB, upstreamB, "example.com:80", cfg)
	if err != nil {
		t.Fatalf("BuildPlainHTTPStack: %v", err)
	}
	defer stack.Close()

	// Both topmost layers exist and are http1.Layer.
	if _, ok := stack.ClientTopmost().(*http1.Layer); !ok {
		t.Errorf("client topmost = %T, want *http1.Layer", stack.ClientTopmost())
	}
	if _, ok := stack.UpstreamTopmost().(*http1.Layer); !ok {
		t.Errorf("upstream topmost = %T, want *http1.Layer", stack.UpstreamTopmost())
	}

	// upstreamH2 should be nil — plain HTTP never routes to h2.
	if stack.UpstreamH2Layer() != nil {
		t.Error("upstreamH2 should be nil for plain HTTP stack")
	}

	// ConnID is set.
	if stack.ConnID == "" {
		t.Error("stack.ConnID is empty")
	}
}

func TestBuildPlainHTTPStack_NilConfig(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()
	upstreamA, upstreamB := net.Pipe()
	defer upstreamA.Close()
	defer upstreamB.Close()

	if _, err := BuildPlainHTTPStack(clientB, upstreamB, "example.com:80", nil); err == nil {
		t.Error("expected error with nil config, got nil")
	}
}

func TestBuildPlainHTTPStack_NilConn(t *testing.T) {
	cfg := &BuildConfig{}
	if _, err := BuildPlainHTTPStack(nil, nil, "example.com:80", cfg); err == nil {
		t.Error("expected error with nil conn, got nil")
	}
}
