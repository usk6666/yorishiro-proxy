package connector

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestNewSOCKS5Handler_NegotiationError(t *testing.T) {
	neg := NewSOCKS5Negotiator(nil)

	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator: neg,
	})

	clientConn, serverConn := net.Pipe()

	go func() {
		// Send garbage (not a valid SOCKS5 greeting)
		_, _ = clientConn.Write([]byte{0x04, 0x01, 0x00}) // SOCKS4, not SOCKS5
		clientConn.Close()
	}()

	pc := NewPeekConn(serverConn)
	ctx := ContextWithConnID(context.Background(), "test")

	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler should return nil on negotiation error, got: %v", err)
	}
}

func TestNewSOCKS5Handler_ScopeDenial(t *testing.T) {
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{
		{Hostname: "blocked.com"},
	})

	neg := NewSOCKS5Negotiator(nil)
	neg.Scope = scope

	var stackCalled atomic.Bool
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator: neg,
		OnStack: func(ctx context.Context, stack *ConnectionStack, clientSnap, upstreamSnap *envelope.TLSSnapshot, target string) {
			stackCalled.Store(true)
		},
	})

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		defer clientConn.Close()
		// SOCKS5 greeting: version=5, 1 method, NO_AUTH
		_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})

		// Read method selection
		buf := make([]byte, 2)
		if _, err := clientConn.Read(buf); err != nil {
			return
		}

		// SOCKS5 CONNECT request to blocked.com:443
		// VER=5, CMD=CONNECT, RSV=0, ATYP=DOMAIN
		host := "blocked.com"
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
		req = append(req, 0x01, 0xBB) // port 443
		_, _ = clientConn.Write(req)

		// Read reply (should be denial REP=0x02)
		reply := make([]byte, 10)
		_, _ = clientConn.Read(reply)
	}()

	pc := NewPeekConn(serverConn)
	ctx := ContextWithConnID(context.Background(), "test")

	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler returned error: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if stackCalled.Load() {
		t.Error("OnStack should not be called when target is blocked by scope")
	}
}

func TestNewSOCKS5Handler_AuthFailure(t *testing.T) {
	auth := NewStaticAuthenticator(map[string]string{
		"validuser": "validpass",
	})

	neg := NewSOCKS5Negotiator(nil)
	neg.Authenticator = auth

	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator: neg,
	})

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		defer clientConn.Close()
		// SOCKS5 greeting: version=5, 1 method, USERNAME/PASSWORD
		_, _ = clientConn.Write([]byte{0x05, 0x01, 0x02})

		// Read method selection
		buf := make([]byte, 2)
		if _, err := clientConn.Read(buf); err != nil {
			return
		}

		// Send wrong credentials
		// VER=1, ULEN=4, UNAME="bad!", PLEN=4, PASSWD="bad!"
		_, _ = clientConn.Write([]byte{0x01, 0x04, 'b', 'a', 'd', '!', 0x04, 'b', 'a', 'd', '!'})

		// Read auth result (should be failure)
		authReply := make([]byte, 2)
		_, _ = clientConn.Read(authReply)
	}()

	pc := NewPeekConn(serverConn)
	ctx := ContextWithConnID(context.Background(), "test")

	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler should return nil on auth failure, got: %v", err)
	}
}

func TestNewSOCKS5Handler_NilOnStack(t *testing.T) {
	neg := NewSOCKS5Negotiator(nil)

	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator: neg,
		BuildCfg:   nil, // stack build will fail
		OnStack:    nil,
	})

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		defer clientConn.Close()
		// SOCKS5 greeting
		_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})

		buf := make([]byte, 2)
		if _, err := clientConn.Read(buf); err != nil {
			return
		}

		// CONNECT to example.com:443
		host := "example.com"
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
		req = append(req, 0x01, 0xBB)
		_, _ = clientConn.Write(req)

		// Read reply
		reply := make([]byte, 10)
		_, _ = clientConn.Read(reply)
	}()

	pc := NewPeekConn(serverConn)
	ctx := context.Background()

	// Should not panic with nil OnStack and nil BuildCfg (stack build fails)
	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler returned error: %v", err)
	}
}

func TestNewSOCKS5Handler_SuccessfulNegotiation_StackBuildFails(t *testing.T) {
	neg := NewSOCKS5Negotiator(nil)

	var stackCalled atomic.Bool
	handler := NewSOCKS5Handler(SOCKS5HandlerConfig{
		Negotiator: neg,
		BuildCfg:   nil, // nil config → stack build fails
		OnStack: func(ctx context.Context, stack *ConnectionStack, clientSnap, upstreamSnap *envelope.TLSSnapshot, target string) {
			stackCalled.Store(true)
		},
	})

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	go func() {
		defer clientConn.Close()
		// Full SOCKS5 handshake
		_, _ = clientConn.Write([]byte{0x05, 0x01, 0x00})

		buf := make([]byte, 2)
		if _, err := clientConn.Read(buf); err != nil {
			return
		}

		host := "example.com"
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
		req = append(req, 0x01, 0xBB)
		_, _ = clientConn.Write(req)

		reply := make([]byte, 10)
		_, _ = clientConn.Read(reply)
	}()

	pc := NewPeekConn(serverConn)
	ctx := ContextWithConnID(context.Background(), "test")

	err := handler(ctx, pc)
	if err != nil {
		t.Errorf("handler returned error: %v", err)
	}

	// Stack build fails with nil config, so OnStack should not be called
	time.Sleep(50 * time.Millisecond)
	if stackCalled.Load() {
		t.Error("OnStack should not be called when stack build fails")
	}
}
