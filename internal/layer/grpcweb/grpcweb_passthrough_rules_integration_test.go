//go:build e2e && !e2e_smoke

package grpcweb_test

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	grpcrules "github.com/usk6666/yorishiro-proxy/internal/rules/grpc"
)

// USK-1203 review findings F-1 / S-1: the malformed-body passthrough must
// survive a Start Transform rule, and must not bypass the Input
// SafetyFilter's body/payload rules.

// sendRawGRPCWebHTTP1Request writes one HTTP/1.1 gRPC-Web request with body
// through the proxy and returns whatever the client read until close.
func sendRawGRPCWebHTTP1Request(t *testing.T, proxyAddr, target, contentType string, body []byte) []byte {
	t.Helper()
	tlsConn := connectThroughProxy(t, proxyAddr, target, nil)
	defer tlsConn.Close()
	req := fmt.Sprintf(
		"POST /pkg.Echo/Say HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		target, contentType, len(body))
	if _, err := tlsConn.Write(append([]byte(req), body...)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	return readUntilClose(tlsConn, 5*time.Second)
}

// TestGRPCWeb_MalformedRequestWithStartTransformForwardedVerbatim — F-1: a
// matching gRPC Start Transform rule (metadata add) must not clear the
// passthrough body. The upstream receives the malformed body verbatim and
// the metadata modification on the headers.
func TestGRPCWeb_MalformedRequestWithStartTransformForwardedVerbatim(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamResp := buildGRPCWebResponseHTTP([]byte("ack"), 0, "OK", false)
	upstreamLn, captured := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return upstreamResp
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	xfm := grpcrules.NewTransformEngine()
	rule, err := grpcrules.CompileTransformRule("add-md", 0, grpcrules.DirectionSend, "", "",
		grpcrules.TransformAddMetadata, "X-Added", "yes", "", "", 0, "")
	if err != nil {
		t.Fatalf("compile rule: %v", err)
	}
	xfm.AddRule(*rule)

	proxyAddr, _, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{transformEngine: xfm})
	clientResp := sendRawGRPCWebHTTP1Request(t, proxyAddr, target, "application/grpc-web+proto", malformedLPMBody)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	assertClientGotUpstreamResponse(t, clientResp, upstreamResp)
	upstreamLn.Close()
	reqs := captured()
	assertUpstreamBody(t, reqs, malformedLPMBody)
	if len(reqs) == 1 {
		hdrs, _ := splitHTTPMessage(t, reqs[0])
		if got := headerValues(hdrs, "X-Added"); len(got) != 1 || got[0] != "yes" {
			t.Errorf("upstream X-Added = %q, want [\"yes\"] (Start Transform not applied)", got)
		}
	}
}

// TestGRPCWeb_MalformedRequestBlockedBySafety — S-1: a valid LPM frame
// carrying a destructive SQL payload followed by one stray byte fails LPM
// parsing, so no GRPCDataMessage is emitted. The Input SafetyFilter must
// still evaluate the passthrough body and keep it from reaching upstream.
func TestGRPCWeb_MalformedRequestBlockedBySafety(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	payload := []byte("DROP TABLE users")
	body := append([]byte{0x00, 0x00, 0x00, 0x00, byte(len(payload))}, payload...)
	body = append(body, 0x00)

	upstreamLn, captured := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP([]byte("ack"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	safety := grpcrules.NewSafetyEngine()
	if err := safety.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatalf("load preset: %v", err)
	}

	proxyAddr, _, _, sessionDone := startGRPCWebHTTP1Proxy(t, ctx, pipelineOpts{safetyEngine: safety})
	_ = sendRawGRPCWebHTTP1Request(t, proxyAddr, target, "application/grpc-web+proto", body)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	upstreamLn.Close()
	for i, r := range captured() {
		if bytes.Contains(r, payload) {
			t.Errorf("upstream request %d carries the blocked payload: %q", i, r)
		}
	}
}
