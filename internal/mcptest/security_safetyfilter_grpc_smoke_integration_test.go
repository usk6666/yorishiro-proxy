//go:build e2e

// Package mcptest_test holds USK-768's smoke parity for the
// SafetyFilter engine on the gRPC Send path — the gRPC analogue of
// security_safetyfilter_smoke_integration_test.go.
//
// USK-760 (PR #753) wired *safety.Engine through proxybuild.Deps for
// HTTP, WS, and gRPC. The HTTP smoke covers the wire end-to-end, but
// without a parallel gRPC smoke a regression that stops populating
// proxybuild.Deps.GRPCSafetyEngine (or that breaks the gRPC SafetyStep
// dispatch) would only surface in nightly e2e. This file closes that
// gap by booting the production server with the destructive-sql preset
// and proving:
//
//  1. A benign gRPC unary payload reaches the upstream (sanity gate).
//  2. A destructive-SQL gRPC unary payload does NOT reach the upstream
//     — pipeline.SafetyStep blocked it.
//
// The destructive-sql preset's regex matches the gRPC payload bytes
// via internal/rules/grpc/safety.extractTarget's
// common.TargetBody → TargetPayload aliasing, so the existing preset
// works against gRPC envelopes without modification (no rule change
// required for this Issue).
//
// USK-771 (PR #761) fixed the prior dispatch-side RST_STREAM(CANCEL)
// regression — the production gRPC dispatch now wraps the upstream
// stream with grpclayer.Wrap so envelopes reach Pipeline. That fix is
// the prerequisite for this smoke to assert SafetyFilter behaviour
// (rather than an unrelated dispatch bug). Helpers used here
// (dialGRPCThroughProxy / openCONNECTTunnel / grpcUpstreamHostPort /
// hostOnly / grpcRegressionRawCodec) are defined in
// grpc_dispatch_smoke_integration_test.go; both files live in the
// mcptest_test package.
package mcptest_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_SafetyFilter_BlocksDestructiveSQL_GRPC mirrors the HTTP
// smoke (TestE2E_SafetyFilter_BlocksDestructiveSQL) but routes through
// a gRPC unary RPC that traverses the proxy via CONNECT + TLS(h2).
//
// Both calls target the same method through the same proxy instance,
// so any divergence narrows directly to the gRPC SafetyStep behavior:
//
//   - A unary call whose payload matches the destructive-sql preset
//     never reaches the observed upstream.
//   - A unary call whose payload is benign DOES reach the upstream —
//     proving the test environment is otherwise functional and the
//     block in the destructive case is the SafetyFilter doing its job,
//     not a connectivity issue.
//
// USK-760 closed the wiring gap (proxybuild.Deps.GRPCSafetyEngine is
// populated by InitPerProtocolSafetyEngines), and USK-771 closed the
// dispatch-path bug (gRPC envelopes now reach Pipeline). With both on
// main this test is the merge-gate sentinel for the gRPC SafetyFilter
// path: a future regression in either link would resurface here.
func TestE2E_SafetyFilter_BlocksDestructiveSQL_GRPC(t *testing.T) {
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON:    safetyFilterDestructiveSQLConfig,
		UpstreamProto: "grpc",
	})

	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}

	upstreamHostPort := grpcUpstreamHostPort(t, h.UpstreamTLS.URL)
	cc := dialGRPCThroughProxy(t, proxyAddr, upstreamHostPort)
	defer cc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// (1) Benign payload — must reach the upstream. The hit counter is
	// the sanity gate: without this baseline a "blocked" assertion
	// below would be indistinguishable from a transport-broken proxy.
	benignReq := []byte("SELECT 1")
	var benignResp []byte
	if err := cc.Invoke(ctx, mcptest.GRPCSafetyEchoMethod, &benignReq, &benignResp,
		grpc.ForceCodec(grpcRegressionRawCodec{})); err != nil {
		t.Fatalf("benign gRPC Invoke: %v", err)
	}
	if !bytes.Equal(benignResp, benignReq) {
		t.Fatalf("benign gRPC echo mismatch: got %q want %q", benignResp, benignReq)
	}
	if got := h.GRPCObservedHits.Total(); got != 1 {
		t.Fatalf("upstream hits after benign gRPC call = %d, want 1", got)
	}
	if got := h.GRPCObservedHits.PerMethod(mcptest.GRPCSafetyEchoMethod); got != 1 {
		t.Fatalf("upstream per-method hits after benign call = %d, want 1", got)
	}

	// (2) Destructive-SQL payload — must NOT reach the upstream. The
	// preset matches "DROP TABLE users" via the SQL-keyword regex.
	// SafetyStep contract is "drop the envelope on Send", not "return
	// a specific gRPC status", so the durable assertion is the
	// upstream hit counter. The RPC may complete with a transport / RPC
	// error or with an empty response — either is acceptable; what
	// matters is that the upstream handler did not run. (Mirrors the
	// HTTP smoke's tolerance pattern.)
	destructiveReq := []byte("DROP TABLE users")
	var destructiveResp []byte
	hitsBefore := h.GRPCObservedHits.Total()
	invokeErr := cc.Invoke(ctx, mcptest.GRPCSafetyEchoMethod, &destructiveReq, &destructiveResp,
		grpc.ForceCodec(grpcRegressionRawCodec{}))
	hitsAfter := h.GRPCObservedHits.Total()
	if hitsAfter != hitsBefore {
		t.Errorf("upstream hits advanced after destructive gRPC call: before=%d after=%d (block failed)",
			hitsBefore, hitsAfter)
	}
	if invokeErr == nil && bytes.Equal(destructiveResp, destructiveReq) {
		// An echo response that matches the request would prove the
		// upstream answered — strictly stronger than the hit-counter
		// assertion above. Surfacing both makes the failure mode
		// obvious in test output.
		t.Errorf("destructive gRPC call returned an echo response; SafetyFilter did not block")
	}
}
