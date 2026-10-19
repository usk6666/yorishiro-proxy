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
//     — pipeline.SafetyStep blocked it — and the client promptly gets
//     grpc-status 7 PERMISSION_DENIED (USK-1202).
//  3. The blocked RPC is recorded with blocked_by=safety_filter and
//     state=error, the same rule as an HTTP SafetyFilter block.
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
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

	// (2) Destructive-SQL payload — must NOT reach the upstream, and the
	// client must be told so promptly (USK-1202). The preset matches
	// "DROP TABLE users" via the SQL-keyword regex; SafetyStep answers a
	// native-gRPC block with grpc-status 7 PERMISSION_DENIED (the gRPC
	// analogue of the HTTP 403). Only this call gets a short deadline,
	// so a proxy that leaves the RPC hanging fails on DeadlineExceeded
	// instead of passing.
	destructiveReq := []byte("DROP TABLE users")
	var destructiveResp []byte
	hitsBefore := h.GRPCObservedHits.Total()
	blockedCtx, blockedCancel := context.WithTimeout(ctx, 2*time.Second)
	defer blockedCancel()
	start := time.Now()
	invokeErr := cc.Invoke(blockedCtx, mcptest.GRPCSafetyEchoMethod, &destructiveReq, &destructiveResp,
		grpc.ForceCodec(grpcRegressionRawCodec{}))
	elapsed := time.Since(start)
	if invokeErr == nil {
		t.Fatalf("destructive gRPC call succeeded (resp=%q); SafetyFilter did not block", destructiveResp)
	}
	st, ok := status.FromError(invokeErr)
	if !ok {
		t.Fatalf("destructive gRPC call error is not a gRPC status: %T %v", invokeErr, invokeErr)
	}
	if st.Code() != codes.PermissionDenied {
		t.Errorf("destructive gRPC call status = %v (%q) after %v; want PermissionDenied", st.Code(), st.Message(), elapsed)
	}
	if !strings.Contains(st.Message(), "safety_filter") {
		t.Errorf("destructive gRPC call status message = %q; want it to contain safety_filter", st.Message())
	}
	if elapsed > 1500*time.Millisecond {
		t.Errorf("destructive gRPC call took %v to fail; want < 1.5s (the proxy must end the RPC, not the client deadline)", elapsed)
	}
	if hitsAfter := h.GRPCObservedHits.Total(); hitsAfter != hitsBefore {
		t.Errorf("upstream hits advanced after destructive gRPC call: before=%d after=%d (block failed)",
			hitsBefore, hitsAfter)
	}

	// (3) Recording: the blocked RPC is an audit Stream with
	// blocked_by=safety_filter and state=error, the same rule as an HTTP
	// SafetyFilter block. SaveStream goes through an async write queue,
	// so poll briefly.
	var blocked map[string]any
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && blocked == nil {
		res := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
			"filter": map[string]any{
				"blocked_by": "safety_filter",
				"protocol":   "grpc",
			},
		})
		if flows, _ := res.Decoded["flows"].([]any); len(flows) > 0 {
			blocked, _ = flows[0].(map[string]any)
		}
		if blocked == nil {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if blocked == nil {
		t.Fatalf("query(flows, blocked_by=safety_filter, protocol=grpc) returned 0 results; the block was not recorded")
	}
	if got, _ := blocked["blocked_by"].(string); got != "safety_filter" {
		t.Errorf("blocked Stream.blocked_by = %q, want safety_filter", got)
	}
	if got, _ := blocked["state"].(string); !strings.EqualFold(got, "error") {
		t.Errorf("blocked Stream.state = %q, want error", got)
	}
	if got, _ := blocked["protocol"].(string); got != "grpc" {
		t.Errorf("blocked Stream.protocol = %q, want grpc", got)
	}
}
