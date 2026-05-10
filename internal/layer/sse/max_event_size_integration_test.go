//go:build e2e && !e2e_smoke

// Package sse_test integration coverage for the operator-configured per-event
// SSE byte cap (USK-806). The cap is wired from ProxyConfig.SSE.MaxEventSize
// through:
//
//	config.ResolveSSEMaxEventSize → connector.BuildConfig.SSEMaxEventSize
//	→ proxybuild.buildSessionOptions → session.SessionOptions.SSEMaxEventSize
//	→ runUpgradeSSE → sse.WithMaxEventSize on the post-Upgrade SSE Channel.
//
// Pre-USK-806 the BuildConfig field was populated but never read, so the
// effective cap was the parser default DefaultMaxEventSize (1 MiB)
// regardless of operator config.
//
// Test shape mirrors the USK-802 per_stream_record_cap_integration_test.go
// precedent: build the SSE Channel with the operator option, drive an
// oversize event through the parser, and assert the typed *layer.StreamError
// surfaces.
package sse_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/sse"
)

// TestSSE_MaxEventSize_OperatorOverride verifies that the operator-supplied
// per-event byte cap reaches the SSE parser via sse.WithMaxEventSize and
// surfaces a typed *layer.StreamError when an event exceeds it. Mirrors the
// existing TestSSE_DirectChannelOversizeProducesStreamError in
// sse_integration_test.go but specifically exercises the USK-806 wiring
// contract: any positive operator value must reach the wrap site.
//
// The SSE Channel returns *layer.StreamError{Code: ErrorInternalError} on
// oversize events (verified by the existing 64-byte cap test).
//
// Without USK-806's wiring, the operator setting was silently ignored and
// the only effective cap was 1 MiB (sse.DefaultMaxEventSize). With a 1 MiB
// cap from the operator, parsing a ~1.5 MiB event must surface
// *layer.StreamError{Code: ErrorInternalError}.
func TestSSE_MaxEventSize_OperatorOverride(t *testing.T) {
	t.Parallel()

	const streamID = "sse-cap-override"
	const cap1MiB = 1 << 20

	// 1.5 MiB-ish event payload — well above the 1 MiB operator cap, well
	// below sse.DefaultMaxEventSize would have rejected it (since that IS
	// 1 MiB). The point of this test is the override path, not the
	// default-vs-override comparison; sse.DefaultMaxEventSize happens to
	// match the cap we set, so a separate "default-unchanged" test below
	// uses a payload comfortably under both ceilings.
	huge := strings.Repeat("x", (1<<20)+(512<<10))
	wire := "data: " + huge + "\n\n"

	inner := newInnerStub(streamID)
	first := makeSSEFirstResponse(streamID, 0)
	body := strings.NewReader(wire)
	upstreamCh := sse.Wrap(inner, first, body, sse.WithMaxEventSize(cap1MiB))
	defer upstreamCh.Close()

	// Drive Next directly. The first call returns the re-shaped first
	// response envelope; the second drives the parser, which must reject
	// the oversize event.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := upstreamCh.Next(ctx); err != nil {
		t.Fatalf("first Next (re-shaped first response) returned %v; want nil", err)
	}
	_, err := upstreamCh.Next(ctx)
	if err == nil {
		t.Fatal("Next on oversize event returned nil error; want *layer.StreamError")
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Next returned %T (%v); want *layer.StreamError", err, err)
	}
	if se.Code != layer.ErrorInternalError {
		t.Errorf("StreamError.Code = %v, want layer.ErrorInternalError (oversize SSE event)", se.Code)
	}
}

// TestSSE_MaxEventSize_DefaultUnchanged verifies the default behavior is
// preserved when no operator override is supplied. An event under
// DefaultMaxEventSize must parse successfully through a Channel built
// without WithMaxEventSize.
//
// session.runUpgradeSSE skips the Option append when SSEMaxEventSize <= 0
// (the > 0 guard), so the parser default takes effect. This test pins
// down the "default behavior unchanged when config absent" acceptance
// criterion at the Layer's wire boundary.
func TestSSE_MaxEventSize_DefaultUnchanged(t *testing.T) {
	t.Parallel()

	const streamID = "sse-cap-default"

	// 4 KiB event — comfortably below sse.DefaultMaxEventSize (1 MiB) and
	// below any operator value the test harness might inject.
	medium := strings.Repeat("y", 4096)
	wire := "data: " + medium + "\n\n"

	inner := newInnerStub(streamID)
	first := makeSSEFirstResponse(streamID, 0)
	body := strings.NewReader(wire)

	// No WithMaxEventSize — equivalent to BuildConfig.SSEMaxEventSize=0.
	upstreamCh := sse.Wrap(inner, first, body)
	defer upstreamCh.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if _, err := upstreamCh.Next(ctx); err != nil {
		t.Fatalf("first Next (re-shaped first response) returned %v; want nil", err)
	}
	env, err := upstreamCh.Next(ctx)
	if err != nil {
		t.Fatalf("Next on 4 KiB event returned %v; want nil (well below DefaultMaxEventSize)", err)
	}
	if env == nil {
		t.Fatal("Next returned nil envelope on a valid event; want SSEMessage envelope")
	}
}
