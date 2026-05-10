//go:build e2e && !e2e_smoke

// Package ws_test integration coverage for the operator-configured
// per-frame WebSocket payload cap (USK-806). The cap is wired from
// ProxyConfig.WebSocket.MaxFrameSize through:
//
//	config.ResolveWSMaxFrameSize → connector.BuildConfig.WSMaxFrameSize
//	→ proxybuild.buildSessionOptions → session.SessionOptions.WSMaxFrameSize
//	→ session.wsLifecycleOptions → ws.WithMaxFrameSize on both client- and
//	  upstream-facing ws.Layer constructions in runUpgradeWS /
//	  runUpgradeWSOverH2.
//
// Pre-USK-806 the BuildConfig field was populated but never read, so the
// effective cap was the compile-time `maxFramePayloadSize` (16 MiB)
// regardless of operator config.
//
// Test shape mirrors the USK-802 per_stream_record_cap_integration_test.go
// precedent: paired Layer construction with the operator option layered on
// top, exercise the actual wire path that enforces the cap, assert the
// typed *layer.StreamError surfaces.
package ws_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// TestWS_MaxFrameSize_OperatorOverride verifies that the operator-supplied
// per-frame payload cap reaches the *ws.Layer Send path and surfaces a
// typed *layer.StreamError when an oversize payload is attempted. This is
// the integration-shape mirror of unit test
// TestLayer_Send_OversizedPayload_ErrorAborted (layer_test.go), tagged for
// the e2e tier so it runs alongside the rest of the WS layer e2e suite.
//
// The ws.WithMaxFrameSize cap currently enforces only on the Send path
// (channel.go:573 reads c.opts.maxFrameSize); the Receive path uses the
// compile-time const maxFramePayloadSize. This is fine for USK-806's
// purposes — the production wiring path is symmetric (both ws.New calls
// receive the same Option slice), and the Send-side enforcement is what
// activates the operator override semantically.
//
// Without USK-806's wiring, the operator setting was silently ignored and
// the only effective cap was 16 MiB (compile-time). With a 1 MiB cap from
// the operator, attempting to Send a 1.5 MiB payload must surface
// *layer.StreamError{Code: ErrorAborted}.
func TestWS_MaxFrameSize_OperatorOverride(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// Drain the wire end so the Layer's underlying Write does not block
	// before the cap check fires (the cap check is pre-mask, pre-Write).
	go io.Copy(io.Discard, a) //nolint:errcheck

	const cap1MiB = 1 << 20
	l := ws.New(b, b, b, "stream-cap", ws.RoleServer, ws.WithMaxFrameSize(cap1MiB))
	defer l.Close()

	ch := <-l.Channels()

	// 1.5 MiB payload — well above the 1 MiB cap, well below the
	// compile-time 16 MiB ceiling. If the operator override is dropped,
	// this Send would succeed (compile-time ceiling not exceeded). With
	// the override active, the cap check at channel.go:573 fires.
	const payloadSize = (1 << 20) + (512 << 10)
	env := &envelope.Envelope{
		Direction: envelope.Receive, // RoleServer writes Direction=Receive frames.
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSBinary,
			Fin:     true,
			Payload: make([]byte, payloadSize),
		},
	}

	err := ch.Send(context.Background(), env)
	if err == nil {
		t.Fatalf("Send returned nil error; want *layer.StreamError for payload %d > cap %d",
			payloadSize, cap1MiB)
	}
	var se *layer.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Send returned %T (%v); want *layer.StreamError", err, err)
	}
	if se.Code != layer.ErrorAborted {
		t.Errorf("StreamError.Code = %v, want layer.ErrorAborted (oversize Send is Aborted)", se.Code)
	}
}

// TestWS_MaxFrameSize_DefaultUnchanged verifies the legacy / default
// behavior is preserved when no operator override is supplied. Sending a
// 1.5 MiB payload through a Layer constructed without WithMaxFrameSize
// (or with WithMaxFrameSize(0), which is no-op per the Option's contract)
// must succeed — the compile-time 16 MiB ceiling is the only enforcement.
//
// This test is the safety-net for the "default behavior unchanged when
// config absent" acceptance criterion. Bridging an unset config field
// (zero value) into SessionOptions and then into ws.WithMaxFrameSize must
// be a no-op all the way down, and this asserts that contract at the
// Layer's wire boundary.
func TestWS_MaxFrameSize_DefaultUnchanged(t *testing.T) {
	t.Parallel()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// Drain the wire end so the underlying Write does not block.
	go io.Copy(io.Discard, a) //nolint:errcheck

	// No WithMaxFrameSize supplied — equivalent to BuildConfig.WSMaxFrameSize=0.
	// session.wsLifecycleOptions skips the Option append in that case (the
	// > 0 guard in the helper), so the Layer's default cap remains in effect.
	l := ws.New(b, b, b, "stream-default", ws.RoleServer)
	defer l.Close()

	ch := <-l.Channels()

	// 1.5 MiB payload — above what would be a 1 MiB operator cap, well
	// below the 16 MiB compile-time ceiling. Must succeed when no override
	// is in effect.
	const payloadSize = (1 << 20) + (512 << 10)
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSBinary,
			Fin:     true,
			Payload: make([]byte, payloadSize),
		},
	}

	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatalf("Send (no operator cap) returned %v; want nil — payload %d is below 16 MiB ceiling",
			err, payloadSize)
	}
}
