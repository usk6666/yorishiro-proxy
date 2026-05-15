//go:build e2e && !e2e_smoke

package grpcweb_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	nethttp "net/http"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// USK-898 e2e: gRPC-Web text-variant body envelopes
// (application/grpc-web-text[+proto]) must emit wire_level=grpcweb-base64
// envelopes carrying the on-wire base64 body bytes (BEFORE the layer's
// in-place base64 decode). Binary variants (application/grpc-web[+proto])
// must NOT fire.
//
// Bug class this test guards against (defense-in-depth — no live bug
// today):
//   - Base64 padding anomalies
//   - Illegal-character smuggling
//   - Encoding-side bombs hidden by the in-place decode
//
// e2e Subsystem Verification Checklist coverage (CLAUDE.md):
//   - Communication success: gRPC-Web flows end-to-end through the proxy.
//   - Stream recording: Stream saved with Protocol="grpc-web".
//   - Flow recording: both semantic envelopes (Start / Data / End) and
//     grpcweb-base64 envelopes recorded under the same StreamID with
//     independent sequence counters per (Direction, WireLevel).
//   - Raw bytes recording: grpcweb-base64 envelopes carry the on-wire
//     base64 body bytes — NOT the decoded LPM bytes.
//   - L4-capable: base64 wire envelopes are wire-snapshot envelopes; no
//     L7 normalisation applied (base64 bytes recorded as-observed).
//   - MCP tool integration: a base64 wire flow is retrievable from the
//     store by ID — the same lookup the `query` MCP tool performs.

// pipelineOptsBase64 customises the test Pipeline + grpcweb wraps for
// the USK-898 tests. The struct is local to this file to avoid
// extending the shared pipelineOpts.
type pipelineOptsBase64 struct {
	// recordOpts are extra RecordStep Options layered onto the canonical
	// chain. Used to inject WithGRPCWebBase64MaxPerStream for the cap
	// test.
	recordOpts []pipeline.Option

	// installBase64Callback, when true, wires the grpcweb base64 record
	// callback (USK-898) on both the client-side and upstream-side
	// grpcweb wraps via session.GRPCWebBase64RecordOption.
	installBase64Callback bool
}

func buildPipelineBase64(store flow.Writer, opts pipelineOptsBase64) *pipeline.Pipeline {
	logger := slog.Default()
	recordOpts := []pipeline.Option{
		pipeline.WithWireEncoder(envelope.ProtocolGRPCWeb, grpcweb.EncodeWireBytes),
	}
	recordOpts = append(recordOpts, opts.recordOpts...)
	steps := []pipeline.Step{
		pipeline.NewHostScopeStep(nil),
		pipeline.NewHTTPScopeStep(nil),
		pipeline.NewSafetyStep(nil, nil, nil, logger),
		pipeline.NewTransformStep(nil, nil, nil, nil),
		pipeline.NewInterceptStep(nil, nil, nil, nil, nil, nil, logger),
		pipeline.NewRecordStep(store, logger, recordOpts...),
	}
	return pipeline.New(steps...)
}

// startGRPCWebHTTP1ProxyBase64 starts a FullListener configured for HTTP
// MITM and wires the USK-898 base64 record callback into both the
// client-side and upstream-side grpcweb wraps when
// opts.installBase64Callback is true. This is the HTTP/1.1 sibling of
// proxybuild.builder.go's h2 grpcWebBase64Opt wiring; the test harness
// replicates the minimal subset so the test exercises the full record
// path without depending on the live proxybuild stack.
func startGRPCWebHTTP1ProxyBase64(
	t *testing.T,
	ctx context.Context,
	opts pipelineOptsBase64,
) (proxyAddr string, store *testStore, sessionDone <-chan struct{}) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	store = &testStore{}
	done := make(chan struct{})

	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	onStack := func(streamCtx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, target string) {
		defer close(done)
		defer stack.Close()

		rawClientCh := <-stack.ClientTopmost().Channels()

		p := buildPipelineBase64(store, opts)

		// Build the per-stream base64 record Option (USK-898). The same
		// closure is installed on both client-side and upstream-side
		// wraps so the per-direction sequence counters live in one place.
		var grpcwebOpts []grpcweb.Option
		if opts.installBase64Callback {
			flowCtx := envelope.EnvelopeContext{TargetHost: target}
			grpcwebOpts = append(grpcwebOpts,
				session.GRPCWebBase64RecordOption(ctx, p, rawClientCh.StreamID(), flowCtx),
			)
		}

		clientCh := grpcweb.Wrap(rawClientCh, grpcweb.RoleServer, grpcwebOpts...)

		session.RunSession(streamCtx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			rawUp := <-stack.UpstreamTopmost().Channels()
			return grpcweb.Wrap(rawUp, grpcweb.RoleClient, grpcwebOpts...), nil
		}, p, session.SessionOptions{
			OnComplete: func(cctx context.Context, streamID string, err error) {
				state := "complete"
				if err != nil && !errors.Is(err, io.EOF) {
					state = "error"
				}
				if streamID != "" {
					_ = store.UpdateStream(cctx, streamID, flow.StreamUpdate{
						State:         state,
						FailureReason: session.ClassifyError(err),
					})
				}
			},
		})
	}

	flCfg := connector.FullListenerConfig{
		Name: "test-base64",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator: connector.NewCONNECTNegotiator(slog.Default()),
			BuildCfg:   buildCfg,
			OnStack:    onStack,
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx) //nolint:errcheck // test
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for FullListener ready")
	}

	return fl.Addr(), store, done
}

// startGRPCWebHTTP2ProxyBase64 mirrors the HTTP/1 harness for the h2
// path. Wires session.GRPCWebBase64RecordOption into both the client-
// side and upstream-side grpcweb wraps, matching the production wiring
// in internal/proxybuild/builder.go.
func startGRPCWebHTTP2ProxyBase64(
	t *testing.T,
	ctx context.Context,
	opts pipelineOptsBase64,
) (proxyAddr string, store *testStore, sessionDone <-chan struct{}) {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)
	store = &testStore{}
	done := make(chan struct{}, 16)

	bcfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	onHTTP2Stack := func(cbCtx context.Context, stack *connector.ConnectionStack, upstreamH2 *intHTTP2.Layer, _, _ *envelope.TLSSnapshot, target string) {
		clientL, ok := stack.ClientTopmost().(*intHTTP2.Layer)
		if !ok {
			t.Errorf("ClientTopmost is not *http2.Layer")
			return
		}
		clientLOpts := httpaggregator.OptionsFromLayer(clientL)
		upstreamLOpts := httpaggregator.OptionsFromLayer(upstreamH2)

		var wg sync.WaitGroup
		for {
			select {
			case <-cbCtx.Done():
				wg.Wait()
				return
			case streamCh, open := <-clientL.Channels():
				if !open {
					wg.Wait()
					return
				}
				wg.Add(1)
				go func(ch layer.Channel) {
					defer wg.Done()
					defer func() {
						select {
						case done <- struct{}{}:
						default:
						}
					}()

					p := buildPipelineBase64(store, opts)
					var grpcwebOpts []grpcweb.Option
					if opts.installBase64Callback {
						flowCtx := envelope.EnvelopeContext{TargetHost: target}
						grpcwebOpts = append(grpcwebOpts,
							session.GRPCWebBase64RecordOption(ctx, p, ch.StreamID(), flowCtx),
						)
					}

					dispatched, derr := connector.DispatchH2StreamWithOpts(
						cbCtx, ch, httpaggregator.RoleServer, clientLOpts,
						slog.Default(), nil, grpcwebOpts,
					)
					if derr != nil {
						_ = ch.Close()
						return
					}
					clientCh := dispatched

					session.RunSession(cbCtx, clientCh, func(dctx context.Context, _ *envelope.Envelope) (layer.Channel, error) {
						upStream, oerr := upstreamH2.OpenStream(dctx)
						if oerr != nil {
							return nil, oerr
						}
						aggUp := httpaggregator.Wrap(upStream, httpaggregator.RoleClient, nil, upstreamLOpts)
						return grpcweb.Wrap(aggUp, grpcweb.RoleClient, grpcwebOpts...), nil
					}, p, session.SessionOptions{
						OnComplete: func(cctx context.Context, streamID string, err error) {
							state := "complete"
							if err != nil && !errors.Is(err, io.EOF) {
								state = "error"
							}
							if streamID != "" {
								_ = store.UpdateStream(cctx, streamID, flow.StreamUpdate{
									State:         state,
									FailureReason: session.ClassifyError(err),
								})
							}
						},
					})
				}(streamCh)
			}
		}
	}

	flCfg := connector.FullListenerConfig{
		Name: "grpcweb-h2-base64",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator: connector.NewCONNECTNegotiator(slog.Default()),
			BuildCfg:   bcfg,
			OnStack: func(_ context.Context, s *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
				_ = s.Close()
			},
			OnHTTP2Stack: onHTTP2Stack,
			Logger:       slog.Default(),
		}),
	}
	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx) //nolint:errcheck // test
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("h2 full listener not ready")
	}
	return fl.Addr(), store, done
}

// base64FlowsForStream returns flows in store filtered to streamID and
// wire_level=grpcweb-base64. Optionally filtered by direction when
// dir != "".
func base64FlowsForStream(store *testStore, streamID, dir string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range store.allFlows() {
		if f == nil || f.StreamID != streamID {
			continue
		}
		if f.WireLevel != flow.WireLevelGRPCWebBase64 {
			continue
		}
		if dir != "" && f.Direction != dir {
			continue
		}
		out = append(out, f)
	}
	return out
}

// waitForBase64Flows polls the store until at least n grpcweb-base64
// flows for streamID in dir are recorded, or until timeout. Failure
// prints diagnostic counts.
func waitForBase64Flows(t *testing.T, store *testStore, streamID, dir string, n int, timeout time.Duration) []*flow.Flow {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []*flow.Flow
	for time.Now().Before(deadline) {
		last = base64FlowsForStream(store, streamID, dir)
		if len(last) >= n {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: want %d %s grpcweb-base64 flows for stream %s; have %d", n, dir, streamID, len(last))
	return nil
}

// firstBase64Stream returns the first recorded Stream or fails the test.
func firstBase64Stream(t *testing.T, store *testStore, timeout time.Duration) *flow.Stream {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		streams := store.getStreams()
		if len(streams) > 0 {
			return streams[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no Stream recorded within timeout")
	return nil
}

// isBase64Byte reports whether b is a member of the standard base64
// alphabet (RFC 4648).
func isBase64Byte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z':
		return true
	case b >= 'a' && b <= 'z':
		return true
	case b >= '0' && b <= '9':
		return true
	case b == '+', b == '/', b == '=':
		return true
	}
	return false
}

// TestGRPCWebBase64Recording_TextUnary covers Issue case 1:
// gRPC-Web text unary RPC → 1 Send base64 envelope (request body) + 1
// Receive base64 envelope (response body).
func TestGRPCWebBase64Recording_TextUnary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	respPayload := []byte("hello-base64-unary")
	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP(respPayload, 0, "OK", true /* base64 */)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, sessionDone := startGRPCWebHTTP1ProxyBase64(t, ctx, pipelineOptsBase64{
		installBase64Callback: true,
	})

	_ = sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("ping-base64"), true /* base64 */)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	st := firstBase64Stream(t, store, 5*time.Second)
	if st.Protocol != string(envelope.ProtocolGRPCWeb) {
		t.Errorf("Stream.Protocol = %q, want %q", st.Protocol, string(envelope.ProtocolGRPCWeb))
	}

	sendBase64 := waitForBase64Flows(t, store, st.ID, "send", 1, 5*time.Second)
	recvBase64 := waitForBase64Flows(t, store, st.ID, "receive", 1, 5*time.Second)
	if got := len(sendBase64); got != 1 {
		t.Errorf("send base64 count = %d, want 1", got)
	}
	if got := len(recvBase64); got != 1 {
		t.Errorf("receive base64 count = %d, want 1", got)
	}

	for _, f := range append(sendBase64, recvBase64...) {
		if len(f.RawBytes) == 0 {
			t.Errorf("base64 flow has empty RawBytes")
			continue
		}
		for _, b := range f.RawBytes {
			if !isBase64Byte(b) {
				t.Errorf("base64 flow RawBytes contains non-base64 byte %#x", b)
				break
			}
		}
		if f.WireLevel != flow.WireLevelGRPCWebBase64 {
			t.Errorf("base64 flow WireLevel = %q, want %q", f.WireLevel, flow.WireLevelGRPCWebBase64)
		}
	}
}

// TestGRPCWebBase64Recording_BinaryDoesNotFire covers Issue case 3 (the
// negative test): an application/grpc-web+proto (binary) request must
// NOT emit any grpcweb-base64 envelope. The callback fires only on the
// text branch by code structure.
func TestGRPCWebBase64Recording_BinaryDoesNotFire(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	respPayload := []byte("hello-binary")
	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP(respPayload, 0, "OK", false /* binary */)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, sessionDone := startGRPCWebHTTP1ProxyBase64(t, ctx, pipelineOptsBase64{
		installBase64Callback: true,
	})

	_ = sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("ping-binary"), false /* binary */)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	st := firstBase64Stream(t, store, 5*time.Second)

	// Wait briefly to allow any in-flight base64 records to land before
	// asserting absence — false-positive guard.
	time.Sleep(200 * time.Millisecond)

	all := base64FlowsForStream(store, st.ID, "")
	if len(all) != 0 {
		t.Errorf("binary variant fired the base64 callback %d times; want 0 (callback must be code-structurally limited to isBase64 branch)", len(all))
	}
}

// TestGRPCWebBase64Recording_PerStreamCap covers Issue case 4:
// WithGRPCWebBase64MaxPerStream caps the per-stream base64 record count.
// gRPC-Web is unary at the wire level (request → response), so a single
// RPC produces 1 Send + 1 Receive base64 envelope = 2 total. We set
// cap=1 and assert ≤1 envelope recorded.
func TestGRPCWebBase64Recording_PerStreamCap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	respPayload := []byte("cap-test")
	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP(respPayload, 0, "OK", true /* base64 */)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	const cap = 1
	proxyAddr, store, sessionDone := startGRPCWebHTTP1ProxyBase64(t, ctx, pipelineOptsBase64{
		installBase64Callback: true,
		recordOpts: []pipeline.Option{
			pipeline.WithGRPCWebBase64MaxPerStream(cap),
		},
	})

	resp := sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("ping"), true /* base64 */)
	// Wire forwarding intact: client must see a 200 response.
	if !bytes.Contains(resp, []byte("200 OK")) {
		t.Errorf("client did not see 200 OK; resp=%q", resp)
	}

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	st := firstBase64Stream(t, store, 5*time.Second)

	// Allow a brief moment for any post-EOF flush to drain into the
	// store before asserting the cap.
	time.Sleep(200 * time.Millisecond)

	all := base64FlowsForStream(store, st.ID, "")
	if len(all) > cap {
		t.Errorf("recorded base64 count = %d exceeds cap %d", len(all), cap)
	}
	// Sanity: an unconstrained run would produce 2 envelopes (Send +
	// Receive). Recording 2 means the cap did not fire — regression.
	if len(all) >= 2 {
		t.Errorf("cap did not fire: recorded %d envelopes (>= 2 indicates no drops)", len(all))
	}
}

// TestGRPCWebBase64Recording_MalformedBase64StillFires covers Issue
// case 5: a request whose body is malformed base64 must STILL fire the
// wire-record callback BEFORE the in-place decode runs — so the wire
// snapshot is preserved even when the decode subsequently fails. The
// semantic-envelope path emits Anomaly(MalformedGRPCWebBase64); the
// wire-record path captures the failing wire bytes verbatim.
func TestGRPCWebBase64Recording_MalformedBase64StillFires(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		// Upstream may receive a connection (the proxy dials lazily on
		// the first upstream.Send carrying the Anomaly Start) but never
		// a real request body — the session latches EOF inside the
		// channel after emitAnomalyStart.
		return buildGRPCWebResponseHTTP([]byte("never"), 0, "OK", false)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, sessionDone := startGRPCWebHTTP1ProxyBase64(t, ctx, pipelineOptsBase64{
		installBase64Callback: true,
	})

	malformedBody := []byte("!!!definitely-not-base64!!!")
	tlsConn := connectThroughProxy(t, proxyAddr, target, nil)
	defer tlsConn.Close()
	req := fmt.Sprintf(
		"POST /pkg.Echo/Say HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		target, "application/grpc-web-text+proto", len(malformedBody))
	if _, err := tlsConn.Write(append([]byte(req), malformedBody...)); err != nil {
		t.Fatalf("write malformed request: %v", err)
	}
	// Drain response (session terminates via EOF after the anomaly).
	_ = tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	tmp := make([]byte, 1024)
	for {
		_, err := tlsConn.Read(tmp)
		if err != nil {
			break
		}
	}

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	st := firstBase64Stream(t, store, 5*time.Second)

	// The send-side base64 wire envelope MUST be recorded even though
	// the decode failed downstream — that is the load-bearing wire-
	// record-before-decode contract.
	sendBase64 := waitForBase64Flows(t, store, st.ID, "send", 1, 5*time.Second)
	if got := len(sendBase64); got != 1 {
		t.Errorf("malformed base64 send envelope count = %d, want 1 (wire-record-before-decode contract violated)", got)
	}
	if got := sendBase64[0].RawBytes; !bytes.Equal(got, malformedBody) {
		t.Errorf("send base64 RawBytes = %q, want %q (malformed bytes must round-trip)", got, malformedBody)
	}
}

// TestGRPCWebBase64Recording_MCPQueryParity covers Issue case 6:
// a grpcweb-base64 flow is retrievable from the store by ID — the same
// lookup the `query` MCP tool performs. The testStore.allFlows() is
// the substitute for the MCP query round-trip (mirrors the USK-896
// pattern in TestGRPCLPMRecording_MCPQueryParity).
func TestGRPCWebBase64Recording_MCPQueryParity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	respPayload := []byte("mcp-parity")
	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return buildGRPCWebResponseHTTP(respPayload, 0, "OK", true /* base64 */)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, sessionDone := startGRPCWebHTTP1ProxyBase64(t, ctx, pipelineOptsBase64{
		installBase64Callback: true,
	})

	_ = sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("ping-mcp"), true /* base64 */)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	st := firstBase64Stream(t, store, 5*time.Second)
	sendBase64 := waitForBase64Flows(t, store, st.ID, "send", 1, 5*time.Second)
	if len(sendBase64) == 0 {
		t.Fatal("no send-side base64 flow recorded")
	}

	var found bool
	for _, f := range store.allFlows() {
		if f != nil && f.ID == sendBase64[0].ID && f.WireLevel == flow.WireLevelGRPCWebBase64 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("base64 flow %q not retrievable from store; MCP query tool would not see it either", sendBase64[0].ID)
	}
}

// TestGRPCWebBase64Recording_TextServerStreamingShape covers Issue
// case 2 in spirit (text server-streaming "many messages"): gRPC-Web's
// wire shape is request/response at the HTTPMessage level, but a single
// response body can pack multiple LPM frames. The callback fires ONCE
// per inbound text HTTPMessage regardless of how many LPM frames the
// body carries — which is the correct contract because the base64
// encoding is applied at the body level, not per LPM.
//
// We verify this by encoding a 5-LPM response body and asserting
// exactly 1 receive base64 envelope (NOT 5).
func TestGRPCWebBase64Recording_TextServerStreamingShape(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Build a 5-frame data body + 1 trailer frame inside a single
	// base64-encoded body. gRPC-Web allows multiple LPMs per body so
	// this is the on-wire shape of a server-streamed gRPC-Web response.
	var binaryBody []byte
	for i := 0; i < 5; i++ {
		binaryBody = append(binaryBody, grpcweb.EncodeFrame(false, false, []byte(fmt.Sprintf("msg-%d", i)))...)
	}
	trailerText := "grpc-status: 0\r\ngrpc-message: OK\r\n"
	binaryBody = append(binaryBody, grpcweb.EncodeFrame(true, false, []byte(trailerText))...)
	base64Body := grpcweb.EncodeBase64Body(binaryBody)

	respHeader := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		"application/grpc-web-text+proto", len(base64Body))
	respBytes := append([]byte(respHeader), base64Body...)

	upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
		return respBytes
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, sessionDone := startGRPCWebHTTP1ProxyBase64(t, ctx, pipelineOptsBase64{
		installBase64Callback: true,
	})

	_ = sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("ping-stream"), true /* base64 */)

	select {
	case <-sessionDone:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	st := firstBase64Stream(t, store, 5*time.Second)
	recvBase64 := waitForBase64Flows(t, store, st.ID, "receive", 1, 5*time.Second)
	// One HTTPMessage carries the entire response body (5 LPMs + 1
	// trailer). The base64-record callback fires once per HTTPMessage —
	// so we expect exactly 1 receive base64 envelope. This documents
	// the contract the callback enforces; if a future refactor
	// accidentally fires the callback per LPM, this test surfaces the
	// regression.
	if got := len(recvBase64); got != 1 {
		t.Errorf("receive base64 count = %d, want 1 (one envelope per HTTPMessage, not per LPM)", got)
	}
	if got := recvBase64[0].RawBytes; !bytes.Equal(got, base64Body) {
		t.Errorf("receive base64 RawBytes mismatch:\n got %d bytes\nwant %d bytes", len(got), len(base64Body))
	}
}

// TestGRPCWebBase64Recording_HTTP2TextUnary covers the h2 path of the
// same record contract. The production wiring in
// internal/proxybuild/builder.go threads grpcWebBase64Opt through
// DispatchH2StreamFull / WrapH2UpstreamForDispatchFull; here we
// exercise the equivalent minimal harness via
// DispatchH2StreamWithOpts.
func TestGRPCWebBase64Recording_HTTP2TextUnary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	respPayload := []byte("hello-h2-base64")
	upAddr, upShutdown := startGRPCWebHTTP2Upstream(t, func(_ *nethttp.Request) ([]byte, string) {
		body := buildGRPCWebResponseBody(respPayload, 0, "OK", true /* base64 */)
		return body, "application/grpc-web-text+proto"
	})
	defer upShutdown()

	proxyAddr, store, done := startGRPCWebHTTP2ProxyBase64(t, ctx, pipelineOptsBase64{
		installBase64Callback: true,
	})

	status, _, _ := sendGRPCWebHTTP2Request(t, proxyAddr, upAddr, []byte("ping-h2"), true /* base64 */)
	if status != 200 {
		t.Errorf("client status = %d, want 200", status)
	}

	// Wait for at least one stream completion.
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for h2 session to complete")
	}

	st := firstBase64Stream(t, store, 5*time.Second)
	if st.Protocol != string(envelope.ProtocolGRPCWeb) {
		t.Errorf("Stream.Protocol = %q, want %q", st.Protocol, string(envelope.ProtocolGRPCWeb))
	}

	// Receive side is the load-bearing case for h2: response body is
	// base64-encoded, so the receive base64 callback must fire.
	recvBase64 := waitForBase64Flows(t, store, st.ID, "receive", 1, 5*time.Second)
	if got := len(recvBase64); got != 1 {
		t.Errorf("h2 receive base64 count = %d, want 1", got)
	}
	if got := recvBase64[0].WireLevel; got != flow.WireLevelGRPCWebBase64 {
		t.Errorf("h2 receive base64 WireLevel = %q, want %q", got, flow.WireLevelGRPCWebBase64)
	}
}
