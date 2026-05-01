//go:build e2e

package mcp

// resend_raw_integration_test.go — RFC-001 N8 acceptance gate for the
// resend_raw MCP tool (USK-675).
//
// The suite drives raw byte payloads through resend_raw against:
//   - a plain TCP echo server (round-trip + smuggling payload preservation)
//   - a TLS echo server (TLS dial path)
//
// Acceptance criteria (USK-675):
//   AC#1: TLS-passthrough host raw HTTP/1 round-trip
//   AC#2: HTTP smuggling payload (dual CL/TE) reaches the wire un-normalized
//   AC#3: Patches apply by exact offset
//   AC#4: PluginStepPost fires once on send (and once per receive chunk)
//   AC#5: Legacy resend_raw_h2 unaffected — reuses different tool name + struct
//
// Pattern: in-memory MCP transports + a per-test echo server + a fresh
// flow store seeded with the original RawMessage Send Flow that
// resend_raw recovers via flow_id.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// resendRawHookCallable wraps a Go counter increment in a Starlark
// Callable so it can be registered on the pluginv2 Engine. Mirrors the
// helper in resend_grpc_integration_test.go.
func resendRawHookCallable(name string, fn func()) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		fn()
		return starlark.None, nil
	})
}

// setupResendRawSession spins up an MCP server pre-wired with a fresh
// flow store and a pluginv2.Engine that pre-registers post-pipeline
// counter hooks for ("raw", "on_chunk"). Returns the client session,
// the flow store (so the test can seed a recorded RawMessage Stream),
// and the on_chunk counter pointer.
func setupResendRawSession(t *testing.T) (*gomcp.ClientSession, flow.Store, *int32) {
	t.Helper()
	store := newTestStore(t)
	engine := pluginv2.NewEngine(nil)

	var chunkCount int32
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoRaw,
		Event:      pluginv2.EventOnChunk,
		Phase:      pluginv2.PhasePostPipeline,
		PluginName: "resend-raw-post-chunk",
		Fn: resendRawHookCallable("post-chunk", func() {
			atomic.AddInt32(&chunkCount, 1)
		}),
	})

	ctx := context.Background()
	srv := newServer(ctx, nil, store, nil, WithPluginv2Engine(engine))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "resend-raw-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store, &chunkCount
}

// seedRawStream creates a Stream + Send Flow row with the given raw
// bytes so resend_raw can recover them via flow_id.
func seedRawStream(t *testing.T, store flow.Store, payload []byte) string {
	t.Helper()
	streamID := "seed-raw-" + nowSuffix()
	now := time.Now()
	st := &flow.Stream{
		ID:        streamID,
		Protocol:  "raw",
		State:     "complete",
		Timestamp: now,
		ConnID:    "conn-" + streamID,
	}
	if err := store.SaveStream(context.Background(), st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	send := &flow.Flow{
		ID:        "send-" + streamID,
		StreamID:  streamID,
		Sequence:  0,
		Direction: "send",
		Timestamp: now,
		Body:      payload,
		RawBytes:  payload,
		URL:       &url.URL{},
	}
	if err := store.SaveFlow(context.Background(), send); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	return streamID
}

func nowSuffix() string {
	return time.Now().Format("150405.000000000")
}

// startTCPEcho stands up a TCP echo server and returns its address +
// a captured-bytes getter (everything the server receives, in order).
func startTCPEcho(t *testing.T) (string, func() []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var (
		mu   sync.Mutex
		recv []byte
	)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buf)
			if n > 0 {
				mu.Lock()
				recv = append(recv, buf[:n]...)
				mu.Unlock()
				_, _ = conn.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	return ln.Addr().String(), func() []byte {
		mu.Lock()
		defer mu.Unlock()
		out := make([]byte, len(recv))
		copy(out, recv)
		return out
	}
}

// startTLSEcho stands up a TLS echo server with a self-signed cert and
// returns its address + a captured-bytes getter.
func startTLSEcho(t *testing.T) (string, func() []byte) {
	t.Helper()
	cfg := newResendRawTestTLSConfig(t, "localhost")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var (
		mu   sync.Mutex
		recv []byte
	)
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buf)
			if n > 0 {
				mu.Lock()
				recv = append(recv, buf[:n]...)
				mu.Unlock()
				// Echo a small canned response so the receive loop
				// has something to record.
				_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			}
			if err != nil {
				return
			}
		}
	}()
	return ln.Addr().String(), func() []byte {
		mu.Lock()
		defer mu.Unlock()
		out := make([]byte, len(recv))
		copy(out, recv)
		return out
	}
}

// newResendRawTestTLSConfig generates a self-signed TLS server config
// covering hostname. Local copy of the connector's helper (package
// boundary).
func newResendRawTestTLSConfig(t *testing.T, hostname string) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}
}

// callResendRaw issues the resend_raw tool and decodes the structured
// result. Test fails on transport errors or IsError responses.
func callResendRaw(t *testing.T, cs *gomcp.ClientSession, input map[string]any) *resendRawTypedResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "resend_raw",
		Arguments: input,
	})
	if err != nil {
		t.Fatalf("CallTool resend_raw: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("tool returned error: %s", msg.String())
	}
	if res.StructuredContent == nil {
		t.Fatal("expected structured content, got nil")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out resendRawTypedResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode structured content: %v", err)
	}
	return &out
}

// ---------------------------------------------------------------------------
// AC#1 (TLS) — TLS-passthrough host raw HTTP/1 round-trip.
// ---------------------------------------------------------------------------

func TestResendRaw_TLSRoundTrip(t *testing.T) {
	cs, store, chunkCount := setupResendRawSession(t)
	addr, getRecv := startTLSEcho(t)

	originalReq := []byte("GET /seed HTTP/1.1\r\nHost: localhost\r\n\r\n")
	streamID := seedRawStream(t, store, originalReq)

	result := callResendRaw(t, cs, map[string]any{
		"flow_id":              streamID,
		"target_addr":          addr,
		"use_tls":              true,
		"sni":                  "localhost",
		"insecure_skip_verify": true,
		"timeout_ms":           5000,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if string(getRecv()) == string(originalReq) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if string(getRecv()) != string(originalReq) {
		t.Errorf("upstream received = %q, want %q", getRecv(), originalReq)
	}

	respBytes, err := base64.StdEncoding.DecodeString(result.ResponseBytes)
	if err != nil {
		t.Fatalf("decode response_bytes: %v", err)
	}
	if !strings.HasPrefix(string(respBytes), "HTTP/1.1 200") {
		t.Errorf("response = %q, want HTTP/1.1 200 prefix", respBytes)
	}
	if got := atomic.LoadInt32(chunkCount); got < 2 {
		t.Errorf("on_chunk hook fired %d times, want >= 2 (1 send + 1 receive)", got)
	}
}

// ---------------------------------------------------------------------------
// AC#2 — HTTP smuggling payload (dual CL/TE) round-trips byte-for-byte.
// Override sends the smuggling payload regardless of the recorded bytes.
// ---------------------------------------------------------------------------

func TestResendRaw_SmugglingPayloadVerbatim(t *testing.T) {
	cs, store, _ := setupResendRawSession(t)
	addr, getRecv := startTCPEcho(t)

	// Seed with arbitrary recorded bytes; override_bytes will replace them.
	streamID := seedRawStream(t, store, []byte("ignored-recorded"))

	smuggling := []byte(
		"POST / HTTP/1.1\r\n" +
			"Host: target\r\n" +
			"Content-Length: 13\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"\r\n" +
			"0\r\n" +
			"\r\n" +
			"GET /admin HTTP/1.1\r\nHost: target\r\n\r\n",
	)

	callResendRaw(t, cs, map[string]any{
		"flow_id":                 streamID,
		"target_addr":             addr,
		"override_bytes":          base64.StdEncoding.EncodeToString(smuggling),
		"override_bytes_encoding": "base64",
		"timeout_ms":              3000,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if string(getRecv()) == string(smuggling) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if string(getRecv()) != string(smuggling) {
		t.Errorf("smuggling payload mutated on the wire — diff between sent and received bytes\nsent:  %q\nrecv:  %q", smuggling, getRecv())
	}
}

// ---------------------------------------------------------------------------
// AC#3 — Patches apply by exact offset.
// ---------------------------------------------------------------------------

func TestResendRaw_PatchesApplyAtExactOffset(t *testing.T) {
	cs, store, _ := setupResendRawSession(t)
	addr, getRecv := startTCPEcho(t)

	original := []byte("GET /aaaa HTTP/1.1\r\nHost: target\r\n\r\n")
	streamID := seedRawStream(t, store, original)

	// Replace the path "/aaaa" with "/bbbb": offset 4, 5 bytes.
	// Bytes 0..3 = "GET ", byte 4 = '/', bytes 4..8 = "/aaaa".
	callResendRaw(t, cs, map[string]any{
		"flow_id":     streamID,
		"target_addr": addr,
		"patches": []map[string]any{
			{"offset": 4, "data": "/bbbb"},
		},
		"timeout_ms": 3000,
	})

	expected := []byte("GET /bbbb HTTP/1.1\r\nHost: target\r\n\r\n")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if string(getRecv()) == string(expected) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if string(getRecv()) != string(expected) {
		t.Errorf("patched bytes wrong\nsent:  %q\nrecv:  %q", expected, getRecv())
	}
}

// ---------------------------------------------------------------------------
// Validation: flow_id required.
// ---------------------------------------------------------------------------

func TestResendRaw_RejectsMissingFlowID(t *testing.T) {
	cs, _, _ := setupResendRawSession(t)
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_raw",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
		},
	})
	if err != nil {
		// MCP-level rejection (schema validation) — acceptable.
		return
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected error for missing flow_id; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: target_addr required.
// ---------------------------------------------------------------------------

func TestResendRaw_RejectsMissingTargetAddr(t *testing.T) {
	cs, store, _ := setupResendRawSession(t)
	streamID := seedRawStream(t, store, []byte("x"))
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_raw",
		Arguments: map[string]any{
			"flow_id": streamID,
		},
	})
	if err != nil {
		// MCP-level rejection (schema validation) — acceptable.
		return
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected error for missing target_addr; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: override_bytes + patches mutually exclusive.
// ---------------------------------------------------------------------------

func TestResendRaw_RejectsOverrideAndPatchesTogether(t *testing.T) {
	cs, store, _ := setupResendRawSession(t)
	streamID := seedRawStream(t, store, []byte("x"))
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_raw",
		Arguments: map[string]any{
			"flow_id":        streamID,
			"target_addr":    "127.0.0.1:9999",
			"override_bytes": "y",
			"patches": []map[string]any{
				{"offset": 0, "data": "z"},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected mutex error; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: target_addr requires explicit port.
// ---------------------------------------------------------------------------

func TestResendRaw_RejectsTargetAddrWithoutPort(t *testing.T) {
	cs, store, _ := setupResendRawSession(t)
	streamID := seedRawStream(t, store, []byte("x"))
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_raw",
		Arguments: map[string]any{
			"flow_id":     streamID,
			"target_addr": "host-without-port",
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for missing port; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// CRLF guards on user-supplied URL components (NOT on payload — wire bytes
// are sacred and CRLF in the payload is the entire point of this tool).
// ---------------------------------------------------------------------------

func TestResendRaw_RejectsCRLFInTargetAddrAndSNI(t *testing.T) {
	cs, store, _ := setupResendRawSession(t)
	streamID := seedRawStream(t, store, []byte("x"))

	cases := []struct {
		name, field, value string
	}{
		{"target-addr-cr", "target_addr", "127.0.0.1:80\rInjected"},
		{"target-addr-lf", "target_addr", "127.0.0.1:80\nInjected"},
		{"sni-cr", "sni", "host\rInjected"},
		{"sni-lf", "sni", "host\nInjected"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			input := map[string]any{
				"flow_id":     streamID,
				"target_addr": "127.0.0.1:9999",
			}
			input[c.field] = c.value
			res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name:      "resend_raw",
				Arguments: input,
			})
			if res == nil || !res.IsError {
				t.Fatalf("expected error for %s=%q; got %+v", c.field, c.value, res)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Wire fidelity: payload CRLF is preserved (deliberately NOT rejected).
// ---------------------------------------------------------------------------

func TestResendRaw_PayloadCRLFNotRejected(t *testing.T) {
	cs, store, _ := setupResendRawSession(t)
	addr, getRecv := startTCPEcho(t)

	streamID := seedRawStream(t, store, []byte("seed"))
	payloadWithCRLF := []byte("line1\r\nline2\r\n")

	callResendRaw(t, cs, map[string]any{
		"flow_id":                 streamID,
		"target_addr":             addr,
		"override_bytes":          base64.StdEncoding.EncodeToString(payloadWithCRLF),
		"override_bytes_encoding": "base64",
		"timeout_ms":              3000,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if string(getRecv()) == string(payloadWithCRLF) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if string(getRecv()) != string(payloadWithCRLF) {
		t.Errorf("payload CRLF normalized\nsent:  %q\nrecv:  %q", payloadWithCRLF, getRecv())
	}
}

// ---------------------------------------------------------------------------
// Tag application — verifies that input.tag lands on the new Stream row.
// ---------------------------------------------------------------------------

func TestResendRaw_TagAppliedToStreamRow(t *testing.T) {
	cs, store, _ := setupResendRawSession(t)
	addr, _ := startTCPEcho(t)

	streamID := seedRawStream(t, store, []byte("ping"))

	result := callResendRaw(t, cs, map[string]any{
		"flow_id":     streamID,
		"target_addr": addr,
		"tag":         "raw-resend-tag-1",
		"timeout_ms":  3000,
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s, err := store.GetStream(context.Background(), result.StreamID)
		if err == nil && s != nil && s.Tags["tag"] == "raw-resend-tag-1" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("tag did not propagate to stream %s within deadline", result.StreamID)
}

// ---------------------------------------------------------------------------
// Validation: patches[].offset is bounded to maxResendRawPayload at the
// schema layer (CWE-789, security review S-1). Without this guard,
// job.ApplyPatches would allocate a multi-GiB destination slice before
// the post-application size check fires in buildResendRawPlan.
// ---------------------------------------------------------------------------

func TestResendRaw_RejectsPatchOffsetExceedingPayloadCap(t *testing.T) {
	cs, store, _ := setupResendRawSession(t)
	streamID := seedRawStream(t, store, []byte("x"))
	// 1 GiB offset — well above the 16 MiB payload cap.
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_raw",
		Arguments: map[string]any{
			"flow_id":     streamID,
			"target_addr": "127.0.0.1:9999",
			"patches": []map[string]any{
				{"offset": 1 << 30, "data": "z"},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for offset exceeding payload cap; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Non-raw flow_id is rejected with an explicit pointer to the right tool.
// ---------------------------------------------------------------------------

func TestResendRaw_RejectsNonRawFlowID(t *testing.T) {
	cs, store, _ := setupResendRawSession(t)
	streamID := "http-stream-" + nowSuffix()
	if err := store.SaveStream(context.Background(), &flow.Stream{
		ID: streamID, Protocol: "http", State: "complete", Timestamp: time.Now(),
	}); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_raw",
		Arguments: map[string]any{
			"flow_id":     streamID,
			"target_addr": "127.0.0.1:9999",
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for non-raw flow_id; got %+v", res)
	}
}

// resend_raw_helpers.go imports envelope only; this var keeps the
// import live in the test file via a pluginv2 reference, since the
// raw-direction constants live there.
var _ envelope.Direction = envelope.Send
