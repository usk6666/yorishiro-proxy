//go:build e2e

package mcp

// fuzz_raw_integration_test.go — RFC-001 N8 acceptance gate for the
// fuzz_raw MCP tool (USK-680).
//
// Acceptance criteria:
//   AC#1: N variant generation + per-variant Stream rows in flow store
//   AC#2: Smuggling payload variants reach the wire un-normalized
//   AC#3: PluginStepPost fires per variant; PluginStepPre never fires
//   AC#4: Legacy `fuzz` tool unaffected (parallel coexistence)

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// fuzzRawHookCallable wraps a Go counter increment in a Starlark
// Callable. Mirrors helpers in resend_raw_integration_test.go and
// fuzz_http_integration_test.go.
func fuzzRawHookCallable(name string, fn func()) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		fn()
		return starlark.None, nil
	})
}

// setupFuzzRawSession spins up an MCP server pre-wired with a fresh
// flow store and a pluginv2.Engine that pre-registers pre/post counter
// hooks for ("raw", "on_chunk"). Returns the client session, the flow
// store, and the (preCount, postCount) atomic pointers.
func setupFuzzRawSession(t *testing.T) (*gomcp.ClientSession, flow.Store, *int32, *int32) {
	t.Helper()
	store := newTestStore(t)
	engine := pluginv2.NewEngine(nil)

	var preCount, postCount int32
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoRaw,
		Event:      pluginv2.EventOnChunk,
		Phase:      pluginv2.PhasePrePipeline,
		PluginName: "fuzz-raw-pre",
		Fn: fuzzRawHookCallable("pre", func() {
			atomic.AddInt32(&preCount, 1)
		}),
	})
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoRaw,
		Event:      pluginv2.EventOnChunk,
		Phase:      pluginv2.PhasePostPipeline,
		PluginName: "fuzz-raw-post",
		Fn: fuzzRawHookCallable("post", func() {
			atomic.AddInt32(&postCount, 1)
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

	client := gomcp.NewClient(&gomcp.Implementation{Name: "fuzz-raw-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store, &preCount, &postCount
}

// startFuzzRawTCPServer stands up a TCP server that captures EACH
// connection's received bytes separately (one variant = one connection).
// The returned getter exposes the per-connection captures in accept
// order, so tests can verify each variant landed verbatim.
func startFuzzRawTCPServer(t *testing.T) (string, func() [][]byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var (
		mu       sync.Mutex
		captures [][]byte
	)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 8192)
				var got []byte
				for {
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					n, err := c.Read(buf)
					if n > 0 {
						got = append(got, buf[:n]...)
						// Reply with a canned response so the receive loop
						// has something to record.
						_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
					}
					if err != nil {
						break
					}
				}
				mu.Lock()
				captures = append(captures, got)
				mu.Unlock()
			}(conn)
		}
	}()

	return ln.Addr().String(), func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]byte, len(captures))
		for i, c := range captures {
			cc := make([]byte, len(c))
			copy(cc, c)
			out[i] = cc
		}
		return out
	}
}

// startFuzzRawTLSServer stands up a TLS server with the helper's
// self-signed cert. Captures per-connection bytes like
// startFuzzRawTCPServer.
func startFuzzRawTLSServer(t *testing.T) (string, func() [][]byte) {
	t.Helper()
	cfg := newResendRawTestTLSConfig(t, "localhost")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var (
		mu       sync.Mutex
		captures [][]byte
	)
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 8192)
				var got []byte
				for {
					_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
					n, err := c.Read(buf)
					if n > 0 {
						got = append(got, buf[:n]...)
						_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
					}
					if err != nil {
						break
					}
				}
				mu.Lock()
				captures = append(captures, got)
				mu.Unlock()
			}(conn)
		}
	}()

	return ln.Addr().String(), func() [][]byte {
		mu.Lock()
		defer mu.Unlock()
		out := make([][]byte, len(captures))
		for i, c := range captures {
			cc := make([]byte, len(c))
			copy(cc, c)
			out[i] = cc
		}
		return out
	}
}

// callFuzzRaw issues the fuzz_raw tool and decodes the structured
// result. Test fails on transport errors or IsError responses.
func callFuzzRaw(t *testing.T, cs *gomcp.ClientSession, input map[string]any) *fuzzRawResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "fuzz_raw",
		Arguments: input,
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_raw: %v", err)
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
	var out fuzzRawResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode structured content: %v", err)
	}
	return &out
}

// waitForCaptures polls until at least n connection captures have been
// recorded, or the deadline passes.
func waitForCaptures(getRecv func() [][]byte, n int, deadline time.Duration) [][]byte {
	stop := time.Now().Add(deadline)
	for time.Now().Before(stop) {
		caps := getRecv()
		if len(caps) >= n {
			return caps
		}
		time.Sleep(20 * time.Millisecond)
	}
	return getRecv()
}

// ---------------------------------------------------------------------------
// AC#1 + AC#2 + AC#3 — N variant smuggling payloads round-trip un-normalised
// against a TLS-passthrough server. Each variant gets its own per-Stream row
// in the flow store, PluginStepPost fires per Send envelope, PluginStepPre
// stays at zero, and the captured wire bytes match the substituted payloads
// byte-for-byte (including embedded CRLF / control characters).
// ---------------------------------------------------------------------------

func TestFuzzRaw_TLSSmugglingVariantsRoundTrip(t *testing.T) {
	cs, store, preCount, postCount := setupFuzzRawSession(t)
	addr, getRecv := startFuzzRawTLSServer(t)

	// 3 different smuggling payloads. Each contains intentional CRLF
	// boundaries that a wire-normalising proxy would sanitise; fuzz_raw
	// must pass them through verbatim.
	variants := [][]byte{
		[]byte("POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /a HTTP/1.1\r\nHost: target\r\n\r\n"),
		[]byte("POST / HTTP/1.1\r\nHost: target\r\nContent-Length: 0\r\nContent-Length: 44\r\n\r\nGET /b HTTP/1.1\r\nHost: target\r\n\r\n"),
		[]byte("GET /c\x00\r\nHost: target\r\n\r\n"),
	}
	encodedPayloads := make([]string, len(variants))
	for i, v := range variants {
		encodedPayloads[i] = base64.StdEncoding.EncodeToString(v)
	}

	result := callFuzzRaw(t, cs, map[string]any{
		"target_addr":          addr,
		"use_tls":              true,
		"sni":                  "localhost",
		"insecure_skip_verify": true,
		"positions": []map[string]any{
			{"path": "payload", "payloads": encodedPayloads, "encoding": "base64"},
		},
		"timeout_ms": 5000,
	})

	if result.TotalVariants != len(variants) {
		t.Errorf("TotalVariants = %d, want %d", result.TotalVariants, len(variants))
	}
	if result.CompletedVariants != len(variants) {
		t.Errorf("CompletedVariants = %d, want %d", result.CompletedVariants, len(variants))
	}
	if len(result.Variants) != len(variants) {
		t.Fatalf("len(Variants) = %d, want %d", len(result.Variants), len(variants))
	}

	// AC#1: per-variant Stream rows recorded.
	for i, row := range result.Variants {
		if row.StreamID == "" {
			t.Errorf("variants[%d].StreamID is empty", i)
		}
		if row.Error != "" {
			t.Errorf("variants[%d].Error = %q, want empty", i, row.Error)
		}
		s, err := store.GetStream(context.Background(), row.StreamID)
		if err != nil || s == nil {
			t.Errorf("variants[%d]: GetStream(%s) err=%v", i, row.StreamID, err)
		}
	}

	// AC#2: every variant payload reached the wire byte-for-byte.
	caps := waitForCaptures(getRecv, len(variants), 3*time.Second)
	if len(caps) < len(variants) {
		t.Fatalf("captured %d connections, want %d", len(caps), len(variants))
	}
	// Build a set of "sent" payloads for set-comparison (variant order
	// equals connect order on a serial run, but we set-compare to keep
	// the assertion robust to any future loop reordering).
	want := map[string]bool{}
	for _, v := range variants {
		want[string(v)] = true
	}
	got := map[string]bool{}
	for _, c := range caps {
		got[string(c)] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("upstream did not see payload %q (got %d captures)", w, len(caps))
		}
	}

	// AC#3: PluginStepPost fired per Send envelope (= len(variants))
	// PLUS once per response chunk (each connection echoes one canned
	// 38-byte response, so ≥ len(variants) more fires). PluginStepPre
	// must never fire (resend bypass per RFC §9.3 D1).
	if got := atomic.LoadInt32(preCount); got != 0 {
		t.Errorf("on_chunk pre hook fired %d times, want 0 (PluginStepPre bypassed)", got)
	}
	if got := atomic.LoadInt32(postCount); got < int32(len(variants)) {
		t.Errorf("on_chunk post hook fired %d times, want >= %d (one per Send envelope)", got, len(variants))
	}
}

// ---------------------------------------------------------------------------
// AC#1 — Patch-data position substitutes input.Patches[N].Data per variant.
// Demonstrates the patches[N].data position path against a flow_id base.
// ---------------------------------------------------------------------------

func TestFuzzRaw_PatchDataPositionSubstitution(t *testing.T) {
	cs, store, _, _ := setupFuzzRawSession(t)
	addr, getRecv := startFuzzRawTCPServer(t)

	// Seed a recorded flow with a request; the position mutates a
	// 5-byte path slice via patches[0].data.
	original := []byte("GET /aaaa HTTP/1.1\r\nHost: target\r\n\r\n")
	streamID := seedRawStream(t, store, original)

	pathPayloads := []string{"/bbbb", "/cccc", "/dddd"}
	result := callFuzzRaw(t, cs, map[string]any{
		"flow_id":     streamID,
		"target_addr": addr,
		"patches": []map[string]any{
			{"offset": 4, "data": "/aaaa"}, // base patch — substituted per variant
		},
		"positions": []map[string]any{
			{"path": "patches[0].data", "payloads": pathPayloads},
		},
		"timeout_ms": 5000,
	})
	if result.CompletedVariants != len(pathPayloads) {
		t.Fatalf("CompletedVariants = %d, want %d", result.CompletedVariants, len(pathPayloads))
	}

	caps := waitForCaptures(getRecv, len(pathPayloads), 3*time.Second)
	if len(caps) < len(pathPayloads) {
		t.Fatalf("captured %d connections, want %d", len(caps), len(pathPayloads))
	}
	want := map[string]bool{}
	for _, p := range pathPayloads {
		want[fmt.Sprintf("GET %s HTTP/1.1\r\nHost: target\r\n\r\n", p)] = true
	}
	for _, c := range caps {
		if !want[string(c)] {
			t.Errorf("unexpected capture %q", c)
		}
	}
}

// ---------------------------------------------------------------------------
// AC#1 — From-scratch (no flow_id) variant via "payload" position only.
// ---------------------------------------------------------------------------

func TestFuzzRaw_FromScratchPayloadPosition(t *testing.T) {
	cs, _, _, postCount := setupFuzzRawSession(t)
	addr, getRecv := startFuzzRawTCPServer(t)

	payloads := []string{"hello-1", "hello-2", "hello-3"}
	result := callFuzzRaw(t, cs, map[string]any{
		"target_addr": addr,
		"positions": []map[string]any{
			{"path": "payload", "payloads": payloads},
		},
		"timeout_ms": 5000,
	})
	if result.CompletedVariants != len(payloads) {
		t.Fatalf("CompletedVariants = %d, want %d", result.CompletedVariants, len(payloads))
	}
	if got := atomic.LoadInt32(postCount); got < int32(len(payloads)) {
		t.Errorf("on_chunk post hook fired %d, want >= %d", got, len(payloads))
	}

	caps := waitForCaptures(getRecv, len(payloads), 3*time.Second)
	want := map[string]bool{}
	for _, p := range payloads {
		want[p] = true
	}
	got := map[string]bool{}
	for _, c := range caps {
		got[string(c)] = true
	}
	for w := range want {
		if !got[w] {
			t.Errorf("upstream did not see payload %q", w)
		}
	}
}

// ---------------------------------------------------------------------------
// Wire fidelity: payload CRLF / control chars survive verbatim. This is the
// central MITM invariant of fuzz_raw — analysts use it for smuggling fuzz
// against parsers that diverge on CRLF or NUL handling.
// ---------------------------------------------------------------------------

func TestFuzzRaw_PayloadCRLFNotNormalized(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)
	addr, getRecv := startFuzzRawTCPServer(t)

	// Two "smuggling-shaped" payloads with embedded CR/LF/NUL.
	smuggle1 := []byte("line1\r\nline2\r\n\x00\r\n")
	smuggle2 := []byte("\rinjected\nline\r\n")
	encoded := []string{
		base64.StdEncoding.EncodeToString(smuggle1),
		base64.StdEncoding.EncodeToString(smuggle2),
	}

	callFuzzRaw(t, cs, map[string]any{
		"target_addr": addr,
		"positions": []map[string]any{
			{"path": "payload", "payloads": encoded, "encoding": "base64"},
		},
		"timeout_ms": 3000,
	})

	caps := waitForCaptures(getRecv, 2, 3*time.Second)
	if len(caps) < 2 {
		t.Fatalf("captured %d connections, want 2", len(caps))
	}
	got := map[string]bool{}
	for _, c := range caps {
		got[string(c)] = true
	}
	if !got[string(smuggle1)] {
		t.Errorf("smuggle1 mutated on the wire (got captures %v)", got)
	}
	if !got[string(smuggle2)] {
		t.Errorf("smuggle2 mutated on the wire (got captures %v)", got)
	}
}

// ---------------------------------------------------------------------------
// Cartesian product across two positions ("payload" only — the patches[N].data
// position is not stackable with payload because payload wins wholesale).
// Two patches[N].data positions exercise the cartesian product without
// "payload" override.
// ---------------------------------------------------------------------------

func TestFuzzRaw_TwoPatchPositionsCartesian(t *testing.T) {
	cs, store, _, _ := setupFuzzRawSession(t)
	addr, getRecv := startFuzzRawTCPServer(t)

	// Base bytes: "GET /AAAA HTTP/1.1\r\nHost: BBBB\r\n\r\n"
	// Position 0: patch[0] @ offset 4, replaces "/AAAA"
	// Position 1: patch[1] @ offset 25, replaces "BBBB"
	// Note: "\r\nHost: " is 8 chars; "GET /AAAA HTTP/1.1" is 18 chars;
	//       "GET /AAAA HTTP/1.1\r\nHost: " puts BBBB at offset 26.
	original := []byte("GET /AAAA HTTP/1.1\r\nHost: BBBB\r\n\r\n")
	streamID := seedRawStream(t, store, original)

	// Compute exact offsets so we don't get stuck on miscounts.
	pathOffset := 4  // "GET " is 4 bytes
	hostOffset := 26 // "GET /AAAA HTTP/1.1\r\nHost: " is 26 bytes

	pathPayloads := []string{"/x111", "/x222"}
	hostPayloads := []string{"H001", "H002", "H003"}

	result := callFuzzRaw(t, cs, map[string]any{
		"flow_id":     streamID,
		"target_addr": addr,
		"patches": []map[string]any{
			{"offset": pathOffset, "data": "/AAAA"},
			{"offset": hostOffset, "data": "BBBB"},
		},
		"positions": []map[string]any{
			{"path": "patches[0].data", "payloads": pathPayloads},
			{"path": "patches[1].data", "payloads": hostPayloads},
		},
		"timeout_ms": 10000,
	})
	expected := len(pathPayloads) * len(hostPayloads)
	if result.TotalVariants != expected {
		t.Errorf("TotalVariants = %d, want %d", result.TotalVariants, expected)
	}
	if result.CompletedVariants != expected {
		t.Errorf("CompletedVariants = %d, want %d", result.CompletedVariants, expected)
	}

	caps := waitForCaptures(getRecv, expected, 5*time.Second)
	if len(caps) < expected {
		t.Fatalf("captured %d connections, want %d", len(caps), expected)
	}
	pairs := map[string]bool{}
	for _, c := range caps {
		pairs[string(c)] = true
	}
	for _, pp := range pathPayloads {
		for _, hp := range hostPayloads {
			want := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", pp, hp)
			if !pairs[want] {
				t.Errorf("missing variant %q", want)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Tag application — every variant Stream gets the tag.
// ---------------------------------------------------------------------------

func TestFuzzRaw_TagAppliedToEachVariantStream(t *testing.T) {
	cs, store, _, _ := setupFuzzRawSession(t)
	addr, _ := startFuzzRawTCPServer(t)

	result := callFuzzRaw(t, cs, map[string]any{
		"target_addr": addr,
		"positions": []map[string]any{
			{"path": "payload", "payloads": []string{"v1", "v2"}},
		},
		"tag":        "fuzz-raw-tag-7",
		"timeout_ms": 5000,
	})
	if result.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", result.CompletedVariants)
	}

	deadline := time.Now().Add(2 * time.Second)
	for _, row := range result.Variants {
		for time.Now().Before(deadline) {
			s, err := store.GetStream(context.Background(), row.StreamID)
			if err == nil && s != nil && s.Tags["tag"] == "fuzz-raw-tag-7" {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		s, _ := store.GetStream(context.Background(), row.StreamID)
		if s == nil || s.Tags["tag"] != "fuzz-raw-tag-7" {
			t.Errorf("stream %s tag not applied (got %v)", row.StreamID, s)
		}
	}
}

// ---------------------------------------------------------------------------
// AC#4 — Legacy `fuzz` tool unaffected (parallel coexistence). The MCP server
// must register both tool names; calling fuzz_raw does not unwire fuzz.
// ---------------------------------------------------------------------------

func TestFuzzRaw_LegacyFuzzToolStillRegistered(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)
	res, err := cs.ListTools(context.Background(), &gomcp.ListToolsParams{})
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range res.Tools {
		names[tool.Name] = true
	}
	if !names["fuzz"] {
		t.Error("legacy fuzz tool missing from registry")
	}
	if !names["fuzz_raw"] {
		t.Error("fuzz_raw tool missing from registry")
	}
	if !names["resend_raw"] {
		t.Error("resend_raw tool missing from registry (parallel sibling)")
	}
}

// ---------------------------------------------------------------------------
// Validation: target_addr required.
// ---------------------------------------------------------------------------

func TestFuzzRaw_RejectsMissingTargetAddr(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"x"}},
			},
		},
	})
	if err != nil {
		// MCP-level rejection is acceptable.
		return
	}
	if res == nil || !res.IsError {
		t.Fatalf("expected error for missing target_addr; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: positions required.
// ---------------------------------------------------------------------------

func TestFuzzRaw_RejectsEmptyPositions(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"positions":   []map[string]any{},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for empty positions; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: at least one of {flow_id, override_bytes, "payload" position}
// must supply variant bytes.
// ---------------------------------------------------------------------------

func TestFuzzRaw_RejectsMissingByteSource(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)
	// flow_id empty, override_bytes empty, no "payload" position
	// (only patches[0].data which has nothing to substitute).
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"patches": []map[string]any{
				{"offset": 0, "data": "x"},
			},
			"positions": []map[string]any{
				{"path": "patches[0].data", "payloads": []string{"a", "b"}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for missing byte source; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: invalid path syntax rejected.
// ---------------------------------------------------------------------------

func TestFuzzRaw_RejectsInvalidPath(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"positions": []map[string]any{
				{"path": "method", "payloads": []string{"x"}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for invalid path; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: patches[N].data with N out of range rejected.
// ---------------------------------------------------------------------------

func TestFuzzRaw_RejectsPatchIndexOutOfRange(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr":    "127.0.0.1:9999",
			"override_bytes": "seed",
			"positions": []map[string]any{
				// patches is empty, so patches[0].data is invalid.
				{"path": "patches[0].data", "payloads": []string{"x"}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for out-of-range patch index; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: variant cartesian product cap enforced.
// ---------------------------------------------------------------------------

func TestFuzzRaw_RejectsExcessiveVariantCount(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)
	bigList := make([]string, 100)
	for i := range bigList {
		bigList[i] = fmt.Sprintf("p%d", i)
	}
	bigList2 := make([]string, 100)
	for i := range bigList2 {
		bigList2[i] = fmt.Sprintf("q%d", i)
	}
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr":    "127.0.0.1:9999",
			"override_bytes": "seed",
			"patches": []map[string]any{
				{"offset": 0, "data": "a"},
				{"offset": 10, "data": "b"},
			},
			"positions": []map[string]any{
				{"path": "patches[0].data", "payloads": bigList},
				{"path": "patches[1].data", "payloads": bigList2},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for excessive variant count; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: per-payload decoded size cap (CWE-770).
// ---------------------------------------------------------------------------

func TestFuzzRaw_RejectsExcessivePayloadSize(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)
	bigPayload := strings.Repeat("A", 2<<20) // 2 MiB > 1 MiB cap
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{bigPayload}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for oversized payload; got %+v", res)
	}
	var msg strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			msg.WriteString(tc.Text)
		}
	}
	if !strings.Contains(msg.String(), "exceeds") && !strings.Contains(msg.String(), "cap") {
		t.Errorf("error message %q does not mention size cap", msg.String())
	}
}

// ---------------------------------------------------------------------------
// CRLF guards on user-supplied URL components (NOT on payload — wire bytes
// are sacred and CRLF in the payload is the entire point of this tool).
// ---------------------------------------------------------------------------

func TestFuzzRaw_RejectsCRLFInTargetAddrAndSNI(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)

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
				"target_addr": "127.0.0.1:9999",
				"positions": []map[string]any{
					{"path": "payload", "payloads": []string{"x"}},
				},
			}
			input[c.field] = c.value
			res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name:      "fuzz_raw",
				Arguments: input,
			})
			if res == nil || !res.IsError {
				t.Fatalf("expected error for %s=%q; got %+v", c.field, c.value, res)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Validation: override_bytes + patches mutually exclusive (mirrors resend_raw).
// ---------------------------------------------------------------------------

func TestFuzzRaw_RejectsOverrideAndPatchesTogether(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr":    "127.0.0.1:9999",
			"override_bytes": "y",
			"patches": []map[string]any{
				{"offset": 0, "data": "z"},
			},
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"x"}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected mutex error; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: duplicate position paths rejected (the per-variant payload
// map is keyed by path, so duplicates would silently lose substitutions
// while still expanding the cartesian product).
// ---------------------------------------------------------------------------

func TestFuzzRaw_RejectsDuplicatePositionPaths(t *testing.T) {
	cs, _, _, _ := setupFuzzRawSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"a"}},
				{"path": "payload", "payloads": []string{"b"}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for duplicate position path; got %+v", res)
	}
	var msg strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			msg.WriteString(tc.Text)
		}
	}
	if !strings.Contains(msg.String(), "duplicate path") {
		t.Errorf("error message %q does not mention duplicate path", msg.String())
	}
}

// ---------------------------------------------------------------------------
// Non-raw flow_id is rejected with an explicit pointer to the right tool.
// ---------------------------------------------------------------------------

func TestFuzzRaw_RejectsNonRawFlowID(t *testing.T) {
	cs, store, _, _ := setupFuzzRawSession(t)
	streamID := "http-stream-" + nowSuffix()
	if err := store.SaveStream(context.Background(), &flow.Stream{
		ID: streamID, Protocol: "http", State: "complete", Timestamp: time.Now(),
	}); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_raw",
		Arguments: map[string]any{
			"flow_id":     streamID,
			"target_addr": "127.0.0.1:9999",
			"positions": []map[string]any{
				{"path": "payload", "payloads": []string{"x"}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for non-raw flow_id; got %+v", res)
	}
}
