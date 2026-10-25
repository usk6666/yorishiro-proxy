//go:build e2e && !e2e_smoke

package mcp

// stream_error_tag_integration_test.go — USK-1350 coverage: a Stream
// created by resend_* / fuzz_* that ends in error must carry the error
// text in tags["error"] (capped by flow.TruncateErrorTag), exactly like
// the live data path's OnComplete hook does. Successfully completed
// Streams must carry no tags["error"].
//
// Every test drives the real MCP tool. Refused-dial fixtures use a
// loopback port that was bound and immediately closed.

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// closedLoopbackAddr returns a 127.0.0.1 address with nothing listening,
// so a dial to it is refused.
func closedLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return addr
}

// startReadThenCloseServer accepts connections, reads one chunk of the
// request, and closes the connection without writing any response.
func startReadThenCloseServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				buf := make([]byte, 8192)
				_, _ = c.Read(buf)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// getStream fetches streamID, failing the test on a miss.
func getStream(t *testing.T, store flow.Store, streamID string) *flow.Stream {
	t.Helper()
	st, err := store.GetStream(context.Background(), streamID)
	if err != nil || st == nil {
		t.Fatalf("GetStream(%s): stream=%v err=%v", streamID, st, err)
	}
	return st
}

// assertErrorTagged checks st is State="error" with a non-empty
// tags["error"] that contains wantSubstr, and returns the tag value.
func assertErrorTagged(t *testing.T, st *flow.Stream, wantSubstr string) string {
	t.Helper()
	if st.State != "error" {
		t.Errorf("Stream %s State = %q, want error", st.ID, st.State)
	}
	tag, ok := st.Tags["error"]
	if !ok || tag == "" {
		t.Fatalf("Stream %s tags[\"error\"] missing (tags=%v); want the error text (USK-1350)", st.ID, st.Tags)
	}
	if len(tag) > flow.ErrorTagMaxLen {
		t.Errorf("Stream %s len(tags[\"error\"]) = %d, want <= %d", st.ID, len(tag), flow.ErrorTagMaxLen)
	}
	if wantSubstr != "" && !strings.Contains(tag, wantSubstr) {
		t.Errorf("Stream %s tags[\"error\"] = %q, want it to contain %q", st.ID, tag, wantSubstr)
	}
	return tag
}

// assertNoErrorTag checks st completed normally without tags["error"].
func assertNoErrorTag(t *testing.T, st *flow.Stream) {
	t.Helper()
	if st.State != "complete" {
		t.Errorf("Stream %s State = %q, want complete", st.ID, st.State)
	}
	if v, ok := st.Tags["error"]; ok {
		t.Errorf("Stream %s tags[\"error\"] = %q present on a successful Stream; want absent", st.ID, v)
	}
}

// TestResendHTTP_RefusedDial_RecordsErrorTag reproduces the report: a
// resend_http to a refused port must leave the dial error text on the
// Stream, as the live path does.
func TestResendHTTP_RefusedDial_RecordsErrorTag(t *testing.T) {
	cs, store, _, _ := setupResendHTTPSession(t)
	addr := closedLoopbackAddr(t)

	res := callResendHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": addr,
		"path":      "/",
		"headers": []map[string]any{
			{"name": "Host", "value": addr},
		},
		"timeout_ms": 5000,
	})
	if !res.IsError {
		t.Fatalf("expected refused dial to surface as IsError, got success")
	}
	toolErr := extractTextContent(res)

	st := getStream(t, store, findOriginStream(t, store, flow.OriginResend).ID)
	tag := assertErrorTagged(t, st, "refused")
	if !strings.Contains(toolErr, tag) {
		t.Errorf("tags[\"error\"] = %q is not a substring of the MCP error text %q", tag, toolErr)
	}
}

// TestResendTools_RefusedDial_RecordsErrorTag covers the remaining
// resend_* tools against a refused port.
func TestResendTools_RefusedDial_RecordsErrorTag(t *testing.T) {
	tests := []struct {
		name string
		// run calls the tool against addr and returns the tool result
		// and the store to inspect.
		run func(t *testing.T, addr string) (*gomcp.CallToolResult, flow.Store)
	}{
		{
			name: "resend_ws",
			run: func(t *testing.T, addr string) (*gomcp.CallToolResult, flow.Store) {
				cs, store, _, _ := setupResendWSSession(t)
				seedID := seedResendWSFlow(t, store, addr, false)
				return callResendWS(t, cs, map[string]any{
					"flow_id":    seedID,
					"opcode":     "text",
					"payload":    "x",
					"timeout_ms": 5000,
				}), store
			},
		},
		{
			name: "resend_grpc",
			run: func(t *testing.T, addr string) (*gomcp.CallToolResult, flow.Store) {
				cs, store, _, _ := setupResendGRPCSession(t)
				return callResendGRPC(t, cs, map[string]any{
					"target_addr": addr,
					"scheme":      "https",
					"service":     resendGRPCServiceName,
					"method":      resendGRPCMethodUnary,
					"messages": []map[string]any{
						{"payload": "x"},
					},
					"timeout_ms": 5000,
				}), store
			},
		},
		{
			name: "resend_raw",
			run: func(t *testing.T, addr string) (*gomcp.CallToolResult, flow.Store) {
				cs, store, _ := setupResendRawSession(t)
				seedID := seedRawStream(t, store, []byte("ping"))
				res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
					Name: "resend_raw",
					Arguments: map[string]any{
						"flow_id":     seedID,
						"target_addr": addr,
						"timeout_ms":  5000,
					},
				})
				if err != nil {
					t.Fatalf("CallTool resend_raw: %v", err)
				}
				return res, store
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := closedLoopbackAddr(t)
			res, store := tt.run(t, addr)
			if !res.IsError {
				t.Fatalf("expected refused dial to surface as IsError, got success")
			}
			toolErr := extractTextContent(res)

			st := getStream(t, store, findOriginStream(t, store, flow.OriginResend).ID)
			tag := assertErrorTagged(t, st, "refused")
			if !strings.Contains(toolErr, tag) {
				t.Errorf("tags[\"error\"] = %q is not a substring of the MCP error text %q", tag, toolErr)
			}
		})
	}
}

// TestFuzzTools_RefusedDial_RecordsErrorTagPerVariant: every fuzz
// variant Stream that failed to dial carries its own error text, equal
// to the capped row.Error.
func TestFuzzTools_RefusedDial_RecordsErrorTagPerVariant(t *testing.T) {
	type variant struct{ streamID, errText string }
	tests := []struct {
		name string
		run  func(t *testing.T, addr string) ([]variant, flow.Store)
	}{
		{
			name: "fuzz_http",
			run: func(t *testing.T, addr string) ([]variant, flow.Store) {
				cs, store, _, _ := setupFuzzHTTPSession(t)
				result := callFuzzHTTP(t, cs, map[string]any{
					"method":    "GET",
					"scheme":    "http",
					"authority": addr,
					"path":      "/seed",
					"headers": []map[string]any{
						{"name": "Host", "value": addr},
					},
					"positions": []map[string]any{
						{"path": "path", "payloads": []string{"/v1", "/v2"}},
					},
					"timeout_ms": 5000,
				})
				var out []variant
				for _, r := range result.Variants {
					out = append(out, variant{r.StreamID, r.Error})
				}
				return out, store
			},
		},
		{
			name: "fuzz_ws",
			run: func(t *testing.T, addr string) ([]variant, flow.Store) {
				cs, store, _, _ := setupFuzzWSSession(t)
				result := callFuzzWS(t, cs, map[string]any{
					"target_addr": addr,
					"scheme":      "ws",
					"path":        "/echo",
					"opcode":      "text",
					"positions": []map[string]any{
						{"path": "payload", "payloads": []string{"v1", "v2"}},
					},
					"timeout_ms": 5000,
				})
				var out []variant
				for _, r := range result.Variants {
					out = append(out, variant{r.StreamID, r.Error})
				}
				return out, store
			},
		},
		{
			name: "fuzz_grpc",
			run: func(t *testing.T, addr string) ([]variant, flow.Store) {
				cs, store, _ := setupFuzzGRPCSession(t)
				result := callFuzzGRPC(t, cs, map[string]any{
					"target_addr": addr,
					"scheme":      "https",
					"service":     fuzzGRPCServiceName,
					"method":      fuzzGRPCMethodUnary,
					"messages": []map[string]any{
						{"payload": "seed"},
					},
					"positions": []map[string]any{
						{"path": "messages[0].payload", "payloads": []string{"v1", "v2"}},
					},
					"timeout_ms": 5000,
				})
				var out []variant
				for _, r := range result.Variants {
					out = append(out, variant{r.StreamID, r.Error})
				}
				return out, store
			},
		},
		{
			name: "fuzz_raw",
			run: func(t *testing.T, addr string) ([]variant, flow.Store) {
				cs, store, _, _ := setupFuzzRawSession(t)
				result := callFuzzRaw(t, cs, map[string]any{
					"target_addr": addr,
					"positions": []map[string]any{
						{"path": "payload", "payloads": []string{"v1", "v2"}},
					},
					"timeout_ms": 5000,
				})
				var out []variant
				for _, r := range result.Variants {
					out = append(out, variant{r.StreamID, r.Error})
				}
				return out, store
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := closedLoopbackAddr(t)
			variants, store := tt.run(t, addr)
			if len(variants) != 2 {
				t.Fatalf("got %d variants, want 2", len(variants))
			}
			for i, v := range variants {
				if v.streamID == "" || v.errText == "" {
					t.Fatalf("variants[%d] stream_id=%q error=%q; want both set for a refused dial", i, v.streamID, v.errText)
				}
				st := getStream(t, store, v.streamID)
				tag := assertErrorTagged(t, st, "refused")
				if want := flow.TruncateErrorTag(v.errText); tag != want {
					t.Errorf("variants[%d] tags[\"error\"] = %q, want %q (TruncateErrorTag(row.Error))", i, tag, want)
				}
			}
		})
	}
}

// TestResendTools_Success_NoErrorTag is a guard: a normally completed
// resend / fuzz Stream must not carry tags["error"].
func TestResendTools_Success_NoErrorTag(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T) ([]string, flow.Store)
	}{
		{
			name: "resend_http",
			run: func(t *testing.T) ([]string, flow.Store) {
				cs, store, _, _ := setupResendHTTPSession(t)
				authority := startDelayedHTTPServer(t, 0)
				res := callResendHTTP(t, cs, map[string]any{
					"method":    "GET",
					"scheme":    "http",
					"authority": authority,
					"path":      "/",
					"headers": []map[string]any{
						{"name": "Host", "value": authority},
					},
					"timeout_ms": 5000,
				})
				if res.IsError {
					t.Fatalf("tool returned error: %s", extractTextContent(res))
				}
				var out resendHTTPResult
				decodeStructuredResult(t, res, &out)
				return []string{out.StreamID}, store
			},
		},
		{
			name: "resend_ws",
			run: func(t *testing.T) ([]string, flow.Store) {
				cs, store, _, _ := setupResendWSSession(t)
				addr := startDelayedWSEchoServer(t, 0)
				seedID := seedResendWSFlow(t, store, addr, false)
				res := callResendWS(t, cs, map[string]any{
					"flow_id":    seedID,
					"opcode":     "text",
					"payload":    "ok",
					"timeout_ms": 5000,
				})
				if res.IsError {
					t.Fatalf("tool returned error: %s", extractTextContent(res))
				}
				var out resendWSResult
				decodeStructuredResult(t, res, &out)
				return []string{out.StreamID}, store
			},
		},
		{
			name: "resend_grpc",
			run: func(t *testing.T) ([]string, flow.Store) {
				cs, store, _, _ := setupResendGRPCSession(t)
				addr, shutdown := startResendGRPCUpstream(t, &resendGRPCEchoServer{})
				t.Cleanup(shutdown)
				res := callResendGRPC(t, cs, map[string]any{
					"target_addr": addr,
					"scheme":      "https",
					"service":     resendGRPCServiceName,
					"method":      resendGRPCMethodUnary,
					"messages": []map[string]any{
						{"payload": "ok"},
					},
					"timeout_ms": 10000,
				})
				var out resendGRPCResult
				decodeResendGRPCResult(t, res, &out)
				return []string{out.StreamID}, store
			},
		},
		{
			name: "resend_raw",
			run: func(t *testing.T) ([]string, flow.Store) {
				cs, store, _ := setupResendRawSession(t)
				addr := startDelayedRawServer(t, 0)
				seedID := seedRawStream(t, store, []byte("ping"))
				out := callResendRaw(t, cs, map[string]any{
					"flow_id":     seedID,
					"target_addr": addr,
					"timeout_ms":  5000,
				})
				return []string{out.StreamID}, store
			},
		},
		{
			name: "fuzz_http",
			run: func(t *testing.T) ([]string, flow.Store) {
				cs, store, _, _ := setupFuzzHTTPSession(t)
				authority := startDelayedHTTPServer(t, 0)
				result := callFuzzHTTP(t, cs, map[string]any{
					"method":    "GET",
					"scheme":    "http",
					"authority": authority,
					"path":      "/seed",
					"headers": []map[string]any{
						{"name": "Host", "value": authority},
					},
					"positions": []map[string]any{
						{"path": "path", "payloads": []string{"/v1", "/v2"}},
					},
					"timeout_ms": 5000,
				})
				var ids []string
				for _, r := range result.Variants {
					ids = append(ids, r.StreamID)
				}
				return ids, store
			},
		},
		{
			name: "fuzz_ws",
			run: func(t *testing.T) ([]string, flow.Store) {
				cs, store, _, _ := setupFuzzWSSession(t)
				addr := startDelayedWSEchoServer(t, 0)
				result := callFuzzWS(t, cs, map[string]any{
					"target_addr": addr,
					"scheme":      "ws",
					"path":        "/echo",
					"opcode":      "text",
					"positions": []map[string]any{
						{"path": "payload", "payloads": []string{"v1", "v2"}},
					},
					"timeout_ms": 5000,
				})
				var ids []string
				for _, r := range result.Variants {
					ids = append(ids, r.StreamID)
				}
				return ids, store
			},
		},
		{
			name: "fuzz_grpc",
			run: func(t *testing.T) ([]string, flow.Store) {
				cs, store, _ := setupFuzzGRPCSession(t)
				addr, shutdown := startFuzzGRPCUpstream(t, &fuzzGRPCEchoServer{})
				t.Cleanup(shutdown)
				result := callFuzzGRPC(t, cs, map[string]any{
					"target_addr": addr,
					"scheme":      "https",
					"service":     fuzzGRPCServiceName,
					"method":      fuzzGRPCMethodUnary,
					"messages": []map[string]any{
						{"payload": "seed"},
					},
					"positions": []map[string]any{
						{"path": "messages[0].payload", "payloads": []string{"v1", "v2"}},
					},
					"timeout_ms": 10000,
				})
				var ids []string
				for _, r := range result.Variants {
					ids = append(ids, r.StreamID)
				}
				return ids, store
			},
		},
		{
			name: "fuzz_raw",
			run: func(t *testing.T) ([]string, flow.Store) {
				cs, store, _, _ := setupFuzzRawSession(t)
				addr := startDelayedRawServer(t, 0)
				result := callFuzzRaw(t, cs, map[string]any{
					"target_addr": addr,
					"positions": []map[string]any{
						{"path": "payload", "payloads": []string{"v1", "v2"}},
					},
					"timeout_ms": 5000,
				})
				var ids []string
				for _, r := range result.Variants {
					ids = append(ids, r.StreamID)
				}
				return ids, store
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, store := tt.run(t)
			if len(ids) == 0 {
				t.Fatalf("no Streams returned")
			}
			for _, id := range ids {
				if id == "" {
					t.Fatalf("empty stream_id in result")
				}
				assertNoErrorTag(t, getStream(t, store, id))
			}
		})
	}
}

// startWSUpgradeThenCloseServer completes the WebSocket upgrade, reads
// one client frame, and closes the connection without replying, so the
// resend_ws receive loop sees a bare io.EOF.
func startWSUpgradeThenCloseServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				r := bufio.NewReader(c)
				if _, err := http.ReadRequest(r); err != nil {
					return
				}
				resp := "HTTP/1.1 101 Switching Protocols\r\n" +
					"Upgrade: websocket\r\n" +
					"Connection: Upgrade\r\n" +
					"Sec-WebSocket-Accept: dummy-accept-key\r\n" +
					"\r\n"
				if _, err := c.Write([]byte(resp)); err != nil {
					return
				}
				_, _ = ws.ReadFrame(r)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// TestResendTools_UpstreamClosesWithoutResponse_RecordsErrorTag pins the
// io.EOF decision (USK-1350): an upstream that takes the request and
// closes without answering is a genuine pre-response failure. The tool
// reports IsError, so the Stream is State="error" with the cause in
// tags["error"] — the live path's "io.EOF → complete" carve-out
// deliberately does not apply to resend / fuzz.
//
// resend_ws is the case where a bare io.EOF reaches finalizeResendStream
// (wrapped as "upstream receive: EOF"). resend_http's HTTP/1.x layer
// already reclassifies the same close as an aborted StreamError, which
// is pinned alongside it.
func TestResendTools_UpstreamClosesWithoutResponse_RecordsErrorTag(t *testing.T) {
	tests := []struct {
		name       string
		wantSubstr string
		run        func(t *testing.T) (*gomcp.CallToolResult, flow.Store)
	}{
		{
			name:       "resend_ws_eof",
			wantSubstr: "EOF",
			run: func(t *testing.T) (*gomcp.CallToolResult, flow.Store) {
				cs, store, _, _ := setupResendWSSession(t)
				addr := startWSUpgradeThenCloseServer(t)
				seedID := seedResendWSFlow(t, store, addr, false)
				return callResendWS(t, cs, map[string]any{
					"flow_id":    seedID,
					"opcode":     "text",
					"payload":    "x",
					"timeout_ms": 5000,
				}), store
			},
		},
		{
			name:       "resend_http_aborted",
			wantSubstr: "closed the connection before sending a response",
			run: func(t *testing.T) (*gomcp.CallToolResult, flow.Store) {
				cs, store, _, _ := setupResendHTTPSession(t)
				addr := startReadThenCloseServer(t)
				return callResendHTTP(t, cs, map[string]any{
					"method":    "GET",
					"scheme":    "http",
					"authority": addr,
					"path":      "/",
					"headers": []map[string]any{
						{"name": "Host", "value": addr},
					},
					"timeout_ms": 5000,
				}), store
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, store := tt.run(t)
			if !res.IsError {
				t.Fatalf("expected no-response close to surface as IsError, got success")
			}
			st := getStream(t, store, findOriginStream(t, store, flow.OriginResend).ID)
			assertErrorTagged(t, st, tt.wantSubstr)
		})
	}
}
