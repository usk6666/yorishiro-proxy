package mcp

// output_filter_resend_raw_macro_test.go — Output Filter coverage for the
// resend_raw response_bytes and macro run_macro kv_store return paths
// (USK-1276).
//
// Both tools return upstream-derived data to the AI agent. When
// safety_filter.output rules are configured, the copy handed to the
// agent must be masked, while the wire, the recorded flows and the
// macro engine's own KV Store keep the original bytes (CLAUDE.md MITM
// principle 7 / RFC-001 §3.7). Every test drives the real tool handler
// over an in-memory MCP session.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

const (
	usk1276CardNumber      = "4111111111111111"
	usk1276CardReplacement = "[CARD]"
)

// newUSK1276CardEngine builds an Output-only engine from the credit-card
// preset with a recognisable replacement, the same constructor the
// production wiring (mcpserver init) uses.
func newUSK1276CardEngine(t *testing.T) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{Preset: "credit-card", Action: "mask", Replacement: usk1276CardReplacement},
		},
	})
	if err != nil {
		t.Fatalf("safety.NewEngine: %v", err)
	}
	return engine
}

// newUSK1276Session connects an in-memory MCP client to a server built
// with the given store and (optional) safety engine.
func newUSK1276Session(t *testing.T, store flow.Store, engine *safety.Engine, doer httpDoer) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	var opts []ServerOption
	if engine != nil {
		opts = append(opts, WithSafetyEngine(engine))
	}
	s := newServer(ctx, nil, store, nil, opts...)
	if doer != nil {
		s.jobRunner.replayDoer = doer
	}
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "usk1276-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// startUSK1276RawUpstream starts a one-shot loopback TCP server that
// reads the request, writes resp verbatim and closes. Shape mirrors the
// startTCPEcho helper in resend_raw_integration_test.go (e2e-tagged, so
// not reachable from this untagged file).
func startUSK1276RawUpstream(t *testing.T, resp []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, rerr := conn.Read(buf); rerr != nil {
			return
		}
		_, _ = conn.Write(resp)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		// Drain until the client closes so the close is graceful.
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, conn)
	}()
	return ln.Addr().String()
}

// seedUSK1276RawStream records a raw Stream + Send Flow so resend_raw can
// recover the payload via flow_id. Copies the seedRawStream shape from
// resend_raw_integration_test.go.
func seedUSK1276RawStream(t *testing.T, store flow.Store, payload []byte) string {
	t.Helper()
	streamID := "usk1276-raw-" + time.Now().Format("150405.000000000")
	now := time.Now()
	if err := store.SaveStream(context.Background(), &flow.Stream{
		ID:        streamID,
		Protocol:  "raw",
		State:     "complete",
		Timestamp: now,
		ConnID:    "conn-" + streamID,
	}); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if err := store.SaveFlow(context.Background(), &flow.Flow{
		ID:        "send-" + streamID,
		StreamID:  streamID,
		Sequence:  0,
		Direction: "send",
		Timestamp: now,
		Body:      payload,
		RawBytes:  payload,
		URL:       &url.URL{},
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	return streamID
}

// runUSK1276ResendRaw seeds a raw flow, points resend_raw at a loopback
// upstream that answers with resp, and returns the decoded result.
func runUSK1276ResendRaw(t *testing.T, store flow.Store, engine *safety.Engine, resp []byte) *resendRawTypedResult {
	t.Helper()
	addr := startUSK1276RawUpstream(t, resp)
	streamID := seedUSK1276RawStream(t, store, []byte("GET / HTTP/1.1\r\nHost: target\r\n\r\n"))
	cs := newUSK1276Session(t, store, engine, nil)

	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_raw",
		Arguments: map[string]any{
			"flow_id":     streamID,
			"target_addr": addr,
			"timeout_ms":  5000,
		},
	})
	if err != nil {
		t.Fatalf("CallTool resend_raw: %v", err)
	}
	if res.IsError {
		t.Fatalf("resend_raw returned error: %s", outputTextContent(res))
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

func decodeUSK1276ResponseBytes(t *testing.T, r *resendRawTypedResult) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(r.ResponseBytes)
	if err != nil {
		t.Fatalf("response_bytes is not base64: %v", err)
	}
	return b
}

// R1 + R3: response_bytes is masked; response_size keeps the wire length.
func TestResendRaw_OutputFilter_MasksResponseBytes(t *testing.T) {
	store := newTestStore(t)
	wire := []byte("HTTP/1.1 200 OK\r\n\r\ncard=" + usk1276CardNumber)
	out := runUSK1276ResendRaw(t, store, newUSK1276CardEngine(t), wire)

	got := decodeUSK1276ResponseBytes(t, out)
	if bytes.Contains(got, []byte(usk1276CardNumber)) {
		t.Errorf("response_bytes leaks the card number to the agent: %q", got)
	}
	if !bytes.Contains(got, []byte(usk1276CardReplacement)) {
		t.Errorf("response_bytes missing mask replacement %q: %q", usk1276CardReplacement, got)
	}
	if out.ResponseSize != len(wire) {
		t.Errorf("response_size = %d, want wire length %d (pre-mask)", out.ResponseSize, len(wire))
	}
}

// R2: the recorded receive chunks keep the cleartext wire bytes.
func TestResendRaw_OutputFilter_RecordedChunksUnmasked(t *testing.T) {
	store := newTestStore(t)
	wire := []byte("HTTP/1.1 200 OK\r\n\r\ncard=" + usk1276CardNumber)
	out := runUSK1276ResendRaw(t, store, newUSK1276CardEngine(t), wire)

	recv, err := store.GetFlows(context.Background(), out.StreamID, flow.FlowListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	if len(recv) == 0 {
		t.Fatal("no receive flows recorded for the resend stream")
	}
	var rawConcat, bodyConcat []byte
	for _, f := range recv {
		rawConcat = append(rawConcat, f.RawBytes...)
		bodyConcat = append(bodyConcat, f.Body...)
	}
	if !bytes.Equal(rawConcat, wire) {
		t.Errorf("recorded receive RawBytes = %q, want wire bytes %q", rawConcat, wire)
	}
	if bytes.Contains(rawConcat, []byte(usk1276CardReplacement)) || bytes.Contains(bodyConcat, []byte(usk1276CardReplacement)) {
		t.Errorf("Output Filter mask leaked into recorded flows: raw=%q body=%q", rawConcat, bodyConcat)
	}
}

// R4: without an engine response_bytes is byte-identical, binary included.
func TestResendRaw_OutputFilter_NoEngineByteIdentical(t *testing.T) {
	store := newTestStore(t)
	wire := append([]byte{0x00, 0xff, 0xfe, 0x80, ' '}, []byte(usk1276CardNumber)...)
	out := runUSK1276ResendRaw(t, store, nil, wire)

	got := decodeUSK1276ResponseBytes(t, out)
	if !bytes.Equal(got, wire) {
		t.Errorf("response_bytes = %q, want byte-identical %q", got, wire)
	}
	if out.ResponseSize != len(wire) {
		t.Errorf("response_size = %d, want %d", out.ResponseSize, len(wire))
	}
}

// usk1276MacroFixture is a two-step macro against an httptest upstream:
// step "login" returns {"email":"alice@example.com"} and extracts it;
// step "use" sends override_body "e=§email§" and the upstream captures it.
type usk1276MacroFixture struct {
	store    flow.Store
	cs       *gomcp.ClientSession
	mu       sync.Mutex
	useBody  string
	loginSID string
	useSID   string
}

func (f *usk1276MacroFixture) capturedUseBody() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.useBody
}

func newUSK1276MacroFixture(t *testing.T, engine *safety.Engine) *usk1276MacroFixture {
	t.Helper()
	f := &usk1276MacroFixture{store: newTestStore(t)}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"email":"alice@example.com"}`))
		case "/use":
			b, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.useBody = string(b)
			f.mu.Unlock()
			_, _ = w.Write([]byte("ok"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(upstream.Close)

	ctx := context.Background()
	seed := func(path, method string) string {
		u, _ := url.Parse(upstream.URL + path)
		st := &flow.Stream{Protocol: "HTTP/1.x", State: "complete", Timestamp: time.Now().UTC()}
		if err := f.store.SaveStream(ctx, st); err != nil {
			t.Fatalf("SaveStream: %v", err)
		}
		if err := f.store.SaveFlow(ctx, &flow.Flow{
			StreamID:  st.ID,
			Sequence:  0,
			Direction: "send",
			Timestamp: time.Now().UTC(),
			Method:    method,
			URL:       u,
			Headers:   map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
		}); err != nil {
			t.Fatalf("SaveFlow: %v", err)
		}
		return st.ID
	}
	f.loginSID = seed("/login", "GET")
	f.useSID = seed("/use", "POST")
	f.cs = newUSK1276Session(t, f.store, engine, newPermissiveClient())

	def := callMacro(t, f.cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "usk1276",
			"initial_vars": map[string]any{
				"contact":         "carol@example.com",
				"bob@example.com": "plain",
			},
			"steps": []any{
				map[string]any{
					"id":      "login",
					"flow_id": f.loginSID,
					"extract": []any{
						map[string]any{
							"name":      "email",
							"from":      "response",
							"source":    "body_json",
							"json_path": "$.email",
						},
					},
				},
				map[string]any{
					"id":            "use",
					"flow_id":       f.useSID,
					"override_body": "e=§email§",
				},
			},
		},
	})
	if def.IsError {
		t.Fatalf("define_macro failed: %s", outputTextContent(def))
	}
	return f
}

func (f *usk1276MacroFixture) run(t *testing.T) macroRunMacroResult {
	t.Helper()
	res := callMacro(t, f.cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{"name": "usk1276"},
	})
	if res.IsError {
		t.Fatalf("run_macro failed: %s", outputTextContent(res))
	}
	var out macroRunMacroResult
	unmarshalExecuteResult(t, res, &out)
	if out.Status != "completed" {
		t.Fatalf("run_macro status = %q (error %q), want completed", out.Status, out.Error)
	}
	return out
}

// M1 + M4 (keys) + decision 10 (initial_vars values): kv_store values are
// masked in the returned copy; keys are never masked.
func TestRunMacro_OutputFilter_MasksKVStoreValues(t *testing.T) {
	f := newUSK1276MacroFixture(t, newOutputMaskingSafetyEngine(t))
	out := f.run(t)

	if got := out.KVStore["email"]; got != "[EMAIL_REDACTED]" {
		t.Errorf("kv_store[email] = %q, want %q", got, "[EMAIL_REDACTED]")
	}
	if got := out.KVStore["contact"]; got != "[EMAIL_REDACTED]" {
		t.Errorf("kv_store[contact] = %q, want %q (initial_vars values are masked too)", got, "[EMAIL_REDACTED]")
	}
	if got, ok := out.KVStore["bob@example.com"]; !ok || got != "plain" {
		t.Errorf("kv_store[bob@example.com] = %q (present=%v), want key unmasked with value %q", got, ok, "plain")
	}
	for k, v := range out.KVStore {
		if strings.Contains(v, "alice@example.com") || strings.Contains(v, "carol@example.com") {
			t.Errorf("kv_store[%s] leaks cleartext email: %q", k, v)
		}
	}
}

// M2 + M3: macro-internal values and recorded flows keep the cleartext.
func TestRunMacro_OutputFilter_InternalValuesAndRecordingUnmasked(t *testing.T) {
	f := newUSK1276MacroFixture(t, newOutputMaskingSafetyEngine(t))
	f.run(t)

	if got := f.capturedUseBody(); got != "e=alice@example.com" {
		t.Errorf("step 2 wire body = %q, want %q (later steps must receive the original value)", got, "e=alice@example.com")
	}

	ctx := context.Background()
	streams, err := f.store.ListStreams(ctx, flow.StreamListOptions{Limit: 100})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	var loginStream string
	for _, st := range streams {
		if st.Tags["macro"] == "usk1276" && st.Tags["macro_step"] == "login" {
			loginStream = st.ID
		}
	}
	if loginStream == "" {
		t.Fatal("no recorded stream for macro step login")
	}
	recv, err := f.store.GetFlows(ctx, loginStream, flow.FlowListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	if len(recv) != 1 {
		t.Fatalf("receive flows = %d, want 1", len(recv))
	}
	if !strings.Contains(string(recv[0].Body), "alice@example.com") {
		t.Errorf("recorded login response body = %q, want cleartext email", recv[0].Body)
	}
}

// M4 (no engine): kv_store is returned exactly.
func TestRunMacro_OutputFilter_NoEngineExact(t *testing.T) {
	f := newUSK1276MacroFixture(t, nil)
	out := f.run(t)

	want := map[string]string{
		"email":           "alice@example.com",
		"contact":         "carol@example.com",
		"bob@example.com": "plain",
	}
	if len(out.KVStore) != len(want) {
		t.Errorf("kv_store = %v, want %v", out.KVStore, want)
	}
	for k, v := range want {
		if out.KVStore[k] != v {
			t.Errorf("kv_store[%s] = %q, want %q", k, out.KVStore[k], v)
		}
	}
}
