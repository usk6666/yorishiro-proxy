//go:build e2e && !e2e_smoke

// USK-1393: a plugin DROP / RESPOND is recorded in the flow store. A
// DROP leaves a state=error Stream with blocked_by="plugin" plus the row
// of the envelope the plugin stopped; a RESPOND leaves the request and
// the plugin's synthesized response (metadata synthetic=true) with no
// blocked_by. Both carry the plugin identity tags plugin / plugin_hook /
// plugin_phase. Driven through the production wiring (mcpserver.Run +
// proxybuild) and observed only through the MCP query tool.
package mcptest_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// pluginOutcomeName is the plugin name pluginsConfigJSON registers; the
// plugin tag on a recorded Stream carries it.
const pluginOutcomeName = "smoke_header_injector"

// startPluginOutcomeHarness boots the production server with script
// loaded as a plugin and starts a proxy listener. The server log goes to
// a file at warn level and is checked by assertNoServerErrorLog when the
// test ends: recording a plugin outcome must not log a failed store write.
func startPluginOutcomeHarness(t *testing.T, script, upstreamProto string) (*mcptest.Harness, string) {
	t.Helper()
	path := writePluginScript(t, "plugin_outcome.star", script)
	logPath := filepath.Join(t.TempDir(), "server.log")
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON:    pluginsConfigJSON(t, path),
		UpstreamProto: upstreamProto,
		ExtraArgs:     []string{"-log-file", logPath},
		LogLevel:      "warn",
	})
	// Registered after StartHarness, so it runs before the harness stops.
	t.Cleanup(func() { assertNoServerErrorLog(t, logPath) })
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
	}
	return h, proxyAddr
}

// queryStreams returns the Streams `query flows` reports for filter.
func queryStreams(t *testing.T, h *mcptest.Harness, filter map[string]any) []map[string]any {
	t.Helper()
	args := map[string]any{"resource": "flows", "limit": 200}
	if filter != nil {
		args["filter"] = filter
	}
	res := h.MustOK(t, "query", args)
	raw, _ := res.Decoded["flows"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// waitStreams polls `query flows` with filter until ok accepts the result
// or the deadline passes, and returns the last result.
func waitStreams(t *testing.T, h *mcptest.Harness, filter map[string]any, ok func([]map[string]any) bool) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := queryStreams(t, h, filter)
		if ok(got) || time.Now().After(deadline) {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// queryStreamMessages returns the semantic messages of one Stream.
func queryStreamMessages(t *testing.T, h *mcptest.Harness, streamID string) []map[string]any {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "messages", "id": streamID})
	var out struct {
		Messages []map[string]any `json:"messages"`
	}
	if err := json.Unmarshal([]byte(res.Text), &out); err != nil {
		t.Fatalf("decode query(messages): %v (text=%q)", err, res.Text)
	}
	return out.Messages
}

func streamTag(s map[string]any, key string) string {
	tags, _ := s["tags"].(map[string]any)
	v, _ := tags[key].(string)
	return v
}

func msgMeta(m map[string]any, key string) string {
	md, _ := m["metadata"].(map[string]any)
	v, _ := md[key].(string)
	return v
}

func str(m map[string]any, key string) string {
	v, _ := m[key].(string)
	return v
}

// assertPluginStreamTags checks the plugin identity tags on a Stream.
func assertPluginStreamTags(t *testing.T, s map[string]any, hook, phase string) {
	t.Helper()
	want := map[string]string{"plugin": pluginOutcomeName, "plugin_hook": hook, "plugin_phase": phase}
	for k, v := range want {
		if got := streamTag(s, k); got != v {
			t.Errorf("Stream %v tags[%q] = %q, want %q (tags %v)", s["id"], k, got, v, s["tags"])
		}
	}
}

// assertPluginDropStream requires exactly n Streams of protocol with
// blocked_by=plugin, each in state=error with the plugin tags and a Send
// row; it returns them.
func assertPluginDropStream(t *testing.T, h *mcptest.Harness, protocol, hook, phase string, n int) []map[string]any {
	t.Helper()
	got := waitStreams(t, h, map[string]any{"blocked_by": "plugin", "protocol": protocol},
		func(s []map[string]any) bool { return len(s) >= n })
	if len(got) != n {
		t.Fatalf("query flows blocked_by=plugin protocol=%s: %d Streams, want %d (all Streams: %v)",
			protocol, len(got), n, queryStreams(t, h, nil))
	}
	for _, s := range got {
		if st := str(s, "state"); st != "error" {
			t.Errorf("Stream %v state = %q, want error", s["id"], st)
		}
		assertPluginStreamTags(t, s, hook, phase)
		var send int
		for _, m := range queryStreamMessages(t, h, str(s, "id")) {
			if str(m, "direction") == "send" {
				send++
			}
		}
		if send == 0 {
			t.Errorf("Stream %v records no Send message; want the envelope the plugin dropped", s["id"])
		}
	}
	return got
}

// assertRespondNotBlocked fails for a Stream carrying blocked_by.
func assertRespondNotBlocked(t *testing.T, s map[string]any) {
	t.Helper()
	if b := str(s, "blocked_by"); b != "" {
		t.Errorf("Stream %v blocked_by = %q, want none (RESPOND is not a block)", s["id"], b)
	}
}

// waitCompleteStream waits for the single Stream of protocol and returns
// it once its state is complete (or the last observation at the
// deadline).
func waitCompleteStream(t *testing.T, h *mcptest.Harness, protocol string) map[string]any {
	t.Helper()
	got := waitStreams(t, h, map[string]any{"protocol": protocol}, func(s []map[string]any) bool {
		return len(s) == 1 && str(s[0], "state") == "complete"
	})
	if len(got) != 1 {
		t.Fatalf("query flows protocol=%s: %d Streams, want 1 (all Streams: %v)", protocol, len(got), queryStreams(t, h, nil))
	}
	if st := str(got[0], "state"); st != "complete" {
		t.Errorf("Stream %v state = %q, want complete", got[0]["id"], st)
	}
	return got[0]
}

// findMessage returns the first message matching direction and pred.
func findMessage(msgs []map[string]any, direction string, pred func(map[string]any) bool) map[string]any {
	for _, m := range msgs {
		if str(m, "direction") == direction && pred(m) {
			return m
		}
	}
	return nil
}

// --- AC1: an HTTP request a plugin DROPped is recorded ---------------------

const pluginHTTPDropScript = `
def gate(msg, ctx):
    if msg["path"].startswith("/plugin-drop"):
        return action.DROP
    return None

register_hook("http", "on_request", gate, phase=%q)
`

// TestE2E_PluginDropHTTPRequest_RecordedBlockedByPlugin covers AC1 on
// HTTP/1.x (plain forward, pre_pipeline) and HTTP/2 (CONNECT + TLS h2,
// post_pipeline).
func TestE2E_PluginDropHTTPRequest_RecordedBlockedByPlugin(t *testing.T) {
	t.Run("h1", func(t *testing.T) {
		h, proxyAddr := startPluginOutcomeHarness(t, fmt.Sprintf(pluginHTTPDropScript, "pre_pipeline"), "")
		upstreamAddr, _ := startObservedUpstream(t)
		pURL, _ := url.Parse("http://" + proxyAddr)
		client := &http.Client{
			Transport: &http.Transport{Proxy: http.ProxyURL(pURL), DisableKeepAlives: true},
			Timeout:   2 * time.Second,
		}
		if resp, err := client.Get("http://" + upstreamAddr + "/plugin-drop"); err == nil {
			_ = resp.Body.Close()
			t.Fatalf("dropped request answered %d; want no response", resp.StatusCode)
		}
		got := assertPluginDropStream(t, h, "http", "http.on_request", "pre_pipeline", 1)
		msgs := queryStreamMessages(t, h, str(got[0], "id"))
		req := findMessage(msgs, "send", func(m map[string]any) bool { return str(m, "method") == "GET" })
		if req == nil || !strings.Contains(str(req, "url"), "/plugin-drop") {
			t.Errorf("messages = %v, want the dropped GET /plugin-drop", msgs)
		}
	})
	t.Run("h2", func(t *testing.T) {
		h, proxyAddr := startPluginOutcomeHarness(t, fmt.Sprintf(pluginHTTPDropScript, "post_pipeline"), "")
		upstreamAddr := startH2TLSUpstream(t)
		client := newH2TLSClientThroughProxy(t, proxyAddr, upstreamAddr)
		client.Timeout = 2 * time.Second
		if resp, err := client.Get("https://" + upstreamAddr + "/plugin-drop"); err == nil {
			_ = resp.Body.Close()
			t.Fatalf("dropped request answered %d; want no response", resp.StatusCode)
		}
		got := assertPluginDropStream(t, h, "http", "http.on_request", "post_pipeline", 1)
		msgs := queryStreamMessages(t, h, str(got[0], "id"))
		if findMessage(msgs, "send", func(m map[string]any) bool { return str(m, "method") == "GET" }) == nil {
			t.Errorf("messages = %v, want the semantic GET request row", msgs)
		}
	})
}

// --- AC3: a Send-side RESPOND's synthesized response is recorded ----------

const pluginHTTPRespondScript = `
def gate(msg, ctx):
    return action.RESPOND(status_code=418, headers=[("Content-Type", "text/plain")], body=b"plugin-says-no")

register_hook("http", "on_request", gate, phase=%q)
`

// assertSyntheticHTTPResponse checks the Stream holds the request and the
// plugin's 418 marked synthetic.
func assertSyntheticHTTPResponse(t *testing.T, h *mcptest.Harness, s map[string]any) {
	t.Helper()
	msgs := queryStreamMessages(t, h, str(s, "id"))
	if findMessage(msgs, "send", func(m map[string]any) bool { return str(m, "method") == "GET" }) == nil {
		t.Errorf("messages = %v, want the GET request row", msgs)
	}
	resp := findMessage(msgs, "receive", func(map[string]any) bool { return true })
	if resp == nil {
		t.Fatalf("messages = %v, want the plugin response row", msgs)
	}
	if code, _ := resp["status_code"].(float64); code != 418 {
		t.Errorf("response status_code = %v, want 418", resp["status_code"])
	}
	if got := msgMeta(resp, "synthetic"); got != "true" {
		t.Errorf("response metadata.synthetic = %q, want \"true\"", got)
	}
}

// TestE2E_PluginRespondHTTPRequest_RecordsSyntheticResponse covers AC3 on
// HTTP/1.x and HTTP/2.
func TestE2E_PluginRespondHTTPRequest_RecordsSyntheticResponse(t *testing.T) {
	t.Run("h1", func(t *testing.T) {
		h, proxyAddr := startPluginOutcomeHarness(t, fmt.Sprintf(pluginHTTPRespondScript, "pre_pipeline"), "")
		upstreamAddr, _ := startObservedUpstream(t)
		resp := proxiedGet(t, proxyHTTPClient(t, proxyAddr), "http://"+upstreamAddr+"/plugin-respond")
		if resp.statusCode != 418 {
			t.Fatalf("status = %d (err %v), want the plugin's 418", resp.statusCode, resp.err)
		}
		s := waitCompleteStream(t, h, "http")
		assertRespondNotBlocked(t, s)
		assertPluginStreamTags(t, s, "http.on_request", "pre_pipeline")
		assertSyntheticHTTPResponse(t, h, s)
	})
	t.Run("h2", func(t *testing.T) {
		h, proxyAddr := startPluginOutcomeHarness(t, fmt.Sprintf(pluginHTTPRespondScript, "post_pipeline"), "")
		upstreamAddr := startH2TLSUpstream(t)
		client := newH2TLSClientThroughProxy(t, proxyAddr, upstreamAddr)
		resp, err := client.Get("https://" + upstreamAddr + "/plugin-respond")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 418 {
			t.Fatalf("status = %d, want the plugin's 418", resp.StatusCode)
		}
		s := waitCompleteStream(t, h, "http")
		assertRespondNotBlocked(t, s)
		assertPluginStreamTags(t, s, "http.on_request", "post_pipeline")
		assertSyntheticHTTPResponse(t, h, s)
	})
}

const pluginGRPCRespondScript = `
def gate(msg, ctx):
    if not msg["service"]:
        return None
    return action.RESPOND_GRPC(status=7, message="denied by plugin")

register_hook("grpc", "on_start", gate)
register_hook("grpc-web", "on_start", gate)
`

// assertSyntheticGRPCEnd checks the Stream holds a Send Start and the
// plugin's synthesized End (grpc_status 7, synthetic=true).
func assertSyntheticGRPCEnd(t *testing.T, h *mcptest.Harness, s map[string]any) {
	t.Helper()
	msgs := queryStreamMessages(t, h, str(s, "id"))
	if findMessage(msgs, "send", func(m map[string]any) bool { return msgMeta(m, "grpc_event") == "start" }) == nil {
		t.Errorf("messages = %v, want the Send Start row", msgs)
	}
	end := findMessage(msgs, "receive", func(m map[string]any) bool { return msgMeta(m, "grpc_event") == "end" })
	if end == nil {
		t.Fatalf("messages = %v, want the synthesized End row", msgs)
	}
	if got := msgMeta(end, "grpc_status"); got != "7" {
		t.Errorf("End grpc_status = %q, want 7", got)
	}
	if got := msgMeta(end, "synthetic"); got != "true" {
		t.Errorf("End metadata.synthetic = %q, want \"true\"", got)
	}
}

// TestE2E_PluginRespondGRPCStart_RecordsSyntheticEnd covers AC3 for a
// Send-side RESPOND_GRPC on native gRPC and gRPC-Web (h1 and h2).
func TestE2E_PluginRespondGRPCStart_RecordsSyntheticEnd(t *testing.T) {
	t.Run("grpc", func(t *testing.T) {
		h, proxyAddr := startPluginOutcomeHarness(t, pluginGRPCRespondScript, "grpc")
		cc := dialGRPCThroughProxyAs(t, proxyAddr, grpcUpstreamHostPort(t, h.UpstreamTLS.URL), "")
		err := invokeEcho(cc, mcptest.GRPCSafetyEchoMethod)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("call err = %v, want PermissionDenied from the plugin", err)
		}
		_ = cc.Close()
		s := waitCompleteStream(t, h, "grpc")
		assertRespondNotBlocked(t, s)
		assertPluginStreamTags(t, s, "grpc.on_start", "pre_pipeline")
		assertSyntheticGRPCEnd(t, h, s)
	})
	t.Run("grpc-web h2", func(t *testing.T) {
		h, proxyAddr := startPluginOutcomeHarness(t, pluginGRPCRespondScript, "grpc-web")
		up := grpcUpstreamHostPort(t, h.UpstreamTLS.URL)
		resp, err := sendGRPCWebH2(proxyAddr, up, "", mcptest.GRPCWebSafetyEchoMethod, "application/grpc-web+proto",
			grpcweb.EncodeFrame(false, false, []byte("hi")))
		if err != nil {
			t.Fatalf("gRPC-Web call: %v", err)
		}
		if trailers, _ := grpcWebTrailerFrame(t, "application/grpc-web+proto", resp.body); trailers["grpc-status"] != "7" {
			t.Fatalf("trailers = %v, want grpc-status 7 from the plugin", trailers)
		}
		s := waitCompleteStream(t, h, "grpc-web")
		assertRespondNotBlocked(t, s)
		assertPluginStreamTags(t, s, "grpc-web.on_start", "pre_pipeline")
		assertSyntheticGRPCEnd(t, h, s)
	})
	t.Run("grpc-web h1", func(t *testing.T) {
		h, proxyAddr := startPluginOutcomeHarness(t, pluginGRPCRespondScript, "")
		upstreamAddr, _, _ := byteCountingHTTPUpstream(t)
		body := string(grpcweb.EncodeFrame(false, false, []byte("hi")))
		req := fmt.Sprintf("POST http://%s/pkg.Echo/Say HTTP/1.1\r\nHost: %s\r\nContent-Type: application/grpc-web\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			upstreamAddr, upstreamAddr, len(body), body)
		c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatalf("write request: %v", err)
		}
		var got bytes.Buffer
		_, _ = io.Copy(&got, c)
		_ = c.Close()
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(got.Bytes())), nil)
		if err != nil {
			t.Fatalf("client received %q, want an HTTP response: %v", got.Bytes(), err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if trailers, _ := grpcWebTrailerFrame(t, "application/grpc-web", respBody); trailers["grpc-status"] != "7" {
			t.Fatalf("trailers = %v, want grpc-status 7 from the plugin", trailers)
		}
		s := waitCompleteStream(t, h, "grpc-web")
		assertRespondNotBlocked(t, s)
		assertPluginStreamTags(t, s, "grpc-web.on_start", "pre_pipeline")
		assertSyntheticGRPCEnd(t, h, s)
	})
}

// --- AC4: response-side on_start RESPOND_GRPC / DROP ----------------------

const pluginGRPCResponseStartScript = `
def gate(msg, ctx):
    if msg["service"]:
        return None
    return %s

register_hook("grpc", "on_start", gate)
register_hook("grpc-web", "on_start", gate)
`

// callGRPCResponseStart drives one RPC whose response Start the plugin
// stops, and returns the harness. proto is "grpc" or "grpc-web".
func callGRPCResponseStart(t *testing.T, proto, ret string) *mcptest.Harness {
	t.Helper()
	h, proxyAddr := startPluginOutcomeHarness(t, fmt.Sprintf(pluginGRPCResponseStartScript, ret), proto)
	up := grpcUpstreamHostPort(t, h.UpstreamTLS.URL)
	if proto == "grpc" {
		cc := dialGRPCThroughProxyAs(t, proxyAddr, up, "")
		_ = invokeEcho(cc, mcptest.GRPCSafetyEchoMethod)
		_ = cc.Close()
		return h
	}
	_, _ = sendGRPCWebH2(proxyAddr, up, "", mcptest.GRPCWebSafetyEchoMethod, "application/grpc-web+proto",
		grpcweb.EncodeFrame(false, false, []byte("hi")))
	return h
}

// assertReceiveStartRecorded checks the upstream's response Start row.
func assertReceiveStartRecorded(t *testing.T, msgs []map[string]any) {
	t.Helper()
	if findMessage(msgs, "receive", func(m map[string]any) bool { return msgMeta(m, "grpc_event") == "start" }) == nil {
		t.Errorf("messages = %v, want the upstream's response Start row", msgs)
	}
}

// TestE2E_PluginGRPCResponseStart_Recorded covers AC4 on native gRPC and
// gRPC-Web over h2.
func TestE2E_PluginGRPCResponseStart_Recorded(t *testing.T) {
	for _, proto := range []string{"grpc", "grpc-web"} {
		t.Run(proto+"/respond", func(t *testing.T) {
			h := callGRPCResponseStart(t, proto, `action.RESPOND_GRPC(status=7, message="denied by plugin")`)
			s := waitCompleteStream(t, h, proto)
			assertRespondNotBlocked(t, s)
			assertPluginStreamTags(t, s, proto+".on_start", "pre_pipeline")
			msgs := queryStreamMessages(t, h, str(s, "id"))
			assertReceiveStartRecorded(t, msgs)
			end := findMessage(msgs, "receive", func(m map[string]any) bool { return msgMeta(m, "grpc_event") == "end" })
			if end == nil {
				t.Fatalf("messages = %v, want the synthesized End row", msgs)
			}
			if msgMeta(end, "grpc_status") != "7" || msgMeta(end, "synthetic") != "true" {
				t.Errorf("End metadata = %v, want grpc_status=7 synthetic=true", end["metadata"])
			}
		})
		t.Run(proto+"/drop", func(t *testing.T) {
			h := callGRPCResponseStart(t, proto, `action.DROP`)
			got := assertPluginDropStream(t, h, proto, proto+".on_start", "pre_pipeline", 1)
			assertReceiveStartRecorded(t, queryStreamMessages(t, h, str(got[0], "id")))
		})
	}
}

// --- D3: resend records the synthetic response exactly once --------------

const pluginResendRespondScript = `
def gate(msg, ctx):
    return action.RESPOND(status_code=418, body=b"resend-plugin")

register_hook("http", "on_request", gate, phase="post_pipeline")
`

// TestE2E_ResendHTTP_PluginRespondRecordedOnce pins that a post_pipeline
// plugin RESPOND on resend_http leaves its Stream with the request and
// exactly one synthetic response row. A second recording attempt of the
// same response collides with the first on the flows table's keys, so it
// shows up as a RecordStep "flow save failed" error in the server log
// rather than as a second row — the log is checked too.
func TestE2E_ResendHTTP_PluginRespondRecordedOnce(t *testing.T) {
	path := writePluginScript(t, "plugin_outcome.star", pluginResendRespondScript)
	logPath := filepath.Join(t.TempDir(), "server.log")
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: pluginsConfigJSON(t, path),
		ExtraArgs:  []string{"-log-file", logPath},
		LogLevel:   "warn", // assertNoServerErrorLog checks WARN lines too
	})
	upstreamAddr, _ := startObservedUpstream(t)
	res := h.MustOK(t, "resend_http", map[string]any{
		"method":     "GET",
		"scheme":     "http",
		"authority":  upstreamAddr,
		"path":       "/resend",
		"timeout_ms": 5000,
	})
	streamID, _ := res.Decoded["stream_id"].(string)
	if streamID == "" {
		t.Fatalf("resend_http stream_id is empty (result %s); want the recorded Stream", res.Text)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var msgs []map[string]any
	for ctx.Err() == nil {
		msgs = queryStreamMessages(t, h, streamID)
		if len(msgs) >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var recv int
	for _, m := range msgs {
		if str(m, "direction") != "receive" {
			continue
		}
		recv++
		if code, _ := m["status_code"].(float64); code != 418 || msgMeta(m, "synthetic") != "true" {
			t.Errorf("receive row = %v, want the plugin's 418 marked synthetic", m)
		}
	}
	if recv != 1 {
		t.Errorf("receive rows = %d, want exactly 1 (messages %v)", recv, msgs)
	}
	assertNoServerErrorLog(t, logPath)
}
