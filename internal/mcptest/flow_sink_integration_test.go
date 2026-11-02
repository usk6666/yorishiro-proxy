//go:build e2e && !e2e_smoke

package mcptest_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	wslayer "github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// USK-1119: flow sink end-to-end. A harness booted with a flow_sink
// config streams every committed record into <dir>/flows.jsonl; these
// tests drive real traffic and MCP tools and compare the sink lines with
// the stored records (read back through manage export_flows, whose lines
// are built by the same converter from the SQLite rows).

// flowSinkConfigJSON returns a ConfigJSON document with a flow_sink in a
// fresh directory, plus that directory. extra is merged into the
// flow_sink object.
func flowSinkConfigJSON(t *testing.T, extra map[string]any) (string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sink")
	sink := map[string]any{"dir": dir}
	for k, v := range extra {
		sink[k] = v
	}
	b, err := json.Marshal(map[string]any{"flow_sink": sink})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	return string(b), dir
}

// readSinkDir reads every sink line in consumption order (rotated files
// by name, then flows.jsonl).
func readSinkDir(t *testing.T, dir string) []*flow.ExportRecord {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, "flows-*.jsonl"))
	sort.Strings(files)
	files = append(files, filepath.Join(dir, "flows.jsonl"))
	var out []*flow.ExportRecord
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", f, err)
		}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64*1024), 64<<20)
		for sc.Scan() {
			var rec flow.ExportRecord
			if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
				// The active file may end in a line still being written.
				break
			}
			out = append(out, &rec)
		}
	}
	return out
}

// sinkLinesForStream returns the lines of one stream, in order.
func sinkLinesForStream(recs []*flow.ExportRecord, id string) []*flow.ExportRecord {
	var out []*flow.ExportRecord
	for _, r := range recs {
		if r.Stream != nil && r.Stream.ID == id {
			out = append(out, r)
		}
	}
	return out
}

// waitSink polls the sink directory until pred holds.
func waitSink(t *testing.T, dir, what string, pred func([]*flow.ExportRecord) bool) []*flow.ExportRecord {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		recs := readSinkDir(t, dir)
		if pred(recs) {
			return recs
		}
		if time.Now().After(deadline) {
			t.Fatalf("flow sink in %s: %s not observed within 15s (%d lines)", dir, what, len(recs))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// exportedRecords exports every stream as JSONL through manage
// export_flows and returns the records by stream ID.
func exportedRecords(t *testing.T, h *mcptest.Harness, name string) map[string]*flow.ExportRecord {
	t.Helper()
	h.MustOK(t, "manage", map[string]any{
		"action": "export_flows",
		"params": map[string]any{"format": "jsonl", "output_path": name, "include_bodies": true},
	})
	data, err := os.ReadFile(filepath.Join(h.ExportDir, name))
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	out := map[string]*flow.ExportRecord{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 64<<20)
	for sc.Scan() {
		var rec flow.ExportRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("export line: %v", err)
		}
		out[rec.Stream.ID] = &rec
	}
	return out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// assertSinkMatchesStore checks one stream's sink lines against the
// stored record: the first line is stream_created, every stored flow
// appears exactly once as a flow_saved line equal to the stored flow,
// sends precede their receives, and the last line's snapshot equals the
// stored stream (state complete).
func assertSinkMatchesStore(t *testing.T, label string, lines []*flow.ExportRecord, stored *flow.ExportRecord) {
	t.Helper()
	if len(lines) == 0 {
		t.Fatalf("%s: no sink lines", label)
	}
	if lines[0].Event != string(flow.SinkEventStreamCreated) {
		t.Errorf("%s: first line event = %q, want stream_created", label, lines[0].Event)
	}
	seen := map[string]int{} // flow ID → line index
	for i, l := range lines {
		if l.Event != string(flow.SinkEventFlowSaved) {
			continue
		}
		if len(l.Flows) != 1 {
			t.Fatalf("%s: flow_saved line carries %d flows", label, len(l.Flows))
		}
		if _, dup := seen[l.Flows[0].ID]; dup {
			t.Errorf("%s: flow %s emitted twice", label, l.Flows[0].ID)
		}
		seen[l.Flows[0].ID] = i
	}
	if len(seen) != len(stored.Flows) {
		t.Errorf("%s: sink has %d flows, store has %d", label, len(seen), len(stored.Flows))
	}
	firstSend, firstRecv := -1, -1
	for _, sf := range stored.Flows {
		idx, ok := seen[sf.ID]
		if !ok {
			t.Errorf("%s: stored flow %s (%s seq %d) missing from sink", label, sf.ID, sf.Direction, sf.Sequence)
			continue
		}
		if got, want := mustJSON(t, lines[idx].Flows[0]), mustJSON(t, sf); got != want {
			t.Errorf("%s: sink flow %s =\n%s\nwant stored\n%s", label, sf.ID, got, want)
		}
		if sf.Direction == "send" && (firstSend < 0 || idx < firstSend) {
			firstSend = idx
		}
		if sf.Direction == "receive" && (firstRecv < 0 || idx < firstRecv) {
			firstRecv = idx
		}
	}
	if firstSend < 0 || firstRecv < 0 || firstSend > firstRecv {
		t.Errorf("%s: first send line %d, first receive line %d; want send before receive", label, firstSend, firstRecv)
	}
	last := lines[len(lines)-1]
	if last.Stream.State != "complete" {
		t.Errorf("%s: last line state = %q, want complete", label, last.Stream.State)
	}
	if got, want := mustJSON(t, last.Stream), mustJSON(t, stored.Stream); got != want {
		t.Errorf("%s: last sink snapshot =\n%s\nwant stored\n%s", label, got, want)
	}
}

// assertQueryAgrees cross-checks the sink's flows against the MCP query
// view of the same stream (protocol, and each message's body).
func assertQueryAgrees(t *testing.T, h *mcptest.Harness, label, id string, lines []*flow.ExportRecord) {
	t.Helper()
	fl := queryFlowDecoded(t, h, id)
	if p, _ := fl["protocol"].(string); p != lines[len(lines)-1].Stream.Protocol {
		t.Errorf("%s: query protocol %q != sink protocol %q", label, p, lines[len(lines)-1].Stream.Protocol)
	}
	msgs := h.MustOK(t, "query", map[string]any{"resource": "messages", "id": id, "limit": 1000}).Decoded
	list, _ := msgs["messages"].([]any)
	bodies := map[string]string{}
	for _, m := range list {
		e, _ := m.(map[string]any)
		mid, _ := e["id"].(string)
		body, _ := e["body"].(string)
		if enc, _ := e["body_encoding"].(string); enc == "base64" {
			b, _ := base64.StdEncoding.DecodeString(body)
			body = string(b)
		}
		bodies[mid] = body
	}
	for _, l := range lines {
		if l.Event != string(flow.SinkEventFlowSaved) {
			continue
		}
		f := l.Flows[0]
		want, ok := bodies[f.ID]
		if !ok {
			t.Errorf("%s: sink flow %s not listed by query messages", label, f.ID)
			continue
		}
		got, _ := base64.StdEncoding.DecodeString(f.Body)
		if string(got) != want {
			t.Errorf("%s: flow %s body sink=%q query=%q", label, f.ID, got, want)
		}
	}
}

// --- Test Plan #11 ---------------------------------------------------------

// TestE2E_FlowSink_HTTPHTTPSWSRecordsMatchStore: plain HTTP, HTTPS (CONNECT
// + MITM) and WebSocket traffic through a sink-configured proxy produce,
// per stream, stream_created → send → receive → complete lines equal to
// the stored records, including bodies and raw bytes.
func TestE2E_FlowSink_HTTPHTTPSWSRecordsMatchStore(t *testing.T) {
	cfg, sinkDir := flowSinkConfigJSON(t, nil)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{UpstreamProto: "ws", ConfigJSON: cfg})
	proxyAddr := startProxyWithPassthrough(t, h)

	// Plain HTTP.
	httpAddr, _ := startObservedUpstream(t)
	r := <-requestThroughProxy(t, proxyHTTPClient(t, proxyAddr), "POST", "http://"+httpAddr+"/sink-plain", nil, []byte("plain-body"))
	if r.err != nil || r.statusCode != 200 {
		t.Fatalf("plain HTTP: status %d err %v", r.statusCode, r.err)
	}
	// HTTPS.
	httpsAddr := startH1TLSUpstream(t)
	resp, err := newH1TLSClientThroughProxy(t, proxyAddr).Post("https://"+httpsAddr+"/sink-tls", "text/plain", strings.NewReader("tls-body"))
	if err != nil {
		t.Fatalf("HTTPS: %v", err)
	}
	_ = resp.Body.Close()
	// WebSocket.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := dialWSThroughProxy(ctx, t, proxyAddr, wsUpstreamHostPort(t, h.UpstreamTLS.URL))
	if err != nil {
		t.Fatalf("dial WS: %v", err)
	}
	if err := writeMaskedClientFrame(conn, wslayer.OpcodeText, []byte("ws-frame")); err != nil {
		t.Fatalf("write frame: %v", err)
	}
	if _, err := readServerFrameWithDeadline(conn, 5*time.Second); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	_ = writeMaskedClientFrame(conn, wslayer.OpcodeClose, []byte{0x03, 0xe8})
	_, _ = readServerFrameWithDeadline(conn, 5*time.Second)
	_ = conn.Close()

	ids := map[string]string{
		"http":  waitCompleteStreamID(t, h, map[string]any{"url_pattern": "/sink-plain"}),
		"https": waitCompleteStreamID(t, h, map[string]any{"url_pattern": "/sink-tls"}),
		"ws":    waitCompleteStreamID(t, h, map[string]any{"url_pattern": "/ws"}),
	}
	stored := exportedRecords(t, h, "sink-oracle.jsonl")

	recs := waitSink(t, sinkDir, "every stored flow of the three streams", func(recs []*flow.ExportRecord) bool {
		for _, id := range ids {
			lines := sinkLinesForStream(recs, id)
			n := 0
			for _, l := range lines {
				if l.Event == string(flow.SinkEventFlowSaved) {
					n++
				}
			}
			st := stored[id]
			if st == nil || n < len(st.Flows) || len(lines) == 0 || lines[len(lines)-1].Stream.State != "complete" {
				return false
			}
		}
		return true
	})

	runID := recs[0].RunID
	for i, r := range recs {
		if r.RunID != runID || r.Version != "1" || r.Seq == 0 {
			t.Errorf("line %d: run_id %q version %q seq %d", i, r.RunID, r.Version, r.Seq)
		}
		if i > 0 && r.Seq <= recs[i-1].Seq {
			t.Errorf("line %d: seq %d not increasing after %d", i, r.Seq, recs[i-1].Seq)
		}
	}
	for label, id := range ids {
		lines := sinkLinesForStream(recs, id)
		assertSinkMatchesStore(t, label, lines, stored[id])
		assertQueryAgrees(t, h, label, id, lines)
		raw := false
		for _, l := range lines {
			if l.Event == string(flow.SinkEventFlowSaved) && l.Flows[0].RawBytes != "" {
				raw = true
			}
		}
		if !raw {
			t.Errorf("%s: no sink flow carries raw_bytes", label)
		}
	}
	if p := stored[ids["ws"]].Stream.Protocol; p != "ws" {
		t.Errorf("ws stream protocol = %q, want ws", p)
	}
}

// --- Test Plan #12 ---------------------------------------------------------

// TestE2E_FlowSink_ResendAndFuzzRecordsStreamed: records written by the
// resend_http and fuzz_http MCP tools reach the sink with their origin.
func TestE2E_FlowSink_ResendAndFuzzRecordsStreamed(t *testing.T) {
	cfg, sinkDir := flowSinkConfigJSON(t, nil)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: cfg})
	proxyAddr := startProxyWithPassthrough(t, h)
	upstream, _ := startObservedUpstream(t)
	r := <-requestThroughProxy(t, proxyHTTPClient(t, proxyAddr), "GET", "http://"+upstream+"/sink-seed", nil, nil)
	if r.err != nil {
		t.Fatalf("seed request: %v", r.err)
	}
	seed := waitCompleteStreamID(t, h, map[string]any{"url_pattern": "/sink-seed"})

	h.MustOK(t, "resend_http", map[string]any{"flow_id": seed, "path": "/sink-resent"})
	h.MustOK(t, "fuzz_http", map[string]any{
		"flow_id":    seed,
		"positions":  []map[string]any{{"path": "path", "payloads": []string{"/sink-fuzz-a", "/sink-fuzz-b"}}},
		"timeout_ms": 10000,
	})

	byOrigin := func(recs []*flow.ExportRecord) map[string]map[string]bool {
		out := map[string]map[string]bool{}
		for _, r := range recs {
			if r.Event != string(flow.SinkEventFlowSaved) || r.Stream == nil {
				continue
			}
			if out[r.Stream.Origin] == nil {
				out[r.Stream.Origin] = map[string]bool{}
			}
			if f := r.Flows[0]; f.Direction == "send" {
				out[r.Stream.Origin][f.URL] = true
			}
		}
		return out
	}
	hasURL := func(m map[string]bool, suffix string) bool {
		for u := range m {
			if strings.HasSuffix(u, suffix) {
				return true
			}
		}
		return false
	}
	recs := waitSink(t, sinkDir, "resend and fuzz sends", func(recs []*flow.ExportRecord) bool {
		o := byOrigin(recs)
		return hasURL(o["resend"], "/sink-resent") && hasURL(o["fuzz"], "/sink-fuzz-a") && hasURL(o["fuzz"], "/sink-fuzz-b")
	})
	o := byOrigin(recs)
	if !hasURL(o["proxy"], "/sink-seed") {
		t.Errorf("proxy-origin seed send missing from sink: %v", o["proxy"])
	}
	stored := exportedRecords(t, h, "resend-oracle.jsonl")
	for _, r := range recs {
		if r.Event != string(flow.SinkEventFlowSaved) || (r.Stream.Origin != "resend" && r.Stream.Origin != "fuzz") {
			continue
		}
		st := stored[r.Stream.ID]
		if st == nil {
			t.Errorf("sink stream %s (%s) not in the store", r.Stream.ID, r.Stream.Origin)
			continue
		}
		found := false
		for _, sf := range st.Flows {
			if sf.ID == r.Flows[0].ID {
				found = true
				if got, want := mustJSON(t, r.Flows[0]), mustJSON(t, sf); got != want {
					t.Errorf("%s flow %s =\n%s\nwant stored\n%s", r.Stream.Origin, sf.ID, got, want)
				}
			}
		}
		if !found {
			t.Errorf("%s flow %s not in the store", r.Stream.Origin, r.Flows[0].ID)
		}
	}
}

// --- Test Plan #14 ---------------------------------------------------------

// TestE2E_FlowSink_MergeImportIntoSecondInstance: the sink file of one
// instance, imported with import_flows on_conflict=merge into a second
// instance, reproduces the original stream and flows.
func TestE2E_FlowSink_MergeImportIntoSecondInstance(t *testing.T) {
	cfg, sinkDir := flowSinkConfigJSON(t, nil)
	a := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: cfg})
	proxyAddr := startProxyWithPassthrough(t, a)
	upstream, _ := startObservedUpstream(t)
	r := <-requestThroughProxy(t, proxyHTTPClient(t, proxyAddr), "POST", "http://"+upstream+"/sink-merge", nil, []byte("merge-body"))
	if r.err != nil {
		t.Fatalf("request: %v", r.err)
	}
	id := waitCompleteStreamID(t, a, map[string]any{"url_pattern": "/sink-merge"})
	want := exportedRecords(t, a, "a.jsonl")[id]
	waitSink(t, sinkDir, "the complete stream with its flows", func(recs []*flow.ExportRecord) bool {
		lines := sinkLinesForStream(recs, id)
		n := 0
		for _, l := range lines {
			if l.Event == string(flow.SinkEventFlowSaved) {
				n++
			}
		}
		return n == len(want.Flows) && len(lines) > 0 && lines[len(lines)-1].Stream.State == "complete"
	})

	var data []byte
	files, _ := filepath.Glob(filepath.Join(sinkDir, "flows-*.jsonl"))
	sort.Strings(files)
	for _, f := range append(files, filepath.Join(sinkDir, "flows.jsonl")) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		data = append(data, b...)
	}

	b := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	if err := os.WriteFile(filepath.Join(b.ExportDir, "from-sink.jsonl"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	for round := 1; round <= 2; round++ {
		res := b.MustOK(t, "manage", map[string]any{
			"action": "import_flows",
			"params": map[string]any{"input_path": "from-sink.jsonl", "on_conflict": "merge"},
		})
		if n := numFromAny(res.Decoded["errors"]); n != 0 {
			t.Fatalf("round %d import errors = %d: %s", round, n, res.Text)
		}
		got := exportedRecords(t, b, fmt.Sprintf("b-%d.jsonl", round))[id]
		if got == nil {
			t.Fatalf("round %d: stream %s not imported", round, id)
		}
		if g, w := mustJSON(t, got), mustJSON(t, want); g != w {
			t.Errorf("round %d: imported record =\n%s\nwant original\n%s", round, g, w)
		}
	}
}
