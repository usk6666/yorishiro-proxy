//go:build e2e && !e2e_smoke

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	"github.com/usk6666/yorishiro-proxy/internal/session"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// Intercept modify_and_forward body_patches on a request whose body was
// spilled to disk, driven end to end: a real FullListener (CONNECT + TLS
// MITM, HTTP/1.x or HTTP/2) with a lowered spill threshold holds the
// request through InterceptStep, the MCP intercept tool resolves the hold,
// and a capturing upstream records what actually reached the wire. After
// the session ends, no spill file may remain.

const (
	spillPatchThreshold = 64 << 10
	spillPatchPadLen    = 128 << 10
)

// spillPatchBody is a ~128 KiB JSON request body with the marker key at the
// end, well past the spill threshold.
func spillPatchBody() []byte {
	return []byte(`{"pad":"` + strings.Repeat("a", spillPatchPadLen) + `","marker":"old"}`)
}

// capturedRequest is what the upstream observed.
type capturedRequest struct {
	proto         string
	body          []byte
	contentLength string
	te            []string
}

// startSpillPatchUpstream serves both HTTP/1.1 and h2 over TLS and reports
// every request it receives.
func startSpillPatchUpstream(t *testing.T) (target string, got <-chan capturedRequest) {
	t.Helper()
	ch := make(chan capturedRequest, 4)
	srv := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		body, _ := io.ReadAll(r.Body)
		ch <- capturedRequest{
			proto:         r.Proto,
			body:          body,
			contentLength: r.Header.Get("Content-Length"),
			te:            r.TransferEncoding,
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), ch
}

// spillPatchHarness is a MITM listener whose pipeline holds every request
// to /hold, plus an MCP client whose intercept tool resolves those holds.
type spillPatchHarness struct {
	proxyAddr string
	spillDir  string
	queue     *common.HoldQueue
	store     flow.Store
	inspector *mcpSpillInspector
	cs        *gomcp.ClientSession
	sessions  sync.WaitGroup
}

func (h *spillPatchHarness) buildPipeline(enc pipeline.WireEncoder) *pipeline.Pipeline {
	engine := httprules.NewInterceptEngine()
	engine.AddRule(httprules.InterceptRule{
		ID:          "hold-spilled",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/hold$`),
	})
	return pipeline.New(
		h.inspector,
		pipeline.NewHostScopeStep(nil),
		pipeline.NewHTTPScopeStep(nil),
		pipeline.NewInterceptStep(engine, nil, nil, nil, h.queue, nil, testutil.DiscardLogger()),
		pipeline.NewRecordStep(h.store, testutil.DiscardLogger(),
			pipeline.WithWireEncoder(envelope.ProtocolHTTP, enc)),
	)
}

func startSpillPatchHarness(t *testing.T, ctx context.Context) *spillPatchHarness {
	t.Helper()
	store, err := flow.NewSQLiteStore(ctx, filepath.Join(t.TempDir(), "spill-patch.db"), testutil.DiscardLogger())
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	h := &spillPatchHarness{
		spillDir: t.TempDir(),
		queue:    common.NewHoldQueue(),
		store:    store,
	}
	h.queue.SetTimeout(60 * time.Second)
	h.inspector = &mcpSpillInspector{dir: h.spillDir}

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
		BodySpillThreshold: spillPatchThreshold,
		BodySpillDir:       h.spillDir,
	}

	onStack := func(sctx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		h.sessions.Add(1)
		defer h.sessions.Done()
		defer stack.Close()
		clientCh := <-stack.ClientTopmost().Channels()
		session.RunSession(sctx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			return <-stack.UpstreamTopmost().Channels(), nil
		}, h.buildPipeline(http1.EncodeWireBytes))
	}

	onHTTP2Stack := func(cbCtx context.Context, stack *connector.ConnectionStack, upstreamH2 *intHTTP2.Layer, _, _ *envelope.TLSSnapshot, _ string) {
		clientL, ok := stack.ClientTopmost().(*intHTTP2.Layer)
		if !ok {
			t.Errorf("stack.ClientTopmost is %T, want *http2.Layer", stack.ClientTopmost())
			return
		}
		clientOpts := httpaggregator.OptionsFromLayer(clientL)
		upstreamOpts := httpaggregator.OptionsFromLayer(upstreamH2)
		var wg sync.WaitGroup
		defer wg.Wait()
		for {
			select {
			case <-cbCtx.Done():
				return
			case ch, ok := <-clientL.Channels():
				if !ok {
					return
				}
				wg.Add(1)
				h.sessions.Add(1)
				go func(ch layer.Channel) {
					defer wg.Done()
					defer h.sessions.Done()
					aggCh, derr := connector.DispatchH2Stream(cbCtx, ch, httpaggregator.RoleServer, clientOpts, slog.Default())
					if derr != nil {
						_ = ch.Close()
						return
					}
					dial := func(dctx context.Context, _ *envelope.Envelope) (layer.Channel, error) {
						upCh, oerr := upstreamH2.OpenStream(dctx)
						if oerr != nil {
							return nil, oerr
						}
						return httpaggregator.Wrap(upCh, httpaggregator.RoleClient, nil, upstreamOpts), nil
					}
					session.RunSession(cbCtx, aggCh, dial, h.buildPipeline(httpaggregator.EncodeWireBytes))
				}(ch)
			}
		}
	}

	fl := connector.NewFullListener(connector.FullListenerConfig{
		Name: "spill-patch",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator:   connector.NewCONNECTNegotiator(testutil.DiscardLogger()),
			BuildCfg:     buildCfg,
			OnStack:      onStack,
			OnHTTP2Stack: onHTTP2Stack,
			Logger:       testutil.DiscardLogger(),
		}),
	})
	go fl.Start(ctx) //nolint:errcheck
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("FullListener not ready")
	}
	h.proxyAddr = fl.Addr()

	srv := newServer(ctx, ca, store, nil, WithHoldQueue(h.queue))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "spill-patch", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	h.cs = cs
	return h
}

// spillPatchTunnel dials proxyAddr and completes a CONNECT to target.
func spillPatchTunnel(proxyAddr, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200") {
		c.Close()
		return nil, fmt.Errorf("CONNECT failed: %q %v", status, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			c.Close()
			return nil, err
		}
		if l == "\r\n" {
			break
		}
	}
	if br.Buffered() > 0 {
		c.Close()
		return nil, errors.New("unexpected bytes after CONNECT response")
	}
	return c, nil
}

// spillPatchClient returns an HTTP client tunnelling through the proxy over
// HTTP/1.1 (proto "h1") or h2 (proto "h2").
func spillPatchClient(t *testing.T, proto, proxyAddr, target string) *nethttp.Client {
	t.Helper()
	if proto == "h2" {
		return &nethttp.Client{Timeout: 90 * time.Second, Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}, //nolint:gosec // test
			DialTLSContext: func(_ context.Context, _, _ string, cfg *tls.Config) (net.Conn, error) {
				raw, err := spillPatchTunnel(proxyAddr, target)
				if err != nil {
					return nil, err
				}
				tc := tls.Client(raw, cfg)
				if err := tc.Handshake(); err != nil {
					raw.Close()
					return nil, err
				}
				return tc, nil
			},
		}}
	}
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	return &nethttp.Client{Timeout: 90 * time.Second, Transport: &nethttp.Transport{
		Proxy:             nethttp.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test
		TLSNextProto:      map[string]func(string, *tls.Conn) nethttp.RoundTripper{},
		DisableKeepAlives: true,
	}}
}

type spillPatchClientResult struct {
	status int
	err    error
}

// sendHeldRequest POSTs body to /hold in the background.
func sendHeldRequest(ctx context.Context, cli *nethttp.Client, target string, body []byte) <-chan spillPatchClientResult {
	out := make(chan spillPatchClientResult, 1)
	go func() {
		req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodPost, "https://"+target+"/hold", bytes.NewReader(body))
		if err != nil {
			out <- spillPatchClientResult{err: err}
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = int64(len(body))
		resp, err := cli.Do(req)
		if err != nil {
			out <- spillPatchClientResult{err: err}
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		out <- spillPatchClientResult{status: resp.StatusCode}
	}()
	return out
}

// waitHeldID waits for the request to be held and returns its intercept
// id, releasing the List clones it inspected.
func (h *spillPatchHarness) waitHeldID(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var id string
		for _, e := range h.queue.List() {
			id = e.ID
			e.Envelope.ReleaseBuffers()
		}
		if id != "" {
			return id
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no request was held")
	return ""
}

// waitNoSpillFiles polls until the spill directory is empty after every
// session has ended.
func (h *spillPatchHarness) waitNoSpillFiles(t *testing.T) {
	t.Helper()
	sessionsDone := make(chan struct{})
	go func() {
		h.sessions.Wait()
		close(sessionsDone)
	}()
	select {
	case <-sessionsDone:
	case <-time.After(30 * time.Second):
		t.Error("sessions did not finish")
	}
	deadline := time.Now().Add(10 * time.Second)
	n := countMCPSpillFiles(t, h.spillDir)
	for n != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		n = countMCPSpillFiles(t, h.spillDir)
	}
	if n != 0 {
		t.Errorf("%d spill files remain after the session ended, want 0 (held body buffer reference leaked)", n)
	}
}

func countMCPSpillFiles(t *testing.T, dir string) int {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, config.BodySpillPrefix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	return len(matches)
}

// callIntercept invokes the intercept tool and returns the tool result.
func (h *spillPatchHarness) callIntercept(t *testing.T, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	res, err := h.cs.CallTool(context.Background(), &gomcp.CallToolParams{Name: "intercept", Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(intercept): %v", err)
	}
	return res
}

// sendVariantBodies returns the recorded Send-direction bodies keyed by
// Metadata["variant"].
func (h *spillPatchHarness) sendVariantBodies(t *testing.T, ctx context.Context) map[string][]byte {
	t.Helper()
	streams, err := h.store.ListStreams(ctx, flow.StreamListOptions{})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	out := map[string][]byte{}
	for _, st := range streams {
		flows, err := h.store.GetFlows(ctx, st.ID, flow.FlowListOptions{Direction: "send"})
		if err != nil {
			t.Fatalf("GetFlows: %v", err)
		}
		for _, f := range flows {
			out[f.Metadata["variant"]] = f.Body
		}
	}
	return out
}

func toolErrorText(res *gomcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// TestInterceptSpilledBody_BodyPatchesReachUpstream: body_patches applied
// through modify_and_forward to a held, disk-spilled request rewrite the
// full body, the patched bytes reach the upstream (HTTP/1.x re-stamps
// Content-Length), the modified variant records them next to the original,
// and no spill file outlives the session.
func TestInterceptSpilledBody_BodyPatchesReachUpstream(t *testing.T) {
	orig := spillPatchBody()
	patchedMarker := bytes.Replace(orig, []byte(`"marker":"old"`), []byte(`"marker":"new"`), 1)

	tests := []struct {
		name    string
		proto   string
		patches []map[string]any
		want    []byte
	}{
		{
			name:    "h1_json_path",
			proto:   "h1",
			patches: []map[string]any{{"json_path": "$.marker", "value": "new"}},
			want:    patchedMarker,
		},
		{
			name:    "h1_regex",
			proto:   "h1",
			patches: []map[string]any{{"regex": `"marker":"old"`, "replace": `"marker":"new"`}},
			want:    patchedMarker,
		},
		{
			name:    "h1_regex_empty_match_start",
			proto:   "h1",
			patches: []map[string]any{{"regex": `^`, "replace": `PRE`}},
			want:    append([]byte("PRE"), orig...),
		},
		{
			name:    "h1_regex_empty_match_end",
			proto:   "h1",
			patches: []map[string]any{{"regex": `$`, "replace": `POST`}},
			want:    append(append([]byte{}, orig...), "POST"...),
		},
		{
			name:    "h2_json_path",
			proto:   "h2",
			patches: []map[string]any{{"json_path": "$.marker", "value": "new"}},
			want:    patchedMarker,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
			defer cancel()
			target, upstream := startSpillPatchUpstream(t)
			h := startSpillPatchHarness(t, ctx)

			resCh := sendHeldRequest(ctx, spillPatchClient(t, tc.proto, h.proxyAddr, target), target, orig)
			id := h.waitHeldID(t)
			if !h.inspector.sawFileBacked.Load() {
				t.Fatalf("held request body was not spilled; a %d-byte body must spill above %d", len(orig), spillPatchThreshold)
			}

			res := h.callIntercept(t, map[string]any{
				"action": "modify_and_forward",
				"params": map[string]any{"intercept_id": id},
				"http":   map[string]any{"body_patches": tc.patches},
			})
			if res.IsError {
				// Unblock the client before failing.
				_ = h.queue.Release(id, &common.HoldAction{Type: common.ActionDrop})
				t.Fatalf("intercept modify_and_forward failed: %s", toolErrorText(res))
			}

			var got capturedRequest
			select {
			case got = <-upstream:
			case <-time.After(60 * time.Second):
				t.Fatal("upstream never received the request")
			}
			if r := <-resCh; r.err != nil || r.status != 200 {
				t.Errorf("client result = (%d, %v), want (200, nil)", r.status, r.err)
			}

			if !bytes.Equal(got.body, tc.want) {
				t.Errorf("upstream body (%d bytes) != patched body (%d bytes); head=%q tail=%q",
					len(got.body), len(tc.want), spillHead(got.body), spillTail(got.body))
			}
			if tc.proto == "h1" {
				if got.contentLength != strconv.Itoa(len(tc.want)) {
					t.Errorf("upstream Content-Length = %q, want %d", got.contentLength, len(tc.want))
				}
				if len(got.te) != 0 {
					t.Errorf("upstream Transfer-Encoding = %v, want none", got.te)
				}
			}

			h.waitNoSpillFiles(t)

			variants := h.sendVariantBodies(t, ctx)
			if !bytes.Equal(variants["modified"], tc.want) {
				t.Errorf("modified variant body (%d bytes) != patched body (%d bytes)", len(variants["modified"]), len(tc.want))
			}
			if !bytes.Equal(variants["original"], orig) {
				t.Errorf("original variant body (%d bytes) != wire body (%d bytes)", len(variants["original"]), len(orig))
			}
		})
	}
}

// TestInterceptSpilledBody_NoSpillFileAfterSession: whichever action
// resolves the hold on a spilled request, every buffer reference the hold
// path took is released by the time the session ends.
func TestInterceptSpilledBody_NoSpillFileAfterSession(t *testing.T) {
	type action struct {
		name         string
		args         func(id string) map[string]any
		wantUpstream bool
	}
	actions := []action{
		{
			name: "release",
			args: func(id string) map[string]any {
				return map[string]any{"action": "release", "params": map[string]any{"intercept_id": id}}
			},
			wantUpstream: true,
		},
		{
			name: "modify_and_forward_header_only",
			args: func(id string) map[string]any {
				return map[string]any{
					"action": "modify_and_forward",
					"params": map[string]any{"intercept_id": id},
					"http":   map[string]any{"path": "/hold"},
				}
			},
			wantUpstream: true,
		},
		{
			name: "modify_and_forward_patch",
			args: func(id string) map[string]any {
				return map[string]any{
					"action": "modify_and_forward",
					"params": map[string]any{"intercept_id": id},
					"http":   map[string]any{"body_patches": []map[string]any{{"json_path": "$.marker", "value": "new"}}},
				}
			},
			wantUpstream: true,
		},
		{
			name: "drop",
			args: func(id string) map[string]any {
				return map[string]any{"action": "drop", "params": map[string]any{"intercept_id": id}}
			},
		},
	}
	orig := spillPatchBody()
	for _, proto := range []string{"h1", "h2"} {
		for _, a := range actions {
			t.Run(proto+"_"+a.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
				defer cancel()
				target, upstream := startSpillPatchUpstream(t)
				h := startSpillPatchHarness(t, ctx)

				resCh := sendHeldRequest(ctx, spillPatchClient(t, proto, h.proxyAddr, target), target, orig)
				id := h.waitHeldID(t)
				if !h.inspector.sawFileBacked.Load() {
					t.Fatalf("held request body was not spilled")
				}
				if res := h.callIntercept(t, a.args(id)); res.IsError {
					_ = h.queue.Release(id, &common.HoldAction{Type: common.ActionDrop})
					t.Fatalf("intercept %s failed: %s", a.name, toolErrorText(res))
				}

				r := <-resCh
				if a.wantUpstream {
					select {
					case <-upstream:
					case <-time.After(60 * time.Second):
						t.Fatal("upstream never received the request")
					}
					if r.err != nil || r.status != 200 {
						t.Errorf("client result = (%d, %v), want (200, nil)", r.status, r.err)
					}
				} else if r.err == nil && r.status != nethttp.StatusForbidden {
					t.Errorf("client status after drop = %d, want 403", r.status)
				}

				h.waitNoSpillFiles(t)
			})
		}
	}
}

func spillHead(b []byte) []byte {
	if len(b) > 32 {
		return b[:32]
	}
	return b
}

func spillTail(b []byte) []byte {
	if len(b) > 32 {
		return b[len(b)-32:]
	}
	return b
}
