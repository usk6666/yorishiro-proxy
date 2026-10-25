//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// A real Starlark plugin rewrites msg["body"] on an HTTP message whose body
// exceeded the spill threshold and was spilled to disk, driven through
// BuildLiveStack's CONNECT MITM path (HTTP/1.1 and h2). The rewritten body
// must reach the peer, both variants must be recorded, and once the
// connection is gone no spill file may remain. On HTTP/1.x the modified
// variant's RawBytes must be exactly the re-encoded message.

const (
	pluginSpillThreshold = 64 << 10
	pluginSpillBodyLen   = 128 << 10
)

var pluginSpillBody = bytes.Repeat([]byte("s"), pluginSpillBodyLen)

// pluginSpillUpstream answers every request with pluginSpillBody and
// reports the request body it received and whether a spill file existed
// while the proxy was forwarding the request.
type pluginSpillUpstream struct {
	target   string
	gotBody  chan []byte
	sawSpill atomic.Bool
}

func startPluginSpillUpstream(t *testing.T, spillDir string) *pluginSpillUpstream {
	t.Helper()
	u := &pluginSpillUpstream{gotBody: make(chan []byte, 4)}
	srv := httptest.NewUnstartedServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		body, _ := io.ReadAll(r.Body)
		if n, _ := filepath.Glob(filepath.Join(spillDir, config.BodySpillPrefix+"*")); len(n) > 0 {
			u.sawSpill.Store(true)
		}
		u.gotBody <- body
		w.Header().Set("Content-Type", "text/plain")
		if r.ProtoMajor == 1 {
			// Fixed framing so the HTTP/1.x original variant is the plain
			// body. On h2 the length is left out: the proxy does not
			// re-stamp content-length after a plugin body rewrite.
			w.Header().Set("Content-Length", strconv.Itoa(len(pluginSpillBody)))
		}
		_, _ = w.Write(pluginSpillBody)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u.target = srv.Listener.Addr().String()
	return u
}

// startPluginSpillMITM boots a BuildLiveStack listener with a lowered spill
// threshold and a real plugin engine loaded from script.
func startPluginSpillMITM(t *testing.T, ctx context.Context, script, spillDir string) (*flowStoreCapture, string) {
	t.Helper()
	store := &flowStoreCapture{}
	buildCfg := rawWinsBuildConfig(t)
	buildCfg.BodySpillThreshold = pluginSpillThreshold
	buildCfg.BodySpillDir = spillDir
	stack, err := proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
		Logger:         testutil.DiscardLogger(),
		ListenerName:   "plugin-body-spill",
		ListenAddr:     "127.0.0.1:0",
		FlowStore:      store,
		BuildConfig:    buildCfg,
		PluginV2Engine: loadRawWinsPlugin(t, ctx, script),
	})
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	go func() { _ = stack.Listener.Start(ctx) }()
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready in 5s")
	}
	return store, stack.Listener.Addr()
}

// pluginSpillClient returns an HTTP client tunnelling through the proxy over
// HTTP/1.1 ("h1") or h2 ("h2"), and a func that tears its connections down.
func pluginSpillClient(t *testing.T, proto, proxyAddr, target string) (*nethttp.Client, func()) {
	t.Helper()
	if proto == "h2" {
		tr := &http2.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}, //nolint:gosec // test
			DialTLSContext: func(_ context.Context, _, _ string, cfg *tls.Config) (net.Conn, error) {
				raw, err := connectTunnelDialerForPoolTest(proxyAddr, target)
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
		}
		return &nethttp.Client{Timeout: 30 * time.Second, Transport: tr}, tr.CloseIdleConnections
	}
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	tr := &nethttp.Transport{
		Proxy:             nethttp.ProxyURL(proxyURL),
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test
		TLSNextProto:      map[string]func(string, *tls.Conn) nethttp.RoundTripper{},
		DisableKeepAlives: true,
	}
	return &nethttp.Client{Timeout: 30 * time.Second, Transport: tr}, tr.CloseIdleConnections
}

// variantFlowOf returns the recorded flow for direction / variant.
func variantFlowOf(store *flowStoreCapture, direction, variant string) *flow.Flow {
	for _, f := range store.Flows() {
		if f != nil && f.Direction == direction && f.Metadata["variant"] == variant {
			return f
		}
	}
	return nil
}

// waitNoPluginSpillFiles polls until spillDir holds no spill file.
func waitNoPluginSpillFiles(t *testing.T, spillDir string) {
	t.Helper()
	count := func() int {
		m, err := filepath.Glob(filepath.Join(spillDir, config.BodySpillPrefix+"*"))
		if err != nil {
			t.Fatal(err)
		}
		return len(m)
	}
	deadline := time.Now().Add(10 * time.Second)
	n := count()
	for n != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		n = count()
	}
	if n != 0 {
		t.Errorf("%d spill files remain after the session ended, want 0 (a plugin body replacement leaked a buffer reference)", n)
	}
}

// h1HeadLen returns the length of the header section of an HTTP/1.x
// message (through the blank line), or -1.
func h1HeadLen(raw []byte) int {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return -1
	}
	return i + 4
}

func TestPluginBodySpill_ReplaceReleasesSpillFile(t *testing.T) {
	const (
		newReq  = "plugin-request-body"
		newResp = "plugin-response-body"
	)
	type row struct {
		name   string
		script string
		// dir is the direction whose message the plugin modifies ("" for
		// the no-op control).
		dir string
		// newBody is the body the plugin writes ("" for a header-only
		// mutation or the no-op control).
		newBody string
	}
	rows := []row{
		{
			name: "pre_on_request",
			script: `
def h(msg, ctx):
    msg["body"] = b"` + newReq + `"
register_hook("http", "on_request", h)
`,
			dir: "send", newBody: newReq,
		},
		{
			name: "post_on_request",
			script: `
def h(msg, ctx):
    msg["body"] = b"` + newReq + `"
register_hook("http", "on_request", h, phase="post_pipeline")
`,
			dir: "send", newBody: newReq,
		},
		{
			name: "pre_on_response",
			script: `
def h(msg, ctx):
    msg["body"] = b"` + newResp + `"
register_hook("http", "on_response", h)
`,
			dir: "receive", newBody: newResp,
		},
		{
			name: "post_on_response",
			script: `
def h(msg, ctx):
    msg["body"] = b"` + newResp + `"
register_hook("http", "on_response", h, phase="post_pipeline")
`,
			dir: "receive", newBody: newResp,
		},
		{
			name: "header_only_on_request",
			script: `
def h(msg, ctx):
    msg["path"] = "/changed"
register_hook("http", "on_request", h)
`,
			dir: "send",
		},
		{
			name: "header_only_on_response",
			script: `
def h(msg, ctx):
    msg["status_reason"] = "Fine"
register_hook("http", "on_response", h)
`,
			dir: "receive",
		},
		{
			name: "noop_control",
			script: `
def h(msg, ctx):
    pass
register_hook("http", "on_request", h)
register_hook("http", "on_response", h, phase="post_pipeline")
`,
		},
	}

	for _, proto := range []string{"h1", "h2"} {
		for _, r := range rows {
			if proto == "h2" && r.name == "header_only_on_response" {
				// HTTP/2 carries no reason phrase; the mutation has no
				// h2 representation.
				continue
			}
			t.Run(proto+"_"+r.name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				spillDir := t.TempDir()
				up := startPluginSpillUpstream(t, spillDir)
				store, proxyAddr := startPluginSpillMITM(t, ctx, r.script, spillDir)

				cli, closeConns := pluginSpillClient(t, proto, proxyAddr, up.target)
				req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodPost, "https://"+up.target+"/spill", bytes.NewReader(pluginSpillBody))
				if err != nil {
					t.Fatal(err)
				}
				req.ContentLength = int64(len(pluginSpillBody))
				resp, err := cli.Do(req)
				if err != nil {
					t.Fatalf("client request: %v", err)
				}
				respBody, rerr := io.ReadAll(resp.Body)
				resp.Body.Close()
				closeConns()
				if rerr != nil {
					t.Fatalf("read response body: %v", rerr)
				}
				if resp.StatusCode != 200 {
					t.Errorf("client status = %d, want 200", resp.StatusCode)
				}

				var upBody []byte
				select {
				case upBody = <-up.gotBody:
				case <-time.After(10 * time.Second):
					t.Fatal("upstream never received the request")
				}
				if !up.sawSpill.Load() {
					t.Fatalf("no spill file existed while the %d-byte request was forwarded; the body must spill above %d", len(pluginSpillBody), pluginSpillThreshold)
				}

				wantUp, wantClient := pluginSpillBody, pluginSpillBody
				if r.newBody != "" && r.dir == "send" {
					wantUp = []byte(r.newBody)
				}
				if r.newBody != "" && r.dir == "receive" {
					wantClient = []byte(r.newBody)
				}
				if !bytes.Equal(upBody, wantUp) {
					t.Errorf("upstream body (%d bytes) = %.40q, want %d bytes %.40q", len(upBody), upBody, len(wantUp), wantUp)
				}
				if !bytes.Equal(respBody, wantClient) {
					t.Errorf("client body (%d bytes) = %.40q, want %d bytes %.40q", len(respBody), respBody, len(wantClient), wantClient)
				}

				waitNoPluginSpillFiles(t, spillDir)

				if r.dir == "" {
					return
				}
				orig := variantFlowOf(store, r.dir, "original")
				mod := variantFlowOf(store, r.dir, "modified")
				if orig == nil || mod == nil {
					t.Fatalf("%s variants missing (original=%v modified=%v)", r.dir, orig != nil, mod != nil)
				}
				if !bytes.Equal(orig.Body, pluginSpillBody) {
					t.Errorf("original variant body (%d bytes), want the %d-byte spilled body", len(orig.Body), len(pluginSpillBody))
				}
				wantModBody := pluginSpillBody
				if r.newBody != "" {
					wantModBody = []byte(r.newBody)
				}
				if !bytes.Equal(mod.Body, wantModBody) {
					t.Errorf("modified variant body (%d bytes) = %.40q, want %d bytes", len(mod.Body), mod.Body, len(wantModBody))
				}

				if proto != "h1" {
					return
				}
				// The original variant is the wire message: header
				// section + the spilled body, once.
				if hl := h1HeadLen(orig.RawBytes); hl < 0 || !bytes.Equal(orig.RawBytes[hl:], pluginSpillBody) {
					t.Errorf("original variant RawBytes (%d bytes) are not header section + the %d-byte wire body", len(orig.RawBytes), len(pluginSpillBody))
				}
				// The modified variant is the re-encoded message: header
				// section + the modified body, with no stale wire body
				// stitched after it.
				if hl := h1HeadLen(mod.RawBytes); hl < 0 || !bytes.Equal(mod.RawBytes[hl:], wantModBody) {
					tail := mod.RawBytes
					if len(tail) > 40 {
						tail = tail[len(tail)-40:]
					}
					t.Errorf("modified variant RawBytes (%d bytes, head %d) do not end in exactly the %d-byte modified body; tail=%q",
						len(mod.RawBytes), hl, len(wantModBody), tail)
				}
				if r.newBody != "" && !strings.Contains(string(mod.RawBytes), "Content-Length: "+strconv.Itoa(len(r.newBody))+"\r\n") {
					t.Errorf("modified variant RawBytes do not carry the re-stamped Content-Length %d", len(r.newBody))
				}
			})
		}
	}
}
