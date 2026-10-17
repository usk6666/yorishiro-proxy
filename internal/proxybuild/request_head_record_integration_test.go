//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// USK-1181: request heads the proxy closes before an Envelope exists (414,
// 431, header deadline) are recorded on every HTTP/1 Layer entry path.

const usk1181RawCap = 4096

// startUSK1181Manager starts a Manager with request_timeout_ms=300ms and a
// small max_raw_capture_size, returning it and its proxy address.
func startUSK1181Manager(t *testing.T, ctx context.Context, store flow.Writer) (*proxybuild.Manager, string) {
	t.Helper()
	logger := testutil.DiscardLogger()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
		MaxRawCaptureSize:  usk1181RawCap,
	}
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger: logger,
		StackFactory: func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
			return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
				Logger:       logger,
				ListenerName: name,
				ListenAddr:   addr,
				FlowStore:    store,
				BuildConfig:  buildCfg,
			})
		},
		BuildConfig: buildCfg,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.SetRequestTimeout(300 * time.Millisecond)
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	_, addr := mgr.Status()
	return mgr, addr
}

// usk1181Reject writes payload on conn (in the background, since the proxy
// stops reading once the limit trips) and returns everything the proxy
// sends back before closing.
func usk1181Reject(t *testing.T, conn net.Conn, payload string) []byte {
	t.Helper()
	go func() { _, _ = conn.Write([]byte(payload)) }()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	// A read error after the response (e.g. RST) is irrelevant here: the
	// Layer-level tests pin the FIN; this test asserts recording.
	got, _ := io.ReadAll(conn)
	return got
}

// assertRejectRecorded checks the Stream + send/receive flows for a 414 /
// 431 reject.
func assertRejectRecorded(t *testing.T, store *usk1181Store, reason, scheme string, status int, payload string, clientGot []byte) {
	t.Helper()
	st, flows := awaitErrorStream(t, store, reason, 2, 5*time.Second)
	if st.Protocol != "http" || st.Scheme != scheme {
		t.Errorf("stream protocol/scheme = %q/%q, want http/%s", st.Protocol, st.Scheme, scheme)
	}
	if st.Tags["closed_by"] != "proxy" {
		t.Errorf("Tags[closed_by] = %q, want proxy", st.Tags["closed_by"])
	}
	var send, recv *flow.Flow
	for _, f := range flows {
		switch f.Direction {
		case "send":
			send = f
		case "receive":
			recv = f
		}
	}
	if send == nil || recv == nil {
		t.Fatalf("want send + receive flows, got %d", len(flows))
	}
	if send.Sequence != 0 || recv.Sequence != 1 {
		t.Errorf("sequences send=%d receive=%d, want 0/1", send.Sequence, recv.Sequence)
	}
	if string(send.RawBytes) != payload[:usk1181RawCap] {
		t.Errorf("send RawBytes = %d bytes, want the first %d bytes sent", len(send.RawBytes), usk1181RawCap)
	}
	if send.Metadata["raw_truncated"] != "true" {
		t.Errorf("send Metadata[raw_truncated] = %q, want true", send.Metadata["raw_truncated"])
	}
	if recv.StatusCode != status {
		t.Errorf("receive StatusCode = %d, want %d", recv.StatusCode, status)
	}
	if string(recv.RawBytes) != string(clientGot) {
		t.Errorf("receive RawBytes = %q, want the bytes the client read %q", recv.RawBytes, clientGot)
	}
	if recv.Metadata["proxy_generated"] != "true" {
		t.Errorf("receive Metadata[proxy_generated] = %q, want true", recv.Metadata["proxy_generated"])
	}
}

func TestProxybuild_PlainHTTP_RequestHeadRejectsRecorded(t *testing.T) {
	upstream := startUSK1162Upstream(t)
	upHost := strings.TrimPrefix(upstream.URL, "http://")

	cases := []struct {
		name    string
		payload string
		reason  string
		status  int
	}{
		{name: "414", reason: "request_line_too_long", status: 414,
			payload: "GET http://" + upHost + "/" + strings.Repeat("x", 4<<20) + " HTTP/1.1\r\nHost: " + upHost + "\r\n\r\n"},
		{name: "431", reason: "request_header_too_large", status: 431,
			payload: "GET http://" + upHost + "/ HTTP/1.1\r\nHost: " + upHost + "\r\nX-Big: " + strings.Repeat("b", 4<<20) + "\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			store := &usk1181Store{}
			_, proxyAddr := startUSK1181Manager(t, ctx, store)
			conn, _ := usk1162Dial(t, proxyAddr)
			got := usk1181Reject(t, conn, tc.payload)
			if !strings.HasPrefix(string(got), "HTTP/1.1 "+strconv.Itoa(tc.status)+" ") {
				t.Fatalf("client read %.120q, want HTTP/1.1 %d", got, tc.status)
			}
			assertRejectRecorded(t, store, tc.reason, "http", tc.status, tc.payload, got)
		})
	}
}

func TestProxybuild_CONNECT_MITM_RequestLineTooLongRecorded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	upstream := httptest.NewTLSServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, _ *gohttp.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	target := strings.TrimPrefix(upstream.URL, "https://")

	store := &usk1181Store{}
	_, proxyAddr := startUSK1181Manager(t, ctx, store)
	raw, err := connectTunnelDialerForPoolTest(proxyAddr, target)
	if err != nil {
		t.Fatalf("CONNECT: %v", err)
	}
	defer raw.Close()
	tconn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test
		NextProtos:         []string{"http/1.1"},
		ServerName:         "127.0.0.1",
	})
	_ = tconn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	payload := "GET /" + strings.Repeat("x", 4<<20) + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	got := usk1181Reject(t, tconn, payload)
	if !strings.HasPrefix(string(got), "HTTP/1.1 414 ") {
		t.Fatalf("client read %.120q, want HTTP/1.1 414", got)
	}
	assertRejectRecorded(t, store, "request_line_too_long", "https", 414, payload, got)
}

func TestProxybuild_TCPForward_HTTP_RequestHeadTimeoutRecorded(t *testing.T) {
	for _, protocol := range []string{"http", "websocket"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			upstream := startUSK1162Upstream(t)
			host := strings.TrimPrefix(upstream.URL, "http://")
			store := &usk1181Store{}
			fwdAddr := startUSK1162Forward(t, ctx, store, host, protocol)

			conn, br := usk1162Dial(t, fwdAddr)
			done := make(chan struct{})
			defer close(done)
			slow := "GET /slow HTTP/1.1\r\nHost: " + host + "\r\nX-Pad: " + strings.Repeat("p", 200) + "\r\n\r\n"
			go usk1162Trickle(conn, []byte(slow), 50*time.Millisecond, done)
			if got := usk1162AwaitClose(t, br, conn, 3*time.Second); got != "" {
				t.Errorf("forward replied to a trickled request: %.120q", got)
			}

			st, flows := awaitErrorStream(t, store, "request_head_timeout", 1, 5*time.Second)
			if st.Protocol != "http" || st.Scheme != "http" {
				t.Errorf("stream protocol/scheme = %q/%q, want http/http", st.Protocol, st.Scheme)
			}
			if st.Tags["request_timeout_ms"] != "300" {
				t.Errorf("Tags[request_timeout_ms] = %q, want 300", st.Tags["request_timeout_ms"])
			}
			if len(flows[0].RawBytes) == 0 || !strings.HasPrefix(slow, string(flows[0].RawBytes)) {
				t.Errorf("send RawBytes = %q, want a non-empty prefix of the trickled request", flows[0].RawBytes)
			}
		})
	}
}
