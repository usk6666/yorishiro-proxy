package connector

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// rejectingProxyRecorder is an upstream HTTP CONNECT proxy that records the
// Basic-auth username and CONNECT authority of every tunnel request and
// then refuses it with 502, so a redial fails before its stale Layer is
// ever consulted.
type rejectingProxyRecorder struct {
	addr string
	mu   sync.Mutex
	seen []string // "user@authority"
}

func startRejectingProxyRecorder(t *testing.T) *rejectingProxyRecorder {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen recorder: %v", err)
	}
	r := &rejectingProxyRecorder{addr: ln.Addr().String()}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				user := req.Header.Get("Proxy-Authorization")
				if dec, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(user, "Basic ")); err == nil {
					user, _, _ = strings.Cut(string(dec), ":")
				}
				r.mu.Lock()
				r.seen = append(r.seen, user+"@"+req.Host)
				r.mu.Unlock()
				_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			}()
		}
	}()
	return r
}

func (r *rejectingProxyRecorder) tunnels() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// TestRedialUpstream_PerTargetHostRotationKeyedByDialTarget: a redial whose
// ctx carries only the listener name (the ctx dispatchStack hands to the
// h1 chain / h2 redial) resolves per_target_host rotation by ut.Dial, so it
// reuses the upstream proxy the first dial cached for that target.
func TestRedialUpstream_PerTargetHostRotationKeyedByDialTarget(t *testing.T) {
	const listener = "rot-redial-unit"
	const target = "127.0.0.1:9" // never reached: the recorder refuses the tunnel
	cases := []struct {
		name   string
		redial func(ctx context.Context, cfg *BuildConfig) error
	}{
		{"h1 profiled", func(ctx context.Context, cfg *BuildConfig) error {
			_, err := RedialUpstreamH1(ctx, SameUpstreamTarget(target), UpstreamTLSProfiled, &http1.Layer{}, cfg, 1)
			return err
		}},
		{"h1 no-ALPN", func(ctx context.Context, cfg *BuildConfig) error {
			_, err := RedialUpstreamH1(ctx, SameUpstreamTarget(target), UpstreamTLSStandardNoALPN, &http1.Layer{}, cfg, 1)
			return err
		}},
		{"h2", func(ctx context.Context, cfg *BuildConfig) error {
			_, err := RedialUpstreamH2(ctx, SameUpstreamTarget(target), &http2.Layer{}, cfg, 1, nil)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := startRejectingProxyRecorder(t)
			cfg := &BuildConfig{ProxyConfig: &config.ProxyConfig{}, InsecureSkipVerify: true}
			resolver := NewRotationResolver(RotationConfig{
				Template:     fmt.Sprintf("http://session-§__nonce§:pass@%s", rec.addr),
				Policy:       RotationPerTargetHost,
				ListenerName: listener,
			}, 0, 0)
			cfg.SetRotationForListener(listener, resolver)
			ctx := ContextWithListenerName(context.Background(), listener)

			// The first dial cached this URL for target.
			first, err := resolver.Resolve(ctx, listener, target)
			if err != nil {
				t.Fatalf("seed Resolve: %v", err)
			}

			if err := tc.redial(ctx, cfg); err == nil {
				t.Fatal("redial succeeded, want the recorder's 502 refusal")
			}
			want := first.User.Username() + "@" + target
			if got := rec.tunnels(); len(got) != 1 || got[0] != want {
				t.Errorf("upstream proxy tunnels = %q, want [%q] (the first dial's rotation slot)", got, want)
			}
		})
	}
}

// TestDialPlainUpstream_PerTargetHostRotationKeyedByTarget: the plain dial
// used by plaintext CONNECT / SOCKS5 tunnels resolves per_target_host by
// the target it dials even when ctx carries no dial target.
func TestDialPlainUpstream_PerTargetHostRotationKeyedByTarget(t *testing.T) {
	const listener = "rot-plain-unit"
	const target = "127.0.0.1:9"
	rec := startRejectingProxyRecorder(t)
	cfg := &BuildConfig{ProxyConfig: &config.ProxyConfig{}}
	resolver := NewRotationResolver(RotationConfig{
		Template:     fmt.Sprintf("http://session-§__nonce§:pass@%s", rec.addr),
		Policy:       RotationPerTargetHost,
		ListenerName: listener,
	}, 0, 0)
	cfg.SetRotationForListener(listener, resolver)
	ctx := ContextWithListenerName(context.Background(), listener)
	first, err := resolver.Resolve(ctx, listener, target)
	if err != nil {
		t.Fatalf("seed Resolve: %v", err)
	}
	if c, err := dialPlainUpstream(ctx, target, cfg); err == nil {
		_ = c.Close()
		t.Fatal("dial succeeded, want the recorder's 502 refusal")
	}
	want := first.User.Username() + "@" + target
	if got := rec.tunnels(); len(got) != 1 || got[0] != want {
		t.Errorf("upstream proxy tunnels = %q, want [%q]", got, want)
	}
}
