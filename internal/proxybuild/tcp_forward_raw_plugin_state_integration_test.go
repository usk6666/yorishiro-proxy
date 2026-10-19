//go:build e2e && !e2e_smoke

// USK-1083 T9: plugin ctx.stream_state / ctx.transaction_state work on raw
// (bytechunk) connections — a value set on a Send chunk is visible on the
// Receive chunk of the same connection — and both scopes are released when
// the connection closes, so a long-running proxy does not accumulate them.
package proxybuild_test

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// waitRawStreamsCompleteUSK1083 polls until n raw Streams are complete.
func waitRawStreamsCompleteUSK1083(t *testing.T, ctx context.Context, store *flow.SQLiteStore, n int) []*flow.Stream {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		streams, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: "raw"})
		if err != nil {
			t.Fatalf("ListStreams: %v", err)
		}
		done := 0
		for _, s := range streams {
			if s.State == "complete" {
				done++
			}
		}
		if done >= n {
			return streams
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d/%d raw Streams complete after 5s", done, n)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestProxybuild_TCPForward_Raw_PluginStateScopedAndReleased(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const script = `
def on_chunk(msg, ctx):
    if msg["bytes"] == b"PING":
        ctx.stream_state.set("seen", True)
        ctx.transaction_state.set("seen", True)
    elif msg["bytes"] == b"PONG":
        if ctx.stream_state.get("seen") == True and ctx.transaction_state.get("seen") == True:
            msg["bytes"] = b"PONG+state"
    return None
register_hook("raw", "on_chunk", on_chunk)
`
	pluginPath := filepath.Join(t.TempDir(), "state.star")
	if err := os.WriteFile(pluginPath, []byte(script), 0o600); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	engine := pluginv2.NewEngine(testutil.DiscardLogger())
	if err := engine.LoadPlugins(ctx, []pluginv2.PluginConfig{{Path: pluginPath, OnError: string(pluginv2.OnErrorAbort)}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}

	// Upstream answers every chunk with PONG (not an echo, so the plugin
	// can tell the directions apart by content).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
					if _, err := c.Write([]byte("PONG")); err != nil {
						return
					}
				}
			}(c)
		}
	}()

	store := openSQLiteStoreUSK1216(t, ctx)
	fwdAddr := startRawForwardUSK1216(t, ctx, store, engine, ln.Addr().String())

	const conns = 3
	for i := 0; i < conns; i++ {
		c, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial forward: %v", err)
		}
		if _, err := c.Write([]byte("PING")); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len("PONG+state"))
		n, err := io.ReadAtLeast(c, got, len("PONG"))
		if err != nil {
			t.Fatalf("conn %d read: %v", i, err)
		}
		if n < len(got) {
			// The rewrite may be split; read the rest if any.
			m, _ := io.ReadFull(c, got[n:])
			n += m
		}
		if string(got[:n]) != "PONG+state" {
			t.Errorf("conn %d: client read %q, want %q (stream/transaction state set on Send not visible on Receive)", i, got[:n], "PONG+state")
		}
		_ = c.Close()
	}

	st := waitRawStreamsCompleteUSK1083(t, ctx, store, conns)
	for _, s := range st {
		if s.ConnID == "" {
			t.Errorf("raw Stream %s has empty ConnID", s.ID)
			continue
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, found := engine.LookupStreamStateBool(s.ConnID, s.ID, "seen"); !found {
				break
			}
			if time.Now().After(deadline) {
				t.Errorf("stream_state for (%s, %s) still held 5s after the connection closed; want released", s.ConnID, s.ID)
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}
