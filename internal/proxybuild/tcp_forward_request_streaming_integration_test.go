//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// USK-1414 T18: the request body-mode predicate BuildLiveStack builds
// reaches the client-facing HTTP/1.x Layer of the target-override stack
// (tcp_forwards L7 and plain transparent share that builder): the first
// fragment of a request body reaches the upstream before the client sends
// the rest.
func TestProxybuild_TCPForward_HTTP_RequestBodyStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	body := bytes.Repeat([]byte("0123456789abcdef"), 512) // 8 KiB
	half := len(body) / 2
	got1 := make(chan struct{})
	result := make(chan []byte, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
		br := bufio.NewReader(c)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				result <- nil
				return
			}
			if line == "\r\n" {
				break
			}
		}
		b := make([]byte, len(body))
		if _, err := io.ReadFull(br, b[:half]); err != nil {
			result <- nil
			return
		}
		close(got1)
		if _, err := io.ReadFull(br, b[half:]); err != nil {
			result <- nil
			return
		}
		result <- b
		_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}()

	store := &flowStoreCapture{}
	mgr := newForwardTestManager(t, store)
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: ln.Addr().String(), Protocol: "http"},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	fwdAddr := mgr.TCPForwardAddrs()["0"]

	c, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer c.Close()
	if _, err := fmt.Fprintf(c, "POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body)); err != nil {
		t.Fatalf("write head: %v", err)
	}
	if _, err := c.Write(body[:half]); err != nil {
		t.Fatalf("write fragment 1: %v", err)
	}
	select {
	case <-got1:
	case <-time.After(15 * time.Second):
		t.Fatal("the upstream did not receive the first body fragment before the client sent the rest (request body buffered)")
	}
	if _, err := c.Write(body[half:]); err != nil {
		t.Fatalf("write fragment 2: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp, _ := io.ReadAll(c)
	if !strings.HasPrefix(string(resp), "HTTP/1.1 200 OK") {
		t.Errorf("client response = %q, want 200", resp)
	}
	select {
	case b := <-result:
		if !bytes.Equal(b, body) {
			t.Error("upstream body differs from the client's body")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upstream did not finish")
	}
}
