package proxybuild

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/layer/tlslayer"
)

// USK-1189: a client-side TLS MITM handshake the proxy itself abandoned
// because request_timeout_ms expired keeps FailureReason=client_tls_error
// but carries the proxy-closed timeout tags; every other client_tls_error
// (certificate rejection, alert) and every upstream_tls_error does not.

var usk1189TimeoutTagKeys = []string{"phase", "closed_by", "timeout", "request_timeout_ms"}

// realHandshakeTimeoutErr drives tlslayer.Server against a peer that never
// sends a ClientHello, bounded by a short context, and returns the error
// wrapped exactly as the connector's MITM path wraps it.
func realHandshakeTimeoutErr(t *testing.T, target string) error {
	t.Helper()
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, _, err := tlslayer.Server(ctx, server, &tls.Config{MinVersion: tls.VersionTLS12})
	if err == nil {
		t.Fatal("tlslayer.Server succeeded against a silent peer")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("precondition: handshake error %v does not wrap context.DeadlineExceeded", err)
	}
	return fmt.Errorf("%w for %s: %w", connector.ErrClientTLSMITMHandshake, target, err)
}

func TestBuildTLSStackBuildErrorRecorder_HandshakeTimeout_Tagged(t *testing.T) {
	store := &recordingFlowStore{}
	bc := &connector.BuildConfig{}
	bc.SetRequestHeaderTimeout(250 * time.Millisecond)
	rec := buildTLSStackBuildErrorRecorder(store, nil, "live", bc, silentLogger())
	rec(context.Background(), "example.test:443", realHandshakeTimeoutErr(t, "example.test:443"))
	if len(store.saved) != 1 {
		t.Fatalf("SaveStream count = %d, want 1", len(store.saved))
	}
	st := store.saved[0]
	if st.FailureReason != "client_tls_error" {
		t.Errorf("FailureReason = %q, want client_tls_error", st.FailureReason)
	}
	want := map[string]string{
		"phase":              "tls_handshake",
		"closed_by":          "proxy",
		"timeout":            "request_timeout",
		"request_timeout_ms": "250",
		"target":             "example.test:443",
	}
	for k, v := range want {
		if st.Tags[k] != v {
			t.Errorf("Tags[%q] = %q, want %q", k, st.Tags[k], v)
		}
	}
	if st.Tags["error"] == "" {
		t.Error("Tags[error] is empty")
	}
}

func TestBuildTLSStackBuildErrorRecorder_NonTimeout_NotTagged(t *testing.T) {
	dialErr := func() error {
		d := net.Dialer{Timeout: time.Nanosecond}
		c, err := d.Dial("tcp", "127.0.0.1:1")
		if c != nil {
			_ = c.Close()
		}
		return err
	}()
	if dialErr == nil || !errors.Is(dialErr, context.DeadlineExceeded) {
		t.Fatalf("precondition: 1ns dial error %v does not satisfy errors.Is(context.DeadlineExceeded)", dialErr)
	}
	cases := []struct {
		name       string
		err        error
		wantReason string
	}{
		{
			name:       "certificate rejection",
			err:        fmt.Errorf("%w for x: %w", connector.ErrClientTLSMITMHandshake, errors.New("tlslayer: server handshake: remote error: tls: bad certificate")),
			wantReason: "client_tls_error",
		},
		{
			name:       "upstream dial timeout",
			err:        fmt.Errorf("connector: dial upstream: %w", dialErr),
			wantReason: "upstream_tls_error",
		},
		{
			name:       "client handshake canceled",
			err:        fmt.Errorf("%w for x: %w", connector.ErrClientTLSMITMHandshake, fmt.Errorf("tlslayer: server handshake: %w", context.Canceled)),
			wantReason: "client_tls_error",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &recordingFlowStore{}
			bc := &connector.BuildConfig{}
			bc.SetRequestHeaderTimeout(250 * time.Millisecond)
			rec := buildTLSStackBuildErrorRecorder(store, nil, "live", bc, silentLogger())
			rec(context.Background(), "example.test:443", tc.err)
			if len(store.saved) != 1 {
				t.Fatalf("SaveStream count = %d, want 1", len(store.saved))
			}
			st := store.saved[0]
			if st.FailureReason != tc.wantReason {
				t.Errorf("FailureReason = %q, want %q", st.FailureReason, tc.wantReason)
			}
			for _, k := range usk1189TimeoutTagKeys {
				if v, ok := st.Tags[k]; ok {
					t.Errorf("Tags[%q] = %q, want absent", k, v)
				}
			}
		})
	}
}
