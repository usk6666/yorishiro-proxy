package proxybuild

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func transparentUnitDeps(t *testing.T, addr string, r connector.OriginalDstResolver) (Deps, *testutil.CaptureLogger) {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	logs, logger := testutil.NewCaptureLogger()
	return Deps{
		Logger:     logger,
		ListenAddr: addr,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig: &config.ProxyConfig{},
			Issuer:      cert.NewIssuer(ca),
		},
		TransparentMode:        config.TransparentModeRedirect,
		TransparentPeekTimeout: 50 * time.Millisecond,
		OriginalDstResolver:    r,
	}, logs
}

// startTransparentUnitStack builds and starts a transparent Stack.
func startTransparentUnitStack(t *testing.T, addr string, r connector.OriginalDstResolver) (*Stack, *testutil.CaptureLogger) {
	t.Helper()
	deps, logs := transparentUnitDeps(t, addr, r)
	stack, err := BuildLiveStack(context.Background(), deps)
	if err != nil {
		t.Fatalf("BuildLiveStack: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = stack.Listener.Start(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	select {
	case <-stack.Listener.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("listener not ready")
	}
	return stack, logs
}

// T21: transparent mode on a platform without REDIRECT support is a
// BuildLiveStack error; an unknown mode is too.
func TestBuildLiveStack_Transparent_UnsupportedPlatform(t *testing.T) {
	prev := transparentSupported
	transparentSupported = func() bool { return false }
	defer func() { transparentSupported = prev }()

	deps, _ := transparentUnitDeps(t, "127.0.0.1:0", nil)
	_, err := BuildLiveStack(context.Background(), deps)
	if err == nil || !errors.Is(err, errors.ErrUnsupported) || !strings.Contains(err.Error(), "Linux") {
		t.Fatalf("BuildLiveStack = %v, want an ErrUnsupported error mentioning Linux", err)
	}
}

func TestBuildLiveStack_Transparent_UnknownMode(t *testing.T) {
	deps, _ := transparentUnitDeps(t, "127.0.0.1:0", connector.OriginalDstFunc(func(net.Conn) (netip.AddrPort, error) {
		return netip.AddrPort{}, nil
	}))
	deps.TransparentMode = "tproxy"
	if _, err := BuildLiveStack(context.Background(), deps); err == nil || !strings.Contains(err.Error(), "transparent") {
		t.Fatalf("BuildLiveStack = %v, want an error naming the transparent mode", err)
	}
}

// The Manager forwards ListenerOptions to the factory and reports the
// mode in ListenerStatus.
func TestManager_StartNamedWithOptions_Transparent(t *testing.T) {
	var gotOpts ListenerOptions
	mgr, err := NewManager(ManagerConfig{
		Logger: testutil.DiscardLogger(),
		StackFactory: func(context.Context, string, string) (*Stack, error) {
			return nil, errors.New("StackFactory must not be used when StackFactoryWithOptions is set")
		},
		StackFactoryWithOptions: func(ctx context.Context, name, addr string, opts ListenerOptions) (*Stack, error) {
			gotOpts = opts
			deps, _ := transparentUnitDeps(t, addr, connector.OriginalDstFunc(func(net.Conn) (netip.AddrPort, error) {
				return netip.AddrPort{}, errors.New("unused")
			}))
			deps.ListenerName = name
			deps.TransparentMode = opts.TransparentMode
			deps.TransparentPeekTimeout = opts.TransparentPeekTimeout
			return BuildLiveStack(ctx, deps)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	opts := ListenerOptions{TransparentMode: config.TransparentModeRedirect, TransparentPeekTimeout: 250 * time.Millisecond}
	if err := mgr.StartNamedWithOptions(context.Background(), "gw", "127.0.0.1:0", opts); err != nil {
		t.Fatalf("StartNamedWithOptions: %v", err)
	}
	defer func() { _ = mgr.StopAll(context.Background()) }()
	if gotOpts != opts {
		t.Errorf("factory got %+v, want %+v", gotOpts, opts)
	}
	st := mgr.ListenerStatuses()
	if len(st) != 1 || st[0].TransparentMode != config.TransparentModeRedirect {
		t.Errorf("ListenerStatuses = %+v, want transparent_mode redirect", st)
	}
}

func TestManager_StartNamedWithOptions_RefusesOptionsWithoutFactory(t *testing.T) {
	mgr, err := NewManager(ManagerConfig{
		Logger: testutil.DiscardLogger(),
		StackFactory: func(context.Context, string, string) (*Stack, error) {
			return nil, errors.New("not called")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = mgr.StartNamedWithOptions(context.Background(), "gw", "127.0.0.1:0", ListenerOptions{TransparentMode: config.TransparentModeRedirect})
	if err == nil || !strings.Contains(err.Error(), "transparent") {
		t.Fatalf("StartNamedWithOptions = %v, want an error about the unsupported options", err)
	}
}
