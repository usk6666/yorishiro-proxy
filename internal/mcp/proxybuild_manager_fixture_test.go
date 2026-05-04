package mcp

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// newTestProxybuildManager constructs a *proxybuild.Manager backed by the
// production BuildLiveStack factory with a minimal Deps recipe (mirrors
// cmd/yorishiro-proxy/main.go::newLiveBuildConfig + newLiveManager). The
// factory is wired so MCP tools that call StartNamed observe a real
// listener lifecycle; tests that never call Start pay only the
// construction cost. The manager's StopAll is registered with t.Cleanup
// so callers do not need to wire teardown manually.
func newTestProxybuildManager(t *testing.T) *proxybuild.Manager {
	t.Helper()
	return newTestProxybuildManagerWithStore(t, nil)
}

// newTestProxybuildManagerWithStore is the explicit-store form. Tests
// that build a real flow.Writer (typically a SQLite store for
// integration-style assertions) pass it in here so the proxybuild Stack
// records flows into that store. nil store yields the no-op fixture
// store; tests that never trigger recording need not pass anything.
func newTestProxybuildManagerWithStore(t *testing.T, store flow.Writer) *proxybuild.Manager {
	t.Helper()
	logger := testutil.DiscardLogger()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("cert.CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	fs := store
	if fs == nil {
		fs = noopFixtureFlowWriter{}
	}

	factory := func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
		return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
			Logger:       logger,
			ListenerName: name,
			ListenAddr:   addr,
			FlowStore:    fs,
			BuildConfig:  buildCfg,
		})
	}

	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:       logger,
		StackFactory: factory,
	})
	if err != nil {
		t.Fatalf("proxybuild.NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	return mgr
}

// noopFixtureFlowWriter satisfies flow.Writer with no-op implementations
// for tests that only need the proxybuild Stack to construct without
// exercising recording.
type noopFixtureFlowWriter struct{}

func (noopFixtureFlowWriter) SaveFlow(_ context.Context, _ *flow.Flow) error     { return nil }
func (noopFixtureFlowWriter) SaveStream(_ context.Context, _ *flow.Stream) error { return nil }
func (noopFixtureFlowWriter) UpdateStream(_ context.Context, _ string, _ flow.StreamUpdate) error {
	return nil
}
