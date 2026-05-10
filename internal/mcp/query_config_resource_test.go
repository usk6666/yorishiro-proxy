package mcp

import (
	"context"
	"encoding/json"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// newTestProxybuildManagerWithBuildConfig is a fixture variant of
// newTestProxybuildManager that binds the given *connector.BuildConfig to
// the resulting Manager (USK-807). The new MaxBodySize / BodySpillThreshold
// / BodySpillDir / WSMaxFrameSize / GRPCMaxMessageSize / SSEMaxEventSize
// / GRPCMaxMessagesPerStream / SSEMaxEventsPerStream accessors read this
// snapshot, so tests that exercise them must use this constructor instead
// of the default fixture (which leaves Manager.buildCfg nil and yields
// zero from every cap accessor).
func newTestProxybuildManagerWithBuildConfig(t *testing.T, buildCfg *connector.BuildConfig) *proxybuild.Manager {
	t.Helper()
	logger := testutil.DiscardLogger()

	if buildCfg.Issuer == nil {
		ca := &cert.CA{}
		if err := ca.Generate(); err != nil {
			t.Fatalf("cert.CA.Generate: %v", err)
		}
		buildCfg.Issuer = cert.NewIssuer(ca)
	}
	if buildCfg.ProxyConfig == nil {
		buildCfg.ProxyConfig = &config.ProxyConfig{}
	}

	factory := func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
		return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
			Logger:       logger,
			ListenerName: name,
			ListenAddr:   addr,
			FlowStore:    noopFixtureFlowWriter{},
			BuildConfig:  buildCfg,
		})
	}

	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:       logger,
		StackFactory: factory,
		BuildConfig:  buildCfg,
	})
	if err != nil {
		t.Fatalf("proxybuild.NewManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.StopAll(context.Background()) })
	return mgr
}

// TestQuery_Config_ProtocolCaps_Populated round-trips queryConfigResult JSON
// when the connector manager exposes non-zero values for every protocol-layer
// cap surfaced by USK-800 (MaxRawCaptureSize) and USK-807 (the remaining
// seven caps). Confirms each snake_case key surfaces with the expected
// value and the populator path inside handleQueryConfig wires every accessor.
func TestQuery_Config_ProtocolCaps_Populated(t *testing.T) {
	t.Parallel()

	const (
		wantMaxBody             int64  = 5 << 20
		wantSpillThreshold      int64  = 7 << 20
		wantSpillDir            string = "/tmp/usk-807-spill"
		wantMaxRaw              int64  = 9 << 20
		wantWSMaxFrame          int64  = 11 << 20
		wantGRPCMaxMessage      uint32 = 13 << 20
		wantSSEMaxEvent         int    = 1 << 20
		wantGRPCMessagesPerStrm int    = 4242
		wantSSEEventsPerStrm    int    = 8484
	)

	buildCfg := &connector.BuildConfig{
		MaxBodySize:              wantMaxBody,
		BodySpillThreshold:       wantSpillThreshold,
		BodySpillDir:             wantSpillDir,
		MaxRawCaptureSize:        wantMaxRaw,
		WSMaxFrameSize:           wantWSMaxFrame,
		GRPCMaxMessageSize:       wantGRPCMaxMessage,
		SSEMaxEventSize:          wantSSEMaxEvent,
		GRPCMaxMessagesPerStream: wantGRPCMessagesPerStrm,
		SSEMaxEventsPerStream:    wantSSEEventsPerStrm,
	}
	manager := newTestProxybuildManagerWithBuildConfig(t, buildCfg)

	ctx := context.Background()
	ca := newTestCA(t)
	store := newTestStore(t)
	s := newServer(ctx, ca, store, manager)

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	result := callQuery(t, cs, queryInput{Resource: "config"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	// Round-trip through queryConfigResult to verify Go-typed values.
	var out queryConfigResult
	unmarshalQueryResult(t, result, &out)
	if out.MaxBodySize != wantMaxBody {
		t.Errorf("MaxBodySize = %d, want %d", out.MaxBodySize, wantMaxBody)
	}
	if out.BodySpillThreshold != wantSpillThreshold {
		t.Errorf("BodySpillThreshold = %d, want %d", out.BodySpillThreshold, wantSpillThreshold)
	}
	if out.BodySpillDir != wantSpillDir {
		t.Errorf("BodySpillDir = %q, want %q", out.BodySpillDir, wantSpillDir)
	}
	if out.MaxRawCaptureSize != wantMaxRaw {
		t.Errorf("MaxRawCaptureSize = %d, want %d", out.MaxRawCaptureSize, wantMaxRaw)
	}
	if out.WSMaxFrameSize != wantWSMaxFrame {
		t.Errorf("WSMaxFrameSize = %d, want %d", out.WSMaxFrameSize, wantWSMaxFrame)
	}
	if out.GRPCMaxMessageSize != wantGRPCMaxMessage {
		t.Errorf("GRPCMaxMessageSize = %d, want %d", out.GRPCMaxMessageSize, wantGRPCMaxMessage)
	}
	if out.SSEMaxEventSize != wantSSEMaxEvent {
		t.Errorf("SSEMaxEventSize = %d, want %d", out.SSEMaxEventSize, wantSSEMaxEvent)
	}
	if out.GRPCMaxMessagesPerStream != wantGRPCMessagesPerStrm {
		t.Errorf("GRPCMaxMessagesPerStream = %d, want %d", out.GRPCMaxMessagesPerStream, wantGRPCMessagesPerStrm)
	}
	if out.SSEMaxEventsPerStream != wantSSEEventsPerStrm {
		t.Errorf("SSEMaxEventsPerStream = %d, want %d", out.SSEMaxEventsPerStream, wantSSEEventsPerStrm)
	}

	// Round-trip through a generic map to verify snake_case JSON keys are
	// present in the wire payload (omitempty did not skip them).
	if len(result.Content) == 0 {
		t.Fatal("result.Content is empty")
	}
	textPart, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(textPart.Text), &raw); err != nil {
		t.Fatalf("unmarshal raw JSON: %v", err)
	}
	for _, key := range []string{
		"max_body_size",
		"body_spill_threshold",
		"body_spill_dir",
		"max_raw_capture_size",
		"ws_max_frame_size",
		"grpc_max_message_size",
		"sse_max_event_size",
		"grpc_max_messages_per_stream",
		"sse_max_events_per_stream",
	} {
		if _, present := raw[key]; !present {
			t.Errorf("expected JSON key %q to be present, raw=%v", key, raw)
		}
	}
}

// TestQuery_Config_ProtocolCaps_OmittedWhenZero confirms `omitempty` works
// for every protocol-layer cap surfaced by USK-800 / USK-807: when the
// underlying BuildConfig fields are all zero / empty, the corresponding
// snake_case keys are omitted from the JSON payload.
func TestQuery_Config_ProtocolCaps_OmittedWhenZero(t *testing.T) {
	t.Parallel()

	// All-zero BuildConfig — every cap accessor returns its zero value.
	buildCfg := &connector.BuildConfig{}
	manager := newTestProxybuildManagerWithBuildConfig(t, buildCfg)

	ctx := context.Background()
	ca := newTestCA(t)
	store := newTestStore(t)
	s := newServer(ctx, ca, store, manager)

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	result := callQuery(t, cs, queryInput{Resource: "config"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	if len(result.Content) == 0 {
		t.Fatal("result.Content is empty")
	}
	textPart, ok := result.Content[0].(*gomcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(textPart.Text), &raw); err != nil {
		t.Fatalf("unmarshal raw JSON: %v", err)
	}
	for _, key := range []string{
		"max_body_size",
		"body_spill_threshold",
		"body_spill_dir",
		"max_raw_capture_size",
		"ws_max_frame_size",
		"grpc_max_message_size",
		"sse_max_event_size",
		"grpc_max_messages_per_stream",
		"sse_max_events_per_stream",
	} {
		if _, present := raw[key]; present {
			t.Errorf("expected JSON key %q to be OMITTED for zero value, raw[%q]=%v", key, key, raw[key])
		}
	}
}

// TestQuery_Config_TLSFingerprint_BootValue is the USK-809 regression for
// the "query config always returns chrome" display bug: when the bound
// BuildConfig has a non-default TLSFingerprint set at boot, query config
// must surface that value rather than the literal "chrome" fallback the
// pre-fix currentTLSFingerprint() emitted whenever no test-only setter
// was injected (the production wiring path).
func TestQuery_Config_TLSFingerprint_BootValue(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		want string
	}{
		{"firefox", "firefox"},
		{"safari", "safari"},
		{"none", "none"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			buildCfg := &connector.BuildConfig{TLSFingerprint: tc.want}
			manager := newTestProxybuildManagerWithBuildConfig(t, buildCfg)

			ctx := context.Background()
			ca := newTestCA(t)
			store := newTestStore(t)
			s := newServer(ctx, ca, store, manager)

			ct, st := gomcp.NewInMemoryTransports()
			ss, err := s.server.Connect(ctx, st, nil)
			if err != nil {
				t.Fatalf("server connect: %v", err)
			}
			t.Cleanup(func() { ss.Close() })

			client := gomcp.NewClient(&gomcp.Implementation{Name: "test", Version: "v0.0.1"}, nil)
			cs, err := client.Connect(ctx, ct, nil)
			if err != nil {
				t.Fatalf("client connect: %v", err)
			}
			t.Cleanup(func() { cs.Close() })

			result := callQuery(t, cs, queryInput{Resource: "config"})
			if result.IsError {
				t.Fatalf("expected success, got error: %v", result.Content)
			}

			var out queryConfigResult
			unmarshalQueryResult(t, result, &out)
			if out.TLSFingerprint != tc.want {
				t.Errorf("tls_fingerprint = %q, want %q (display path must read from BuildConfig, not literal chrome fallback)",
					out.TLSFingerprint, tc.want)
			}
		})
	}
}

// TestQuery_Config_TLSFingerprint_RuntimeOverride_ViaBuildConfig is the
// USK-809 regression for the live-wire mutation gap: a runtime
// SetTLSFingerprint call (the wiring proxy_start / configure relies on)
// must be reflected in subsequent query config reads.
func TestQuery_Config_TLSFingerprint_RuntimeOverride_ViaBuildConfig(t *testing.T) {
	t.Parallel()

	// Boot-time fingerprint is "chrome" — the pre-fix default. After
	// BuildConfig.SetTLSFingerprint("firefox") (the runtime wiring used
	// by Manager.SetTLSFingerprint), query config must surface "firefox",
	// not the boot value.
	buildCfg := &connector.BuildConfig{TLSFingerprint: "chrome"}
	manager := newTestProxybuildManagerWithBuildConfig(t, buildCfg)

	// Install the runtime override the same way applyTLSFingerprint
	// would in production (Manager.SetTLSFingerprint -> BuildConfig).
	manager.SetTLSFingerprint("firefox")

	ctx := context.Background()
	ca := newTestCA(t)
	store := newTestStore(t)
	s := newServer(ctx, ca, store, manager)

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	result := callQuery(t, cs, queryInput{Resource: "config"})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryConfigResult
	unmarshalQueryResult(t, result, &out)
	if out.TLSFingerprint != "firefox" {
		t.Errorf("tls_fingerprint = %q, want firefox (runtime override must be visible to display path)",
			out.TLSFingerprint)
	}

	// Clear the override and confirm the boot value re-emerges — the
	// override is layered on top, not destructive.
	manager.SetTLSFingerprint("")

	result = callQuery(t, cs, queryInput{Resource: "config"})
	if result.IsError {
		t.Fatalf("expected success on second query, got error: %v", result.Content)
	}
	unmarshalQueryResult(t, result, &out)
	if out.TLSFingerprint != "chrome" {
		t.Errorf("after clear, tls_fingerprint = %q, want chrome (boot fallback)",
			out.TLSFingerprint)
	}
}
