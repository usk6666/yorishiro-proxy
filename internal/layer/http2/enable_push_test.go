package http2

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// syncBuffer wraps bytes.Buffer with a mutex so the slog handler
// (driven from the reader goroutine) and the test goroutine can
// safely interleave Write / String calls under -race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// waitForLog polls buf until it contains substr or a 2-second deadline
// elapses. The handleGoAwayFrame log emission is on a separate reader
// goroutine, so a deterministic poll is preferable to a fixed sleep.
func waitForLog(t *testing.T, buf *syncBuffer, substr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), substr) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waitForLog: %q not observed within 2s; buf=%q", substr, buf.String())
}

// TestApplyEnablePushDefault validates the role-conditional default helper
// in isolation. Mirrors TestSettings_Apply table-driven style.
//
// USK-820: A client that sends SETTINGS_ENABLE_PUSH=1 violates RFC 9113
// §6.5.2 ("A client MUST send a value of 0"). DefaultSettings() seeds 1
// for the legacy non-zero default; applyEnablePushDefault must downshift
// that to 0 for ClientRole.
//
// USK-825: RFC 9113 §7.2.2 forbids servers from explicitly setting the
// value ("Servers MUST NOT explicitly set this value"). The wire-level
// fix is in settingsToFrame, which omits SETTINGS_ENABLE_PUSH from the
// initial SETTINGS for ServerRole; this helper additionally zeros the
// in-memory value for state hygiene so LocalSettings() matches the wire.
// Post-USK-823 (server-push recording retired) no caller legitimately
// advertises ENABLE_PUSH=1 from either role.
func TestApplyEnablePushDefault(t *testing.T) {
	tests := []struct {
		name string
		role Role
		// in is the EnablePush value loaded into Settings before the helper
		// runs. The helper unconditionally normalizes to 0 for both roles
		// — there is no legitimate way to bypass RFC 9113 §6.5.2 / §7.2.2.
		in   uint32
		want uint32
	}{
		// ServerRole: USK-825 forces 0 for state hygiene; the wire-side
		// omission is enforced by settingsToFrame.
		{"server_role_forces_1_to_0", ServerRole, 1, 0},
		{"server_role_keeps_0", ServerRole, 0, 0},
		// ClientRole: forced to 0 regardless of input. RFC 9113 §6.5.2
		// requires this; strict upstreams (httpbin GFE, nghttp2-server)
		// reply with GOAWAY(PROTOCOL_ERROR) otherwise (USK-820).
		{"client_role_forces_1_to_0", ClientRole, 1, 0},
		{"client_role_keeps_0", ClientRole, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Settings{EnablePush: tt.in}
			applyEnablePushDefault(&s, tt.role)
			if s.EnablePush != tt.want {
				t.Errorf("applyEnablePushDefault(role=%s, in=%d): EnablePush = %d, want %d",
					tt.role, tt.in, s.EnablePush, tt.want)
			}
		})
	}
}

// TestSettingsToFrame_EnablePush_PerRole drives the full New() boot through a
// pipe-backed peer and asserts the wire SETTINGS frame's ENABLE_PUSH presence
// and value are correct for each role.
//
// USK-820: ClientRole used to emit ENABLE_PUSH=1, which strict h2 servers
// (Google Frontend, nghttp2-server) reject with GOAWAY(PROTOCOL_ERROR) per
// RFC 9113 §6.5.2. ClientRole now emits ENABLE_PUSH=0.
//
// USK-825: ServerRole used to emit ENABLE_PUSH=1 (the legacy seeded default),
// which strict h2 clients (curl, Chrome, golang.org/x/net/http2) reject with
// GOAWAY(PROTOCOL_ERROR) per RFC 9113 §7.2.2 ("Servers MUST NOT explicitly
// set this value"). ServerRole now omits SETTINGS_ENABLE_PUSH from the
// initial SETTINGS frame entirely.
func TestSettingsToFrame_EnablePush_PerRole(t *testing.T) {
	tests := []struct {
		name string
		// start launches the layer in the desired role and returns the wire-
		// observed initial SETTINGS params from the peer. Mirrors the helper
		// pattern used by TestLayer_*_AdvertisesEnableConnectProtocol.
		start func(*testing.T) []frame.Setting
		// wantPresent is true when SETTINGS_ENABLE_PUSH must appear on the
		// wire. ServerRole omits the setting entirely per RFC 9113 §7.2.2.
		wantPresent bool
		// wantValue is the expected emitted value when wantPresent is true.
		wantValue uint32
	}{
		{
			name: "server_role_omits_enable_push",
			start: func(t *testing.T) []frame.Setting {
				_, peer, cleanup := startServerLayer(t)
				t.Cleanup(cleanup)
				return readInitialSettings(t, peer)
			},
			// RFC 9113 §7.2.2: "Servers MUST NOT explicitly set this value."
			// Strict h2 clients treat any emitted value (including 1, the
			// pre-USK-825 default) as PROTOCOL_ERROR. ServerRole omits the
			// setting entirely.
			wantPresent: false,
		},
		{
			name: "client_role_advertises_push_0",
			start: func(t *testing.T) []frame.Setting {
				_, peer, cleanup := startClientLayer(t)
				t.Cleanup(cleanup)
				return readInitialSettings(t, peer)
			},
			// ClientRole MUST advertise 0 per RFC 9113 §6.5.2 (USK-820).
			wantPresent: true,
			wantValue:   0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := tt.start(t)
			v, ok := findSetting(params, frame.SettingEnablePush)
			if tt.wantPresent {
				if !ok {
					t.Fatalf("initial SETTINGS missing ENABLE_PUSH; got %+v", params)
				}
				if v != tt.wantValue {
					t.Errorf("ENABLE_PUSH = %d, want %d (role default mismatch)", v, tt.wantValue)
				}
				return
			}
			// wantPresent == false: ServerRole must omit the setting.
			if ok {
				t.Errorf("initial SETTINGS contains ENABLE_PUSH=%d, want absent (RFC 9113 §7.2.2, USK-825); got %+v",
					v, params)
			}
		})
	}
}

// TestClientRole_WithInitialSettings_EnablePushOverride_DowngradedToZero
// exercises the safety net: even if a caller passes WithInitialSettings
// with EnablePush=1, the ClientRole boot path must still downshift it to
// 0 before sending the preface SETTINGS. This locks the helper's
// "unconditional rewrite for ClientRole" contract — the only escape
// hatch is to not be in ClientRole.
func TestClientRole_WithInitialSettings_EnablePushOverride_DowngradedToZero(t *testing.T) {
	custom := DefaultSettings()
	custom.EnablePush = 1 // attempt to bypass the role default
	_, peer, cleanup := startClientLayer(t, WithInitialSettings(custom))
	defer cleanup()

	params := readInitialSettings(t, peer)
	v, ok := findSetting(params, frame.SettingEnablePush)
	if !ok {
		t.Fatalf("ClientRole initial SETTINGS missing ENABLE_PUSH; got %+v", params)
	}
	if v != 0 {
		t.Errorf("ClientRole ENABLE_PUSH = %d, want 0 (WithInitialSettings must not bypass role default)", v)
	}
}

// TestServerRole_WithInitialSettings_EnablePushOverride_Omitted is the
// USK-825 ServerRole companion to the ClientRole override test above.
// Even if a caller passes WithInitialSettings{EnablePush: 1} (the
// pre-USK-825 default seeded by DefaultSettings()), the ServerRole boot
// path must omit SETTINGS_ENABLE_PUSH from the initial SETTINGS frame
// entirely per RFC 9113 §7.2.2 ("Servers MUST NOT explicitly set this
// value"). Strict h2 clients reject any emitted value with
// GOAWAY(PROTOCOL_ERROR); there is no legitimate caller-driven escape
// hatch.
func TestServerRole_WithInitialSettings_EnablePushOverride_Omitted(t *testing.T) {
	custom := DefaultSettings()
	custom.EnablePush = 1 // attempt to bypass the role default
	_, peer, cleanup := startServerLayer(t, WithInitialSettings(custom))
	defer cleanup()

	params := readInitialSettings(t, peer)
	if v, ok := findSetting(params, frame.SettingEnablePush); ok {
		t.Errorf("ServerRole initial SETTINGS contains ENABLE_PUSH=%d, want absent (RFC 9113 §7.2.2, USK-825); got %+v",
			v, params)
	}
}

// TestHandleGoAwayFrame_LogsErrCodeAndDebugData verifies the USK-820
// observability fix: when a peer sends GOAWAY, the upstream-provided
// errCode and debugData must surface in the logs (previously discarded
// with `_, _, _`). This is the diagnostic surface that would have caught
// the SETTINGS_ENABLE_PUSH=1 regression in a release cycle instead of
// requiring a packet capture to confirm.
func TestHandleGoAwayFrame_LogsErrCodeAndDebugData(t *testing.T) {
	// Capture slog.Default() output by swapping in a buffer-backed handler.
	buf := &syncBuffer{}
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(prev)

	// Drive a ClientRole layer so we exercise the same code path the live
	// proxy upstream uses. Send a GOAWAY with PROTOCOL_ERROR + debug data
	// from the peer; assert the layer logged the structured fields.
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()

	// Drain the layer's initial SETTINGS / WINDOW_UPDATE so a subsequent
	// peer GOAWAY is the next frame the layer's reader sees.
	_ = readInitialSettings(t, peer)

	const debugData = "ENABLE_PUSH must be 0 from a client"
	if err := peer.wr.WriteGoAway(0, ErrCodeProtocol, []byte(debugData)); err != nil {
		t.Fatalf("peer.WriteGoAway: %v", err)
	}

	// Poll for the log line so the test stays deterministic without a fixed sleep.
	waitForLog(t, buf, "http2: peer sent GOAWAY")
	_ = l // keep handle alive until we've inspected the log buffer

	got := buf.String()
	wantSubstrings := []string{
		"http2: peer sent GOAWAY",
		`err_code_name=PROTOCOL_ERROR`,
		`err_code=1`,
		"debug_data=" + `"` + debugData + `"`,
	}
	for _, sub := range wantSubstrings {
		if !strings.Contains(got, sub) {
			t.Errorf("GOAWAY log missing %q\n--- log ---\n%s", sub, got)
		}
	}
}

// TestHandleGoAwayFrame_LogsErrCodeName_NoErrorCase exercises the
// graceful-shutdown branch (ErrCodeNo). Even for benign GOAWAYs the
// log surface should be structured — operators rely on the warn-level
// signal to spot signs of upstream resource exhaustion.
func TestHandleGoAwayFrame_LogsErrCodeName_NoErrorCase(t *testing.T) {
	buf := &syncBuffer{}
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(prev)

	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	_ = readInitialSettings(t, peer)

	if err := peer.wr.WriteGoAway(0, ErrCodeNo, nil); err != nil {
		t.Fatalf("peer.WriteGoAway: %v", err)
	}

	waitForLog(t, buf, "http2: peer sent GOAWAY")
	_ = l

	got := buf.String()
	if !strings.Contains(got, `err_code_name=NO_ERROR`) {
		t.Errorf("expected err_code_name=NO_ERROR in log, got:\n%s", got)
	}
	// debug_data was nil → must not be emitted at all.
	if strings.Contains(got, "debug_data=") {
		t.Errorf("debug_data= should be omitted when peer sent no debug payload, got:\n%s", got)
	}
}
