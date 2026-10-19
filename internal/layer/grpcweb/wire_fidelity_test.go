package grpcweb

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// USK-1219 (⊇ USK-1062), USK-1069 (⊇ USK-1110) and the empty-body
// delivery gap: the gRPC-Web Layer sits between two HTTP legs, so every
// test here drives the real relay shape — one Layer's Next feeding the
// opposite-role Layer's Send — and asserts what the next hop would see.

// relay drains every envelope the nextRole Layer emits for in, lets mutate
// edit them (an Intercept / Transform / plugin Step stand-in), pushes them
// through a fresh sendRole Layer, and returns the single HTTPMessage that
// Layer handed to its inner Channel.
func relay(
	t *testing.T,
	in *envelope.Envelope,
	nextRole, sendRole Role,
	mutate func(envs []*envelope.Envelope) []*envelope.Envelope,
	opts ...Option,
) *envelope.HTTPMessage {
	t.Helper()
	src := newMockChannel(in.StreamID, in)
	next := Wrap(src, nextRole, opts...)
	defer next.Close()
	envs := drainEnvelopes(t, next, 16)
	if len(envs) == 0 {
		t.Fatal("relay: the Next side emitted no envelopes")
	}
	if mutate != nil {
		envs = mutate(envs)
	}
	dst := newMockChannel(in.StreamID)
	send := Wrap(dst, sendRole)
	defer send.Close()
	return sendAll(t, send, dst, envs...)
}

// startOf returns the Start message of an emitted envelope sequence.
func startOf(t *testing.T, envs []*envelope.Envelope) *envelope.GRPCStartMessage {
	t.Helper()
	sm, ok := envs[0].Message.(*envelope.GRPCStartMessage)
	if !ok {
		t.Fatalf("envs[0] = %T, want *GRPCStartMessage", envs[0].Message)
	}
	return sm
}

// responseEnv is mustHTTPResponseEnv with an explicit reason phrase.
func responseEnv(headers []envelope.KeyValue, body []byte, status int, reason string) *envelope.Envelope {
	env := mustHTTPResponseEnv("s-fid", headers, body, status)
	env.Message.(*envelope.HTTPMessage).StatusReason = reason
	return env
}

// requestEnv is mustHTTPRequestEnv with an explicit RawQuery.
func requestEnv(headers []envelope.KeyValue, body []byte, path, rawQuery string) *envelope.Envelope {
	env := mustHTTPRequestEnv("s-fid", headers, body, path)
	env.Message.(*envelope.HTTPMessage).RawQuery = rawQuery
	return env
}

// validResponseBody is one data LPM plus a grpc-status: 0 trailer LPM.
func validResponseBody() []byte {
	body := append([]byte{}, EncodeFrame(false, false, []byte("resp"))...)
	return append(body, EncodeFrame(true, false, []byte("grpc-status: 0\r\n"))...)
}

// withoutContentLength drops Content-Length entries, which
// reconcileBodyFraming (USK-1203) legitimately owns.
func withoutContentLength(kvs []envelope.KeyValue) []envelope.KeyValue {
	var out []envelope.KeyValue
	for _, kv := range kvs {
		if strings.EqualFold(kv.Name, "content-length") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// --- T1: the upstream HTTP status reaches the client side ---

func TestRelay_ResponseStatusReachesClient(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		reason     string
		headers    []envelope.KeyValue
		body       []byte
		wantStatus int
		wantReason string
	}{
		{
			name:       "503_with_valid_frames",
			status:     503,
			reason:     "Service Unavailable",
			headers:    []envelope.KeyValue{{Name: "Content-Type", Value: "application/grpc-web+proto"}},
			body:       validResponseBody(),
			wantStatus: 503,
			wantReason: "Service Unavailable",
		},
		{
			// A non-gRPC body fails LPM parsing and takes the
			// emitAnomalyStart passthrough; the status must ride along.
			name:       "404_non_grpc_body_passthrough",
			status:     404,
			reason:     "Not Found",
			headers:    []envelope.KeyValue{{Name: "Content-Type", Value: "text/plain"}},
			body:       []byte("Service Unavailable"),
			wantStatus: 404,
			wantReason: "Not Found",
		},
		{
			name:       "200_ok",
			status:     200,
			reason:     "OK",
			headers:    []envelope.KeyValue{{Name: "Content-Type", Value: "application/grpc-web+proto"}},
			body:       validResponseBody(),
			wantStatus: 200,
			wantReason: "OK",
		},
		{
			// HTTP/2 has no reason phrase; an empty one is left empty
			// (the HTTP/1.x synthetic send path fills it from statusText).
			name:       "502_from_h2_without_reason",
			status:     502,
			reason:     "",
			headers:    []envelope.KeyValue{{Name: "content-type", Value: "application/grpc-web+proto"}},
			body:       validResponseBody(),
			wantStatus: 502,
			wantReason: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := responseEnv(tt.headers, tt.body, tt.status, tt.reason)
			var gotStart *envelope.GRPCStartMessage
			out := relay(t, in, RoleClient, RoleServer, func(envs []*envelope.Envelope) []*envelope.Envelope {
				gotStart = startOf(t, envs)
				return envs
			})
			if gotStart.HTTPStatus != tt.wantStatus || gotStart.HTTPStatusReason != tt.wantReason {
				t.Errorf("Start overlay = (%d, %q), want (%d, %q)",
					gotStart.HTTPStatus, gotStart.HTTPStatusReason, tt.wantStatus, tt.wantReason)
			}
			if out.Status != tt.wantStatus || out.StatusReason != tt.wantReason {
				t.Errorf("client-side HTTPMessage status = (%d, %q), want (%d, %q)",
					out.Status, out.StatusReason, tt.wantStatus, tt.wantReason)
			}
		})
	}
}

// TestRelay_SyntheticStartWithoutStatusEmits200 pins R3: a Start whose
// HTTPStatus was never set (a synthetic / test producer) is written as
// 200 OK rather than "0 Unknown" / :status 0.
func TestRelay_SyntheticStartWithoutStatusEmits200(t *testing.T) {
	dst := newMockChannel("s-syn")
	send := Wrap(dst, RoleServer)
	defer send.Close()
	out := sendAll(t, send, dst,
		&envelope.Envelope{StreamID: "s-syn", Direction: envelope.Receive, Protocol: envelope.ProtocolGRPCWeb,
			Message: &envelope.GRPCStartMessage{ContentType: "application/grpc-web+proto"}},
		&envelope.Envelope{StreamID: "s-syn", Direction: envelope.Receive, Protocol: envelope.ProtocolGRPCWeb,
			Message: &envelope.GRPCEndMessage{}},
	)
	if out.Status != 200 || out.StatusReason != "OK" {
		t.Errorf("status = (%d, %q), want (200, \"OK\")", out.Status, out.StatusReason)
	}
}

// --- T2: control-header layout round-trips in both directions ---

func TestRelay_ControlHeaderLayoutRoundTrip(t *testing.T) {
	frame := EncodeFrame(false, false, []byte("ping"))
	tests := []struct {
		name    string
		request bool
		headers []envelope.KeyValue
		body    []byte
	}{
		{
			name:    "request_casing_position_and_raw_values",
			request: true,
			headers: []envelope.KeyValue{
				{Name: "Host", Value: "api.example"},
				{Name: "X-Before", Value: "1"},
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
				{Name: "Grpc-Timeout", Value: "5S"},
				{Name: "grpc-accept-encoding", Value: "gzip, identity"},
				{Name: "X-After", Value: "2"},
			},
			body: frame,
		},
		{
			name:    "request_duplicate_content_type",
			request: true,
			headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
				{Name: "X-Mid", Value: "1"},
				{Name: "content-type", Value: "application/grpc-web-text"},
			},
			body: frame,
		},
		{
			name:    "request_malformed_timeout_kept",
			request: true,
			headers: []envelope.KeyValue{
				{Name: "X-First", Value: "1"},
				{Name: "Grpc-Timeout", Value: "soon"},
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
			},
			body: frame,
		},
		{
			name:    "request_control_headers_last",
			request: true,
			headers: []envelope.KeyValue{
				{Name: "X-A", Value: "1"},
				{Name: "X-B", Value: "2"},
				{Name: "GRPC-ENCODING", Value: " identity "},
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
			},
			body: frame,
		},
		{
			name: "response_casing_and_position",
			headers: []envelope.KeyValue{
				{Name: "X-First", Value: "1"},
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
				{Name: "Grpc-Encoding", Value: "identity"},
				{Name: "X-Last", Value: "2"},
			},
			body: validResponseBody(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var in *envelope.Envelope
			nextRole, sendRole := RoleClient, RoleServer
			if tt.request {
				in = requestEnv(tt.headers, tt.body, "/pkg.Svc/Do", "")
				nextRole, sendRole = RoleServer, RoleClient
			} else {
				in = responseEnv(tt.headers, tt.body, 200, "OK")
			}
			out := relay(t, in, nextRole, sendRole, nil)
			got := withoutContentLength(out.Headers)
			if !kvEqual(got, tt.headers) {
				t.Errorf("headers not round-tripped:\n got  %v\n want %v", got, tt.headers)
			}
		})
	}
}

// --- T3: structured edits rewrite in place; Clone falls back ---

func TestRelay_ControlHeaderFieldEdits(t *testing.T) {
	frame := EncodeFrame(false, false, []byte("ping"))
	observed := []envelope.KeyValue{
		{Name: "Host", Value: "api.example"},
		{Name: "X-Before", Value: "1"},
		{Name: "Content-Type", Value: "application/grpc-web+proto"},
		{Name: "Grpc-Encoding", Value: "identity"},
		{Name: "X-After", Value: "2"},
	}
	tests := []struct {
		name   string
		mutate func(t *testing.T, envs []*envelope.Envelope) []*envelope.Envelope
		want   []envelope.KeyValue
	}{
		{
			name: "content_type_changed_rewritten_in_place",
			mutate: func(t *testing.T, envs []*envelope.Envelope) []*envelope.Envelope {
				startOf(t, envs).ContentType = "application/grpc-web+json"
				return envs
			},
			want: []envelope.KeyValue{
				{Name: "Host", Value: "api.example"},
				{Name: "X-Before", Value: "1"},
				{Name: "Content-Type", Value: "application/grpc-web+json"},
				{Name: "Grpc-Encoding", Value: "identity"},
				{Name: "X-After", Value: "2"},
			},
		},
		{
			name: "encoding_cleared_entry_dropped",
			mutate: func(t *testing.T, envs []*envelope.Envelope) []*envelope.Envelope {
				startOf(t, envs).Encoding = ""
				return envs
			},
			want: []envelope.KeyValue{
				{Name: "Host", Value: "api.example"},
				{Name: "X-Before", Value: "1"},
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
				{Name: "X-After", Value: "2"},
			},
		},
		{
			name: "timeout_newly_set_synthesized_at_front",
			mutate: func(t *testing.T, envs []*envelope.Envelope) []*envelope.Envelope {
				startOf(t, envs).Timeout = time.Second
				return envs
			},
			want: []envelope.KeyValue{
				{Name: "grpc-timeout", Value: "1000m"},
				{Name: "Host", Value: "api.example"},
				{Name: "X-Before", Value: "1"},
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
				{Name: "Grpc-Encoding", Value: "identity"},
				{Name: "X-After", Value: "2"},
			},
		},
		{
			name: "metadata_replaced_anchors_clamp",
			mutate: func(t *testing.T, envs []*envelope.Envelope) []*envelope.Envelope {
				startOf(t, envs).Metadata = []envelope.KeyValue{{Name: "X-Only", Value: "z"}}
				return envs
			},
			want: []envelope.KeyValue{
				{Name: "X-Only", Value: "z"},
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
				{Name: "Grpc-Encoding", Value: "identity"},
			},
		},
		{
			// env.Clone drops Opaque (Envelope.Clone: "Opaque
			// intentionally not cloned"), which is what an intercept
			// modify produces; the layout falls back to the synthesized
			// form, same as the http1 synthetic send path.
			name: "clone_falls_back_to_synthesized_layout",
			mutate: func(t *testing.T, envs []*envelope.Envelope) []*envelope.Envelope {
				clone := envs[0].Clone()
				if clone.Opaque != nil {
					t.Fatal("precondition: Envelope.Clone must drop Opaque")
				}
				envs[0] = clone
				return envs
			},
			want: []envelope.KeyValue{
				{Name: "content-type", Value: "application/grpc-web+proto"},
				{Name: "grpc-encoding", Value: "identity"},
				{Name: "Host", Value: "api.example"},
				{Name: "X-Before", Value: "1"},
				{Name: "X-After", Value: "2"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := requestEnv(observed, frame, "/pkg.Svc/Do", "")
			out := relay(t, in, RoleServer, RoleClient, func(envs []*envelope.Envelope) []*envelope.Envelope {
				return tt.mutate(t, envs)
			})
			got := withoutContentLength(out.Headers)
			if !kvEqual(got, tt.want) {
				t.Errorf("headers:\n got  %v\n want %v", got, tt.want)
			}
		})
	}
}

// --- T4: :path / query round-trip invariant (USK-1069 / USK-1110) ---

// TestRelay_SendStartPathRoundTrip mirrors the native gRPC Layer's
// TestChannel_SendStartPathRoundTrip (USK-1053): the observed (Path,
// RawQuery) pair must reach the next hop byte-identically unless the
// derived Service/Method view was edited on a parseable :path. The join
// of Path and RawQuery belongs to the inner HTTP Layer, so the pair is
// asserted separately.
func TestRelay_SendStartPathRoundTrip(t *testing.T) {
	cases := []struct {
		name         string
		path         string
		rawQuery     string
		mutate       func(*envelope.GRPCStartMessage)
		wantPath     string
		wantRawQuery string
	}{
		{name: "well_formed", path: "/pkg.Svc/Do", wantPath: "/pkg.Svc/Do"},
		{name: "query_carried", path: "/pkg.Svc/Do", rawQuery: "trace=1&x=%27", wantPath: "/pkg.Svc/Do", wantRawQuery: "trace=1&x=%27"},
		{name: "no_inner_slash", path: "/NoSlash", wantPath: "/NoSlash"},
		{name: "no_leading_slash", path: "noslash", wantPath: "noslash"},
		{name: "no_leading_slash_two_segments", path: "svc/M", wantPath: "svc/M"},
		{name: "leading_double_slash", path: "//Do", wantPath: "//Do"},
		{name: "trailing_slash", path: "/pkg.Svc/Do/", wantPath: "/pkg.Svc/Do/"},
		{name: "multi_slash", path: "/a/b/c", wantPath: "/a/b/c"},
		{name: "leading_double_slash_two_segments", path: "//pkg/Do", wantPath: "//pkg/Do"},
		{name: "empty_path_rebuilds_root", path: "", wantPath: "/"},
		{
			name: "override_on_parseable_path",
			path: "/pkg.Svc/Do", rawQuery: "q=1",
			mutate: func(m *envelope.GRPCStartMessage) {
				m.Service = "new.Svc"
				m.Method = "NewDo"
			},
			wantPath: "/new.Svc/NewDo", wantRawQuery: "q=1",
		},
		{
			name: "override_on_unparseable_path_keeps_wire",
			path: "/NoSlash",
			mutate: func(m *envelope.GRPCStartMessage) {
				m.Service = "new.Svc"
				m.Method = "NewDo"
			},
			wantPath: "/NoSlash",
		},
	}
	frame := EncodeFrame(false, false, []byte("ping"))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hdrs := []envelope.KeyValue{{Name: "Content-Type", Value: "application/grpc-web+proto"}}
			in := requestEnv(hdrs, frame, tc.path, tc.rawQuery)
			out := relay(t, in, RoleServer, RoleClient, func(envs []*envelope.Envelope) []*envelope.Envelope {
				sm := startOf(t, envs)
				if sm.Path != tc.path || sm.RawQuery != tc.rawQuery {
					t.Fatalf("Start overlay = (Path %q, RawQuery %q), want (%q, %q)",
						sm.Path, sm.RawQuery, tc.path, tc.rawQuery)
				}
				if tc.mutate != nil {
					tc.mutate(sm)
				}
				return envs
			})
			if out.Path != tc.wantPath {
				t.Errorf("HTTPMessage.Path = %q, want %q", out.Path, tc.wantPath)
			}
			if out.RawQuery != tc.wantRawQuery {
				t.Errorf("HTTPMessage.RawQuery = %q, want %q", out.RawQuery, tc.wantRawQuery)
			}
		})
	}
}

// TestRelay_SyntheticStartWithoutPathRebuilds — a Start built without a
// Path (a synthetic producer) still gets "/Service/Method".
func TestRelay_SyntheticStartWithoutPathRebuilds(t *testing.T) {
	dst := newMockChannel("s-syn")
	send := Wrap(dst, RoleClient)
	defer send.Close()
	out := sendAll(t, send, dst,
		&envelope.Envelope{StreamID: "s-syn", Direction: envelope.Send, Protocol: envelope.ProtocolGRPCWeb,
			Message: &envelope.GRPCStartMessage{Service: "pkg.Svc", Method: "Do", ContentType: "application/grpc-web+proto"}},
		&envelope.Envelope{StreamID: "s-syn", Direction: envelope.Send, Protocol: envelope.ProtocolGRPCWeb,
			Message: &envelope.GRPCEndMessage{}},
	)
	if out.Path != "/pkg.Svc/Do" || out.RawQuery != "" {
		t.Errorf("(Path, RawQuery) = (%q, %q), want (\"/pkg.Svc/Do\", \"\")", out.Path, out.RawQuery)
	}
}

// --- T11 (N1): empty-body responses are delivered ---

func TestRelay_EmptyBodyResponseDelivered(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		reason      string
		headers     []envelope.KeyValue
		wantStatus  uint32
		wantMessage string
		wantAnomaly bool
	}{
		{
			name:   "503_content_length_zero",
			status: 503,
			reason: "Service Unavailable",
			headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "text/plain"},
				{Name: "Content-Length", Value: "0"},
			},
			wantAnomaly: true,
		},
		{
			// gRPC-Web "trailers-only" response: grpc-status travels in
			// the HTTP headers and the body is empty.
			name:   "trailers_only_grpc_status_in_headers",
			status: 200,
			reason: "OK",
			headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "application/grpc-web+proto"},
				{Name: "Grpc-Status", Value: "12"},
				{Name: "Grpc-Message", Value: "unimplemented"},
				{Name: "Content-Length", Value: "0"},
			},
			wantStatus:  12,
			wantMessage: "unimplemented",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := pluginv2.NewEngine(nil)
			var fires atomic.Int32
			var sawStatus atomic.Int64
			engine.Registry().Register(pluginv2.Hook{
				Protocol:   pluginv2.ProtoGRPCWeb,
				Event:      pluginv2.EventOnEnd,
				Phase:      pluginv2.PhaseNone,
				PluginName: "test",
				Fn: builtinHook("end", func(msg starlark.Value, _ starlark.Value) {
					fires.Add(1)
					v, _, _ := msg.(*starlark.Dict).Get(starlark.String("status"))
					if i, ok := v.(starlark.Int).Int64(); ok {
						sawStatus.Store(i)
					}
				}),
			})

			in := responseEnv(tt.headers, nil, tt.status, tt.reason)
			var end *envelope.GRPCEndMessage
			out := relay(t, in, RoleClient, RoleServer, func(envs []*envelope.Envelope) []*envelope.Envelope {
				if len(envs) != 2 {
					t.Fatalf("got %d envelopes, want 2 (Start + End)", len(envs))
				}
				m, ok := envs[1].Message.(*envelope.GRPCEndMessage)
				if !ok {
					t.Fatalf("envs[1] = %T, want *GRPCEndMessage", envs[1].Message)
				}
				end = m
				return envs
			}, WithLifecycleEngine(engine))

			if end.Status != tt.wantStatus || end.Message != tt.wantMessage {
				t.Errorf("End (status, message) = (%d, %q), want (%d, %q)",
					end.Status, end.Message, tt.wantStatus, tt.wantMessage)
			}
			if got := hasAnomaly(end.Anomalies, envelope.AnomalyMissingGRPCWebTrailer); got != tt.wantAnomaly {
				t.Errorf("End missing-trailer anomaly = %v, want %v (anomalies %v)", got, tt.wantAnomaly, end.Anomalies)
			}
			if out.Status != tt.status {
				t.Errorf("client-side status = %d, want %d", out.Status, tt.status)
			}
			if len(out.Body) != 0 {
				t.Errorf("client-side body = %x, want empty (no trailer frame the wire did not carry)", out.Body)
			}
			if !kvEqual(out.Headers, tt.headers) {
				t.Errorf("client-side headers:\n got  %v\n want %v", out.Headers, tt.headers)
			}
			if got := fires.Load(); got != 1 {
				t.Errorf("on_end fired %d times, want 1", got)
			}
			if got := sawStatus.Load(); got != int64(tt.wantStatus) {
				t.Errorf("on_end status = %d, want %d", got, tt.wantStatus)
			}
		})
	}
}
