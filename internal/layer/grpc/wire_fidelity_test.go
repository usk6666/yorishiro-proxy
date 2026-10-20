package grpc

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// USK-1251: native gRPC wire fidelity. The Channel-seam tests below drive
// the real relay shape the session uses: a RoleClient Channel's Next (the
// upstream leg) feeds envelopes into a RoleServer Channel's Send (the
// client leg) — or, for requests, RoleServer Next into RoleClient Send —
// and assert what the opposite inner HTTP/2 Channel was asked to write.
// Fixture shapes are the H2HeadersEvent / H2TrailersEvent values the
// http2 assembler produces (buildHeadersEvent: pseudo-headers projected
// onto Status / Path / ..., regular fields in wire order on Headers).

// drainAll reads every envelope ch yields until io.EOF.
func drainAll(t *testing.T, ch interface {
	Next(context.Context) (*envelope.Envelope, error)
}) []*envelope.Envelope {
	t.Helper()
	var out []*envelope.Envelope
	for i := 0; i < 64; i++ {
		env, err := ch.Next(context.Background())
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("Next #%d: %v", i, err)
		}
		out = append(out, env)
	}
	t.Fatalf("drainAll: more than 64 envelopes")
	return nil
}

// relayMutate lets a test stand in for a Pipeline Step between the two
// legs. It returns the envelope to Send (nil = drop it).
type relayMutate func(i int, env *envelope.Envelope) *envelope.Envelope

// relayResponse pushes the upstream response events via push onto a
// RoleClient Channel, drains it, runs every envelope through mutate, and
// Sends the result on a RoleServer Channel that has already relayed the
// client's request Start. It returns the drained envelopes and what the
// RoleServer Channel handed its inner HTTP/2 Channel.
func relayResponse(t *testing.T, push func(*stubInner), mutate relayMutate) ([]*envelope.Envelope, []*envelope.Envelope) {
	t.Helper()
	envs, sent, errs := relayResponseErrs(t, push, mutate)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("client Send #%d (%T): %v", i, envs[i].Message, err)
		}
	}
	return envs, sent
}

// relayResponseErrs is relayResponse returning each client Send's error
// (indexed like the drained envelopes; nil for a dropped one) instead of
// failing the test on it.
func relayResponseErrs(t *testing.T, push func(*stubInner), mutate relayMutate) ([]*envelope.Envelope, []*envelope.Envelope, []error) {
	t.Helper()
	upStub := newStubInner("up")
	push(upStub)
	up := Wrap(upStub, nil, RoleClient)
	defer up.Close()

	clientStub := newStubInner("client")
	clientStub.pushHeaders(envelope.Send, []byte("HPACK-req"), requestStartHeaders("/svc.S/M"))
	client := Wrap(clientStub, nil, RoleServer)
	defer client.Close()
	drainNext(t, client, 1)

	envs := drainAll(t, up)
	errs := make([]error, len(envs))
	for i, env := range envs {
		out := env
		if mutate != nil {
			out = mutate(i, env)
		}
		if out == nil {
			continue
		}
		errs[i] = client.Send(context.Background(), out)
	}
	return envs, clientStub.sentSnapshot(), errs
}

// relayRequest pushes the client's request events onto a RoleServer
// Channel, drains it, runs every envelope through mutate, and Sends the
// result on a RoleClient Channel. It returns what the RoleClient Channel
// handed its inner HTTP/2 Channel.
func relayRequest(t *testing.T, hdr *http2.H2HeadersEvent, mutate relayMutate) []*envelope.Envelope {
	t.Helper()
	clientStub := newStubInner("client")
	clientStub.pushHeaders(envelope.Send, []byte("HPACK-req"), hdr)
	clientStub.pushData(envelope.Send, makeLPM(false, []byte("req")), true)
	client := Wrap(clientStub, nil, RoleServer)
	defer client.Close()

	upStub := newStubInner("up")
	up := Wrap(upStub, nil, RoleClient)
	defer up.Close()

	for i, env := range drainAll(t, client) {
		out := env
		if mutate != nil {
			out = mutate(i, env)
		}
		if out == nil {
			continue
		}
		if err := up.Send(context.Background(), out); err != nil {
			t.Fatalf("upstream Send #%d (%T): %v", i, out.Message, err)
		}
	}
	return upStub.sentSnapshot()
}

func headersEvents(sent []*envelope.Envelope) []*http2.H2HeadersEvent {
	var out []*http2.H2HeadersEvent
	for _, e := range sent {
		if h, ok := e.Message.(*http2.H2HeadersEvent); ok {
			out = append(out, h)
		}
	}
	return out
}

func firstHeaders(t *testing.T, sent []*envelope.Envelope) *http2.H2HeadersEvent {
	t.Helper()
	hs := headersEvents(sent)
	if len(hs) == 0 {
		t.Fatalf("no H2HeadersEvent sent (sent %d envelopes)", len(sent))
	}
	return hs[0]
}

func describeSent(sent []*envelope.Envelope) []string {
	var out []string
	for _, e := range sent {
		switch m := e.Message.(type) {
		case *http2.H2HeadersEvent:
			out = append(out, "HEADERS(status="+strconv.Itoa(m.Status)+", end_stream="+btoa(m.EndStream)+", "+kvString(m.Headers)+")")
		case *http2.H2DataEvent:
			out = append(out, "DATA(len="+strconv.Itoa(len(m.Payload))+", end_stream="+btoa(m.EndStream)+")")
		case *http2.H2TrailersEvent:
			out = append(out, "TRAILERS("+kvString(m.Trailers)+")")
		default:
			out = append(out, "?")
		}
	}
	return out
}

func btoa(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func kvString(kvs []envelope.KeyValue) string {
	s := "["
	for i, kv := range kvs {
		if i > 0 {
			s += ", "
		}
		s += kv.Name + ": " + kv.Value
	}
	return s + "]"
}

func startOf(t *testing.T, envs []*envelope.Envelope) *envelope.GRPCStartMessage {
	t.Helper()
	for _, e := range envs {
		if m, ok := e.Message.(*envelope.GRPCStartMessage); ok {
			return m
		}
	}
	t.Fatalf("no GRPCStartMessage in %d envelopes", len(envs))
	return nil
}

func endOf(t *testing.T, envs []*envelope.Envelope) (*envelope.Envelope, *envelope.GRPCEndMessage) {
	t.Helper()
	for _, e := range envs {
		if m, ok := e.Message.(*envelope.GRPCEndMessage); ok {
			return e, m
		}
	}
	t.Fatalf("no GRPCEndMessage in %d envelopes", len(envs))
	return nil, nil
}

func hasAnomalyType(as []envelope.Anomaly, typ envelope.AnomalyType) bool {
	for _, a := range as {
		if a.Type == typ {
			return true
		}
	}
	return false
}

// TestRelay_UpstreamHTTPStatusReachesClient (T3, T1 at the Channel seam):
// a normal gRPC response with :status 503 reaches the client as 503, and
// the Receive Start carries it as HTTPStatus (what RecordStep projects
// onto Flow.StatusCode).
func TestRelay_UpstreamHTTPStatusReachesClient(t *testing.T) {
	t.Parallel()
	envs, sent := relayResponse(t, func(s *stubInner) {
		s.pushHeaders(envelope.Receive, []byte("HPACK-resp"), &http2.H2HeadersEvent{
			Status:  503,
			Headers: []envelope.KeyValue{{Name: "content-type", Value: "application/grpc"}},
		})
		s.pushTrailers(envelope.Receive, []byte("HPACK-trl"), []envelope.KeyValue{
			{Name: "grpc-status", Value: "14"},
		})
	}, nil)

	if got := startOf(t, envs).HTTPStatus; got != 503 {
		t.Errorf("Receive Start HTTPStatus = %d, want 503", got)
	}
	if got := firstHeaders(t, sent).Status; got != 503 {
		t.Errorf("client :status = %d, want 503 (sent %v)", got, describeSent(sent))
	}
}

// TestRelay_EndStreamResponseWithoutGRPCStatus (T3, T12, U2): a response
// HEADERS frame that carries END_STREAM but no grpc-status — a load
// balancer's error page — reaches the client as exactly that one HEADERS
// frame: observed :status, observed header list (no fabricated
// content-type, no fabricated grpc-status), END_STREAM. The Layer emits a
// Status=0 placeholder End stamped AnomalyGRPCMissingStatus.
func TestRelay_EndStreamResponseWithoutGRPCStatus(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		status  int
		headers []envelope.KeyValue
	}{
		{
			name:    "bare_503",
			status:  503,
			headers: []envelope.KeyValue{{Name: "server", Value: "lb"}},
		},
		{
			name:   "html_502",
			status: 502,
			headers: []envelope.KeyValue{
				{Name: "server", Value: "lb"},
				{Name: "content-type", Value: "text/html"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			envs, sent := relayResponse(t, func(s *stubInner) {
				s.pushHeaders(envelope.Receive, []byte("HPACK-resp"), &http2.H2HeadersEvent{
					Status:    tt.status,
					EndStream: true,
					Headers:   slices.Clone(tt.headers),
				})
			}, nil)

			endEnv, end := endOf(t, envs)
			if end.Status != 0 || end.Message != "" || len(end.Trailers) != 0 {
				t.Errorf("placeholder End = %+v, want Status=0, no message, no trailers", end)
			}
			if endEnv.Raw != nil {
				t.Errorf("placeholder End Raw = %x, want nil", endEnv.Raw)
			}
			if !hasAnomalyType(end.Anomalies, envelope.AnomalyGRPCMissingStatus) {
				t.Errorf("End anomalies = %v, want %s", end.Anomalies, envelope.AnomalyGRPCMissingStatus)
			}

			if len(sent) != 1 {
				t.Fatalf("client-side sends = %v, want exactly one HEADERS frame", describeSent(sent))
			}
			h, ok := sent[0].Message.(*http2.H2HeadersEvent)
			if !ok {
				t.Fatalf("client-side send = %T, want *http2.H2HeadersEvent", sent[0].Message)
			}
			if h.Status != tt.status {
				t.Errorf("client :status = %d, want %d", h.Status, tt.status)
			}
			if !h.EndStream {
				t.Errorf("client HEADERS END_STREAM = false, want true")
			}
			if !slices.Equal(h.Headers, tt.headers) {
				t.Errorf("client headers:\n got  %s\n want %s", kvString(h.Headers), kvString(tt.headers))
			}
		})
	}
}

// TestRelay_RequestHeaderLayoutPreserved (T4, T9, U3): the client's
// request header list reaches the upstream verbatim — control-header
// position, raw grpc-timeout / grpc-accept-encoding values, duplicates and
// unparseable values — and no te: trailers is added when the client sent
// none (an observed te is relayed as is).
func TestRelay_RequestHeaderLayoutPreserved(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		headers []envelope.KeyValue
	}{
		{
			name: "control_headers_after_metadata_no_te",
			headers: []envelope.KeyValue{
				{Name: "user-agent", Value: "grpc-go/1.70"},
				{Name: "content-type", Value: "application/grpc"},
				{Name: "grpc-accept-encoding", Value: "identity, gzip"},
				{Name: "grpc-timeout", Value: "1000m"},
				{Name: "x-md", Value: "v"},
			},
		},
		{
			name: "duplicates_unparseable_and_te",
			headers: []envelope.KeyValue{
				{Name: "content-type", Value: "application/grpc"},
				{Name: "x-a", Value: "1"},
				{Name: "content-type", Value: "application/grpc+proto"},
				{Name: "grpc-timeout", Value: "soon"},
				{Name: "te", Value: "trailers"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sent := relayRequest(t, &http2.H2HeadersEvent{
				Method: "POST", Scheme: "https", Authority: "api.example.com", Path: "/svc.S/M",
				Headers: slices.Clone(tt.headers),
			}, nil)
			h := firstHeaders(t, sent)
			if !slices.Equal(h.Headers, tt.headers) {
				t.Errorf("upstream request headers:\n got  %s\n want %s", kvString(h.Headers), kvString(tt.headers))
			}
		})
	}
}

// TestRelay_ResponseHeaderLayoutPreserved (T5): the response header list
// reaches the client in its observed order, duplicates included.
func TestRelay_ResponseHeaderLayoutPreserved(t *testing.T) {
	t.Parallel()
	want := []envelope.KeyValue{
		{Name: "x-envoy-upstream-service-time", Value: "3"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "grpc-encoding", Value: "identity"},
		{Name: "content-type", Value: "application/grpc+proto"},
		{Name: "x-b", Value: "2"},
	}
	_, sent := relayResponse(t, func(s *stubInner) {
		s.pushHeaders(envelope.Receive, []byte("HPACK-resp"), &http2.H2HeadersEvent{
			Status:  200,
			Headers: slices.Clone(want),
		})
		s.pushTrailers(envelope.Receive, []byte("HPACK-trl"), []envelope.KeyValue{{Name: "grpc-status", Value: "0"}})
	}, nil)
	if h := firstHeaders(t, sent); !slices.Equal(h.Headers, want) {
		t.Errorf("client response headers:\n got  %s\n want %s", kvString(h.Headers), kvString(want))
	}
}

// runPluginOnStart runs a Starlark (grpc, on_start) plugin over env
// through the real pluginv2 dispatcher (the Message builder replaces
// env.Message and keeps env, so the Layer's Opaque survives).
func runPluginOnStart(t *testing.T, body string, env *envelope.Envelope) *envelope.Envelope {
	t.Helper()
	script := filepath.Join(t.TempDir(), "p.star")
	src := "def f(msg, ctx):\n" + body + "\n\nregister_hook(\"grpc\", \"on_start\", f)\n"
	if err := os.WriteFile(script, []byte(src), 0o600); err != nil {
		t.Fatalf("write plugin: %v", err)
	}
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []pluginv2.PluginConfig{{Path: script, OnError: "abort"}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	hooks := eng.Registry().Lookup(pluginv2.ProtoGRPC, pluginv2.EventOnStart, pluginv2.PhasePrePipeline)
	if len(hooks) != 1 {
		t.Fatalf("registered hooks = %d, want 1", len(hooks))
	}
	out, err := eng.Dispatch(context.Background(), hooks[0], env)
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if out.Action != pluginv2.ActionContinue || out.Mutation != pluginv2.MutationMessageOnly {
		t.Fatalf("plugin outcome (action, mutation) = (%v, %v), want (continue, message-only)", out.Action, out.Mutation)
	}
	// Mirror pipeline.pluginDispatcher.applyMutation for a Message-only
	// mutation: a shallow copy carrying the rebuilt Message, so env.Opaque
	// survives. (pipeline cannot be imported here: it depends on this
	// package.)
	next := *env
	next.Message = out.NewMessage
	return &next
}

// TestRelay_PluginEditOfControlFieldRewrittenInPlace (T6): a plugin edit
// of a structured control field is written back into the observed entry —
// name and position kept, value replaced — and clearing it drops the
// entry. Untouched control headers keep their raw observed value.
func TestRelay_PluginEditOfControlFieldRewrittenInPlace(t *testing.T) {
	t.Parallel()
	observed := []envelope.KeyValue{
		{Name: "user-agent", Value: "grpc-go/1.70"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "grpc-accept-encoding", Value: "identity, gzip"},
		{Name: "grpc-timeout", Value: "1000m"},
		{Name: "x-md", Value: "v"},
	}
	tests := []struct {
		name   string
		plugin string
		want   []envelope.KeyValue
	}{
		{
			name:   "timeout_edited",
			plugin: "    msg[\"timeout\"] = 2000000000",
			want: []envelope.KeyValue{
				{Name: "user-agent", Value: "grpc-go/1.70"},
				{Name: "content-type", Value: "application/grpc"},
				{Name: "grpc-accept-encoding", Value: "identity, gzip"},
				{Name: "grpc-timeout", Value: "2S"},
				{Name: "x-md", Value: "v"},
			},
		},
		{
			name:   "content_type_edited",
			plugin: "    msg[\"content_type\"] = \"application/grpc+json\"",
			want: []envelope.KeyValue{
				{Name: "user-agent", Value: "grpc-go/1.70"},
				{Name: "content-type", Value: "application/grpc+json"},
				{Name: "grpc-accept-encoding", Value: "identity, gzip"},
				{Name: "grpc-timeout", Value: "1000m"},
				{Name: "x-md", Value: "v"},
			},
		},
		{
			name:   "timeout_cleared",
			plugin: "    msg[\"timeout\"] = 0",
			want: []envelope.KeyValue{
				{Name: "user-agent", Value: "grpc-go/1.70"},
				{Name: "content-type", Value: "application/grpc"},
				{Name: "grpc-accept-encoding", Value: "identity, gzip"},
				{Name: "x-md", Value: "v"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			sent := relayRequest(t, &http2.H2HeadersEvent{
				Method: "POST", Scheme: "https", Authority: "api.example.com", Path: "/svc.S/M",
				Headers: slices.Clone(observed),
			}, func(_ int, env *envelope.Envelope) *envelope.Envelope {
				if _, ok := env.Message.(*envelope.GRPCStartMessage); ok {
					return runPluginOnStart(t, tt.plugin, env)
				}
				return env
			})
			if h := firstHeaders(t, sent); !slices.Equal(h.Headers, tt.want) {
				t.Errorf("upstream request headers:\n got  %s\n want %s", kvString(h.Headers), kvString(tt.want))
			}
		})
	}
}

// TestRelay_ClonedReceiveStartKeepsHTTPStatus (T7): intercept
// modify_and_forward Clone()s the envelope, which drops the Layer's
// Opaque. The status overlay lives on the Message and survives; the header
// layout falls back to the synthesized one (content-type first).
func TestRelay_ClonedReceiveStartKeepsHTTPStatus(t *testing.T) {
	t.Parallel()
	_, sent := relayResponse(t, func(s *stubInner) {
		s.pushHeaders(envelope.Receive, []byte("HPACK-resp"), &http2.H2HeadersEvent{
			Status: 503,
			Headers: []envelope.KeyValue{
				{Name: "x-envoy", Value: "1"},
				{Name: "content-type", Value: "application/grpc"},
			},
		})
		s.pushTrailers(envelope.Receive, []byte("HPACK-trl"), []envelope.KeyValue{{Name: "grpc-status", Value: "14"}})
	}, func(_ int, env *envelope.Envelope) *envelope.Envelope {
		if _, ok := env.Message.(*envelope.GRPCStartMessage); ok {
			return env.Clone()
		}
		return env
	})
	h := firstHeaders(t, sent)
	if h.Status != 503 {
		t.Errorf("client :status = %d, want 503", h.Status)
	}
	want := []envelope.KeyValue{
		{Name: "content-type", Value: "application/grpc"},
		{Name: "x-envoy", Value: "1"},
	}
	if !slices.Equal(h.Headers, want) {
		t.Errorf("client headers (synthesized layout):\n got  %s\n want %s", kvString(h.Headers), kvString(want))
	}
}

// TestSend_SyntheticStartKeepsLegacyLayout (T8, guard): a Start built by a
// synthetic producer (resend_grpc / fuzz_grpc / RESPOND_GRPC — no Opaque,
// HTTPStatus 0, empty ContentType) keeps the pre-USK-1251 output exactly.
func TestSend_SyntheticStartKeepsLegacyLayout(t *testing.T) {
	t.Parallel()
	md := []envelope.KeyValue{{Name: "x-md", Value: "v"}}

	t.Run("request", func(t *testing.T) {
		t.Parallel()
		stub := newStubInner("s")
		ch := Wrap(stub, nil, RoleClient)
		defer ch.Close()
		if err := ch.Send(context.Background(), &envelope.Envelope{
			Direction: envelope.Send, Protocol: envelope.ProtocolGRPC,
			Message: &envelope.GRPCStartMessage{Service: "svc.S", Method: "M", Metadata: slices.Clone(md)},
		}); err != nil {
			t.Fatalf("Send: %v", err)
		}
		h := firstHeaders(t, stub.sentSnapshot())
		want := []envelope.KeyValue{
			{Name: "content-type", Value: "application/grpc"},
			{Name: "te", Value: "trailers"},
			{Name: "x-md", Value: "v"},
		}
		if !slices.Equal(h.Headers, want) {
			t.Errorf("headers:\n got  %s\n want %s", kvString(h.Headers), kvString(want))
		}
	})
	t.Run("response", func(t *testing.T) {
		t.Parallel()
		stub := newStubInner("s")
		ch := Wrap(stub, nil, RoleServer)
		defer ch.Close()
		if err := ch.Send(context.Background(), &envelope.Envelope{
			Direction: envelope.Receive, Protocol: envelope.ProtocolGRPC,
			Message: &envelope.GRPCStartMessage{Metadata: slices.Clone(md)},
		}); err != nil {
			t.Fatalf("Send: %v", err)
		}
		h := firstHeaders(t, stub.sentSnapshot())
		if h.Status != 200 {
			t.Errorf(":status = %d, want 200", h.Status)
		}
		want := []envelope.KeyValue{
			{Name: "content-type", Value: "application/grpc"},
			{Name: "x-md", Value: "v"},
		}
		if !slices.Equal(h.Headers, want) {
			t.Errorf("headers:\n got  %s\n want %s", kvString(h.Headers), kvString(want))
		}
	})
}

// trailersOnlyHeaders is a trailers-only response header list as an Envoy
// front sends it: metadata ahead of content-type, grpc-message
// percent-encoded.
func trailersOnlyHeaders() []envelope.KeyValue {
	return []envelope.KeyValue{
		{Name: "x-envoy", Value: "1"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "grpc-status", Value: "14"},
		{Name: "grpc-message", Value: "no%20healthy%20upstream"},
	}
}

func pushTrailersOnly(status int) func(*stubInner) {
	return func(s *stubInner) {
		s.pushHeaders(envelope.Receive, []byte("HPACK-trailers-only"), &http2.H2HeadersEvent{
			Status:    status,
			EndStream: true,
			Headers:   trailersOnlyHeaders(),
		})
	}
}

// TestRelay_TrailersOnlyResponseRelayedAsSingleHeaders (T10, U1): a
// trailers-only response reaches the client as ONE HEADERS frame with
// END_STREAM carrying the identical header list — not HEADERS + a TRAILERS
// frame duplicating grpc-status / x-envoy / content-type. The Layer still
// emits Start + End (grpc-status 14) for recording.
func TestRelay_TrailersOnlyResponseRelayedAsSingleHeaders(t *testing.T) {
	t.Parallel()
	for _, status := range []int{200, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()
			envs, sent := relayResponse(t, pushTrailersOnly(status), nil)
			if _, end := endOf(t, envs); end.Status != 14 || end.Message != "no healthy upstream" {
				t.Errorf("End (status, message) = (%d, %q), want (14, %q)", end.Status, end.Message, "no healthy upstream")
			}
			if len(sent) != 1 {
				t.Fatalf("client-side sends = %v, want exactly one HEADERS frame", describeSent(sent))
			}
			h, ok := sent[0].Message.(*http2.H2HeadersEvent)
			if !ok {
				t.Fatalf("client-side send = %T, want *http2.H2HeadersEvent", sent[0].Message)
			}
			if h.Status != status || !h.EndStream {
				t.Errorf("client HEADERS (status, end_stream) = (%d, %v), want (%d, true)", h.Status, h.EndStream, status)
			}
			if want := trailersOnlyHeaders(); !slices.Equal(h.Headers, want) {
				t.Errorf("client headers:\n got  %s\n want %s", kvString(h.Headers), kvString(want))
			}
		})
	}
}

// TestRelay_TrailersOnlyEditTakesEffect (T11): an edit to a trailers-only
// response reaches the wire in a defined shape.
//
//   - End status / message edit (Transform set_status, plugin, intercept —
//     the last Clone()s the End): written into the observed grpc-status /
//     grpc-message entries in place, still one HEADERS frame.
//   - Start-side edit with an untouched End: relayed as edited, the End
//     does not revert it.
//   - End trailer-metadata edit: not representable in place, so the
//     response falls back to HEADERS (no END_STREAM) + TRAILERS rebuilt
//     from the End.
func TestRelay_TrailersOnlyEditTakesEffect(t *testing.T) {
	t.Parallel()
	editEnd := func(clone bool, fn func(*envelope.GRPCEndMessage)) relayMutate {
		return func(_ int, env *envelope.Envelope) *envelope.Envelope {
			if _, ok := env.Message.(*envelope.GRPCEndMessage); !ok {
				return env
			}
			if clone {
				env = env.Clone()
			}
			fn(env.Message.(*envelope.GRPCEndMessage))
			return env
		}
	}
	withValue := func(name, value string) []envelope.KeyValue {
		out := trailersOnlyHeaders()
		for i := range out {
			if out[i].Name == name {
				out[i].Value = value
			}
		}
		return out
	}
	without := func(name string) []envelope.KeyValue {
		var out []envelope.KeyValue
		for _, kv := range trailersOnlyHeaders() {
			if kv.Name != name {
				out = append(out, kv)
			}
		}
		return out
	}

	tests := []struct {
		name   string
		mutate relayMutate
		// single-frame expectation
		wantHeaders []envelope.KeyValue
		// fallback expectation (wantHeaders nil)
		wantTrailers []envelope.KeyValue
	}{
		{
			name:        "end_status_edited",
			mutate:      editEnd(false, func(m *envelope.GRPCEndMessage) { m.Status = 7 }),
			wantHeaders: withValue("grpc-status", "7"),
		},
		{
			name:        "end_status_edited_after_clone",
			mutate:      editEnd(true, func(m *envelope.GRPCEndMessage) { m.Status = 7 }),
			wantHeaders: withValue("grpc-status", "7"),
		},
		{
			name:        "end_message_cleared",
			mutate:      editEnd(false, func(m *envelope.GRPCEndMessage) { m.Message = "" }),
			wantHeaders: without("grpc-message"),
		},
		{
			name: "start_metadata_edited_end_untouched",
			mutate: func(_ int, env *envelope.Envelope) *envelope.Envelope {
				if m, ok := env.Message.(*envelope.GRPCStartMessage); ok {
					for i := range m.Metadata {
						if m.Metadata[i].Name == "grpc-status" {
							m.Metadata[i].Value = "3"
						}
					}
				}
				return env
			},
			wantHeaders: withValue("grpc-status", "3"),
		},
		{
			name: "end_trailers_edited_falls_back",
			mutate: editEnd(false, func(m *envelope.GRPCEndMessage) {
				m.Trailers = append(m.Trailers, envelope.KeyValue{Name: "x-added", Value: "1"})
			}),
			wantTrailers: []envelope.KeyValue{
				{Name: "grpc-status", Value: "14"},
				{Name: "grpc-message", Value: "no healthy upstream"},
				{Name: "x-envoy", Value: "1"},
				{Name: "content-type", Value: "application/grpc"},
				{Name: "x-added", Value: "1"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, sent := relayResponse(t, pushTrailersOnly(200), tt.mutate)
			if tt.wantHeaders != nil {
				if len(sent) != 1 {
					t.Fatalf("client-side sends = %v, want one HEADERS frame", describeSent(sent))
				}
				h, ok := sent[0].Message.(*http2.H2HeadersEvent)
				if !ok || !h.EndStream {
					t.Fatalf("client-side sends = %v, want one HEADERS frame with END_STREAM", describeSent(sent))
				}
				if !slices.Equal(h.Headers, tt.wantHeaders) {
					t.Errorf("client headers:\n got  %s\n want %s", kvString(h.Headers), kvString(tt.wantHeaders))
				}
				return
			}
			if len(sent) != 2 {
				t.Fatalf("client-side sends = %v, want HEADERS + TRAILERS", describeSent(sent))
			}
			h, ok := sent[0].Message.(*http2.H2HeadersEvent)
			if !ok || h.EndStream {
				t.Fatalf("client-side send #0 = %v, want HEADERS without END_STREAM", describeSent(sent))
			}
			tr, ok := sent[1].Message.(*http2.H2TrailersEvent)
			if !ok {
				t.Fatalf("client-side send #1 = %T, want *http2.H2TrailersEvent", sent[1].Message)
			}
			if !slices.Equal(tr.Trailers, tt.wantTrailers) {
				t.Errorf("client trailers:\n got  %s\n want %s", kvString(tr.Trailers), kvString(tt.wantTrailers))
			}
		})
	}
}

// TestRelay_EndStreamResponseWithoutGRPCStatusEdits (T11/T12 edges): the
// placeholder End of a bare END_STREAM response.
//
//   - A status edit adds grpc-status to the single HEADERS frame.
//   - When the Start was Clone()d (its HEADERS already went out without
//     END_STREAM), the untouched placeholder ends the stream with an empty
//     DATA frame — no grpc-status is fabricated.
func TestRelay_EndStreamResponseWithoutGRPCStatusEdits(t *testing.T) {
	t.Parallel()
	push := func(s *stubInner) {
		s.pushHeaders(envelope.Receive, []byte("HPACK-resp"), &http2.H2HeadersEvent{
			Status:    503,
			EndStream: true,
			Headers:   []envelope.KeyValue{{Name: "server", Value: "lb"}},
		})
	}

	t.Run("status_edited", func(t *testing.T) {
		t.Parallel()
		_, sent := relayResponse(t, push, func(_ int, env *envelope.Envelope) *envelope.Envelope {
			if m, ok := env.Message.(*envelope.GRPCEndMessage); ok {
				m.Status = 14
			}
			return env
		})
		if len(sent) != 1 {
			t.Fatalf("client-side sends = %v, want one HEADERS frame", describeSent(sent))
		}
		h, ok := sent[0].Message.(*http2.H2HeadersEvent)
		if !ok || !h.EndStream || h.Status != 503 {
			t.Fatalf("client-side sends = %v, want HEADERS(503, END_STREAM)", describeSent(sent))
		}
		want := []envelope.KeyValue{{Name: "server", Value: "lb"}, {Name: "grpc-status", Value: "14"}}
		if !slices.Equal(h.Headers, want) {
			t.Errorf("client headers:\n got  %s\n want %s", kvString(h.Headers), kvString(want))
		}
	})

	t.Run("start_cloned", func(t *testing.T) {
		t.Parallel()
		_, sent := relayResponse(t, push, func(_ int, env *envelope.Envelope) *envelope.Envelope {
			if _, ok := env.Message.(*envelope.GRPCStartMessage); ok {
				return env.Clone()
			}
			return env
		})
		if len(sent) != 2 {
			t.Fatalf("client-side sends = %v, want HEADERS + empty DATA(END_STREAM)", describeSent(sent))
		}
		if h, ok := sent[0].Message.(*http2.H2HeadersEvent); !ok || h.Status != 503 {
			t.Errorf("client-side send #0 = %v, want HEADERS(503)", describeSent(sent))
		}
		d, ok := sent[1].Message.(*http2.H2DataEvent)
		if !ok || !d.EndStream || len(d.Payload) != 0 {
			t.Errorf("client-side send #1 = %v, want empty DATA with END_STREAM", describeSent(sent))
		}
	})
}

// sentHasGRPCStatus reports whether any frame the client-side Channel
// handed its inner HTTP/2 Channel carries a grpc-status entry.
func sentHasGRPCStatus(sent []*envelope.Envelope) bool {
	for _, e := range sent {
		var kvs []envelope.KeyValue
		switch m := e.Message.(type) {
		case *http2.H2HeadersEvent:
			kvs = m.Headers
		case *http2.H2TrailersEvent:
			kvs = m.Trailers
		}
		if hasHeader(kvs, "grpc-status") {
			return true
		}
	}
	return false
}

// TestRelay_MissingStatusPlaceholderFabricatesNoStatus: the Status=0
// placeholder End of a response without grpc-status must never reach the
// client as a made-up grpc-status: 0 (OK).
//
//   - start_dropped: a Step dropped the Receive Start, so no response
//     HEADERS went out. A proxy-built Trailers-Only would fabricate
//     :status 200 + grpc-status 0 and turn the upstream's 503 into a
//     successful RPC; the Send fails with a StreamError instead, so the
//     session resets the client stream.
//   - trailers_edited: an End trailer edit forces the HEADERS + TRAILERS
//     fallback; the TRAILERS frame carries the edited trailers but no
//     grpc-status the upstream never sent.
//   - start_cloned_trailers_edited: the same edit after a Clone()d Start
//     (HEADERS already sent) — TRAILERS without grpc-status.
func TestRelay_MissingStatusPlaceholderFabricatesNoStatus(t *testing.T) {
	t.Parallel()
	push := func(s *stubInner) {
		s.pushHeaders(envelope.Receive, []byte("HPACK-resp"), &http2.H2HeadersEvent{
			Status:    503,
			EndStream: true,
			Headers:   []envelope.KeyValue{{Name: "server", Value: "lb"}},
		})
	}
	added := envelope.KeyValue{Name: "x-added", Value: "v"}
	editTrailers := func(env *envelope.Envelope) {
		if m, ok := env.Message.(*envelope.GRPCEndMessage); ok {
			m.Trailers = append(m.Trailers, added)
		}
	}

	t.Run("start_dropped", func(t *testing.T) {
		t.Parallel()
		envs, sent, errs := relayResponseErrs(t, push, func(_ int, env *envelope.Envelope) *envelope.Envelope {
			if _, ok := env.Message.(*envelope.GRPCStartMessage); ok {
				return nil
			}
			return env
		})
		if sentHasGRPCStatus(sent) {
			t.Errorf("client-side sends = %v, want no fabricated grpc-status", describeSent(sent))
		}
		if len(headersEvents(sent)) != 0 {
			t.Errorf("client-side sends = %v, want no proxy-built response HEADERS", describeSent(sent))
		}
		var endErr error
		for i, e := range envs {
			if _, ok := e.Message.(*envelope.GRPCEndMessage); ok {
				endErr = errs[i]
			}
		}
		var se *layer.StreamError
		if !errors.As(endErr, &se) {
			t.Errorf("End Send err = %v, want a *layer.StreamError so the client stream is reset", endErr)
		}
	})

	t.Run("trailers_edited", func(t *testing.T) {
		t.Parallel()
		_, sent := relayResponse(t, push, func(_ int, env *envelope.Envelope) *envelope.Envelope {
			editTrailers(env)
			return env
		})
		if len(sent) != 2 {
			t.Fatalf("client-side sends = %v, want HEADERS + TRAILERS", describeSent(sent))
		}
		if h, ok := sent[0].Message.(*http2.H2HeadersEvent); !ok || h.Status != 503 || h.EndStream {
			t.Errorf("client-side send #0 = %v, want HEADERS(503) without END_STREAM", describeSent(sent))
		}
		tr, ok := sent[1].Message.(*http2.H2TrailersEvent)
		if !ok {
			t.Fatalf("client-side send #1 = %v, want TRAILERS", describeSent(sent))
		}
		if want := []envelope.KeyValue{added}; !slices.Equal(tr.Trailers, want) {
			t.Errorf("client trailers:\n got  %s\n want %s", kvString(tr.Trailers), kvString(want))
		}
	})

	t.Run("start_cloned_trailers_edited", func(t *testing.T) {
		t.Parallel()
		_, sent := relayResponse(t, push, func(_ int, env *envelope.Envelope) *envelope.Envelope {
			if _, ok := env.Message.(*envelope.GRPCStartMessage); ok {
				return env.Clone()
			}
			editTrailers(env)
			return env
		})
		if len(sent) != 2 {
			t.Fatalf("client-side sends = %v, want HEADERS + TRAILERS", describeSent(sent))
		}
		tr, ok := sent[1].Message.(*http2.H2TrailersEvent)
		if !ok {
			t.Fatalf("client-side send #1 = %v, want TRAILERS", describeSent(sent))
		}
		if want := []envelope.KeyValue{added}; !slices.Equal(tr.Trailers, want) {
			t.Errorf("client trailers:\n got  %s\n want %s", kvString(tr.Trailers), kvString(want))
		}
	})
}

// TestRelay_DataBetweenHeldStartAndEnd: a Receive Data Sent between a
// deferred END_STREAM response Start and its End (e.g. a plugin-injected
// message) flushes the held HEADERS first, without END_STREAM, so the wire
// order stays HEADERS, DATA, then the End's frame.
func TestRelay_DataBetweenHeldStartAndEnd(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		headers []envelope.KeyValue
		// wantEnd checks the frame the End produced.
		wantEnd func(t *testing.T, e *envelope.Envelope, sent []*envelope.Envelope)
	}{
		{
			name:    "trailers_only",
			headers: trailersOnlyHeaders(),
			wantEnd: func(t *testing.T, e *envelope.Envelope, sent []*envelope.Envelope) {
				tr, ok := e.Message.(*http2.H2TrailersEvent)
				if !ok || !hasHeader(tr.Trailers, "grpc-status") {
					t.Errorf("client-side send #2 = %v, want TRAILERS carrying grpc-status", describeSent(sent))
				}
			},
		},
		{
			name:    "missing_status",
			headers: []envelope.KeyValue{{Name: "server", Value: "lb"}},
			wantEnd: func(t *testing.T, e *envelope.Envelope, sent []*envelope.Envelope) {
				d, ok := e.Message.(*http2.H2DataEvent)
				if !ok || !d.EndStream || len(d.Payload) != 0 {
					t.Errorf("client-side send #2 = %v, want empty DATA with END_STREAM (no fabricated grpc-status)", describeSent(sent))
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			upStub := newStubInner("up")
			upStub.pushHeaders(envelope.Receive, []byte("HPACK-resp"), &http2.H2HeadersEvent{
				Status:    200,
				EndStream: true,
				Headers:   slices.Clone(tt.headers),
			})
			up := Wrap(upStub, nil, RoleClient)
			defer up.Close()

			clientStub := newStubInner("client")
			clientStub.pushHeaders(envelope.Send, []byte("HPACK-req"), requestStartHeaders("/svc.S/M"))
			client := Wrap(clientStub, nil, RoleServer)
			defer client.Close()
			drainNext(t, client, 1)

			ctx := context.Background()
			for i, env := range drainAll(t, up) {
				if _, ok := env.Message.(*envelope.GRPCEndMessage); ok {
					inj := &envelope.Envelope{
						StreamID:  env.StreamID,
						Direction: envelope.Receive,
						Protocol:  envelope.ProtocolGRPC,
						Message:   &envelope.GRPCDataMessage{Payload: []byte("inj")},
					}
					if err := client.Send(ctx, inj); err != nil {
						t.Fatalf("client Send (injected Data): %v", err)
					}
				}
				if err := client.Send(ctx, env); err != nil {
					t.Fatalf("client Send #%d (%T): %v", i, env.Message, err)
				}
			}

			sent := clientStub.sentSnapshot()
			if len(sent) != 3 {
				t.Fatalf("client-side sends = %v, want HEADERS, DATA, End frame", describeSent(sent))
			}
			if h, ok := sent[0].Message.(*http2.H2HeadersEvent); !ok || h.EndStream || h.Status != 200 {
				t.Errorf("client-side send #0 = %v, want HEADERS(200) without END_STREAM", describeSent(sent))
			}
			if d, ok := sent[1].Message.(*http2.H2DataEvent); !ok || d.EndStream || len(d.Payload) != 5+len("inj") {
				t.Errorf("client-side send #1 = %v, want the injected LPM DATA without END_STREAM", describeSent(sent))
			}
			tt.wantEnd(t, sent[2], sent)
		})
	}
}
