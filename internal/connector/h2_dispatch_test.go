package connector

import (
	"context"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
)

// TestIsGRPCContentType validates the precise native-gRPC content-type
// discriminator introduced in USK-658. The previous prefix-only matcher
// over-matched application/grpc-web*, breaking gRPC-Web routing.
func TestIsGRPCContentType(t *testing.T) {
	tests := []struct {
		name string
		ct   string
		want bool
	}{
		{"plain gRPC", "application/grpc", true},
		{"gRPC +proto subtype", "application/grpc+proto", true},
		{"gRPC +json subtype", "application/grpc+json", true},
		{"gRPC with charset param", "application/grpc; charset=utf-8", true},
		{"gRPC +proto with charset", "application/grpc+proto; charset=utf-8", true},
		{"gRPC uppercase", "APPLICATION/GRPC", true},
		{"gRPC with leading space", " application/grpc", true},

		// USK-658 regression guards: gRPC-Web variants must NOT match.
		{"grpc-web binary", "application/grpc-web", false},
		{"grpc-web +proto", "application/grpc-web+proto", false},
		{"grpc-web text", "application/grpc-web-text", false},
		{"grpc-web text +proto", "application/grpc-web-text+proto", false},
		{"grpc-web with charset", "application/grpc-web; charset=utf-8", false},

		// Other non-matches.
		{"application/grpcweb (no separator)", "application/grpcweb", false},
		{"json", "application/json", false},
		{"empty", "", false},
		{"text/plain", "text/plain", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGRPCContentType(tt.ct); got != tt.want {
				t.Errorf("isGRPCContentType(%q) = %v, want %v", tt.ct, got, tt.want)
			}
		})
	}
}

// TestExtractContentType verifies the helper returns the first content-type
// header value (case-insensitive name match), preserving wire case in the
// returned value, and "" when no content-type header is present.
func TestExtractContentType(t *testing.T) {
	tests := []struct {
		name    string
		headers []envelope.KeyValue
		want    string
	}{
		{
			name:    "no content-type header",
			headers: []envelope.KeyValue{{Name: "x-other", Value: "ignore"}},
			want:    "",
		},
		{
			name:    "lowercase content-type",
			headers: []envelope.KeyValue{{Name: "content-type", Value: "application/grpc"}},
			want:    "application/grpc",
		},
		{
			name:    "mixed-case header name",
			headers: []envelope.KeyValue{{Name: "Content-Type", Value: "application/grpc-web"}},
			want:    "application/grpc-web",
		},
		{
			name: "first content-type wins",
			headers: []envelope.KeyValue{
				{Name: "content-type", Value: "application/grpc"},
				{Name: "content-type", Value: "application/grpc-web"},
			},
			want: "application/grpc",
		},
		{
			name: "value case preserved",
			headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "Application/GRPC; CHARSET=UTF-8"},
			},
			want: "Application/GRPC; CHARSET=UTF-8",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := &http2.H2HeadersEvent{Headers: tt.headers}
			if got := extractContentType(evt); got != tt.want {
				t.Errorf("extractContentType = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDispatchClassification cross-checks how each test content-type would be
// routed by DispatchH2Stream. The three dispatch buckets are mutually
// exclusive: gRPC-Web wins over native-gRPC by branch order (defense-in-depth);
// the precise discriminator makes order non-load-bearing for correctness.
func TestDispatchClassification(t *testing.T) {
	tests := []struct {
		name        string
		ct          string
		wantGRPC    bool
		wantGRPCWeb bool
	}{
		{"plain gRPC", "application/grpc", true, false},
		{"gRPC +proto", "application/grpc+proto", true, false},
		{"grpc-web binary", "application/grpc-web", false, true},
		{"grpc-web +proto", "application/grpc-web+proto", false, true},
		{"grpc-web text", "application/grpc-web-text", false, true},
		{"grpc-web text +proto", "application/grpc-web-text+proto", false, true},
		{"json", "application/json", false, false},
		{"empty", "", false, false},
		{"application/grpcweb (no separator)", "application/grpcweb", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isGRPC := isGRPCContentType(tt.ct)
			isGRPCWeb := grpcweb.IsGRPCWebContentType(tt.ct)
			if isGRPC != tt.wantGRPC {
				t.Errorf("isGRPCContentType(%q) = %v, want %v", tt.ct, isGRPC, tt.wantGRPC)
			}
			if isGRPCWeb != tt.wantGRPCWeb {
				t.Errorf("grpcweb.IsGRPCWebContentType(%q) = %v, want %v", tt.ct, isGRPCWeb, tt.wantGRPCWeb)
			}
			if isGRPC && isGRPCWeb {
				t.Errorf("classifications must be mutually exclusive; %q matched both", tt.ct)
			}
		})
	}
}

// TestTranslateRoleForGRPCWeb verifies role translation between the
// httpaggregator and grpcweb Role enums. They are independent types; the
// translator makes the coupling explicit.
func TestTranslateRoleForGRPCWeb(t *testing.T) {
	tests := []struct {
		name string
		in   httpaggregator.Role
		want grpcweb.Role
	}{
		{"server", httpaggregator.RoleServer, grpcweb.RoleServer},
		{"client", httpaggregator.RoleClient, grpcweb.RoleClient},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := translateRoleForGRPCWeb(tt.in); got != tt.want {
				t.Errorf("translateRoleForGRPCWeb(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestWrapH2UpstreamForDispatch verifies per-Protocol dispatch of the
// USK-771 upstream wrapper. The Channel returned for ProtocolGRPC must
// accept a *envelope.GRPCStartMessage on Send (whereas the default
// httpaggregator path rejects it as a type mismatch — that mismatch is
// the original USK-771 bug).
func TestWrapH2UpstreamForDispatch(t *testing.T) {
	tests := []struct {
		name    string
		proto   envelope.Protocol
		message envelope.Message
		// wantSendOK is true when wrapping under proto produces a Channel
		// whose Send accepts message without a type-mismatch error. The
		// fakeUpstreamChannel below silently absorbs any inner Send so a
		// nil error from the wrapper means the wrapper accepted the
		// envelope.
		wantSendOK bool
	}{
		{
			name:       "gRPC accepts GRPCStartMessage",
			proto:      envelope.ProtocolGRPC,
			message:    &envelope.GRPCStartMessage{Service: "x.Y", Method: "Z", ContentType: "application/grpc"},
			wantSendOK: true,
		},
		{
			name:       "gRPC-Web accepts GRPCStartMessage",
			proto:      envelope.ProtocolGRPCWeb,
			message:    &envelope.GRPCStartMessage{Service: "x.Y", Method: "Z", ContentType: "application/grpc-web+proto"},
			wantSendOK: true,
		},
		{
			name:       "default rejects GRPCStartMessage",
			proto:      envelope.ProtocolHTTP,
			message:    &envelope.GRPCStartMessage{Service: "x.Y", Method: "Z", ContentType: "application/grpc"},
			wantSendOK: false,
		},
		{
			name:    "default accepts HTTPMessage",
			proto:   envelope.ProtocolHTTP,
			message: &envelope.HTTPMessage{Method: "POST", Path: "/foo", Headers: []envelope.KeyValue{{Name: "host", Value: "x"}}},
			// wrapping is the default httpaggregator; HTTPMessage Send goes
			// through, so the call succeeds.
			wantSendOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := newFakeUpstreamChannel()
			ch := WrapH2UpstreamForDispatch(fake, tt.proto, httpaggregator.WrapOptions{}, nil, nil)
			if ch == nil {
				t.Fatalf("WrapH2UpstreamForDispatch returned nil for proto=%v", tt.proto)
			}
			defer ch.Close()

			env := &envelope.Envelope{
				StreamID:  "test",
				Direction: envelope.Send,
				Protocol:  tt.proto,
				Message:   tt.message,
			}
			err := ch.Send(context.Background(), env)
			if tt.wantSendOK && err != nil {
				t.Fatalf("Send rejected envelope unexpectedly: proto=%v msg=%T err=%v", tt.proto, tt.message, err)
			}
			if !tt.wantSendOK && err == nil {
				t.Fatalf("Send accepted envelope unexpectedly: proto=%v msg=%T", tt.proto, tt.message)
			}
		})
	}
}

// fakeUpstreamChannel is a layer.Channel test double that silently
// absorbs every Send. It is intentionally dumb: we only need to verify
// the WRAPPER's Send-time type acceptance, not the inner Channel's
// behavior. The closed channel is allocated up-front so concurrent
// access to Closed() / Close() is race-free under -race.
type fakeUpstreamChannel struct {
	closed   chan struct{}
	closedOn sync.Once
}

func newFakeUpstreamChannel() *fakeUpstreamChannel {
	return &fakeUpstreamChannel{closed: make(chan struct{})}
}

func (f *fakeUpstreamChannel) StreamID() string { return "fake-up" }
func (f *fakeUpstreamChannel) Next(_ context.Context) (*envelope.Envelope, error) {
	return nil, nil
}

func (f *fakeUpstreamChannel) Send(_ context.Context, _ *envelope.Envelope) error { return nil }

func (f *fakeUpstreamChannel) Close() error {
	f.closedOn.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeUpstreamChannel) Closed() <-chan struct{} { return f.closed }

func (f *fakeUpstreamChannel) Err() error { return nil }

// compile-time assertion: fakeUpstreamChannel implements layer.Channel.
var _ layer.Channel = (*fakeUpstreamChannel)(nil)

// TestTranslateRoleForGRPC mirrors the gRPC-Web role test for the existing
// translator. Keeps both translators covered so a future refactor that
// collapses them into a generic helper still has both directions tested.
func TestTranslateRoleForGRPC(t *testing.T) {
	tests := []struct {
		name string
		in   httpaggregator.Role
		want grpclayer.Role
	}{
		{"server", httpaggregator.RoleServer, grpclayer.RoleServer},
		{"client", httpaggregator.RoleClient, grpclayer.RoleClient},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := translateRoleForGRPC(tt.in); got != tt.want {
				t.Errorf("translateRoleForGRPC(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
