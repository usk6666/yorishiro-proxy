package pipeline

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

func TestDispatchTarget_HTTPRequestSend(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Method: "GET"},
	}
	tgt, ok := dispatchTarget(env)
	if !ok {
		t.Fatal("expected dispatch target")
	}
	if tgt.Protocol != pluginv2.ProtoHTTP || tgt.Event != pluginv2.EventOnRequest {
		t.Errorf("target = %+v", tgt)
	}
}

func TestDispatchTarget_HTTPResponseReceive(t *testing.T) {
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Status: 200},
	}
	tgt, _ := dispatchTarget(env)
	if tgt.Event != pluginv2.EventOnResponse {
		t.Errorf("event = %q, want on_response", tgt.Event)
	}
}

func TestDispatchTarget_WSUpgrade(t *testing.T) {
	cases := []struct {
		name    string
		headers []envelope.KeyValue
		want    bool
	}{
		{
			name: "lowercase",
			headers: []envelope.KeyValue{
				{Name: "connection", Value: "upgrade"},
				{Name: "upgrade", Value: "websocket"},
			},
			want: true,
		},
		{
			name: "mixed case",
			headers: []envelope.KeyValue{
				{Name: "Connection", Value: "Upgrade"},
				{Name: "Upgrade", Value: "websocket"},
			},
			want: true,
		},
		{
			name: "connection multi-token",
			headers: []envelope.KeyValue{
				{Name: "Connection", Value: "keep-alive, Upgrade"},
				{Name: "Upgrade", Value: "websocket"},
			},
			want: true,
		},
		{
			name: "missing upgrade header",
			headers: []envelope.KeyValue{
				{Name: "Connection", Value: "Upgrade"},
			},
			want: false,
		},
		{
			name: "wrong protocol upgrade",
			headers: []envelope.KeyValue{
				{Name: "Connection", Value: "Upgrade"},
				{Name: "Upgrade", Value: "h2c"},
			},
			want: false,
		},
		{
			name:    "no headers",
			headers: nil,
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := &envelope.Envelope{
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolHTTP,
				Message:   &envelope.HTTPMessage{Method: "GET", Headers: tc.headers},
			}
			tgt, ok := dispatchTarget(env)
			if !ok {
				t.Fatal("expected ok")
			}
			isWS := tgt.Protocol == pluginv2.ProtoWS && tgt.Event == pluginv2.EventOnUpgrade
			if isWS != tc.want {
				t.Errorf("isWS = %v, want %v (target=%+v)", isWS, tc.want, tgt)
			}
		})
	}
}

func TestDispatchTarget_WSMessage(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolWebSocket,
		Message:  &envelope.WSMessage{Opcode: envelope.WSText},
	}
	tgt, _ := dispatchTarget(env)
	if tgt.Protocol != pluginv2.ProtoWS || tgt.Event != pluginv2.EventOnMessage {
		t.Errorf("target = %+v", tgt)
	}
}

func TestDispatchTarget_GRPCStartByProtocol(t *testing.T) {
	cases := []struct {
		envProto envelope.Protocol
		want     string
	}{
		{envelope.ProtocolGRPC, pluginv2.ProtoGRPC},
		{envelope.ProtocolGRPCWeb, pluginv2.ProtoGRPCWeb},
	}
	for _, tc := range cases {
		t.Run(string(tc.envProto), func(t *testing.T) {
			env := &envelope.Envelope{
				Protocol: tc.envProto,
				Message:  &envelope.GRPCStartMessage{Service: "S", Method: "M"},
			}
			tgt, _ := dispatchTarget(env)
			if tgt.Protocol != tc.want {
				t.Errorf("Protocol = %q, want %q", tgt.Protocol, tc.want)
			}
			if tgt.Event != pluginv2.EventOnStart {
				t.Errorf("Event = %q", tgt.Event)
			}
		})
	}
}

func TestDispatchTarget_GRPCDataByProtocol(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolGRPCWeb,
		Message:  &envelope.GRPCDataMessage{Service: "S", Method: "M"},
	}
	tgt, _ := dispatchTarget(env)
	if tgt.Protocol != pluginv2.ProtoGRPCWeb || tgt.Event != pluginv2.EventOnData {
		t.Errorf("target = %+v", tgt)
	}
}

func TestDispatchTarget_GRPCEndIsNotDispatched(t *testing.T) {
	env := &envelope.Envelope{
		Protocol: envelope.ProtocolGRPC,
		Message:  &envelope.GRPCEndMessage{Status: 0},
	}
	if _, ok := dispatchTarget(env); ok {
		t.Error("GRPCEnd should not surface via PluginStepPre/Post (lifecycle)")
	}
}

func TestDispatchTarget_SSEAndRaw(t *testing.T) {
	sseEnv := &envelope.Envelope{
		Protocol: envelope.ProtocolSSE,
		Message:  &envelope.SSEMessage{Data: "x"},
	}
	tgt, _ := dispatchTarget(sseEnv)
	if tgt.Protocol != pluginv2.ProtoSSE || tgt.Event != pluginv2.EventOnEvent {
		t.Errorf("sse target = %+v", tgt)
	}

	rawEnv := &envelope.Envelope{
		Protocol: envelope.ProtocolRaw,
		Message:  &envelope.RawMessage{Bytes: []byte("x")},
	}
	tgt, _ = dispatchTarget(rawEnv)
	if tgt.Protocol != pluginv2.ProtoRaw || tgt.Event != pluginv2.EventOnChunk {
		t.Errorf("raw target = %+v", tgt)
	}
}

func TestDispatchTarget_UnknownMessageType(t *testing.T) {
	env := &envelope.Envelope{Protocol: envelope.ProtocolHTTP, Message: nil}
	if _, ok := dispatchTarget(env); ok {
		t.Error("nil Message should not have a target")
	}
}

func TestHeaderValueContainsToken(t *testing.T) {
	cases := []struct {
		v, tok string
		want   bool
	}{
		{"Upgrade", "upgrade", true},
		{"keep-alive, Upgrade", "upgrade", true},
		{"keep-alive,upgrade", "upgrade", true},
		{"  Upgrade  ", "upgrade", true},
		{"close", "upgrade", false},
		{"Upgraded", "upgrade", false},
		{"", "upgrade", false},
	}
	for _, c := range cases {
		got := headerValueContainsToken(c.v, c.tok)
		if got != c.want {
			t.Errorf("headerValueContainsToken(%q, %q) = %v, want %v", c.v, c.tok, got, c.want)
		}
	}
}
