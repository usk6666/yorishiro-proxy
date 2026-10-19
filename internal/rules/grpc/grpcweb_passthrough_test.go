package grpc

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// USK-1203 review findings F-1 / S-1: a gRPC-Web Start emitted for a body
// that failed to parse carries the whole observed body on Envelope.Raw, and
// the upstream-side grpcweb Layer forwards that body verbatim. The rule
// engines must neither destroy that body (F-1) nor let it bypass the Input
// SafetyFilter's body/payload rules (S-1).

// malformedSQLBody is a valid LPM frame carrying a destructive SQL payload
// followed by one stray byte — readAllFrames fails with an incomplete frame
// header, so the layer emits only a Start (Raw = this body) + sentinel End,
// and no GRPCDataMessage ever reaches the payload target.
func malformedSQLBody() []byte {
	payload := []byte("DROP TABLE users")
	b := []byte{0x00, 0x00, 0x00, 0x00, byte(len(payload))}
	b = append(b, payload...)
	return append(b, 0x00)
}

func makeGRPCWebAnomalyStartEnv(ct string, anomaly envelope.AnomalyType, raw []byte) (*envelope.Envelope, *envelope.GRPCStartMessage) {
	env, msg := makeStartEnv(envelope.Send, "pkg.Echo", "Say", nil)
	env.Protocol = envelope.ProtocolGRPCWeb
	env.Raw = raw
	msg.ContentType = ct
	msg.Anomalies = []envelope.Anomaly{{Type: anomaly, Detail: "test"}}
	return env, msg
}

func TestTransformStart_KeepsGRPCWebPassthroughRaw(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionSend, "", "",
		TransformAddMetadata, "X-Trace-Id", "abc", "", "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	body := malformedSQLBody()
	env, msg := makeGRPCWebAnomalyStartEnv("application/grpc-web+proto", envelope.AnomalyMalformedGRPCWebLPM, body)
	if !e.TransformStart(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	if metadataGet(msg.Metadata, "X-Trace-Id") != "abc" {
		t.Errorf("metadata not applied: %v", msg.Metadata)
	}
	if !bytes.Equal(env.Raw, body) {
		t.Errorf("env.Raw = %q, want the passthrough body %q preserved", env.Raw, body)
	}
}

// TestTransformStart_ClearsRawOutsideGRPCWebPassthrough pins the narrow
// scope of the F-1 fix: a native gRPC Start (Raw = HEADERS snapshot) and a
// gRPC-Web Start without a malformed-body anomaly still have Raw cleared.
func TestTransformStart_ClearsRawOutsideGRPCWebPassthrough(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionSend, "", "",
		TransformAddMetadata, "X-Trace-Id", "abc", "", "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	native, nmsg := makeStartEnv(envelope.Send, "pkg.Echo", "Say", nil)
	native.Raw = []byte("hpack")
	nmsg.Anomalies = []envelope.Anomaly{{Type: envelope.AnomalyMalformedGRPCWebLPM}}
	e.TransformStart(context.Background(), native, nmsg)
	if native.Raw != nil {
		t.Errorf("native gRPC Start Raw = %q, want nil", native.Raw)
	}

	web, wmsg := makeGRPCWebAnomalyStartEnv("application/grpc-web+proto", envelope.AnomalyUnexpectedGRPCWebRequestTrailer, []byte("x"))
	e.TransformStart(context.Background(), web, wmsg)
	if web.Raw != nil {
		t.Errorf("gRPC-Web Start without malformed-body anomaly Raw = %q, want nil", web.Raw)
	}
}

func TestSafetyEngine_GRPCWebPassthroughBody(t *testing.T) {
	body := malformedSQLBody()
	textBody := append(encodeTestBase64(body), '!') // invalid base64 tail
	tests := []struct {
		name    string
		ct      string
		anomaly envelope.AnomalyType
		raw     []byte
		want    bool
	}{
		{"binary malformed LPM", "application/grpc-web+proto", envelope.AnomalyMalformedGRPCWebLPM, body, true},
		{"text malformed base64", "application/grpc-web-text+proto", envelope.AnomalyMalformedGRPCWebBase64, textBody, true},
		{"text malformed trailer raw match", "application/grpc-web-text", envelope.AnomalyMalformedGRPCWebTrailer, []byte("DROP TABLE users"), true},
		// USK-1219 review S-3: duplicate Content-Type entries are relayed
		// verbatim, and the Start's ContentType is only the first. A
		// binary first value with a later -text value and a base64 body
		// fails LPM parsing; a backend honouring the last value decodes
		// the base64, so the scan must too.
		{"binary content-type base64 body", "application/grpc-web+proto", envelope.AnomalyMalformedGRPCWebLPM, encodeTestBase64(malformedSQLBody()[:21]), true},
		{"benign malformed body", "application/grpc-web+proto", envelope.AnomalyMalformedGRPCWebLPM, []byte{0x00, 0x00, 0x00, 0x03, 0xe8, 'a'}, false},
		{"no malformed anomaly", "application/grpc-web+proto", envelope.AnomalyUnexpectedGRPCWebRequestTrailer, body, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewSafetyEngine()
			if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
				t.Fatal(err)
			}
			env, msg := makeGRPCWebAnomalyStartEnv(tt.ct, tt.anomaly, tt.raw)
			rawBefore := append([]byte(nil), env.Raw...)
			v := e.CheckInput(context.Background(), env, msg)
			if got := v != nil; got != tt.want {
				t.Fatalf("CheckInput violation = %+v, want violation=%v", v, tt.want)
			}
			if tt.want && v.Target != "payload" {
				t.Errorf("Target = %q, want payload", v.Target)
			}
			if all := e.CheckInputAll(context.Background(), env, msg); (len(all) > 0) != tt.want {
				t.Errorf("CheckInputAll = %d violations, want violation=%v", len(all), tt.want)
			}
			if !bytes.Equal(env.Raw, rawBefore) {
				t.Errorf("CheckInput mutated env.Raw")
			}
		})
	}
}

// encodeTestBase64 is the grpc-web-text wire form of b.
func encodeTestBase64(b []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(b))
}
