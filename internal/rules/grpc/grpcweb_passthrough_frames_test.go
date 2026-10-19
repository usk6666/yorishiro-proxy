package grpc

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// USK-1203 review round 2 (S-4 / F-4 / S-5): the passthrough body scan must
// see each LPM frame's payload — decompressed when the frame is flagged
// compressed — exactly as the Data path would, and must tolerate every
// plausible base64 alignment of a grpc-web-text body.

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// lpmFrame builds one LPM frame (flags + 4-byte big-endian length + payload).
func lpmFrame(flags byte, payload []byte) []byte {
	n := len(payload)
	return append([]byte{flags, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, payload...)
}

func destructiveSQLEngine(t *testing.T) *SafetyEngine {
	t.Helper()
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSafetyEngine_GRPCWebPassthrough_CompressedFrame(t *testing.T) {
	sql := []byte("DROP TABLE users")
	gzFrame := lpmFrame(0x01, gzipBytes(t, sql))
	binBody := append(append([]byte(nil), gzFrame...), 0x00) // stray byte → MalformedLPM
	textBody := append([]byte(base64.StdEncoding.EncodeToString(append(append([]byte(nil), gzFrame...), 0x00))), '!')
	tests := []struct {
		name    string
		ct      string
		anomaly envelope.AnomalyType
		raw     []byte
	}{
		{"binary gzip frame + stray byte", "application/grpc-web+proto", envelope.AnomalyMalformedGRPCWebLPM, binBody},
		{"text gzip frame + stray byte", "application/grpc-web-text+proto", envelope.AnomalyMalformedGRPCWebBase64, textBody},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := destructiveSQLEngine(t)
			env, msg := makeGRPCWebAnomalyStartEnv(tt.ct, tt.anomaly, tt.raw)
			msg.Encoding = "gzip"
			if v := e.CheckInput(context.Background(), env, msg); v == nil {
				t.Fatal("gzip-compressed destructive payload in a malformed body was not blocked")
			}
		})
	}
}

// TestSafetyEngine_GRPCWebPassthrough_UndecodableCompressedFrameFailsClosed —
// a compressed frame the scanner cannot inflate (corrupt gzip, unsupported
// grpc-encoding) is reported as a violation when payload/body rules are
// loaded: the bytes are forwarded verbatim and could not be inspected.
func TestSafetyEngine_GRPCWebPassthrough_UndecodableCompressedFrameFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		encoding string
		payload  []byte
	}{
		{"corrupt gzip", "gzip", []byte("not-gzip-at-all")},
		{"unsupported encoding", "br", []byte("opaque-brotli-bytes")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := append(lpmFrame(0x01, tt.payload), 0x00)
			env, msg := makeGRPCWebAnomalyStartEnv("application/grpc-web+proto", envelope.AnomalyMalformedGRPCWebLPM, body)
			msg.Encoding = tt.encoding

			if v := destructiveSQLEngine(t).CheckInput(context.Background(), env, msg); v == nil {
				t.Error("undecodable compressed frame with body rules loaded: want fail-closed violation")
			}

			// Only a metadata rule loaded: nothing payload-targeted to fail
			// closed for.
			e := NewSafetyEngine()
			re, _ := common.CompilePattern(`never-matches-xyz`)
			e.AddRule(common.CompiledRule{ID: "md", Name: "md", Pattern: re, Targets: []common.Target{TargetMetadata}})
			if v := e.CheckInput(context.Background(), env, msg); v != nil {
				t.Errorf("metadata-only engine: got violation %+v, want none", v)
			}
		})
	}
}

// TestSafetyEngine_GRPCWebPassthrough_AnchoredPayloadRule — F-4: a rule
// anchored at the start of the payload (`^DROP`) matches on the Data path;
// it must match the same frame payload inside a malformed body too.
func TestSafetyEngine_GRPCWebPassthrough_AnchoredPayloadRule(t *testing.T) {
	e := NewSafetyEngine()
	re, err := common.CompilePattern(`^DROP TABLE`)
	if err != nil {
		t.Fatal(err)
	}
	e.AddRule(common.CompiledRule{ID: "anchored", Name: "anchored", Pattern: re, Targets: []common.Target{TargetPayload}})
	body := append(lpmFrame(0x00, []byte("DROP TABLE users")), 0x00)
	env, msg := makeGRPCWebAnomalyStartEnv("application/grpc-web+proto", envelope.AnomalyMalformedGRPCWebLPM, body)
	if v := e.CheckInput(context.Background(), env, msg); v == nil {
		t.Fatal("anchored payload rule did not match the frame payload of a malformed body")
	}
}

// TestSafetyEngine_GRPCWebPassthrough_PaddingIgnoredAlignment — S-5: a
// decoder that ignores every '=' aligns "QU=" + rest differently from one
// that restarts the quantum at '='. The deny-only scan must try both.
func TestSafetyEngine_GRPCWebPassthrough_PaddingIgnoredAlignment(t *testing.T) {
	full := base64.RawStdEncoding.EncodeToString([]byte("A DROP TABLE users"))
	raw := []byte(full[:2] + "=" + full[2:])
	// Precondition: restart-at-'=' decoding does not reveal the payload.
	if got := lenientBase64Decode(raw); bytes.Contains(got, []byte("DROP TABLE")) {
		t.Fatalf("fixture invalid: restart decode already reveals the payload: %q", got)
	}
	env, msg := makeGRPCWebAnomalyStartEnv("application/grpc-web-text+proto", envelope.AnomalyMalformedGRPCWebBase64, raw)
	if v := destructiveSQLEngine(t).CheckInput(context.Background(), env, msg); v == nil {
		t.Fatal("payload visible only to an '='-ignoring decoder was not blocked")
	}
}
