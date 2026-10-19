package pipeline

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow/flowtest"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// USK-1109: safety_filter.input.action "log_only" must let a violating
// Send envelope through (Continue, no BlockedBy, env untouched), log the
// match without the raw fragment, and annotate the result so RecordStep can
// tag the Stream. Block mode stays unchanged (the existing *_Drop /
// *_Respond tests in safety_step_test.go are the reverse guard).

// logOnlyCase is one violating Send envelope per SafetyStep arm. The
// fixtures mirror the block-mode fixtures in safety_step_test.go (the
// shapes the per-protocol Layers emit).
type logOnlyCase struct {
	name    string
	ruleID  string
	newStep func(t *testing.T, logger *slog.Logger) *SafetyStep
	newEnv  func() *envelope.Envelope
}

func logOnlyCases() []logOnlyCase {
	return []logOnlyCase{
		{
			name:   "http body",
			ruleID: "destructive-sql:drop",
			newStep: func(t *testing.T, logger *slog.Logger) *SafetyStep {
				return NewSafetyStep(newTestSafetyEngine(t), nil, nil, logger).WithLogOnly(true)
			},
			newEnv: func() *envelope.Envelope {
				return &envelope.Envelope{
					StreamID:  "s-http",
					FlowID:    "f-http",
					Direction: envelope.Send,
					Protocol:  envelope.ProtocolHTTP,
					Raw:       []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 16\r\n\r\nDROP TABLE users"),
					Message: &envelope.HTTPMessage{
						Method:    "POST",
						Scheme:    "https",
						Authority: "example.com",
						Path:      "/api",
						Headers:   []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
						Body:      []byte("DROP TABLE users"),
					},
				}
			},
		},
		{
			name:   "ws text frame",
			ruleID: "ws:password-leak",
			newStep: func(t *testing.T, logger *slog.Logger) *SafetyStep {
				return NewSafetyStep(nil, newTestWSSafetyEngine(t), nil, logger).WithLogOnly(true)
			},
			newEnv: func() *envelope.Envelope {
				payload := []byte(`{"login":"admin","password=hunter2"}`)
				return &envelope.Envelope{
					StreamID:  "s-ws",
					FlowID:    "f-ws",
					Sequence:  3,
					Direction: envelope.Send,
					Protocol:  envelope.ProtocolWebSocket,
					Raw:       append([]byte("\x81\x24"), payload...),
					Message:   &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: payload},
				}
			},
		},
		{
			name:   "grpc start",
			ruleID: "destructive-sql:drop",
			newStep: func(t *testing.T, logger *slog.Logger) *SafetyStep {
				return NewSafetyStep(nil, nil, newTestGRPCSafetyEngine(t), logger).WithLogOnly(true)
			},
			newEnv: func() *envelope.Envelope {
				// USK-1073: the gRPC engine scans the :path query on Start.
				return &envelope.Envelope{
					StreamID:  "s-grpc-start",
					FlowID:    "f-grpc-start",
					Direction: envelope.Send,
					Protocol:  envelope.ProtocolGRPC,
					Message: &envelope.GRPCStartMessage{
						Scheme:    "https",
						Authority: "api.example.com",
						Service:   "Admin",
						Method:    "Query",
						Path:      "/Admin/Query",
						RawQuery:  "q=DROP TABLE users;",
					},
				}
			},
		},
		{
			name:   "grpc data",
			ruleID: "destructive-sql:drop",
			newStep: func(t *testing.T, logger *slog.Logger) *SafetyStep {
				return NewSafetyStep(nil, nil, newTestGRPCSafetyEngine(t), logger).WithLogOnly(true)
			},
			newEnv: func() *envelope.Envelope {
				payload := []byte("DROP TABLE users")
				return &envelope.Envelope{
					StreamID:  "s-grpc-data",
					FlowID:    "f-grpc-data",
					Sequence:  1,
					Direction: envelope.Send,
					Protocol:  envelope.ProtocolGRPC,
					Raw:       append([]byte("\x00\x00\x00\x00\x10"), payload...),
					Message:   &envelope.GRPCDataMessage{Service: "Admin", Method: "Query", Payload: payload, WireLength: uint32(len(payload))},
				}
			},
		},
		{
			name:   "grpc-web data",
			ruleID: "destructive-sql:drop",
			newStep: func(t *testing.T, logger *slog.Logger) *SafetyStep {
				return NewSafetyStep(nil, nil, newTestGRPCSafetyEngine(t), logger).WithLogOnly(true)
			},
			newEnv: func() *envelope.Envelope {
				return &envelope.Envelope{
					StreamID:  "s-grpcweb",
					FlowID:    "f-grpcweb",
					Sequence:  1,
					Direction: envelope.Send,
					Protocol:  envelope.ProtocolGRPCWeb,
					Message:   &envelope.GRPCDataMessage{Service: "Admin", Method: "Query", Payload: []byte("DROP TABLE users")},
				}
			},
		},
	}
}

func TestSafetyStep_LogOnly_PassesViolatingEnvelope(t *testing.T) {
	for _, tc := range logOnlyCases() {
		t.Run(tc.name, func(t *testing.T) {
			step := tc.newStep(t, nil)
			env := tc.newEnv()
			before := env.Clone()

			result := step.Process(context.Background(), env)

			if result.Action != Continue {
				t.Fatalf("Action = %v, want Continue (log_only must not block)", result.Action)
			}
			if result.BlockedBy != "" {
				t.Errorf("BlockedBy = %q, want empty", result.BlockedBy)
			}
			if result.Response != nil {
				t.Errorf("Response = %+v, want nil", result.Response)
			}
			if result.Envelope != nil {
				t.Errorf("Result.Envelope = %+v, want nil (env forwarded unchanged)", result.Envelope)
			}
			wantKey := "safety_log_only:" + tc.ruleID
			if _, ok := result.Annotations[wantKey]; !ok {
				t.Errorf("Annotations = %v, want key %q", result.Annotations, wantKey)
			}
			// Wire fidelity (RFC-001 Principle 1): env, Raw and Message are
			// untouched on the log_only pass.
			if !bytes.Equal(env.Raw, before.Raw) {
				t.Errorf("env.Raw mutated: got %q, want %q", env.Raw, before.Raw)
			}
			if envelopeModified(before, env) {
				t.Errorf("env.Message mutated on log_only pass")
			}
		})
	}
}

func TestSafetyStep_LogOnly_LogsRedactedMatch(t *testing.T) {
	for _, tc := range logOnlyCases() {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			step := tc.newStep(t, logger)

			step.Process(context.Background(), tc.newEnv())

			out := buf.String()
			if !strings.Contains(out, `"msg":"safety: match observed (log_only, not blocked)"`) {
				t.Fatalf("no log_only record in log output: %s", out)
			}
			if !strings.Contains(out, `"level":"INFO"`) {
				t.Errorf("log_only record is not Info: %s", out)
			}
			if !strings.Contains(out, `"rule_id":"`+tc.ruleID+`"`) {
				t.Errorf("log output lacks rule_id %q: %s", tc.ruleID, out)
			}
			if !strings.Contains(out, `"filter":"safety_filter"`) {
				t.Errorf("log output lacks filter=safety_filter: %s", out)
			}
			if !strings.Contains(out, `"target":`) {
				t.Errorf("log output lacks target: %s", out)
			}
			for _, raw := range []string{"DROP TABLE", "DROP%20TABLE", "password=hunter2", "password="} {
				if strings.Contains(out, raw) {
					t.Errorf("log output contains raw matched fragment %q (CWE-312): %s", raw, out)
				}
			}
		})
	}
}

// TestSafetyStep_Block_LogRedactsMatch: the existing block-mode Info log
// must no longer carry the raw matched fragment either (CWE-312).
func TestSafetyStep_Block_LogRedactsMatch(t *testing.T) {
	for _, tc := range logOnlyCases() {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			step := tc.newStep(t, logger).WithLogOnly(false)

			result := step.Process(context.Background(), tc.newEnv())
			if result.Action == Continue {
				t.Fatalf("block mode: Action = Continue, want a block (fixture precondition)")
			}
			if _, ok := result.Annotations["safety_log_only:"+tc.ruleID]; ok {
				t.Errorf("block mode result carries a log_only annotation: %v", result.Annotations)
			}

			out := buf.String()
			if !strings.Contains(out, `"msg":"safety: request blocked"`) {
				t.Fatalf("no block record in log output: %s", out)
			}
			for _, raw := range []string{"DROP TABLE", "DROP%20TABLE", "password=hunter2", "password="} {
				if strings.Contains(out, raw) {
					t.Errorf("block log contains raw matched fragment %q (CWE-312): %s", raw, out)
				}
			}
		})
	}
}

// passStep is a Continue Step that replaces nothing; it stands in for the
// PluginPre / Intercept / Transform / PluginPost Steps that run between
// SafetyStep and RecordStep, proving the annotation survives them.
type passStep struct{}

func (passStep) Process(_ context.Context, env *envelope.Envelope) Result {
	return Result{Envelope: env}
}

// TestPipeline_LogOnlyAnnotation_RecordedAsStreamTag drives the real
// SafetyStep → (intermediate Step) → RecordStep chain against a real
// SQLite flow store and asserts the log_only annotation lands on the
// Stream's tags — both when the violating envelope is the stream's first
// Send (the Stream row does not exist before RecordStep creates it) and
// when it is a later envelope of a streaming protocol (WS frame).
func TestPipeline_LogOnlyAnnotation_RecordedAsStreamTag(t *testing.T) {
	ctx := context.Background()

	t.Run("first send creates stream", func(t *testing.T) {
		store := flowtest.NewStore(t)
		p := New(
			NewSafetyStep(newTestSafetyEngine(t), nil, nil, nil).WithLogOnly(true),
			passStep{},
			NewRecordStep(store, nil),
		)
		env := &envelope.Envelope{
			StreamID:  "stream-first-send",
			FlowID:    "flow-first-send",
			Sequence:  0,
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       []byte("POST /api HTTP/1.1\r\nHost: example.com\r\nContent-Length: 16\r\n\r\nDROP TABLE users"),
			Message: &envelope.HTTPMessage{
				Method: "POST", Scheme: "http", Authority: "example.com", Path: "/api",
				Headers: []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
				Body:    []byte("DROP TABLE users"),
			},
		}
		_, action, _, blockedBy := p.RunWithBlockedBy(ctx, env)
		if action != Continue || blockedBy != "" {
			t.Fatalf("RunWithBlockedBy = (%v, %q), want (Continue, \"\")", action, blockedBy)
		}
		st, err := store.GetStream(ctx, "stream-first-send")
		if err != nil {
			t.Fatalf("GetStream: %v", err)
		}
		if v, ok := st.Tags["safety_log_only:destructive-sql:drop"]; !ok || v == "" {
			t.Errorf("Stream.Tags = %v, want non-empty safety_log_only:destructive-sql:drop", st.Tags)
		}
	})

	t.Run("later ws frame", func(t *testing.T) {
		store := flowtest.NewStore(t)
		p := New(
			NewSafetyStep(nil, newTestWSSafetyEngine(t), nil, nil).WithLogOnly(true),
			passStep{},
			NewRecordStep(store, nil),
		)
		benign := &envelope.Envelope{
			StreamID: "stream-ws", FlowID: "flow-ws-0", Sequence: 0,
			Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
			Raw:     []byte("\x81\x05hello"),
			Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("hello")},
		}
		if _, action, _ := p.Run(ctx, benign); action != Continue {
			t.Fatalf("benign frame action = %v", action)
		}
		st, err := store.GetStream(ctx, "stream-ws")
		if err != nil {
			t.Fatalf("GetStream after benign: %v", err)
		}
		if len(st.Tags) != 0 {
			t.Fatalf("benign frame tagged the stream: %v", st.Tags)
		}

		payload := []byte("password=hunter2")
		bad := &envelope.Envelope{
			StreamID: "stream-ws", FlowID: "flow-ws-2", Sequence: 2,
			Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
			Raw:     append([]byte("\x81\x10"), payload...),
			Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: payload},
		}
		if _, action, _ := p.Run(ctx, bad); action != Continue {
			t.Fatalf("violating frame action = %v, want Continue", action)
		}
		st, err = store.GetStream(ctx, "stream-ws")
		if err != nil {
			t.Fatalf("GetStream after violating frame: %v", err)
		}
		if v, ok := st.Tags["safety_log_only:ws:password-leak"]; !ok || v == "" {
			t.Errorf("Stream.Tags = %v, want non-empty safety_log_only:ws:password-leak", st.Tags)
		}
	})
}

// annotateStep emits a fixed annotation on Continue, standing in for any
// Step that uses the generic Result.Annotations contract.
type annotateStep struct{ tags map[string]string }

func (s annotateStep) Process(_ context.Context, _ *envelope.Envelope) Result {
	return Result{Annotations: s.tags}
}

// TestPipeline_ResultAnnotations_MergedAndRecorded pins the generic
// contract independent of SafetyStep: annotations from several Steps are
// merged, survive a later Step that replaces the envelope, and RecordStep
// appends them to the Stream's tags without clobbering one another.
func TestPipeline_ResultAnnotations_MergedAndRecorded(t *testing.T) {
	ctx := context.Background()
	store := flowtest.NewStore(t)
	p := New(
		annotateStep{tags: map[string]string{"a": "1"}},
		passStep{},
		annotateStep{tags: map[string]string{"b": "2"}},
		NewRecordStep(store, nil),
	)
	env := &envelope.Envelope{
		StreamID: "stream-annot", FlowID: "flow-annot", Sequence: 0,
		Direction: envelope.Send, Protocol: envelope.ProtocolRaw,
		Raw:     []byte("hello"),
		Message: &envelope.RawMessage{Bytes: []byte("hello")},
	}
	if _, action, _ := p.Run(ctx, env); action != Continue {
		t.Fatalf("action = %v, want Continue", action)
	}
	st, err := store.GetStream(ctx, "stream-annot")
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if st.Tags["a"] != "1" || st.Tags["b"] != "2" {
		t.Errorf("Stream.Tags = %v, want a=1 and b=2", st.Tags)
	}
}

// TestInterceptStep_ModifyAndForward_SafetyRecheck_LogOnly: the intercept
// modify_and_forward re-check uses the same *SafetyStep, so in log_only
// mode a destructive modified envelope is forwarded and the observation
// reaches RecordStep through the InterceptStep's Result.
func TestInterceptStep_ModifyAndForward_SafetyRecheck_LogOnly(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, nil, nil, nil, queue, newDestructiveSQLSafetyStep(t).WithLogOnly(true), nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Method: "POST", Path: "/api/query", Body: []byte(`{"query":"SELECT 1"}`)},
	}
	modifiedEnv := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Method: "POST", Path: "/api/query", Body: []byte("DROP TABLE users;")},
	}
	releaseFirst(t, queue, &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modifiedEnv})

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Fatalf("Action = %v, want Continue (log_only re-check must not block)", result.Action)
	}
	if result.Envelope != modifiedEnv {
		t.Errorf("Result.Envelope = %p, want the modified envelope %p", result.Envelope, modifiedEnv)
	}
	if _, ok := result.Annotations["safety_log_only:destructive-sql:drop"]; !ok {
		t.Errorf("Annotations = %v, want safety_log_only:destructive-sql:drop", result.Annotations)
	}
}
