package pipeline

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/flow/flowtest"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
)

// USK-1109 review F-1: in log_only the live wire must observe EVERY
// matching rule, not just the first — otherwise a noisy early rule hides
// later ones, defeating the point of a dry run. The MCP-plane
// safety.Engine.CheckInput already logs every log_only match.
func TestSafetyStep_LogOnly_AnnotatesEveryMatchingRule(t *testing.T) {
	// "DROP TABLE … ; TRUNCATE TABLE …" matches both destructive-sql:drop
	// and destructive-sql:truncate (preset order: drop first).
	const sqlBody = "DROP TABLE users; TRUNCATE TABLE logs;"

	twoRuleWS := func(t *testing.T) *wsrules.SafetyEngine {
		e := newTestWSSafetyEngine(t) // ws:password-leak
		pat, err := common.CompilePattern(`(?i)\bDROP\s+TABLE\b`)
		if err != nil {
			t.Fatal(err)
		}
		e.AddRule(common.CompiledRule{ID: "ws:drop-table", Name: "DROP TABLE", Pattern: pat, Targets: []common.Target{wsrules.TargetPayload}})
		return e
	}

	tests := []struct {
		name    string
		step    func(t *testing.T, logger *slog.Logger) *SafetyStep
		env     func() *envelope.Envelope
		ruleIDs []string
	}{
		{
			name: "http",
			step: func(t *testing.T, l *slog.Logger) *SafetyStep {
				return NewSafetyStep(newTestSafetyEngine(t), nil, nil, l).WithLogOnly(true)
			},
			env: func() *envelope.Envelope {
				return &envelope.Envelope{
					StreamID: "s", Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
					Message: &envelope.HTTPMessage{Method: "POST", Scheme: "http", Authority: "example.com", Path: "/api", Body: []byte(sqlBody)},
				}
			},
			ruleIDs: []string{"destructive-sql:drop", "destructive-sql:truncate"},
		},
		{
			name: "ws",
			step: func(t *testing.T, l *slog.Logger) *SafetyStep {
				return NewSafetyStep(nil, twoRuleWS(t), nil, l).WithLogOnly(true)
			},
			env: func() *envelope.Envelope {
				return &envelope.Envelope{
					StreamID: "s", Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
					Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("password=x; DROP TABLE users")},
				}
			},
			ruleIDs: []string{"ws:password-leak", "ws:drop-table"},
		},
		{
			name: "grpc data",
			step: func(t *testing.T, l *slog.Logger) *SafetyStep {
				return NewSafetyStep(nil, nil, newTestGRPCSafetyEngine(t), l).WithLogOnly(true)
			},
			env: func() *envelope.Envelope {
				return &envelope.Envelope{
					StreamID: "s", Sequence: 1, Direction: envelope.Send, Protocol: envelope.ProtocolGRPC,
					Message: &envelope.GRPCDataMessage{Service: "Admin", Method: "Query", Payload: []byte(sqlBody)},
				}
			},
			ruleIDs: []string{"destructive-sql:drop", "destructive-sql:truncate"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			result := tc.step(t, logger).Process(context.Background(), tc.env())
			if result.Action != Continue {
				t.Fatalf("Action = %v, want Continue", result.Action)
			}
			out := buf.String()
			for _, id := range tc.ruleIDs {
				if _, ok := result.Annotations[SafetyLogOnlyTagPrefix+id]; !ok {
					t.Errorf("Annotations = %v, want key %q", result.Annotations, SafetyLogOnlyTagPrefix+id)
				}
				if !strings.Contains(out, `"rule_id":"`+id+`"`) {
					t.Errorf("log output lacks rule_id %q: %s", id, out)
				}
			}
		})
	}

	// Block mode is still first-match: one rule, one block.
	t.Run("block mode stays first-match", func(t *testing.T) {
		env := &envelope.Envelope{
			StreamID: "s", Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
			Message: &envelope.HTTPMessage{Method: "POST", Scheme: "http", Path: "/api", Body: []byte(sqlBody)},
		}
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, nil))
		r := NewSafetyStep(newTestSafetyEngine(t), nil, nil, logger).Process(context.Background(), env)
		if r.Action != Respond {
			t.Fatalf("Action = %v, want Respond", r.Action)
		}
		if n := strings.Count(buf.String(), `"msg":"safety: request blocked"`); n != 1 {
			t.Errorf("block-mode log records = %d, want 1: %s", n, buf.String())
		}
	})
}

// countingStore wraps the real SQLite store and counts UpdateStream calls
// that carry a safety_log_only AppendTags key.
type countingStore struct {
	*flow.SQLiteStore
	mu         sync.Mutex
	annotWrite int
}

func (c *countingStore) UpdateStream(ctx context.Context, id string, u flow.StreamUpdate) error {
	for k := range u.AppendTags {
		if strings.HasPrefix(k, SafetyLogOnlyTagPrefix) {
			c.mu.Lock()
			c.annotWrite++
			c.mu.Unlock()
			break
		}
	}
	return c.SQLiteStore.UpdateStream(ctx, id, u)
}

// USK-1109 review F-3 / S-1 (CWE-400): a flood of matching frames on one
// Stream must not issue one tag write per frame. The first observation is
// written; repeats of the same (key, value) on the same Stream are skipped.
// The same key on another Stream still writes.
func TestRecordStep_LogOnlyAnnotation_WrittenOncePerStream(t *testing.T) {
	ctx := context.Background()
	store := &countingStore{SQLiteStore: flowtest.NewStore(t)}
	p := New(
		NewSafetyStep(nil, newTestWSSafetyEngine(t), nil, nil).WithLogOnly(true),
		NewRecordStep(store, nil),
	)
	frame := func(streamID string, seq int) *envelope.Envelope {
		payload := []byte("password=hunter2")
		return &envelope.Envelope{
			StreamID: streamID, FlowID: streamID + "-f", Sequence: seq,
			Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
			Raw:     append([]byte("\x81\x10"), payload...),
			Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: payload},
		}
	}
	for i := 0; i < 20; i++ {
		if _, action, _ := p.Run(ctx, frame("stream-flood", i)); action != Continue {
			t.Fatalf("frame %d action = %v", i, action)
		}
	}
	if store.annotWrite != 1 {
		t.Errorf("annotation tag writes for 20 matching frames on one Stream = %d, want 1", store.annotWrite)
	}
	st, err := store.GetStream(ctx, "stream-flood")
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if st.Tags[SafetyLogOnlyTagPrefix+"ws:password-leak"] == "" {
		t.Errorf("Stream.Tags = %v, want the log_only tag", st.Tags)
	}

	// A second Stream is tagged independently.
	if _, action, _ := p.Run(ctx, frame("stream-other", 0)); action != Continue {
		t.Fatalf("other stream action = %v", action)
	}
	if store.annotWrite != 2 {
		t.Errorf("annotation tag writes after a second Stream = %d, want 2", store.annotWrite)
	}
	st, err = store.GetStream(ctx, "stream-other")
	if err != nil {
		t.Fatalf("GetStream other: %v", err)
	}
	if st.Tags[SafetyLogOnlyTagPrefix+"ws:password-leak"] == "" {
		t.Errorf("other Stream.Tags = %v, want the log_only tag", st.Tags)
	}
}
