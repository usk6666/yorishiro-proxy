package proxybuild

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	wsrules "github.com/usk6666/yorishiro-proxy/internal/rules/ws"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// queueChannel is a minimal layer.Channel: Next yields the queued
// envelopes, then io.EOF.
type queueChannel struct {
	mu        sync.Mutex
	streamID  string
	queue     []*envelope.Envelope
	closeOnce sync.Once
	done      chan struct{}
}

func newQueueChannel(streamID string, envs ...*envelope.Envelope) *queueChannel {
	return &queueChannel{streamID: streamID, queue: envs, done: make(chan struct{})}
}

func (c *queueChannel) StreamID() string { return c.streamID }

func (c *queueChannel) Next(context.Context) (*envelope.Envelope, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.queue) == 0 {
		return nil, io.EOF
	}
	env := c.queue[0]
	c.queue = c.queue[1:]
	return env, nil
}

func (c *queueChannel) Send(context.Context, *envelope.Envelope) error { return nil }

func (c *queueChannel) Close() error {
	c.closeOnce.Do(func() { close(c.done) })
	return nil
}

func (c *queueChannel) Closed() <-chan struct{} { return c.done }

func (c *queueChannel) Err() error {
	select {
	case <-c.done:
		return io.EOF
	default:
		return nil
	}
}

// laterDropStep stands in for a Step after SafetyStep that ends the chain
// with an attributed Drop (intercept drop, scope re-check, ...).
type laterDropStep struct{}

func (laterDropStep) Process(context.Context, *envelope.Envelope) pipeline.Result {
	return pipeline.Result{Action: pipeline.Drop, BlockedBy: pipeline.BlockedByInterceptDrop}
}

// USK-1109 review F-2: a log_only SafetyStep match followed by a later
// Step that Drops must still leave the safety_log_only:* observation on
// the audit Stream the block recorder writes — both on the first-request
// SaveStream branch and on the mid-stream UpdateStream branch. The
// non-continuing Step's own annotations are not merged (it has none here).
func TestSessionOptions_PipelineDrop_RecordsEarlierLogOnlyAnnotations(t *testing.T) {
	httpSafety := httprules.NewSafetyEngine()
	if err := httpSafety.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}
	wsSafety := wsrules.NewSafetyEngine()
	pat, err := common.CompilePattern(`(?i)password=`)
	if err != nil {
		t.Fatal(err)
	}
	wsSafety.AddRule(common.CompiledRule{ID: "ws:password-leak", Name: "pw", Pattern: pat, Targets: []common.Target{wsrules.TargetPayload}})

	tests := []struct {
		name       string
		seedActive bool
		env        *envelope.Envelope
		wantKey    string
	}{
		{
			name: "first request (SaveStream)",
			env: &envelope.Envelope{
				StreamID: "stream-f2", FlowID: "f", Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
				Message: &envelope.HTTPMessage{Method: "POST", Scheme: "http", Authority: "example.com", Path: "/api", Body: []byte("DROP TABLE users")},
			},
			wantKey: pipeline.SafetyLogOnlyTagPrefix + "destructive-sql:drop",
		},
		{
			name:       "mid-stream (UpdateStream)",
			seedActive: true,
			env: &envelope.Envelope{
				StreamID: "stream-f2", FlowID: "f", Sequence: 3, Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
				Message: &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("password=hunter2")},
			},
			wantKey: pipeline.SafetyLogOnlyTagPrefix + "ws:password-leak",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newSQLiteStoreForTest(t)
			if tc.seedActive {
				seedActiveStreamWithTags(t, store, "stream-f2", map[string]string{"pre": "kept"})
			}
			deps := Deps{ListenerName: "live", FlowStore: store}
			opts := buildSessionOptions(deps, deps.ListenerName)
			p := pipeline.New(
				pipeline.NewSafetyStep(httpSafety, wsSafety, nil, nil).WithLogOnly(true),
				laterDropStep{},
				pipeline.NewRecordStep(store, nil),
			)
			dial := func(context.Context, *envelope.Envelope) (layer.Channel, error) {
				return newQueueChannel("up"), nil
			}
			if err := session.RunSession(context.Background(), newQueueChannel("stream-f2", tc.env), dial, p, opts); err != nil {
				t.Fatalf("RunSession: %v", err)
			}

			st, err := store.GetStream(context.Background(), "stream-f2")
			if err != nil {
				t.Fatalf("GetStream: %v (audit Stream not written)", err)
			}
			if st.BlockedBy != pipeline.BlockedByInterceptDrop {
				t.Errorf("BlockedBy = %q, want %q", st.BlockedBy, pipeline.BlockedByInterceptDrop)
			}
			if st.Tags[tc.wantKey] == "" {
				t.Errorf("audit Stream.Tags = %v, want %q (log_only observation lost on later Drop)", st.Tags, tc.wantKey)
			}
			if tc.seedActive && st.Tags["pre"] != "kept" {
				t.Errorf("audit Stream.Tags = %v, pre-existing tag clobbered", st.Tags)
			}
		})
	}
}
