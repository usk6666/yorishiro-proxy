package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
)

func TestValidateFuzzParams_AttackType(t *testing.T) {
	t.Parallel()

	// base returns a valid fuzzParams with all required fields populated.
	base := func() fuzzParams {
		return fuzzParams{
			FlowID:     "flow-1",
			AttackType: "sequential",
			Positions: []fuzzer.Position{
				{ID: "pos-0", Location: "body_regex"},
			},
		}
	}

	tests := []struct {
		name       string
		attackType string
		wantErr    string
	}{
		{
			name:       "valid sequential",
			attackType: "sequential",
		},
		{
			name:       "valid parallel",
			attackType: "parallel",
		},
		{
			name:       "empty attack_type includes valid values",
			attackType: "",
			wantErr:    "attack_type is required for fuzz action: valid values are sequential, parallel",
		},
		{
			name:       "invalid attack_type includes valid values",
			attackType: "unknown",
			wantErr:    `invalid attack_type "unknown": valid values are sequential, parallel`,
		},
		{
			name:       "similar but wrong value",
			attackType: "Sequential",
			wantErr:    `invalid attack_type "Sequential": valid values are sequential, parallel`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := base()
			p.AttackType = tt.attackType
			err := validateFuzzParams(p)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %q, got nil", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Errorf("error mismatch:\n  got:  %s\n  want: %s", err.Error(), tt.wantErr)
			}
		})
	}
}

// fuzzTestStore is a minimal flow.Store stub used only by fuzz_tool tests.
// It returns pre-configured flows and messages; unimplemented methods panic.
type fuzzTestStore struct {
	flow              *flow.Flow
	messages          []*flow.Message
	getMessagesCalled bool
}

func (s *fuzzTestStore) GetFlow(_ context.Context, _ string) (*flow.Flow, error) {
	return s.flow, nil
}

func (s *fuzzTestStore) GetMessages(_ context.Context, _ string, _ flow.MessageListOptions) ([]*flow.Message, error) {
	s.getMessagesCalled = true
	return s.messages, nil
}

// The remaining Store interface methods are unused in these tests.
func (s *fuzzTestStore) ListFlows(context.Context, flow.ListOptions) ([]*flow.Flow, error) {
	panic("not implemented")
}
func (s *fuzzTestStore) CountFlows(context.Context, flow.ListOptions) (int, error) {
	panic("not implemented")
}
func (s *fuzzTestStore) CountMessages(context.Context, string) (int, error) {
	panic("not implemented")
}
func (s *fuzzTestStore) SaveFlow(context.Context, *flow.Flow) error { panic("not implemented") }
func (s *fuzzTestStore) UpdateFlow(context.Context, string, flow.FlowUpdate) error {
	panic("not implemented")
}
func (s *fuzzTestStore) AppendMessage(context.Context, *flow.Message) error {
	panic("not implemented")
}
func (s *fuzzTestStore) DeleteFlow(context.Context, string) error { panic("not implemented") }
func (s *fuzzTestStore) DeleteAllFlows(context.Context) (int64, error) {
	panic("not implemented")
}
func (s *fuzzTestStore) DeleteFlowsByProtocol(context.Context, string) (int64, error) {
	panic("not implemented")
}
func (s *fuzzTestStore) DeleteFlowsOlderThan(context.Context, time.Time) (int64, error) {
	panic("not implemented")
}
func (s *fuzzTestStore) DeleteExcessFlows(context.Context, int) (int64, error) {
	panic("not implemented")
}
func (s *fuzzTestStore) SaveMacro(context.Context, string, string, string) error {
	panic("not implemented")
}
func (s *fuzzTestStore) GetMacro(context.Context, string) (*flow.MacroRecord, error) {
	panic("not implemented")
}
func (s *fuzzTestStore) ListMacros(context.Context) ([]*flow.MacroRecord, error) {
	panic("not implemented")
}
func (s *fuzzTestStore) DeleteMacro(context.Context, string) error { panic("not implemented") }

func TestHandleFuzzStart_RejectsGRPCFlow(t *testing.T) {
	t.Parallel()

	store := &fuzzTestStore{
		flow: &flow.Flow{
			ID:       "flow-grpc-1",
			Protocol: "gRPC",
		},
		messages: []*flow.Message{},
	}

	srv := &Server{deps: &deps{store: store}}

	params := fuzzParams{
		FlowID:     "flow-grpc-1",
		AttackType: "sequential",
		Positions: []fuzzer.Position{
			{ID: "pos-0", Location: "body_regex"},
		},
	}

	_, _, err := srv.handleFuzzStart(context.Background(), params)
	if err == nil {
		t.Fatal("expected error for gRPC flow, got nil")
	}

	want := "fuzzing gRPC flows is not yet supported: gRPC uses length-prefixed protobuf frames that require frame-aware mutation"
	if err.Error() != want {
		t.Errorf("error mismatch:\n  got:  %s\n  want: %s", err.Error(), want)
	}

	// Verify that GetMessages was NOT called — the gRPC guard should
	// short-circuit before loading messages.
	if store.getMessagesCalled {
		t.Error("GetMessages should not be called for rejected gRPC flows")
	}
}

func TestHandleFuzzStart_AllowsHTTPFlow(t *testing.T) {
	t.Parallel()

	store := &fuzzTestStore{
		flow: &flow.Flow{
			ID:       "flow-http-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*flow.Message{},
	}

	// Server with store but no fuzzRunner — should pass the gRPC guard
	// and fail later at "fuzz runner is not initialized".
	srv := &Server{deps: &deps{store: store}}

	params := fuzzParams{
		FlowID:     "flow-http-1",
		AttackType: "sequential",
		Positions: []fuzzer.Position{
			{ID: "pos-0", Location: "body_regex"},
		},
	}

	_, _, err := srv.handleFuzzStart(context.Background(), params)
	if err == nil {
		t.Fatal("expected error (fuzz runner not initialized), got nil")
	}

	// The error should NOT be the gRPC rejection error.
	grpcErr := "fuzzing gRPC flows is not yet supported"
	if strings.Contains(err.Error(), grpcErr) {
		t.Errorf("HTTP flow should not trigger gRPC rejection, got: %s", err.Error())
	}

	// Should reach the "fuzz runner is not initialized" check.
	if !strings.Contains(err.Error(), "fuzz runner is not initialized") {
		t.Errorf("expected 'fuzz runner is not initialized' error, got: %s", err.Error())
	}
}
