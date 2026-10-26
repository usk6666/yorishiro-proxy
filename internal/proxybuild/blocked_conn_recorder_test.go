package proxybuild

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

func TestNewBlockedConnRecorder_NilStoreRecordsNothing(t *testing.T) {
	r := newBlockedConnRecorder(nil, "l", silentLogger(), nil)
	if r != nil {
		t.Fatalf("newBlockedConnRecorder(nil store) = %+v, want nil", r)
	}
	// A nil recorder is safe to call.
	r.record(context.Background(), blockedConn{BlockedBy: "rate_limit"})
}

func TestBlockedConnRecorder_Record(t *testing.T) {
	excluded := flow.NewRecordScope()
	excluded.SetRules(nil, []flow.ScopeRule{{Hostname: "excluded.example"}})

	tests := []struct {
		name      string
		scope     *flow.RecordScope
		host      string
		wantSaved int
	}{
		{name: "no capture_scope records", scope: nil, host: "a.example", wantSaved: 1},
		{name: "in-scope host records", scope: excluded, host: "a.example", wantSaved: 1},
		{name: "excluded host is not recorded", scope: excluded, host: "excluded.example", wantSaved: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &recordingFlowStore{}
			r := newBlockedConnRecorder(store, "fwd", silentLogger(), tt.scope)
			ctx := connector.ContextWithConnID(context.Background(), "conn-1")
			r.record(ctx, blockedConn{
				Protocol:      "raw",
				Scheme:        "http",
				ClientAddr:    "127.0.0.1:5555",
				ScopeHost:     tt.host,
				BlockedBy:     "rate_limit",
				FailureReason: "rate_limit",
				Tags:          map[string]string{"via": "tcp-forward"},
			})
			store.mu.Lock()
			defer store.mu.Unlock()
			if len(store.saved) != tt.wantSaved {
				t.Fatalf("saved %d Streams, want %d", len(store.saved), tt.wantSaved)
			}
			if tt.wantSaved == 0 {
				return
			}
			st := store.saved[0]
			if st.State != "error" || st.BlockedBy != "rate_limit" || st.FailureReason != "rate_limit" {
				t.Errorf("Stream State=%q BlockedBy=%q FailureReason=%q", st.State, st.BlockedBy, st.FailureReason)
			}
			if st.ConnID != "conn-1" || st.ListenerName != "fwd" || st.Origin != flow.OriginProxy {
				t.Errorf("Stream ConnID=%q ListenerName=%q Origin=%q", st.ConnID, st.ListenerName, st.Origin)
			}
			if st.ConnInfo == nil || st.ConnInfo.ClientAddr != "127.0.0.1:5555" || st.ConnInfo.ServerAddr != "" {
				t.Errorf("Stream ConnInfo = %+v", st.ConnInfo)
			}
			if st.Tags["via"] != "tcp-forward" {
				t.Errorf("Stream Tags = %v", st.Tags)
			}
		})
	}
}
