package sse

import (
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func ptrInt64(v int64) *int64 { return &v }

func sseEnvelope(msg *envelope.SSEMessage) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolSSE,
		Message:   msg,
	}
}

func TestInterceptEngine_MatchByEvent(t *testing.T) {
	e := NewInterceptEngine()
	r, err := CompileInterceptRule("r1", DirectionReceive, "^ping$", "", "", nil, nil, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	e.AddRule(*r)

	got := e.Match(sseEnvelope(&envelope.SSEMessage{Event: "ping", Data: "x"}), &envelope.SSEMessage{Event: "ping", Data: "x"})
	if len(got) != 1 || got[0] != "r1" {
		t.Errorf("got %v, want [r1]", got)
	}

	got = e.Match(sseEnvelope(&envelope.SSEMessage{Event: "pong"}), &envelope.SSEMessage{Event: "pong"})
	if got != nil {
		t.Errorf("expected no match for pong, got %v", got)
	}
}

func TestInterceptEngine_MatchByDataAndID(t *testing.T) {
	e := NewInterceptEngine()
	r, err := CompileInterceptRule("r1", "", "", "^msg-\\d+$", "hello", nil, nil, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	e.AddRule(*r)

	msg := &envelope.SSEMessage{Event: "", ID: "msg-42", Data: "hello world"}
	if got := e.Match(sseEnvelope(msg), msg); len(got) != 1 {
		t.Errorf("got %v, want match", got)
	}

	msg.ID = "wrong"
	if got := e.Match(sseEnvelope(msg), msg); got != nil {
		t.Errorf("expected no match, got %v", got)
	}
}

func TestInterceptEngine_RetryRange(t *testing.T) {
	e := NewInterceptEngine()
	r, err := CompileInterceptRule("r1", "", "", "", "", ptrInt64(1000), ptrInt64(5000), nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	e.AddRule(*r)

	cases := []struct {
		retry time.Duration
		want  bool
	}{
		{retry: 0, want: false},                      // unset → skip
		{retry: 500 * time.Millisecond, want: false}, // below min
		{retry: 2000 * time.Millisecond, want: true}, // in range
		{retry: 5000 * time.Millisecond, want: true}, // inclusive max
		{retry: 6000 * time.Millisecond, want: false},
	}
	for _, tc := range cases {
		msg := &envelope.SSEMessage{Retry: tc.retry}
		got := e.Match(sseEnvelope(msg), msg)
		if (len(got) > 0) != tc.want {
			t.Errorf("retry=%v: got %v want %v", tc.retry, got, tc.want)
		}
	}
}

func TestInterceptEngine_Anomalies_OrSemantic(t *testing.T) {
	e := NewInterceptEngine()
	r, err := CompileInterceptRule("r1", "", "", "", "", nil, nil, []string{"SSETruncated", "SSEDuplicateID"})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	e.AddRule(*r)

	hit := &envelope.SSEMessage{Anomalies: []envelope.Anomaly{{Type: envelope.AnomalySSEDuplicateID}}}
	if got := e.Match(sseEnvelope(hit), hit); len(got) != 1 {
		t.Errorf("expected hit, got %v", got)
	}
	miss := &envelope.SSEMessage{Anomalies: []envelope.Anomaly{{Type: "Unrelated"}}}
	if got := e.Match(sseEnvelope(miss), miss); got != nil {
		t.Errorf("expected miss, got %v", got)
	}
}

func TestInterceptEngine_DirectionSendRejected(t *testing.T) {
	if _, err := CompileInterceptRule("r1", "send", "", "", "", nil, nil, nil); err == nil {
		t.Fatal("expected error for direction=send")
	}
}

func TestInterceptEngine_BadRegex(t *testing.T) {
	if _, err := CompileInterceptRule("r1", "", "[", "", "", nil, nil, nil); err == nil {
		t.Fatal("expected error for invalid event pattern")
	}
}

func TestInterceptEngine_RemoveEnableRules(t *testing.T) {
	e := NewInterceptEngine()
	r1, _ := CompileInterceptRule("r1", "", "^a$", "", "", nil, nil, nil)
	r2, _ := CompileInterceptRule("r2", "", "^b$", "", "", nil, nil, nil)
	e.AddRule(*r1)
	e.AddRule(*r2)

	if got := e.Rules(); len(got) != 2 {
		t.Fatalf("Rules len = %d, want 2", len(got))
	}

	if !e.EnableRule("r1", false) {
		t.Fatal("EnableRule(r1,false) returned false")
	}
	msg := &envelope.SSEMessage{Event: "a"}
	if got := e.Match(sseEnvelope(msg), msg); got != nil {
		t.Errorf("disabled rule matched: %v", got)
	}

	if !e.RemoveRule("r1") {
		t.Fatal("RemoveRule(r1) returned false")
	}
	if e.RemoveRule("missing") {
		t.Error("RemoveRule on missing returned true")
	}
}

// TestInterceptEngine_ConcurrentSetRulesAndMatch exercises the RWMutex.
// `go test -race` is the actual gate.
func TestInterceptEngine_ConcurrentSetRulesAndMatch(t *testing.T) {
	e := NewInterceptEngine()
	r, _ := CompileInterceptRule("r1", "", "^.*$", "", "", nil, nil, nil)
	e.AddRule(*r)

	var wg sync.WaitGroup
	wg.Add(2)
	stop := make(chan struct{})
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				r2, _ := CompileInterceptRule("r1", "", "^x$", "", "", nil, nil, nil)
				e.SetRules([]InterceptRule{*r2})
			}
		}
	}()
	go func() {
		defer wg.Done()
		msg := &envelope.SSEMessage{Event: "x"}
		for i := 0; i < 200; i++ {
			_ = e.Match(sseEnvelope(msg), msg)
		}
		close(stop)
	}()
	wg.Wait()
}
