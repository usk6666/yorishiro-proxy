package grpc

import (
	"regexp"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func makeStartEnv(direction envelope.Direction, service, method string, metadata []envelope.KeyValue) (*envelope.Envelope, *envelope.GRPCStartMessage) {
	msg := &envelope.GRPCStartMessage{
		Service:     service,
		Method:      method,
		Metadata:    metadata,
		ContentType: "application/grpc",
	}
	env := &envelope.Envelope{
		Direction: direction,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
	}
	return env, msg
}

func makeDataEnv(direction envelope.Direction, service, method string, payload []byte) (*envelope.Envelope, *envelope.GRPCDataMessage) {
	msg := &envelope.GRPCDataMessage{
		Service:    service,
		Method:     method,
		Payload:    payload,
		WireLength: uint32(len(payload)),
	}
	env := &envelope.Envelope{
		Direction: direction,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
	}
	return env, msg
}

func makeEndEnv(direction envelope.Direction, status uint32, message string) (*envelope.Envelope, *envelope.GRPCEndMessage) {
	msg := &envelope.GRPCEndMessage{
		Status:  status,
		Message: message,
	}
	env := &envelope.Envelope{
		Direction: direction,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
	}
	return env, msg
}

func TestInterceptEngine_MatchStart_Service(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:             "r1",
		Enabled:        true,
		Direction:      DirectionSend,
		ServicePattern: regexp.MustCompile(`example\.Greeter`),
	}})

	env, msg := makeStartEnv(envelope.Send, "example.Greeter", "SayHello", nil)
	matched := e.MatchStart(env, msg)
	if len(matched) != 1 || matched[0] != "r1" {
		t.Errorf("matched = %v, want [r1]", matched)
	}

	env2, msg2 := makeStartEnv(envelope.Send, "other.Service", "SayHello", nil)
	if len(e.MatchStart(env2, msg2)) != 0 {
		t.Error("expected no match for non-matching service")
	}
}

func TestInterceptEngine_MatchStart_Method(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:            "r1",
		Enabled:       true,
		Direction:     DirectionBoth,
		MethodPattern: regexp.MustCompile(`^Say`),
	}})

	env, msg := makeStartEnv(envelope.Send, "example.Greeter", "SayHello", nil)
	if len(e.MatchStart(env, msg)) != 1 {
		t.Error("expected match on SayHello")
	}

	env2, msg2 := makeStartEnv(envelope.Send, "example.Greeter", "Greet", nil)
	if len(e.MatchStart(env2, msg2)) != 0 {
		t.Error("expected no match on Greet")
	}
}

func TestInterceptEngine_MatchStart_HeaderMatch(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionSend,
		HeaderMatch: map[string]*regexp.Regexp{
			"x-api-key": regexp.MustCompile(`^secret-`),
		},
	}})

	// Mixed-case wire metadata should still match (case-insensitive lookup).
	metadata := []envelope.KeyValue{{Name: "X-Api-Key", Value: "secret-42"}}
	env, msg := makeStartEnv(envelope.Send, "svc", "Method", metadata)
	if len(e.MatchStart(env, msg)) != 1 {
		t.Error("expected match on x-api-key")
	}

	metadata2 := []envelope.KeyValue{{Name: "x-api-key", Value: "public"}}
	env2, msg2 := makeStartEnv(envelope.Send, "svc", "Method", metadata2)
	if len(e.MatchStart(env2, msg2)) != 0 {
		t.Error("expected no match on public key")
	}
}

func TestInterceptEngine_MatchData_PayloadPattern(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:             "r1",
		Enabled:        true,
		Direction:      DirectionSend,
		PayloadPattern: regexp.MustCompile(`secret`),
	}})

	env, msg := makeDataEnv(envelope.Send, "svc", "Method", []byte("contains secret data"))
	if len(e.MatchData(env, msg)) != 1 {
		t.Error("expected match on payload pattern")
	}

	env2, msg2 := makeDataEnv(envelope.Send, "svc", "Method", []byte("clean"))
	if len(e.MatchData(env2, msg2)) != 0 {
		t.Error("expected no match on clean payload")
	}
}

func TestInterceptEngine_MatchData_HeaderMatchIgnored(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionSend,
		HeaderMatch: map[string]*regexp.Regexp{
			"x-api-key": regexp.MustCompile(`unreachable`),
		},
	}})

	// HeaderMatch is Start-only; on Data it must be a no-op (still
	// matches because Direction/Service/Method gates pass and
	// HeaderMatch is ignored).
	env, msg := makeDataEnv(envelope.Send, "svc", "Method", []byte("anything"))
	matched := e.MatchData(env, msg)
	if len(matched) != 1 {
		t.Errorf("HeaderMatch should be ignored on Data; matched=%v", matched)
	}
}

func TestInterceptEngine_MatchEnd_HeaderMatchIgnored(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionReceive,
		HeaderMatch: map[string]*regexp.Regexp{
			"x-api-key": regexp.MustCompile(`unreachable`),
		},
	}})

	env, msg := makeEndEnv(envelope.Receive, 0, "OK")
	matched := e.MatchEnd(env, msg)
	if len(matched) != 1 {
		t.Errorf("HeaderMatch should be ignored on End; matched=%v", matched)
	}
}

func TestInterceptEngine_DirectionFilter(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionReceive,
	}})

	envSend, msgSend := makeStartEnv(envelope.Send, "svc", "M", nil)
	if len(e.MatchStart(envSend, msgSend)) != 0 {
		t.Error("send-direction event must not match a receive-only rule")
	}

	envRecv, msgRecv := makeStartEnv(envelope.Receive, "svc", "M", nil)
	if len(e.MatchStart(envRecv, msgRecv)) != 1 {
		t.Error("receive-direction event must match a receive-only rule")
	}
}

func TestInterceptEngine_DirectionBoth_MatchesEither(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionBoth,
	}})

	envSend, msgSend := makeStartEnv(envelope.Send, "svc", "M", nil)
	if len(e.MatchStart(envSend, msgSend)) != 1 {
		t.Error("DirectionBoth must match Send")
	}
	envRecv, msgRecv := makeStartEnv(envelope.Receive, "svc", "M", nil)
	if len(e.MatchStart(envRecv, msgRecv)) != 1 {
		t.Error("DirectionBoth must match Receive")
	}
}

func TestInterceptEngine_DisabledRuleSkipped(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   false,
		Direction: DirectionBoth,
	}})

	env, msg := makeStartEnv(envelope.Send, "svc", "M", nil)
	if len(e.MatchStart(env, msg)) != 0 {
		t.Error("disabled rule must not match")
	}
}

func TestInterceptEngine_AddRemoveRule(t *testing.T) {
	e := NewInterceptEngine()
	e.AddRule(InterceptRule{ID: "r1", Enabled: true, Direction: DirectionBoth})
	e.AddRule(InterceptRule{ID: "r2", Enabled: true, Direction: DirectionBoth})

	env, msg := makeStartEnv(envelope.Send, "svc", "M", nil)
	if got := e.MatchStart(env, msg); len(got) != 2 {
		t.Errorf("expected 2 matches, got %v", got)
	}
	e.RemoveRule("r1")
	if got := e.MatchStart(env, msg); len(got) != 1 || got[0] != "r2" {
		t.Errorf("expected [r2] after remove, got %v", got)
	}
}

func TestCompileInterceptRule_Success(t *testing.T) {
	rule, err := CompileInterceptRule("r1", DirectionBoth,
		`^example\.`, `^Say`,
		map[string]string{"X-API-Key": `^token-`},
		`payload-needle`,
	)
	if err != nil {
		t.Fatal(err)
	}
	if rule.ServicePattern == nil || rule.MethodPattern == nil || rule.PayloadPattern == nil {
		t.Error("patterns should be compiled")
	}
	if _, ok := rule.HeaderMatch["x-api-key"]; !ok {
		t.Error("header key must be lowercased at compile time")
	}
}

func TestCompileInterceptRule_BadRegex(t *testing.T) {
	if _, err := CompileInterceptRule("r1", DirectionBoth, `(`, ``, nil, ``); err == nil {
		t.Error("expected service pattern error")
	}
	if _, err := CompileInterceptRule("r1", DirectionBoth, ``, `(`, nil, ``); err == nil {
		t.Error("expected method pattern error")
	}
	if _, err := CompileInterceptRule("r1", DirectionBoth, ``, ``, map[string]string{"k": `(`}, ``); err == nil {
		t.Error("expected header match error")
	}
	if _, err := CompileInterceptRule("r1", DirectionBoth, ``, ``, nil, `(`); err == nil {
		t.Error("expected payload pattern error")
	}
}

func TestExtractHostname_GRPC(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:8080", "::1"},
	}
	for _, tt := range tests {
		got := extractHostname(tt.in)
		if got != tt.want {
			t.Errorf("extractHostname(%q) = %q want %q", tt.in, got, tt.want)
		}
	}
}

func TestConvertDirection(t *testing.T) {
	if convertDirection(envelope.Send) != DirectionSend {
		t.Error("Send -> DirectionSend")
	}
	if convertDirection(envelope.Receive) != DirectionReceive {
		t.Error("Receive -> DirectionReceive")
	}
}
