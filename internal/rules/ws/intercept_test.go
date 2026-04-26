package ws

import (
	"regexp"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func testWSEnv(direction envelope.Direction, host, upgradePath string, msg *envelope.WSMessage) *envelope.Envelope {
	return &envelope.Envelope{
		Direction: direction,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   msg,
		Context: envelope.EnvelopeContext{
			TargetHost:  host + ":443",
			UpgradePath: upgradePath,
		},
	}
}

func textFrame(payload string) *envelope.WSMessage {
	return &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Fin:     true,
		Payload: []byte(payload),
	}
}

func binaryFrame(payload []byte) *envelope.WSMessage {
	return &envelope.WSMessage{
		Opcode:  envelope.WSBinary,
		Fin:     true,
		Payload: payload,
	}
}

func contFrame(payload []byte) *envelope.WSMessage {
	return &envelope.WSMessage{
		Opcode:  envelope.WSContinuation,
		Fin:     false,
		Payload: payload,
	}
}

func TestInterceptEngine_Match_Host(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionBoth,
		HostPattern: regexp.MustCompile(`example\.com`),
	}})

	env := testWSEnv(envelope.Send, "example.com", "/ws", textFrame("hello"))
	if got := e.Match(env, env.Message.(*envelope.WSMessage)); len(got) != 1 || got[0] != "r1" {
		t.Errorf("matched = %v, want [r1]", got)
	}

	env2 := testWSEnv(envelope.Send, "other.com", "/ws", textFrame("hello"))
	if got := e.Match(env2, env2.Message.(*envelope.WSMessage)); len(got) != 0 {
		t.Errorf("matched = %v, want empty", got)
	}
}

func TestInterceptEngine_Match_Path(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:          "r1",
		Enabled:     true,
		Direction:   DirectionBoth,
		PathPattern: regexp.MustCompile(`^/ws/v1/`),
	}})

	env := testWSEnv(envelope.Send, "example.com", "/ws/v1/chat", textFrame(""))
	if got := e.Match(env, env.Message.(*envelope.WSMessage)); len(got) != 1 {
		t.Errorf("expected match on /ws/v1/chat, got %v", got)
	}

	env2 := testWSEnv(envelope.Send, "example.com", "/ws/v2/admin", textFrame(""))
	if got := e.Match(env2, env2.Message.(*envelope.WSMessage)); len(got) != 0 {
		t.Errorf("expected no match on /ws/v2/admin, got %v", got)
	}
}

func TestInterceptEngine_Match_DirectionFilter(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionReceive,
	}})

	sendEnv := testWSEnv(envelope.Send, "example.com", "/ws", textFrame(""))
	if got := e.Match(sendEnv, sendEnv.Message.(*envelope.WSMessage)); len(got) != 0 {
		t.Errorf("Receive-only rule matched a Send frame: %v", got)
	}

	recvEnv := testWSEnv(envelope.Receive, "example.com", "/ws", textFrame(""))
	if got := e.Match(recvEnv, recvEnv.Message.(*envelope.WSMessage)); len(got) != 1 {
		t.Errorf("Receive-only rule did not match a Receive frame: %v", got)
	}
}

func TestInterceptEngine_Match_DirectionBoth(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   true,
		Direction: DirectionBoth,
	}})

	for _, dir := range []envelope.Direction{envelope.Send, envelope.Receive} {
		env := testWSEnv(dir, "example.com", "/ws", textFrame(""))
		if got := e.Match(env, env.Message.(*envelope.WSMessage)); len(got) != 1 {
			t.Errorf("DirectionBoth did not match dir=%v: %v", dir, got)
		}
	}
}

func TestInterceptEngine_Match_OpcodeFilter_Empty_MatchesAll(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:           "r1",
		Enabled:      true,
		Direction:    DirectionBoth,
		OpcodeFilter: nil, // empty
	}})

	for _, msg := range []*envelope.WSMessage{
		{Opcode: envelope.WSText, Fin: true},
		{Opcode: envelope.WSBinary, Fin: true},
		{Opcode: envelope.WSPing},
		{Opcode: envelope.WSClose},
		{Opcode: envelope.WSContinuation},
	} {
		env := testWSEnv(envelope.Send, "example.com", "/ws", msg)
		if got := e.Match(env, msg); len(got) != 1 {
			t.Errorf("empty OpcodeFilter did not match opcode 0x%X: %v", uint8(msg.Opcode), got)
		}
	}
}

func TestInterceptEngine_Match_OpcodeFilter_LiteralContinuation(t *testing.T) {
	// OpcodeFilter:[WSText] must NOT match a WSContinuation frame, even
	// though the continuation may have started life as a Text fragment.
	// The engine does not track per-stream first-fragment type — operators
	// must list WSContinuation explicitly.
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:           "r1",
		Enabled:      true,
		Direction:    DirectionBoth,
		OpcodeFilter: []envelope.WSOpcode{envelope.WSText},
	}})

	cont := contFrame([]byte("part2"))
	env := testWSEnv(envelope.Send, "example.com", "/ws", cont)
	if got := e.Match(env, cont); len(got) != 0 {
		t.Errorf("WSText filter matched a Continuation frame: %v", got)
	}

	text := textFrame("hello")
	env2 := testWSEnv(envelope.Send, "example.com", "/ws", text)
	if got := e.Match(env2, text); len(got) != 1 {
		t.Errorf("WSText filter did not match a Text frame: %v", got)
	}
}

// TestInterceptEngine_Match_OpcodeFilterPreBail asserts the engine
// rejects on opcode mismatch BEFORE evaluating PayloadPattern. We cannot
// directly hand the engine a counting matcher because PayloadPattern is a
// concrete *regexp.Regexp, so the test uses a payload that the regex
// would unambiguously match if evaluated and asserts the rule does NOT
// fire on a Binary frame whose opcode falls outside the filter.
func TestInterceptEngine_Match_OpcodeFilterPreBail(t *testing.T) {
	// A PayloadPattern that WOULD match a binary frame's payload bytes if
	// it were evaluated. The OpcodeFilter:[WSText] must short-circuit
	// BEFORE we reach PayloadPattern.
	pat := regexp.MustCompile(`AAAA`)

	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:             "r1",
		Enabled:        true,
		Direction:      DirectionBoth,
		OpcodeFilter:   []envelope.WSOpcode{envelope.WSText},
		PayloadPattern: pat,
	}})

	bin := binaryFrame([]byte("AAAA")) // payload that PayloadPattern would match
	env := testWSEnv(envelope.Send, "example.com", "/ws", bin)
	got := e.Match(env, bin)
	if len(got) != 0 {
		t.Fatalf("Text-only rule matched Binary frame: %v", got)
	}
	// Sanity: same rule with a Text frame whose payload also satisfies
	// the pattern must match — proving the regex is fine and the Binary
	// rejection is genuinely opcode-based.
	tf := textFrame("AAAA")
	env2 := testWSEnv(envelope.Send, "example.com", "/ws", tf)
	if got2 := e.Match(env2, tf); len(got2) != 1 {
		t.Fatalf("Text-only rule did not match Text frame with matching payload: %v", got2)
	}
}

func TestInterceptEngine_Match_PayloadPattern(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:             "r1",
		Enabled:        true,
		Direction:      DirectionBoth,
		PayloadPattern: regexp.MustCompile(`secret\d+`),
	}})

	env := testWSEnv(envelope.Send, "example.com", "/ws", textFrame(`{"k":"secret123"}`))
	if got := e.Match(env, env.Message.(*envelope.WSMessage)); len(got) != 1 {
		t.Errorf("expected match on payload, got %v", got)
	}

	env2 := testWSEnv(envelope.Send, "example.com", "/ws", textFrame(`{"k":"safe"}`))
	if got := e.Match(env2, env2.Message.(*envelope.WSMessage)); len(got) != 0 {
		t.Errorf("expected no match on safe payload, got %v", got)
	}
}

func TestInterceptEngine_Match_ANDCombination(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:             "r1",
		Enabled:        true,
		Direction:      DirectionBoth,
		HostPattern:    regexp.MustCompile(`example\.com`),
		PathPattern:    regexp.MustCompile(`^/ws/v1`),
		OpcodeFilter:   []envelope.WSOpcode{envelope.WSText},
		PayloadPattern: regexp.MustCompile(`hello`),
	}})

	// All conditions match.
	env := testWSEnv(envelope.Send, "example.com", "/ws/v1/chat", textFrame("hello world"))
	if got := e.Match(env, env.Message.(*envelope.WSMessage)); len(got) != 1 {
		t.Error("expected match when all conditions met")
	}

	// Host fails.
	env2 := testWSEnv(envelope.Send, "other.com", "/ws/v1/chat", textFrame("hello"))
	if got := e.Match(env2, env2.Message.(*envelope.WSMessage)); len(got) != 0 {
		t.Error("expected no match when host differs")
	}

	// Path fails.
	env3 := testWSEnv(envelope.Send, "example.com", "/api/rest", textFrame("hello"))
	if got := e.Match(env3, env3.Message.(*envelope.WSMessage)); len(got) != 0 {
		t.Error("expected no match when path differs")
	}

	// Opcode fails.
	env4 := testWSEnv(envelope.Send, "example.com", "/ws/v1/chat", binaryFrame([]byte("hello")))
	if got := e.Match(env4, env4.Message.(*envelope.WSMessage)); len(got) != 0 {
		t.Error("expected no match when opcode differs")
	}

	// Payload fails.
	env5 := testWSEnv(envelope.Send, "example.com", "/ws/v1/chat", textFrame("goodbye"))
	if got := e.Match(env5, env5.Message.(*envelope.WSMessage)); len(got) != 0 {
		t.Error("expected no match when payload differs")
	}
}

func TestInterceptEngine_Match_DisabledRule(t *testing.T) {
	e := NewInterceptEngine()
	e.SetRules([]InterceptRule{{
		ID:        "r1",
		Enabled:   false,
		Direction: DirectionBoth,
	}})
	env := testWSEnv(envelope.Send, "example.com", "/ws", textFrame(""))
	if got := e.Match(env, env.Message.(*envelope.WSMessage)); len(got) != 0 {
		t.Errorf("disabled rule matched: %v", got)
	}
}

func TestInterceptEngine_AddRemoveRule(t *testing.T) {
	e := NewInterceptEngine()
	e.AddRule(InterceptRule{ID: "r1", Enabled: true, Direction: DirectionBoth})
	e.AddRule(InterceptRule{ID: "r2", Enabled: true, Direction: DirectionBoth})

	env := testWSEnv(envelope.Send, "example.com", "/ws", textFrame(""))
	if got := e.Match(env, env.Message.(*envelope.WSMessage)); len(got) != 2 {
		t.Errorf("expected 2 matches, got %d", len(got))
	}

	e.RemoveRule("r1")
	if got := e.Match(env, env.Message.(*envelope.WSMessage)); len(got) != 1 {
		t.Errorf("expected 1 match after removal, got %d", len(got))
	}
}

func TestCompileInterceptRule(t *testing.T) {
	rule, err := CompileInterceptRule("r1", DirectionBoth,
		`example\.com`, `^/ws/`,
		[]envelope.WSOpcode{envelope.WSText, envelope.WSBinary},
		`secret`)
	if err != nil {
		t.Fatal(err)
	}
	if rule.HostPattern == nil || rule.PathPattern == nil || rule.PayloadPattern == nil {
		t.Error("patterns should be compiled")
	}
	if len(rule.OpcodeFilter) != 2 {
		t.Errorf("OpcodeFilter len = %d, want 2", len(rule.OpcodeFilter))
	}
	if !rule.Enabled {
		t.Error("compiled rule should be enabled by default")
	}
}

func TestExtractHostname(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"example.com:443", "example.com"},
		{"example.com", "example.com"},
		{"[::1]:8080", "::1"},
	}
	for _, tt := range tests {
		got := extractHostname(tt.input)
		if got != tt.want {
			t.Errorf("extractHostname(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestConvertDirection(t *testing.T) {
	if got := convertDirection(envelope.Send); got != DirectionSend {
		t.Errorf("Send -> %q, want %q", got, DirectionSend)
	}
	if got := convertDirection(envelope.Receive); got != DirectionReceive {
		t.Errorf("Receive -> %q, want %q", got, DirectionReceive)
	}
}

func TestContainsCRLF(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"normal", false},
		{"with\rCR", true},
		{"with\nLF", true},
		{"both\r\n", true},
	}
	for _, c := range cases {
		if got := containsCRLF(c.s); got != c.want {
			t.Errorf("containsCRLF(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}
