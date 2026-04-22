package http

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

func testSafetyMsg(method, path, host, query string, headers []envelope.KeyValue, body []byte) *envelope.HTTPMessage {
	return &envelope.HTTPMessage{
		Method:    method,
		Scheme:    "https",
		Authority: host,
		Path:      path,
		RawQuery:  query,
		Headers:   headers,
		Body:      body,
	}
}

func TestSafetyEngine_DestructiveSQL_DropTable(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	msg := testSafetyMsg("POST", "/api", "example.com", "", nil,
		[]byte("DROP TABLE users"))
	v := e.CheckInput(context.Background(), msg)
	if v == nil {
		t.Fatal("expected violation for DROP TABLE")
	}
	if v.RuleID != "destructive-sql:drop" {
		t.Errorf("RuleID = %q, want destructive-sql:drop", v.RuleID)
	}
	if v.Target != "body" {
		t.Errorf("Target = %q, want body", v.Target)
	}
}

func TestSafetyEngine_DestructiveSQL_InQuery(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	// Raw query with actual whitespace (not URL-encoded).
	// Note: URL target matches before query because the reconstructed URL
	// also contains the query string. Either target is acceptable.
	msg := testSafetyMsg("GET", "/search", "example.com",
		"q=DROP TABLE users", nil, nil)
	v := e.CheckInput(context.Background(), msg)
	if v == nil {
		t.Fatal("expected violation for DROP TABLE in query")
	}
	if v.Target != "url" && v.Target != "query" {
		t.Errorf("Target = %q, want url or query", v.Target)
	}
}

func TestSafetyEngine_DestructiveSQL_InURL(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	msg := testSafetyMsg("GET", "/api/DROP TABLE foo", "example.com", "", nil, nil)
	v := e.CheckInput(context.Background(), msg)
	if v == nil {
		t.Fatal("expected violation for DROP TABLE in URL")
	}
	if v.Target != "url" {
		t.Errorf("Target = %q, want url", v.Target)
	}
}

func TestSafetyEngine_DestructiveSQL_Truncate(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	msg := testSafetyMsg("POST", "/", "example.com", "", nil,
		[]byte("TRUNCATE TABLE sessions"))
	v := e.CheckInput(context.Background(), msg)
	if v == nil {
		t.Fatal("expected violation for TRUNCATE TABLE")
	}
}

func TestSafetyEngine_DestructiveSQL_Safe(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	msg := testSafetyMsg("POST", "/api", "example.com", "", nil,
		[]byte("SELECT * FROM users WHERE id = 1"))
	v := e.CheckInput(context.Background(), msg)
	if v != nil {
		t.Errorf("unexpected violation for safe query: %+v", v)
	}
}

func TestSafetyEngine_DestructiveOSCommand(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveOSCommand); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		body string
		want bool
	}{
		{"rm -rf", "rm -rf /", true},
		{"shutdown", "shutdown -h now", true},
		{"mkfs", "mkfs.ext4 /dev/sda1", true},
		{"dd", "dd if=/dev/zero of=/dev/sda", true},
		{"safe ls", "ls -la /tmp", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := testSafetyMsg("POST", "/", "example.com", "", nil, []byte(tt.body))
			v := e.CheckInput(context.Background(), msg)
			if tt.want && v == nil {
				t.Error("expected violation")
			}
			if !tt.want && v != nil {
				t.Errorf("unexpected violation: %+v", v)
			}
		})
	}
}

func TestSafetyEngine_NoRules(t *testing.T) {
	e := NewSafetyEngine()
	msg := testSafetyMsg("POST", "/", "example.com", "", nil,
		[]byte("DROP TABLE users"))
	v := e.CheckInput(context.Background(), msg)
	if v != nil {
		t.Error("expected no violation with no rules loaded")
	}
}

func TestSafetyEngine_CheckInputAll(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	msg := testSafetyMsg("POST", "/", "example.com", "", nil,
		[]byte("DROP TABLE users; TRUNCATE TABLE sessions"))
	violations := e.CheckInputAll(context.Background(), msg)
	if len(violations) < 2 {
		t.Errorf("expected at least 2 violations, got %d", len(violations))
	}
}

func TestSafetyEngine_CustomRule(t *testing.T) {
	e := NewSafetyEngine()

	re, _ := common.CompilePattern(`(?i)eval\(`)
	e.AddRule(common.CompiledRule{
		ID:       "custom:eval",
		Name:     "eval() call",
		Pattern:  re,
		Targets:  []common.Target{common.TargetBody},
		Category: "custom",
	})

	msg := testSafetyMsg("POST", "/", "example.com", "", nil,
		[]byte(`eval(userInput)`))
	v := e.CheckInput(context.Background(), msg)
	if v == nil {
		t.Fatal("expected violation for eval()")
	}
	if v.RuleID != "custom:eval" {
		t.Errorf("RuleID = %q", v.RuleID)
	}
}

func TestSafetyEngine_RuleCount(t *testing.T) {
	e := NewSafetyEngine()
	if e.RuleCount() != 0 {
		t.Errorf("expected 0, got %d", e.RuleCount())
	}
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}
	if e.RuleCount() == 0 {
		t.Error("expected non-zero after loading preset")
	}
}

func TestSafetyEngine_NilBody(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	// nil body with dangerous query should still match on query target.
	msg := testSafetyMsg("GET", "/", "example.com",
		"q=DROP TABLE users", nil, nil)
	v := e.CheckInput(context.Background(), msg)
	if v == nil {
		t.Fatal("expected violation in query even with nil body")
	}
}

func TestReconstructURL(t *testing.T) {
	tests := []struct {
		msg  *envelope.HTTPMessage
		want string
	}{
		{
			&envelope.HTTPMessage{Scheme: "https", Authority: "example.com", Path: "/api", RawQuery: "k=v"},
			"https://example.com/api?k=v",
		},
		{
			&envelope.HTTPMessage{Scheme: "http", Authority: "example.com", Path: "/"},
			"http://example.com/",
		},
		{
			&envelope.HTTPMessage{Authority: "example.com", Path: "/no-scheme"},
			"example.com/no-scheme",
		},
	}
	for _, tt := range tests {
		got := reconstructURL(tt.msg)
		if got != tt.want {
			t.Errorf("reconstructURL = %q, want %q", got, tt.want)
		}
	}
}

// TestSafetyEngine_CheckInput_BodyBufferFileBackedSQLi verifies that a
// disk-backed BodyBuffer (12 MiB) carrying a SQL injection pattern is
// materialized via Bytes(ctx) and matched by the safety engine. Before
// USK-633 the body target was silently skipped whenever msg.Body was nil,
// which let >10 MiB bodies bypass Safety entirely.
func TestSafetyEngine_CheckInput_BodyBufferFileBackedSQLi(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	// Build a 12 MiB body with a DROP TABLE needle in the middle so the
	// file-mode reader has to traverse multiple readChunkSize chunks.
	const payloadSize = 12 << 20
	needle := []byte("DROP TABLE users")
	filler := bytes.Repeat([]byte("A"), payloadSize/2)
	body := append(append([]byte(nil), filler...), needle...)
	body = append(body, filler...)

	bb, err := bodybuf.NewFile(t.TempDir(), "test-body", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bb.Release() })
	if _, err := bb.Write(body); err != nil {
		t.Fatal(err)
	}

	msg := &envelope.HTTPMessage{
		Method:     "POST",
		Scheme:     "https",
		Authority:  "example.com",
		Path:       "/api",
		BodyBuffer: bb,
	}

	v := e.CheckInput(context.Background(), msg)
	if v == nil {
		t.Fatal("expected violation from disk-backed body materialization")
	}
	if v.Target != "body" {
		t.Errorf("Target = %q, want body", v.Target)
	}
	if !strings.Contains(v.Match, "DROP TABLE") {
		t.Errorf("Match = %q, want substring DROP TABLE", v.Match)
	}
}

// TestSafetyEngine_CheckInput_CtxCancel_SkipsBodyTarget verifies that a
// cancelled ctx during disk-backed body materialization is swallowed at
// the body target: no violation, no panic, and other targets still evaluate.
func TestSafetyEngine_CheckInput_CtxCancel_SkipsBodyTarget(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	// Disk-backed body containing a pattern that would match if read.
	bb, err := bodybuf.NewFile(t.TempDir(), "test-body", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bb.Release() })
	if _, err := bb.Write([]byte("DROP TABLE users")); err != nil {
		t.Fatal(err)
	}

	msg := &envelope.HTTPMessage{
		Method:     "POST",
		Scheme:     "https",
		Authority:  "example.com",
		Path:       "/api",
		BodyBuffer: bb,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled: Bytes(ctx) must fail fast.

	// Must not panic and must return nil (body skipped, URL/query clean).
	v := e.CheckInput(ctx, msg)
	if v != nil {
		t.Errorf("expected nil violation with cancelled ctx, got %+v", v)
	}
}

func TestAllHeadersString_NoNormalization(t *testing.T) {
	headers := []envelope.KeyValue{
		{Name: "Content-Type", Value: "text/html"},
		{Name: "x-custom", Value: "value"},
		{Name: "X-UPPER", Value: "CAPS"},
	}
	result := allHeadersString(headers)

	// Wire casing must be preserved — no canonicalization.
	if result != "Content-Type: text/html\nx-custom: value\nX-UPPER: CAPS\n" {
		t.Errorf("allHeadersString = %q", result)
	}
}
