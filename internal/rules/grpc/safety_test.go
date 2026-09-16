package grpc

import (
	"bytes"
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

func TestSafetyEngine_PresetReuse_DestructiveSQL_OnPayload(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	// destructive-sql preset uses common.TargetBody. The gRPC engine
	// must remap that to TargetPayload data extraction.
	env, msg := makeDataEnv(envelope.Send, "svc", "M", []byte("DROP TABLE users"))
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation from preset on payload")
	}
	if v.Target != "payload" {
		t.Errorf("Target = %q, want payload", v.Target)
	}
	if v.RuleID != "destructive-sql:drop" {
		t.Errorf("RuleID = %q, want destructive-sql:drop", v.RuleID)
	}
}

func TestSafetyEngine_TargetPayload_BlocksMatch(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`(?i)password=`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:password-leak",
		Name:    "Password leak",
		Pattern: re,
		Targets: []common.Target{TargetPayload},
	})

	env, msg := makeDataEnv(envelope.Send, "svc", "M", []byte("payload password=hunter2"))
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation")
	}
	if v.Target != "payload" {
		t.Errorf("Target = %q, want payload", v.Target)
	}
}

func TestSafetyEngine_TargetMetadata_OnStart(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`Bearer\s+[a-z0-9]+`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:auth-leak",
		Name:    "Auth header leak",
		Pattern: re,
		Targets: []common.Target{TargetMetadata},
	})

	metadata := []envelope.KeyValue{{Name: "authorization", Value: "Bearer abcdef123"}}
	env, msg := makeStartEnv(envelope.Send, "svc", "M", metadata)
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation on metadata")
	}
	if v.Target != "metadata" {
		t.Errorf("Target = %q, want metadata", v.Target)
	}
}

func TestSafetyEngine_TargetMetadata_OnEndTrailers(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`internal-trace=`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:trace-leak",
		Pattern: re,
		Targets: []common.Target{TargetMetadata},
	})

	msg := &envelope.GRPCEndMessage{
		Status:   0,
		Trailers: []envelope.KeyValue{{Name: "x-debug", Value: "internal-trace=abc"}},
	}
	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
	}
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation on End trailers")
	}
	if v.Target != "metadata" {
		t.Errorf("Target = %q, want metadata (trailers)", v.Target)
	}
}

func TestSafetyEngine_TargetService(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`forbidden\.`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:forbidden-svc",
		Pattern: re,
		Targets: []common.Target{TargetService},
	})

	env, msg := makeStartEnv(envelope.Send, "forbidden.AdminService", "Reset", nil)
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation on service name")
	}
	if v.Target != "service" {
		t.Errorf("Target = %q, want service", v.Target)
	}
}

func TestSafetyEngine_TargetMethod(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`^Delete`)
	e.AddRule(common.CompiledRule{
		ID:      "custom:dangerous-verb",
		Pattern: re,
		Targets: []common.Target{TargetMethod},
	})

	env, msg := makeStartEnv(envelope.Send, "svc", "DeleteAllUsers", nil)
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation on method name")
	}
	if v.Target != "method" {
		t.Errorf("Target = %q, want method", v.Target)
	}
}

func TestSafetyEngine_NoMatch_ReturnsNil(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}
	env, msg := makeDataEnv(envelope.Send, "svc", "M", []byte("benign payload"))
	if v := e.CheckInput(context.Background(), env, msg); v != nil {
		t.Errorf("unexpected violation: %+v", v)
	}
}

func TestSafetyEngine_CheckInputAll(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}
	env, msg := makeDataEnv(envelope.Send, "svc", "M",
		[]byte("DROP TABLE users; TRUNCATE TABLE sessions"))
	violations := e.CheckInputAll(context.Background(), env, msg)
	if len(violations) < 2 {
		t.Errorf("expected at least 2 violations, got %d", len(violations))
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
		t.Error("expected non-zero after preset load")
	}
}

func TestSafetyEngine_SetRules(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`x`)
	e.SetRules([]common.CompiledRule{
		{ID: "a", Pattern: re, Targets: []common.Target{TargetPayload}},
		{ID: "b", Pattern: re, Targets: []common.Target{TargetPayload}},
	})
	if e.RuleCount() != 2 {
		t.Errorf("RuleCount = %d, want 2", e.RuleCount())
	}
	e.SetRules(nil)
	if e.RuleCount() != 0 {
		t.Errorf("RuleCount after nil = %d, want 0", e.RuleCount())
	}
}

func TestSafetyEngine_NilEnvOrMsg(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`anything`)
	e.AddRule(common.CompiledRule{
		ID: "r1", Pattern: re, Targets: []common.Target{TargetPayload},
	})

	if v := e.CheckInput(context.Background(), nil, nil); v != nil {
		t.Error("nil env/msg must not panic and must return nil")
	}
}

func TestSafetyEngine_CheckMetadataTarget(t *testing.T) {
	e := NewSafetyEngine()
	re, _ := common.CompilePattern(`^Bearer\s`)
	rule := &common.CompiledRule{
		ID:      "custom:bearer",
		Name:    "Bearer token",
		Pattern: re,
	}

	metadata := []envelope.KeyValue{{Name: "Authorization", Value: "Bearer xyz"}}
	v := e.CheckMetadataTarget(metadata, "authorization", rule)
	if v == nil {
		t.Fatal("expected violation on Authorization metadata")
	}
	if v.Target != "metadata:authorization" {
		t.Errorf("Target = %q", v.Target)
	}

	// Missing metadata returns nil.
	if v := e.CheckMetadataTarget(metadata, "x-missing", rule); v != nil {
		t.Errorf("expected nil for missing metadata, got %+v", v)
	}
}

// TestSafetyEngine_CheckInput_DoesNotMutateMessage_NoMatch confirms the
// wire-fidelity invariant (RFC-001 Principle 1) for the no-match path on
// gRPC Data envelopes: the live-path engine must leave Payload and the
// underlying byte slice untouched.
func TestSafetyEngine_CheckInput_DoesNotMutateDataMessage_NoMatch(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	payloadOriginal := []byte("benign rpc payload")
	env, msg := makeDataEnv(envelope.Send, "svc", "M", payloadOriginal)
	rawOriginal := []byte("frame-bytes-from-the-wire")
	env.Raw = rawOriginal

	payloadSnap := append([]byte(nil), payloadOriginal...)
	rawSnap := append([]byte(nil), rawOriginal...)
	service, method := msg.Service, msg.Method

	if v := e.CheckInput(context.Background(), env, msg); v != nil {
		t.Fatalf("unexpected violation: %+v", v)
	}

	if !bytes.Equal(msg.Payload, payloadSnap) {
		t.Errorf("Payload mutated: got %q, want %q", string(msg.Payload), string(payloadSnap))
	}
	if !bytes.Equal(payloadOriginal, payloadSnap) {
		t.Errorf("underlying payload slice mutated: got %q, want %q", string(payloadOriginal), string(payloadSnap))
	}
	if !bytes.Equal(env.Raw, rawSnap) {
		t.Errorf("env.Raw mutated: got %q, want %q", string(env.Raw), string(rawSnap))
	}
	if !bytes.Equal(rawOriginal, rawSnap) {
		t.Errorf("underlying env.Raw slice mutated: got %q, want %q", string(rawOriginal), string(rawSnap))
	}
	if msg.Service != service || msg.Method != method {
		t.Errorf("scalar field mutated: service=%q method=%q", msg.Service, msg.Method)
	}
}

// TestSafetyEngine_CheckInput_DoesNotMutateDataMessage_OnMatch confirms
// the wire-fidelity invariant (RFC-001 Principle 1) on the matched-rule
// path: even on Drop, the engine must leave the payload byte-for-byte
// identical so the recorder captures the original wire bytes.
func TestSafetyEngine_CheckInput_DoesNotMutateDataMessage_OnMatch(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	payloadOriginal := []byte("DROP TABLE users\n--rest-of-payload")
	env, msg := makeDataEnv(envelope.Send, "svc", "M", payloadOriginal)
	rawOriginal := []byte("wire-frame-prefix DROP TABLE users wire-frame-suffix")
	env.Raw = rawOriginal

	payloadSnap := append([]byte(nil), payloadOriginal...)
	rawSnap := append([]byte(nil), rawOriginal...)

	if v := e.CheckInput(context.Background(), env, msg); v == nil {
		t.Fatal("expected violation; rule precondition for the test failed")
	}

	if !bytes.Equal(msg.Payload, payloadSnap) {
		t.Errorf("Payload mutated after match: got %q, want %q", string(msg.Payload), string(payloadSnap))
	}
	if !bytes.Equal(payloadOriginal, payloadSnap) {
		t.Errorf("underlying payload slice mutated after match: got %q, want %q", string(payloadOriginal), string(payloadSnap))
	}
	if !bytes.Equal(env.Raw, rawSnap) {
		t.Errorf("env.Raw mutated after match: got %q, want %q", string(env.Raw), string(rawSnap))
	}
}

// startFieldSnapshot captures every GRPCStartMessage field the safety
// engine reads, plus the wire bytes, so a non-mutation assertion covers
// the whole read surface rather than just Metadata. USK-1073 widened that
// surface to Scheme / Authority / Path / RawQuery, and the engine's
// no-mutation contract (safety.go, "MUST NOT mutate") has to be enforced
// over all of it.
type startFieldSnapshot struct {
	metadata  []envelope.KeyValue
	scheme    string
	authority string
	path      string
	rawQuery  string
	service   string
	method    string
	raw       []byte
}

func snapshotStart(t *testing.T, env *envelope.Envelope, msg *envelope.GRPCStartMessage) startFieldSnapshot {
	t.Helper()
	return startFieldSnapshot{
		metadata:  append([]envelope.KeyValue(nil), msg.Metadata...),
		scheme:    msg.Scheme,
		authority: msg.Authority,
		path:      msg.Path,
		rawQuery:  msg.RawQuery,
		service:   msg.Service,
		method:    msg.Method,
		raw:       append([]byte(nil), env.Raw...),
	}
}

func (s startFieldSnapshot) assertUnchanged(t *testing.T, env *envelope.Envelope, msg *envelope.GRPCStartMessage) {
	t.Helper()
	if len(msg.Metadata) != len(s.metadata) {
		t.Errorf("Metadata length mutated: got %d, want %d", len(msg.Metadata), len(s.metadata))
	} else {
		for i := range msg.Metadata {
			if msg.Metadata[i] != s.metadata[i] {
				t.Errorf("Metadata[%d] mutated: got %+v, want %+v", i, msg.Metadata[i], s.metadata[i])
			}
		}
	}
	if msg.Scheme != s.scheme {
		t.Errorf("Scheme mutated: got %q, want %q", msg.Scheme, s.scheme)
	}
	if msg.Authority != s.authority {
		t.Errorf("Authority mutated: got %q, want %q", msg.Authority, s.authority)
	}
	if msg.Path != s.path {
		t.Errorf("Path mutated: got %q, want %q", msg.Path, s.path)
	}
	if msg.RawQuery != s.rawQuery {
		t.Errorf("RawQuery mutated: got %q, want %q", msg.RawQuery, s.rawQuery)
	}
	if msg.Service != s.service {
		t.Errorf("Service mutated: got %q, want %q", msg.Service, s.service)
	}
	if msg.Method != s.method {
		t.Errorf("Method mutated: got %q, want %q", msg.Method, s.method)
	}
	if !bytes.Equal(env.Raw, s.raw) {
		t.Errorf("env.Raw mutated: got %q, want %q", string(env.Raw), string(s.raw))
	}
}

// TestSafetyEngine_CheckInput_DoesNotMutateStartMessage_NoMatch confirms
// the wire-fidelity invariant (RFC-001 Principle 1) for gRPC Start
// envelopes on the no-match path: metadata, the request-side
// pseudo-header fields, and Envelope.Raw must all remain untouched.
func TestSafetyEngine_CheckInput_DoesNotMutateStartMessage_NoMatch(t *testing.T) {
	e := NewSafetyEngine()
	pat, err := common.CompilePattern(`Bearer\s+[a-z0-9]+`)
	if err != nil {
		t.Fatal(err)
	}
	e.AddRule(common.CompiledRule{
		ID:      "custom:auth-leak",
		Pattern: pat,
		Targets: []common.Target{TargetMetadata, common.TargetURL, common.TargetQuery},
	})
	// The presets are what actually exercise the url / query arms in
	// production, so load them here too — a mutation on those arms would
	// otherwise go unobserved.
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	metadata := []envelope.KeyValue{
		{Name: "Authorization", Value: "Basic abcdef"},
		{Name: "x-trace-id", Value: "xyz-1"},
	}
	env, msg := makeStartEnvWithURL(t, "https", "API.Example.com:443", "/pkg.Svc/GetUser", "id=42", "pkg.Svc", "GetUser")
	msg.Metadata = metadata
	rawOriginal := []byte("HEADERS-frame-bytes-from-the-wire")
	env.Raw = rawOriginal
	rawSnap := append([]byte(nil), rawOriginal...)
	snap := snapshotStart(t, env, msg)

	if v := e.CheckInput(context.Background(), env, msg); v != nil {
		t.Fatalf("unexpected violation: %+v", v)
	}

	snap.assertUnchanged(t, env, msg)
	if !bytes.Equal(rawOriginal, rawSnap) {
		t.Errorf("underlying env.Raw slice mutated: got %q, want %q", string(rawOriginal), string(rawSnap))
	}
}

// TestSafetyEngine_CheckInput_DoesNotMutateStartMessage_OnMatch is the
// matched-rule mirror of the test above. The Data path has had both
// variants for a while; the Start path had neither, because until
// USK-1073 it had no target a shipped preset could fire on. Even when the
// verdict is Drop, the engine must leave the observed :path and query
// byte-for-byte intact so RecordStep captures what the wire carried.
func TestSafetyEngine_CheckInput_DoesNotMutateStartMessage_OnMatch(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	env, msg := makeStartEnvWithURL(t, "https", "api.example.com", "/;DROP TABLE users--", "q=DROP TABLE users", "", "")
	rawOriginal := []byte("HEADERS :path /;DROP TABLE users--?q=DROP TABLE users")
	env.Raw = rawOriginal
	rawSnap := append([]byte(nil), rawOriginal...)
	snap := snapshotStart(t, env, msg)

	if v := e.CheckInput(context.Background(), env, msg); v == nil {
		t.Fatal("expected violation; rule precondition for the test failed")
	}

	snap.assertUnchanged(t, env, msg)
	if !bytes.Equal(rawOriginal, rawSnap) {
		t.Errorf("underlying env.Raw slice mutated after match: got %q, want %q", string(rawOriginal), string(rawSnap))
	}
}

func TestAllMetadataString_NoNormalization(t *testing.T) {
	metadata := []envelope.KeyValue{
		{Name: "Authorization", Value: "Bearer x"},
		{Name: "x-trace-id", Value: "abc"},
		{Name: "X-UPPER", Value: "CAPS"},
	}
	got := allMetadataString(metadata)
	want := "Authorization: Bearer x\nx-trace-id: abc\nX-UPPER: CAPS\n"
	if got != want {
		t.Errorf("allMetadataString = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------
// USK-1073: common.TargetURL / common.TargetQuery on a gRPC Start.
//
// Before USK-1053 a malformed :path was normalized to "/Service/Method"
// on Send and the query was dropped outright, so there was nothing on a
// Start worth scanning. USK-1053 made both wire-faithful; these tests
// pin the Input SafetyFilter arms that scan them.
// ---------------------------------------------------------------------

// makeStartEnvWithURL builds a Send-direction gRPC Start envelope with the
// request-side pseudo-header fields populated the way layer/grpc's
// buildStartMessage populates them (Send only). It is a sibling of
// makeStartEnv rather than a change to it: makeStartEnv has callers in
// four test files that do not care about the URL axis.
func makeStartEnvWithURL(t *testing.T, scheme, authority, path, rawQuery, service, method string) (*envelope.Envelope, *envelope.GRPCStartMessage) {
	t.Helper()
	env, msg := makeStartEnv(envelope.Send, service, method, nil)
	msg.Scheme = scheme
	msg.Authority = authority
	msg.Path = path
	msg.RawQuery = rawQuery
	return env, msg
}

// TestSafetyEngine_PresetReuse_DestructiveSQL_OnStartPath covers the
// USK-1053 variant where the whole :path is malformed: parseGRPCPath
// yields Service=="" Method=="", pathForStart therefore re-emits the
// observed path verbatim, and the preset must see it.
func TestSafetyEngine_PresetReuse_DestructiveSQL_OnStartPath(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	env, msg := makeStartEnvWithURL(t, "https", "api.example.com", "/;DROP TABLE users--", "", "", "")
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation from preset on a destructive :path")
	}
	if v.Target != "url" {
		t.Errorf("Target = %q, want url", v.Target)
	}
	if v.RuleID != "destructive-sql:drop" {
		t.Errorf("RuleID = %q, want destructive-sql:drop", v.RuleID)
	}
	if v.Match != "DROP TABLE " {
		t.Errorf("Match = %q, want %q", v.Match, "DROP TABLE ")
	}
}

// TestSafetyEngine_PresetReuse_DestructiveSQL_OnStartQuery covers the
// other USK-1053 variant: a well-formed RPC path carrying a destructive
// query. The reported target is "url", not "query", because the preset
// declares Targets{body, url, query} in that order and the reconstructed
// url already contains the query — byte-identical to how the same rule
// behaves on HTTP.
func TestSafetyEngine_PresetReuse_DestructiveSQL_OnStartQuery(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	env, msg := makeStartEnvWithURL(t, "https", "api.example.com", "/pkg.Svc/Method", "q=DROP TABLE users", "pkg.Svc", "Method")
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation from preset on a destructive query")
	}
	if v.Target != "url" {
		t.Errorf("Target = %q, want url (preset target order is body, url, query)", v.Target)
	}
	if v.RuleID != "destructive-sql:drop" {
		t.Errorf("RuleID = %q, want destructive-sql:drop", v.RuleID)
	}
}

// TestSafetyEngine_PresetReuse_BenignStart_NotBlocked is the other half of
// the bidirectional guard: an ordinary RPC target must survive both
// shipped presets untouched. Without this, a rule that matched everything
// would satisfy the positive tests above.
func TestSafetyEngine_PresetReuse_BenignStart_NotBlocked(t *testing.T) {
	e := NewSafetyEngine()
	for _, name := range []string{common.PresetDestructiveSQL, common.PresetDestructiveOSCommand} {
		if err := e.LoadPreset(name); err != nil {
			t.Fatal(err)
		}
	}
	if e.RuleCount() == 0 {
		t.Fatal("precondition failed: no rules loaded")
	}

	cases := []struct {
		name      string
		scheme    string
		authority string
		path      string
		rawQuery  string
		service   string
		method    string
	}{
		{"plain rpc", "https", "api.example.com", "/pkg.Svc/GetUser", "", "pkg.Svc", "GetUser"},
		{"rpc with query", "https", "api.example.com", "/pkg.Svc/GetUser", "id=42&name=alice", "pkg.Svc", "GetUser"},
		{"h2c scheme", "http", "127.0.0.1:8080", "/helloworld.Greeter/SayHello", "", "helloworld.Greeter", "SayHello"},
		{"malformed but benign path", "https", "api.example.com", "//weird", "", "", ""},
		{"no url fields at all", "", "", "", "", "pkg.Svc", "GetUser"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, msg := makeStartEnvWithURL(t, tc.scheme, tc.authority, tc.path, tc.rawQuery, tc.service, tc.method)
			if v := e.CheckInput(context.Background(), env, msg); v != nil {
				t.Errorf("benign Start blocked: %+v", v)
			}
		})
	}
}

// TestSafetyEngine_TargetQuery_OnStart pins the "query" target name for a
// rule that asks for the query alone — the spelling an operator writes in
// safety_filter.input rules, already accepted by config validation.
func TestSafetyEngine_TargetQuery_OnStart(t *testing.T) {
	e := NewSafetyEngine()
	re, err := common.CompilePattern(`(?i)DROP\s+TABLE`)
	if err != nil {
		t.Fatal(err)
	}
	e.AddRule(common.CompiledRule{
		ID:      "custom:drop-table",
		Name:    "DROP TABLE",
		Pattern: re,
		Targets: []common.Target{common.TargetQuery},
	})

	env, msg := makeStartEnvWithURL(t, "https", "api.example.com", "/pkg.Svc/Method", "q=DROP TABLE users", "pkg.Svc", "Method")
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation on the query target")
	}
	if v.Target != "query" {
		t.Errorf("Target = %q, want query", v.Target)
	}

	// Same rule, same destructive text in the path instead of the query —
	// a query-only rule must not fire.
	envNoQuery, msgNoQuery := makeStartEnvWithURL(t, "https", "api.example.com", "/;DROP TABLE users--", "", "", "")
	if v := e.CheckInput(context.Background(), envNoQuery, msgNoQuery); v != nil {
		t.Errorf("query-only rule fired without a query: %+v", v)
	}
}

// TestSafetyEngine_TargetURL_OnStart pins the "url" target name and shows
// that the url target spans authority + path + query, not just the path.
func TestSafetyEngine_TargetURL_OnStart(t *testing.T) {
	e := NewSafetyEngine()
	re, err := common.CompilePattern(`https://internal\.admin\.example\.com/`)
	if err != nil {
		t.Fatal(err)
	}
	e.AddRule(common.CompiledRule{
		ID:      "custom:internal-host",
		Name:    "Internal admin host",
		Pattern: re,
		Targets: []common.Target{common.TargetURL},
	})

	env, msg := makeStartEnvWithURL(t, "https", "internal.admin.example.com", "/pkg.Svc/Method", "", "pkg.Svc", "Method")
	v := e.CheckInput(context.Background(), env, msg)
	if v == nil {
		t.Fatal("expected violation on the url target")
	}
	if v.Target != "url" {
		t.Errorf("Target = %q, want url", v.Target)
	}

	env2, msg2 := makeStartEnvWithURL(t, "https", "public.example.com", "/pkg.Svc/Method", "", "pkg.Svc", "Method")
	if v := e.CheckInput(context.Background(), env2, msg2); v != nil {
		t.Errorf("url rule fired on an unrelated authority: %+v", v)
	}
}

// TestSafetyEngine_CheckInputAll_StartURLQuery_OneViolationPerRule
// documents that a rule matching both the url and the query yields a
// single Violation: checkRule returns on the first matching target within
// a rule. Same structure as http.checkRule.
func TestSafetyEngine_CheckInputAll_StartURLQuery_OneViolationPerRule(t *testing.T) {
	e := NewSafetyEngine()
	re, err := common.CompilePattern(`(?i)DROP\s+TABLE`)
	if err != nil {
		t.Fatal(err)
	}
	e.AddRule(common.CompiledRule{
		ID:      "custom:drop-table",
		Pattern: re,
		Targets: []common.Target{common.TargetURL, common.TargetQuery},
	})

	env, msg := makeStartEnvWithURL(t, "https", "api.example.com", "/pkg.Svc/Method", "q=DROP TABLE users", "pkg.Svc", "Method")
	got := e.CheckInputAll(context.Background(), env, msg)
	if len(got) != 1 {
		t.Fatalf("CheckInputAll returned %d violations, want 1: %+v", len(got), got)
	}
	if got[0].Target != "url" {
		t.Errorf("Target = %q, want url", got[0].Target)
	}
}

// TestSafetyEngine_CheckInput_PercentEncodedQuery_NotBlocked pins a known
// and deliberate limitation: the query is matched raw and undecoded,
// exactly as rules/http matches HTTPMessage.RawQuery. Percent-decoding
// here would normalize what the wire did not normalize (MITM Principle
// 1). This fix buys HTTP-parity coverage, not more — if percent-decoded
// matching is ever wanted it must land on HTTP and gRPC together, and
// this test is the tripwire that will notice.
func TestSafetyEngine_CheckInput_PercentEncodedQuery_NotBlocked(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatal(err)
	}

	env, msg := makeStartEnvWithURL(t, "https", "api.example.com", "/pkg.Svc/Method", "q=DROP%20TABLE%20users", "pkg.Svc", "Method")
	if v := e.CheckInput(context.Background(), env, msg); v != nil {
		t.Errorf("percent-encoded query unexpectedly blocked (%+v); rules/http does not catch it either — "+
			"if this behaviour changed, change it for HTTP and gRPC together", v)
	}
}

func TestExtractTarget_StartURLQuery(t *testing.T) {
	cases := []struct {
		name     string
		target   common.Target
		msg      *envelope.GRPCStartMessage
		wantData string
		wantName string
	}{
		{
			name:     "url full",
			target:   common.TargetURL,
			msg:      &envelope.GRPCStartMessage{Scheme: "https", Authority: "a.example.com", Path: "/p.S/M", RawQuery: "x=1"},
			wantData: "https://a.example.com/p.S/M?x=1",
			wantName: "url",
		},
		{
			name:     "url no query",
			target:   common.TargetURL,
			msg:      &envelope.GRPCStartMessage{Scheme: "https", Authority: "a.example.com", Path: "/p.S/M"},
			wantData: "https://a.example.com/p.S/M",
			wantName: "url",
		},
		{
			name:     "url synthetic start falls back to service/method",
			target:   common.TargetURL,
			msg:      &envelope.GRPCStartMessage{Scheme: "https", Authority: "a.example.com", Service: "p.S", Method: "M"},
			wantData: "https://a.example.com/p.S/M",
			wantName: "url",
		},
		{
			name:   "url empty on a response-side start",
			target: common.TargetURL,
			// buildStartMessage sets Scheme/Authority/Path/RawQuery on Send
			// only, so a Receive Start carries none of them. An empty data
			// string makes checkRule skip the target.
			msg:      &envelope.GRPCStartMessage{},
			wantData: "",
			wantName: "url",
		},
		{
			name:     "query present",
			target:   common.TargetQuery,
			msg:      &envelope.GRPCStartMessage{Path: "/p.S/M", RawQuery: "x=1&y=2"},
			wantData: "x=1&y=2",
			wantName: "query",
		},
		{
			name:     "query absent",
			target:   common.TargetQuery,
			msg:      &envelope.GRPCStartMessage{Path: "/p.S/M"},
			wantData: "",
			wantName: "query",
		},
		{
			name:     "unrelated target still falls through",
			target:   common.TargetHeaders,
			msg:      &envelope.GRPCStartMessage{Path: "/p.S/M"},
			wantData: "",
			wantName: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, name := extractTarget(tc.target, tc.msg)
			if data != tc.wantData {
				t.Errorf("data = %q, want %q", data, tc.wantData)
			}
			if name != tc.wantName {
				t.Errorf("name = %q, want %q", name, tc.wantName)
			}
		})
	}
}

// TestExtractTarget_URLQueryNotApplicableToDataOrEnd confirms the
// deliberate absence of url / query cases on the Data and End arms: those
// message types carry no Path / RawQuery / Authority / Scheme, so they
// must fall through to ("", "") and let checkRule continue.
func TestExtractTarget_URLQueryNotApplicableToDataOrEnd(t *testing.T) {
	msgs := map[string]envelope.Message{
		"data": &envelope.GRPCDataMessage{Service: "p.S", Method: "M", Payload: []byte("x")},
		"end":  &envelope.GRPCEndMessage{},
	}
	for kind, msg := range msgs {
		for _, target := range []common.Target{common.TargetURL, common.TargetQuery} {
			// Subtests: map iteration order is randomized, so without
			// them a failure is neither ordered nor reproducible via -run.
			t.Run(kind+"/"+string(target), func(t *testing.T) {
				data, name := extractTarget(target, msg)
				if data != "" || name != "" {
					t.Errorf("extractTarget(%q, %s) = (%q, %q), want empty", target, kind, data, name)
				}
			})
		}
	}
}

func TestReconstructURL_GRPCStart(t *testing.T) {
	cases := []struct {
		name string
		msg  *envelope.GRPCStartMessage
		want string
	}{
		{"nil message", nil, ""},
		{"zero value", &envelope.GRPCStartMessage{}, ""},
		{
			"full",
			&envelope.GRPCStartMessage{Scheme: "https", Authority: "a.example.com", Path: "/p.S/M", RawQuery: "x=1"},
			"https://a.example.com/p.S/M?x=1",
		},
		{
			"no scheme omits the separator",
			&envelope.GRPCStartMessage{Authority: "a.example.com", Path: "/p.S/M"},
			"a.example.com/p.S/M",
		},
		{
			"no authority",
			&envelope.GRPCStartMessage{Scheme: "https", Path: "/p.S/M"},
			"https:///p.S/M",
		},
		{
			"empty path with service and method",
			&envelope.GRPCStartMessage{Scheme: "http", Authority: "a", Service: "p.S", Method: "M"},
			"http://a/p.S/M",
		},
		{
			"empty path with service only",
			&envelope.GRPCStartMessage{Scheme: "http", Authority: "a", Service: "p.S"},
			"http://a/p.S/",
		},
		{
			"empty path with neither service nor method stays empty",
			&envelope.GRPCStartMessage{Scheme: "http", Authority: "a"},
			"http://a",
		},
		{
			"observed path wins over service and method",
			&envelope.GRPCStartMessage{Scheme: "https", Authority: "a", Path: "/;DROP TABLE x--", Service: "ignored", Method: "ignored"},
			"https://a/;DROP TABLE x--",
		},
		{
			"empty query adds no question mark",
			&envelope.GRPCStartMessage{Scheme: "https", Authority: "a", Path: "/p.S/M", RawQuery: ""},
			"https://a/p.S/M",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reconstructURL(tc.msg); got != tc.want {
				t.Errorf("reconstructURL = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReconstructURL_GRPCStart_NoNormalization is the MITM Principle 1
// guard on the scan boundary: the builder must not lowercase the
// authority, strip a default port, percent-decode, or collapse slashes.
// Any of those would make the engine match against something the wire
// never carried.
func TestReconstructURL_GRPCStart_NoNormalization(t *testing.T) {
	msg := &envelope.GRPCStartMessage{
		Scheme:    "HTTPS",
		Authority: "API.Example.COM:443",
		Path:      "//pkg.Svc//Method%2Fx",
		RawQuery:  "A=%20b&A=%20b",
	}
	want := "HTTPS://API.Example.COM:443//pkg.Svc//Method%2Fx?A=%20b&A=%20b"
	if got := reconstructURL(msg); got != want {
		t.Errorf("reconstructURL normalized the wire value:\n got %q\nwant %q", got, want)
	}
}
