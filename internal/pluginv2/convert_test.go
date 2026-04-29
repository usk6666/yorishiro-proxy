package pluginv2

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestSnakeCase_GoldenTable(t *testing.T) {
	// Pinned mapping used everywhere convertMessageToDict produces a
	// dict key. Discharges RFC §9.3 D2's "mechanical" mandate by
	// asserting the rule rather than a manual alias table.
	cases := []struct {
		in, want string
	}{
		// Single word.
		{"Method", "method"},
		{"Path", "path"},
		// lowercase-then-uppercase.
		{"RawQuery", "raw_query"},
		{"StatusReason", "status_reason"},
		{"ContentType", "content_type"},
		{"AcceptEncoding", "accept_encoding"},
		{"WireLength", "wire_length"},
		{"EndStream", "end_stream"},
		{"CloseCode", "close_code"},
		{"CloseReason", "close_reason"},
		{"BodyStream", "body_stream"},
		{"StatusDetails", "status_details"},
		// Trailing acronym.
		{"FlowID", "flow_id"},
		{"StreamID", "stream_id"},
		// Bare acronym.
		{"ID", "id"},
		{"URL", "url"},
		// Acronym then lowercase.
		{"HTTPCode", "http_code"},
		// Numeric tail (JA3 / JA4).
		{"JA3", "ja3"},
		{"JA4", "ja4"},
		// Empty.
		{"", ""},
	}
	for _, tc := range cases {
		got := snakeCase(tc.in)
		if got != tc.want {
			t.Errorf("snakeCase(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestConvertMessageToDict_NilEnvelope(t *testing.T) {
	if _, err := convertMessageToDict(nil); err == nil {
		t.Fatal("expected error for nil envelope")
	}
}

func TestConvertMessageToDict_NilMessage(t *testing.T) {
	if _, err := convertMessageToDict(&envelope.Envelope{}); err == nil {
		t.Fatal("expected error for nil message")
	}
}

func TestConvertMessageToDict_UnsupportedType(t *testing.T) {
	env := &envelope.Envelope{Message: unknownMessage{}}
	_, err := convertMessageToDict(env)
	if !errors.Is(err, ErrUnsupportedMessageType) {
		t.Fatalf("err = %v, want ErrUnsupportedMessageType", err)
	}
}

type unknownMessage struct{}

func (unknownMessage) Protocol() envelope.Protocol    { return "unknown" }
func (unknownMessage) CloneMessage() envelope.Message { return unknownMessage{} }

func TestRoundTrip_HTTPMessage_NoChange(t *testing.T) {
	m := &envelope.HTTPMessage{
		Method:       "POST",
		Scheme:       "https",
		Authority:    "example.com",
		Path:         "/api",
		RawQuery:     "x=1&y=2",
		Status:       200,
		StatusReason: "OK",
		Headers: []envelope.KeyValue{
			{Name: "X-First", Value: "v1"},
			{Name: "x-first", Value: "v2"},
		},
		Trailers: []envelope.KeyValue{{Name: "X-Trailer", Value: "tv"}},
		Body:     []byte("hello"),
		Anomalies: []envelope.Anomaly{
			{Type: envelope.AnomalyDuplicateCL, Detail: "two CL"},
		},
	}
	env := &envelope.Envelope{Message: m, Raw: []byte("WIRE")}
	d, err := convertMessageToDict(env)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if d.classify() != MutationUnchanged {
		t.Fatalf("classify = %s before mutation", d.classify())
	}
	got, raw, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationUnchanged {
		t.Fatalf("kind = %s, want unchanged", kind)
	}
	if got != envelope.Message(m) {
		t.Fatalf("Unchanged path must alias original Message; got %p, want %p", got, m)
	}
	if &raw[0] != &env.Raw[0] {
		t.Fatalf("Unchanged path must alias original Raw")
	}
}

func TestRoundTrip_WSMessage(t *testing.T) {
	m := &envelope.WSMessage{
		Opcode:      envelope.WSText,
		Fin:         true,
		Masked:      true,
		Mask:        [4]byte{0x01, 0x02, 0x03, 0x04},
		Payload:     []byte("hi"),
		CloseCode:   1000,
		CloseReason: "normal",
		Compressed:  false,
	}
	env := &envelope.Envelope{Message: m, Raw: []byte("WS")}
	d, err := convertMessageToDict(env)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	got, _, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationUnchanged {
		t.Fatalf("kind = %s; expected unchanged on no mutation", kind)
	}
	if got != m {
		t.Fatalf("unchanged path must alias original")
	}
}

func TestRoundTrip_GRPCStartMessage(t *testing.T) {
	m := &envelope.GRPCStartMessage{
		Service: "greeter.Greeter",
		Method:  "SayHello",
		Metadata: []envelope.KeyValue{
			{Name: "x-token", Value: "abc"},
			{Name: "X-Token", Value: "def"},
		},
		Timeout:        5 * time.Second,
		ContentType:    "application/grpc+proto",
		Encoding:       "gzip",
		AcceptEncoding: []string{"gzip", "identity"},
	}
	env := &envelope.Envelope{Message: m}
	d, err := convertMessageToDict(env)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	got, _, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationUnchanged || got != m {
		t.Fatalf("unchanged round-trip failed: kind=%s aliased=%v", kind, got == m)
	}
}

func TestRoundTrip_GRPCDataMessage(t *testing.T) {
	m := &envelope.GRPCDataMessage{
		Service:    "greeter.Greeter",
		Method:     "SayHello",
		Compressed: true,
		WireLength: 12,
		Payload:    []byte("payload-bytes"),
		EndStream:  true,
	}
	env := &envelope.Envelope{Message: m}
	d, err := convertMessageToDict(env)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	got, _, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationUnchanged || got != m {
		t.Fatalf("unchanged round-trip failed: kind=%s aliased=%v", kind, got == m)
	}
}

func TestRoundTrip_GRPCEndMessage(t *testing.T) {
	m := &envelope.GRPCEndMessage{
		Status:        0,
		Message:       "ok",
		StatusDetails: []byte("details"),
		Trailers:      []envelope.KeyValue{{Name: "trailer-key", Value: "trailer-val"}},
	}
	env := &envelope.Envelope{Message: m}
	d, err := convertMessageToDict(env)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	got, _, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationUnchanged || got != m {
		t.Fatalf("unchanged round-trip failed: kind=%s aliased=%v", kind, got == m)
	}
}

func TestRoundTrip_RawMessage(t *testing.T) {
	m := &envelope.RawMessage{Bytes: []byte("raw-bytes")}
	env := &envelope.Envelope{Message: m, Raw: []byte("raw-bytes")}
	d, err := convertMessageToDict(env)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	got, _, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationUnchanged || got != m {
		t.Fatalf("unchanged round-trip failed")
	}
}

func TestRoundTrip_SSEMessage(t *testing.T) {
	m := &envelope.SSEMessage{
		Event: "tick",
		Data:  "payload",
		ID:    "42",
		Retry: 5 * time.Second,
	}
	env := &envelope.Envelope{Message: m}
	d, err := convertMessageToDict(env)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	got, _, kind, err := dictToMessage(d)
	if err != nil {
		t.Fatalf("dictToMessage: %v", err)
	}
	if kind != MutationUnchanged || got != m {
		t.Fatalf("unchanged round-trip failed")
	}
}

func TestHTTPBody_OversizedReturnsErr(t *testing.T) {
	m := &envelope.HTTPMessage{Body: make([]byte, maxPluginBodySize+1)}
	env := &envelope.Envelope{Message: m}
	_, err := convertMessageToDict(env)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("err = %v, want ErrBodyTooLarge", err)
	}
}

func TestHTTPMessage_DictExposesAllExpectedKeys(t *testing.T) {
	m := &envelope.HTTPMessage{}
	env := &envelope.Envelope{Message: m}
	d, err := convertMessageToDict(env)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	want := []string{
		"anomalies", "authority", "body", "headers",
		"method", "path", "raw_query", "scheme",
		"status", "status_reason", "trailers",
	}
	got := d.sortedKeysForTest()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HTTPMessage keys mismatch\n got:  %v\n want: %v", got, want)
	}
}

func TestGRPCDataMessage_DictExposesDenormalizedReadOnly(t *testing.T) {
	m := &envelope.GRPCDataMessage{}
	env := &envelope.Envelope{Message: m}
	d, err := convertMessageToDict(env)
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if !d.readOnly["service"] || !d.readOnly["method"] {
		t.Fatalf("GRPCDataMessage service/method not marked read-only: %v", d.readOnly)
	}
}
