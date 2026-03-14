package http

import (
	"io"
	"strings"
	"testing"
)

func TestSSEParser_Next_BasicEvents(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantCount int
		want      []SSEEvent
	}{
		{
			name:      "single data event",
			input:     "data: hello world\n\n",
			wantCount: 1,
			want: []SSEEvent{
				{Data: "hello world"},
			},
		},
		{
			name:      "multiple data lines joined by newline",
			input:     "data: line1\ndata: line2\ndata: line3\n\n",
			wantCount: 1,
			want: []SSEEvent{
				{Data: "line1\nline2\nline3"},
			},
		},
		{
			name:      "event with type",
			input:     "event: update\ndata: payload\n\n",
			wantCount: 1,
			want: []SSEEvent{
				{EventType: "update", Data: "payload"},
			},
		},
		{
			name:      "event with id",
			input:     "id: 42\ndata: message\n\n",
			wantCount: 1,
			want: []SSEEvent{
				{ID: "42", Data: "message"},
			},
		},
		{
			name:      "event with retry",
			input:     "retry: 3000\ndata: reconnect\n\n",
			wantCount: 1,
			want: []SSEEvent{
				{Retry: "3000", Data: "reconnect"},
			},
		},
		{
			name:      "event with all fields",
			input:     "event: chat\nid: 123\nretry: 5000\ndata: hello\n\n",
			wantCount: 1,
			want: []SSEEvent{
				{EventType: "chat", ID: "123", Retry: "5000", Data: "hello"},
			},
		},
		{
			name:      "two events",
			input:     "data: first\n\ndata: second\n\n",
			wantCount: 2,
			want: []SSEEvent{
				{Data: "first"},
				{Data: "second"},
			},
		},
		{
			name:      "events with comments between",
			input:     ": comment\ndata: hello\n\n: another comment\ndata: world\n\n",
			wantCount: 2,
			want: []SSEEvent{
				{Data: "hello"},
				{Data: "world"},
			},
		},
		{
			name:      "comment-only block is skipped",
			input:     ": just a comment\n\ndata: real event\n\n",
			wantCount: 1,
			want: []SSEEvent{
				{Data: "real event"},
			},
		},
		{
			name:      "data with no space after colon",
			input:     "data:nospace\n\n",
			wantCount: 1,
			want: []SSEEvent{
				{Data: "nospace"},
			},
		},
		{
			name:      "data with multiple spaces after colon",
			input:     "data:  two spaces\n\n",
			wantCount: 1,
			want: []SSEEvent{
				// Only the first space is stripped per spec
				{Data: " two spaces"},
			},
		},
		{
			name:      "empty data field",
			input:     "data:\n\n",
			wantCount: 1,
			want: []SSEEvent{
				{Data: ""},
			},
		},
		{
			name:      "field without colon",
			input:     "data: test\nfieldonly\n\n",
			wantCount: 1,
			want: []SSEEvent{
				{Data: "test"},
			},
		},
		{
			name:      "unknown field is ignored",
			input:     "custom: value\ndata: test\n\n",
			wantCount: 1,
			want: []SSEEvent{
				{Data: "test"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewSSEParser(strings.NewReader(tt.input), 0)

			var events []*SSEEvent
			for {
				event, err := parser.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("Next() unexpected error: %v", err)
				}
				events = append(events, event)
			}

			if len(events) != tt.wantCount {
				t.Fatalf("got %d events, want %d", len(events), tt.wantCount)
			}

			for i, want := range tt.want {
				got := events[i]
				if got.Data != want.Data {
					t.Errorf("event[%d].Data = %q, want %q", i, got.Data, want.Data)
				}
				if got.EventType != want.EventType {
					t.Errorf("event[%d].EventType = %q, want %q", i, got.EventType, want.EventType)
				}
				if got.ID != want.ID {
					t.Errorf("event[%d].ID = %q, want %q", i, got.ID, want.ID)
				}
				if got.Retry != want.Retry {
					t.Errorf("event[%d].Retry = %q, want %q", i, got.Retry, want.Retry)
				}
				if got.RawBytes == nil {
					t.Errorf("event[%d].RawBytes should not be nil", i)
				}
			}
		})
	}
}

func TestSSEParser_Next_StreamEndWithoutBlankLine(t *testing.T) {
	// When the stream ends without a trailing blank line, the accumulated
	// fields should be emitted as a final event.
	input := "data: final"
	parser := NewSSEParser(strings.NewReader(input), 0)

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("Next() unexpected error: %v", err)
	}
	if event.Data != "final" {
		t.Errorf("Data = %q, want %q", event.Data, "final")
	}

	_, err = parser.Next()
	if err != io.EOF {
		t.Errorf("second Next() should return io.EOF, got %v", err)
	}
}

func TestSSEParser_Next_EmptyStream(t *testing.T) {
	parser := NewSSEParser(strings.NewReader(""), 0)
	_, err := parser.Next()
	if err != io.EOF {
		t.Errorf("Next() on empty stream should return io.EOF, got %v", err)
	}
}

func TestSSEParser_Next_OnlyComments(t *testing.T) {
	input := ": comment1\n: comment2\n"
	parser := NewSSEParser(strings.NewReader(input), 0)
	_, err := parser.Next()
	if err != io.EOF {
		t.Errorf("Next() on comment-only stream should return io.EOF, got %v", err)
	}
}

func TestSSEParser_Next_OnlyBlankLines(t *testing.T) {
	input := "\n\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)
	_, err := parser.Next()
	if err != io.EOF {
		t.Errorf("Next() on blank-line-only stream should return io.EOF, got %v", err)
	}
}

func TestSSEParser_Next_MaxSizeExceeded(t *testing.T) {
	// Create an event that exceeds the maximum size.
	data := "data: " + strings.Repeat("x", 200) + "\n\n"
	parser := NewSSEParser(strings.NewReader(data), 100)

	_, err := parser.Next()
	if err == nil {
		t.Fatal("Next() should return error for oversized event")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("error message = %q, want containing 'exceeds maximum size'", err.Error())
	}
}

func TestSSEParser_Next_MultipleBlankLinesDelimiter(t *testing.T) {
	// Multiple blank lines between events should not produce empty events.
	input := "data: first\n\n\n\ndata: second\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)

	event1, err := parser.Next()
	if err != nil {
		t.Fatalf("first Next() error: %v", err)
	}
	if event1.Data != "first" {
		t.Errorf("event1.Data = %q, want %q", event1.Data, "first")
	}

	event2, err := parser.Next()
	if err != nil {
		t.Fatalf("second Next() error: %v", err)
	}
	if event2.Data != "second" {
		t.Errorf("event2.Data = %q, want %q", event2.Data, "second")
	}

	_, err = parser.Next()
	if err != io.EOF {
		t.Errorf("third Next() should return io.EOF, got %v", err)
	}
}

func TestSSEParser_Next_RawBytesPreserved(t *testing.T) {
	input := "event: test\ndata: hello\n\n"
	parser := NewSSEParser(strings.NewReader(input), 0)

	event, err := parser.Next()
	if err != nil {
		t.Fatalf("Next() error: %v", err)
	}

	if string(event.RawBytes) != input {
		t.Errorf("RawBytes = %q, want %q", string(event.RawBytes), input)
	}
}

func TestSSEEvent_String(t *testing.T) {
	event := &SSEEvent{
		EventType: "chat",
		ID:        "42",
		Retry:     "5000",
		Data:      "hello\nworld",
	}

	got := event.String()
	if !strings.Contains(got, "event: chat\n") {
		t.Errorf("String() should contain 'event: chat\\n', got %q", got)
	}
	if !strings.Contains(got, "id: 42\n") {
		t.Errorf("String() should contain 'id: 42\\n', got %q", got)
	}
	if !strings.Contains(got, "retry: 5000\n") {
		t.Errorf("String() should contain 'retry: 5000\\n', got %q", got)
	}
	if !strings.Contains(got, "data: hello\n") {
		t.Errorf("String() should contain 'data: hello\\n', got %q", got)
	}
	if !strings.Contains(got, "data: world\n") {
		t.Errorf("String() should contain 'data: world\\n', got %q", got)
	}
}

func TestParseSSEField(t *testing.T) {
	tests := []struct {
		line      string
		wantName  string
		wantValue string
	}{
		{"data: hello", "data", "hello"},
		{"data:hello", "data", "hello"},
		{"data:  hello", "data", " hello"},
		{"data:", "data", ""},
		{"event: custom", "event", "custom"},
		{"fieldonly", "fieldonly", ""},
		{"id: 123", "id", "123"},
		{"retry: 3000", "retry", "3000"},
		{": comment", "", "comment"},
		{":comment", "", "comment"},
		{"data: value:with:colons", "data", "value:with:colons"},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			gotName, gotValue := parseSSEField(tt.line)
			if gotName != tt.wantName {
				t.Errorf("parseSSEField(%q) name = %q, want %q", tt.line, gotName, tt.wantName)
			}
			if gotValue != tt.wantValue {
				t.Errorf("parseSSEField(%q) value = %q, want %q", tt.line, gotValue, tt.wantValue)
			}
		})
	}
}
