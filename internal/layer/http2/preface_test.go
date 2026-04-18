package http2

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunServerPreface_Valid(t *testing.T) {
	r := strings.NewReader(ClientPreface)
	if err := runServerPreface(r); err != nil {
		t.Fatalf("runServerPreface(valid): %v", err)
	}
}

func TestRunServerPreface_Invalid(t *testing.T) {
	r := strings.NewReader(strings.Repeat("X", len(ClientPreface)))
	if err := runServerPreface(r); err == nil {
		t.Fatalf("runServerPreface(invalid): want error, got nil")
	}
}

func TestRunServerPreface_Short(t *testing.T) {
	r := strings.NewReader("PRI *")
	if err := runServerPreface(r); err == nil {
		t.Fatalf("runServerPreface(short): want error, got nil")
	}
}

func TestRunClientPreface(t *testing.T) {
	var buf bytes.Buffer
	if err := runClientPreface(&buf); err != nil {
		t.Fatalf("runClientPreface: %v", err)
	}
	if buf.String() != ClientPreface {
		t.Errorf("runClientPreface wrote %q, want %q", buf.String(), ClientPreface)
	}
}

func TestClientPrefaceLength(t *testing.T) {
	if len(ClientPreface) != 24 {
		t.Errorf("ClientPreface length = %d, want 24", len(ClientPreface))
	}
}
