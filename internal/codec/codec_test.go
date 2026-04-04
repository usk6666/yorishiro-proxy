package codec_test

import (
	"context"
	"io"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// mockCodec is a minimal Codec implementation used solely for compile-time
// interface satisfaction checks.
type mockCodec struct{}

func (m *mockCodec) Next(_ context.Context) (*exchange.Exchange, error) {
	return nil, io.EOF
}

func (m *mockCodec) Send(_ context.Context, _ *exchange.Exchange) error {
	return nil
}

func (m *mockCodec) Close() error {
	return nil
}

// Compile-time interface check.
var _ codec.Codec = (*mockCodec)(nil)

func TestCodecInterfaceSatisfaction(t *testing.T) {
	// The compile-time check above (var _ codec.Codec = ...) is sufficient.
	// This test exists so that `go test` reports a passing test for the
	// codec package rather than "no test files".
	var m mockCodec
	ex, err := m.Next(context.Background())
	if ex != nil {
		t.Fatalf("expected nil exchange, got %v", ex)
	}
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}
