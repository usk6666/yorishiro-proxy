package bytechunk

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestChannel_Send_RawWins covers USK-1079 / RFC-001 §9.3 D4 on raw TCP:
// a raw-authoritative envelope writes Raw (the plugin's msg["raw"]), an
// unmarked one keeps writing Message.Bytes.
func TestChannel_Send_RawWins(t *testing.T) {
	tests := []struct {
		name string
		auth bool
		raw  []byte
		want string
	}{
		{name: "marked writes Raw", auth: true, raw: []byte("PLUGIN-RAW"), want: "PLUGIN-RAW"},
		{name: "unmarked writes Bytes", auth: false, raw: []byte("STALE-RAW"), want: "message"},
		{name: "marked with empty Raw falls back to Bytes", auth: true, raw: nil, want: "message"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxySide, peer := net.Pipe()
			defer proxySide.Close()
			defer peer.Close()

			l := New(proxySide, "stream-raw-wins", envelope.Receive)
			defer l.Close()
			ch := <-l.Channels()

			env := &envelope.Envelope{
				Direction:        envelope.Send,
				Protocol:         envelope.ProtocolRaw,
				Raw:              tt.raw,
				RawAuthoritative: tt.auth,
				Message:          &envelope.RawMessage{Bytes: []byte("message")},
			}
			readc := make(chan []byte, 1)
			go func() {
				b, _ := io.ReadAll(peer)
				readc <- b
			}()
			if err := ch.Send(context.Background(), env); err != nil {
				t.Fatalf("Send: %v", err)
			}
			_ = proxySide.Close()
			select {
			case got := <-readc:
				if string(got) != tt.want {
					t.Errorf("wire = %q, want %q", got, tt.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("peer read did not finish")
			}
		})
	}
}
