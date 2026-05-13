package ws

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// USK-867: replay actual wire bytes captured from a production failure.
//
// The bytes below were extracted from test-logs/ws-phase3-export.jsonl, the
// JSONL export referenced in the original Linear report. They correspond to
// two streams that failed with
// `upstream.Next: stream error protocol_error: ws: deflate: deflate decompress: unexpected EOF`.
//
// The bytes are the unmasked permessage-deflate payloads (the RSV1=1 frame
// payload, after WebSocket frame-header parsing and client-mask removal).
// They are fed directly into (*deflateState).decompress to localize whether
// the decode failure originates in the deflate code path or upstream of it.
//
// Source streams in the export:
//   - 0f99451a-f32c-44b4-b23a-7c0b7afa6b68: "p3-01-deflate-hello" / "p3-01-deflate-second"
//   - 265e311b-6af5-413c-a959-9c1dfde4afc9: "first" / "second" / "third"
//
// Both streams produced the same error on the second client→server frame.

func TestDeflateState_USK867_WireBytes_Stream_0f99451a(t *testing.T) {
	// Unmasked client→server payloads from stream 0f99451a, in order of arrival.
	msg1Compressed, err := hex.DecodeString("2a30d63530d44d494dcb492c49d5cd48cdc9c90700")
	if err != nil {
		t.Fatalf("hex decode msg1: %v", err)
	}
	msg2Compressed, err := hex.DecodeString("2a40112a4e4dcecf4b0100")
	if err != nil {
		t.Fatalf("hex decode msg2: %v", err)
	}

	ds := newDeflateState(deflateParams{
		enabled:         true,
		contextTakeover: true,
		windowBits:      15,
	})
	defer ds.close()

	decoded1, err := ds.decompress(msg1Compressed, 1<<20)
	if err != nil {
		t.Fatalf("msg1 decompress: %v", err)
	}
	if want := []byte("p3-01-deflate-hello"); !bytes.Equal(decoded1, want) {
		t.Fatalf("msg1 decoded = %q, want %q", decoded1, want)
	}

	decoded2, err := ds.decompress(msg2Compressed, 1<<20)
	if err != nil {
		t.Fatalf("msg2 decompress: %v (this is the USK-867 failure mode)", err)
	}
	if want := []byte("p3-01-deflate-second"); !bytes.Equal(decoded2, want) {
		t.Fatalf("msg2 decoded = %q, want %q", decoded2, want)
	}
}

func TestDeflateState_USK867_WireBytes_Stream_265e311b(t *testing.T) {
	// Unmasked client→server payloads from stream 265e311b ("first"/"second").
	msg1Compressed, err := hex.DecodeString("4acb2c2a2e0100")
	if err != nil {
		t.Fatalf("hex decode msg1: %v", err)
	}
	msg2Compressed, err := hex.DecodeString("2a4e4dcecf4b0100")
	if err != nil {
		t.Fatalf("hex decode msg2: %v", err)
	}

	ds := newDeflateState(deflateParams{
		enabled:         true,
		contextTakeover: true,
		windowBits:      15,
	})
	defer ds.close()

	decoded1, err := ds.decompress(msg1Compressed, 1<<20)
	if err != nil {
		t.Fatalf("msg1 decompress: %v", err)
	}
	if want := []byte("first"); !bytes.Equal(decoded1, want) {
		t.Fatalf("msg1 decoded = %q, want %q", decoded1, want)
	}

	decoded2, err := ds.decompress(msg2Compressed, 1<<20)
	if err != nil {
		t.Fatalf("msg2 decompress: %v (this is the USK-867 failure mode)", err)
	}
	if want := []byte("second"); !bytes.Equal(decoded2, want) {
		t.Fatalf("msg2 decoded = %q, want %q", decoded2, want)
	}
}

// Same wire bytes, but exercising the server→client decode direction (the
// "upstream.Next" direction where the live error surfaces). The bytes are
// identical for the c→s "first" payload from stream 265e311b because the echo
// server reflected the same compressed bytes back; this confirms that the
// echoed payload also decodes cleanly through (*deflateState).
func TestDeflateState_USK867_WireBytes_Stream_265e311b_AsReceive(t *testing.T) {
	msg1Echo, err := hex.DecodeString("4acb2c2a2e0100")
	if err != nil {
		t.Fatalf("hex decode msg1: %v", err)
	}

	ds := newDeflateState(deflateParams{
		enabled:         true,
		contextTakeover: true,
		windowBits:      15,
	})
	defer ds.close()

	decoded1, err := ds.decompress(msg1Echo, 1<<20)
	if err != nil {
		t.Fatalf("msg1 echo decompress: %v", err)
	}
	if want := []byte("first"); !bytes.Equal(decoded1, want) {
		t.Fatalf("msg1 echo decoded = %q, want %q", decoded1, want)
	}
}
