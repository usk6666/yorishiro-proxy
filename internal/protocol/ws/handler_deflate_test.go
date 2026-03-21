package ws

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	gohttp "net/http"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestHandleUpgrade_DeflateCompressedTextFrame(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	respHeader := gohttp.Header{}
	respHeader.Set("Sec-WebSocket-Extensions", "permessage-deflate; server_no_context_takeover; client_no_context_takeover")
	resp := &gohttp.Response{StatusCode: 101, Header: respHeader}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-deflate-1", "127.0.0.1:1234", nil)
	}()

	// Compress the text "Hello, Deflate!" with DEFLATE.
	original := "Hello, Deflate!"
	compressed := deflateCompress(t, []byte(original))

	// Client sends a compressed text frame (RSV1=true).
	clientFrame := &Frame{
		Fin:     true,
		RSV1:    true,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: compressed,
	}
	go func() {
		WriteFrame(clientEnd, clientFrame)
	}()

	// Upstream should receive the frame with RSV1 preserved (wire transparency).
	received, err := ReadFrame(upstreamEnd)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if !received.RSV1 {
		t.Error("upstream frame RSV1 = false, want true (wire transparency)")
	}
	if !bytes.Equal(received.Payload, compressed) {
		t.Error("upstream payload should be compressed (wire transparency)")
	}

	// Close.
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	closeFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeClose,
		Masked:  true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: closePayload,
	}
	go func() {
		WriteFrame(clientEnd, closeFrame)
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("HandleUpgrade returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}

	// Verify that the stored message body is the decompressed plaintext.
	messages := store.Messages()
	var sendMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "send" && msg.Body != nil && string(msg.Body) == original {
			sendMsg = msg
			break
		}
	}
	if sendMsg == nil {
		// Debug: print all stored messages.
		for _, msg := range messages {
			t.Logf("stored message: seq=%d dir=%s body=%q raw=%v metadata=%v",
				msg.Sequence, msg.Direction, msg.Body, msg.RawBytes, msg.Metadata)
		}
		t.Fatal("decompressed message with body 'Hello, Deflate!' not found in store")
	}
	if sendMsg.Metadata["compressed"] != "true" {
		t.Errorf("metadata[compressed] = %q, want %q", sendMsg.Metadata["compressed"], "true")
	}
}

func TestHandleUpgrade_DeflateCompressedServerFrame(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	respHeader := gohttp.Header{}
	respHeader.Set("Sec-WebSocket-Extensions", "permessage-deflate")
	resp := &gohttp.Response{StatusCode: 101, Header: respHeader}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-deflate-2", "127.0.0.1:2345", nil)
	}()

	// Server sends a compressed text frame (RSV1=true).
	original := "Server response data"
	compressed := deflateCompress(t, []byte(original))

	serverFrame := &Frame{
		Fin:     true,
		RSV1:    true,
		Opcode:  OpcodeText,
		Payload: compressed,
	}
	go func() {
		WriteFrame(upstreamEnd, serverFrame)
	}()

	// Client receives the frame with RSV1 preserved.
	received, err := ReadFrame(clientEnd)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !received.RSV1 {
		t.Error("client frame RSV1 = false, want true (wire transparency)")
	}

	// Close.
	closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Payload: []byte{0x03, 0xE8}}
	go func() {
		WriteFrame(upstreamEnd, closeFrame)
	}()
	ReadFrame(clientEnd)
	clientEnd.Close()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("HandleUpgrade returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}

	// Verify stored message is decompressed.
	messages := store.Messages()
	var recvMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "receive" && msg.Body != nil && string(msg.Body) == original {
			recvMsg = msg
			break
		}
	}
	if recvMsg == nil {
		for _, msg := range messages {
			t.Logf("stored message: seq=%d dir=%s body=%q raw=%v metadata=%v",
				msg.Sequence, msg.Direction, msg.Body, msg.RawBytes, msg.Metadata)
		}
		t.Fatal("decompressed message with body 'Server response data' not found")
	}
	if recvMsg.Metadata["compressed"] != "true" {
		t.Errorf("metadata[compressed] = %q, want %q", recvMsg.Metadata["compressed"], "true")
	}
}

func TestHandleUpgrade_NoDeflate_RSV1NotSet(t *testing.T) {
	// When no permessage-deflate is negotiated, frames without RSV1
	// should be recorded as-is (no decompression attempted).
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	resp := &gohttp.Response{StatusCode: 101} // No extensions header.

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-nodeflate", "127.0.0.1:3456", nil)
	}()

	// Client sends a plain text frame.
	clientFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeText,
		Masked:  true,
		MaskKey: [4]byte{0x12, 0x34, 0x56, 0x78},
		Payload: []byte("plain text"),
	}
	go func() {
		WriteFrame(clientEnd, clientFrame)
	}()

	ReadFrame(upstreamEnd)

	// Close.
	closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Masked: true, MaskKey: [4]byte{0x01, 0x02, 0x03, 0x04}, Payload: []byte{0x03, 0xE8}}
	go func() {
		WriteFrame(clientEnd, closeFrame)
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("HandleUpgrade returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}

	// Verify: message stored as plain text, no "compressed" metadata.
	messages := store.Messages()
	var sendMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "send" && string(msg.Body) == "plain text" {
			sendMsg = msg
			break
		}
	}
	if sendMsg == nil {
		t.Fatal("plain text message not found in store")
	}
	if _, ok := sendMsg.Metadata["compressed"]; ok {
		t.Error("metadata should not contain 'compressed' key for non-deflate frames")
	}
}

func TestHandleUpgrade_DeflateCompressedBinaryFrame(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	respHeader := gohttp.Header{}
	respHeader.Set("Sec-WebSocket-Extensions", "permessage-deflate; client_no_context_takeover")
	resp := &gohttp.Response{StatusCode: 101, Header: respHeader}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-deflate-bin", "127.0.0.1:4567", nil)
	}()

	// Compress binary data.
	original := []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD}
	compressed := deflateCompress(t, original)

	clientFrame := &Frame{
		Fin:     true,
		RSV1:    true,
		Opcode:  OpcodeBinary,
		Masked:  true,
		MaskKey: [4]byte{0x55, 0x66, 0x77, 0x88},
		Payload: compressed,
	}
	go func() {
		WriteFrame(clientEnd, clientFrame)
	}()

	ReadFrame(upstreamEnd)

	// Close.
	closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Masked: true, MaskKey: [4]byte{0x01, 0x02, 0x03, 0x04}, Payload: []byte{0x03, 0xE8}}
	go func() {
		WriteFrame(clientEnd, closeFrame)
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("HandleUpgrade returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}

	// Verify stored as decompressed raw bytes (binary opcode).
	messages := store.Messages()
	var binaryMsg *flow.Message
	for _, msg := range messages {
		if msg.Direction == "send" && msg.RawBytes != nil && bytes.Equal(msg.RawBytes, original) {
			binaryMsg = msg
			break
		}
	}
	if binaryMsg == nil {
		for _, msg := range messages {
			t.Logf("stored: seq=%d dir=%s body=%q raw=%v meta=%v",
				msg.Sequence, msg.Direction, msg.Body, msg.RawBytes, msg.Metadata)
		}
		t.Fatal("decompressed binary message not found in store")
	}
	if binaryMsg.Metadata["compressed"] != "true" {
		t.Errorf("metadata[compressed] = %q, want %q", binaryMsg.Metadata["compressed"], "true")
	}
}

func TestHandleUpgrade_DeflateContextTakeover_MultipleMessages(t *testing.T) {
	// Verify that with context_takeover=true (the default, no
	// client_no_context_takeover), multiple messages compressed with a shared
	// LZ77 context are correctly decompressed and stored.
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	clientConn, clientEnd := net.Pipe()
	upstreamConn, upstreamEnd := net.Pipe()
	defer clientConn.Close()
	defer clientEnd.Close()
	defer upstreamConn.Close()
	defer upstreamEnd.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, _ := gohttp.NewRequest("GET", "ws://example.com/ws", nil)
	respHeader := gohttp.Header{}
	// No no_context_takeover flags — context takeover is enabled (default).
	respHeader.Set("Sec-WebSocket-Extensions", "permessage-deflate")
	resp := &gohttp.Response{StatusCode: 101, Header: respHeader}

	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.HandleUpgrade(ctx, clientConn, upstreamConn, nil, req, resp, "conn-ctx-takeover", "127.0.0.1:5678", nil)
	}()

	// Compress 3 messages with shared context (simulating a real client with
	// context takeover enabled).
	originals := []string{"first message", "second message", "third message"}
	var originalBytes [][]byte
	for _, s := range originals {
		originalBytes = append(originalBytes, []byte(s))
	}
	compressedMsgs := deflateCompressWithContext(t, originalBytes)

	// Send each compressed message as a client frame and drain from upstream.
	for i, compressed := range compressedMsgs {
		frame := &Frame{
			Fin:     true,
			RSV1:    true,
			Opcode:  OpcodeText,
			Masked:  true,
			MaskKey: [4]byte{byte(i), 0x34, 0x56, 0x78},
			Payload: compressed,
		}
		writeErrCh := make(chan error, 1)
		go func() {
			writeErrCh <- WriteFrame(clientEnd, frame)
		}()
		// Drain the relayed frame from upstream.
		if _, err := ReadFrame(upstreamEnd); err != nil {
			t.Fatalf("upstream read message %d: %v", i, err)
		}
		if err := <-writeErrCh; err != nil {
			t.Fatalf("WriteFrame message %d: %v", i, err)
		}
	}

	// Close.
	closePayload := make([]byte, 2)
	binary.BigEndian.PutUint16(closePayload, 1000)
	closeFrame := &Frame{
		Fin:     true,
		Opcode:  OpcodeClose,
		Masked:  true,
		MaskKey: [4]byte{0xAA, 0xBB, 0xCC, 0xDD},
		Payload: closePayload,
	}
	closeWriteErrCh := make(chan error, 1)
	go func() {
		closeWriteErrCh <- WriteFrame(clientEnd, closeFrame)
	}()
	ReadFrame(upstreamEnd)
	upstreamEnd.Close()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("HandleUpgrade returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler timeout")
	}

	// Verify all 3 messages were stored decompressed.
	messages := store.Messages()
	for _, original := range originals {
		found := false
		for _, msg := range messages {
			if msg.Direction == "send" && msg.Body != nil && string(msg.Body) == original {
				found = true
				if msg.Metadata["compressed"] != "true" {
					t.Errorf("message %q metadata[compressed] = %q, want %q",
						original, msg.Metadata["compressed"], "true")
				}
				break
			}
		}
		if !found {
			for _, msg := range messages {
				t.Logf("stored: seq=%d dir=%s body=%q raw=%v meta=%v",
					msg.Sequence, msg.Direction, msg.Body, msg.RawBytes, msg.Metadata)
			}
			t.Fatalf("decompressed message %q not found in store", original)
		}
	}
}
