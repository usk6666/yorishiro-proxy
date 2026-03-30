package http2

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

func TestRoundTripStream_BasicStreaming(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &Transport{Logger: logger}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)

		streamID, headers, body := server.readRequest(t)

		var method, path string
		for _, hf := range headers {
			switch hf.Name {
			case ":method":
				method = hf.Value
			case ":path":
				path = hf.Value
			}
		}
		if method != "POST" {
			t.Errorf("method = %q, want POST", method)
		}
		if path != "/api/stream" {
			t.Errorf("path = %q, want /api/stream", path)
		}
		if string(body) != "request-body" {
			t.Errorf("body = %q, want request-body", body)
		}

		server.sendResponse(t, streamID, 200, []hpack.HeaderField{
			{Name: "content-type", Value: "application/grpc"},
		}, []byte("streaming-response-data"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com:443"},
		{Name: ":path", Value: "/api/stream"},
	}

	result, err := transport.RoundTripStream(ctx, clientConn, headers, bytes.NewReader([]byte("request-body")), StreamOptions{})
	if err != nil {
		t.Fatalf("RoundTripStream: %v", err)
	}
	defer result.Body.Close()

	if result.StatusCode != 200 {
		t.Errorf("status = %d, want 200", result.StatusCode)
	}

	respBody, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(respBody) != "streaming-response-data" {
		t.Errorf("body = %q, want streaming-response-data", respBody)
	}

	if result.ServerAddr == "" {
		t.Error("ServerAddr is empty")
	}

	wg.Wait()
}

func TestRoundTripStream_NoBody(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &Transport{Logger: logger}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
		streamID, _, body := server.readRequest(t)
		if len(body) != 0 {
			t.Errorf("body = %q, want empty", body)
		}
		server.sendResponse(t, streamID, 204, nil, nil)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/health"},
	}

	result, err := transport.RoundTripStream(ctx, clientConn, headers, nil, StreamOptions{})
	if err != nil {
		t.Fatalf("RoundTripStream: %v", err)
	}
	defer result.Body.Close()

	if result.StatusCode != 204 {
		t.Errorf("status = %d, want 204", result.StatusCode)
	}

	respBody, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if len(respBody) != 0 {
		t.Errorf("body = %q, want empty", respBody)
	}

	wg.Wait()
}

func TestRoundTripStream_Trailers(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &Transport{Logger: logger}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
		streamID, _, _ := server.readRequest(t)

		// Send response HEADERS (without END_STREAM).
		respHeaders := []hpack.HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-type", Value: "application/grpc"},
		}
		fragment := server.enc.Encode(respHeaders)
		if err := server.writer.WriteHeaders(streamID, false, true, fragment); err != nil {
			t.Errorf("write response HEADERS: %v", err)
			return
		}

		// Send DATA.
		if err := server.writer.WriteData(streamID, false, []byte("data-payload")); err != nil {
			t.Errorf("write DATA: %v", err)
			return
		}

		// Send trailing HEADERS with END_STREAM.
		trailers := []hpack.HeaderField{
			{Name: "grpc-status", Value: "0"},
			{Name: "grpc-message", Value: "OK"},
		}
		trailerFragment := server.enc.Encode(trailers)
		if err := server.writer.WriteHeaders(streamID, true, true, trailerFragment); err != nil {
			t.Errorf("write trailer HEADERS: %v", err)
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/grpc.Service/Method"},
	}

	result, err := transport.RoundTripStream(ctx, clientConn, headers, bytes.NewReader([]byte("grpc-request")), StreamOptions{})
	if err != nil {
		t.Fatalf("RoundTripStream: %v", err)
	}
	defer result.Body.Close()

	// Trailers should not be available before reading body.
	_, trErr := result.Trailers()
	if trErr != ErrBodyNotFullyRead {
		t.Errorf("Trailers() before body read: got %v, want ErrBodyNotFullyRead", trErr)
	}

	// Read body.
	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "data-payload" {
		t.Errorf("body = %q, want data-payload", body)
	}

	// Trailers should now be available.
	trailers, err := result.Trailers()
	if err != nil {
		t.Fatalf("Trailers: %v", err)
	}

	var grpcStatus, grpcMessage string
	for _, hf := range trailers {
		switch hf.Name {
		case "grpc-status":
			grpcStatus = hf.Value
		case "grpc-message":
			grpcMessage = hf.Value
		}
	}
	if grpcStatus != "0" {
		t.Errorf("grpc-status = %q, want 0", grpcStatus)
	}
	if grpcMessage != "OK" {
		t.Errorf("grpc-message = %q, want OK", grpcMessage)
	}

	wg.Wait()
}

func TestRoundTripStream_ContextCancel(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &Transport{Logger: logger}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
		// Don't send any response -- let the client cancel.
		for {
			_, err := server.reader.ReadFrame()
			if err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/slow"},
	}

	// Use a body that blocks forever to test context cancellation.
	pr, pw := io.Pipe()
	defer pw.Close()

	_, err := transport.RoundTripStream(ctx, clientConn, headers, pr, StreamOptions{})
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if !strings.Contains(err.Error(), "context") {
		t.Errorf("error = %v, want context-related error", err)
	}

	wg.Wait()
}

func TestRoundTripStream_OnSendRecvFrameCallbacks(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &Transport{Logger: logger}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
		streamID, _, _ := server.readRequest(t)
		server.sendResponse(t, streamID, 200, nil, []byte("callback-test"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var sentFrames atomic.Int32
	var recvFrames atomic.Int32

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/callback"},
	}

	result, err := transport.RoundTripStream(ctx, clientConn, headers, bytes.NewReader([]byte("body")), StreamOptions{
		OnSendFrame: func(frameBytes []byte) {
			sentFrames.Add(1)
			if len(frameBytes) < frame.HeaderSize {
				t.Errorf("sent frame too short: %d bytes", len(frameBytes))
			}
		},
		OnRecvFrame: func(frameBytes []byte) {
			recvFrames.Add(1)
			if len(frameBytes) < frame.HeaderSize {
				t.Errorf("recv frame too short: %d bytes", len(frameBytes))
			}
		},
	})
	if err != nil {
		t.Fatalf("RoundTripStream: %v", err)
	}
	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "callback-test" {
		t.Errorf("body = %q, want callback-test", body)
	}

	// We should have seen at least 2 sent frames (HEADERS + DATA with END_STREAM).
	if s := sentFrames.Load(); s < 2 {
		t.Errorf("sent frames = %d, want >= 2", s)
	}

	// We should have seen at least 2 recv frames (HEADERS + DATA).
	if r := recvFrames.Load(); r < 2 {
		t.Errorf("recv frames = %d, want >= 2", r)
	}

	wg.Wait()
}

func TestRoundTripStream_LargeBodyFlowControl(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &Transport{Logger: logger}

	// Create a body larger than the default window size (65535 bytes).
	largeBody := bytes.Repeat([]byte("X"), 100000)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)

		var headerFragment []byte
		var streamID uint32
		var endHeaders, endStream bool

		// Read HEADERS.
		for {
			f, err := server.reader.ReadFrame()
			if err != nil {
				t.Errorf("read frame: %v", err)
				return
			}
			switch f.Header.Type {
			case frame.TypeHeaders:
				streamID = f.Header.StreamID
				endHeaders = f.Header.Flags.Has(frame.FlagEndHeaders)
				endStream = f.Header.Flags.Has(frame.FlagEndStream)
				frag, _ := f.HeaderBlockFragment()
				headerFragment = append(headerFragment, frag...)
				if endHeaders {
					goto readData
				}
			case frame.TypeWindowUpdate, frame.TypeSettings, frame.TypePing:
				continue
			}
		}

	readData:
		_ = headerFragment

		// Read DATA frames and send WINDOW_UPDATEs.
		var totalData int
		for !endStream {
			f, err := server.reader.ReadFrame()
			if err != nil {
				t.Errorf("read frame: %v", err)
				return
			}
			switch f.Header.Type {
			case frame.TypeData:
				payload, _ := f.DataPayload()
				totalData += len(payload)
				endStream = f.Header.Flags.Has(frame.FlagEndStream)
				if len(payload) > 0 {
					server.writer.WriteWindowUpdate(0, uint32(len(payload)))        //nolint:errcheck
					server.writer.WriteWindowUpdate(streamID, uint32(len(payload))) //nolint:errcheck
				}
			case frame.TypeWindowUpdate, frame.TypeSettings, frame.TypePing:
				continue
			}
		}

		if totalData != len(largeBody) {
			t.Errorf("received %d bytes, want %d", totalData, len(largeBody))
		}

		server.sendResponse(t, streamID, 200, nil, []byte("ok"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/large"},
	}

	result, err := transport.RoundTripStream(ctx, clientConn, headers, bytes.NewReader(largeBody), StreamOptions{})
	if err != nil {
		t.Fatalf("RoundTripStream: %v", err)
	}
	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "ok" {
		t.Errorf("body = %q, want ok", body)
	}

	wg.Wait()
}

func TestStreamRoundTripResult_TrailersBeforeBodyRead(t *testing.T) {
	result := &StreamRoundTripResult{}

	_, err := result.Trailers()
	if err != ErrBodyNotFullyRead {
		t.Errorf("Trailers() on fresh result: got %v, want ErrBodyNotFullyRead", err)
	}
}

func TestStreamRoundTripResult_TrailersAfterMarkDone(t *testing.T) {
	result := &StreamRoundTripResult{}

	expectedTrailers := []hpack.HeaderField{
		{Name: "grpc-status", Value: "0"},
	}
	result.markBodyDone(expectedTrailers)

	trailers, err := result.Trailers()
	if err != nil {
		t.Fatalf("Trailers: %v", err)
	}
	if len(trailers) != 1 || trailers[0].Name != "grpc-status" {
		t.Errorf("trailers = %v, want [{grpc-status 0}]", trailers)
	}
}

func TestRoundTripStream_HeadersEndStreamNoBody(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &Transport{Logger: logger}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
		streamID, _, _ := server.readRequest(t)
		respHeaders := []hpack.HeaderField{
			{Name: ":status", Value: "204"},
		}
		fragment := server.enc.Encode(respHeaders)
		if err := server.writer.WriteHeaders(streamID, true, true, fragment); err != nil {
			t.Errorf("write HEADERS: %v", err)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/no-body"},
	}

	result, err := transport.RoundTripStream(ctx, clientConn, headers, nil, StreamOptions{})
	if err != nil {
		t.Fatalf("RoundTripStream: %v", err)
	}
	defer result.Body.Close()

	if result.StatusCode != 204 {
		t.Errorf("status = %d, want 204", result.StatusCode)
	}

	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if len(body) != 0 {
		t.Errorf("body = %q, want empty", body)
	}

	wg.Wait()
}

func TestRoundTripStream_ExistingRoundTripOnConnUnaffected(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &Transport{Logger: logger}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)
		streamID, _, body := server.readRequest(t)
		if string(body) != "existing-test" {
			t.Errorf("body = %q, want existing-test", body)
		}
		server.sendResponse(t, streamID, 200, nil, []byte("existing-response"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/existing"},
	}

	result, err := transport.RoundTripOnConn(ctx, clientConn, headers, bytes.NewReader([]byte("existing-test")))
	if err != nil {
		t.Fatalf("RoundTripOnConn: %v", err)
	}

	if result.StatusCode != 200 {
		t.Errorf("status = %d, want 200", result.StatusCode)
	}

	body, _ := io.ReadAll(result.Body)
	if string(body) != "existing-response" {
		t.Errorf("body = %q, want existing-response", body)
	}

	wg.Wait()
}

func TestRoundTripStream_BidirectionalStreaming(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &Transport{Logger: logger}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)

		// Read HEADERS frame.
		var streamID uint32
		for {
			f, err := server.reader.ReadFrame()
			if err != nil {
				t.Errorf("read frame: %v", err)
				return
			}
			if f.Header.Type == frame.TypeHeaders {
				streamID = f.Header.StreamID
				break
			}
		}

		// Send response HEADERS (without END_STREAM).
		respHeaders := []hpack.HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-type", Value: "application/grpc"},
		}
		fragment := server.enc.Encode(respHeaders)
		if err := server.writer.WriteHeaders(streamID, false, true, fragment); err != nil {
			t.Errorf("write response HEADERS: %v", err)
			return
		}

		// Echo back each DATA frame as we receive it.
		for {
			f, err := server.reader.ReadFrame()
			if err != nil {
				t.Errorf("read frame: %v", err)
				return
			}
			switch f.Header.Type {
			case frame.TypeData:
				payload, _ := f.DataPayload()
				endStream := f.Header.Flags.Has(frame.FlagEndStream)

				if len(payload) > 0 {
					server.writer.WriteWindowUpdate(0, uint32(len(payload)))        //nolint:errcheck
					server.writer.WriteWindowUpdate(streamID, uint32(len(payload))) //nolint:errcheck
				}

				if len(payload) > 0 {
					if err := server.writer.WriteData(streamID, false, payload); err != nil {
						t.Errorf("write echo DATA: %v", err)
						return
					}
				}

				if endStream {
					trailers := []hpack.HeaderField{
						{Name: "grpc-status", Value: "0"},
					}
					trailerFragment := server.enc.Encode(trailers)
					if err := server.writer.WriteHeaders(streamID, true, true, trailerFragment); err != nil {
						t.Errorf("write trailers: %v", err)
					}
					return
				}
			case frame.TypeWindowUpdate, frame.TypeSettings, frame.TypePing:
				continue
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bodyPR, bodyPW := io.Pipe()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/grpc.Echo/BidiStream"},
		{Name: "content-type", Value: "application/grpc"},
	}

	resultCh := make(chan *StreamRoundTripResult, 1)
	errCh := make(chan error, 1)
	go func() {
		result, err := transport.RoundTripStream(ctx, clientConn, headers, bodyPR, StreamOptions{})
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- result
	}()

	bodyPW.Write([]byte("chunk1")) //nolint:errcheck
	bodyPW.Write([]byte("chunk2")) //nolint:errcheck
	bodyPW.Close()

	var result *StreamRoundTripResult
	select {
	case result = <-resultCh:
	case err := <-errCh:
		t.Fatalf("RoundTripStream: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for result")
	}

	if result.StatusCode != 200 {
		t.Errorf("status = %d, want 200", result.StatusCode)
	}

	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(body) != "chunk1chunk2" {
		t.Errorf("body = %q, want chunk1chunk2", body)
	}

	trailers, err := result.Trailers()
	if err != nil {
		t.Fatalf("Trailers: %v", err)
	}
	var grpcStatus string
	for _, hf := range trailers {
		if hf.Name == "grpc-status" {
			grpcStatus = hf.Value
		}
	}
	if grpcStatus != "0" {
		t.Errorf("grpc-status = %q, want 0", grpcStatus)
	}

	wg.Wait()
}

func TestRoundTripStream_GOAWAYMidStream(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &Transport{Logger: logger}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)

		// Read client HEADERS frame to get the stream ID.
		var streamID uint32
		for {
			f, err := server.reader.ReadFrame()
			if err != nil {
				t.Errorf("read frame: %v", err)
				return
			}
			if f.Header.Type == frame.TypeHeaders {
				streamID = f.Header.StreamID
				break
			}
		}

		// Send response HEADERS (without END_STREAM) to unblock the client.
		respHeaders := []hpack.HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-type", Value: "application/grpc"},
		}
		fragment := server.enc.Encode(respHeaders)
		if err := server.writer.WriteHeaders(streamID, false, true, fragment); err != nil {
			t.Errorf("write response HEADERS: %v", err)
			return
		}

		// Send some data so the client has partial body.
		if err := server.writer.WriteData(streamID, false, []byte("partial")); err != nil {
			t.Errorf("write DATA: %v", err)
			return
		}

		// Now send GOAWAY with lastStreamID=0 to reject the active stream.
		if err := server.writer.WriteGoAway(0, ErrCodeNo, nil); err != nil {
			t.Errorf("write GOAWAY: %v", err)
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/api/goaway"},
	}

	// Use a pipe body to keep the stream open for bidirectional streaming.
	bodyPR, bodyPW := io.Pipe()
	defer bodyPW.Close()

	result, err := transport.RoundTripStream(ctx, clientConn, headers, bodyPR, StreamOptions{})
	if err != nil {
		// GOAWAY before headers would cause an error here; that's acceptable.
		if !strings.Contains(err.Error(), "GOAWAY") && !strings.Contains(err.Error(), "connection error") {
			t.Fatalf("unexpected error: %v", err)
		}
		wg.Wait()
		return
	}
	defer result.Body.Close()

	// Read body — should get partial data then an error or EOF.
	_, readErr := io.ReadAll(result.Body)
	// The read may succeed (partial data) or return an error from GOAWAY.
	// Either outcome is acceptable; the key assertion is no panic.
	_ = readErr

	wg.Wait()
}

func TestRoundTripStream_RSTStreamMidStream(t *testing.T) {
	clientConn, serverConn := localConnPair(t)
	defer clientConn.Close()
	defer serverConn.Close()

	server := newPipeServer(serverConn)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	transport := &Transport{Logger: logger}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		server.handshake(t)

		// Read client HEADERS frame to get the stream ID.
		var streamID uint32
		for {
			f, err := server.reader.ReadFrame()
			if err != nil {
				t.Errorf("read frame: %v", err)
				return
			}
			if f.Header.Type == frame.TypeHeaders {
				streamID = f.Header.StreamID
				break
			}
		}

		// Send response HEADERS (without END_STREAM).
		respHeaders := []hpack.HeaderField{
			{Name: ":status", Value: "200"},
			{Name: "content-type", Value: "application/grpc"},
		}
		fragment := server.enc.Encode(respHeaders)
		if err := server.writer.WriteHeaders(streamID, false, true, fragment); err != nil {
			t.Errorf("write response HEADERS: %v", err)
			return
		}

		// Send some data.
		if err := server.writer.WriteData(streamID, false, []byte("before-rst")); err != nil {
			t.Errorf("write DATA: %v", err)
			return
		}

		// Send RST_STREAM to abruptly terminate the stream.
		if err := server.writer.WriteRSTStream(streamID, ErrCodeCancel); err != nil {
			t.Errorf("write RST_STREAM: %v", err)
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/api/rst"},
	}

	bodyPR, bodyPW := io.Pipe()
	defer bodyPW.Close()

	result, err := transport.RoundTripStream(ctx, clientConn, headers, bodyPR, StreamOptions{})
	if err != nil {
		// RST_STREAM may arrive before or after headers are processed.
		if !strings.Contains(err.Error(), "RST_STREAM") && !strings.Contains(err.Error(), "connection error") {
			t.Fatalf("unexpected error: %v", err)
		}
		wg.Wait()
		return
	}
	defer result.Body.Close()

	// Read body — should get an error from RST_STREAM.
	_, readErr := io.ReadAll(result.Body)
	if readErr == nil {
		// It's possible all data arrived before RST_STREAM was processed.
		// The key assertion is no panic or goroutine leak.
	} else if !strings.Contains(readErr.Error(), "RST_STREAM") && !strings.Contains(readErr.Error(), "connection error") {
		t.Errorf("unexpected read error: %v", readErr)
	}

	wg.Wait()
}
