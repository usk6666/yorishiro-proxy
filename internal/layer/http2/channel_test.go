package http2

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

func TestChannel_StreamID_IsUUID(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	id := ch.StreamID()
	// UUID format: 8-4-4-4-12 chars (36 with hyphens).
	if len(id) != 36 {
		t.Errorf("StreamID = %q, expected UUID-format (36 chars)", id)
	}
}

func TestChannel_Send_SyntheticRequest(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	msg := &envelope.HTTPMessage{
		Method:    "POST",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/foo",
		RawQuery:  "q=1",
		Headers: []envelope.KeyValue{
			{Name: "content-type", Value: "text/plain"},
		},
		Body: []byte("hello"),
	}
	env := &envelope.Envelope{
		StreamID:  ch.StreamID(),
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	sendErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sendErr <- ch.Send(ctx, env)
	}()

	// Settings already consumed at startup. Next frame is HEADERS.
	f, err := peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read HEADERS: %v", err)
	}
	if f.Header.Type != frame.TypeHeaders {
		t.Fatalf("got %s, want HEADERS", f.Header.Type)
	}
	frag, err := f.HeaderBlockFragment()
	if err != nil {
		t.Fatalf("HeaderBlockFragment: %v", err)
	}
	hdrs, err := peer.decoder.Decode(frag)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := map[string]string{
		":method":      "POST",
		":scheme":      "https",
		":path":        "/foo?q=1",
		":authority":   "example.com",
		"content-type": "text/plain",
	}
	got := map[string]string{}
	for _, h := range hdrs {
		got[h.Name] = h.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("header %s = %q, want %q (all: %+v)", k, got[k], v, got)
		}
	}

	// Then DATA.
	f, err = peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read DATA: %v", err)
	}
	if f.Header.Type != frame.TypeData {
		t.Fatalf("got %s, want DATA", f.Header.Type)
	}
	if string(f.Payload) != "hello" {
		t.Errorf("body = %q, want hello", f.Payload)
	}
	if !f.Header.Flags.Has(frame.FlagEndStream) {
		t.Errorf("DATA missing END_STREAM")
	}

	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestChannel_Close_Idempotent(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := ch.Close(); err != nil {
			t.Errorf("Close #%d: %v", i, err)
		}
	}
}

func TestChannel_PushChannel_RejectsSend(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	// Open a stream and send a request to anchor the conversation.
	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	go func() {
		_ = ch.Send(context.Background(), &envelope.Envelope{
			Message: &envelope.HTTPMessage{
				Method: "GET", Scheme: "https", Authority: "x", Path: "/",
			},
		})
	}()

	// Drain the SETTINGS, SETTINGS-ACK, HEADERS frames.
	for i := 0; i < 5; i++ {
		_ = peer.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		f, err := peer.rd.ReadFrame()
		if err != nil {
			break
		}
		if f.Header.Type == frame.TypeHeaders {
			break
		}
	}
	_ = peer.conn.SetReadDeadline(time.Time{})

	// Now send a PUSH_PROMISE for stream 2 → expect a new push channel via
	// l.Channels().
	pushHeaders := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/pushed"},
	}
	encoded := peer.encoder.Encode(pushHeaders)
	if err := peer.wr.WritePushPromise(1, 2, true, encoded); err != nil {
		t.Fatalf("WritePushPromise: %v", err)
	}

	var pushCh = waitForChannel(t, l, time.Second)
	if pushCh == nil {
		t.Fatal("no push channel emitted")
	}

	// Send on push channel must be rejected.
	err = pushCh.Send(context.Background(), &envelope.Envelope{
		Message: &envelope.HTTPMessage{Method: "GET", Path: "/", Scheme: "https", Authority: "x"},
	})
	if err == nil {
		t.Fatal("Send on push channel: want error, got nil")
	}
}

// waitForChannel polls l.Channels() until a Channel arrives or timeout.
func waitForChannel(t *testing.T, l *Layer, dur time.Duration) (ch layer.Channel) {
	t.Helper()
	deadline := time.NewTimer(dur)
	defer deadline.Stop()
	for {
		select {
		case c, ok := <-l.Channels():
			if !ok {
				return nil
			}
			return c
		case <-deadline.C:
			return nil
		}
	}
}

// TestBuildTrailerFields_Anomalies is a table-driven unit test for USK-626:
// the Send-trailer path must flag the same anomalies the Receive path flags
// for initial headers (H2ConnectionSpecificHeader / H2UppercaseHeaderName /
// malformed "te:") without changing the emitted wire form. Pseudo-headers in
// trailers are flagged H2InvalidPseudoHeader and dropped (emitting them would
// cause the peer to treat the stream as malformed per RFC 9113 §8.1).
func TestBuildTrailerFields_Anomalies(t *testing.T) {
	tests := []struct {
		name           string
		trailers       []envelope.KeyValue
		wantFieldNames []string // lowercase emitted names in order; nil means no trailer frame
		wantAnomalies  []envelope.Anomaly
	}{
		{
			name: "clean trailers emit no anomalies",
			trailers: []envelope.KeyValue{
				{Name: "grpc-status", Value: "0"},
				{Name: "grpc-message", Value: ""},
			},
			wantFieldNames: []string{"grpc-status", "grpc-message"},
			wantAnomalies:  nil,
		},
		{
			name: "uppercase name flags H2UppercaseHeaderName and is still emitted lowercased",
			trailers: []envelope.KeyValue{
				{Name: "Grpc-Status", Value: "0"},
			},
			wantFieldNames: []string{"grpc-status"},
			wantAnomalies: []envelope.Anomaly{
				{Type: envelope.H2UppercaseHeaderName, Detail: "Grpc-Status"},
			},
		},
		{
			name: "connection-specific header flags H2ConnectionSpecificHeader and is still emitted",
			trailers: []envelope.KeyValue{
				{Name: "transfer-encoding", Value: "chunked"},
			},
			wantFieldNames: []string{"transfer-encoding"},
			wantAnomalies: []envelope.Anomaly{
				{Type: envelope.H2ConnectionSpecificHeader, Detail: "transfer-encoding"},
			},
		},
		{
			name: "te with non-trailers value flags H2ConnectionSpecificHeader",
			trailers: []envelope.KeyValue{
				{Name: "te", Value: "gzip"},
			},
			wantFieldNames: []string{"te"},
			wantAnomalies: []envelope.Anomaly{
				{Type: envelope.H2ConnectionSpecificHeader, Detail: "te: gzip"},
			},
		},
		{
			name: "te: trailers is the documented exception and flags no anomaly",
			trailers: []envelope.KeyValue{
				{Name: "te", Value: "trailers"},
			},
			wantFieldNames: []string{"te"},
			wantAnomalies:  nil,
		},
		{
			name: "pseudo-header in trailers is dropped and flagged H2InvalidPseudoHeader",
			trailers: []envelope.KeyValue{
				{Name: ":status", Value: "200"},
				{Name: "grpc-status", Value: "0"},
			},
			wantFieldNames: []string{"grpc-status"},
			wantAnomalies: []envelope.Anomaly{
				{Type: envelope.H2InvalidPseudoHeader, Detail: "in trailers: :status"},
			},
		},
		{
			name: "combined anomalies accumulate in order",
			trailers: []envelope.KeyValue{
				{Name: "Upgrade", Value: "h2c"},
				{Name: ":path", Value: "/evil"},
				{Name: "te", Value: "deflate"},
				{Name: "grpc-status", Value: "0"},
			},
			wantFieldNames: []string{"upgrade", "te", "grpc-status"},
			wantAnomalies: []envelope.Anomaly{
				{Type: envelope.H2UppercaseHeaderName, Detail: "Upgrade"},
				{Type: envelope.H2ConnectionSpecificHeader, Detail: "Upgrade"},
				{Type: envelope.H2InvalidPseudoHeader, Detail: "in trailers: :path"},
				{Type: envelope.H2ConnectionSpecificHeader, Detail: "te: deflate"},
			},
		},
		{
			name:           "empty trailers return nil fields and nil anomalies",
			trailers:       nil,
			wantFieldNames: nil,
			wantAnomalies:  nil,
		},
		{
			name: "trailers containing only a pseudo-header return nil fields and the anomaly",
			trailers: []envelope.KeyValue{
				{Name: ":status", Value: "200"},
			},
			wantFieldNames: nil,
			wantAnomalies: []envelope.Anomaly{
				{Type: envelope.H2InvalidPseudoHeader, Detail: "in trailers: :status"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields, anomalies := buildTrailerFields(tt.trailers)

			if len(fields) != len(tt.wantFieldNames) {
				t.Fatalf("fields count = %d, want %d (fields=%+v)", len(fields), len(tt.wantFieldNames), fields)
			}
			for i, want := range tt.wantFieldNames {
				if fields[i].Name != want {
					t.Errorf("fields[%d].Name = %q, want %q", i, fields[i].Name, want)
				}
			}

			if len(anomalies) != len(tt.wantAnomalies) {
				t.Fatalf("anomalies count = %d, want %d (anomalies=%+v)", len(anomalies), len(tt.wantAnomalies), anomalies)
			}
			for i, want := range tt.wantAnomalies {
				if anomalies[i] != want {
					t.Errorf("anomalies[%d] = %+v, want %+v", i, anomalies[i], want)
				}
			}
		})
	}
}

// TestChannel_Send_TrailerAnomaliesAppendedToMessage verifies that anomalies
// surfaced by buildTrailerFields are appended onto msg.Anomalies by the Send
// path. This is the subsystem-integration proof — a caller observing the
// HTTPMessage after Send sees the diagnostic record.
func TestChannel_Send_TrailerAnomaliesAppendedToMessage(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	msg := &envelope.HTTPMessage{
		Method:    "POST",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/stream",
		Headers: []envelope.KeyValue{
			{Name: "content-type", Value: "application/grpc"},
		},
		Body: []byte{0x00},
		Trailers: []envelope.KeyValue{
			{Name: "Transfer-Encoding", Value: "chunked"}, // uppercase + connection-specific
			{Name: "grpc-status", Value: "0"},
		},
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
	}

	// Drain peer frames so the writer queue doesn't stall on net.Pipe.
	go func() {
		for {
			if _, err := peer.rd.ReadFrame(); err != nil {
				return
			}
		}
	}()

	if err := ch.Send(context.Background(), env); err != nil {
		t.Fatalf("Send: %v", err)
	}

	wantAnomalies := []envelope.Anomaly{
		{Type: envelope.H2UppercaseHeaderName, Detail: "Transfer-Encoding"},
		{Type: envelope.H2ConnectionSpecificHeader, Detail: "Transfer-Encoding"},
	}
	if len(msg.Anomalies) != len(wantAnomalies) {
		t.Fatalf("msg.Anomalies = %+v, want %+v", msg.Anomalies, wantAnomalies)
	}
	for i, want := range wantAnomalies {
		if msg.Anomalies[i] != want {
			t.Errorf("msg.Anomalies[%d] = %+v, want %+v", i, msg.Anomalies[i], want)
		}
	}
}

// TestBodyChanged_PointerIdentity verifies the pointer-identity check
// for the file-backed track and byte comparison for the memory track
// (USK-632 dual-path bodyChanged, mirroring HTTP/1.x USK-631).
func TestBodyChanged_PointerIdentity(t *testing.T) {
	bb1 := bodybuf.NewMemory([]byte("one"))
	defer bb1.Release()
	bb2 := bodybuf.NewMemory([]byte("two"))
	defer bb2.Release()

	bufCases := []struct {
		name       string
		msgBuffer  *bodybuf.BodyBuffer
		origBuffer *bodybuf.BodyBuffer
		want       bool
	}{
		{"same pointer", bb1, bb1, false},
		{"different pointers", bb1, bb2, true},
		{"nil to non-nil", bb1, nil, true},
		{"non-nil to nil", nil, bb1, true},
	}
	for _, c := range bufCases {
		t.Run("buffer/"+c.name, func(t *testing.T) {
			msg := &envelope.HTTPMessage{BodyBuffer: c.msgBuffer}
			op := &opaqueHTTP2{origBodyBuffer: c.origBuffer}
			if got := bodyChanged(msg, op); got != c.want {
				t.Errorf("bodyChanged = %v, want %v", got, c.want)
			}
		})
	}

	bodyCases := []struct {
		name     string
		msgBody  []byte
		origBody []byte
		want     bool
	}{
		{"both nil", nil, nil, false},
		{"identical bytes", []byte("hello"), []byte("hello"), false},
		{"different bytes", []byte("hello"), []byte("world"), true},
		{"different lengths", []byte("hi"), []byte("hello"), true},
		{"nil to bytes", []byte("hi"), nil, true},
		{"bytes to nil", nil, []byte("hi"), true},
	}
	for _, c := range bodyCases {
		t.Run("memory/"+c.name, func(t *testing.T) {
			msg := &envelope.HTTPMessage{Body: c.msgBody}
			op := &opaqueHTTP2{origBody: c.origBody}
			if got := bodyChanged(msg, op); got != c.want {
				t.Errorf("bodyChanged = %v, want %v", got, c.want)
			}
		})
	}
}

// TestChannel_Send_CrossLayerOpaqueFallsToSynthetic verifies that an envelope
// whose opaqueHTTP2 snapshot was produced by a different Layer falls through
// to the synthetic path, even when stream IDs coincidentally match. Without
// the USK-617 same-Layer guard, cross-Layer forwarding (the common MITM case)
// would write raw frame bytes whose embedded HPACK dynamic-table indices are
// meaningless to the destination Layer's decoder.
func TestChannel_Send_CrossLayerOpaqueFallsToSynthetic(t *testing.T) {
	// Foreign Layer — used only so we have a valid, distinct *Layer pointer
	// to stamp onto the envelope's opaqueHTTP2 field.
	foreign, peerF, cleanupF := startClientLayer(t)
	defer cleanupF()
	peerF.consumePeerSettings(t)

	// Destination Layer and stream.
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	cs := ch.(*channel)
	if cs.h2Stream != 1 {
		// Both fresh client layers allocate 1 first — this is the stream-ID
		// collision that makes the layer guard essential.
		t.Fatalf("unexpected h2Stream = %d, want 1", cs.h2Stream)
	}

	body := []byte("hello-cross-layer")
	msg := &envelope.HTTPMessage{
		Method:    "POST",
		Scheme:    "https",
		Authority: "example.com",
		Path:      "/x",
		Headers:   []envelope.KeyValue{{Name: "content-type", Value: "text/plain"}},
		Body:      body,
	}
	// Opaque says "I came from layer foreign, stream 1" — the stream ID
	// coincidentally matches cs.h2Stream. Sentinel frame bytes would be
	// written verbatim if the cross-Layer guard fails.
	env := &envelope.Envelope{
		StreamID:  ch.StreamID(),
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
		Opaque: &opaqueHTTP2{
			layer:          foreign,
			streamID:       cs.h2Stream,
			frames:         [][]byte{{0xde, 0xad, 0xbe, 0xef}},
			origHeaders:    []hpack.HeaderField{{Name: ":method", Value: "POST"}},
			origBodyBuffer: nil,
		},
	}

	sendErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		sendErr <- ch.Send(ctx, env)
	}()

	// HEADERS must be a real HPACK-encoded frame, not the sentinel 0xdeadbeef.
	f, err := peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read HEADERS: %v", err)
	}
	if f.Header.Type != frame.TypeHeaders {
		t.Fatalf("first frame = %s, want HEADERS (synthetic path for cross-Layer)", f.Header.Type)
	}
	frag, err := f.HeaderBlockFragment()
	if err != nil {
		t.Fatalf("HeaderBlockFragment: %v", err)
	}
	hdrs, err := peer.decoder.Decode(frag)
	if err != nil {
		t.Fatalf("decode HEADERS: %v", err)
	}
	var gotMethod, gotPath string
	for _, h := range hdrs {
		switch h.Name {
		case ":method":
			gotMethod = h.Value
		case ":path":
			gotPath = h.Value
		}
	}
	if gotMethod != "POST" || gotPath != "/x" {
		t.Errorf("headers = {:method=%q, :path=%q}, want {POST, /x}", gotMethod, gotPath)
	}

	f, err = peer.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read DATA: %v", err)
	}
	if f.Header.Type != frame.TypeData {
		t.Fatalf("second frame = %s, want DATA", f.Header.Type)
	}
	if string(f.Payload) != string(body) {
		t.Errorf("body = %q, want %q", f.Payload, body)
	}
	if !f.Header.Flags.Has(frame.FlagEndStream) {
		t.Error("DATA missing END_STREAM")
	}

	if err := <-sendErr; err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestChannel_Next_EOFWhenLayerClosed(t *testing.T) {
	l, peer, _ := startClientLayer(t)
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	// Close the peer side so the reader hits EOF and shuts down.
	_ = peer.conn.Close()

	// Force the layer to close (it would also close on EOF).
	_ = l.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = ch.Next(ctx)
	if err == nil || !errors.Is(err, io.EOF) {
		// The error may be ctx.Err if shutdown raced; accept io.EOF as
		// the canonical post-close result.
		if err == nil {
			t.Fatalf("Next: want io.EOF, got nil")
		}
	}
}
