package http2

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// sendRequestAsEvents decomposes a POST-with-body request into event
// envelopes and sends them on ch sequentially: HEADERS(no END_STREAM),
// DATA(END_STREAM=true with the full body). Returns the first error.
func sendRequestAsEvents(ctx context.Context, ch layer.Channel, body []byte) error {
	hdr := &H2HeadersEvent{
		Method: "POST", Scheme: "https", Authority: "x", Path: "/",
	}
	if err := ch.Send(ctx, &envelope.Envelope{Direction: envelope.Send, Message: hdr}); err != nil {
		return err
	}
	data := &H2DataEvent{Payload: body, EndStream: true}
	return ch.Send(ctx, &envelope.Envelope{Direction: envelope.Send, Message: data})
}

func TestWriter_HeadersAndDataInOrder(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	body := []byte("ABCDEFGH")
	go func() {
		_ = sendRequestAsEvents(context.Background(), ch, body)
	}()

	gotHeaders := false
	gotData := false
	deadline := time.Now().Add(2 * time.Second)
	for !gotData && time.Now().Before(deadline) {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		switch f.Header.Type {
		case frame.TypeHeaders:
			if gotData {
				t.Fatal("HEADERS arrived after DATA")
			}
			gotHeaders = true
		case frame.TypeData:
			if !gotHeaders {
				t.Fatal("DATA arrived before HEADERS")
			}
			if string(f.Payload) != string(body) {
				t.Errorf("body = %q, want %q", f.Payload, body)
			}
			if !f.Header.Flags.Has(frame.FlagEndStream) {
				t.Error("DATA missing END_STREAM")
			}
			gotData = true
		}
	}
	if !gotData {
		t.Fatal("did not observe DATA frame")
	}
}

func TestWriter_DataSplitByMaxFrameSize(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	ch, err := l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	body := make([]byte, 40000)
	for i := range body {
		body[i] = 'x'
	}
	go func() {
		_ = sendRequestAsEvents(context.Background(), ch, body)
	}()

	dataFrames := 0
	endStreamSeen := false
	totalBytes := 0
	deadline := time.Now().Add(3 * time.Second)
	for !endStreamSeen && time.Now().Before(deadline) {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if f.Header.Type == frame.TypeData {
			dataFrames++
			totalBytes += len(f.Payload)
			if uint32(len(f.Payload)) > frame.DefaultMaxFrameSize {
				t.Errorf("DATA payload %d > MAX_FRAME_SIZE %d", len(f.Payload), frame.DefaultMaxFrameSize)
			}
			if f.Header.Flags.Has(frame.FlagEndStream) {
				endStreamSeen = true
			}
		}
	}
	if dataFrames < 2 {
		t.Errorf("dataFrames = %d, want >= 2", dataFrames)
	}
	if totalBytes != len(body) {
		t.Errorf("totalBytes = %d, want %d", totalBytes, len(body))
	}
}

func TestWriter_FlowControlBlocksAndUnblocks(t *testing.T) {
	cliConn, srvConn := net.Pipe()
	peer := newH2Peer(srvConn)

	type layerResult struct {
		l   *Layer
		err error
	}
	done := make(chan layerResult, 1)
	go func() {
		l, err := New(cliConn, "fc-test", ClientRole)
		done <- layerResult{l: l, err: err}
	}()

	pf := make([]byte, 24)
	if _, err := io.ReadFull(peer.conn, pf); err != nil {
		t.Fatalf("read preface: %v", err)
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("New: %v", res.err)
	}
	defer func() {
		_ = res.l.Close()
		_ = peer.conn.Close()
	}()

	// Tiny INITIAL_WINDOW_SIZE: new streams are tightly windowed.
	if err := peer.wr.WriteSettings([]frame.Setting{
		{ID: frame.SettingInitialWindowSize, Value: 32},
	}); err != nil {
		t.Fatalf("write SETTINGS: %v", err)
	}

	drained := make(chan struct{})
	var dataFrames []*frame.Frame
	var dfMu sync.Mutex
	go func() {
		defer close(drained)
		for {
			f, err := peer.rd.ReadFrame()
			if err != nil {
				return
			}
			if f.Header.Type == frame.TypeData {
				dfMu.Lock()
				dataFrames = append(dataFrames, f)
				dfMu.Unlock()
			}
		}
	}()

	ch, err := res.l.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if res.l.conn.PeerSettings().InitialWindowSize == 32 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	body := make([]byte, 200)
	sendDone := make(chan error, 1)
	go func() {
		sendDone <- sendRequestAsEvents(context.Background(), ch, body)
	}()

	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-sendDone:
		t.Fatalf("Send completed prematurely: %v (window not enforced)", err)
	default:
	}

	chStruct := ch.(*channel)
	if err := peer.wr.WriteWindowUpdate(0, 1<<20); err != nil {
		t.Fatalf("WriteWindowUpdate conn: %v", err)
	}
	if err := peer.wr.WriteWindowUpdate(chStruct.h2Stream, 1<<20); err != nil {
		t.Fatalf("WriteWindowUpdate stream: %v", err)
	}

	select {
	case err := <-sendDone:
		if err != nil {
			t.Fatalf("Send: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Send did not complete after WINDOW_UPDATE")
	}
}

func TestWriter_ConcurrentSendsDoNotInterleaveFrames(t *testing.T) {
	l, peer, cleanup := startClientLayer(t)
	defer cleanup()
	peer.consumePeerSettings(t)

	const numStreams = 4
	chs := make([]*channel, numStreams)
	for i := 0; i < numStreams; i++ {
		c, err := l.OpenStream(context.Background())
		if err != nil {
			t.Fatalf("OpenStream %d: %v", i, err)
		}
		chs[i] = c.(*channel)
	}

	var wg sync.WaitGroup
	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := make([]byte, 1024)
			for k := range body {
				body[k] = byte('a' + i)
			}
			_ = sendRequestAsEvents(context.Background(), chs[i], body)
		}(i)
	}

	per := map[uint32]int{}
	deadline := time.Now().Add(3 * time.Second)
	completed := 0
	for completed < numStreams && time.Now().Before(deadline) {
		f, err := peer.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if f.Header.StreamID == 0 {
			continue
		}
		switch f.Header.Type {
		case frame.TypeHeaders:
			if per[f.Header.StreamID] != 0 {
				t.Errorf("stream %d: HEADERS out of order (state=%d)", f.Header.StreamID, per[f.Header.StreamID])
			}
			per[f.Header.StreamID] = 1
		case frame.TypeData:
			if per[f.Header.StreamID] != 1 {
				t.Errorf("stream %d: DATA before HEADERS (state=%d)", f.Header.StreamID, per[f.Header.StreamID])
			}
			if f.Header.Flags.Has(frame.FlagEndStream) {
				per[f.Header.StreamID] = 2
				completed++
			}
		}
	}
	wg.Wait()
	if completed != numStreams {
		t.Errorf("completed=%d, want %d", completed, numStreams)
	}
}
