package job

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestGRPCResendSource_NextEmitsStartDataEndThenEOF(t *testing.T) {
	t.Parallel()

	start := &envelope.GRPCStartMessage{
		Service:     "pkg.svc",
		Method:      "Echo",
		ContentType: "application/grpc+proto",
		Metadata:    []envelope.KeyValue{{Name: "x-trace", Value: "abc"}},
	}
	dataA := []byte("hello")
	dataB := []byte("world")
	end := &envelope.GRPCEndMessage{Status: 0, Message: ""}

	src := NewGRPCResendSource("stream-1", "conn-1", GRPCResendSpec{
		Start: start,
		Data: []GRPCResendDataPart{
			{Payload: dataA},
			{Payload: dataB},
		},
		End: end,
	})

	ctx := context.Background()

	envStart, err := src.Next(ctx)
	if err != nil {
		t.Fatalf("first Next: %v", err)
	}
	if envStart.Sequence != 0 || envStart.Direction != envelope.Send {
		t.Errorf("Start envelope: seq=%d dir=%v want seq=0 dir=Send", envStart.Sequence, envStart.Direction)
	}
	if envStart.Protocol != envelope.ProtocolGRPC {
		t.Errorf("Start.Protocol = %v, want ProtocolGRPC", envStart.Protocol)
	}
	startMsg, ok := envStart.Message.(*envelope.GRPCStartMessage)
	if !ok {
		t.Fatalf("Start.Message = %T, want *GRPCStartMessage", envStart.Message)
	}
	if startMsg.Service != "pkg.svc" || startMsg.Method != "Echo" {
		t.Errorf("Service/Method = %q/%q, want pkg.svc/Echo", startMsg.Service, startMsg.Method)
	}
	if envStart.StreamID != "stream-1" || envStart.Context.ConnID != "conn-1" {
		t.Errorf("StreamID/ConnID = %q/%q", envStart.StreamID, envStart.Context.ConnID)
	}
	if envStart.FlowID == "" {
		t.Error("Start.FlowID empty")
	}

	for i, want := range [][]byte{dataA, dataB} {
		envData, err := src.Next(ctx)
		if err != nil {
			t.Fatalf("data %d Next: %v", i, err)
		}
		if envData.Sequence != i+1 {
			t.Errorf("data %d Sequence = %d, want %d", i, envData.Sequence, i+1)
		}
		dataMsg, ok := envData.Message.(*envelope.GRPCDataMessage)
		if !ok {
			t.Fatalf("data %d Message = %T, want *GRPCDataMessage", i, envData.Message)
		}
		if dataMsg.Service != "pkg.svc" || dataMsg.Method != "Echo" {
			t.Errorf("data %d Service/Method = %q/%q, want denormalized from Start", i, dataMsg.Service, dataMsg.Method)
		}
		if string(dataMsg.Payload) != string(want) {
			t.Errorf("data %d Payload = %q, want %q", i, dataMsg.Payload, want)
		}
		if dataMsg.WireLength != uint32(len(want)) {
			t.Errorf("data %d WireLength = %d, want %d", i, dataMsg.WireLength, len(want))
		}
	}

	envEnd, err := src.Next(ctx)
	if err != nil {
		t.Fatalf("end Next: %v", err)
	}
	if envEnd.Sequence != 3 {
		t.Errorf("End.Sequence = %d, want 3", envEnd.Sequence)
	}
	if _, ok := envEnd.Message.(*envelope.GRPCEndMessage); !ok {
		t.Fatalf("End.Message = %T, want *GRPCEndMessage", envEnd.Message)
	}

	if _, err := src.Next(ctx); !errors.Is(err, io.EOF) {
		t.Errorf("after exhaustion: err = %v, want io.EOF", err)
	}
}

func TestGRPCResendSource_EndStreamFlagOnLastDataNoEnd(t *testing.T) {
	t.Parallel()

	src := NewGRPCResendSource("s-2", "c-2", GRPCResendSpec{
		Start: &envelope.GRPCStartMessage{Service: "S", Method: "M"},
		Data: []GRPCResendDataPart{
			{Payload: []byte("only"), EndStream: true},
		},
	})

	if _, err := src.Next(context.Background()); err != nil {
		t.Fatalf("start Next: %v", err)
	}
	envData, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("data Next: %v", err)
	}
	dataMsg := envData.Message.(*envelope.GRPCDataMessage)
	if !dataMsg.EndStream {
		t.Error("EndStream = false on last Data, want true (no end envelope)")
	}

	if _, err := src.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Errorf("after Data exhaustion: err = %v, want io.EOF", err)
	}
}

func TestGRPCResendSource_RawBytesSeedsEnvelopeRaw(t *testing.T) {
	t.Parallel()

	rawData := []byte{0x00, 0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'} // LPM(0, 5) + "hello"
	src := NewGRPCResendSource("s-3", "c-3", GRPCResendSpec{
		Start: &envelope.GRPCStartMessage{Service: "S", Method: "M"},
		Data: []GRPCResendDataPart{
			{Payload: []byte("hello"), Raw: rawData, EndStream: true},
		},
	})

	if _, err := src.Next(context.Background()); err != nil {
		t.Fatalf("start Next: %v", err)
	}
	envData, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("data Next: %v", err)
	}
	if string(envData.Raw) != string(rawData) {
		t.Errorf("Data.Raw = %x, want %x", envData.Raw, rawData)
	}
}

func TestGRPCResendSource_CompressedAndWireLengthOverride(t *testing.T) {
	t.Parallel()

	src := NewGRPCResendSource("s-4", "c-4", GRPCResendSpec{
		Start: &envelope.GRPCStartMessage{Service: "S", Method: "M", Encoding: "gzip"},
		Data: []GRPCResendDataPart{
			{Payload: []byte("decompressed"), Compressed: true, WireLength: 7, EndStream: true},
		},
	})

	if _, err := src.Next(context.Background()); err != nil {
		t.Fatalf("start Next: %v", err)
	}
	envData, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("data Next: %v", err)
	}
	dataMsg := envData.Message.(*envelope.GRPCDataMessage)
	if !dataMsg.Compressed {
		t.Error("Compressed = false, want true")
	}
	if dataMsg.WireLength != 7 {
		t.Errorf("WireLength = %d, want 7 (override)", dataMsg.WireLength)
	}
}
