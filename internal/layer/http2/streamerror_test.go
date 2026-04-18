package http2

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

func TestTranslateH2StreamError(t *testing.T) {
	cases := []struct {
		name string
		code uint32
		want layer.ErrorCode
	}{
		{"CANCEL", ErrCodeCancel, layer.ErrorCanceled},
		{"PROTOCOL", ErrCodeProtocol, layer.ErrorProtocol},
		{"REFUSED_STREAM", ErrCodeRefusedStream, layer.ErrorRefused},
		{"INTERNAL", ErrCodeInternal, layer.ErrorInternalError},
		{"FLOW_CONTROL", ErrCodeFlowControl, layer.ErrorAborted},
		{"COMPRESSION", ErrCodeCompression, layer.ErrorAborted},
		{"NO_ERROR", ErrCodeNo, layer.ErrorAborted},
		{"unknown", 0xff, layer.ErrorAborted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := translateH2StreamError(c.code); got != c.want {
				t.Errorf("translateH2StreamError(0x%x) = %s, want %s", c.code, got, c.want)
			}
		})
	}
}
