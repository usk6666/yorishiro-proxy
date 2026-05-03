package httputil

import (
	"encoding/json"

	codecparser "github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/fingerprint"
	layerparser "github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// MergeTechnologyTags runs the fingerprint detector (if non-nil) on the
// response headers and body, and merges the detection results into the given
// base tags map. The result is stored as a JSON array under the key
// "technologies". If the detector is nil or detects nothing, the original
// tags are returned unchanged.
//
// The legacy internal/codec/http1/parser.RawHeaders shape is converted to
// the layer parser shape for fingerprint.Detector.Analyze. The two structs
// are field-identical; this caller dies with internal/protocol/ at USK-697.
func MergeTechnologyTags(baseTags map[string]string, det *fingerprint.Detector, headers codecparser.RawHeaders, body []byte) map[string]string {
	if det == nil {
		return baseTags
	}
	layerHeaders := make(layerparser.RawHeaders, len(headers))
	for i, h := range headers {
		layerHeaders[i] = layerparser.RawHeader{Name: h.Name, Value: h.Value, RawValue: h.RawValue}
	}
	result := det.Analyze(layerHeaders, body)
	if len(result.Detections) == 0 {
		return baseTags
	}
	data, err := json.Marshal(result.Detections)
	if err != nil {
		return baseTags
	}
	tags := make(map[string]string)
	for k, v := range baseTags {
		tags[k] = v
	}
	tags["technologies"] = string(data)
	return tags
}
