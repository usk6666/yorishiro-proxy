package httputil

import (
	"encoding/json"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/fingerprint"
)

// MergeTechnologyTags runs the fingerprint detector (if non-nil) on the
// response headers and body, and merges the detection results into the given
// base tags map. The result is stored as a JSON array under the key
// "technologies". If the detector is nil or detects nothing, the original
// tags are returned unchanged.
func MergeTechnologyTags(baseTags map[string]string, det *fingerprint.Detector, headers parser.RawHeaders, body []byte) map[string]string {
	if det == nil {
		return baseTags
	}
	result := det.Analyze(headers, body)
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
