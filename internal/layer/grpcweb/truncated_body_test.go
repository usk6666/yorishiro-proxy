package grpcweb

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// TestRoundTrip_TruncatedBodyAnomalyReachesOppositeSide — USK-1229 review
// F-2: an HTTP/1.x response whose body the upstream cut short carries
// AnomalyTruncatedBody. Re-assembling it on the client side must keep the
// anomaly, so the client-facing HTTP/1.x Layer ends the connection
// instead of treating the exchange as answered completely.
func TestRoundTrip_TruncatedBodyAnomalyReachesOppositeSide(t *testing.T) {
	const ct = "application/grpc-web+proto"
	const detail = "connection closed after 12 of 100 Content-Length body bytes"
	resp := mustHTTPResponseEnv("s-trunc",
		[]envelope.KeyValue{{Name: "Content-Type", Value: ct}, {Name: "Content-Length", Value: "100"}},
		EncodeFrame(false, false, []byte("hello!!")), 200)
	resp.Message.(*envelope.HTTPMessage).Anomalies = []envelope.Anomaly{
		{Type: envelope.AnomalyTruncatedBody, Detail: detail},
	}

	up := Wrap(newMockChannel("s-trunc", resp), RoleClient)
	events := drainEnvelopes(t, up, 8)
	if len(events) == 0 {
		t.Fatal("upstream side emitted no events")
	}

	down := newMockChannel("s-trunc")
	hm := sendAll(t, Wrap(down, RoleServer), down, events...)
	var found bool
	for _, a := range hm.Anomalies {
		if a.Type == envelope.AnomalyTruncatedBody {
			found = true
			if a.Detail != detail {
				t.Errorf("TruncatedBody Detail = %q, want %q", a.Detail, detail)
			}
		}
	}
	if !found {
		t.Errorf("re-assembled response anomalies = %+v, want %s", hm.Anomalies, envelope.AnomalyTruncatedBody)
	}
}
