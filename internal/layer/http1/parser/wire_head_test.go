package parser

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// USK-1320: the header section is captured twice in meaning but once in
// memory — WireHead is the complete head as read (the send source) and
// RawBytes is the record copy capped at ParseOptions.MaxRawCapture.
// Invariants: RawBytes is a prefix of WireHead, len(RawBytes) <= cap, and
// Truncated == len(WireHead) > len(RawBytes). A capped record carries the
// RawHeaderTruncated anomaly so the truncation is discoverable.

// headParseResult is the subset of RawRequest / RawResponse these tests
// assert on.
type headParseResult struct {
	rawBytes  []byte
	wireHead  []byte
	truncated bool
	anomalies []Anomaly
	body      []byte
}

func parseHeadRequest(t *testing.T, wire string, capN int64) headParseResult {
	t.Helper()
	req, err := ParseRequestWithOptions(newReader(wire), ParseOptions{MaxRawCapture: capN})
	if err != nil {
		t.Fatalf("ParseRequestWithOptions: %v", err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return headParseResult{req.RawBytes, req.WireHead, req.Truncated, req.Anomalies, body}
}

func parseHeadResponse(t *testing.T, wire string, capN int64) headParseResult {
	t.Helper()
	resp, err := ParseResponseWithOptions(newReader(wire), ParseOptions{MaxRawCapture: capN})
	if err != nil {
		t.Fatalf("ParseResponseWithOptions: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return headParseResult{resp.RawBytes, resp.WireHead, resp.Truncated, resp.Anomalies, body}
}

func countAnomaly(as []Anomaly, typ AnomalyType) int {
	n := 0
	for _, a := range as {
		if a.Type == typ {
			n++
		}
	}
	return n
}

func TestParseWithOptions_WireHeadUncappedRawBytesCapped(t *testing.T) {
	longHdr := "X-Long: " + strings.Repeat("a", 200) + "\r\n"
	cases := []struct {
		name    string
		resp    bool
		head    string
		body    string
		capN    int64
		wantCap bool
	}{
		{name: "request long header over cap", head: "POST /p HTTP/1.1\r\nHost: x\r\n" + longHdr + "Content-Length: 3\r\n\r\n", body: "abc", capN: 64, wantCap: true},
		{name: "request long target over cap", head: "GET /" + strings.Repeat("b", 200) + " HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n", body: "abc", capN: 64, wantCap: true},
		{name: "request under cap", head: "POST /p HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n", body: "abc", capN: 1024},
		{name: "request exactly at cap", head: "GET / HTTP/1.1\r\nHost: x\r\n\r\n", capN: int64(len("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))},
		{name: "response long header over cap", resp: true, head: "HTTP/1.1 200 OK\r\n" + longHdr + "Content-Length: 2\r\n\r\n", body: "ok", capN: 64, wantCap: true},
		{name: "response long reason over cap", resp: true, head: "HTTP/1.1 200 " + strings.Repeat("R", 200) + "\r\nContent-Length: 2\r\n\r\n", body: "ok", capN: 64, wantCap: true},
		{name: "response under cap", resp: true, head: "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", body: "ok", capN: 1024},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got headParseResult
			if tc.resp {
				got = parseHeadResponse(t, tc.head+tc.body, tc.capN)
			} else {
				got = parseHeadRequest(t, tc.head+tc.body, tc.capN)
			}
			if string(got.wireHead) != tc.head {
				t.Errorf("WireHead = %q (len %d), want the complete head (len %d)", got.wireHead, len(got.wireHead), len(tc.head))
			}
			if string(got.body) != tc.body {
				t.Errorf("body = %q, want %q", got.body, tc.body)
			}
			if !bytes.HasPrefix([]byte(tc.head), got.rawBytes) {
				t.Errorf("RawBytes %q is not a prefix of the wire head", got.rawBytes)
			}
			if int64(len(got.rawBytes)) > tc.capN {
				t.Errorf("len(RawBytes) = %d, exceeds cap %d", len(got.rawBytes), tc.capN)
			}
			if got.truncated != tc.wantCap {
				t.Errorf("Truncated = %v, want %v", got.truncated, tc.wantCap)
			}
			if got.truncated != (len(got.wireHead) > len(got.rawBytes)) {
				t.Errorf("Truncated = %v but len(WireHead)=%d len(RawBytes)=%d", got.truncated, len(got.wireHead), len(got.rawBytes))
			}
			wantAnoms := 0
			if tc.wantCap {
				wantAnoms = 1
				if int64(len(got.rawBytes)) != tc.capN {
					t.Errorf("len(RawBytes) = %d, want exactly the cap %d", len(got.rawBytes), tc.capN)
				}
			} else if !bytes.Equal(got.rawBytes, got.wireHead) {
				t.Errorf("under cap: RawBytes %q != WireHead %q", got.rawBytes, got.wireHead)
			}
			if n := countAnomaly(got.anomalies, AnomalyRawHeaderTruncated); n != wantAnoms {
				t.Errorf("RawHeaderTruncated anomalies = %d, want %d (all: %+v)", n, wantAnoms, got.anomalies)
			}
		})
	}
}

// TestParseRequest_DefaultCap_WireHeadKeepsThreeMiBHead: with the package
// default cap a 3 MiB Cookie head is kept whole in WireHead while RawBytes
// stays at MaxRawCaptureSize.
func TestParseRequest_DefaultCap_WireHeadKeepsThreeMiBHead(t *testing.T) {
	head := "GET / HTTP/1.1\r\nHost: x\r\nCookie: " + strings.Repeat("c", 3<<20) + "\r\n\r\n"
	got := parseHeadRequest(t, head, 0)
	if len(got.wireHead) != len(head) || string(got.wireHead) != head {
		t.Errorf("len(WireHead) = %d, want %d", len(got.wireHead), len(head))
	}
	if len(got.rawBytes) != MaxRawCaptureSize || !got.truncated {
		t.Errorf("len(RawBytes) = %d Truncated = %v, want %d / true", len(got.rawBytes), got.truncated, MaxRawCaptureSize)
	}
	if countAnomaly(got.anomalies, AnomalyRawHeaderTruncated) != 1 {
		t.Errorf("anomalies = %+v, want one RawHeaderTruncated", got.anomalies)
	}
}

// TestParseRequest_PartialRequestErrorRawStaysCapped: an over-limit head
// still fails with the capped Raw view (unchanged by USK-1320).
func TestParseRequest_PartialRequestErrorRawStaysCapped(t *testing.T) {
	const capN = 64
	wire := "GET / HTTP/1.1\r\nHost: x\r\nX-Big: " + strings.Repeat("a", maxHeaderSize+10) + "\r\n\r\n"
	_, err := ParseRequestWithOptions(newReader(wire), ParseOptions{MaxRawCapture: capN})
	var perr *PartialRequestError
	if !errors.As(err, &perr) {
		t.Fatalf("err = %v, want *PartialRequestError", err)
	}
	if !errors.Is(err, ErrHeaderSectionTooLarge) {
		t.Errorf("err = %v, want ErrHeaderSectionTooLarge", err)
	}
	if len(perr.Raw) != capN || !perr.Truncated {
		t.Errorf("len(Raw) = %d Truncated = %v, want %d / true", len(perr.Raw), perr.Truncated, capN)
	}
	if string(perr.Raw) != wire[:capN] {
		t.Errorf("Raw = %q, want wire prefix %q", perr.Raw, wire[:capN])
	}
}
