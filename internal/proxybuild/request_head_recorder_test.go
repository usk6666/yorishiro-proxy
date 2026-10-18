package proxybuild

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// headRecStore captures Streams and Flows written by the USK-1181
// request-head recorder.
type headRecStore struct {
	mu      sync.Mutex
	streams []*flow.Stream
	flows   []*flow.Flow
}

func (s *headRecStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *st
	s.streams = append(s.streams, &cp)
	return nil
}

func (s *headRecStore) UpdateStream(context.Context, string, flow.StreamUpdate) error { return nil }

func (s *headRecStore) SaveFlow(_ context.Context, f *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *f
	s.flows = append(s.flows, &cp)
	return nil
}

func (s *headRecStore) snapshot() ([]*flow.Stream, []*flow.Flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*flow.Stream(nil), s.streams...), append([]*flow.Flow(nil), s.flows...)
}

func timeoutHead() *http1.RequestHeadError {
	raw := "GET /x?y=1 HTTP/1.1\r\nHost: example.test\r\nX-Pa"
	return &http1.RequestHeadError{
		Reason:        http1.RequestHeadTimeout,
		Phase:         http1.RequestHeadPhaseHeaders,
		Scheme:        "https",
		Raw:           []byte(raw),
		Method:        "GET",
		RequestTarget: "/x?y=1",
		Proto:         "HTTP/1.1",
		Path:          "/x",
		RawQuery:      "y=1",
		Authority:     "example.test",
		Headers:       parser.RawHeaders{{Name: "Host", Value: "example.test"}},
		Timeout:       300 * time.Millisecond,
		Started:       time.Now().Add(-300 * time.Millisecond),
		Err:           errors.Join(errors.New("http1: parse request"), os.ErrDeadlineExceeded),
	}
}

func TestRequestHeadRecorder_NilStore(t *testing.T) {
	if rec := buildRequestHeadRecorder(nil, nil, "l", silentLogger()); rec != nil {
		t.Fatal("expected nil recorder for nil store")
	}
}

func TestRequestHeadRecorder_Timeout(t *testing.T) {
	store := &headRecStore{}
	rec := buildRequestHeadRecorder(store, nil, "live", silentLogger())
	head := timeoutHead()
	rec(context.Background(), requestHeadFailure{
		ConnID: "conn-1", ClientAddr: "127.0.0.1:5555", Target: "example.test:443", Head: head,
	})

	streams, flows := store.snapshot()
	if len(streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(streams))
	}
	st := streams[0]
	if st.Protocol != "http" || st.State != "error" || st.Scheme != "https" {
		t.Errorf("stream protocol/state/scheme = %q/%q/%q, want http/error/https", st.Protocol, st.State, st.Scheme)
	}
	if st.FailureReason != "request_head_timeout" {
		t.Errorf("FailureReason = %q, want request_head_timeout", st.FailureReason)
	}
	if st.BlockedBy != "" {
		t.Errorf("BlockedBy = %q, want empty", st.BlockedBy)
	}
	if st.ConnID != "conn-1" {
		t.Errorf("ConnID = %q, want conn-1", st.ConnID)
	}
	if st.ConnInfo == nil || st.ConnInfo.ClientAddr != "127.0.0.1:5555" || st.ConnInfo.ServerAddr != "example.test:443" {
		t.Errorf("ConnInfo = %+v", st.ConnInfo)
	}
	wantTags := map[string]string{
		"closed_by":          "proxy",
		"phase":              "headers",
		"request_timeout_ms": "300",
		"target":             "example.test:443",
		"listener":           "live",
	}
	for k, v := range wantTags {
		if st.Tags[k] != v {
			t.Errorf("Tags[%q] = %q, want %q", k, st.Tags[k], v)
		}
	}
	if st.Tags["error"] == "" {
		t.Error("Tags[error] is empty")
	}
	if len(flows) != 1 {
		t.Fatalf("flows = %d, want 1 (send only)", len(flows))
	}
	fl := flows[0]
	if fl.StreamID != st.ID || fl.Sequence != 0 || fl.Direction != "send" {
		t.Errorf("flow stream/seq/dir = %q/%d/%q, want %q/0/send", fl.StreamID, fl.Sequence, fl.Direction, st.ID)
	}
	if string(fl.RawBytes) != string(head.Raw) {
		t.Errorf("RawBytes = %q, want %q", fl.RawBytes, head.Raw)
	}
	if fl.Method != "GET" || fl.URL == nil || fl.URL.Path != "/x" || fl.URL.RawQuery != "y=1" || fl.URL.Host != "example.test" {
		t.Errorf("Method/URL = %q %v", fl.Method, fl.URL)
	}
	if fl.HTTPVersion != "http/1.1" {
		t.Errorf("HTTPVersion = %q, want http/1.1", fl.HTTPVersion)
	}
	if got := fl.Headers["Host"]; len(got) != 1 || got[0] != "example.test" {
		t.Errorf("Headers[Host] = %v", got)
	}
	if fl.Metadata["raw_captured_bytes"] != strconv.Itoa(len(head.Raw)) {
		t.Errorf("Metadata[raw_captured_bytes] = %q, want %d", fl.Metadata["raw_captured_bytes"], len(head.Raw))
	}
	if _, ok := fl.Metadata["raw_truncated"]; ok {
		t.Errorf("Metadata[raw_truncated] present on an untruncated capture")
	}
}

func TestRequestHeadRecorder_RejectWithResponse(t *testing.T) {
	resp := []byte("HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
	cases := []struct {
		name    string
		written bool
	}{
		{name: "response written", written: true},
		{name: "response write failed", written: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &headRecStore{}
			rec := buildRequestHeadRecorder(store, nil, "live", silentLogger())
			head := &http1.RequestHeadError{
				Reason:          http1.RequestHeadHeaderTooLarge,
				Phase:           http1.RequestHeadPhaseHeaders,
				Scheme:          "http",
				Raw:             []byte("GET / HTTP/1.1\r\nX-Big: bbbb"),
				RawTruncated:    true,
				Method:          "GET",
				RequestTarget:   "/",
				Proto:           "HTTP/1.1",
				Path:            "/",
				Status:          431,
				Response:        resp,
				ResponseWritten: tc.written,
				Err:             parser.ErrHeaderSectionTooLarge,
			}
			rec(context.Background(), requestHeadFailure{ConnID: "c", Target: "example.test:80", Head: head})

			streams, flows := store.snapshot()
			if len(streams) != 1 {
				t.Fatalf("streams = %d, want 1", len(streams))
			}
			st := streams[0]
			if st.FailureReason != "request_header_too_large" || st.State != "error" || st.Scheme != "http" {
				t.Errorf("stream = reason %q state %q scheme %q", st.FailureReason, st.State, st.Scheme)
			}
			if st.Tags["phase"] != "headers" || st.Tags["closed_by"] != "proxy" {
				t.Errorf("Tags = %v", st.Tags)
			}
			if _, ok := st.Tags["request_timeout_ms"]; ok {
				t.Errorf("Tags[request_timeout_ms] set with no armed deadline: %v", st.Tags)
			}
			if got := st.Tags["wrote_response"]; got != strconv.FormatBool(tc.written) {
				t.Errorf("Tags[wrote_response] = %q, want %v", got, tc.written)
			}
			var send, recv *flow.Flow
			for _, f := range flows {
				switch f.Direction {
				case "send":
					send = f
				case "receive":
					recv = f
				}
			}
			if send == nil {
				t.Fatal("no send flow")
			}
			if send.Metadata["raw_truncated"] != "true" {
				t.Errorf("send Metadata[raw_truncated] = %q, want true", send.Metadata["raw_truncated"])
			}
			if send.Metadata["raw_captured_bytes"] != strconv.Itoa(len(head.Raw)) {
				t.Errorf("send Metadata[raw_captured_bytes] = %q", send.Metadata["raw_captured_bytes"])
			}
			if !tc.written {
				if recv != nil {
					t.Fatalf("receive flow recorded for a response that was not written: %+v", recv)
				}
				return
			}
			if recv == nil {
				t.Fatal("no receive flow for the written 431")
			}
			if recv.Sequence != 1 || recv.StatusCode != 431 || string(recv.RawBytes) != string(resp) {
				t.Errorf("receive flow seq=%d status=%d raw=%q", recv.Sequence, recv.StatusCode, recv.RawBytes)
			}
			if recv.Metadata["proxy_generated"] != "true" {
				t.Errorf("receive Metadata[proxy_generated] = %q, want true", recv.Metadata["proxy_generated"])
			}
		})
	}
}

func TestRequestHeadRecorder_CaptureScope(t *testing.T) {
	cases := []struct {
		name      string
		excludes  []flow.ScopeRule
		includes  []flow.ScopeRule
		target    string
		authority string
		want      int
	}{
		{name: "excluded target", excludes: []flow.ScopeRule{{Hostname: "example.test"}},
			target: "example.test:443", authority: "example.test", want: 0},
		{name: "other host recorded", excludes: []flow.ScopeRule{{Hostname: "other.test"}},
			target: "example.test:443", authority: "example.test", want: 1},
		{name: "no authority fails closed under hostname exclude", excludes: []flow.ScopeRule{{Hostname: "other.test"}},
			target: "", authority: "", want: 0},
		{name: "include matches", includes: []flow.ScopeRule{{Hostname: "example.test"}},
			target: "example.test:443", authority: "example.test", want: 1},
		{name: "include misses", includes: []flow.ScopeRule{{Hostname: "other.test"}},
			target: "example.test:443", authority: "example.test", want: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := flow.NewRecordScope()
			scope.SetRules(tc.includes, tc.excludes)
			store := &headRecStore{}
			rec := buildRequestHeadRecorder(store, scope, "live", silentLogger())
			head := timeoutHead()
			head.Authority = tc.authority
			if tc.authority == "" {
				head.Headers = nil
			}
			rec(context.Background(), requestHeadFailure{ConnID: "c", Target: tc.target, Head: head})
			streams, _ := store.snapshot()
			if len(streams) != tc.want {
				t.Fatalf("streams = %d, want %d", len(streams), tc.want)
			}
		})
	}
}
