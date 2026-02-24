package session

import (
	"net/url"
	"time"
)

// Entry represents a single recorded proxy session entry.
type Entry struct {
	ID        string
	ConnID    string // connection ID for log correlation
	Protocol  string
	Request   RecordedRequest
	Response  RecordedResponse
	Timestamp time.Time
	Duration  time.Duration
}

// RecordedRequest holds the captured request data.
type RecordedRequest struct {
	Method        string
	URL           *url.URL
	Headers       map[string][]string
	Body          []byte
	BodyTruncated bool
}

// RecordedResponse holds the captured response data.
type RecordedResponse struct {
	StatusCode    int
	Headers       map[string][]string
	Body          []byte
	BodyTruncated bool
}
