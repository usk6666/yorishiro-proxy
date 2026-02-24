package session

import (
	"net/url"
	"time"
)

// Entry represents a single recorded proxy session entry.
type Entry struct {
	ID        string
	Protocol  string
	Request   RecordedRequest
	Response  RecordedResponse
	Timestamp time.Time
	Duration  time.Duration
	// Tags holds optional key-value metadata for the session entry.
	// Examples include security flags such as smuggling detection results.
	// A nil map indicates no tags are present.
	Tags map[string]string
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
