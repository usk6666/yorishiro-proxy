package job

import (
	"context"
	"fmt"
	"io"
	"net/url"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
	http1 "github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// FuzzHTTPSource is an EnvelopeSource that yields HTTPMessage Envelopes
// with fuzz payloads injected at configured positions. Uses the existing
// fuzzer.Iterator for attack type iteration (sequential/parallel) and
// fuzzer.ApplyPosition for payload injection.
type FuzzHTTPSource struct {
	reader   flow.Reader
	streamID string
	iterator fuzzer.Iterator
	baseData *fuzzer.RequestData
	posMap   map[string]fuzzer.Position
	kvStore  map[string]string

	initialized bool
}

// FuzzHTTPConfig configures a FuzzHTTPSource.
type FuzzHTTPConfig struct {
	// Reader provides access to the flow store.
	Reader flow.Reader
	// StreamID is the base flow stream to fuzz.
	StreamID string
	// AttackType is "sequential" or "parallel".
	AttackType string
	// Positions defines where payloads are injected.
	Positions []fuzzer.Position
	// ResolvedPayloads maps payload set name to resolved payload strings.
	ResolvedPayloads map[string][]string
	// KVStore for template expansion. May be nil.
	KVStore map[string]string
}

// NewFuzzHTTPSource creates a fuzz source for HTTP requests.
// The iterator is created eagerly to validate configuration; the base flow
// is fetched lazily on the first Next() call.
func NewFuzzHTTPSource(cfg FuzzHTTPConfig) (*FuzzHTTPSource, error) {
	iter, err := fuzzer.NewIterator(cfg.AttackType, cfg.Positions, cfg.ResolvedPayloads)
	if err != nil {
		return nil, fmt.Errorf("fuzz http source: create iterator: %w", err)
	}

	posMap := make(map[string]fuzzer.Position, len(cfg.Positions))
	for _, p := range cfg.Positions {
		posMap[p.ID] = p
	}

	return &FuzzHTTPSource{
		reader:   cfg.Reader,
		streamID: cfg.StreamID,
		iterator: iter,
		posMap:   posMap,
		kvStore:  cfg.KVStore,
	}, nil
}

// Total returns the total number of fuzz iterations.
func (s *FuzzHTTPSource) Total() int {
	return s.iterator.Total()
}

// Next returns the next fuzz Envelope or io.EOF when exhausted.
func (s *FuzzHTTPSource) Next(ctx context.Context) (*envelope.Envelope, error) {
	if !s.initialized {
		if err := s.init(ctx); err != nil {
			return nil, err
		}
	}

	fc, ok := s.iterator.Next()
	if !ok {
		return nil, io.EOF
	}

	data := s.baseData.Clone()
	for posID, payload := range fc.Payloads {
		pos, exists := s.posMap[posID]
		if !exists {
			continue
		}
		if err := fuzzer.ApplyPosition(data, pos, payload); err != nil {
			return nil, fmt.Errorf("fuzz http source: apply position %s: %w", posID, err)
		}
	}

	env := requestDataToEnvelope(data)

	if len(s.kvStore) > 0 {
		if err := ExpandEnvelopeTemplates(env, s.kvStore); err != nil {
			return nil, fmt.Errorf("fuzz http source: template expansion: %w", err)
		}
	}

	return env, nil
}

// init fetches the base flow and converts it to RequestData.
func (s *FuzzHTTPSource) init(ctx context.Context) error {
	flows, err := s.reader.GetFlows(ctx, s.streamID, flow.FlowListOptions{
		Direction: "send",
	})
	if err != nil {
		return fmt.Errorf("fuzz http source: get flows: %w", err)
	}
	if len(flows) == 0 {
		return fmt.Errorf("fuzz http source: no send flow for stream %s", s.streamID)
	}

	f := flows[0]
	s.baseData = flowToRequestData(f)
	s.initialized = true
	return nil
}

// flowToRequestData converts a flow.Flow to a fuzzer.RequestData.
func flowToRequestData(f *flow.Flow) *fuzzer.RequestData {
	data := &fuzzer.RequestData{
		Method: f.Method,
		Body:   f.Body,
	}
	if f.URL != nil {
		u := *f.URL
		data.URL = &u
	} else {
		data.URL = &url.URL{Scheme: "http", Path: "/"}
	}
	if f.Headers != nil {
		data.Headers = make(map[string][]string, len(f.Headers))
		for k, v := range f.Headers {
			data.Headers[k] = append([]string(nil), v...)
		}
	} else {
		data.Headers = make(map[string][]string)
	}
	return data
}

// requestDataToEnvelope converts fuzzer.RequestData to an Envelope via BuildSendEnvelope.
func requestDataToEnvelope(data *fuzzer.RequestData) *envelope.Envelope {
	scheme := "http"
	authority := ""
	path := "/"
	rawQuery := ""

	if data.URL != nil {
		if data.URL.Scheme != "" {
			scheme = data.URL.Scheme
		}
		authority = data.URL.Host
		if data.URL.Path != "" {
			path = data.URL.Path
		}
		rawQuery = data.URL.RawQuery
	}

	headers := mapHeadersToKeyValues(data.Headers)

	return http1.BuildSendEnvelope(data.Method, scheme, authority, path, rawQuery, headers, data.Body)
}
