package job

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	http1 "github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/macro"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// MacroSendFuncAdapter creates a macro.SendFunc that bridges the Envelope/Channel
// world. Each call dials upstream, sends the request through the macro pipeline
// (without InterceptStep), reads the response, and converts back.
//
// The macroPipeline should be Pipeline.Without(InterceptStep). All other Steps
// (Safety, Transform, Record) still apply to macro traffic.
func MacroSendFuncAdapter(dial session.DialFunc, macroPipeline *pipeline.Pipeline) macro.SendFunc {
	return func(ctx context.Context, req *macro.SendRequest) (*macro.SendResponse, error) {
		env := sendRequestToEnvelope(req)

		// Run through the macro pipeline (no InterceptStep).
		if macroPipeline != nil {
			env, _, _ = macroPipeline.Run(ctx, env)
		}

		upstream, err := dial(ctx, env)
		if err != nil {
			return nil, fmt.Errorf("macro send: dial: %w", err)
		}
		defer upstream.Close()

		if err := upstream.Send(ctx, env); err != nil {
			return nil, fmt.Errorf("macro send: upstream.Send: %w", err)
		}

		respEnv, err := upstream.Next(ctx)
		if err != nil {
			return nil, fmt.Errorf("macro send: upstream.Next: %w", err)
		}

		// Run response through macro pipeline.
		if macroPipeline != nil {
			respEnv, _, _ = macroPipeline.Run(ctx, respEnv)
		}

		return envelopeToSendResponse(respEnv)
	}
}

// sendRequestToEnvelope converts a macro.SendRequest to an Envelope with
// HTTPMessage. Uses BuildSendEnvelope for consistent synthetic envelope
// construction.
func sendRequestToEnvelope(req *macro.SendRequest) *envelope.Envelope {
	scheme, authority, path, rawQuery := parseMacroURL(req.URL)
	headers := mapHeadersToKeyValues(req.Headers)

	return http1.BuildSendEnvelope(req.Method, scheme, authority, path, rawQuery, headers, req.Body)
}

// envelopeToSendResponse converts a response Envelope back to a
// macro.SendResponse.
func envelopeToSendResponse(env *envelope.Envelope) (*macro.SendResponse, error) {
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		return nil, fmt.Errorf("macro send: response is not HTTPMessage, got %T", env.Message)
	}

	respHeaders := keyValuesToHTTPHeader(msg.Headers)

	// Reconstruct URL from message fields.
	respURL := msg.Scheme + "://" + msg.Authority + msg.Path
	if msg.RawQuery != "" {
		respURL += "?" + msg.RawQuery
	}

	return &macro.SendResponse{
		StatusCode: msg.Status,
		Headers:    respHeaders,
		Body:       msg.Body,
		URL:        respURL,
	}, nil
}

// parseMacroURL parses a URL string from macro.SendRequest into components.
func parseMacroURL(rawURL string) (scheme, authority, path, rawQuery string) {
	scheme = "https"

	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		scheme = rawURL[:idx]
		rawURL = rawURL[idx+3:]
	}

	pathStart := strings.IndexByte(rawURL, '/')
	if pathStart < 0 {
		authority = rawURL
		path = "/"
		return
	}
	authority = rawURL[:pathStart]
	rest := rawURL[pathStart:]

	if qIdx := strings.IndexByte(rest, '?'); qIdx >= 0 {
		path = rest[:qIdx]
		rawQuery = rest[qIdx+1:]
	} else {
		path = rest
	}
	return
}

// mapHeadersToKeyValues converts map[string][]string to []envelope.KeyValue.
func mapHeadersToKeyValues(headers map[string][]string) []envelope.KeyValue {
	if headers == nil {
		return nil
	}
	var kvs []envelope.KeyValue
	for name, values := range headers {
		for _, v := range values {
			kvs = append(kvs, envelope.KeyValue{Name: name, Value: v})
		}
	}
	return kvs
}

// keyValuesToHTTPHeader converts []envelope.KeyValue to http.Header.
// This is acceptable because macro types use net/http (control plane, not data path).
func keyValuesToHTTPHeader(kvs []envelope.KeyValue) http.Header {
	h := make(http.Header, len(kvs))
	for _, kv := range kvs {
		h.Add(kv.Name, kv.Value)
	}
	return h
}

// FlowFetcherAdapter adapts flow.Reader to the macro.FlowFetcher interface.
type FlowFetcherAdapter struct {
	reader flow.Reader
}

// NewFlowFetcherAdapter creates a FlowFetcherAdapter wrapping a flow.Reader.
func NewFlowFetcherAdapter(reader flow.Reader) *FlowFetcherAdapter {
	return &FlowFetcherAdapter{reader: reader}
}

// GetFlowRequest retrieves a send flow by its flow ID and converts it to
// a macro.SendRequest. The flowID parameter is actually a stream ID —
// the adapter fetches the first send flow within that stream.
func (a *FlowFetcherAdapter) GetFlowRequest(ctx context.Context, flowID string) (*macro.SendRequest, error) {
	// Try as stream ID first (the common case for macro steps).
	flows, err := a.reader.GetFlows(ctx, flowID, flow.FlowListOptions{
		Direction: "send",
	})
	if err != nil {
		return nil, fmt.Errorf("flow fetcher: get flows for %s: %w", flowID, err)
	}

	if len(flows) == 0 {
		// Try as individual flow ID.
		f, err := a.reader.GetFlow(ctx, flowID)
		if err != nil {
			return nil, fmt.Errorf("flow fetcher: get flow %s: %w", flowID, err)
		}
		return flowToSendRequest(f), nil
	}

	return flowToSendRequest(flows[0]), nil
}

// flowToSendRequest converts a flow.Flow to a macro.SendRequest.
func flowToSendRequest(f *flow.Flow) *macro.SendRequest {
	reqURL := ""
	if f.URL != nil {
		reqURL = f.URL.String()
	}

	return &macro.SendRequest{
		Method:  f.Method,
		URL:     reqURL,
		Headers: f.Headers,
		Body:    f.Body,
	}
}
