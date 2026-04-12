//go:build legacy

package pipeline

import (
	"context"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
)

func newTestPipeline(t *testing.T, ruleList ...rules.Rule) *rules.Pipeline {
	t.Helper()
	p := rules.NewPipeline()
	for _, r := range ruleList {
		if err := p.AddRule(r); err != nil {
			t.Fatalf("AddRule(%q): %v", r.ID, err)
		}
	}
	return p
}

func TestTransformStep_Send_HeaderMatch(t *testing.T) {
	p := newTestPipeline(t, rules.Rule{
		ID:        "add-auth",
		Enabled:   true,
		Priority:  0,
		Direction: rules.DirectionRequest,
		Action: rules.Action{
			Type:   rules.ActionAddHeader,
			Header: "Authorization",
			Value:  "Bearer test-token",
		},
	})

	step := NewTransformStep(p)
	u, _ := url.Parse("http://example.com/api")
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       u,
		Headers: []exchange.KeyValue{
			{Name: "Content-Type", Value: "application/json"},
		},
		Body: []byte("request body"),
	}

	result := step.Process(context.Background(), ex)

	if result.Action != Continue {
		t.Fatalf("Action = %v, want Continue", result.Action)
	}
	if got := exchange.HeaderGet(ex.Headers, "Authorization"); got != "Bearer test-token" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer test-token")
	}
	if got := exchange.HeaderGet(ex.Headers, "Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want %q", got, "application/json")
	}
}

func TestTransformStep_Send_BodyReplace(t *testing.T) {
	p := newTestPipeline(t, rules.Rule{
		ID:        "replace-body",
		Enabled:   true,
		Priority:  0,
		Direction: rules.DirectionRequest,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "old-value",
			Value:   "new-value",
		},
	})

	step := NewTransformStep(p)
	u, _ := url.Parse("http://example.com/api")
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "POST",
		URL:       u,
		Headers:   []exchange.KeyValue{{Name: "Content-Type", Value: "text/plain"}},
		Body:      []byte("data: old-value here"),
	}

	step.Process(context.Background(), ex)

	expected := "data: new-value here"
	if string(ex.Body) != expected {
		t.Errorf("Body = %q, want %q", string(ex.Body), expected)
	}
}

func TestTransformStep_Send_NoMatch(t *testing.T) {
	p := newTestPipeline(t, rules.Rule{
		ID:        "api-only",
		Enabled:   true,
		Priority:  0,
		Direction: rules.DirectionRequest,
		Conditions: rules.Conditions{
			URLPattern: "/api/.*",
		},
		Action: rules.Action{
			Type:   rules.ActionAddHeader,
			Header: "X-API",
			Value:  "true",
		},
	})

	step := NewTransformStep(p)
	u, _ := url.Parse("http://example.com/public/test")
	origHeaders := []exchange.KeyValue{{Name: "Content-Type", Value: "text/html"}}
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       u,
		Headers:   origHeaders,
		Body:      []byte("body"),
	}

	step.Process(context.Background(), ex)

	if got := exchange.HeaderGet(ex.Headers, "X-API"); got != "" {
		t.Errorf("X-API should not be set for non-matching URL, got %q", got)
	}
}

func TestTransformStep_Receive_HeaderMatch(t *testing.T) {
	p := newTestPipeline(t, rules.Rule{
		ID:        "remove-csp",
		Enabled:   true,
		Priority:  0,
		Direction: rules.DirectionResponse,
		Action: rules.Action{
			Type:   rules.ActionRemoveHeader,
			Header: "Content-Security-Policy",
		},
	})

	step := NewTransformStep(p)
	ex := &exchange.Exchange{
		Direction: exchange.Receive,
		Status:    200,
		Headers: []exchange.KeyValue{
			{Name: "Content-Security-Policy", Value: "default-src 'self'"},
			{Name: "Content-Type", Value: "text/html"},
		},
		Body: []byte("<html></html>"),
	}

	step.Process(context.Background(), ex)

	if got := exchange.HeaderGet(ex.Headers, "Content-Security-Policy"); got != "" {
		t.Errorf("CSP header should be removed, got %q", got)
	}
	if got := exchange.HeaderGet(ex.Headers, "Content-Type"); got != "text/html" {
		t.Errorf("Content-Type = %q, want %q", got, "text/html")
	}
}

func TestTransformStep_Receive_BodyReplace(t *testing.T) {
	p := newTestPipeline(t, rules.Rule{
		ID:        "replace-domain",
		Enabled:   true,
		Priority:  0,
		Direction: rules.DirectionResponse,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: `https://cdn\.example\.com`,
			Value:   "https://local.proxy",
		},
	})

	step := NewTransformStep(p)
	ex := &exchange.Exchange{
		Direction: exchange.Receive,
		Status:    200,
		Headers:   []exchange.KeyValue{{Name: "Content-Type", Value: "text/html"}},
		Body:      []byte(`<script src="https://cdn.example.com/app.js"></script>`),
	}

	step.Process(context.Background(), ex)

	expected := `<script src="https://local.proxy/app.js"></script>`
	if string(ex.Body) != expected {
		t.Errorf("Body = %q, want %q", string(ex.Body), expected)
	}
}

func TestTransformStep_BodyNil_HeaderOnlyTransform(t *testing.T) {
	p := newTestPipeline(t,
		rules.Rule{
			ID:        "add-header",
			Enabled:   true,
			Priority:  0,
			Direction: rules.DirectionRequest,
			Action: rules.Action{
				Type:   rules.ActionAddHeader,
				Header: "X-Injected",
				Value:  "yes",
			},
		},
		rules.Rule{
			ID:        "replace-body",
			Enabled:   true,
			Priority:  10,
			Direction: rules.DirectionRequest,
			Action: rules.Action{
				Type:    rules.ActionReplaceBody,
				Pattern: "anything",
				Value:   "replaced",
			},
		},
	)

	step := NewTransformStep(p)
	u, _ := url.Parse("http://example.com/test")
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       u,
		Headers:   []exchange.KeyValue{{Name: "Host", Value: "example.com"}},
		Body:      nil, // passthrough mode
	}

	step.Process(context.Background(), ex)

	// Header rule should apply.
	if got := exchange.HeaderGet(ex.Headers, "X-Injected"); got != "yes" {
		t.Errorf("X-Injected = %q, want %q", got, "yes")
	}
	// Body should remain nil (passthrough preserved).
	if ex.Body != nil {
		t.Errorf("Body should remain nil in passthrough mode, got %v", ex.Body)
	}
}

func TestTransformStep_PipelineNil_Continue(t *testing.T) {
	step := NewTransformStep(nil)

	u, _ := url.Parse("http://example.com/test")
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       u,
		Headers:   []exchange.KeyValue{{Name: "Host", Value: "example.com"}},
		Body:      []byte("body"),
	}

	origBody := string(ex.Body)
	origHeaderLen := len(ex.Headers)

	result := step.Process(context.Background(), ex)

	if result.Action != Continue {
		t.Fatalf("Action = %v, want Continue", result.Action)
	}
	if string(ex.Body) != origBody {
		t.Errorf("Body changed unexpectedly: %q", string(ex.Body))
	}
	if len(ex.Headers) != origHeaderLen {
		t.Errorf("Headers length changed: got %d, want %d", len(ex.Headers), origHeaderLen)
	}
}
