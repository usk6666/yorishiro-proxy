package proxybuild

import (
	"context"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// bodyModeFixture builds the envelope / message pair the HTTP/1.x Layer
// hands the predicate: a header-only message plus the Envelope context
// (paired request method / path for a response).
type bodyModeFixture struct {
	dir         envelope.Direction
	status      int
	method      string // request method (Send) or paired request method (Receive)
	path        string
	contentType string
}

func (f bodyModeFixture) build() (*envelope.Envelope, *envelope.HTTPMessage) {
	msg := &envelope.HTTPMessage{HTTPVersion: envelope.HTTPVersion11}
	if f.contentType != "" {
		msg.Headers = append(msg.Headers, envelope.KeyValue{Name: "Content-Type", Value: f.contentType})
	}
	env := &envelope.Envelope{
		Direction: f.dir,
		Protocol:  envelope.ProtocolHTTP,
		Message:   msg,
		Context:   envelope.EnvelopeContext{TargetHost: "example.com:443"},
	}
	if f.dir == envelope.Send {
		msg.Method = f.method
		msg.Path = f.path
		msg.Authority = "example.com"
	} else {
		msg.Status = f.status
		env.Context.RequestMethod = f.method
		env.Context.RequestPath = f.path
	}
	return env, msg
}

func loadBodyModePlugin(t *testing.T, script string, maxBody int64) *pluginv2.Engine {
	t.Helper()
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []pluginv2.PluginConfig{{
		Path:    filepath.Join("testdata", script),
		OnError: string(pluginv2.OnErrorAbort),
	}}); err != nil {
		t.Fatalf("LoadPlugins(%s): %v", script, err)
	}
	if maxBody > 0 {
		eng.SetMaxBodySize(maxBody)
	}
	return eng
}

func mustInterceptRule(t *testing.T, dir httprules.RuleDirection, path string) httprules.InterceptRule {
	t.Helper()
	r, err := httprules.CompileInterceptRule("ic-"+path, dir, "", path, nil, nil)
	if err != nil {
		t.Fatalf("CompileInterceptRule: %v", err)
	}
	return *r
}

func mustTransformRule(t *testing.T, dir httprules.RuleDirection, path string, action httprules.TransformActionType) httprules.TransformRule {
	t.Helper()
	var r *httprules.TransformRule
	var err error
	switch action {
	case httprules.TransformReplaceBody:
		r, err = httprules.CompileTransformRule("tf-body", 0, dir, "", path, nil, action, "", "", "secret", "redacted")
	default:
		r, err = httprules.CompileTransformRule("tf-hdr", 0, dir, "", path, nil, action, "X-Test", "1", "", "")
	}
	if err != nil {
		t.Fatalf("CompileTransformRule: %v", err)
	}
	return *r
}

// TestNewHTTPBodyModeFunc_DecisionTable drives the production predicate
// with real rule engines and a real pluginv2 Engine (USK-1409 T1).
func TestNewHTTPBodyModeFunc_DecisionTable(t *testing.T) {
	bodySafety := httprules.NewSafetyEngine()
	if err := bodySafety.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatalf("LoadPreset: %v", err)
	}
	urlSafety := httprules.NewSafetyEngine()
	urlSafety.AddRule(common.CompiledRule{
		ID:      "url-only",
		Name:    "url only",
		Pattern: regexp.MustCompile(`/admin`),
		Targets: []common.Target{common.TargetURL},
	})

	interceptHold := httprules.NewInterceptEngine()
	interceptHold.AddRule(mustInterceptRule(t, httprules.DirectionResponse, "^/hold"))

	replaceBody := httprules.NewTransformEngine()
	replaceBody.AddRule(mustTransformRule(t, httprules.DirectionResponse, "^/rewrite", httprules.TransformReplaceBody))
	setHeader := httprules.NewTransformEngine()
	setHeader.AddRule(mustTransformRule(t, httprules.DirectionResponse, "", httprules.TransformSetHeader))

	onResponse := loadBodyModePlugin(t, "body_mode_on_response.star", 2048)
	onRequest := loadBodyModePlugin(t, "body_mode_on_request.star", 4096)

	okResp := bodyModeFixture{dir: envelope.Receive, status: 200, method: "GET", path: "/data"}

	tests := []struct {
		name    string
		engines HTTPBodyModeEngines
		fx      bodyModeFixture
		want    layer.BodyMode
	}{
		{name: "no engines, response streams", fx: okResp, want: layer.Stream()},
		{name: "intercept response rule matches", engines: HTTPBodyModeEngines{Intercept: interceptHold},
			fx: bodyModeFixture{dir: envelope.Receive, status: 200, method: "GET", path: "/hold/1"}, want: layer.Buffer()},
		{name: "intercept response rule misses", engines: HTTPBodyModeEngines{Intercept: interceptHold},
			fx: okResp, want: layer.Stream()},
		{name: "replace_body matches", engines: HTTPBodyModeEngines{Transform: replaceBody},
			fx: bodyModeFixture{dir: envelope.Receive, status: 200, method: "GET", path: "/rewrite"}, want: layer.Buffer()},
		{name: "replace_body misses", engines: HTTPBodyModeEngines{Transform: replaceBody},
			fx: okResp, want: layer.Stream()},
		{name: "set_header matches but leaves the body alone", engines: HTTPBodyModeEngines{Transform: setHeader},
			fx: okResp, want: layer.Stream()},
		{name: "plugin on_response hook", engines: HTTPBodyModeEngines{Plugin: onResponse},
			fx: okResp, want: layer.BufferUpTo(2048)},
		{name: "plugin on_request hook only, response", engines: HTTPBodyModeEngines{Plugin: onRequest},
			fx: okResp, want: layer.Stream()},
		{name: "plugin on_request hook, request", engines: HTTPBodyModeEngines{Plugin: onRequest},
			fx: bodyModeFixture{dir: envelope.Send, method: "POST", path: "/upload"}, want: layer.BufferUpTo(4096)},
		{name: "plugin present and replace_body matches", engines: HTTPBodyModeEngines{Plugin: onResponse, Transform: replaceBody},
			fx: bodyModeFixture{dir: envelope.Receive, status: 200, method: "GET", path: "/rewrite"}, want: layer.Buffer()},
		{name: "safety body rule, request", engines: HTTPBodyModeEngines{Safety: bodySafety},
			fx: bodyModeFixture{dir: envelope.Send, method: "POST", path: "/q"}, want: layer.Buffer()},
		{name: "safety URL-only rule, request", engines: HTTPBodyModeEngines{Safety: urlSafety},
			fx: bodyModeFixture{dir: envelope.Send, method: "POST", path: "/q"}, want: layer.Stream()},
		{name: "safety body rule does not apply to responses", engines: HTTPBodyModeEngines{Safety: bodySafety},
			fx: okResp, want: layer.Stream()},
		{name: "grpc-web response", fx: bodyModeFixture{dir: envelope.Receive, status: 200, method: "POST", path: "/svc/M", contentType: "application/grpc-web+proto"},
			want: layer.Buffer()},
		{name: "grpc-web-text request", fx: bodyModeFixture{dir: envelope.Send, method: "POST", path: "/svc/M", contentType: "application/grpc-web-text"},
			want: layer.Buffer()},
		{name: "response to HEAD", fx: bodyModeFixture{dir: envelope.Receive, status: 200, method: "HEAD", path: "/data"}, want: layer.Buffer()},
		{name: "204", fx: bodyModeFixture{dir: envelope.Receive, status: 204, method: "GET", path: "/data"}, want: layer.Buffer()},
		{name: "304", fx: bodyModeFixture{dir: envelope.Receive, status: 304, method: "GET", path: "/data"}, want: layer.Buffer()},
		{name: "101", fx: bodyModeFixture{dir: envelope.Receive, status: 101, method: "GET", path: "/ws"}, want: layer.Buffer()},
		{name: "1xx", fx: bodyModeFixture{dir: envelope.Receive, status: 103, method: "GET", path: "/data"}, want: layer.Buffer()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fn := NewHTTPBodyModeFunc(tt.engines)
			if fn == nil {
				t.Fatal("NewHTTPBodyModeFunc returned nil")
			}
			env, msg := tt.fx.build()
			if got := fn(env, msg); got != tt.want {
				t.Errorf("mode = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestNewHTTPBodyModeFunc_RuleAddedLater checks the predicate reads the
// engines on every call: a rule added after construction applies to the
// next message (USK-1409 R16).
func TestNewHTTPBodyModeFunc_RuleAddedLater(t *testing.T) {
	tf := httprules.NewTransformEngine()
	fn := NewHTTPBodyModeFunc(HTTPBodyModeEngines{Transform: tf})
	env, msg := bodyModeFixture{dir: envelope.Receive, status: 200, method: "GET", path: "/rewrite"}.build()
	if got := fn(env, msg); got != layer.Stream() {
		t.Fatalf("before rule: mode = %v, want stream", got)
	}
	tf.AddRule(mustTransformRule(t, httprules.DirectionResponse, "^/rewrite", httprules.TransformReplaceBody))
	if got := fn(env, msg); got != layer.Buffer() {
		t.Fatalf("after rule: mode = %v, want buffer", got)
	}
}
