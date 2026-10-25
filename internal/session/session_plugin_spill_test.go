package session

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// These tests drive a disk-spilled HTTP message through real PluginStepPre /
// PluginStepPost Steps backed by a real pluginv2.Engine inside RunSession.
// Whatever the hooks do to the body — replace it, leave it alone, replace it
// and then DROP / RESPOND — every buffer reference must be released exactly
// once by the time RunSession returns: no spill file may remain, and a
// double Release would panic (bodybuf rejects a release below zero).

// makeSpilledResponse is the Receive-direction twin of makeSpilledRequest.
func makeSpilledResponse(t *testing.T, dir string, body string) *envelope.Envelope {
	t.Helper()
	newBuf := func() *bodybuf.BodyBuffer {
		buf, err := bodybuf.NewFile(dir, bodyBufSpillPrefix, 1<<20)
		if err != nil {
			t.Fatalf("bodybuf.NewFile: %v", err)
		}
		if _, err := buf.Write([]byte(body)); err != nil {
			t.Fatalf("bodybuf.Write: %v", err)
		}
		return buf
	}
	return &envelope.Envelope{
		StreamID:  "s",
		FlowID:    "f-resp",
		Sequence:  1,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"),
		RawBuffer: newBuf(),
		Message: &envelope.HTTPMessage{
			Status:     200,
			Headers:    []envelope.KeyValue{{Name: "Content-Type", Value: "text/plain"}},
			BodyBuffer: newBuf(),
		},
	}
}

// pluginHook builds a hook whose Fn calls fn with the msg dict.
func pluginHook(event string, phase pluginv2.Phase, fn func(msg starlark.HasSetKey) (starlark.Value, error)) pluginv2.Hook {
	return pluginv2.Hook{
		Protocol:   pluginv2.ProtoHTTP,
		Event:      event,
		Phase:      phase,
		PluginName: "spill-test",
		Fn: starlark.NewBuiltin("hook", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			msg, ok := args[0].(starlark.HasSetKey)
			if !ok {
				return nil, fmt.Errorf("hook arg is %T, want a settable msg dict", args[0])
			}
			return fn(msg)
		}),
	}
}

func replaceBodyHook(event string, phase pluginv2.Phase, body string) pluginv2.Hook {
	return pluginHook(event, phase, func(msg starlark.HasSetKey) (starlark.Value, error) {
		return starlark.None, msg.SetKey(starlark.String("body"), starlark.Bytes(body))
	})
}

func TestRunSession_PluginBodyReplace_SpilledBodyReleased(t *testing.T) {
	const (
		onReq  = pluginv2.EventOnRequest
		onResp = pluginv2.EventOnResponse
		pre    = pluginv2.PhasePrePipeline
		post   = pluginv2.PhasePostPipeline
	)
	dropHook := func(event string, phase pluginv2.Phase) pluginv2.Hook {
		return pluginHook(event, phase, func(starlark.HasSetKey) (starlark.Value, error) {
			return starlark.String("DROP"), nil
		})
	}
	respondHook := func(event string, phase pluginv2.Phase) pluginv2.Hook {
		return pluginHook(event, phase, func(starlark.HasSetKey) (starlark.Value, error) {
			return &pluginv2.RespondAction{HTTPResponse: &pluginv2.HTTPRespondPayload{
				StatusCode: 403,
				Body:       []byte("denied"),
			}}, nil
		})
	}
	noopHook := func(event string, phase pluginv2.Phase) pluginv2.Hook {
		return pluginHook(event, phase, func(starlark.HasSetKey) (starlark.Value, error) {
			return starlark.None, nil
		})
	}
	headerHook := func(event string, phase pluginv2.Phase) pluginv2.Hook {
		return pluginHook(event, phase, func(msg starlark.HasSetKey) (starlark.Value, error) {
			if event == onReq {
				return starlark.None, msg.SetKey(starlark.String("path"), starlark.String("/changed"))
			}
			return starlark.None, msg.SetKey(starlark.String("status_reason"), starlark.String("Fine"))
		})
	}

	cases := []struct {
		name string
		// spilledResponse: the spilled message is the upstream response
		// (Receive) rather than the client request (Send).
		spilledResponse bool
		hooks           []pluginv2.Hook
		// after are Steps appended after PluginStepPost.
		after []pipeline.Step
		// wantUpstream reports whether the request reaches the upstream.
		wantUpstream bool
	}{
		{name: "pre_replaces_request", hooks: []pluginv2.Hook{replaceBodyHook(onReq, pre, "new")}, wantUpstream: true},
		{name: "post_replaces_request", hooks: []pluginv2.Hook{replaceBodyHook(onReq, post, "new")}, wantUpstream: true},
		{name: "pre_replaces_response", spilledResponse: true, hooks: []pluginv2.Hook{replaceBodyHook(onResp, pre, "new")}, wantUpstream: true},
		{name: "post_replaces_response", spilledResponse: true, hooks: []pluginv2.Hook{replaceBodyHook(onResp, post, "new")}, wantUpstream: true},
		{
			name:         "pre_and_post_replace_request",
			hooks:        []pluginv2.Hook{replaceBodyHook(onReq, pre, "one"), replaceBodyHook(onReq, post, "two")},
			wantUpstream: true,
		},
		{
			name:         "two_hooks_both_replace",
			hooks:        []pluginv2.Hook{replaceBodyHook(onReq, pre, "one"), replaceBodyHook(onReq, pre, "two")},
			wantUpstream: true,
		},
		{
			name:  "replace_then_drop",
			hooks: []pluginv2.Hook{replaceBodyHook(onReq, pre, "new"), dropHook(onReq, pre)},
		},
		{
			name:  "replace_then_respond",
			hooks: []pluginv2.Hook{replaceBodyHook(onReq, pre, "new"), respondHook(onReq, pre)},
		},
		{
			// DROP is not in the on_response action mask: the dispatcher
			// rejects that outcome and continues with the replaced body.
			name:            "replace_then_disallowed_drop_response",
			spilledResponse: true,
			hooks:           []pluginv2.Hook{replaceBodyHook(onResp, pre, "new"), dropHook(onResp, pre)},
			wantUpstream:    true,
		},
		{
			name:            "replace_then_respond_response",
			spilledResponse: true,
			hooks:           []pluginv2.Hook{replaceBodyHook(onResp, pre, "new"), respondHook(onResp, pre)},
			wantUpstream:    true,
		},
		{
			name:         "replace_then_transform_commit",
			hooks:        []pluginv2.Hook{replaceBodyHook(onReq, pre, "new")},
			after:        []pipeline.Step{transformReleaseStep{}},
			wantUpstream: true,
		},
		{name: "noop_hook_request", hooks: []pluginv2.Hook{noopHook(onReq, pre)}, wantUpstream: true},
		{name: "noop_hook_response", spilledResponse: true, hooks: []pluginv2.Hook{noopHook(onResp, post)}, wantUpstream: true},
		{name: "header_only_request", hooks: []pluginv2.Hook{headerHook(onReq, pre)}, wantUpstream: true},
		{name: "header_only_response", spilledResponse: true, hooks: []pluginv2.Hook{headerHook(onResp, post)}, wantUpstream: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()

			eng := pluginv2.NewEngine(testutil.DiscardLogger())
			for _, h := range c.hooks {
				eng.Registry().Register(h)
			}
			steps := []pipeline.Step{
				pipeline.NewPluginStepPre(eng, nil, testutil.DiscardLogger()),
				pipeline.NewPluginStepPost(eng, nil, testutil.DiscardLogger()),
			}
			steps = append(steps, c.after...)

			var req, resp *envelope.Envelope
			if c.spilledResponse {
				req = &envelope.Envelope{
					StreamID:  "s",
					FlowID:    "f",
					Direction: envelope.Send,
					Protocol:  envelope.ProtocolHTTP,
					Raw:       []byte("GET /spill HTTP/1.1\r\nHost: example.com\r\n\r\n"),
					Message: &envelope.HTTPMessage{
						Method:  "GET",
						Path:    "/spill",
						Headers: []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
					},
				}
				resp = makeSpilledResponse(t, dir, "spilled-response-body")
			} else {
				req = makeSpilledRequest(t, dir, "spilled-request-body")
				resp = &envelope.Envelope{
					Direction: envelope.Receive,
					Protocol:  envelope.ProtocolHTTP,
					Message:   &envelope.HTTPMessage{Status: 200, Body: []byte("ok")},
				}
			}
			if got := countSpillFiles(t, dir); got != 2 {
				t.Fatalf("setup: spill files = %d, want 2", got)
			}

			clientCh := &mockChannel{streamID: "s", nextEnvelopes: []*envelope.Envelope{req}}
			upstreamCh := &mockChannel{streamID: "u", nextEnvelopes: []*envelope.Envelope{resp}}
			dialed := false
			dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
				dialed = true
				return upstreamCh, nil
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := RunSession(ctx, clientCh, dial, pipeline.New(steps...)); err != nil {
				t.Fatalf("RunSession: %v", err)
			}

			if dialed != c.wantUpstream {
				t.Errorf("upstream dialed = %v, want %v", dialed, c.wantUpstream)
			}
			if got := countSpillFiles(t, dir); got != 0 {
				t.Errorf("after session: spill files = %d, want 0 (a plugin body replacement leaked a buffer reference)", got)
			}
		})
	}
}
